import { collectAgentIDs, resolveSigilumPluginConfig, type HookEvent } from "./config.ts";
import { ensureAgentKeypair } from "./keys.ts";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

type HookHandler = (event: HookEvent) => Promise<void>;
type ConnectionProtocol = "http" | "mcp";
type ConnectionStatus = "active" | "disabled";

type GatewayConnection = {
  id?: string;
  name?: string;
  protocol?: ConnectionProtocol;
  status?: ConnectionStatus;
};

type GatewayConnectionsResponse = {
  connections?: GatewayConnection[];
};

type RuntimeCredentialFinding = {
  provider: string;
  field: string;
  variable: string;
  value: string;
  source_path: string;
  location: string;
};

type RuntimeCredentialReport = {
  generated_at: string;
  findings: RuntimeCredentialFinding[];
};

type SubjectHintRecord = {
  agent_id: string;
  session_key: string;
  channel: string;
  from: string;
  sender_id: string;
  sender_e164: string;
  subject: string;
  updated_at: string;
};

type SubjectHintStore = {
  updated_at: string;
  by_session: Record<string, SubjectHintRecord>;
  by_agent: Record<string, SubjectHintRecord>;
  recent: SubjectHintRecord[];
};

const PROVIDER_ALIAS: Record<string, string> = {
  anthropic: "anthropic",
  claude: "anthropic",
  azure: "azure",
  cohere: "cohere",
  cerebras: "cerebras",
  deepseek: "deepseek",
  discord: "discord",
  fireworks: "fireworks",
  gemini: "google",
  google: "google",
  groq: "groq",
  hf: "huggingface",
  huggingface: "huggingface",
  linear: "linear",
  mistral: "mistral",
  notion: "notion",
  openai: "openai",
  openrouter: "openrouter",
  perplexity: "perplexity",
  replicate: "replicate",
  serpapi: "serpapi",
  slack: "slack",
  together: "together",
  vertex: "google",
  voyage: "voyage",
  xai: "xai",
};

const RUNTIME_REPORT_FILENAME = "legacy-runtime-credentials.json";
const SUBJECT_HINTS_FILENAME = "subject-hints.json";
const MAX_RECENT_SUBJECT_HINTS = 200;

function asObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown): string {
  if (typeof value !== "string") {
    return "";
  }
  return value.trim();
}

function sanitizeAgentID(value: string): string {
  return asString(value).replace(/[^a-zA-Z0-9._-]/g, "_");
}

function parseAgentIDFromSessionKey(sessionKey: string): string {
  const normalized = asString(sessionKey);
  if (!normalized) {
    return "";
  }
  const parts = normalized.split(":");
  if (parts.length >= 2 && parts[0].toLowerCase() === "agent") {
    return sanitizeAgentID(parts[1]);
  }
  return sanitizeAgentID(parts[0]);
}

function splitTokens(input: string): string[] {
  return String(input || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .split(/\s+/g)
    .filter((token) => token.length > 0);
}

function inferProviderFromText(input: string): string {
  for (const token of splitTokens(input)) {
    const provider = PROVIDER_ALIAS[token];
    if (provider) {
      return provider;
    }
  }
  return "";
}

function looksLikeSecretKeyName(key: string): boolean {
  const value = String(key || "").trim().toLowerCase();
  if (!value) {
    return false;
  }
  if (value.includes("apikey") || value.includes("api_key")) {
    return true;
  }
  if (value.endsWith("_token") || value.includes("access_token")) {
    return true;
  }
  if (value.endsWith("_secret") || value.includes("client_secret")) {
    return true;
  }
  if (value.endsWith("_password") || value.includes("auth_token")) {
    return true;
  }
  if (value === "token" || value === "secret" || value === "api_key") {
    return true;
  }
  return false;
}

function shouldSkipRuntimeCredentialKey(key: string): boolean {
  const upper = String(key || "").trim().toUpperCase();
  if (!upper) {
    return true;
  }
  for (const prefix of ["SIGILUM_", "OPENCLAW_", "GATEWAY_"]) {
    if (upper.startsWith(prefix)) {
      return true;
    }
  }
  return false;
}

function looksLikeSecretValue(raw: string): boolean {
  let value = String(raw || "").trim();
  if (!value || value.length < 8) {
    return false;
  }
  if (value.toLowerCase().startsWith("bearer ")) {
    value = value.slice(7).trim();
  }
  if (value.startsWith("{{") && value.endsWith("}}")) {
    return false;
  }
  if (value.startsWith("${") && value.endsWith("}")) {
    return false;
  }
  const lower = value.toLowerCase();
  for (const marker of ["your_api_key", "your-api-key", "placeholder", "changeme", "replace_me", "example", "sigilum-provider-proxy-key"]) {
    if (lower.includes(marker)) {
      return false;
    }
  }
  for (const prefix of ["sk-", "xoxb-", "xoxp-", "xapp-", "ghp_", "pat_", "pk_live_", "sk_live_", "sk_test_", "aiza", "xai-"]) {
    if (lower.startsWith(prefix)) {
      return true;
    }
  }
  if (/\s/.test(value)) {
    return false;
  }
  const letters = (value.match(/[a-z]/gi) || []).length;
  const digits = (value.match(/[0-9]/g) || []).length;
  const nonAlphaNum = (value.match(/[^a-z0-9]/gi) || []).length;
  if (letters < 3 || digits < 2) {
    return false;
  }
  return value.length >= 12 && (nonAlphaNum >= 1 || value.length >= 20);
}

function normalizeVariableKey(value: string): string {
  const normalized = String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toUpperCase();
  return normalized;
}

function readHookEnv(event: HookEvent, hookName: string): Record<string, unknown> {
  const cfgFromContext = asObject(event.context?.cfg);
  const cfg = Object.keys(cfgFromContext).length > 0
    ? cfgFromContext
    : asObject(event.context?.config);
  const hooks = asObject(cfg.hooks);
  const internal = asObject(hooks.internal);
  const entries = asObject(internal.entries);
  const hookEntry = asObject(entries[hookName]);
  return asObject(hookEntry.env);
}

function resolveOpenClawHome(event: HookEvent, keyRoot: string): string {
  const directEnv = asString(process.env.OPENCLAW_HOME);
  if (directEnv) {
    return directEnv;
  }
  const hookEnv = readHookEnv(event, "sigilum-plugin");
  const hookOpenClawHome = asString(hookEnv.OPENCLAW_HOME);
  if (hookOpenClawHome) {
    return hookOpenClawHome;
  }

  const normalizedKeyRoot = asString(keyRoot);
  if (normalizedKeyRoot) {
    const keyRootParent = path.dirname(normalizedKeyRoot);
    if (path.basename(keyRootParent) === ".sigilum") {
      return path.dirname(keyRootParent);
    }
  }
  return path.join(os.homedir(), ".openclaw");
}

function resolveRuntimeCredentialReportPath(event: HookEvent, keyRoot: string): string {
  const override = asString(process.env.SIGILUM_LEGACY_RUNTIME_REPORT_PATH);
  if (override) {
    return override;
  }
  const hookEnv = readHookEnv(event, "sigilum-plugin");
  const hookOverride = asString(hookEnv.SIGILUM_LEGACY_RUNTIME_REPORT_PATH);
  if (hookOverride) {
    return hookOverride;
  }
  const openClawHome = resolveOpenClawHome(event, keyRoot);
  return path.join(openClawHome, ".sigilum", RUNTIME_REPORT_FILENAME);
}

function resolveSubjectHintsPath(event: HookEvent, keyRoot: string): string {
  const override = asString(process.env.SIGILUM_SUBJECT_HINTS_PATH);
  if (override) {
    return override;
  }
  const hookEnv = readHookEnv(event, "sigilum-plugin");
  const hookOverride = asString(hookEnv.SIGILUM_SUBJECT_HINTS_PATH);
  if (hookOverride) {
    return hookOverride;
  }
  const openClawHome = resolveOpenClawHome(event, keyRoot);
  return path.join(openClawHome, ".sigilum", SUBJECT_HINTS_FILENAME);
}

function isMessageReceivedEvent(event: HookEvent): boolean {
  return event.type === "message" && event.action === "received";
}

function readSubjectHintStore(filePath: string): SubjectHintStore {
  const fallback: SubjectHintStore = {
    updated_at: new Date(0).toISOString(),
    by_session: {},
    by_agent: {},
    recent: [],
  };
  if (!fs.existsSync(filePath)) {
    return fallback;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as SubjectHintStore;
    const bySession = asObject(parsed.by_session) as Record<string, SubjectHintRecord>;
    const byAgent = asObject(parsed.by_agent) as Record<string, SubjectHintRecord>;
    const recent = Array.isArray(parsed.recent)
      ? parsed.recent.filter((entry) => entry && typeof entry === "object") as SubjectHintRecord[]
      : [];
    return {
      updated_at: asString(parsed.updated_at) || fallback.updated_at,
      by_session: bySession,
      by_agent: byAgent,
      recent,
    };
  } catch {
    return fallback;
  }
}

function slackSenderFromFromField(rawFrom: string): string {
  const from = asString(rawFrom);
  if (!from) {
    return "";
  }
  const lower = from.toLowerCase();
  if (!lower.startsWith("slack:")) {
    return "";
  }
  return from.slice("slack:".length).trim();
}

function extractSubjectHint(event: HookEvent): SubjectHintRecord | null {
  const context = asObject(event.context);
  const metadata = asObject(context.metadata);
  const sessionKey = asString(event.sessionKey);
  const agentID = parseAgentIDFromSessionKey(sessionKey);
  if (!sessionKey || !agentID) {
    return null;
  }

  const from = asString(context.from);
  const slackFromSender = slackSenderFromFromField(from);
  let channel =
    asString(context.channelId).toLowerCase() ||
    asString(metadata.provider).toLowerCase() ||
    asString(metadata.surface).toLowerCase();
  if (!channel && slackFromSender) {
    channel = "slack";
  }
  const senderID = asString(metadata.senderId) || slackFromSender;
  const senderE164 = asString(metadata.senderE164);

  const subjectCandidates: string[] = [];
  if (channel === "slack") {
    subjectCandidates.push(senderID, slackFromSender);
  } else {
    subjectCandidates.push(senderE164, senderID);
  }
  subjectCandidates.push(from);
  const subject = subjectCandidates.map((candidate) => asString(candidate)).find(Boolean) || "";

  if (!subject && !senderID && !senderE164 && !from) {
    return null;
  }

  return {
    agent_id: agentID,
    session_key: sessionKey,
    channel,
    from,
    sender_id: senderID,
    sender_e164: senderE164,
    subject,
    updated_at: new Date().toISOString(),
  };
}

function upsertSubjectHint(event: HookEvent, keyRoot: string): void {
  const hint = extractSubjectHint(event);
  if (!hint) {
    return;
  }

  const storePath = resolveSubjectHintsPath(event, keyRoot);
  if (!storePath) {
    return;
  }
  const store = readSubjectHintStore(storePath);
  store.updated_at = hint.updated_at;
  store.by_session[hint.session_key] = hint;
  store.by_agent[hint.agent_id] = hint;
  store.recent = [
    hint,
    ...store.recent.filter((entry) => {
      if (!entry || typeof entry !== "object") {
        return false;
      }
      const sessionKey = asString(entry.session_key);
      if (sessionKey && sessionKey === hint.session_key) {
        return false;
      }
      const stamp = [
        asString(entry.agent_id),
        asString(entry.channel),
        asString(entry.subject),
        asString(entry.sender_id),
        asString(entry.sender_e164),
      ].join("|");
      const nextStamp = [
        hint.agent_id,
        hint.channel,
        hint.subject,
        hint.sender_id,
        hint.sender_e164,
      ].join("|");
      return stamp !== nextStamp;
    }),
  ].slice(0, MAX_RECENT_SUBJECT_HINTS);

  const directory = path.dirname(storePath);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporary = `${storePath}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, `${JSON.stringify(store, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, storePath);
}

function collectRuntimeCredentialFindings(): RuntimeCredentialFinding[] {
  const findings: RuntimeCredentialFinding[] = [];
  const seen = new Set<string>();
  for (const [key, value] of Object.entries(process.env)) {
    const envKey = String(key || "").trim();
    const envValue = String(value || "").trim();
    if (shouldSkipRuntimeCredentialKey(envKey)) {
      continue;
    }
    if (!looksLikeSecretKeyName(envKey) || !looksLikeSecretValue(envValue)) {
      continue;
    }
    const signature = `${envKey.toUpperCase()}|${envValue}`;
    if (seen.has(signature)) {
      continue;
    }
    seen.add(signature);

    const provider = inferProviderFromText(envKey) || inferProviderFromText(envValue) || "unknown";
    const variable = normalizeVariableKey(envKey) || normalizeVariableKey(`${provider}_API_KEY`) || "SIGILUM_IMPORTED_KEY";
    findings.push({
      provider,
      field: envKey,
      variable,
      value: envValue,
      source_path: "openclaw_runtime_env",
      location: `process.env.${envKey}`,
    });
  }
  findings.sort((left, right) => left.field.localeCompare(right.field));
  return findings;
}

function writeRuntimeCredentialReport(event: HookEvent, keyRoot: string): void {
  const reportPath = resolveRuntimeCredentialReportPath(event, keyRoot);
  if (!reportPath) {
    return;
  }
  const findings = collectRuntimeCredentialFindings();
  const payload: RuntimeCredentialReport = {
    generated_at: new Date().toISOString(),
    findings,
  };

  const directory = path.dirname(reportPath);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
}

function isGatewayStartupEvent(event: HookEvent): boolean {
  return event.type === "gateway" && event.action === "startup";
}

function isReloadEvent(event: HookEvent): boolean {
  const type = String(event.type || "").toLowerCase();
  const action = String(event.action || "").toLowerCase();
  if (type === "reload" || type === "config") {
    return true;
  }
  if (type === "gateway" && action.includes("reload")) {
    return true;
  }
  return action.includes("reload");
}

function shouldRun(event: HookEvent): boolean {
  return (
    (event.type === "gateway" && event.action === "startup") ||
    (event.type === "command" && event.action === "new") ||
    isMessageReceivedEvent(event) ||
    isReloadEvent(event)
  );
}

function dashboardOrigin(url: string): string {
  const value = String(url || "").trim();
  if (!value) return "";
  try {
    const parsed = new URL(value);
    return `${parsed.protocol}//${parsed.host}`.replace(/\/+$/g, "");
  } catch {
    return value.replace(/\/+$/g, "");
  }
}

function buildPasskeySetupUrl(dashboardUrl: string, namespace: string): string {
  const origin = dashboardOrigin(dashboardUrl);
  const ns = String(namespace || "").trim();
  if (!origin || !ns) return "";
  return `${origin}/bootstrap/passkey?namespace=${encodeURIComponent(ns)}`;
}

function normalizeGatewayBaseURL(value: string): string {
  return String(value || "").trim().replace(/\/+$/g, "");
}

async function listGatewayConnections(
  gatewayURL: string,
  gatewayAdminToken: string,
): Promise<GatewayConnection[]> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = String(gatewayAdminToken || "").trim();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${normalizeGatewayBaseURL(gatewayURL)}/api/admin/connections`, {
    method: "GET",
    headers,
  });
  if (!response.ok) {
    throw new Error(`list connections failed (${response.status})`);
  }
  const payload = (await response.json()) as GatewayConnectionsResponse;
  return Array.isArray(payload.connections) ? payload.connections : [];
}

function selectActiveSecureMCPConnections(connections: GatewayConnection[]): string[] {
  const ids = selectActiveSecureConnections(connections)
    .filter((connection) => String(connection.protocol || "").trim().toLowerCase() === "mcp")
    .map((connection) => String(connection.id || "").trim())
    .filter((id) => id.length > 0);
  return [...new Set(ids)].sort();
}

function selectActiveSecureConnections(connections: GatewayConnection[]): GatewayConnection[] {
  return connections.filter((connection) => {
    const id = String(connection.id || "").trim();
    const status = String(connection.status || "").trim().toLowerCase();
    return (
      id.startsWith("sigilum-secure-") &&
      (status === "" || status === "active")
    );
  });
}

function providerAliasMap(connections: GatewayConnection[]): Array<{ provider: string; connectionID: string; protocol: string }> {
  const byProvider = new Map<string, { provider: string; connectionID: string; protocol: string }>();
  for (const connection of selectActiveSecureConnections(connections)) {
    const connectionID = String(connection.id || "").trim();
    if (!connectionID) continue;
    const provider = providerFromConnectionID(connectionID);
    if (!provider) continue;
    const protocol = String(connection.protocol || "").trim().toLowerCase() || "unknown";
    if (!byProvider.has(provider)) {
      byProvider.set(provider, { provider, connectionID, protocol });
      continue;
    }
    const current = byProvider.get(provider)!;
    if (current.protocol !== "mcp" && protocol === "mcp") {
      byProvider.set(provider, { provider, connectionID, protocol });
    }
  }
  return [...byProvider.values()].sort((left, right) => left.provider.localeCompare(right.provider));
}

async function listActiveSigilumConnections(
  gatewayURL: string,
  gatewayAdminToken: string,
): Promise<GatewayConnection[]> {
  const connections = await listGatewayConnections(gatewayURL, gatewayAdminToken);
  return selectActiveSecureConnections(connections);
}

function providerFromConnectionID(connectionID: string): string {
  const id = String(connectionID || "").trim();
  const prefix = "sigilum-secure-";
  if (!id.startsWith(prefix)) {
    return "";
  }
  return id.slice(prefix.length).trim();
}

function buildGatewayPolicyMessage(gatewayURL: string, secureConnections: GatewayConnection[]): string {
  const mcpConnections = selectActiveSecureMCPConnections(secureConnections);
  const aliases = providerAliasMap(secureConnections);
  const lines: string[] = [
    "Sigilum gateway-first policy:",
    "- Use Sigilum gateway as the default provider path.",
    "- For provider capability questions (for example: \"can you access linear?\"):",
    "  1) Derive connection id: sigilum-secure-<provider>",
    "  2) Run signed runtime check via helper: gateway-admin.sh tools <connection_id> (auto-routes mcp/proxy when protocol metadata is available)",
    "  3) Answer from HTTP_STATUS (200=yes, 401/403=auth required, 404=missing connection)",
    "  4) If APPROVAL_REQUIRED=true, include APPROVAL_NAMESPACE + APPROVAL_AGENT_ID + APPROVAL_PUBLIC_KEY in the approval request to the user.",
    "  5) Do not truncate helper output to first lines; parse full output including APPROVAL_* fields.",
    "- Negative-answer gate: before saying \"no integration\", \"no access\", or requesting direct provider credentials, run the signed tools check first.",
    "- Do not infer gateway restart bugs from 401/403 alone; treat APPROVAL_REQUIRED=true as authorization-required-now (new/revoked/expired).",
    "- Do not ask for direct provider API keys unless gateway connection is missing/disabled/test fails.",
    `- Gateway URL: ${normalizeGatewayBaseURL(gatewayURL) || "<unset>"}`,
    "- Enforce per-agent registration: runtime checks must be signed and claim-gated.",
    "- Do not use /api/admin/* as capability checks (admin bypass path).",
    "- Runtime endpoints:",
    "  - GET /mcp/{connection_id}/tools",
    "  - POST /mcp/{connection_id}/tools/{tool}/call",
    "  - /proxy/{connection_id}/... for protocol=http connections",
  ];

  if (aliases.length > 0) {
    lines.push("- Provider alias map (authoritative for this session):");
    for (const alias of aliases) {
      lines.push(`  - ${alias.provider} -> ${alias.connectionID} (${alias.protocol})`);
    }
  } else {
    lines.push("- Provider alias map: none discovered.");
  }

  if (mcpConnections.length > 0) {
    lines.push("- Active Sigilum MCP connections:");
    for (const id of mcpConnections) {
      const provider = providerFromConnectionID(id);
      if (provider) {
        lines.push(`  - ${id} (provider=${provider})`);
      } else {
        lines.push(`  - ${id}`);
      }
    }
  } else {
    lines.push("- Active Sigilum MCP connections: none discovered.");
  }

  if (mcpConnections.includes("sigilum-secure-linear")) {
    lines.push(
      "- Linear route present: sigilum-secure-linear. Prefer gateway path before requesting a direct Linear API key.",
    );
  }

  return lines.join("\n");
}

const handler: HookHandler = async (event) => {
  if (!shouldRun(event)) {
    return;
  }

  try {
    const cfg = resolveSigilumPluginConfig(event);
    if (isMessageReceivedEvent(event)) {
      try {
        upsertSubjectHint(event, cfg.keyRoot);
      } catch (err) {
        console.error(
          "[sigilum-plugin] subject hint capture failed:",
          err instanceof Error ? err.message : String(err),
        );
      }
      return;
    }

    if (isGatewayStartupEvent(event) || isReloadEvent(event)) {
      try {
        writeRuntimeCredentialReport(event, cfg.keyRoot);
      } catch (err) {
        console.error(
          "[sigilum-plugin] runtime credential report failed:",
          err instanceof Error ? err.message : String(err),
        );
      }
    }
    if (isGatewayStartupEvent(event)) {
      const passkeySetupUrl = buildPasskeySetupUrl(cfg.dashboardUrl, cfg.namespace);
      console.log(
        `[sigilum-plugin] namespace=${cfg.namespace || "<unset>"} api=${cfg.apiUrl} gateway=${cfg.gatewayUrl}`,
      );
      console.log(`[sigilum-plugin] dashboard=${cfg.dashboardUrl}`);
      if (passkeySetupUrl) {
        console.log(`[sigilum-plugin] passkey_setup=${passkeySetupUrl}`);
      }
    }

    let secureConnections: GatewayConnection[] = [];
    try {
      secureConnections = await listActiveSigilumConnections(cfg.gatewayUrl, cfg.gatewayAdminToken);
    } catch (err) {
      console.error(
        "[sigilum-plugin] mcp discovery inventory failed:",
        err instanceof Error ? err.message : String(err),
      );
    }
    event.messages.push(buildGatewayPolicyMessage(cfg.gatewayUrl, secureConnections));

    if (!cfg.autoBootstrapAgents) {
      return;
    }

    if (!cfg.namespace) {
      event.messages.push(
        "Sigilum hook: SIGILUM_NAMESPACE is not configured. Skipping agent key bootstrap.",
      );
      return;
    }

    const agentIDs = collectAgentIDs(event);
    const created: string[] = [];
    const existing: string[] = [];

    for (const agentID of agentIDs) {
      const result = ensureAgentKeypair(agentID, cfg.keyRoot);
      if (result.created) {
        created.push(agentID);
      } else {
        existing.push(agentID);
      }
    }

    if (created.length > 0) {
      event.messages.push(
        [
          "Sigilum identities bootstrapped.",
          `Created: ${created.join(", ")}`,
          `Existing: ${existing.length > 0 ? existing.join(", ") : "none"}`,
          `Namespace: ${cfg.namespace}`,
          `Key root: ${cfg.keyRoot}`,
        ].join("\n"),
      );
    }
  } catch (err) {
    console.error(
      "[sigilum-plugin] bootstrap error:",
      err instanceof Error ? err.message : String(err),
    );
  }
};

export default handler;
