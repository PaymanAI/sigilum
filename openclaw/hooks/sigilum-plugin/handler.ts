import { collectAgentIDs, resolveSigilumPluginConfig, type HookEvent } from "./config.ts";
import { ensureAgentKeypair } from "./keys.ts";

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
  const ids = connections
    .filter((connection) => {
      const id = String(connection.id || "").trim();
      const protocol = String(connection.protocol || "").trim().toLowerCase();
      const status = String(connection.status || "").trim().toLowerCase();
      return (
        id.startsWith("sigilum-secure-") &&
        protocol === "mcp" &&
        (status === "" || status === "active")
      );
    })
    .map((connection) => String(connection.id || "").trim())
    .filter((id) => id.length > 0);
  return [...new Set(ids)].sort();
}

async function listActiveSigilumMCPConnections(
  gatewayURL: string,
  gatewayAdminToken: string,
): Promise<string[]> {
  const connections = await listGatewayConnections(gatewayURL, gatewayAdminToken);
  return selectActiveSecureMCPConnections(connections);
}

function providerFromConnectionID(connectionID: string): string {
  const id = String(connectionID || "").trim();
  const prefix = "sigilum-secure-";
  if (!id.startsWith(prefix)) {
    return "";
  }
  return id.slice(prefix.length).trim();
}

function buildGatewayPolicyMessage(gatewayURL: string, mcpConnections: string[]): string {
  const lines: string[] = [
    "Sigilum gateway-first policy:",
    "- Use Sigilum gateway as the default provider path.",
    "- For provider capability questions (for example: \"can you access linear?\"):",
    "  1) Derive connection id: sigilum-secure-<provider>",
    "  2) Run signed runtime check via helper: gateway-admin.sh tools <connection_id>",
    "  3) Answer from HTTP_STATUS (200=yes, 401/403=auth required, 404=missing connection)",
    "  4) If APPROVAL_REQUIRED=true, include APPROVAL_NAMESPACE + APPROVAL_AGENT_ID + APPROVAL_PUBLIC_KEY in the approval request to the user.",
    "- Do not ask for direct provider API keys unless gateway connection is missing/disabled/test fails.",
    `- Gateway URL: ${normalizeGatewayBaseURL(gatewayURL) || "<unset>"}`,
    "- Enforce per-agent registration: runtime checks must be signed and claim-gated.",
    "- Do not use /api/admin/* as capability checks (admin bypass path).",
    "- Runtime endpoints:",
    "  - GET /mcp/{connection_id}/tools",
    "  - POST /mcp/{connection_id}/tools/{tool}/call",
  ];

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

    let mcpConnections: string[] = [];
    try {
      mcpConnections = await listActiveSigilumMCPConnections(cfg.gatewayUrl, cfg.gatewayAdminToken);
    } catch (err) {
      console.error(
        "[sigilum-plugin] mcp discovery inventory failed:",
        err instanceof Error ? err.message : String(err),
      );
    }
    event.messages.push(buildGatewayPolicyMessage(cfg.gatewayUrl, mcpConnections));

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
