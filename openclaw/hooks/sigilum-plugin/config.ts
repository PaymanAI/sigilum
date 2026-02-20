import * as os from "node:os";
import * as path from "node:path";

export interface SigilumPluginConfig {
  namespace: string;
  apiUrl: string;
  gatewayUrl: string;
  gatewayAdminToken: string;
  dashboardUrl: string;
  keyRoot: string;
  autoBootstrapAgents: boolean;
}

const DEFAULT_API_URL = "https://api.sigilum.id";
const DEFAULT_GATEWAY_URL = "http://localhost:38100";
const DEFAULT_DASHBOARD_URL = "https://sigilum.id";
const DEFAULT_KEY_ROOT = path.join(os.homedir(), ".openclaw", ".sigilum", "keys");
const DEFAULT_AGENT_ID = "default";

export interface HookEvent {
  type: string;
  action: string;
  sessionKey: string;
  timestamp: Date;
  messages: string[];
  context: {
    cfg?: Record<string, unknown>;
    config?: Record<string, unknown>;
    [key: string]: unknown;
  };
}

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

function parseBool(value: string | undefined, fallback: boolean): boolean {
  if (!value) {
    return fallback;
  }
  switch (value.trim().toLowerCase()) {
    case "1":
    case "true":
    case "yes":
    case "on":
      return true;
    case "0":
    case "false":
    case "no":
    case "off":
      return false;
    default:
      return fallback;
  }
}

function readHookEnv(cfg: Record<string, unknown>, hookName: string): Record<string, unknown> {
  const hooks = asObject(cfg.hooks);
  const internal = asObject(hooks.internal);
  const entries = asObject(internal.entries);
  const hookEntry = asObject(entries[hookName]);
  return asObject(hookEntry.env);
}

function resolveConfigObject(event: HookEvent): Record<string, unknown> {
  const fromCfg = asObject(event.context?.cfg);
  if (Object.keys(fromCfg).length > 0) {
    return fromCfg;
  }
  return asObject(event.context?.config);
}

export function resolveSigilumPluginConfig(event: HookEvent): SigilumPluginConfig {
  const cfg = resolveConfigObject(event);
  const hookEnv = readHookEnv(cfg, "sigilum-plugin");

  const namespace =
    asString(process.env.SIGILUM_NAMESPACE) ||
    asString(hookEnv.SIGILUM_NAMESPACE);

  const apiUrl =
    asString(process.env.SIGILUM_API_URL) ||
    asString(hookEnv.SIGILUM_API_URL) ||
    DEFAULT_API_URL;

  const gatewayUrl =
    asString(process.env.SIGILUM_GATEWAY_URL) ||
    asString(hookEnv.SIGILUM_GATEWAY_URL) ||
    DEFAULT_GATEWAY_URL;

  const dashboardUrl =
    asString(process.env.SIGILUM_DASHBOARD_URL) ||
    asString(hookEnv.SIGILUM_DASHBOARD_URL) ||
    DEFAULT_DASHBOARD_URL;

  const gatewayAdminToken =
    asString(process.env.SIGILUM_GATEWAY_ADMIN_TOKEN) ||
    asString(hookEnv.SIGILUM_GATEWAY_ADMIN_TOKEN);

  const keyRoot =
    asString(process.env.SIGILUM_KEY_ROOT) ||
    asString(hookEnv.SIGILUM_KEY_ROOT) ||
    DEFAULT_KEY_ROOT;

  const autoBootstrapAgents = parseBool(
    asString(process.env.SIGILUM_AUTO_BOOTSTRAP_AGENTS) ||
      asString(hookEnv.SIGILUM_AUTO_BOOTSTRAP_AGENTS),
    true,
  );

  return {
    namespace,
    apiUrl,
    gatewayUrl,
    gatewayAdminToken,
    dashboardUrl,
    keyRoot,
    autoBootstrapAgents,
  };
}

function collectAllowedSubagentIDs(source: Record<string, unknown>, ids: Set<string>): void {
  const subagents = asObject(source.subagents);
  const allowAgents = subagents.allowAgents;
  if (!Array.isArray(allowAgents)) {
    return;
  }

  for (const entry of allowAgents) {
    const id = asString(entry);
    if (id) {
      ids.add(id);
    }
  }
}

export function collectAgentIDs(event: HookEvent): string[] {
  const cfg = resolveConfigObject(event);
  const ids = new Set<string>();
  ids.add(DEFAULT_AGENT_ID);

  const agents = asObject(cfg.agents);
  const defaults = asObject(agents.defaults);
  const defaultsId = asString(defaults.id);
  if (defaultsId) {
    ids.add(defaultsId);
  }
  collectAllowedSubagentIDs(defaults, ids);

  const list = agents.list;
  if (Array.isArray(list)) {
    for (const item of list) {
      const agent = asObject(item);
      const id = asString(agent.id);
      if (id) {
        ids.add(id);
      }
      collectAllowedSubagentIDs(agent, ids);
    }
  }

  return [...ids];
}
