import { collectAgentIDs, resolveSigilumPluginConfig, type HookEvent } from "./config.ts";
import { ensureAgentKeypair } from "./keys.ts";

type HookHandler = (event: HookEvent) => Promise<void>;

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
