import { collectAgentIDs, resolveSigilumPluginConfig, type HookEvent } from "./config.ts";
import { ensureAgentKeypair } from "./keys.ts";

type HookHandler = (event: HookEvent) => Promise<void>;

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

const handler: HookHandler = async (event) => {
  if (!shouldRun(event)) {
    return;
  }

  try {
    const cfg = resolveSigilumPluginConfig(event);
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
