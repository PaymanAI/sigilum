interface HookEvent {
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

type HookHandler = (event: HookEvent) => Promise<void>;

type PendingAuthorization = {
  service: string;
  public_key: string;
  agent_ip?: string;
  created_at?: string;
};

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

function readHookEnv(event: HookEvent): Record<string, unknown> {
  const cfg = asObject(event.context?.cfg);
  const config = Object.keys(cfg).length > 0 ? cfg : asObject(event.context?.config);
  const hooks = asObject(config.hooks);
  const internal = asObject(hooks.internal);
  const entries = asObject(internal.entries);
  const hook = asObject(entries["sigilum-authz-notify"]);
  return asObject(hook.env);
}

function resolveNamespace(event: HookEvent): string {
  const hookEnv = readHookEnv(event);
  return asString(process.env.SIGILUM_NAMESPACE) || asString(hookEnv.SIGILUM_NAMESPACE);
}

function resolveOwnerToken(event: HookEvent): string {
  const hookEnv = readHookEnv(event);
  return asString(process.env.SIGILUM_OWNER_TOKEN) || asString(hookEnv.SIGILUM_OWNER_TOKEN);
}

function resolveApiUrl(event: HookEvent): string {
  const hookEnv = readHookEnv(event);
  const raw =
    asString(process.env.SIGILUM_API_URL) ||
    asString(hookEnv.SIGILUM_API_URL) ||
    "https://api.sigilum.id";
  return raw.replace(/\/+$/, "");
}

function resolveDashboardUrl(event: HookEvent): string {
  const hookEnv = readHookEnv(event);
  return (
    asString(process.env.SIGILUM_DASHBOARD_URL) ||
    asString(hookEnv.SIGILUM_DASHBOARD_URL) ||
    "https://sigilum.id/dashboard"
  );
}

function shouldRun(event: HookEvent): boolean {
  return (
    (event.type === "gateway" && event.action === "startup") ||
    (event.type === "command" && event.action === "new")
  );
}

function timeAgo(raw: string | undefined): string {
  if (!raw) {
    return "unknown time";
  }
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) {
    return "unknown time";
  }

  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) {
    return `${seconds}s ago`;
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

const handler: HookHandler = async (event) => {
  if (!shouldRun(event)) {
    return;
  }

  const namespace = resolveNamespace(event);
  const ownerToken = resolveOwnerToken(event);
  if (!namespace || !ownerToken) {
    return;
  }

  const apiUrl = resolveApiUrl(event);
  const dashboardUrl = resolveDashboardUrl(event);

  try {
    const response = await fetch(
      `${apiUrl}/v1/namespaces/${encodeURIComponent(namespace)}/claims?status=pending&limit=20`,
      {
        headers: {
          Authorization: `Bearer ${ownerToken}`,
        },
      },
    );

    if (response.status === 401 || response.status === 403) {
      console.log("[sigilum-authz-notify] owner token is invalid or unauthorized");
      return;
    }

    if (!response.ok) {
      console.log(`[sigilum-authz-notify] lookup failed: HTTP ${response.status}`);
      return;
    }

    const payload = (await response.json()) as {
      claims?: PendingAuthorization[];
      pagination?: { total?: number };
    };

    const pending = Array.isArray(payload.claims)
      ? payload.claims.filter((row) => true)
      : [];

    if (pending.length === 0) {
      return;
    }

    const total = typeof payload.pagination?.total === "number" ? payload.pagination.total : pending.length;
    const lines = [
      `Sigilum: ${total} pending authorization request${total === 1 ? "" : "s"}.`,
      "",
    ];

    for (const row of pending.slice(0, 5)) {
      const keyShort = row.public_key ? `${row.public_key.slice(0, 20)}...` : "unknown-key";
      const ipPart = row.agent_ip ? `, ip=${row.agent_ip}` : "";
      lines.push(`- service=${row.service} key=${keyShort}${ipPart} (${timeAgo(row.created_at)})`);
    }

    if (total > 5) {
      lines.push(`- ...and ${total - 5} more`);
    }

    lines.push("");
    lines.push(`Review: ${dashboardUrl}`);

    event.messages.push(lines.join("\n"));
  } catch (err) {
    console.error(
      "[sigilum-authz-notify] error:",
      err instanceof Error ? err.message : String(err),
    );
  }
};

export default handler;
