import type { Env } from "../../types.js";

type PairSessionRecord = {
  owner_user_id: string;
  namespace: string;
  pair_code: string;
  created_at: number;
  expires_at: number;
  connected: boolean;
  last_connected_at?: number;
};

type InitPayload = {
  owner_user_id?: string;
  namespace?: string;
  pair_code?: string;
  expires_at?: number;
};

type StatusPayload = {
  owner_user_id?: string;
};

type CommandPayload = {
  owner_user_id?: string;
  method?: string;
  path?: string;
  headers?: Record<string, string>;
  body?: string | null;
  timeout_ms?: number;
};

type GatewayResponseMessage = {
  type: "response";
  request_id: string;
  status?: number;
  headers?: Record<string, string>;
  body?: string | null;
  error?: string;
};

type PendingCommand = {
  resolve: (value: GatewayResponseMessage) => void;
  reject: (reason?: unknown) => void;
  timer: number;
};

const STORAGE_SESSION_KEY = "session";
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_TIMEOUT_MS = 60_000;

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export class GatewayPairingDurableObject {
  private gatewaySocket: WebSocket | null = null;
  private readonly pending = new Map<string, PendingCommand>();

  constructor(
    private readonly state: DurableObjectState,
    private readonly _env: Env,
  ) {
    const sockets = this.state.getWebSockets();
    if (sockets.length > 0) {
      this.gatewaySocket = sockets[0] ?? null;
      for (let i = 1; i < sockets.length; i += 1) {
        try {
          sockets[i]?.close(1000, "replaced");
        } catch {
          // ignore
        }
      }
    }
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/init" && request.method === "POST") {
      return this.handleInit(request);
    }
    if (url.pathname === "/status" && request.method === "POST") {
      return this.handleStatus(request);
    }
    if (url.pathname === "/command" && request.method === "POST") {
      return this.handleCommand(request);
    }
    if (url.pathname === "/connect" && request.method === "GET") {
      return this.handleConnect(request, url);
    }
    return json({ error: "Not found" }, 404);
  }

  async webSocketMessage(_ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const text =
      typeof message === "string"
        ? message
        : new TextDecoder().decode(new Uint8Array(message));

    let parsed: GatewayResponseMessage | null = null;
    try {
      parsed = JSON.parse(text) as GatewayResponseMessage;
    } catch {
      return;
    }

    if (!parsed || parsed.type !== "response" || !parsed.request_id) {
      return;
    }

    const pending = this.pending.get(parsed.request_id);
    if (!pending) return;
    this.pending.delete(parsed.request_id);
    clearTimeout(pending.timer);
    pending.resolve(parsed);
  }

  async webSocketClose(_ws: WebSocket): Promise<void> {
    this.gatewaySocket = null;
    await this.markDisconnected();
    this.rejectAllPending(new Error("Gateway disconnected"));
  }

  private async handleInit(request: Request): Promise<Response> {
    let payload: InitPayload;
    try {
      payload = await request.json<InitPayload>();
    } catch {
      return json({ error: "Invalid JSON body" }, 400);
    }

    const ownerUserId = payload.owner_user_id?.trim();
    const namespace = payload.namespace?.trim();
    const pairCode = payload.pair_code?.trim();
    const expiresAt = Number(payload.expires_at);

    if (!ownerUserId || !namespace || !pairCode || !Number.isFinite(expiresAt)) {
      return json({ error: "owner_user_id, namespace, pair_code, and expires_at are required" }, 400);
    }

    const record: PairSessionRecord = {
      owner_user_id: ownerUserId,
      namespace,
      pair_code: pairCode,
      created_at: Date.now(),
      expires_at: expiresAt,
      connected: false,
    };

    await this.state.storage.put(STORAGE_SESSION_KEY, record);
    return json({ ok: true });
  }

  private async handleStatus(request: Request): Promise<Response> {
    let payload: StatusPayload;
    try {
      payload = await request.json<StatusPayload>();
    } catch {
      return json({ error: "Invalid JSON body" }, 400);
    }

    const ownerUserId = payload.owner_user_id?.trim();
    if (!ownerUserId) return json({ error: "owner_user_id is required" }, 400);

    const record = await this.getSessionRecord();
    if (!record) return json({ error: "Pair session not found" }, 404);
    if (record.owner_user_id !== ownerUserId) return json({ error: "Forbidden" }, 403);

    const connected = this.isGatewayConnected();
    if (record.connected !== connected) {
      record.connected = connected;
      await this.state.storage.put(STORAGE_SESSION_KEY, record);
    }

    return json({
      connected,
      namespace: record.namespace,
      expires_at: record.expires_at,
      last_connected_at: record.last_connected_at ?? null,
    });
  }

  private async handleCommand(request: Request): Promise<Response> {
    let payload: CommandPayload;
    try {
      payload = await request.json<CommandPayload>();
    } catch {
      return json({ error: "Invalid JSON body" }, 400);
    }

    const ownerUserId = payload.owner_user_id?.trim();
    const method = payload.method?.trim().toUpperCase();
    const path = payload.path?.trim();
    const headers = payload.headers ?? {};
    const body = payload.body ?? null;
    const timeoutMs = Math.min(
      Math.max(Number(payload.timeout_ms ?? DEFAULT_TIMEOUT_MS), 1_000),
      MAX_TIMEOUT_MS,
    );

    if (!ownerUserId || !method || !path) {
      return json({ error: "owner_user_id, method, and path are required" }, 400);
    }

    const record = await this.getSessionRecord();
    if (!record) return json({ error: "Pair session not found" }, 404);
    if (record.owner_user_id !== ownerUserId) return json({ error: "Forbidden" }, 403);
    if (record.expires_at <= Date.now()) return json({ error: "Pair session expired" }, 410);
    if (!this.isGatewayConnected()) return json({ error: "Gateway not connected" }, 503);

    const requestId = crypto.randomUUID();
    const responsePromise = new Promise<GatewayResponseMessage>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(requestId);
        reject(new Error("Gateway response timeout"));
      }, timeoutMs);
      this.pending.set(requestId, { resolve, reject, timer: Number(timer) });
    });

    try {
      this.gatewaySocket?.send(JSON.stringify({
        type: "command",
        request_id: requestId,
        method,
        path,
        headers,
        body,
      }));
    } catch (error) {
      const pending = this.pending.get(requestId);
      if (pending) {
        this.pending.delete(requestId);
        clearTimeout(pending.timer);
      }
      return json({ error: `Failed to dispatch command: ${String(error)}` }, 502);
    }

    try {
      const response = await responsePromise;
      return json({
        request_id: requestId,
        status: response.status ?? 500,
        headers: response.headers ?? {},
        body: response.body ?? null,
        error: response.error ?? null,
      });
    } catch (error) {
      return json({ error: String(error) }, 504);
    }
  }

  private async handleConnect(request: Request, url: URL): Promise<Response> {
    const upgrade = request.headers.get("Upgrade")?.toLowerCase();
    if (upgrade !== "websocket") {
      return new Response("Expected websocket upgrade", { status: 426 });
    }

    const namespace = url.searchParams.get("namespace")?.trim();
    const pairCode = url.searchParams.get("code")?.trim();
    if (!namespace || !pairCode) {
      return json({ error: "namespace and code are required" }, 400);
    }

    const record = await this.getSessionRecord();
    if (!record) return json({ error: "Pair session not found" }, 404);
    if (record.expires_at <= Date.now()) return json({ error: "Pair session expired" }, 410);
    if (record.namespace !== namespace) return json({ error: "Namespace mismatch" }, 403);
    if (record.pair_code !== pairCode) return json({ error: "Invalid pair code" }, 403);

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    try {
      if (this.gatewaySocket) {
        try {
          this.gatewaySocket.close(1000, "replaced");
        } catch {
          // ignore
        }
      }
      this.state.acceptWebSocket(server);
      this.gatewaySocket = server;
    } catch (error) {
      return json({ error: `Failed to accept websocket: ${String(error)}` }, 500);
    }

    record.connected = true;
    record.last_connected_at = Date.now();
    await this.state.storage.put(STORAGE_SESSION_KEY, record);

    return new Response(null, { status: 101, webSocket: client });
  }

  private async getSessionRecord(): Promise<PairSessionRecord | null> {
    const value = await this.state.storage.get<PairSessionRecord>(STORAGE_SESSION_KEY);
    if (!value || typeof value !== "object") return null;
    return value;
  }

  private isGatewayConnected(): boolean {
    return this.gatewaySocket?.readyState === 1;
  }

  private async markDisconnected(): Promise<void> {
    const record = await this.getSessionRecord();
    if (!record) return;
    if (!record.connected) return;
    record.connected = false;
    await this.state.storage.put(STORAGE_SESSION_KEY, record);
  }

  private rejectAllPending(error: Error): void {
    for (const [requestId, pending] of this.pending.entries()) {
      this.pending.delete(requestId);
      clearTimeout(pending.timer);
      pending.reject(error);
    }
  }
}
