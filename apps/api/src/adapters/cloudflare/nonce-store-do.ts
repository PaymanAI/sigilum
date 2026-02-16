import type { Env } from "../../types.js";

type CheckRequest = {
  service?: string;
  nonce?: string;
  ttlSeconds?: number;
};

const DEFAULT_TTL_SECONDS = 600;
const MAX_TTL_SECONDS = 86_400;
const MIN_TTL_SECONDS = 1;
const KEY_PREFIX = "nonce:";

export class NonceStoreDurableObject {
  constructor(
    private readonly state: DurableObjectState,
    private readonly _env: Env,
  ) {}

  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    const url = new URL(request.url);
    if (url.pathname !== "/check") {
      return new Response("Not found", { status: 404 });
    }

    let payload: CheckRequest;
    try {
      payload = await request.json<CheckRequest>();
    } catch {
      return Response.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    const service = payload.service?.trim();
    const nonce = payload.nonce?.trim();
    if (!service || !nonce) {
      return Response.json(
        { error: "service and nonce are required" },
        { status: 400 },
      );
    }

    const ttlRaw = payload.ttlSeconds ?? DEFAULT_TTL_SECONDS;
    const ttlSeconds = Math.max(
      MIN_TTL_SECONDS,
      Math.min(MAX_TTL_SECONDS, Math.floor(ttlRaw)),
    );

    const now = Date.now();
    const key = `${KEY_PREFIX}${service}:${nonce}`;
    const existingExpiry = await this.state.storage.get<number>(key);
    if (typeof existingExpiry === "number" && existingExpiry > now) {
      return Response.json({ replay: true });
    }

    const expiresAt = now + ttlSeconds * 1000;
    await this.state.storage.put(key, expiresAt);
    await this.ensureAlarmScheduled(expiresAt);

    return Response.json({ replay: false });
  }

  async alarm(): Promise<void> {
    const now = Date.now();
    const entries = await this.state.storage.list<number>({ prefix: KEY_PREFIX });

    let nextExpiry: number | null = null;
    const deletes: string[] = [];
    for (const [key, expiresAt] of entries) {
      if (typeof expiresAt !== "number") continue;
      if (expiresAt <= now) {
        deletes.push(key);
      } else if (nextExpiry === null || expiresAt < nextExpiry) {
        nextExpiry = expiresAt;
      }
    }

    if (deletes.length > 0) {
      await this.state.storage.delete(deletes);
    }
    if (nextExpiry !== null) {
      await this.state.storage.setAlarm(nextExpiry);
    }
  }

  private async ensureAlarmScheduled(candidateExpiry: number): Promise<void> {
    const current = await this.state.storage.getAlarm();
    if (current === null || candidateExpiry < current) {
      await this.state.storage.setAlarm(candidateExpiry);
    }
  }
}
