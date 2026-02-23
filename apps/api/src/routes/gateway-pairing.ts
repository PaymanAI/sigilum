import { Hono } from "hono";
import type { Context } from "hono";
import { z } from "zod";
import type { Env } from "../types.js";
import { createErrorResponse } from "../utils/validation.js";
import { getBearerToken, verifyJWT } from "./auth.js";

export const gatewayPairingRouter = new Hono<{ Bindings: Env }>();

const startPairingBodySchema = z.object({
  namespace: z.string().trim().min(3).max(64).optional(),
  ttl_seconds: z.number().int().min(30).max(3600).optional(),
});

const commandBodySchema = z.object({
  session_id: z.string().trim().min(1),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
  path: z.string().trim().min(1),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.string().nullable().optional(),
  timeout_ms: z.number().int().min(1000).max(60000).optional(),
});

type StubRequest = RequestInit & { body?: string };

function randomPairCode(length = 8): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = "";
  for (const byte of bytes) {
    out += alphabet[byte % alphabet.length];
  }
  return out;
}

async function requireAuthenticatedUser(c: Context<{ Bindings: Env }>) {
  const token = getBearerToken(c);
  if (!token) return null;
  return verifyJWT(c.env, token);
}

function getPairingStub(env: Env, sessionId: string) {
  if (!env.GATEWAY_PAIRING_DO) {
    throw new Error("GATEWAY_PAIRING_DO binding is required");
  }
  const id = env.GATEWAY_PAIRING_DO.idFromName(sessionId);
  return env.GATEWAY_PAIRING_DO.get(id);
}

async function callStubJSON(stub: DurableObjectStub, path: string, init: StubRequest) {
  const response = await stub.fetch(`https://gateway-pair${path}`, init);
  const payload = await response.json<unknown>().catch(() => ({}));
  return { response, payload };
}

function buildWsUrl(requestUrl: string, sessionId: string, namespace: string, pairCode: string): string {
  const base = new URL(requestUrl);
  base.protocol = base.protocol === "https:" ? "wss:" : "ws:";
  base.pathname = "/v1/gateway/pairing/connect";
  base.searchParams.set("session_id", sessionId);
  base.searchParams.set("namespace", namespace);
  base.searchParams.set("code", pairCode);
  return base.toString();
}

/**
 * GET /v1/gateway/pairing/connect?session_id=...&namespace=...&code=...
 * Upgrade endpoint used by the local gateway bridge websocket client.
 */
gatewayPairingRouter.get("/connect", async (c) => {
  const sessionId = c.req.query("session_id")?.trim();
  const namespace = c.req.query("namespace")?.trim();
  const code = c.req.query("code")?.trim();
  if (!sessionId || !namespace || !code) {
    return c.json(createErrorResponse("session_id, namespace, and code are required", "VALIDATION_ERROR"), 400);
  }

  const stub = getPairingStub(c.env, sessionId);
  const headers = new Headers(c.req.raw.headers);
  const target = new URL("https://gateway-pair/connect");
  target.searchParams.set("namespace", namespace);
  target.searchParams.set("code", code);

  return stub.fetch(target.toString(), {
    method: "GET",
    headers,
  });
});

/**
 * POST /v1/gateway/pairing/start
 * Start a short-lived pairing session used by a local gateway bridge websocket.
 */
gatewayPairingRouter.post("/start", async (c) => {
  const user = await requireAuthenticatedUser(c);
  if (!user) {
    return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);
  }

  let body: z.infer<typeof startPairingBodySchema>;
  try {
    body = startPairingBodySchema.parse(await c.req.json().catch(() => ({})));
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json(createErrorResponse("Validation failed", "VALIDATION_ERROR", err.issues), 400);
    }
    return c.json(createErrorResponse("Invalid request body", "INVALID_JSON"), 400);
  }

  const namespace = (body.namespace ?? user.namespace).trim();
  if (namespace !== user.namespace) {
    return c.json(createErrorResponse("Namespace mismatch for authenticated user", "FORBIDDEN"), 403);
  }

  const sessionId = crypto.randomUUID();
  const pairCode = randomPairCode(8);
  const ttlSeconds = body.ttl_seconds ?? 600;
  const expiresAt = Date.now() + (ttlSeconds * 1000);

  const stub = getPairingStub(c.env, sessionId);
  const { response, payload } = await callStubJSON(stub, "/init", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      owner_user_id: user.userId,
      namespace,
      pair_code: pairCode,
      expires_at: expiresAt,
    }),
  });

  if (!response.ok) {
    return c.json(
      createErrorResponse(`Failed to initialize pairing session: ${JSON.stringify(payload)}`, "INTERNAL_ERROR"),
      500,
    );
  }

  return c.json({
    session_id: sessionId,
    namespace,
    pair_code: pairCode,
    expires_at: new Date(expiresAt).toISOString(),
    ws_url: buildWsUrl(c.req.url, sessionId, namespace, pairCode),
  });
});

/**
 * GET /v1/gateway/pairing/status?session_id=...
 * Returns connection state for the pairing session.
 */
gatewayPairingRouter.get("/status", async (c) => {
  const user = await requireAuthenticatedUser(c);
  if (!user) {
    return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);
  }

  const sessionId = c.req.query("session_id")?.trim();
  if (!sessionId) {
    return c.json(createErrorResponse("session_id is required", "VALIDATION_ERROR"), 400);
  }

  const stub = getPairingStub(c.env, sessionId);
  const { response, payload } = await callStubJSON(stub, "/status", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ owner_user_id: user.userId }),
  });

  if (response.status === 404) {
    return c.json(createErrorResponse("Pair session not found", "NOT_FOUND"), 404);
  }
  if (response.status === 403) {
    return c.json(createErrorResponse("Not authorized for this pair session", "FORBIDDEN"), 403);
  }
  if (!response.ok) {
    return c.json(createErrorResponse("Failed to read pairing status", "INTERNAL_ERROR"), 500);
  }

  return c.json(payload);
});

/**
 * POST /v1/gateway/pairing/command
 * Relay an admin command to the paired local gateway.
 */
gatewayPairingRouter.post("/command", async (c) => {
  const user = await requireAuthenticatedUser(c);
  if (!user) {
    return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);
  }

  let body: z.infer<typeof commandBodySchema>;
  try {
    body = commandBodySchema.parse(await c.req.json());
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json(createErrorResponse("Validation failed", "VALIDATION_ERROR", err.issues), 400);
    }
    return c.json(createErrorResponse("Invalid request body", "INVALID_JSON"), 400);
  }

  const stub = getPairingStub(c.env, body.session_id);
  const { response, payload } = await callStubJSON(stub, "/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      owner_user_id: user.userId,
      method: body.method,
      path: body.path,
      headers: body.headers ?? {},
      body: body.body ?? null,
      timeout_ms: body.timeout_ms,
    }),
  });

  if (response.status === 404) {
    return c.json(createErrorResponse("Pair session not found", "NOT_FOUND"), 404);
  }
  if (response.status === 403) {
    return c.json(createErrorResponse("Not authorized for this pair session", "FORBIDDEN"), 403);
  }
  if (response.status === 503) {
    return c.json(createErrorResponse("Gateway is not connected", "GATEWAY_NOT_CONNECTED"), 503);
  }
  if (!response.ok) {
    return c.json(createErrorResponse("Gateway relay command failed", "GATEWAY_RELAY_FAILED"), response.status as 500);
  }

  return c.json(payload);
});
