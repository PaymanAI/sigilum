import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger as honoLogger } from "hono/logger";
import { prettyJSON } from "hono/pretty-json";
import { namespacesRouter } from "./routes/namespaces.js";
import { claimsRouter } from "./routes/claims.js";
import { verifyRouter } from "./routes/verify.js";
import { didRouter } from "./routes/did.js";
import { didResolutionRouter } from "./routes/did-resolution.js";
import { dispatchWebhookEvent } from "./routes/webhooks.js";
import { authRouter } from "./routes/auth.js";
import { servicesRouter } from "./routes/services.js";
import { testSeedRouter } from "./routes/test-seed.js";
import { gatewayPairingRouter } from "./routes/gateway-pairing.js";
import type { Env } from "./types.js";
import { createErrorResponse } from "./utils/validation.js";
import { getConfig } from "./utils/config.js";
import { handleBlockchainQueue } from "./blockchain-queue-consumer.js";
import { handleWebhookQueue } from "./webhook-queue-consumer.js";
import { requireSignedHeaders } from "./middleware/signed-auth.js";
export { NonceStoreDurableObject } from "./adapters/cloudflare/nonce-store-do.js";
export { GatewayPairingDurableObject } from "./adapters/cloudflare/gateway-pairing-do.js";

export const app = new Hono<{ Bindings: Env }>();

// ─── Middleware ───────────────────────────────────────────────────────────────

// Request ID tracing
app.use("*", async (c, next) => {
  const requestId = c.req.header("X-Request-ID") || crypto.randomUUID();
  await next();
  c.header("X-Request-ID", requestId);
});

app.use("*", async (c, next) => {
  const allowed = (c.env.ALLOWED_ORIGINS ?? "http://localhost:3000")
    .split(",")
    .map((s: string) => s.trim());
  const middleware = cors({
    origin: (origin: string) => (allowed.includes(origin) ? origin : null),
    credentials: true, // Allow cookies to be sent cross-origin
  });
  return middleware(c, next);
});
const QUIET_PREFIXES = ["/v1/gateway/pairing/status", "/v1/gateway/pairing/connect"];
app.use("*", async (c, next) => {
  if (QUIET_PREFIXES.some((p) => c.req.path.startsWith(p))) {
    return next();
  }
  return honoLogger()(c, next);
});
app.use("*", prettyJSON());

// ─── Health Check ────────────────────────────────────────────────────────────

app.get("/health", (c) => {
  return c.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Enforce signed-header auth contract on all API routes.
app.use("/v1/*", requireSignedHeaders);
app.use("/.well-known/*", requireSignedHeaders);

// ─── Routes ──────────────────────────────────────────────────────────────────

app.route("/v1/namespaces", namespacesRouter);
app.route("/v1/claims", claimsRouter);
app.route("/v1/verify", verifyRouter);
app.route("/v1/auth", authRouter);
app.route("/v1/services", servicesRouter);
app.route("/v1/gateway/pairing", gatewayPairingRouter);
app.route("/v1/test", testSeedRouter);
app.route("/.well-known/did", didRouter);
app.route("/1.0", didResolutionRouter);

// ─── 404 ─────────────────────────────────────────────────────────────────────

app.notFound((c) => {
  return c.json(createErrorResponse("Not found", "NOT_FOUND"), 404);
});

// ─── Error Handler ───────────────────────────────────────────────────────────

app.onError((err, c) => {
  console.error("Unhandled error:", err);
  return c.json(createErrorResponse("Internal server error", "INTERNAL_ERROR"), 500);
});

// ─── Scheduled Handler (Cron) ────────────────────────────────────────────────

async function handleScheduled(env: Env): Promise<void> {
  const config = getConfig(env);

  // Auto-expire pending requests older than configured hours for users who have autoExpire enabled
  const stale = await env.DB.prepare(
    `SELECT a.claim_id, a.namespace
     FROM authorizations a
     WHERE a.status = 'pending'
       AND a.created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-${config.autoExpireHours} hours')`,
  ).all();

  if (!stale.results.length) return;

  // Build a set of namespaces to check their policy settings
  const namespaces = [...new Set(stale.results.map((r) => r.namespace as string))];
  const enabledNamespaces = new Set<string>();

  for (const ns of namespaces) {
    const user = await env.DB.prepare("SELECT settings FROM users WHERE namespace = ?")
      .bind(ns)
      .first() as { settings?: string } | null;

    let settings: Record<string, unknown> = {};
    try {
      if (user?.settings) settings = JSON.parse(user.settings);
    } catch { /* ignore */ }

    const policy = (settings.policy ?? {}) as Record<string, unknown>;
    // autoExpire defaults to true (on) unless explicitly disabled
    if (policy.autoExpire !== false) {
      enabledNamespaces.add(ns);
    }
  }

  // Expire matching claims and dispatch webhooks
  let expired = 0;
  for (const row of stale.results) {
    if (enabledNamespaces.has(row.namespace as string)) {
      // Get full claim details for webhook
      const claim = await env.DB.prepare("SELECT * FROM authorizations WHERE claim_id = ? AND status = 'pending'")
        .bind(row.claim_id)
        .first();

      if (claim) {
        await env.DB.prepare("UPDATE authorizations SET status = 'expired' WHERE claim_id = ? AND status = 'pending'")
          .bind(row.claim_id)
          .run();

        // Dispatch webhook event
        await dispatchWebhookEvent(env.DB, "request.expired", {
          claim_id: claim.claim_id,
          namespace: claim.namespace,
          service: claim.service,
          public_key: claim.public_key,
          agent_ip: claim.agent_ip,
        }, env);

        expired++;
      }
    }
  }

  if (expired > 0) {
    console.log(`Auto-expired ${expired} pending authorization(s)`);
  }

  // Clean up old WebAuthn challenges (older than configured hours)
  const challengeCleanup = await env.DB.prepare(
    `DELETE FROM webauthn_challenges WHERE created_at < datetime('now', '-${config.challengeExpiryHours} hour')`
  ).run();

  if (challengeCleanup.meta.changes > 0) {
    console.log(`Cleaned up ${challengeCleanup.meta.changes} expired WebAuthn challenge(s)`);
  }
}

export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(handleScheduled(env));
  },
  async queue(batch: MessageBatch<unknown>, env: Env, ctx: ExecutionContext) {
    const firstMessage = batch.messages[0] as { body?: unknown } | undefined;
    const isWebhookBatch =
      batch.queue === "sigilum-webhook-delivery" ||
      (typeof firstMessage?.body === "object" &&
        firstMessage?.body !== null &&
        (firstMessage.body as { type?: unknown }).type === "webhook_delivery");

    if (isWebhookBatch) {
      ctx.waitUntil(handleWebhookQueue(batch as MessageBatch<any>, env));
      return;
    }
    if (batch.queue !== "sigilum-blockchain") {
      console.warn(`Unknown queue batch received: ${batch.queue}. Falling back to blockchain consumer.`);
    }
    ctx.waitUntil(handleBlockchainQueue(batch as MessageBatch<any>, env));
  },
};
