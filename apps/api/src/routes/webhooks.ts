import { Hono } from "hono";
import { z } from "zod";
import type { Env } from "../types.js";
import { validateServiceApiKey } from "./services.js";
import { isValidWebhookUrl, createErrorResponse } from "../utils/validation.js";
import { getConfig } from "../utils/config.js";
import { encryptWebhookSecret } from "../utils/webhook-secrets.js";
import { enqueueWebhookDelivery } from "../utils/webhook-delivery.js";

const WEBHOOK_EVENTS = [
  "request.submitted",
  "request.approved",
  "request.revoked",
  "request.rejected",
  "request.expired",
] as const;

const createWebhookSchema = z.object({
  url: z.string().url(),
  events: z.array(z.enum(WEBHOOK_EVENTS)).min(1),
  secret: z.string().min(16, "Secret must be at least 16 characters"),
});

async function requireServiceAuth(c: { req: { header: (name: string) => string | undefined }; env: Env }) {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;
  const apiKey = authHeader.slice(7).trim();
  return validateServiceApiKey(c.env.DB, apiKey);
}

export const webhooksRouter = new Hono<{ Bindings: Env }>();

/**
 * POST /v1/webhooks
 * Subscribe to Sigilum events. Requires service API key.
 */
webhooksRouter.post("/", async (c) => {
  const service = await requireServiceAuth(c);
  if (!service) {
    return c.json(createErrorResponse("Missing or invalid service API key", "UNAUTHORIZED"), 401);
  }

  let body: z.infer<typeof createWebhookSchema>;
  try {
    body = createWebhookSchema.parse(await c.req.json());
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json(createErrorResponse("Validation failed", "VALIDATION_ERROR", err.issues), 400);
    }
    return c.json(createErrorResponse("Invalid request body", "INVALID_JSON"), 400);
  }

  // SSRF protection: validate webhook URL
  const urlValidation = await isValidWebhookUrl(body.url);
  if (!urlValidation.valid) {
    return c.json(createErrorResponse(urlValidation.error!, "INVALID_WEBHOOK_URL"), 400);
  }

  // Limit webhooks per service
  const config = getConfig(c.env);
  const count = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM webhooks WHERE service_id = ? AND active = 1",
  )
    .bind(service.serviceId)
    .first<{ cnt: number }>();
  if ((count?.cnt ?? 0) >= config.maxWebhooksPerService) {
    return c.json(createErrorResponse(`Maximum ${config.maxWebhooksPerService} active webhooks per service`, "WEBHOOK_LIMIT_REACHED"), 400);
  }

  const id = `wh_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
  const encryptedSecret = await encryptWebhookSecret(c.env, body.secret);
  await c.env.DB.prepare(
    "INSERT INTO webhooks (id, service_id, url, events, secret_hash) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(id, service.serviceId, body.url, JSON.stringify(body.events), encryptedSecret)
    .run();

  return c.json(
    {
      id,
      url: body.url,
      events: body.events,
      active: true,
    },
    201,
  );
});

/**
 * GET /v1/webhooks
 * List webhook subscriptions for the authenticated service.
 */
webhooksRouter.get("/", async (c) => {
  const service = await requireServiceAuth(c);
  if (!service) {
    return c.json(createErrorResponse("Missing or invalid service API key", "UNAUTHORIZED"), 401);
  }

  const limit = Math.min(parseInt(c.req.query("limit") ?? "50", 10), 200);
  const offset = parseInt(c.req.query("offset") ?? "0", 10);

  const rows = await c.env.DB.prepare(
    "SELECT id, url, events, active, failure_count, last_triggered_at, last_failure_at, created_at FROM webhooks WHERE service_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
  )
    .bind(service.serviceId, limit, offset)
    .all();

  const totalCount = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM webhooks WHERE service_id = ?",
  )
    .bind(service.serviceId)
    .first<{ cnt: number }>();

  const webhooks = rows.results.map((w) => ({
    id: w.id,
    url: w.url,
    events: JSON.parse(w.events as string),
    active: w.active === 1,
    failure_count: w.failure_count,
    last_triggered_at: w.last_triggered_at,
    last_failure_at: w.last_failure_at,
    created_at: w.created_at,
  }));

  return c.json({
    webhooks,
    pagination: {
      limit,
      offset,
      total: totalCount?.cnt ?? 0,
      has_more: offset + limit < (totalCount?.cnt ?? 0),
    },
  });
});

/**
 * DELETE /v1/webhooks/:webhookId
 * Delete a webhook subscription.
 */
webhooksRouter.delete("/:webhookId", async (c) => {
  const service = await requireServiceAuth(c);
  if (!service) {
    return c.json(createErrorResponse("Missing or invalid service API key", "UNAUTHORIZED"), 401);
  }

  const webhookId = c.req.param("webhookId");
  const row = await c.env.DB.prepare(
    "SELECT id FROM webhooks WHERE id = ? AND service_id = ?",
  )
    .bind(webhookId, service.serviceId)
    .first();
  if (!row) {
    return c.json(createErrorResponse("Webhook not found", "NOT_FOUND"), 404);
  }

  await c.env.DB.prepare("DELETE FROM webhooks WHERE id = ?").bind(webhookId).run();

  return c.json({ success: true, deleted: true, webhook_id: webhookId });
});

/**
 * PATCH /v1/webhooks/:webhookId
 * Toggle a webhook active/inactive.
 */
webhooksRouter.patch("/:webhookId", async (c) => {
  const service = await requireServiceAuth(c);
  if (!service) {
    return c.json(createErrorResponse("Missing or invalid service API key", "UNAUTHORIZED"), 401);
  }

  const webhookId = c.req.param("webhookId");
  const body = await c.req.json<{ active?: boolean }>();

  const row = await c.env.DB.prepare(
    "SELECT id, active FROM webhooks WHERE id = ? AND service_id = ?",
  )
    .bind(webhookId, service.serviceId)
    .first();
  if (!row) {
    return c.json(createErrorResponse("Webhook not found", "NOT_FOUND"), 404);
  }

  if (body.active !== undefined) {
    await c.env.DB.prepare("UPDATE webhooks SET active = ? WHERE id = ?")
      .bind(body.active ? 1 : 0, webhookId)
      .run();
  }

  return c.json({ success: true, active: body.active ?? (row.active === 1) });
});

// ─── Webhook delivery (used internally) ────────────────────────────────────

/**
 * Dispatch an event to all matching webhooks for a service.
 * Delivery is queued for durable retries by the webhook queue consumer.
 */
export async function dispatchWebhookEvent(
  db: D1Database,
  event: string,
  payload: Record<string, unknown>,
  env: Env,
): Promise<void> {
  const serviceSlug = payload.service as string;
  if (!serviceSlug) return;

  // Find all active webhooks for this service.
  const rows = await db
    .prepare(
      `SELECT w.id, w.events
       FROM webhooks w
       JOIN services s ON s.id = w.service_id
       WHERE s.slug = ? AND w.active = 1`,
    )
    .bind(serviceSlug)
    .all();

  const occurredAt = new Date().toISOString();

  for (const row of rows.results) {
    try {
      const events = JSON.parse(row.events as string) as string[];
      if (!events.includes(event)) continue;

      await enqueueWebhookDelivery(env, {
        type: "webhook_delivery",
        webhookId: row.id as string,
        event,
        payload,
        occurredAt,
        firstAttemptAt: occurredAt,
        attempt: 0,
      });
    } catch (error) {
      console.error(
        `[WebhookDispatch] Failed to enqueue webhook delivery for webhook ${String(row.id)}:`,
        error,
      );
    }
  }
}
