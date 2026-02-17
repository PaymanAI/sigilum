import type { Env } from "../types.js";
import { enqueueWebhookDelivery } from "../utils/webhook-delivery.js";

// ─── Webhook dispatch (used internally) ────────────────────────────────────

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
