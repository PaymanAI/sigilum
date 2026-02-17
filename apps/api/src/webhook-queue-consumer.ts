import type { Env } from "./types.js";
import { getConfig } from "./utils/config.js";
import { isValidWebhookUrl } from "./utils/validation.js";
import { decryptWebhookSecret } from "./utils/webhook-secrets.js";
import { enqueueWebhookDelivery, type WebhookDeliveryMessage } from "./utils/webhook-delivery.js";

const INITIAL_RETRY_MINUTES = [5, 60, 120, 240, 480] as const;

function getRetryDelayMinutes(nextAttempt: number): number {
  if (nextAttempt <= 0) return INITIAL_RETRY_MINUTES[0];
  const index = nextAttempt - 1;
  if (index < INITIAL_RETRY_MINUTES.length) {
    return INITIAL_RETRY_MINUTES[index]!;
  }
  const extensionIndex = index - (INITIAL_RETRY_MINUTES.length - 1);
  return INITIAL_RETRY_MINUTES[INITIAL_RETRY_MINUTES.length - 1]! * (2 ** extensionIndex);
}

function toErrorString(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

async function signPayload(secret: string, body: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(body);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signatureBuffer = await crypto.subtle.sign("HMAC", cryptoKey, messageData);
  const signatureArray = Array.from(new Uint8Array(signatureBuffer));
  return signatureArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function notifyWebhookFailure(
  env: Env,
  message: WebhookDeliveryMessage,
  webhookUrl: string,
  error: string,
): Promise<void> {
  if (!env.WEBHOOK_ALERT_EMAIL_FROM) {
    console.warn(
      `[WebhookQueue] Final delivery failure for ${message.webhookId} (${message.event}) but WEBHOOK_ALERT_EMAIL_FROM is not configured.`,
    );
    return;
  }

  const namespace = typeof message.payload.namespace === "string"
    ? message.payload.namespace.trim()
    : "";

  let recipient = "";
  if (namespace) {
    const owner = await env.DB.prepare(
      "SELECT email FROM users WHERE namespace = ? LIMIT 1",
    )
      .bind(namespace)
      .first<{ email?: string }>();
    recipient = owner?.email?.trim() ?? "";
  }

  if (!recipient) {
    console.warn(
      `[WebhookQueue] Final delivery failure for ${message.webhookId} (${message.event}) but namespace owner email could not be resolved.`,
    );
    return;
  }

  const subject = `[Sigilum] Webhook delivery failed after retries: ${message.event}`;
  const text = [
    "Webhook delivery exhausted retry window.",
    `Webhook ID: ${message.webhookId}`,
    `Event: ${message.event}`,
    `URL: ${webhookUrl}`,
    `First attempt: ${message.firstAttemptAt}`,
    `Occurred at: ${message.occurredAt}`,
    `Attempts: ${message.attempt + 1}`,
    `Last error: ${error}`,
  ].join("\n");

  const resendApiKey = env.RESEND_API_KEY?.trim() ?? "";
  if (resendApiKey) {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${resendApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: env.WEBHOOK_ALERT_EMAIL_FROM,
        to: recipient,
        subject,
        text,
      }),
    });

    if (response.ok) {
      return;
    }

    const responseBody = await response.text();
    console.error(
      `[WebhookQueue] Resend alert send failed (status ${response.status}): ${responseBody}`,
    );
  }

  console.warn(
    `[WebhookQueue] Final delivery failure for ${message.webhookId} (${message.event}) but alert email transport is not configured (set RESEND_API_KEY).`,
  );
}

async function processWebhookDelivery(
  message: Message<WebhookDeliveryMessage>,
  env: Env,
): Promise<void> {
  const job = message.body;
  if (!job || job.type !== "webhook_delivery") {
    message.ack();
    return;
  }

  const row = await env.DB.prepare(
    `SELECT id, url, events, secret_hash, auth_header_name, auth_header_value, active
     FROM webhooks
     WHERE id = ?
     LIMIT 1`,
  )
    .bind(job.webhookId)
    .first<{
      id: string;
      url: string;
      events: string;
      secret_hash: string;
      auth_header_name?: string | null;
      auth_header_value?: string | null;
      active: number;
    }>();

  if (!row || row.active !== 1) {
    message.ack();
    return;
  }

  let subscribedEvents: string[];
  try {
    const parsed = JSON.parse(row.events);
    subscribedEvents = Array.isArray(parsed) ? parsed as string[] : [];
  } catch (err) {
    console.error(`[WebhookQueue] Invalid events JSON for webhook ${row.id}:`, err);
    await env.DB.prepare(
      "UPDATE webhooks SET last_failure_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), failure_count = failure_count + 1 WHERE id = ?",
    )
      .bind(row.id)
      .run();
    message.ack();
    return;
  }

  if (!subscribedEvents.includes(job.event)) {
    message.ack();
    return;
  }

  const urlValidation = await isValidWebhookUrl(row.url, env);
  if (!urlValidation.valid) {
    console.error(
      `[WebhookQueue] Blocked webhook delivery to invalid target for ${row.id}: ${urlValidation.error ?? "invalid URL"}`,
    );
    await env.DB.prepare(
      "UPDATE webhooks SET active = 0, last_failure_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), failure_count = failure_count + 1 WHERE id = ?",
    )
      .bind(row.id)
      .run();
    message.ack();
    return;
  }

  const body = JSON.stringify({
    event: job.event,
    timestamp: job.occurredAt,
    data: job.payload,
  });

  try {
    const signingSecret = await decryptWebhookSecret(env, row.secret_hash);
    const signature = await signPayload(signingSecret, body);
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Sigilum-Event": job.event,
      "X-Sigilum-Webhook-Id": row.id,
      "X-Sigilum-Signature": `sha256=${signature}`,
    };

    if (row.auth_header_name && row.auth_header_value) {
      headers[row.auth_header_name] = row.auth_header_value;
    }

    const response = await fetch(row.url, {
      method: "POST",
      headers,
      body,
    });

    if (response.ok) {
      await env.DB.prepare(
        "UPDATE webhooks SET last_triggered_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), failure_count = 0 WHERE id = ?",
      )
        .bind(row.id)
        .run();
      message.ack();
      return;
    }

    throw new Error(`Webhook responded with status ${response.status}`);
  } catch (err) {
    const errText = toErrorString(err);
    console.error(`[WebhookQueue] Delivery failed for ${row.id}:`, errText);

    await env.DB.prepare(
      "UPDATE webhooks SET last_failure_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), failure_count = failure_count + 1 WHERE id = ?",
    )
      .bind(row.id)
      .run();

    const config = getConfig(env);
    const retryWindowMs = Math.max(1, config.webhookRetryWindowHours) * 60 * 60 * 1000;
    const firstAttemptAtMs = Date.parse(job.firstAttemptAt);
    const safeFirstAttemptAt = Number.isFinite(firstAttemptAtMs) ? firstAttemptAtMs : Date.now();
    const nextAttempt = job.attempt + 1;
    const delayMinutes = getRetryDelayMinutes(nextAttempt);
    const nextAttemptAtMs = Date.now() + (delayMinutes * 60 * 1000);

    if (nextAttemptAtMs - safeFirstAttemptAt > retryWindowMs) {
      await notifyWebhookFailure(env, job, row.url, errText);
      message.ack();
      return;
    }

    await enqueueWebhookDelivery(
      env,
      {
        ...job,
        attempt: nextAttempt,
      },
      { delaySeconds: delayMinutes * 60 },
    );
    message.ack();
  }
}

export async function handleWebhookQueue(
  batch: MessageBatch<WebhookDeliveryMessage>,
  env: Env,
): Promise<void> {
  for (const message of batch.messages) {
    try {
      await processWebhookDelivery(message, env);
    } catch (err) {
      console.error("[WebhookQueue] Unexpected processing error:", err);
      message.retry();
    }
  }
}
