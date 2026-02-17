import type { Env } from "../types.js";
import { getAdapters } from "../adapters/index.js";

export type WebhookDeliveryMessage = {
  type: "webhook_delivery";
  webhookId: string;
  event: string;
  payload: Record<string, unknown>;
  occurredAt: string;
  firstAttemptAt: string;
  attempt: number;
};

export async function enqueueWebhookDelivery(
  env: Env,
  message: WebhookDeliveryMessage,
  options?: { delaySeconds?: number },
): Promise<void> {
  const queue = getAdapters(env).webhookQueue;
  if (!queue) {
    throw new Error("WEBHOOK_QUEUE binding is not configured");
  }
  await queue.send(message, options);
}

