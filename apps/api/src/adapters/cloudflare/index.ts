import type { Env } from "../../types.js";
import type { PlatformAdapters } from "../interfaces.js";
import { CloudflareDatabaseAdapter } from "./database.js";
import { CloudflareQueueAdapter } from "./queue.js";
import { CloudflareNonceStoreAdapter } from "./nonce-store-adapter.js";

export { NonceStoreDurableObject } from "./nonce-store-do.js";

export function createCloudflareAdapters(env: Env): PlatformAdapters {
  return {
    provider: "cloudflare",
    database: new CloudflareDatabaseAdapter(env.DB),
    blockchainQueue: env.BLOCKCHAIN_QUEUE
      ? new CloudflareQueueAdapter(env.BLOCKCHAIN_QUEUE)
      : undefined,
    webhookQueue: env.WEBHOOK_QUEUE
      ? new CloudflareQueueAdapter(env.WEBHOOK_QUEUE)
      : undefined,
    nonceStore: new CloudflareNonceStoreAdapter(env.NONCE_STORE_DO),
  };
}
