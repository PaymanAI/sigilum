import type { Env } from "../types.js";
import { createCloudflareAdapters } from "./cloudflare/index.js";
import type { AdapterProvider, PlatformAdapters } from "./interfaces.js";
export type {
  AdapterProvider,
  DatabaseAdapter,
  NonceCheckRequest,
  NonceCheckResult,
  NonceStoreAdapter,
  PlatformAdapters,
  QueueAdapter,
} from "./interfaces.js";

const DEFAULT_ADAPTER_PROVIDER: AdapterProvider = "cloudflare";

export function getAdapterProvider(env: Pick<Env, "ADAPTER_PROVIDER">): AdapterProvider {
  const provider = env.ADAPTER_PROVIDER?.toLowerCase();
  if (provider === "cloudflare") {
    return provider;
  }
  return DEFAULT_ADAPTER_PROVIDER;
}

export function getAdapters(env: Env): PlatformAdapters {
  const provider = getAdapterProvider(env);

  switch (provider) {
    case "cloudflare":
      return createCloudflareAdapters(env);
    default:
      return createCloudflareAdapters(env);
  }
}
