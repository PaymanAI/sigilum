export type AdapterProvider = "cloudflare";

export interface DatabaseAdapter {
  readonly binding: D1Database;
  prepare(...args: Parameters<D1Database["prepare"]>): ReturnType<D1Database["prepare"]>;
  batch(...args: Parameters<D1Database["batch"]>): ReturnType<D1Database["batch"]>;
}

export interface QueueAdapter<TMessage = unknown> {
  send(message: TMessage): Promise<void>;
}

export type NonceCheckRequest = {
  service: string;
  nonce: string;
  ttlSeconds?: number;
};

export type NonceCheckResult = {
  replay: boolean;
};

export interface NonceStoreAdapter {
  check(request: NonceCheckRequest): Promise<NonceCheckResult>;
}

export interface PlatformAdapters {
  provider: AdapterProvider;
  database: DatabaseAdapter;
  blockchainQueue?: QueueAdapter;
  nonceStore: NonceStoreAdapter;
}
