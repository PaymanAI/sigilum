export interface Env {
  ENVIRONMENT: "production" | "staging" | "test" | "development";
  ADAPTER_PROVIDER?: "cloudflare"; // Default: cloudflare
  ALLOWED_ORIGINS?: string;
  JWT_SECRET?: string;
  WEBHOOK_SECRET_ENCRYPTION_KEY?: string;
  DB: D1Database;
  BLOCKCHAIN_QUEUE?: Queue;  // Optional: only needed in "queue" mode
  WEBHOOK_QUEUE?: Queue; // Optional: queue-backed durable webhook delivery
  NONCE_STORE_DO?: DurableObjectNamespace;
  WEBHOOK_ALERT_EMAIL_FROM?: string;
  RESEND_API_KEY?: string; // Optional: preferred transport for alert emails
  // CACHE: KVNamespace;

  // Blockchain configuration
  BLOCKCHAIN_NETWORK?: "testnet" | "mainnet"; // Default: testnet
  BLOCKCHAIN_RPC_URL?: string; // Optional, has public defaults
  SIGILUM_REGISTRY_ADDRESS?: string; // Smart contract address
  RELAYER_PRIVATE_KEY?: string; // Relayer wallet private key for gasless transactions
  BLOCKCHAIN_MODE?: "queue" | "sync" | "memory" | "disabled"; // Default: disabled (explicit opt-in for chain writes)

  // Configurable limits (optional, have defaults)
  MAX_PENDING_AUTHORIZATIONS?: string;
  MAX_API_KEYS_PER_SERVICE?: string;
  MAX_WEBHOOKS_PER_SERVICE?: string;
  WEBHOOK_FAILURE_THRESHOLD?: string;
  WEBHOOK_RETRY_WINDOW_HOURS?: string;
  JWT_EXPIRY?: string;
  PENDING_AUTHORIZATION_EXPIRY_HOURS?: string;
  CHALLENGE_EXPIRY_HOURS?: string;
}
