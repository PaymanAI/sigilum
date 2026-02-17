/**
 * Configurable limits with environment variable fallbacks
 */
import type { Env } from "../types.js";

export function getConfig(env: Env) {
  return {
    // Max pending authorization requests per namespace
    maxPendingRequests: parseInt(env.MAX_PENDING_AUTHORIZATIONS ?? "20", 10),

    // Max API keys per service
    maxApiKeysPerService: parseInt(env.MAX_API_KEYS_PER_SERVICE ?? "5", 10),

    // Max webhooks per service
    maxWebhooksPerService: parseInt(env.MAX_WEBHOOKS_PER_SERVICE ?? "5", 10),

    // Webhook failure threshold before auto-disable
    webhookFailureThreshold: parseInt(env.WEBHOOK_FAILURE_THRESHOLD ?? "10", 10),

    // Retry failed webhook events for up to N hours (durable queue retries)
    webhookRetryWindowHours: parseInt(env.WEBHOOK_RETRY_WINDOW_HOURS ?? "24", 10),

    // JWT expiry duration
    jwtExpiry: env.JWT_EXPIRY ?? "7d",

    // Auto-expire duration for pending requests (in hours)
    autoExpireHours: parseInt(env.PENDING_AUTHORIZATION_EXPIRY_HOURS ?? "24", 10),

    // WebAuthn challenge expiry (in hours)
    challengeExpiryHours: parseInt(env.CHALLENGE_EXPIRY_HOURS ?? "1", 10),
  };
}
