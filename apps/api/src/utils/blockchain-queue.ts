/**
 * Blockchain Queue - Async job processing for blockchain operations
 *
 * Supports four modes via BLOCKCHAIN_MODE env var:
 * - "queue" (production): Async via Cloudflare Queues
 * - "sync" (development): Synchronous blockchain calls
 * - "memory" (testing): In-memory queue with immediate processing
 * - "disabled" (local dev): Skip blockchain operations entirely
 */

import type { Env } from "../types.js";
import { getAdapters } from "../adapters/index.js";
import {
  registerNamespaceOnChain,
  registerServiceOnChain,
  approveClaimOnChain,
  revokeClaimOnChain,
  isServiceNamespaceTakenError,
} from "./blockchain.js";

// ─── Job Types ──────────────────────────────────────────────────────────────

export type BlockchainJob =
  | RegisterNamespaceJob
  | RegisterServiceJob
  | ApproveClaimJob
  | RevokeClaimJob;

export interface RegisterNamespaceJob {
  type: "register_namespace";
  namespace: string;
  userId: string;
}

export interface RegisterServiceJob {
  type: "register_service";
  serviceId: string;
  name: string;
  namespace: string;
  website: string;
  description: string;
  tags: string[];
}

export interface ApproveClaimJob {
  type: "approve_claim";
  claimId: string;
  namespace: string;
  publicKey: string;
  service: string;
  agentIP: string;
}

export interface RevokeClaimJob {
  type: "revoke_claim";
  claimId: string;
  namespace: string;
  publicKey: string;
  service: string;
}

// ─── Mode Detection ─────────────────────────────────────────────────────────

/**
 * Get the blockchain processing mode
 */
export function getBlockchainMode(env: Env): "queue" | "sync" | "memory" | "disabled" {
  const mode = env.BLOCKCHAIN_MODE?.toLowerCase();
  if (mode === "queue" || mode === "sync" || mode === "memory" || mode === "disabled") {
    return mode;
  }
  // Safe default for onboarding: explicit opt-in to blockchain mode.
  return "disabled";
}

/**
 * Return an explanatory string when blockchain prerequisites are missing.
 * Empty string means config is usable.
 */
export function getBlockchainConfigError(env: Env): string {
  const missing: string[] = [];
  if (!env.SIGILUM_REGISTRY_ADDRESS?.trim()) {
    missing.push("SIGILUM_REGISTRY_ADDRESS");
  }
  if (!env.RELAYER_PRIVATE_KEY?.trim()) {
    missing.push("RELAYER_PRIVATE_KEY");
  }
  if (missing.length === 0) {
    return "";
  }
  return `missing required blockchain env var(s): ${missing.join(", ")}`;
}

// ─── Job Processing ─────────────────────────────────────────────────────────

/**
 * Process a blockchain job immediately (for sync/memory modes)
 */
async function processJobImmediately(
  env: Env,
  job: BlockchainJob,
): Promise<void> {
  console.log(`Processing blockchain job immediately: ${job.type}`);

  switch (job.type) {
    case "register_namespace": {
      const result = await registerNamespaceOnChain(env, job.namespace);
      await env.DB.prepare(
        "UPDATE users SET registration_tx_hash = ? WHERE id = ?",
      )
        .bind(result.txHash, job.userId)
        .run();
      console.log(`Namespace registered: ${job.namespace}, tx: ${result.txHash}`);
      break;
    }

    case "register_service": {
      try {
        const result = await registerServiceOnChain(
          env,
          job.name,
          job.namespace,
          job.website,
          job.description,
          job.tags,
        );
        await env.DB.prepare(
          "UPDATE services SET registration_tx_hash = ? WHERE id = ?",
        )
          .bind(result.txHash, job.serviceId)
          .run();
        console.log(`Service registered: ${job.namespace}, tx: ${result.txHash}`);
      } catch (error) {
        if (isServiceNamespaceTakenError(error)) {
          console.warn(
            `[Blockchain] Service namespace already registered on-chain, skipping: ${job.namespace}`,
          );
          break;
        }
        throw error;
      }
      break;
    }

    case "approve_claim": {
      const result = await approveClaimOnChain(
        env,
        job.namespace,
        job.publicKey,
        job.service,
        job.agentIP,
      );
      await env.DB.prepare(
        "UPDATE authorizations SET approval_tx_hash = ? WHERE claim_id = ?",
      )
        .bind(result.txHash, job.claimId)
        .run();
      console.log(`Claim approved: ${job.claimId}, tx: ${result.txHash}`);
      break;
    }

    case "revoke_claim": {
      const result = await revokeClaimOnChain(
        env,
        job.namespace,
        job.publicKey,
        job.service,
      );
      await env.DB.prepare(
        "UPDATE authorizations SET revocation_tx_hash = ? WHERE claim_id = ?",
      )
        .bind(result.txHash, job.claimId)
        .run();
      console.log(`Claim revoked: ${job.claimId}, tx: ${result.txHash}`);
      break;
    }

    default:
      console.error("Unknown blockchain job type:", (job as any).type);
  }
}

// ─── In-Memory Queue ────────────────────────────────────────────────────────

const inMemoryQueue: BlockchainJob[] = [];
let processingMemoryQueue = false;

/**
 * Process the in-memory queue (for memory mode)
 */
async function processInMemoryQueue(env: Env): Promise<void> {
  if (processingMemoryQueue || inMemoryQueue.length === 0) return;

  processingMemoryQueue = true;
  while (inMemoryQueue.length > 0) {
    const job = inMemoryQueue.shift();
    if (!job) break;

    try {
      await processJobImmediately(env, job);
    } catch (error) {
      console.error(`Failed to process in-memory job: ${job.type}`, error);
      // Could implement retry logic here
    }
  }
  processingMemoryQueue = false;
}

// ─── Queue Helpers ──────────────────────────────────────────────────────────

/**
 * Send a blockchain job to the queue for async processing
 * Supports four modes: queue, sync, memory, disabled
 */
export async function enqueueBlockchainJob(
  env: Env,
  job: BlockchainJob,
): Promise<void> {
  const mode = getBlockchainMode(env);
  const isProdLike = env.ENVIRONMENT === "production" || env.ENVIRONMENT === "staging";

  switch (mode) {
    case "disabled":
      // Explicitly do not enqueue while disabled. This is intentional.
      if (isProdLike) {
        console.error(
          `[BLOCKCHAIN DISABLED] Skipping blockchain job in ${env.ENVIRONMENT}: ${job.type}`,
        );
      } else {
        console.warn(`[BLOCKCHAIN DISABLED] Skipping blockchain job: ${job.type}`);
      }
      return;

    case "sync":
    case "memory":
    case "queue": {
      const configError = getBlockchainConfigError(env);
      if (configError) {
        console.warn(`[BLOCKCHAIN SKIP] ${configError}. Job "${job.type}" was not submitted on-chain.`);
        return;
      }
      break;
    }
  }

  switch (mode) {
    case "sync":
      // Process immediately and block
      console.log(`[SYNC MODE] Processing blockchain job: ${job.type}`);
      await processJobImmediately(env, job);
      break;

    case "memory":
      // Add to in-memory queue and process asynchronously
      console.log(`[MEMORY MODE] Queuing blockchain job: ${job.type}`);
      inMemoryQueue.push(job);
      // Process in next tick (non-blocking)
      setTimeout(() => processInMemoryQueue(env), 0);
      break;

    case "queue":
      // Use Cloudflare Queue
      const adapters = getAdapters(env);
      if (!adapters.blockchainQueue) {
        console.warn("BLOCKCHAIN_QUEUE not configured, falling back to sync mode");
        await processJobImmediately(env, job);
        return;
      }

      try {
        await adapters.blockchainQueue.send(job);
        console.log(`[QUEUE MODE] Blockchain job enqueued: ${job.type}`);
      } catch (error) {
        console.error(`Failed to enqueue blockchain job: ${job.type}`, error);
        throw error;
      }
      break;
  }
}

/**
 * Send a namespace registration job
 */
export async function enqueueRegisterNamespace(
  env: Env,
  namespace: string,
  userId: string,
): Promise<void> {
  await enqueueBlockchainJob(env, {
    type: "register_namespace",
    namespace,
    userId,
  });
}

/**
 * Send a service registration job
 */
export async function enqueueRegisterService(
  env: Env,
  serviceId: string,
  name: string,
  namespace: string,
  website: string,
  description: string,
  tags: string[],
): Promise<void> {
  await enqueueBlockchainJob(env, {
    type: "register_service",
    serviceId,
    name,
    namespace,
    website,
    description,
    tags,
  });
}

/**
 * Send a claim approval job
 */
export async function enqueueApproveClaim(
  env: Env,
  claimId: string,
  namespace: string,
  publicKey: string,
  service: string,
  agentIP: string,
): Promise<void> {
  await enqueueBlockchainJob(env, {
    type: "approve_claim",
    claimId,
    namespace,
    publicKey,
    service,
    agentIP,
  });
}

/**
 * Send a claim revocation job
 */
export async function enqueueRevokeClaim(
  env: Env,
  claimId: string,
  namespace: string,
  publicKey: string,
  service: string,
): Promise<void> {
  await enqueueBlockchainJob(env, {
    type: "revoke_claim",
    claimId,
    namespace,
    publicKey,
    service,
  });
}
