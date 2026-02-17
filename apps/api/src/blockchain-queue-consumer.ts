/**
 * Blockchain Queue Consumer
 *
 * Processes blockchain operations asynchronously. Each job type corresponds
 * to a blockchain transaction that updates the on-chain state.
 *
 * The consumer updates the database with the transaction hash after successful
 * submission. If the transaction fails, it will be retried automatically by
 * the queue system (up to max_retries configured in wrangler.toml).
 */

import type { Env } from "./types.js";
import type { BlockchainJob } from "./utils/blockchain-queue.js";
import { getBlockchainConfigError, getBlockchainMode } from "./utils/blockchain-queue.js";
import {
  registerNamespaceOnChain,
  registerServiceOnChain,
  approveClaimOnChain,
  revokeClaimOnChain,
  isServiceNamespaceTakenError,
} from "./utils/blockchain.js";

/**
 * Process a batch of blockchain jobs
 */
export async function handleBlockchainQueue(
  batch: MessageBatch<BlockchainJob>,
  env: Env,
): Promise<void> {
  console.log(`Processing blockchain queue batch: ${batch.messages.length} jobs`);

  const mode = getBlockchainMode(env);
  if (mode === "disabled") {
    console.error("[QueueConsumer] BLOCKCHAIN_MODE=disabled. Acknowledging and skipping queued blockchain jobs.");
    for (const message of batch.messages) {
      message.ack();
    }
    return;
  }

  const configError = getBlockchainConfigError(env);
  if (configError) {
    console.error(`[QueueConsumer] ${configError}. Retrying all queued jobs.`);
    for (const message of batch.messages) {
      message.retry({ delaySeconds: 300 });
    }
    return;
  }

  // Process jobs sequentially to avoid RPC rate limits
  for (const message of batch.messages) {
    try {
      await processBlockchainJob(message.body, env);
      message.ack();
    } catch (error) {
      console.error("Failed to process blockchain job:", error);
      // Retry the job by not acking it
      message.retry();
    }
  }
}

/**
 * Process a single blockchain job
 */
async function processBlockchainJob(job: BlockchainJob, env: Env): Promise<void> {
  console.log(`Processing blockchain job: ${job.type}`);

  switch (job.type) {
    case "register_namespace":
      await handleRegisterNamespace(job, env);
      break;

    case "register_service":
      await handleRegisterService(job, env);
      break;

    case "approve_claim":
      await handleApproveClaim(job, env);
      break;

    case "revoke_claim":
      await handleRevokeClaim(job, env);
      break;

    default:
      console.error("Unknown blockchain job type:", (job as any).type);
  }
}

/**
 * Register a namespace on-chain
 */
async function handleRegisterNamespace(
  job: { namespace: string; userId: string },
  env: Env,
): Promise<void> {
  const { namespace, userId } = job;

  try {
    const result = await registerNamespaceOnChain(env, namespace);

    // Update database with transaction hash
    await env.DB.prepare(
      "UPDATE users SET registration_tx_hash = ? WHERE id = ?",
    )
      .bind(result.txHash, userId)
      .run();

    console.log(`Namespace registered on-chain: ${namespace}, tx: ${result.txHash}`);
  } catch (error) {
    console.error(`Failed to register namespace ${namespace}:`, error);
    throw error; // Trigger retry
  }
}

/**
 * Register a service on-chain
 */
async function handleRegisterService(
  job: {
    serviceId: string;
    name: string;
    namespace: string;
    website: string;
    description: string;
    tags: string[];
  },
  env: Env,
): Promise<void> {
  const { serviceId, name, namespace, website, description, tags } = job;

  try {
    const result = await registerServiceOnChain(
      env,
      name,
      namespace,
      website,
      description,
      tags,
    );

    // Update database with transaction hash
    await env.DB.prepare(
      "UPDATE services SET registration_tx_hash = ? WHERE id = ?",
    )
      .bind(result.txHash, serviceId)
      .run();

    console.log(`Service registered on-chain: ${namespace}, tx: ${result.txHash}`);
  } catch (error) {
    if (isServiceNamespaceTakenError(error)) {
      console.warn(
        `[QueueConsumer] Service namespace already registered on-chain, skipping: ${namespace}`,
      );
      return;
    }
    console.error(`Failed to register service ${namespace}:`, error);
    throw error; // Trigger retry
  }
}

/**
 * Approve a claim on-chain
 */
async function handleApproveClaim(
  job: {
    claimId: string;
    namespace: string;
    publicKey: string;
    service: string;
    agentIP: string;
  },
  env: Env,
): Promise<void> {
  const { claimId, namespace, publicKey, service, agentIP } = job;

  try {
    const result = await approveClaimOnChain(env, namespace, publicKey, service, agentIP);

    // Update database with transaction hash
    await env.DB.prepare(
      "UPDATE authorizations SET approval_tx_hash = ? WHERE claim_id = ?",
    )
      .bind(result.txHash, claimId)
      .run();

    console.log(`Claim approved on-chain: ${claimId}, tx: ${result.txHash}`);
  } catch (error) {
    console.error(`Failed to approve claim ${claimId}:`, error);
    throw error; // Trigger retry
  }
}

/**
 * Revoke a claim on-chain
 */
async function handleRevokeClaim(
  job: {
    claimId: string;
    namespace: string;
    publicKey: string;
    service: string;
  },
  env: Env,
): Promise<void> {
  const { claimId, namespace, publicKey, service } = job;

  try {
    const result = await revokeClaimOnChain(env, namespace, publicKey, service);

    // Update database with transaction hash
    await env.DB.prepare(
      "UPDATE authorizations SET revocation_tx_hash = ? WHERE claim_id = ?",
    )
      .bind(result.txHash, claimId)
      .run();

    console.log(`Claim revoked on-chain: ${claimId}, tx: ${result.txHash}`);
  } catch (error) {
    console.error(`Failed to revoke claim ${claimId}:`, error);
    throw error; // Trigger retry
  }
}
