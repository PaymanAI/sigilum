/**
 * Blockchain utilities for Sigilum API
 *
 * Uses a relayer wallet to submit transactions on behalf of users.
 * The relayer pays all gas fees (gasless for users).
 */

import { createWalletClient, createPublicClient, http, keccak256, encodeAbiParameters } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia, base } from "viem/chains";
import type { Env } from "../types.js";

// Keep aligned with contract artifacts and shared signature vectors in sdks/test-vectors/.
const SIGILUM_REGISTRY_ABI = [
  { type: "error", name: "InvalidNameLength", inputs: [] },
  { type: "error", name: "NamespaceTaken", inputs: [] },
  { type: "error", name: "NotNamespaceOwner", inputs: [] },
  { type: "error", name: "InvalidAddress", inputs: [] },
  { type: "error", name: "NamespaceNotActive", inputs: [] },
  { type: "error", name: "TooManyPendingClaims", inputs: [] },
  { type: "error", name: "ClaimNotPending", inputs: [] },
  { type: "error", name: "ClaimExpired", inputs: [] },
  { type: "error", name: "ClaimNotApproved", inputs: [] },
  { type: "error", name: "ClaimAlreadyExists", inputs: [] },
  { type: "error", name: "UnexpectedClaimStatus", inputs: [] },
  { type: "error", name: "OnlySigilumRelayer", inputs: [] },
  { type: "error", name: "ServiceNotFound", inputs: [] },
  { type: "error", name: "ServiceNamespaceTaken", inputs: [] },
  {
    type: "function",
    name: "registerNamespace",
    inputs: [{ name: "name", type: "string" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "approveClaimDirect",
    inputs: [
      { name: "namespace", type: "string" },
      { name: "publicKey", type: "bytes" },
      { name: "service", type: "string" },
      { name: "agentIP", type: "string" },
    ],
    outputs: [{ name: "claimId", type: "bytes32" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "revokeClaimDirect",
    inputs: [
      { name: "namespace", type: "string" },
      { name: "publicKey", type: "bytes" },
      { name: "service", type: "string" },
    ],
    outputs: [{ name: "claimId", type: "bytes32" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "registerService",
    inputs: [
      { name: "name", type: "string" },
      { name: "namespace", type: "string" },
      { name: "website", type: "string" },
      { name: "description", type: "string" },
      { name: "tags", type: "string[]" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "namespaces",
    inputs: [{ name: "", type: "string" }],
    outputs: [
      { name: "owner", type: "address" },
      { name: "active", type: "bool" },
      { name: "createdAt", type: "uint256" },
    ],
    stateMutability: "view",
  },
] as const;

/**
 * Get the chain configuration based on environment
 */
function getChain(env: Env) {
  const isTestnet = env.BLOCKCHAIN_NETWORK === "testnet";
  return isTestnet ? baseSepolia : base;
}

/**
 * Get the RPC URL based on environment
 */
function getRpcUrl(env: Env): string {
  if (env.BLOCKCHAIN_RPC_URL) {
    return env.BLOCKCHAIN_RPC_URL;
  }
  // Default to public RPC
  return env.BLOCKCHAIN_NETWORK === "testnet"
    ? "https://sepolia.base.org"
    : "https://mainnet.base.org";
}

/**
 * Get the registry contract address
 */
function getRegistryAddress(env: Env): `0x${string}` {
  if (!env.SIGILUM_REGISTRY_ADDRESS) {
    throw new Error("SIGILUM_REGISTRY_ADDRESS environment variable is required");
  }
  return env.SIGILUM_REGISTRY_ADDRESS as `0x${string}`;
}

/**
 * Get the relayer account from private key
 */
function getRelayerAccount(env: Env) {
  if (!env.RELAYER_PRIVATE_KEY) {
    throw new Error("RELAYER_PRIVATE_KEY environment variable is required");
  }
  return privateKeyToAccount(env.RELAYER_PRIVATE_KEY as `0x${string}`);
}

/**
 * Create a wallet client for submitting transactions
 */
function createRelayerWalletClient(env: Env) {
  const chain = getChain(env);
  const account = getRelayerAccount(env);
  const rpcUrl = getRpcUrl(env);

  return createWalletClient({
    account,
    chain,
    transport: http(rpcUrl),
  });
}

/**
 * Create a public client for reading from the blockchain
 */
function createBlockchainPublicClient(env: Env) {
  const chain = getChain(env);
  const rpcUrl = getRpcUrl(env);

  return createPublicClient({
    chain,
    transport: http(rpcUrl),
  });
}

/**
 * Decode base64 to Uint8Array (compatible with both Node.js and Cloudflare Workers)
 */
function base64ToBytes(base64: string): Uint8Array {
  // Use atob for base64 decoding (Web API, available in both environments)
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert bytes to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert a Sigilum public key to hex bytes format for blockchain
 * Handles both "ed25519:<base64>" format and raw base64/hex formats
 */
export function publicKeyToHex(publicKey: string): `0x${string}` {
  // Already in hex format
  if (publicKey.startsWith("0x")) {
    return publicKey as `0x${string}`;
  }

  // Strip "ed25519:" prefix if present
  let keyData = publicKey;
  if (publicKey.startsWith("ed25519:")) {
    keyData = publicKey.slice("ed25519:".length);
  }

  // Convert from base64 to bytes
  const bytes = base64ToBytes(keyData);

  // Validate Ed25519 public key length (must be 32 bytes)
  if (bytes.length !== 32) {
    throw new Error(
      `Invalid Ed25519 public key length: expected 32 bytes, got ${bytes.length}. ` +
      `Key: ${publicKey}`
    );
  }

  // Convert to hex
  const hex = bytesToHex(bytes);
  return `0x${hex}`;
}

/**
 * Compute the on-chain claimId as the contract does
 * claimId = keccak256(abi.encode(namespace, publicKey, service))
 */
export function computeOnChainClaimId(
  namespace: string,
  publicKey: string,
  service: string,
): `0x${string}` {
  // Convert public key to consistent hex bytes format
  const publicKeyBytes = publicKeyToHex(publicKey);

  // Encode parameters the same way Solidity's abi.encode does
  const encoded = encodeAbiParameters(
    [
      { type: "string", name: "namespace" },
      { type: "bytes", name: "publicKey" },
      { type: "string", name: "service" },
    ],
    [namespace, publicKeyBytes, service],
  );

  return keccak256(encoded);
}

/**
 * Register a namespace on-chain
 * Called during user signup
 */
export async function registerNamespaceOnChain(
  env: Env,
  namespace: string,
): Promise<{ txHash: string; relayerAddress: string }> {
  const walletClient = createRelayerWalletClient(env);
  const contractAddress = getRegistryAddress(env);

  const hash = await walletClient.writeContract({
    address: contractAddress,
    abi: SIGILUM_REGISTRY_ABI,
    functionName: "registerNamespace",
    args: [namespace],
  });

  return {
    txHash: hash,
    relayerAddress: walletClient.account.address,
  };
}

/**
 * Approve a claim on-chain using direct approval (no pending state)
 * Called when user approves a claim in the dashboard
 *
 * @param namespace - The namespace from the claim
 * @param publicKey - The agent's public key from the claim
 * @param service - The service from the claim
 * @param agentIP - The agent's IP address from the claim
 */
export async function approveClaimOnChain(
  env: Env,
  namespace: string,
  publicKey: string,
  service: string,
  agentIP: string,
): Promise<{ txHash: string; claimId: string }> {
  const walletClient = createRelayerWalletClient(env);
  const contractAddress = getRegistryAddress(env);

  // Convert public key to hex format for blockchain
  const publicKeyBytes = publicKeyToHex(publicKey);

  // Compute the on-chain claimId for logging
  const claimIdBytes32 = computeOnChainClaimId(namespace, publicKey, service);

  console.log(`Approving claim directly on-chain: namespace=${namespace}, service=${service}, claimId=${claimIdBytes32}`);

  // Use approveClaimDirect - creates and approves in one transaction
  const hash = await walletClient.writeContract({
    address: contractAddress,
    abi: SIGILUM_REGISTRY_ABI,
    functionName: "approveClaimDirect",
    args: [namespace, publicKeyBytes, service, agentIP],
  });

  return { txHash: hash, claimId: claimIdBytes32 };
}

/**
 * Revoke a claim on-chain using direct revocation
 */
export async function revokeClaimOnChain(
  env: Env,
  namespace: string,
  publicKey: string,
  service: string,
): Promise<{ txHash: string; claimId: string }> {
  const walletClient = createRelayerWalletClient(env);
  const contractAddress = getRegistryAddress(env);

  // Convert public key to hex format for blockchain
  const publicKeyBytes = publicKeyToHex(publicKey);

  // Compute the on-chain claimId for logging
  const claimIdBytes32 = computeOnChainClaimId(namespace, publicKey, service);

  console.log(`Revoking claim directly on-chain: namespace=${namespace}, service=${service}, claimId=${claimIdBytes32}`);

  // Use revokeClaimDirect - more convenient for API mode
  const hash = await walletClient.writeContract({
    address: contractAddress,
    abi: SIGILUM_REGISTRY_ABI,
    functionName: "revokeClaimDirect",
    args: [namespace, publicKeyBytes, service],
  });

  return { txHash: hash, claimId: claimIdBytes32 };
}

/**
 * Check if a namespace exists on-chain
 */
export async function checkNamespaceOnChain(
  env: Env,
  namespace: string,
): Promise<{ exists: boolean; owner: string; active: boolean }> {
  const publicClient = createBlockchainPublicClient(env);
  const contractAddress = getRegistryAddress(env);

  const result = await publicClient.readContract({
    address: contractAddress,
    abi: SIGILUM_REGISTRY_ABI,
    functionName: "namespaces",
    args: [namespace],
  });

  const [owner, active] = result as [string, boolean, bigint];

  return {
    exists: owner !== "0x0000000000000000000000000000000000000000",
    owner,
    active,
  };
}

/**
 * Wait for a transaction to be confirmed
 */
export async function waitForTransaction(
  env: Env,
  txHash: string,
): Promise<{ confirmed: boolean }> {
  const publicClient = createBlockchainPublicClient(env);

  try {
    await publicClient.waitForTransactionReceipt({
      hash: txHash as `0x${string}`,
      timeout: 60_000, // 60 seconds
    });
    return { confirmed: true };
  } catch (error) {
    console.error("Transaction confirmation failed:", error);
    return { confirmed: false };
  }
}

/**
 * Register a service on-chain (Sigilum-only)
 * Called when a service is created in the dashboard
 */
export async function registerServiceOnChain(
  env: Env,
  name: string,
  namespace: string,
  website: string,
  description: string,
  tags: string[],
): Promise<{ txHash: string }> {
  const walletClient = createRelayerWalletClient(env);
  const contractAddress = getRegistryAddress(env);

  console.log(`Registering service on-chain: name=${name}, namespace=${namespace}`);

  const hash = await walletClient.writeContract({
    address: contractAddress,
    abi: SIGILUM_REGISTRY_ABI,
    functionName: "registerService",
    args: [name, namespace, website, description, tags],
  });

  return { txHash: hash };
}

/**
 * True when registerService reverted because namespace already has a service.
 */
export function isServiceNamespaceTakenError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  if (error.message.includes("ServiceNamespaceTaken")) return true;

  const maybeData = error as {
    cause?: {
      data?: {
        errorName?: string;
      };
    };
  };
  return maybeData.cause?.data?.errorName === "ServiceNamespaceTaken";
}
