import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface AgentKeyResult {
  agentID: string;
  keyDir: string;
  created: boolean;
  fingerprint: string;
  publicKey: string;
}

function sanitizeAgentID(agentID: string): string {
  const sanitized = agentID.trim().replace(/[^a-zA-Z0-9._-]/g, "_");
  return sanitized.length > 0 ? sanitized : "default";
}

function keyObjectFromSeed(seed: Buffer): crypto.KeyObject {
  if (seed.length !== 32) {
    throw new Error("Ed25519 seed must be 32 bytes");
  }
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function derivePublicRaw(privateKeyObj: crypto.KeyObject): Buffer {
  const der = crypto.createPublicKey(privateKeyObj).export({ format: "der", type: "spki" });
  const bytes = Buffer.from(der);
  if (
    bytes.length === ED25519_SPKI_PREFIX.length + 32 &&
    bytes.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    return bytes.subarray(ED25519_SPKI_PREFIX.length);
  }
  throw new Error("Unexpected Ed25519 public key format");
}

function fingerprintForPublicKey(publicKeyRaw: Buffer): string {
  return crypto.createHash("sha256").update(publicKeyRaw).digest("hex").slice(0, 16);
}

function readExistingKeypair(keyDir: string): AgentKeyResult | null {
  if (!fs.existsSync(keyDir)) {
    return null;
  }
  const files = fs.readdirSync(keyDir).filter((entry) => entry.endsWith(".key"));
  if (files.length === 0) {
    return null;
  }

  const fingerprint = files[0].replace(/\.key$/, "");
  const pubPath = path.join(keyDir, `${fingerprint}.pub`);
  if (!fs.existsSync(pubPath)) {
    return null;
  }

  const publicKeyBase64 = fs.readFileSync(pubPath, "utf-8").trim();
  if (!publicKeyBase64) {
    return null;
  }

  return {
    agentID: "",
    keyDir,
    created: false,
    fingerprint,
    publicKey: `ed25519:${publicKeyBase64}`,
  };
}

export function ensureAgentKeypair(agentID: string, keyRoot: string): AgentKeyResult {
  const normalizedID = sanitizeAgentID(agentID);
  const keyDir = path.join(keyRoot, normalizedID);

  fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });

  const existing = readExistingKeypair(keyDir);
  if (existing) {
    return { ...existing, agentID: normalizedID };
  }

  const privateKeySeed = crypto.randomBytes(32);
  const privateKeyObj = keyObjectFromSeed(privateKeySeed);
  const publicKeyRaw = derivePublicRaw(privateKeyObj);
  const fingerprint = fingerprintForPublicKey(publicKeyRaw);
  const publicKeyBase64 = publicKeyRaw.toString("base64");

  const keyPath = path.join(keyDir, `${fingerprint}.key`);
  const pubPath = path.join(keyDir, `${fingerprint}.pub`);

  fs.writeFileSync(keyPath, `${privateKeySeed.toString("base64")}\n`, { mode: 0o600 });
  fs.writeFileSync(pubPath, `${publicKeyBase64}\n`, { mode: 0o644 });

  return {
    agentID: normalizedID,
    keyDir,
    created: true,
    fingerprint,
    publicKey: `ed25519:${publicKeyBase64}`,
  };
}
