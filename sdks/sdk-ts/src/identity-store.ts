import "./setup.js";
import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type {
  InitIdentityOptions,
  InitIdentityResult,
  LoadIdentityOptions,
  SigilumCertificate,
  SigilumIdentity,
  StoredIdentityRecord,
} from "./types.js";

const IDENTITY_RECORD_VERSION = 1;
const CERTIFICATE_VERSION = 1;
const IDENTITIES_DIR = "identities";

export const DEFAULT_SIGILUM_HOME = path.join(os.homedir(), ".sigilum");

function normalizeNamespace(raw: string): string {
  const namespace = raw.trim().toLowerCase();
  if (!namespace) {
    throw new Error("Namespace is required");
  }
  if (!/^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/.test(namespace)) {
    throw new Error(
      "Namespace must match ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$ (3-64 chars, lowercase)",
    );
  }
  return namespace;
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4;
  const padded = normalized + (pad === 0 ? "" : "=".repeat(4 - pad));
  return new Uint8Array(Buffer.from(padded, "base64"));
}

function getHomeDir(explicitHomeDir?: string): string {
  return explicitHomeDir ?? process.env.SIGILUM_HOME ?? DEFAULT_SIGILUM_HOME;
}

function getIdentityDir(homeDir: string, namespace: string): string {
  return path.join(homeDir, IDENTITIES_DIR, namespace);
}

function getIdentityPath(homeDir: string, namespace: string): string {
  return path.join(getIdentityDir(homeDir, namespace), "identity.json");
}

function makeDid(namespace: string): string {
  return `did:sigilum:${namespace}`;
}

function makeFingerprint(publicKey: Uint8Array): string {
  return bytesToHex(sha256(publicKey).slice(0, 8));
}

function makeKeyId(did: string, publicKey: Uint8Array): string {
  return `${did}#ed25519-${makeFingerprint(publicKey)}`;
}

function buildCertificatePayload(cert: Omit<SigilumCertificate, "proof">): string {
  return [
    "sigilum-certificate-v1",
    `namespace:${cert.namespace}`,
    `did:${cert.did}`,
    `key-id:${cert.keyId}`,
    `public-key:${cert.publicKey}`,
    `issued-at:${cert.issuedAt}`,
    `expires-at:${cert.expiresAt ?? ""}`,
  ].join("\n");
}

function createIdentityRecord(namespace: string): StoredIdentityRecord {
  const privateKey = ed.utils.randomSecretKey();
  const publicKey = ed.getPublicKey(privateKey);
  const publicKeyBase64 = Buffer.from(publicKey).toString("base64");
  const did = makeDid(namespace);
  const keyId = makeKeyId(did, publicKey);
  const now = new Date().toISOString();

  const unsignedCertificate: Omit<SigilumCertificate, "proof"> = {
    version: CERTIFICATE_VERSION,
    namespace,
    did,
    keyId,
    publicKey: `ed25519:${publicKeyBase64}`,
    issuedAt: now,
    expiresAt: null,
  };

  const certificatePayload = new TextEncoder().encode(
    buildCertificatePayload(unsignedCertificate),
  );
  const certificateSignature = ed.sign(certificatePayload, privateKey);

  const certificate: SigilumCertificate = {
    ...unsignedCertificate,
    proof: {
      alg: "ed25519",
      sig: toBase64Url(certificateSignature),
    },
  };

  return {
    version: IDENTITY_RECORD_VERSION,
    namespace,
    did,
    keyId,
    publicKey: `ed25519:${publicKeyBase64}`,
    privateKey: Buffer.from(privateKey).toString("base64"),
    certificate,
    createdAt: now,
    updatedAt: now,
  };
}

function writeIdentityRecord(
  homeDir: string,
  namespace: string,
  record: StoredIdentityRecord,
): string {
  const identityDir = getIdentityDir(homeDir, namespace);
  const identityPath = getIdentityPath(homeDir, namespace);
  fs.mkdirSync(identityDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(identityPath, `${JSON.stringify(record, null, 2)}\n`, {
    mode: 0o600,
  });
  return identityPath;
}

function readIdentityRecord(identityPath: string): StoredIdentityRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(identityPath, "utf8"));
  } catch (error) {
    throw new Error(`Failed to read identity file ${identityPath}: ${String(error)}`);
  }

  if (!parsed || typeof parsed !== "object") {
    throw new Error(`Identity file ${identityPath} is invalid`);
  }

  const record = parsed as Partial<StoredIdentityRecord>;
  if (record.version !== IDENTITY_RECORD_VERSION) {
    throw new Error(
      `Unsupported identity version in ${identityPath}: ${String(record.version)}`,
    );
  }

  if (
    !record.namespace
    || !record.did
    || !record.keyId
    || !record.publicKey
    || !record.privateKey
    || !record.certificate
  ) {
    throw new Error(`Identity file ${identityPath} is missing required fields`);
  }

  return record as StoredIdentityRecord;
}

function parsePublicKey(publicKey: string): Uint8Array {
  if (!publicKey.startsWith("ed25519:")) {
    throw new Error(`Unsupported public key format: ${publicKey}`);
  }
  return new Uint8Array(Buffer.from(publicKey.slice("ed25519:".length), "base64"));
}

function resolveNamespace(namespace?: string, homeDir?: string): string {
  if (namespace) {
    return normalizeNamespace(namespace);
  }

  const envNamespace = process.env.SIGILUM_NAMESPACE;
  if (envNamespace) {
    return normalizeNamespace(envNamespace);
  }

  const namespaces = listNamespaces(homeDir);
  if (namespaces.length === 1) {
    const firstNamespace = namespaces[0];
    if (!firstNamespace) {
      throw new Error("Identity lookup failed unexpectedly");
    }
    return firstNamespace;
  }

  if (namespaces.length === 0) {
    throw new Error(
      "No Sigilum identity found. Run `sigilum init <namespace>` first.",
    );
  }

  throw new Error(
    `Multiple identities found (${namespaces.join(", ")}). Pass namespace explicitly or set SIGILUM_NAMESPACE.`,
  );
}

export function verifyCertificate(certificate: SigilumCertificate): boolean {
  if (certificate.version !== CERTIFICATE_VERSION) {
    return false;
  }
  if (certificate.proof.alg !== "ed25519") {
    return false;
  }

  const publicKeyBytes = parsePublicKey(certificate.publicKey);
  const payload = new TextEncoder().encode(
    buildCertificatePayload({
      version: certificate.version,
      namespace: certificate.namespace,
      did: certificate.did,
      keyId: certificate.keyId,
      publicKey: certificate.publicKey,
      issuedAt: certificate.issuedAt,
      expiresAt: certificate.expiresAt,
    }),
  );

  return ed.verify(fromBase64Url(certificate.proof.sig), payload, publicKeyBytes);
}

export function initIdentity(options: InitIdentityOptions): InitIdentityResult {
  const namespace = normalizeNamespace(options.namespace);
  const homeDir = getHomeDir(options.homeDir);
  const identityPath = getIdentityPath(homeDir, namespace);
  const exists = fs.existsSync(identityPath);

  if (exists && !options.force) {
    const identity = loadIdentity({ namespace, homeDir });
    return {
      namespace: identity.namespace,
      did: identity.did,
      keyId: identity.keyId,
      publicKey: identity.publicKey,
      created: false,
      homeDir,
      identityPath,
    };
  }

  const record = createIdentityRecord(namespace);
  const finalPath = writeIdentityRecord(homeDir, namespace, record);

  return {
    namespace,
    did: record.did,
    keyId: record.keyId,
    publicKey: record.publicKey,
    created: true,
    homeDir,
    identityPath: finalPath,
  };
}

export function listNamespaces(explicitHomeDir?: string): string[] {
  const homeDir = getHomeDir(explicitHomeDir);
  const identitiesDir = path.join(homeDir, IDENTITIES_DIR);
  if (!fs.existsSync(identitiesDir)) {
    return [];
  }

  return fs
    .readdirSync(identitiesDir)
    .filter((entry) => {
      const identityPath = path.join(identitiesDir, entry, "identity.json");
      return fs.existsSync(identityPath);
    })
    .sort();
}

export function loadIdentity(options: LoadIdentityOptions = {}): SigilumIdentity {
  const homeDir = getHomeDir(options.homeDir);
  const namespace = resolveNamespace(options.namespace, homeDir);
  const identityPath = getIdentityPath(homeDir, namespace);

  if (!fs.existsSync(identityPath)) {
    throw new Error(
      `Sigilum identity not found for namespace "${namespace}" at ${identityPath}. Run \`sigilum init ${namespace}\` first.`,
    );
  }

  const record = readIdentityRecord(identityPath);

  if (record.namespace !== namespace) {
    throw new Error(
      `Identity namespace mismatch in ${identityPath}: expected ${namespace}, got ${record.namespace}`,
    );
  }

  const privateKey = new Uint8Array(Buffer.from(record.privateKey, "base64"));
  if (privateKey.length !== 32) {
    throw new Error(`Invalid private key length in ${identityPath}`);
  }

  const derivedPublicKey = ed.getPublicKey(privateKey);
  const derivedPublicKeyBase64 = Buffer.from(derivedPublicKey).toString("base64");
  const expectedPublicKey = `ed25519:${derivedPublicKeyBase64}`;
  if (expectedPublicKey !== record.publicKey) {
    throw new Error(`Public key mismatch in ${identityPath}`);
  }

  if (!verifyCertificate(record.certificate)) {
    throw new Error(`Identity certificate verification failed for ${identityPath}`);
  }

  if (
    record.certificate.namespace !== namespace
    || record.certificate.did !== record.did
    || record.certificate.keyId !== record.keyId
    || record.certificate.publicKey !== record.publicKey
  ) {
    throw new Error(`Identity certificate fields do not match record in ${identityPath}`);
  }

  return {
    namespace,
    did: record.did,
    keyId: record.keyId,
    publicKey: record.publicKey,
    privateKey,
    certificate: record.certificate,
    homeDir,
    identityPath,
  };
}

export function getNamespaceApiBase(apiBaseUrl: string, namespace: string): string {
  const base = apiBaseUrl.replace(/\/+$/, "");
  return `${base}/v1/namespaces/${encodeURIComponent(namespace)}`;
}
