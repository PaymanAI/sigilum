import { createErrorResponse, type ApiError } from "./validation.js";

type SigilumCertificate = {
  version: number;
  namespace: string;
  did: string;
  keyId: string;
  publicKey: string;
  issuedAt: string;
  expiresAt: string | null;
  proof: {
    alg: string;
    sig: string;
  };
};

type SignatureInputParts = {
  components: string[];
  created: number;
  keyId: string;
  alg: string;
  nonce: string;
};

export type VerifySignedHttpRequestOptions = {
  request: Request;
  bodyBytes: Uint8Array | null;
  expectedNamespace?: string;
  expectedPublicKey?: string;
  maxAgeSeconds: number;
  nowEpochSeconds?: number;
};

export type VerifySignedHttpRequestSuccess = {
  valid: true;
  namespace: string;
  subject: string;
  publicKey: string;
  keyId: string;
  nonce: string;
  created: number;
};

export type VerifySignedHttpRequestFailure = {
  valid: false;
  status: number;
  error: ApiError;
};

export type VerifySignedHttpRequestResult =
  | VerifySignedHttpRequestSuccess
  | VerifySignedHttpRequestFailure;

function toFailure(
  message: string,
  code: string,
  status: number,
): VerifySignedHttpRequestFailure {
  return {
    valid: false,
    status,
    error: createErrorResponse(message, code),
  };
}

function toBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return fromBase64(padded);
}

function parseSignatureInput(value: string): SignatureInputParts | null {
  const match = value.match(
    /^sig1=\(([^)]*)\);created=(\d+);keyid="([^"]+)";alg="([^"]+)";nonce="([^"]+)"$/,
  );
  if (!match) return null;

  const rawComponents = match[1];
  const createdRaw = match[2];
  const keyId = match[3];
  const alg = match[4];
  const nonce = match[5];
  if (!rawComponents || !createdRaw || !keyId || !alg || !nonce) return null;

  const components = rawComponents
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((token) => {
      if (!/^"[^"]+"$/.test(token)) return null;
      return token.slice(1, -1);
    });

  if (components.some((value) => value === null)) return null;
  const created = Number(createdRaw);
  if (!Number.isFinite(created) || created <= 0) return null;

  return {
    components: components as string[],
    created,
    keyId,
    alg,
    nonce,
  };
}

function parseSignatureHeader(value: string): Uint8Array | null {
  const match = value.match(/^sig1=:([^:]+):$/);
  if (!match) return null;
  const encoded = match[1];
  if (!encoded) return null;
  return fromBase64(encoded);
}

function parsePublicKey(publicKey: string): Uint8Array | null {
  if (!publicKey.startsWith("ed25519:")) return null;
  const encoded = publicKey.slice("ed25519:".length);
  try {
    return fromBase64(encoded);
  } catch {
    return null;
  }
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

async function verifyCertificate(certificate: SigilumCertificate): Promise<boolean> {
  if (certificate.version !== 1) return false;
  if (certificate.proof.alg.toLowerCase() !== "ed25519") return false;
  const publicKey = parsePublicKey(certificate.publicKey);
  if (!publicKey) return false;
  const signature = fromBase64Url(certificate.proof.sig);
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
  const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify("Ed25519", key, signature, payload);
}

function normalizedTargetUri(rawUrl: string): string {
  const url = new URL(rawUrl);
  url.hash = "";
  return url.toString();
}

function buildSignatureParams(parts: SignatureInputParts): string {
  const componentList = parts.components.map((c) => `"${c}"`).join(" ");
  return `(${componentList});created=${parts.created};keyid="${parts.keyId}";alg="ed25519";nonce="${parts.nonce}"`;
}

function resolveComponent(
  component: string,
  method: string,
  targetUri: string,
  headers: Headers,
): string | null {
  if (component === "@method") return method.toLowerCase();
  if (component === "@target-uri") return targetUri;
  const value = headers.get(component);
  if (!value) return null;
  return value;
}

function expectedComponents(hasBody: boolean): string[] {
  if (hasBody) {
    return [
      "@method",
      "@target-uri",
      "content-digest",
      "sigilum-namespace",
      "sigilum-subject",
      "sigilum-agent-key",
      "sigilum-agent-cert",
    ];
  }
  return [
    "@method",
    "@target-uri",
    "sigilum-namespace",
    "sigilum-subject",
    "sigilum-agent-key",
    "sigilum-agent-cert",
  ];
}

function equalArrays(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((item, index) => item === b[index]);
}

async function computeContentDigest(bodyBytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bodyBytes);
  return `sha-256=:${toBase64(new Uint8Array(digest))}:`;
}

export async function verifySignedHttpRequest(
  options: VerifySignedHttpRequestOptions,
): Promise<VerifySignedHttpRequestResult> {
  const headers = options.request.headers;
  const signatureInputHeader = headers.get("signature-input");
  const signatureHeader = headers.get("signature");
  const certHeader = headers.get("sigilum-agent-cert");
  const keyHeader = headers.get("sigilum-agent-key");
  const namespaceHeader = headers.get("sigilum-namespace");
  const subjectHeader = headers.get("sigilum-subject");

  if (!signatureInputHeader || !signatureHeader || !certHeader || !keyHeader || !namespaceHeader || !subjectHeader) {
    return toFailure("Missing required signed-auth headers", "SIGNATURE_MISSING", 401);
  }

  const signatureInput = parseSignatureInput(signatureInputHeader);
  if (!signatureInput) {
    return toFailure("Invalid Signature-Input header format", "SIGNATURE_INVALID", 401);
  }
  if (signatureInput.alg.toLowerCase() !== "ed25519") {
    return toFailure("Unsupported signature algorithm", "SIGNATURE_INVALID", 401);
  }

  const signature = parseSignatureHeader(signatureHeader);
  if (!signature) {
    return toFailure("Invalid Signature header format", "SIGNATURE_INVALID", 401);
  }

  const now = options.nowEpochSeconds ?? Math.floor(Date.now() / 1000);
  const age = now - signatureInput.created;
  if (age < 0 || age > options.maxAgeSeconds) {
    return toFailure("Signature expired or not yet valid", "SIGNATURE_EXPIRED", 401);
  }

  let certificate: SigilumCertificate;
  try {
    certificate = JSON.parse(new TextDecoder().decode(fromBase64Url(certHeader))) as SigilumCertificate;
  } catch {
    return toFailure("Invalid sigilum-agent-cert header", "SIGNATURE_INVALID", 401);
  }

  if (!(await verifyCertificate(certificate))) {
    return toFailure("Invalid agent certificate", "SIGNATURE_INVALID", 401);
  }
  if (certificate.publicKey !== keyHeader) {
    return toFailure("Certificate public key mismatch", "SIGNATURE_INVALID", 401);
  }
  if (certificate.namespace !== namespaceHeader) {
    return toFailure("Namespace header mismatch", "SIGNATURE_INVALID", 401);
  }
  if (options.expectedNamespace && certificate.namespace !== options.expectedNamespace) {
    return toFailure("Namespace does not match request", "SIGNATURE_NAMESPACE_MISMATCH", 403);
  }
  if (options.expectedPublicKey && certificate.publicKey !== options.expectedPublicKey) {
    return toFailure("Public key does not match request", "SIGNATURE_KEY_MISMATCH", 403);
  }
  if (signatureInput.keyId !== certificate.keyId) {
    return toFailure("Signature key ID mismatch", "SIGNATURE_INVALID", 401);
  }

  const expected = expectedComponents(Boolean(options.bodyBytes && options.bodyBytes.length > 0));
  if (!equalArrays(signatureInput.components, expected)) {
    return toFailure("Invalid signed component set", "SIGNATURE_COMPONENTS_INVALID", 401);
  }

  if (options.bodyBytes && options.bodyBytes.length > 0) {
    const expectedDigest = await computeContentDigest(options.bodyBytes);
    const actualDigest = headers.get("content-digest");
    if (!actualDigest || actualDigest !== expectedDigest) {
      return toFailure("Content digest mismatch", "SIGNATURE_DIGEST_MISMATCH", 401);
    }
  }

  const targetUri = normalizedTargetUri(options.request.url);
  const lines: string[] = [];
  for (const component of signatureInput.components) {
    const value = resolveComponent(component, options.request.method, targetUri, headers);
    if (!value) {
      return toFailure(`Missing required signed header: ${component}`, "SIGNATURE_INVALID", 401);
    }
    lines.push(`"${component}": ${value}`);
  }
  const signatureParams = buildSignatureParams(signatureInput);
  lines.push(`"@signature-params": ${signatureParams}`);
  const signingBase = new TextEncoder().encode(lines.join("\n"));

  const publicKey = parsePublicKey(keyHeader);
  if (!publicKey) {
    return toFailure("Invalid sigilum-agent-key header", "SIGNATURE_INVALID", 401);
  }
  const imported = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  const validSignature = await crypto.subtle.verify("Ed25519", imported, signature, signingBase);
  if (!validSignature) {
    return toFailure("Signature verification failed", "SIGNATURE_INVALID", 401);
  }

  return {
    valid: true,
    namespace: certificate.namespace,
    subject: subjectHeader.trim(),
    publicKey: certificate.publicKey,
    keyId: certificate.keyId,
    nonce: signatureInput.nonce,
    created: signatureInput.created,
  };
}
