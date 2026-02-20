import "./setup.js";
import * as ed from "@noble/ed25519";
import { createHash, randomUUID } from "node:crypto";
import { verifyCertificate } from "./identity-store.js";
import type {
  SigilumCertificate,
  SigilumIdentity,
  SignRequestInput,
  SignedRequest,
  VerifySignatureInput,
  VerifySignatureResult,
} from "./types.js";

type SignatureInputParts = {
  components: string[];
  created: number;
  keyId: string;
  alg: string;
  nonce: string;
};

const REQUIRED_COMPONENTS_NO_BODY = [
  "@method",
  "@target-uri",
  "sigilum-namespace",
  "sigilum-subject",
  "sigilum-agent-key",
  "sigilum-agent-cert",
] as const;

const REQUIRED_COMPONENTS_WITH_BODY = [
  "@method",
  "@target-uri",
  "content-digest",
  "sigilum-namespace",
  "sigilum-subject",
  "sigilum-agent-key",
  "sigilum-agent-cert",
] as const;

function normalizeUrl(input: string | URL): URL {
  const url = input instanceof URL ? new URL(input.toString()) : new URL(input);
  url.hash = "";
  return url;
}

function normalizeBody(
  body: SignRequestInput["body"],
): Uint8Array | null {
  if (body == null) {
    return null;
  }
  if (typeof body === "string") {
    return new TextEncoder().encode(body);
  }
  if (body instanceof Uint8Array) {
    return body;
  }
  if (body instanceof ArrayBuffer) {
    return new Uint8Array(body);
  }

  throw new Error(
    "Unsupported body type for signing. Use string, Uint8Array, ArrayBuffer, or null.",
  );
}

function buildSignatureParams(parts: {
  components: string[];
  created: number;
  keyId: string;
  nonce: string;
}): string {
  const componentList = parts.components.map((component) => `"${component}"`).join(" ");
  return `(${componentList});created=${parts.created};keyid="${parts.keyId}";alg="ed25519";nonce="${parts.nonce}"`;
}

function resolveComponentValue(component: string, context: {
  method: string;
  url: URL;
  headers: Headers;
}): string {
  if (component === "@method") {
    // RFC 9421 derived component @method is lower-case.
    return context.method.toLowerCase();
  }
  if (component === "@target-uri") {
    return context.url.toString();
  }

  const headerValue = context.headers.get(component);
  if (!headerValue) {
    throw new Error(`Missing required signed header: ${component}`);
  }
  return headerValue;
}

function buildSigningBase(context: {
  components: string[];
  method: string;
  url: URL;
  headers: Headers;
  signatureParams: string;
}): string {
  const lines = context.components.map((component) => {
    const value = resolveComponentValue(component, {
      method: context.method,
      url: context.url,
      headers: context.headers,
    });
    return `"${component}": ${value}`;
  });

  lines.push(`"@signature-params": ${context.signatureParams}`);
  return lines.join("\n");
}

function parsePublicKey(publicKey: string): Uint8Array {
  if (!publicKey.startsWith("ed25519:")) {
    throw new Error("Unsupported public key format");
  }
  return new Uint8Array(Buffer.from(publicKey.slice("ed25519:".length), "base64"));
}

function hasComponent(components: string[], expected: string): boolean {
  return components.some((component) => component.trim() === expected);
}

function hasValidSignedComponentSet(
  components: string[],
  hasBody: boolean,
): boolean {
  const expected = hasBody
    ? REQUIRED_COMPONENTS_WITH_BODY
    : REQUIRED_COMPONENTS_NO_BODY;
  if (components.length !== expected.length) {
    return false;
  }
  for (let index = 0; index < expected.length; index += 1) {
    if (components[index] !== expected[index]) {
      return false;
    }
  }
  return true;
}

export function encodeCertificateHeader(certificate: SigilumCertificate): string {
  return Buffer.from(JSON.stringify(certificate), "utf8").toString("base64url");
}

export function decodeCertificateHeader(value: string): SigilumCertificate {
  const decoded = Buffer.from(value, "base64url").toString("utf8");
  return JSON.parse(decoded) as SigilumCertificate;
}

function parseSignatureInputHeader(value: string): SignatureInputParts {
  const match = value.match(
    /^sig1=\(([^)]*)\);created=(\d+);keyid="([^"]+)";alg="([^"]+)";nonce="([^"]+)"$/,
  );

  if (!match) {
    throw new Error("Invalid Signature-Input header format");
  }

  const rawComponents = match[1];
  const createdRaw = match[2];
  const keyId = match[3];
  const alg = match[4];
  const nonce = match[5];
  if (!rawComponents || !createdRaw || !keyId || !alg || !nonce) {
    throw new Error("Invalid Signature-Input header parts");
  }

  const components = rawComponents
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((token) => {
      if (!/^"[^"]+"$/.test(token)) {
        throw new Error(`Invalid component in Signature-Input: ${token}`);
      }
      return token.slice(1, -1);
    });

  return {
    components,
    created: Number(createdRaw),
    keyId,
    alg,
    nonce,
  };
}

function parseSignatureHeader(value: string): Uint8Array {
  const match = value.match(/^sig1=:([^:]+):$/);
  if (!match) {
    throw new Error("Invalid Signature header format");
  }
  const encoded = match[1];
  if (!encoded) {
    throw new Error("Invalid Signature header value");
  }
  return new Uint8Array(Buffer.from(encoded, "base64"));
}

function computeContentDigest(bodyBytes: Uint8Array): string {
  const digest = createHash("sha256").update(bodyBytes).digest("base64");
  return `sha-256=:${digest}:`;
}

export function signHttpRequest(
  identity: SigilumIdentity,
  request: SignRequestInput,
): SignedRequest {
  const url = normalizeUrl(request.url);
  const method = (request.method ?? "GET").toUpperCase();
  const headers = new Headers((request.headers ?? {}) as any);
  const bodyBytes = normalizeBody(request.body);

  if (bodyBytes && bodyBytes.length > 0) {
    headers.set("content-digest", computeContentDigest(bodyBytes));
  }

  headers.set("sigilum-namespace", identity.namespace);
  const resolvedSubject =
    request.subject?.trim() ||
    headers.get("sigilum-subject")?.trim() ||
    identity.namespace;
  headers.set("sigilum-subject", resolvedSubject);
  headers.set("sigilum-agent-key", identity.publicKey);
  headers.set("sigilum-agent-cert", encodeCertificateHeader(identity.certificate));

  const components = bodyBytes && bodyBytes.length > 0
    ? [
      "@method",
      "@target-uri",
      "content-digest",
      "sigilum-namespace",
      "sigilum-subject",
      "sigilum-agent-key",
      "sigilum-agent-cert",
    ]
    : ["@method", "@target-uri", "sigilum-namespace", "sigilum-subject", "sigilum-agent-key", "sigilum-agent-cert"];

  const created = request.created ?? Math.floor(Date.now() / 1000);
  const nonce = request.nonce ?? randomUUID();
  const signatureParams = buildSignatureParams({
    components,
    created,
    keyId: identity.keyId,
    nonce,
  });

  const signingBase = buildSigningBase({
    components,
    method,
    url,
    headers,
    signatureParams,
  });

  const signatureBytes = ed.sign(
    new TextEncoder().encode(signingBase),
    identity.privateKey,
  );

  headers.set("signature-input", `sig1=${signatureParams}`);
  headers.set("signature", `sig1=:${Buffer.from(signatureBytes).toString("base64")}:`);

  return {
    url: url.toString(),
    method,
    headers,
    body: request.body ?? null,
  };
}

export function verifyHttpSignature(
  request: VerifySignatureInput,
): VerifySignatureResult {
  const invalid = (code: string, reason: string): VerifySignatureResult => ({
    valid: false,
    code,
    reason,
  });

  try {
    const headers = new Headers(request.headers as any);
    const signatureInput = headers.get("signature-input");
    const signatureHeader = headers.get("signature");

    if (!signatureInput || !signatureHeader) {
      return invalid("SIG_MISSING_SIGNATURE_HEADERS", "Missing Signature-Input or Signature header");
    }

    let parsedInput: SignatureInputParts;
    try {
      parsedInput = parseSignatureInputHeader(signatureInput);
    } catch (error) {
      return invalid(
        "SIG_SIGNATURE_INPUT_INVALID",
        error instanceof Error ? error.message : String(error),
      );
    }
    if (!Number.isFinite(parsedInput.created) || parsedInput.created <= 0) {
      return invalid("SIG_CREATED_INVALID", "Invalid Signature-Input created timestamp");
    }
    if (parsedInput.alg.toLowerCase() !== "ed25519") {
      return invalid("SIG_ALGORITHM_UNSUPPORTED", "Unsupported signature algorithm");
    }

    const strict = request.strict;
    if (strict?.maxAgeSeconds != null) {
      const now = strict.now ?? Math.floor(Date.now() / 1000);
      const age = now - parsedInput.created;
      if (age < 0 || age > strict.maxAgeSeconds) {
        return invalid("SIG_TIMESTAMP_OUT_OF_RANGE", "Signature expired or not yet valid");
      }
    }
    if (strict?.nonceStore) {
      if (strict.nonceStore.has(parsedInput.nonce)) {
        return invalid("SIG_REPLAY_DETECTED", "Replay detected: nonce already seen");
      }
      strict.nonceStore.add(parsedInput.nonce);
    }

    let signature: Uint8Array;
    try {
      signature = parseSignatureHeader(signatureHeader);
    } catch (error) {
      return invalid(
        "SIG_SIGNATURE_HEADER_INVALID",
        error instanceof Error ? error.message : String(error),
      );
    }
    const method = request.method.toUpperCase();
    const url = normalizeUrl(request.url);
    const signatureParams = buildSignatureParams({
      components: parsedInput.components,
      created: parsedInput.created,
      keyId: parsedInput.keyId,
      nonce: parsedInput.nonce,
    });

    let signingBase: string;
    try {
      signingBase = buildSigningBase({
        components: parsedInput.components,
        method,
        url,
        headers,
        signatureParams,
      });
    } catch (error) {
      return invalid(
        "SIG_SIGNING_BASE_INVALID",
        error instanceof Error ? error.message : String(error),
      );
    }

    const certificateHeader = headers.get("sigilum-agent-cert");
    if (!certificateHeader) {
      return invalid("SIG_CERT_HEADER_MISSING", "Missing sigilum-agent-cert header");
    }
    let certificate: SigilumCertificate;
    try {
      certificate = decodeCertificateHeader(certificateHeader);
    } catch (error) {
      return invalid(
        "SIG_CERT_HEADER_INVALID",
        error instanceof Error ? error.message : String(error),
      );
    }

    if (!verifyCertificate(certificate)) {
      return invalid("SIG_CERT_INVALID", "Invalid agent certificate");
    }

    const publicKeyHeader = headers.get("sigilum-agent-key");
    if (!publicKeyHeader) {
      return invalid("SIG_KEY_HEADER_MISSING", "Missing sigilum-agent-key header");
    }

    if (certificate.publicKey !== publicKeyHeader) {
      return invalid("SIG_KEY_MISMATCH", "Certificate public key mismatch");
    }

    const namespaceHeader = headers.get("sigilum-namespace");
    if (!namespaceHeader || namespaceHeader !== certificate.namespace) {
      return invalid("SIG_NAMESPACE_MISMATCH", "Namespace header mismatch");
    }
    const subjectHeader = headers.get("sigilum-subject")?.trim();
    if (!subjectHeader) {
      return invalid("SIG_SUBJECT_MISSING", "Missing sigilum-subject header");
    }
    if (!hasComponent(parsedInput.components, "sigilum-subject")) {
      return invalid("SIG_SUBJECT_COMPONENT_MISSING", "Missing sigilum-subject in signed components");
    }

    const bodyBytes = normalizeBody(request.body);
    const hasBody = Boolean(bodyBytes && bodyBytes.length > 0);
    if (!hasValidSignedComponentSet(parsedInput.components, hasBody)) {
      return invalid("SIG_SIGNED_COMPONENTS_INVALID", "Invalid signed component set");
    }

    if (request.expectedNamespace && request.expectedNamespace !== namespaceHeader) {
      return invalid(
        "SIG_EXPECTED_NAMESPACE_MISMATCH",
        `Namespace mismatch: expected ${request.expectedNamespace}, got ${namespaceHeader}`,
      );
    }
    if (request.expectedSubject && request.expectedSubject !== subjectHeader) {
      return invalid(
        "SIG_EXPECTED_SUBJECT_MISMATCH",
        `Subject mismatch: expected ${request.expectedSubject}, got ${subjectHeader}`,
      );
    }

    if (parsedInput.keyId !== certificate.keyId) {
      return invalid("SIG_KEY_ID_MISMATCH", "keyid mismatch");
    }

    if (bodyBytes && bodyBytes.length > 0) {
      const expectedDigest = computeContentDigest(bodyBytes);
      if (headers.get("content-digest") !== expectedDigest) {
        return invalid("SIG_CONTENT_DIGEST_MISMATCH", "Content digest mismatch");
      }
    }

    let publicKey: Uint8Array;
    try {
      publicKey = parsePublicKey(publicKeyHeader);
    } catch (error) {
      return invalid(
        "SIG_KEY_HEADER_INVALID",
        error instanceof Error ? error.message : String(error),
      );
    }
    const valid = ed.verify(
      signature,
      new TextEncoder().encode(signingBase),
      publicKey,
    );

    if (!valid) {
      return invalid("SIG_VERIFICATION_FAILED", "Signature verification failed");
    }

    return {
      valid: true,
      namespace: certificate.namespace,
      subject: subjectHeader,
      keyId: certificate.keyId,
    };
  } catch (error) {
    return invalid("SIG_INTERNAL_ERROR", error instanceof Error ? error.message : String(error));
  }
}
