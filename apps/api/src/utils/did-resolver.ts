const DID_METHOD_PREFIX = "did:sigilum:";
const DID_RESOLUTION_CONTEXT = "https://w3id.org/did-resolution/v1";
const DID_DOCUMENT_CONTEXT = "https://www.w3.org/ns/did/v1";
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const NAMESPACE_RE = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,62}[a-zA-Z0-9]$/;

export type SigilumDidResolutionError = "invalidDid" | "notFound" | "internalError";

export type SigilumDidDocument = {
  "@context": string;
  id: string;
  controller: string;
  verificationMethod: Array<{
    id: string;
    type: "Ed25519VerificationKey2020";
    controller: string;
    publicKeyMultibase: string;
  }>;
  authentication: string[];
  assertionMethod: string[];
  service?: Array<{
    id: string;
    type: "AgentEndpoint";
    serviceEndpoint: string;
  }>;
};

export type SigilumDidResolutionResult = {
  "@context": string;
  didDocument: SigilumDidDocument | null;
  didDocumentMetadata: {
    created?: string;
    updated?: string;
    deactivated?: boolean;
  };
  didResolutionMetadata: {
    contentType?: string;
    error?: SigilumDidResolutionError;
    message?: string;
  };
};

type NamespaceRow = {
  id: string;
  namespace: string;
  created_at?: string;
  updated_at?: string;
};

type ApprovedClaimRow = {
  claim_id: string;
  service: string;
  status: string;
  public_key: string;
};

type NamespaceClaimPresenceRow = {
  claim_id: string;
};

function decodeBase64Like(value: string): Uint8Array | null {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4;
  const padded = padding === 0 ? normalized : `${normalized}${"=".repeat(4 - padding)}`;
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

function decodeHex(value: string): Uint8Array | null {
  if (!value || value.length % 2 !== 0) return null;
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < value.length; i += 2) {
    const parsed = Number.parseInt(value.slice(i, i + 2), 16);
    if (!Number.isFinite(parsed)) return null;
    bytes[i / 2] = parsed;
  }
  return bytes;
}

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) + BigInt(byte);
  }

  let encoded = "";
  while (value > 0n) {
    const remainder = Number(value % 58n);
    encoded = BASE58_ALPHABET[remainder] + encoded;
    value /= 58n;
  }

  let leadingZeroCount = 0;
  while (leadingZeroCount < bytes.length && bytes[leadingZeroCount] === 0) {
    leadingZeroCount += 1;
  }

  return `${"1".repeat(leadingZeroCount)}${encoded}`;
}

function toPublicKeyMultibase(rawValue: string): string | null {
  const trimmed = rawValue.trim();
  if (!trimmed) return null;

  if (trimmed.startsWith("z")) {
    return trimmed;
  }

  let bytes: Uint8Array | null = null;
  if (trimmed.startsWith("ed25519:")) {
    bytes = decodeBase64Like(trimmed.slice("ed25519:".length).trim());
  } else if (trimmed.startsWith("0x")) {
    bytes = decodeHex(trimmed.slice(2));
  } else {
    bytes = decodeBase64Like(trimmed);
  }

  if (!bytes || bytes.length === 0) return null;
  return `z${base58Encode(bytes)}`;
}

function sanitizeFragmentToken(value: string): string {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  return normalized || "service";
}

export function parseSigilumDid(didInput: string): { did: string; namespace: string } | null {
  const trimmed = didInput.trim();
  if (!trimmed.startsWith(DID_METHOD_PREFIX)) return null;

  // Resolver handles base DID identifier; ignore fragment/query/path if present.
  const withoutPrefix = trimmed.slice(DID_METHOD_PREFIX.length);
  const stopAt = [withoutPrefix.indexOf("#"), withoutPrefix.indexOf("?"), withoutPrefix.indexOf("/")]
    .filter((index) => index >= 0)
    .sort((a, b) => a - b)[0];

  const namespace = stopAt === undefined ? withoutPrefix : withoutPrefix.slice(0, stopAt);
  if (!NAMESPACE_RE.test(namespace)) return null;
  return { did: `${DID_METHOD_PREFIX}${namespace}`, namespace };
}

function buildDidDocument(
  did: string,
  namespace: string,
  claims: ApprovedClaimRow[],
  resolverOrigin: string,
): SigilumDidDocument {
  const verificationMethodByKey = new Map<string, string>();
  const verificationMethod: SigilumDidDocument["verificationMethod"] = [];

  for (const claim of claims) {
    const multibase = toPublicKeyMultibase(String(claim.public_key ?? ""));
    if (!multibase) continue;
    if (verificationMethodByKey.has(multibase)) continue;

    const keyIndex = verificationMethod.length + 1;
    const methodId = `${did}#key-${keyIndex}`;
    verificationMethodByKey.set(multibase, methodId);
    verificationMethod.push({
      id: methodId,
      type: "Ed25519VerificationKey2020",
      controller: did,
      publicKeyMultibase: multibase,
    });
  }

  const serviceNames = [...new Set(claims.map((claim) => String(claim.service ?? "").trim()).filter(Boolean))];
  serviceNames.sort((a, b) => a.localeCompare(b));
  const service = serviceNames.map((serviceName) => {
    const endpoint =
      `${resolverOrigin}/v1/verify?namespace=${encodeURIComponent(namespace)}` +
      `&service=${encodeURIComponent(serviceName)}`;
    return {
      id: `${did}#agent-runtime-${sanitizeFragmentToken(serviceName)}`,
      type: "AgentEndpoint" as const,
      serviceEndpoint: endpoint,
    };
  });

  return {
    "@context": DID_DOCUMENT_CONTEXT,
    id: did,
    controller: did,
    verificationMethod,
    authentication: verificationMethod.map((method) => method.id),
    assertionMethod: verificationMethod.map((method) => method.id),
    ...(service.length > 0 ? { service } : {}),
  };
}

export function didResolutionHttpStatus(error?: SigilumDidResolutionError): number {
  switch (error) {
    case "invalidDid":
      return 400;
    case "notFound":
      return 404;
    case "internalError":
      return 500;
    default:
      return 200;
  }
}

export async function resolveSigilumDid(
  db: D1Database,
  didInput: string,
  resolverOrigin: string,
): Promise<SigilumDidResolutionResult> {
  const parsed = parseSigilumDid(didInput);
  if (!parsed) {
    return {
      "@context": DID_RESOLUTION_CONTEXT,
      didDocument: null,
      didDocumentMetadata: {},
      didResolutionMetadata: {
        error: "invalidDid",
        message: "Invalid DID format. Expected did:sigilum:<namespace>",
      },
    };
  }

  const { did, namespace } = parsed;

  const user = await db.prepare(
    "SELECT id, namespace, created_at, updated_at FROM users WHERE namespace = ? LIMIT 1",
  ).bind(namespace).first<NamespaceRow>();

  if (!user) {
    const historicalClaim = await db.prepare(
      "SELECT claim_id FROM authorizations WHERE namespace = ? LIMIT 1",
    ).bind(namespace).first<NamespaceClaimPresenceRow>();

    if (historicalClaim?.claim_id) {
      return {
        "@context": DID_RESOLUTION_CONTEXT,
        didDocument: {
          "@context": DID_DOCUMENT_CONTEXT,
          id: did,
          controller: did,
          verificationMethod: [],
          authentication: [],
          assertionMethod: [],
        },
        didDocumentMetadata: {
          deactivated: true,
        },
        didResolutionMetadata: {
          contentType: "application/did+ld+json",
        },
      };
    }

    return {
      "@context": DID_RESOLUTION_CONTEXT,
      didDocument: null,
      didDocumentMetadata: {},
      didResolutionMetadata: {
        error: "notFound",
        message: "DID not found",
      },
    };
  }

  const claimsRows = await db.prepare(
    `SELECT claim_id, service, status, public_key
     FROM authorizations
     WHERE namespace = ? AND status = 'approved'
     ORDER BY approved_at DESC, created_at DESC`,
  ).bind(namespace).all<ApprovedClaimRow>();

  const didDocument = buildDidDocument(did, namespace, claimsRows.results, resolverOrigin);
  const createdAt = user.created_at ?? new Date().toISOString();
  const updatedAt = user.updated_at ?? createdAt;

  return {
    "@context": DID_RESOLUTION_CONTEXT,
    didDocument,
    didDocumentMetadata: {
      created: createdAt,
      updated: updatedAt,
      deactivated: false,
    },
    didResolutionMetadata: {
      contentType: "application/did+ld+json",
    },
  };
}
