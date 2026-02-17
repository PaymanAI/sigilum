import { Hono } from "hono";
import type { Env } from "../types.js";
import { createErrorResponse } from "../utils/validation.js";

/** Namespace portion of a DID must be 3-64 characters, alphanumeric and hyphens only. */
const NAMESPACE_RE = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,62}[a-zA-Z0-9]$/;

export const didRouter = new Hono<{ Bindings: Env }>();

function normalizePublicKeyBase64(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith("ed25519:")) {
    const base64 = trimmed.slice("ed25519:".length).trim();
    return base64 || null;
  }
  if (trimmed.startsWith("0x")) {
    const hex = trimmed.slice(2);
    if (!hex || hex.length % 2 !== 0) return null;
    try {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
      }
      let binary = "";
      for (const byte of bytes) {
        binary += String.fromCharCode(byte);
      }
      return btoa(binary);
    } catch {
      return null;
    }
  }
  return trimmed;
}

/**
 * GET /.well-known/did/:did
 * Resolve a DID document (W3C format).
 */
didRouter.get("/:did", async (c) => {
  const did = c.req.param("did");

  if (!did.startsWith("did:sigilum:")) {
    return c.json(createErrorResponse("Invalid DID format. Expected did:sigilum:<namespace>", "VALIDATION_ERROR"), 400);
  }

  // Validate the namespace portion of the DID
  const namespace = did.slice("did:sigilum:".length);
  if (!NAMESPACE_RE.test(namespace)) {
    return c.json(createErrorResponse("Invalid DID format. Expected did:sigilum:<namespace>", "VALIDATION_ERROR"), 400);
  }

  const user = await c.env.DB.prepare(
    "SELECT id, namespace, created_at, updated_at FROM users WHERE namespace = ? LIMIT 1",
  ).bind(namespace).first<{ id: string; namespace: string; created_at?: string; updated_at?: string }>();

  if (!user) {
    return c.json(createErrorResponse("DID not found", "NOT_FOUND"), 404);
  }

  const claimsRows = await c.env.DB.prepare(
    `SELECT claim_id, service, status, public_key
     FROM authorizations
     WHERE namespace = ? AND status = 'approved'
     ORDER BY approved_at DESC, created_at DESC`,
  ).bind(namespace).all<{ claim_id: string; service: string; status: string; public_key: string }>();

  const verificationMethod = claimsRows.results
    .map((claim) => {
      const publicKeyBase64 = normalizePublicKeyBase64(String(claim.public_key ?? ""));
      if (!publicKeyBase64) return null;
      const claimID = String(claim.claim_id ?? "");
      return {
        id: `did:sigilum:${namespace}#claim-${claimID.slice(0, 10)}`,
        type: "Ed25519VerificationKey2020",
        publicKeyBase64,
        service: String(claim.service ?? ""),
        status: String(claim.status ?? "approved"),
      };
    })
    .filter((value): value is NonNullable<typeof value> => Boolean(value));

  const createdAt = user.created_at ?? new Date().toISOString();
  const updatedAt = user.updated_at ?? createdAt;

  c.header("Content-Type", "application/did+json");
  c.header("Cache-Control", "public, max-age=300");

  return c.json({
    "@context": ["https://www.w3.org/ns/did/v1", "https://spec.sigilum.id/v1"],
    id: did,
    controller: did,
    created: createdAt,
    updated: updatedAt,
    verificationMethod,
  });
});
