import { Hono } from "hono";
import type { Env } from "../types.js";
import { createErrorResponse } from "../utils/validation.js";

export const verifyRouter = new Hono<{ Bindings: Env }>();

type ApprovedClaimLookup =
  | {
    available: true;
    table: "authorizations" | "claims";
    claimId?: string;
    approvedAt?: string;
  }
  | { available: false; error: string };

function toErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  return String(err);
}

async function queryApprovedClaim(
  env: Env,
  table: "authorizations" | "claims",
  namespace: string,
  publicKey: string,
  service: string,
): Promise<{ claimId?: string; approvedAt?: string }> {
  const row = await env.DB.prepare(
    `SELECT claim_id, approved_at
     FROM ${table}
     WHERE namespace = ? AND public_key = ? AND service = ? AND status = 'approved'
     LIMIT 1`,
  )
    .bind(namespace, publicKey, service)
    .first<{ claim_id?: string; approved_at?: string }>();
  if (!row?.claim_id) {
    return {};
  }
  return { claimId: row.claim_id, approvedAt: row.approved_at };
}

async function findApprovedClaim(
  env: Env,
  namespace: string,
  publicKey: string,
  service: string,
): Promise<ApprovedClaimLookup> {
  const errors: string[] = [];

  try {
    const claim = await queryApprovedClaim(env, "authorizations", namespace, publicKey, service);
    return {
      available: true,
      table: "authorizations",
      claimId: claim.claimId,
      approvedAt: claim.approvedAt,
    };
  } catch (err) {
    errors.push(`authorizations: ${toErrorMessage(err)}`);
  }

  try {
    const claim = await queryApprovedClaim(env, "claims", namespace, publicKey, service);
    return {
      available: true,
      table: "claims",
      claimId: claim.claimId,
      approvedAt: claim.approvedAt,
    };
  } catch (err) {
    errors.push(`claims: ${toErrorMessage(err)}`);
  }

  return { available: false, error: errors.join(" | ") };
}

/**
 * GET /v1/verify?namespace=...&public_key=...&service=...
 * Check if an agent is authorized for a service.
 * System-of-record is the local D1 database.
 */
verifyRouter.get("/", async (c) => {
  const namespace = c.req.query("namespace");
  const publicKey = c.req.query("public_key");
  const service = c.req.query("service");

  if (!namespace || !publicKey || !service) {
    return c.json(
      createErrorResponse("namespace, public_key, and service query parameters are required", "VALIDATION_ERROR"),
      400,
    );
  }

  const lookup = await findApprovedClaim(c.env, namespace, publicKey, service);
  if (!lookup.available) {
    console.error("D1 lookup failed for /v1/verify:", lookup.error);
    return c.json(createErrorResponse("Authorization store unavailable", "DB_UNAVAILABLE"), 503);
  }

  if (!lookup.claimId) {
    return c.json({ authorized: false, reason: "no_approved_claim" });
  }

  return c.json({
    authorized: true,
    claim_id: lookup.claimId,
    approved_at: lookup.approvedAt,
  });
});
