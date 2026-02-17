import { Hono } from "hono";
import type { Env } from "../types.js";
import { createErrorResponse } from "../utils/validation.js";

export const verifyRouter = new Hono<{ Bindings: Env }>();

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

  let claim: { claim_id?: string; approved_at?: string } | null = null;
  try {
    claim = await c.env.DB.prepare(
      `SELECT claim_id, approved_at
       FROM authorizations
       WHERE namespace = ? AND public_key = ? AND service = ? AND status = 'approved'
       LIMIT 1`,
    )
      .bind(namespace, publicKey, service)
      .first<{ claim_id?: string; approved_at?: string }>();
  } catch (error) {
    console.error("D1 lookup failed for /v1/verify:", error);
    return c.json(createErrorResponse("Authorization store unavailable", "DB_UNAVAILABLE"), 503);
  }

  if (!claim?.claim_id) {
    return c.json({ authorized: false, reason: "no_approved_claim" });
  }

  return c.json({
    authorized: true,
    claim_id: claim.claim_id,
    approved_at: claim.approved_at,
  });
});
