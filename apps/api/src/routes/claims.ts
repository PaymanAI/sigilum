import { Hono } from "hono";
import { z } from "zod";
import type { Env } from "../types.js";
import { validateServiceApiKey } from "./services.js";
import { verifyJWT, getBearerToken } from "./auth.js";
import { dispatchWebhookEvent } from "./webhooks.js";
import { createErrorResponse } from "../utils/validation.js";
import { getConfig } from "../utils/config.js";
import { enqueueApproveClaim, enqueueRevokeClaim } from "../utils/blockchain-queue.js";
import { ipMatchesCIDR } from "../utils/ip-matching.js";
import { getAdapters } from "../adapters/index.js";

/** Maximum approved agents per service. */
export const MAX_APPROVED_AGENTS_PER_SERVICE = 10;
/** Maximum distinct services a namespace can connect to. */
export const MAX_CONNECTED_SERVICES_PER_NAMESPACE = 10;

const submitClaimSchema = z.object({
  namespace: z.string().min(3).max(64),
  public_key: z.string(),
  service: z.string().min(1),
  agent_ip: z.string(),
  nonce: z.string().min(8).max(256),
});

export const claimsRouter = new Hono<{ Bindings: Env }>();

/**
 * POST /v1/claims
 * Submit a new access request (service submits on behalf of an agent).
 * Requires a valid service API key.
 */
claimsRouter.post("/", async (c) => {
  const config = getConfig(c.env);
  const adapters = getAdapters(c.env);

  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json(createErrorResponse("Missing or invalid Authorization header. Use: Bearer sk_live_...", "UNAUTHORIZED"), 401);
  }
  const apiKey = authHeader.slice(7).trim();
  const serviceInfo = await validateServiceApiKey(c.env.DB, apiKey);
  if (!serviceInfo) {
    return c.json(createErrorResponse("Invalid or revoked API key", "FORBIDDEN"), 403);
  }

  let body: z.infer<typeof submitClaimSchema>;
  let rawBody = "";
  try {
    rawBody = await c.req.text();
    body = submitClaimSchema.parse(JSON.parse(rawBody));
  } catch (err) {
    if (err instanceof z.ZodError) {
      const fields = err.issues.map((e) => ({
        field: e.path.join("."),
        message: e.message,
      }));
      return c.json(createErrorResponse("Validation failed", "VALIDATION_ERROR", fields), 400);
    }
    return c.json(createErrorResponse("Invalid request body", "INVALID_JSON"), 400);
  }

  // Ensure the service field matches the authenticated service slug
  if (body.service !== serviceInfo.slug) {
    return c.json(
      createErrorResponse(`API key belongs to service "${serviceInfo.slug}" but request is for "${body.service}"`, "FORBIDDEN"),
      403,
    );
  }

  // Replay protection via nonce store.
  try {
    const nonceResult = await adapters.nonceStore.check({
      service: serviceInfo.slug,
      nonce: body.nonce,
    });
    if (nonceResult.replay) {
      return c.json(
        createErrorResponse("Replay detected: nonce has already been used", "NONCE_REPLAY"),
        409,
      );
    }
  } catch (error) {
    console.error("Nonce validation failed:", error);
    return c.json(
      createErrorResponse("Nonce store unavailable", "NONCE_STORE_UNAVAILABLE"),
      503,
    );
  }

  // Look up namespace owner
  const nsOwner = await c.env.DB.prepare(
    "SELECT id FROM users WHERE namespace = ?",
  )
    .bind(body.namespace)
    .first() as { id: string } | null;

  if (!nsOwner) {
    return c.json(createErrorResponse(`Namespace "${body.namespace}" not found`, "NOT_FOUND"), 404);
  }

  // Idempotency guard: avoid duplicate pending/approved claims for same key.
  const existingActiveClaim = await c.env.DB.prepare(
    `SELECT claim_id, status
     FROM authorizations
     WHERE namespace = ? AND service = ? AND public_key = ? AND status IN ('pending', 'approved')
     ORDER BY
       CASE status
         WHEN 'approved' THEN 0
         ELSE 1
       END,
       created_at DESC
     LIMIT 1`,
  )
    .bind(body.namespace, body.service, body.public_key)
    .first() as { claim_id: string; status: "pending" | "approved" } | null;

  if (existingActiveClaim) {
    if (existingActiveClaim.status === "approved") {
      return c.json(
        {
          claim_id: existingActiveClaim.claim_id,
          status: "approved",
          service: serviceInfo.slug,
          message: "Authorization already approved for this key.",
        },
        200,
      );
    }

    return c.json(
      {
        claim_id: existingActiveClaim.claim_id,
        status: "pending",
        service: serviceInfo.slug,
        message: "Authorization request already pending for this key.",
      },
      200,
    );
  }

  const agentLimit = MAX_APPROVED_AGENTS_PER_SERVICE;
  const serviceLimit = MAX_CONNECTED_SERVICES_PER_NAMESPACE;

  // Count distinct services the user already has approved agents for
  const svcCountRow = await c.env.DB.prepare(
    "SELECT COUNT(DISTINCT service) as cnt FROM authorizations WHERE namespace = ? AND status = 'approved'",
  )
    .bind(body.namespace)
    .first() as { cnt: number } | null;
  const connectedServices = svcCountRow?.cnt ?? 0;

  // Check if this is a new service (no existing approved agents for it)
  const existingSvcRow = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM authorizations WHERE namespace = ? AND service = ? AND status = 'approved'",
  )
    .bind(body.namespace, body.service)
    .first() as { cnt: number } | null;
  const currentCount = existingSvcRow?.cnt ?? 0;
  const isNewService = currentCount === 0;

  const claimId = `cl_${crypto.randomUUID().replace(/-/g, "").slice(0, 24)}`;

  // Auto-reject if this is a new service and the service connection limit is reached
  if (isNewService && connectedServices >= serviceLimit) {
    await c.env.DB.prepare(
      `INSERT INTO authorizations (claim_id, namespace, service, public_key, agent_ip, status, approved_at, revoked_at)
       VALUES (?, ?, ?, ?, ?, 'rejected', NULL, NULL)
       ON CONFLICT(namespace, service, public_key) DO UPDATE SET
         claim_id = excluded.claim_id,
         agent_ip = excluded.agent_ip,
         status = excluded.status,
         approved_at = NULL,
         revoked_at = NULL`,
    )
      .bind(claimId, body.namespace, body.service, body.public_key, body.agent_ip)
      .run();

    return c.json(
        {
          claim_id: claimId,
          status: "rejected",
          service: serviceInfo.slug,
          message: `Auto-rejected: namespace owner allows up to ${serviceLimit} service connections (${connectedServices} currently connected).`,
        },
        201,
      );
  }

  // Auto-reject if namespace owner has reached their agent-per-service limit
  if (currentCount >= agentLimit) {
    await c.env.DB.prepare(
      `INSERT INTO authorizations (claim_id, namespace, service, public_key, agent_ip, status, approved_at, revoked_at)
       VALUES (?, ?, ?, ?, ?, 'rejected', NULL, NULL)
       ON CONFLICT(namespace, service, public_key) DO UPDATE SET
         claim_id = excluded.claim_id,
         agent_ip = excluded.agent_ip,
         status = excluded.status,
         approved_at = NULL,
         revoked_at = NULL`,
    )
      .bind(claimId, body.namespace, body.service, body.public_key, body.agent_ip)
      .run();

    return c.json(
        {
          claim_id: claimId,
          status: "rejected",
          service: serviceInfo.slug,
          message: `Auto-rejected: namespace owner allows up to ${agentLimit} agents per service (${currentCount} currently approved).`,
        },
        201,
      );
  }

  // Check max pending requests limit (policy setting)
  const ownerSettings = await c.env.DB.prepare("SELECT settings FROM users WHERE id = ?")
    .bind(nsOwner.id)
    .first() as { settings?: string } | null;

  let userSettings: Record<string, unknown> = {};
  try {
    if (ownerSettings?.settings) userSettings = JSON.parse(ownerSettings.settings);
  } catch { /* ignore */ }

  const policySettings = (userSettings.policy ?? {}) as Record<string, unknown>;
  const maxPendingEnabled = policySettings.maxPendingLimit !== false;
  const maxPendingCount = config.maxPendingRequests;

  if (maxPendingEnabled) {
    const pendingCountRow = await c.env.DB.prepare(
      "SELECT COUNT(*) as cnt FROM authorizations WHERE namespace = ? AND status = 'pending'",
    )
      .bind(body.namespace)
      .first() as { cnt: number } | null;
    const pendingCount = pendingCountRow?.cnt ?? 0;

    if (pendingCount >= maxPendingCount) {
      await c.env.DB.prepare(
        `INSERT INTO authorizations (claim_id, namespace, service, public_key, agent_ip, status, approved_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, 'rejected', NULL, NULL)
         ON CONFLICT(namespace, service, public_key) DO UPDATE SET
           claim_id = excluded.claim_id,
           agent_ip = excluded.agent_ip,
           status = excluded.status,
           approved_at = NULL,
           revoked_at = NULL`,
      )
        .bind(claimId, body.namespace, body.service, body.public_key, body.agent_ip)
        .run();

      // Dispatch webhook event
      await dispatchWebhookEvent(c.env.DB, "request.rejected", {
        claim_id: claimId,
        namespace: body.namespace,
        service: body.service,
        public_key: body.public_key,
        agent_ip: body.agent_ip,
        reason: "max_pending_reached",
      }, c.env);

      return c.json(
        {
          claim_id: claimId,
          status: "rejected",
          service: serviceInfo.slug,
          message: `Auto-rejected: namespace owner has reached the maximum of ${maxPendingCount} pending requests. Existing requests must be reviewed first.`,
        },
        201,
      );
    }
  }

  // Check auto-approve rules
  const autoApproveTrusted = policySettings.autoApproveTrusted === true;
  const autoApproveIP = policySettings.autoApproveIP === true;
  const trustedServices: string[] = Array.isArray(policySettings.trustedServices) ? policySettings.trustedServices as string[] : [];
  const trustedIPRanges: string[] = Array.isArray(policySettings.trustedIPRanges) ? policySettings.trustedIPRanges as string[] : [];

  let shouldAutoApprove = false;

  // Check if the service is in the trusted list
  if (autoApproveTrusted && trustedServices.includes(body.service)) {
    shouldAutoApprove = true;
  }

  // Check if the agent IP matches a trusted IP range
  if (autoApproveIP && trustedIPRanges.length > 0) {
    for (const range of trustedIPRanges) {
      if (ipMatchesCIDR(body.agent_ip, range)) {
        shouldAutoApprove = true;
        break;
      }
    }
  }

  if (shouldAutoApprove) {
    // Pre-check service connection limit (if this would be the first agent for a new service)
    const preAutoCountRow = await c.env.DB.prepare(
      "SELECT COUNT(*) as cnt FROM authorizations WHERE namespace = ? AND service = ? AND status = 'approved'",
    )
      .bind(body.namespace, body.service)
      .first() as { cnt: number } | null;
    const preAutoCount = preAutoCountRow?.cnt ?? 0;

    if (preAutoCount === 0) {
      const autoSvcCountRow = await c.env.DB.prepare(
        "SELECT COUNT(DISTINCT service) as cnt FROM authorizations WHERE namespace = ? AND status = 'approved'",
      )
        .bind(body.namespace)
        .first() as { cnt: number } | null;
      const autoConnectedServices = autoSvcCountRow?.cnt ?? 0;

      if (autoConnectedServices >= serviceLimit) {
        // Service limit reached, create as pending instead
        await c.env.DB.prepare(
          `INSERT INTO authorizations (claim_id, namespace, service, public_key, agent_ip, status, approved_at, revoked_at)
           VALUES (?, ?, ?, ?, ?, 'pending', NULL, NULL)
           ON CONFLICT(namespace, service, public_key) DO UPDATE SET
             claim_id = excluded.claim_id,
             agent_ip = excluded.agent_ip,
             status = excluded.status,
             approved_at = NULL,
             revoked_at = NULL`,
        )
          .bind(claimId, body.namespace, body.service, body.public_key, body.agent_ip)
          .run();

        return c.json(
          {
            claim_id: claimId,
            status: "pending",
            service: serviceInfo.slug,
            message: `Service limit reached (${serviceLimit}). Auto-approval skipped; awaiting manual review.`,
          },
          201,
        );
      }
    }

    // Ensure a pending row exists for this request first.
    await c.env.DB.prepare(
      `INSERT INTO authorizations (claim_id, namespace, service, public_key, agent_ip, status, approved_at, revoked_at)
       VALUES (?, ?, ?, ?, ?, 'pending', NULL, NULL)
       ON CONFLICT(namespace, service, public_key) DO UPDATE SET
         claim_id = excluded.claim_id,
         agent_ip = excluded.agent_ip,
         status = excluded.status,
         approved_at = NULL,
         revoked_at = NULL`,
    )
      .bind(claimId, body.namespace, body.service, body.public_key, body.agent_ip)
      .run();

    // Atomically approve only if limit is still available.
    const autoApproveUpdate = await c.env.DB.prepare(
      `UPDATE authorizations
       SET status = 'approved', approved_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
       WHERE claim_id = ?
         AND status = 'pending'
         AND (
           SELECT COUNT(*) FROM authorizations
           WHERE namespace = ? AND service = ? AND status = 'approved'
         ) < ?`,
    )
      .bind(claimId, body.namespace, body.service, agentLimit)
      .run();

    if ((autoApproveUpdate.meta.changes ?? 0) === 0) {
      return c.json(
        {
          claim_id: claimId,
          status: "pending",
          service: serviceInfo.slug,
          message: `Agent limit reached due to concurrent requests (${agentLimit}). Auto-approval skipped; awaiting manual review.`,
        },
        201,
      );
    }

    // Queue blockchain approval (async, non-blocking)
    try {
      await enqueueApproveClaim(c.env, claimId, body.namespace, body.public_key, body.service, body.agent_ip);
      console.log(`Claim "${claimId}" auto-approval queued for blockchain submission`);
    } catch (error) {
      console.error("Failed to queue auto-approval to blockchain (agent can still work):", error);
      // Don't fail the request - database is source of truth, blockchain is audit log
    }

    // Dispatch webhook event for successful auto-approval
    await dispatchWebhookEvent(c.env.DB, "request.approved", {
      claim_id: claimId,
      namespace: body.namespace,
      service: body.service,
      public_key: body.public_key,
      agent_ip: body.agent_ip,
      auto_approved: true,
    }, c.env);

    return c.json(
      {
        claim_id: claimId,
        status: "approved",
        service: serviceInfo.slug,
        message: "Auto-approved by namespace owner's policy rules.",
      },
      201,
    );
  }

  // Store claim in database as pending (no blockchain interaction yet)
  await c.env.DB.prepare(
    `INSERT INTO authorizations (claim_id, namespace, service, public_key, agent_ip, status, approved_at, revoked_at)
     VALUES (?, ?, ?, ?, ?, 'pending', NULL, NULL)
     ON CONFLICT(namespace, service, public_key) DO UPDATE SET
       claim_id = excluded.claim_id,
       agent_ip = excluded.agent_ip,
       status = excluded.status,
       approved_at = NULL,
       revoked_at = NULL`,
  )
    .bind(claimId, body.namespace, body.service, body.public_key, body.agent_ip)
    .run();

  return c.json(
    {
      claim_id: claimId,
      status: "pending",
      service: serviceInfo.slug,
      message: "Access request submitted. Awaiting namespace owner approval.",
    },
    201,
  );
});

/**
 * GET /v1/claims/:claimId
 * Get claim details by ID. Requires namespace owner JWT auth.
 */
claimsRouter.get("/:claimId", async (c) => {
  const token = getBearerToken(c);
  if (!token) return c.json(createErrorResponse("Authentication required", "UNAUTHORIZED"), 401);
  const payload = await verifyJWT(c.env, token);
  if (!payload) return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);

  const claimId = c.req.param("claimId");
  const row = await c.env.DB.prepare("SELECT * FROM authorizations WHERE claim_id = ?")
    .bind(claimId)
    .first() as Record<string, unknown> | null;

  if (!row) return c.json(createErrorResponse("Claim not found", "NOT_FOUND"), 404);
  if (row.namespace !== payload.namespace) {
    return c.json(createErrorResponse("Not authorized to view claims in this namespace", "FORBIDDEN"), 403);
  }
  return c.json(row);
});

/**
 * POST /v1/claims/:claimId/approve
 * Approve a pending access request. Enforces agent-per-service and service-connection limits.
 */
claimsRouter.post("/:claimId/approve", async (c) => {
  // Authenticate the namespace owner
  const token = getBearerToken(c);
  if (!token) return c.json(createErrorResponse("Authentication required", "UNAUTHORIZED"), 401);
  const payload = await verifyJWT(c.env, token);
  if (!payload) return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);

  const claimId = c.req.param("claimId");
  const row = await c.env.DB.prepare("SELECT * FROM authorizations WHERE claim_id = ? AND status = 'pending'")
    .bind(claimId)
    .first() as Record<string, unknown> | null;

  if (!row) return c.json(createErrorResponse("Claim not found or not pending", "NOT_FOUND"), 404);

  // Verify this claim belongs to the user's namespace
  if (row.namespace !== payload.namespace) {
    return c.json(createErrorResponse("Not authorized to approve claims in this namespace", "FORBIDDEN"), 403);
  }

  const agentLimit = MAX_APPROVED_AGENTS_PER_SERVICE;
  const serviceLimit = MAX_CONNECTED_SERVICES_PER_NAMESPACE;

  // Pre-check service connection limit (if this would be the first agent for a new service)
  const preCountRow = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM authorizations WHERE namespace = ? AND service = ? AND status = 'approved'",
  )
    .bind(row.namespace as string, row.service as string)
    .first() as { cnt: number } | null;
  const preCount = preCountRow?.cnt ?? 0;

  if (preCount === 0) {
    const svcCountRow = await c.env.DB.prepare(
      "SELECT COUNT(DISTINCT service) as cnt FROM authorizations WHERE namespace = ? AND status = 'approved'",
    )
      .bind(row.namespace as string)
      .first() as { cnt: number } | null;
    const connectedServices = svcCountRow?.cnt ?? 0;

    if (connectedServices >= serviceLimit) {
      return c.json(createErrorResponse(
        `Service limit reached. Maximum ${serviceLimit} service connections. Currently connected to ${connectedServices}.`,
        "SERVICE_LIMIT_REACHED",
        { service_limit: serviceLimit, services_connected: connectedServices },
      ), 403);
    }
  }

  // Step 1: Approve atomically only if the per-service agent limit is still available.
  const approveUpdate = await c.env.DB.prepare(
    `UPDATE authorizations
     SET status = 'approved', approved_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
     WHERE claim_id = ?
       AND status = 'pending'
       AND (
         SELECT COUNT(*) FROM authorizations
         WHERE namespace = ? AND service = ? AND status = 'approved'
       ) < ?`,
  )
    .bind(claimId, row.namespace as string, row.service as string, agentLimit)
    .run();

  if ((approveUpdate.meta.changes ?? 0) === 0) {
    const currentCountRow = await c.env.DB.prepare(
      "SELECT COUNT(*) as cnt FROM authorizations WHERE namespace = ? AND service = ? AND status = 'approved'",
    )
      .bind(row.namespace as string, row.service as string)
      .first() as { cnt: number } | null;
    const currentCount = currentCountRow?.cnt ?? 0;

    return c.json(createErrorResponse(
      `Agent limit reached due to concurrent approvals. Maximum ${agentLimit} agents per service. Currently ${currentCount} approved.`,
      "AGENT_LIMIT_REACHED",
      { agent_limit: agentLimit, current: currentCount },
    ), 409);
  }

  // Step 2: Queue blockchain approval (async, non-blocking)
  // Agent can work immediately, blockchain tx will be submitted in background
  try {
    await enqueueApproveClaim(
      c.env,
      claimId,
      row.namespace as string,
      row.public_key as string,
      row.service as string,
      row.agent_ip as string,
    );
    console.log(`Claim "${claimId}" approval queued for blockchain submission`);
  } catch (error) {
    console.error("Failed to queue blockchain approval (agent can still work):", error);
    // Don't fail the request - database is source of truth, blockchain is audit log
  }

  const approvedCountRow = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM authorizations WHERE namespace = ? AND service = ? AND status = 'approved'",
  )
    .bind(row.namespace as string, row.service as string)
    .first() as { cnt: number } | null;
  const approvedCount = approvedCountRow?.cnt ?? 0;

  // Dispatch webhook event
  await dispatchWebhookEvent(c.env.DB, "request.approved", {
    claim_id: claimId,
    namespace: row.namespace as string,
    service: row.service as string,
    public_key: row.public_key as string,
    agent_ip: row.agent_ip as string,
  }, c.env);

  return c.json({
    claim_id: claimId,
    status: "approved",
    agents_approved: approvedCount,
    agents_limit: agentLimit,
    blockchain_tx_status: "queued",
  });
});

/**
 * POST /v1/claims/:claimId/reject
 * Reject a pending access request. Requires JWT auth (namespace owner).
 */
claimsRouter.post("/:claimId/reject", async (c) => {
  const token = getBearerToken(c);
  if (!token) return c.json(createErrorResponse("Authentication required", "UNAUTHORIZED"), 401);
  const payload = await verifyJWT(c.env, token);
  if (!payload) return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);

  const claimId = c.req.param("claimId");
  const row = await c.env.DB.prepare("SELECT * FROM authorizations WHERE claim_id = ? AND status = 'pending'")
    .bind(claimId)
    .first() as Record<string, unknown> | null;

  if (!row) return c.json(createErrorResponse("Claim not found or not pending", "NOT_FOUND"), 404);

  if (row.namespace !== payload.namespace) {
    return c.json(createErrorResponse("Not authorized to reject claims in this namespace", "FORBIDDEN"), 403);
  }

  // Reject claim (database only - no blockchain interaction)
  await c.env.DB.prepare("UPDATE authorizations SET status = 'rejected' WHERE claim_id = ?")
    .bind(claimId)
    .run();

  // Dispatch webhook event
  await dispatchWebhookEvent(c.env.DB, "request.rejected", {
    claim_id: claimId,
    namespace: row.namespace as string,
    service: row.service as string,
    public_key: row.public_key as string,
    agent_ip: row.agent_ip as string,
  }, c.env);

  return c.json({ claim_id: claimId, status: "rejected" });
});

/**
 * POST /v1/claims/:claimId/revoke
 * Revoke an approved authorization. Requires JWT auth (namespace owner).
 */
claimsRouter.post("/:claimId/revoke", async (c) => {
  const token = getBearerToken(c);
  if (!token) return c.json(createErrorResponse("Authentication required", "UNAUTHORIZED"), 401);
  const payload = await verifyJWT(c.env, token);
  if (!payload) return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);

  const claimId = c.req.param("claimId");
  const row = await c.env.DB.prepare("SELECT * FROM authorizations WHERE claim_id = ? AND status = 'approved'")
    .bind(claimId)
    .first() as Record<string, unknown> | null;

  if (!row) return c.json(createErrorResponse("Claim not found or not approved", "NOT_FOUND"), 404);

  if (row.namespace !== payload.namespace) {
    return c.json(createErrorResponse("Not authorized to revoke claims in this namespace", "FORBIDDEN"), 403);
  }

  // Step 1: Update database FIRST - immediately block agent access
  await c.env.DB.prepare(
    "UPDATE authorizations SET status = 'revoked', revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE claim_id = ?",
  )
    .bind(claimId)
    .run();

  // Step 2: Queue blockchain revocation (async, non-blocking)
  // Access is immediately blocked, blockchain tx will be submitted in background
  try {
    await enqueueRevokeClaim(
      c.env,
      claimId,
      row.namespace as string,
      row.public_key as string,
      row.service as string,
    );
    console.log(`Claim "${claimId}" revocation queued for blockchain submission`);
  } catch (error) {
    console.error("Failed to queue blockchain revocation (access still blocked):", error);
    // Don't fail the request - database is source of truth, blockchain is audit log
  }

  // Dispatch webhook event
  await dispatchWebhookEvent(c.env.DB, "request.revoked", {
    claim_id: claimId,
    namespace: row.namespace as string,
    service: row.service as string,
    public_key: row.public_key as string,
    agent_ip: row.agent_ip as string,
  }, c.env);

  return c.json({ claim_id: claimId, status: "revoked", blockchain_tx_status: "queued" });
});
