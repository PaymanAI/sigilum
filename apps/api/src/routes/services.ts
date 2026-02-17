import { Hono } from "hono";
import { z } from "zod";
import { jwtVerify } from "jose";
import type { Env } from "../types.js";
import { isValidWebhookUrl, createErrorResponse } from "../utils/validation.js";
import { getConfig } from "../utils/config.js";
import { enqueueRegisterService } from "../utils/blockchain-queue.js";
import { encryptWebhookSecret } from "../utils/webhook-secrets.js";
import { isServiceNamespaceTakenError } from "../utils/blockchain.js";

const JWT_ISSUER = "sigilum-api";
const JWT_AUDIENCE = "sigilum-dashboard";

async function verifyJWT(env: Env, token: string) {
  try {
    const secret = env.JWT_SECRET;
    if (!secret) {
      throw new Error("JWT_SECRET environment variable is required");
    }
    const key = new TextEncoder().encode(secret);
    const { payload } = await jwtVerify(token, key, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    const userId = payload.sub;
    const email = payload.email as string;
    const namespace = payload.namespace as string;
    if (!userId || !email || !namespace) return null;
    return { userId, email, namespace };
  } catch {
    return null;
  }
}

function getBearerToken(c: { req: { header: (name: string) => string | undefined } }): string | null {
  // First, check for httpOnly cookie (preferred, secure)
  const JWT_COOKIE_NAME = "sigilum_token";
  const cookies = c.req.header("Cookie");
  if (cookies) {
    const match = cookies.match(new RegExp(`(?:^|;)\\s*${JWT_COOKIE_NAME}=([^;]+)`));
    if (match?.[1]) {
      return match[1].trim();
    }
  }

  // Fallback to Authorization header (for backwards compatibility, SDK usage, etc.)
  const auth = c.req.header("Authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  return auth.slice(7).trim() || null;
}

async function requireAuth(c: { req: { header: (name: string) => string | undefined }; env: Env; json: (data: unknown, status?: number) => Response }) {
  const token = getBearerToken(c);
  if (!token) return null;
  return verifyJWT(c.env, token);
}

/**
 * Hash an API key using SHA-256. Returns hex string.
 */
async function hashApiKey(key: string): Promise<string> {
  const encoded = new TextEncoder().encode(key);
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Generate a random API key: sk_live_<32 random hex chars>
 */
function generateApiKey(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `sk_live_${hex}`;
}

export const servicesRouter = new Hono<{ Bindings: Env }>();

// ─── Slug validation ────────────────────────────────────────────────────────

const slugRegex = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;
const PLAN_SERVICE_REGISTRATION_LIMITS: Record<string, number> = {
  free: 5,
  builder: 5,
  scale: 10,
};

const webhookSchema = z.object({
  url: z.string().url("Must be a valid URL").max(2048),
  secret: z.string().min(16, "Signing secret must be at least 16 characters"),
  auth_header: z.string().max(128).optional(),
  auth_value: z.string().max(2048).optional(),
}).optional();

const createServiceSchema = z.object({
  name: z.string().min(1).max(100),
  slug: z
    .string()
    .min(3)
    .max(64)
    .regex(slugRegex, "Slug must be lowercase alphanumeric with hyphens, 3-64 chars"),
  domain: z.string().min(1, "Domain is required").max(255),
  description: z.string().min(1, "Description is required").max(500),
  webhook: webhookSchema,
});

// ─── CRUD ───────────────────────────────────────────────────────────────────

/**
 * GET /v1/services
 * List all services owned by the current user.
 */
servicesRouter.get("/", async (c) => {
  const payload = await requireAuth(c);
  if (!payload) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);

  const rows = await c.env.DB.prepare(
    `SELECT s.id, s.name, s.slug, s.domain, s.description, s.plan, s.paid_until, s.created_at, s.updated_at,
            s.registration_tx_hash,
            COUNT(k.id) as active_key_count
     FROM services s
     LEFT JOIN service_api_keys k ON k.service_id = s.id AND k.revoked_at IS NULL
     WHERE s.owner_user_id = ?
     GROUP BY s.id, s.name, s.slug, s.domain, s.description, s.plan, s.paid_until, s.created_at, s.updated_at, s.registration_tx_hash
     ORDER BY s.created_at ASC`,
  )
    .bind(payload.userId)
    .all();

  return c.json({ services: rows.results });
});

/**
 * POST /v1/services
 * Register a new service.
 */
servicesRouter.post("/", async (c) => {
  const payload = await requireAuth(c);
  if (!payload) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);

  let body: z.infer<typeof createServiceSchema>;
  try {
    body = createServiceSchema.parse(await c.req.json());
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json(createErrorResponse("Validation failed", "VALIDATION_ERROR", err.issues), 400);
    }
    return c.json(createErrorResponse("Invalid request body", "INVALID_JSON"), 400);
  }

  // Check slug uniqueness
  const existing = await c.env.DB.prepare("SELECT id FROM services WHERE slug = ?")
    .bind(body.slug)
    .first();
  if (existing) {
    return c.json(createErrorResponse("A service with this slug already exists", "CONFLICT"), 409);
  }

  // Check service limit based on user plan
  const user = await c.env.DB.prepare("SELECT plan FROM users WHERE id = ?")
    .bind(payload.userId)
    .first<{ plan: string }>();
  const userPlan = user?.plan ?? "builder";
  const serviceCount = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM services WHERE owner_user_id = ?",
  )
    .bind(payload.userId)
    .first<{ cnt: number }>();

  const limit = PLAN_SERVICE_REGISTRATION_LIMITS[userPlan] ?? 5;
  if ((serviceCount?.cnt ?? 0) >= limit) {
    return c.json(createErrorResponse(`Your ${userPlan} plan allows up to ${limit} service(s). Upgrade to add more.`, "SERVICE_LIMIT_REACHED"), 403);
  }

  const id = crypto.randomUUID();

  // Step 1: Create service in database first
  await c.env.DB.prepare(
    "INSERT INTO services (id, owner_user_id, name, slug, domain, description, plan, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
  )
    .bind(id, payload.userId, body.name, body.slug, body.domain, body.description, userPlan)
    .run();

  // Step 2: Queue blockchain registration (async, non-blocking)
  try {
    const defaultTags = ["service"];
    const fullWebsite = body.domain.startsWith("http") ? body.domain : `https://${body.domain}`;

    await enqueueRegisterService(
      c.env,
      id,
      body.name,
      body.slug,
      fullWebsite,
      body.description,
      defaultTags,
    );

    console.log(`Service blockchain registration queued: ${body.slug}`);
  } catch (error) {
    if (isServiceNamespaceTakenError(error)) {
      console.warn(
        `Service namespace already registered on-chain, skipping blockchain registration for ${body.slug}`,
      );
    } else {
      console.error("Failed to queue blockchain registration (service still created):", error);
    }
    // Continue - service is still usable even if queue fails
  }

  // If a webhook was provided, create it alongside the service
  let webhookResult: { id: string; url: string; events: string[] } | undefined;
  if (body.webhook) {
    const wh = body.webhook;
    const whId = `wh_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const defaultEvents = ["request.submitted", "request.approved", "request.revoked", "request.rejected"];

    const encryptedSecret = await encryptWebhookSecret(c.env, wh.secret);
    await c.env.DB.prepare(
      "INSERT INTO webhooks (id, service_id, url, events, secret_hash, auth_header_name, auth_header_value) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
      .bind(whId, id, wh.url, JSON.stringify(defaultEvents), encryptedSecret, wh.auth_header || null, wh.auth_value || null)
      .run();

    webhookResult = { id: whId, url: wh.url, events: defaultEvents };
  }

  // Fetch the created service to get the database-generated fields
  const created = await c.env.DB.prepare(
    "SELECT created_at, registration_tx_hash FROM services WHERE id = ?",
  )
    .bind(id)
    .first<{ created_at: string; registration_tx_hash: string | null }>();

  return c.json(
    {
      id,
      name: body.name,
      slug: body.slug,
      domain: body.domain,
      description: body.description,
      plan: userPlan,
      created_at: created?.created_at ?? new Date().toISOString(),
      registration_tx_hash: created?.registration_tx_hash ?? null,
      webhook: webhookResult,
    },
    201,
  );
});

/**
 * GET /v1/services/:serviceId
 * Get service details.
 */
servicesRouter.get("/:serviceId", async (c) => {
  const payload = await requireAuth(c);
  if (!payload) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);

  const serviceId = c.req.param("serviceId");
  const svc = await c.env.DB.prepare(
    "SELECT * FROM services WHERE id = ? AND owner_user_id = ?",
  )
    .bind(serviceId, payload.userId)
    .first();
  if (!svc) return c.json(createErrorResponse("Service not found", "NOT_FOUND"), 404);

  return c.json(svc);
});

/**
 * PATCH /v1/services/:serviceId
 * Update service details (name, domain, description).
 */
servicesRouter.patch("/:serviceId", async (c) => {
  const payload = await requireAuth(c);
  if (!payload) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);

  const serviceId = c.req.param("serviceId");
  const svc = await c.env.DB.prepare(
    "SELECT id FROM services WHERE id = ? AND owner_user_id = ?",
  )
    .bind(serviceId, payload.userId)
    .first();
  if (!svc) return c.json(createErrorResponse("Service not found", "NOT_FOUND"), 404);

  const body = await c.req.json<{ name?: string; domain?: string; description?: string }>();
  const updates: string[] = [];
  const values: (string | null)[] = [];

  if (body.name !== undefined) {
    updates.push("name = ?");
    values.push(body.name.trim());
  }
  if (body.domain !== undefined) {
    updates.push("domain = ?");
    values.push(body.domain.trim() || null);
  }
  if (body.description !== undefined) {
    updates.push("description = ?");
    values.push(body.description.trim() || null);
  }
  if (updates.length === 0) {
    return c.json(createErrorResponse("No fields to update", "VALIDATION_ERROR"), 400);
  }

  updates.push("updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')");
  values.push(serviceId, payload.userId);

  await c.env.DB.prepare(
    `UPDATE services SET ${updates.join(", ")} WHERE id = ? AND owner_user_id = ?`,
  )
    .bind(...values)
    .run();

  return c.json({ success: true });
});

/**
 * DELETE /v1/services/:serviceId
 * Delete a service and all its API keys.
 */
servicesRouter.delete("/:serviceId", async (c) => {
  const payload = await requireAuth(c);
  if (!payload) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);

  const serviceId = c.req.param("serviceId");
  const svc = await c.env.DB.prepare(
    "SELECT id FROM services WHERE id = ? AND owner_user_id = ?",
  )
    .bind(serviceId, payload.userId)
    .first();
  if (!svc) return c.json(createErrorResponse("Service not found", "NOT_FOUND"), 404);

  await c.env.DB.prepare("DELETE FROM services WHERE id = ? AND owner_user_id = ?")
    .bind(serviceId, payload.userId)
    .run();

  return c.json({ success: true });
});

/**
 * PATCH /v1/services/:serviceId/plan
 * Change service plan.
 */
servicesRouter.patch("/:serviceId/plan", async (c) => {
  const payload = await requireAuth(c);
  if (!payload) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);

  const serviceId = c.req.param("serviceId");
  const svc = await c.env.DB.prepare(
    "SELECT id FROM services WHERE id = ? AND owner_user_id = ?",
  )
    .bind(serviceId, payload.userId)
    .first();
  if (!svc) return c.json(createErrorResponse("Service not found", "NOT_FOUND"), 404);

  const body = await c.req.json<{ plan?: string }>();
  const plan = body.plan?.trim();
  const validPlans = ["free", "managed"];
  if (!plan || !validPlans.includes(plan)) {
    return c.json(createErrorResponse(`Plan must be one of: ${validPlans.join(", ")}`, "VALIDATION_ERROR"), 400);
  }

  await c.env.DB.prepare(
    "UPDATE services SET plan = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
  )
    .bind(plan, serviceId)
    .run();

  return c.json({ success: true, plan });
});

// ─── API Keys ───────────────────────────────────────────────────────────────

/**
 * GET /v1/services/:serviceId/keys
 * List API keys for a service (prefix only, never the full key).
 */
servicesRouter.get("/:serviceId/keys", async (c) => {
  const payload = await requireAuth(c);
  if (!payload) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);

  const serviceId = c.req.param("serviceId");
  const svc = await c.env.DB.prepare(
    "SELECT id FROM services WHERE id = ? AND owner_user_id = ?",
  )
    .bind(serviceId, payload.userId)
    .first();
  if (!svc) return c.json(createErrorResponse("Service not found", "NOT_FOUND"), 404);

  const limit = Math.min(parseInt(c.req.query("limit") ?? "50", 10), 200);
  const offset = parseInt(c.req.query("offset") ?? "0", 10);

  const keys = await c.env.DB.prepare(
    "SELECT id, name, key_prefix, last_used_at, created_at FROM service_api_keys WHERE service_id = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT ? OFFSET ?",
  )
    .bind(serviceId, limit, offset)
    .all();

  const totalCount = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM service_api_keys WHERE service_id = ? AND revoked_at IS NULL",
  )
    .bind(serviceId)
    .first<{ cnt: number }>();

  return c.json({
    keys: keys.results,
    pagination: {
      limit,
      offset,
      total: totalCount?.cnt ?? 0,
      has_more: offset + limit < (totalCount?.cnt ?? 0),
    },
  });
});

/**
 * POST /v1/services/:serviceId/keys
 * Generate a new API key. Returns the full key ONCE.
 */
servicesRouter.post("/:serviceId/keys", async (c) => {
  const payload = await requireAuth(c);
  if (!payload) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);

  const serviceId = c.req.param("serviceId");
  const svc = await c.env.DB.prepare(
    "SELECT id FROM services WHERE id = ? AND owner_user_id = ?",
  )
    .bind(serviceId, payload.userId)
    .first();
  if (!svc) return c.json(createErrorResponse("Service not found", "NOT_FOUND"), 404);

  // Limit active keys per service
  const activeCount = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM service_api_keys WHERE service_id = ? AND revoked_at IS NULL",
  )
    .bind(serviceId)
    .first<{ cnt: number }>();
  const config = getConfig(c.env);
  if ((activeCount?.cnt ?? 0) >= config.maxApiKeysPerService) {
    return c.json(createErrorResponse(`Maximum ${config.maxApiKeysPerService} active API keys per service. Revoke an existing key first.`, "KEY_LIMIT_REACHED"), 400);
  }

  const body = await c.req.json<{ name?: string }>().catch(() => ({}));
  const keyName = (body as { name?: string }).name?.trim() || "Default";

  const rawKey = generateApiKey();
  const keyHash = await hashApiKey(rawKey);
  const keyPrefix = "..." + rawKey.slice(-4);
  const id = crypto.randomUUID();

  await c.env.DB.prepare(
    "INSERT INTO service_api_keys (id, service_id, name, key_prefix, key_hash) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(id, serviceId, keyName, keyPrefix, keyHash)
    .run();

  return c.json(
    {
      id,
      name: keyName,
      key: rawKey,
      key_prefix: keyPrefix,
      message: "Save this key now. It will not be shown again.",
    },
    201,
  );
});

/**
 * DELETE /v1/services/:serviceId/keys/:keyId
 * Revoke an API key (soft delete).
 */
servicesRouter.delete("/:serviceId/keys/:keyId", async (c) => {
  const payload = await requireAuth(c);
  if (!payload) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);

  const serviceId = c.req.param("serviceId");
  const keyId = c.req.param("keyId");

  const svc = await c.env.DB.prepare(
    "SELECT id FROM services WHERE id = ? AND owner_user_id = ?",
  )
    .bind(serviceId, payload.userId)
    .first();
  if (!svc) return c.json(createErrorResponse("Service not found", "NOT_FOUND"), 404);

  const key = await c.env.DB.prepare(
    "SELECT id FROM service_api_keys WHERE id = ? AND service_id = ? AND revoked_at IS NULL",
  )
    .bind(keyId, serviceId)
    .first();
  if (!key) return c.json(createErrorResponse("API key not found or already revoked", "NOT_FOUND"), 404);

  await c.env.DB.prepare(
    "UPDATE service_api_keys SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
  )
    .bind(keyId)
    .run();

  return c.json({ success: true });
});

// ─── Webhooks (dashboard-managed, JWT auth) ─────────────────────────────────

/**
 * GET /v1/services/:serviceId/webhooks
 * List webhooks for a service (dashboard user must own the service).
 */
servicesRouter.get("/:serviceId/webhooks", async (c) => {
  const payload = await requireAuth(c);
  if (!payload) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);

  const serviceId = c.req.param("serviceId");
  const svc = await c.env.DB.prepare(
    "SELECT id FROM services WHERE id = ? AND owner_user_id = ?",
  )
    .bind(serviceId, payload.userId)
    .first();
  if (!svc) return c.json(createErrorResponse("Service not found", "NOT_FOUND"), 404);

  const limit = Math.min(parseInt(c.req.query("limit") ?? "50", 10), 200);
  const offset = parseInt(c.req.query("offset") ?? "0", 10);

  const rows = await c.env.DB.prepare(
    "SELECT id, url, events, active, failure_count, last_triggered_at, last_failure_at, created_at FROM webhooks WHERE service_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
  )
    .bind(serviceId, limit, offset)
    .all();

  const totalCount = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM webhooks WHERE service_id = ?",
  )
    .bind(serviceId)
    .first<{ cnt: number }>();

  const webhooks = rows.results.map((w) => ({
    id: w.id,
    url: w.url,
    events: JSON.parse(w.events as string),
    active: w.active === 1,
    failure_count: w.failure_count,
    last_triggered_at: w.last_triggered_at,
    last_failure_at: w.last_failure_at,
    created_at: w.created_at,
  }));

  return c.json({
    webhooks,
    pagination: {
      limit,
      offset,
      total: totalCount?.cnt ?? 0,
      has_more: offset + limit < (totalCount?.cnt ?? 0),
    },
  });
});

/**
 * POST /v1/services/:serviceId/webhooks
 * Create a webhook from the dashboard.
 */
servicesRouter.post("/:serviceId/webhooks", async (c) => {
  const payload = await requireAuth(c);
  if (!payload) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);

  const serviceId = c.req.param("serviceId");
  const svc = await c.env.DB.prepare(
    "SELECT id FROM services WHERE id = ? AND owner_user_id = ?",
  )
    .bind(serviceId, payload.userId)
    .first();
  if (!svc) return c.json(createErrorResponse("Service not found", "SERVICE_NOT_FOUND"), 404);

  const body = await c.req.json<{ url: string; events: string[]; secret: string; auth_header?: string; auth_value?: string }>();
  if (!body.url || !body.events?.length || !body.secret || body.secret.length < 16) {
    return c.json(createErrorResponse("url, events (non-empty array), and secret (min 16 chars) are required", "VALIDATION_ERROR"), 400);
  }

  // SSRF protection: validate webhook URL
  const urlValidation = await isValidWebhookUrl(body.url);
  if (!urlValidation.valid) {
    return c.json(createErrorResponse(urlValidation.error!, "INVALID_WEBHOOK_URL"), 400);
  }

  const config = getConfig(c.env);
  const count = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM webhooks WHERE service_id = ? AND active = 1",
  )
    .bind(serviceId)
    .first<{ cnt: number }>();
  if ((count?.cnt ?? 0) >= config.maxWebhooksPerService) {
    return c.json(createErrorResponse(`Maximum ${config.maxWebhooksPerService} active webhooks per service`, "WEBHOOK_LIMIT_REACHED"), 400);
  }

  const id = `wh_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
  const encryptedSecret = await encryptWebhookSecret(c.env, body.secret);
  await c.env.DB.prepare(
    "INSERT INTO webhooks (id, service_id, url, events, secret_hash, auth_header_name, auth_header_value) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(id, serviceId, body.url, JSON.stringify(body.events), encryptedSecret, body.auth_header || null, body.auth_value || null)
    .run();

  return c.json({ id, url: body.url, events: body.events, active: true }, 201);
});

/**
 * DELETE /v1/services/:serviceId/webhooks/:webhookId
 * Delete a webhook from the dashboard.
 */
servicesRouter.delete("/:serviceId/webhooks/:webhookId", async (c) => {
  const payload = await requireAuth(c);
  if (!payload) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);

  const serviceId = c.req.param("serviceId");
  const webhookId = c.req.param("webhookId");

  const svc = await c.env.DB.prepare(
    "SELECT id FROM services WHERE id = ? AND owner_user_id = ?",
  )
    .bind(serviceId, payload.userId)
    .first();
  if (!svc) return c.json(createErrorResponse("Service not found", "NOT_FOUND"), 404);

  const row = await c.env.DB.prepare(
    "SELECT id FROM webhooks WHERE id = ? AND service_id = ?",
  )
    .bind(webhookId, serviceId)
    .first();
  if (!row) return c.json(createErrorResponse("Webhook not found", "NOT_FOUND"), 404);

  await c.env.DB.prepare("DELETE FROM webhooks WHERE id = ?").bind(webhookId).run();
  return c.json({ success: true, deleted: true, webhook_id: webhookId });
});

// ─── Public: validate service API key (used by claims route) ────────────────

/**
 * Given a raw API key, look up the service. Returns service row or null.
 * Also updates last_used_at.
 */
export async function validateServiceApiKey(
  db: D1Database,
  rawKey: string,
): Promise<{ serviceId: string; slug: string; plan: string } | null> {
  const keyHash = await hashApiKey(rawKey);
  const row = await db
    .prepare(
      `SELECT k.id as key_id, k.service_id, s.slug, s.plan
       FROM service_api_keys k
       JOIN services s ON s.id = k.service_id
       WHERE k.key_hash = ? AND k.revoked_at IS NULL`,
    )
    .bind(keyHash)
    .first<{ key_id: string; service_id: string; slug: string; plan: string }>();

  if (!row) return null;

  // Update last_used_at (fire-and-forget)
  db.prepare("UPDATE service_api_keys SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?")
    .bind(row.key_id)
    .run()
    .catch(() => {});

  return { serviceId: row.service_id, slug: row.slug, plan: row.plan };
}
