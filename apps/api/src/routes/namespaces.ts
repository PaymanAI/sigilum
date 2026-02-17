import { Hono } from "hono";
import type { Env } from "../types.js";
import { createErrorResponse } from "../utils/validation.js";
import { validateServiceApiKey } from "./services.js";

/** Namespace must be 3-64 characters, alphanumeric and hyphens only. */
const NAMESPACE_RE = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,62}[a-zA-Z0-9]$/;

export const namespacesRouter = new Hono<{ Bindings: Env }>();

type NamespaceClaimsLookup =
  | {
    available: true;
    table: "authorizations" | "claims";
    claims: Array<Record<string, unknown>>;
    total: number;
  }
  | { available: false; error: string };

type ApprovedClaimsCountLookup =
  | { available: true; count: number }
  | { available: false; error: string };

function toErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function parsePositiveInt(raw: string | undefined, fallback: number, max: number): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, max);
}

function parseNonNegativeInt(raw: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return parsed;
}

async function selectNamespaceClaims(
  env: Env,
  table: "authorizations" | "claims",
  namespace: string,
  status: string | undefined,
  service: string | undefined,
  limit: number,
  offset: number,
): Promise<Array<Record<string, unknown>>> {
  let sql = `SELECT claim_id, namespace, service, public_key, agent_ip, status, created_at, approved_at, revoked_at
             FROM ${table}
             WHERE namespace = ?`;
  const params: Array<string | number> = [namespace];
  if (status) {
    sql += " AND status = ?";
    params.push(status);
  }
  if (service) {
    sql += " AND service = ?";
    params.push(service);
  }
  sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
  params.push(limit, offset);
  const rows = await env.DB.prepare(sql).bind(...params).all();
  return rows.results as Array<Record<string, unknown>>;
}

async function countNamespaceClaims(
  env: Env,
  table: "authorizations" | "claims",
  namespace: string,
  status: string | undefined,
  service: string | undefined,
): Promise<number> {
  let sql = `SELECT COUNT(*) as cnt FROM ${table} WHERE namespace = ?`;
  const params: string[] = [namespace];
  if (status) {
    sql += " AND status = ?";
    params.push(status);
  }
  if (service) {
    sql += " AND service = ?";
    params.push(service);
  }
  const row = await env.DB.prepare(sql).bind(...params).first<{ cnt: number }>();
  return row?.cnt ?? 0;
}

async function lookupNamespaceClaims(
  env: Env,
  namespace: string,
  status: string | undefined,
  service: string | undefined,
  limit: number,
  offset: number,
): Promise<NamespaceClaimsLookup> {
  const errors: string[] = [];
  for (const table of ["authorizations", "claims"] as const) {
    try {
      const [claims, total] = await Promise.all([
        selectNamespaceClaims(env, table, namespace, status, service, limit, offset),
        countNamespaceClaims(env, table, namespace, status, service),
      ]);
      return { available: true, table, claims, total };
    } catch (err) {
      errors.push(`${table}: ${toErrorMessage(err)}`);
    }
  }
  return { available: false, error: errors.join(" | ") };
}

async function countApprovedClaims(
  env: Env,
  namespace: string,
): Promise<ApprovedClaimsCountLookup> {
  const errors: string[] = [];
  for (const table of ["authorizations", "claims"] as const) {
    try {
      const row = await env.DB.prepare(
        `SELECT COUNT(*) as cnt
         FROM ${table}
         WHERE namespace = ? AND status = 'approved'`,
      ).bind(namespace).first<{ cnt: number }>();
      return { available: true, count: row?.cnt ?? 0 };
    } catch (err) {
      errors.push(`${table}: ${toErrorMessage(err)}`);
    }
  }
  return { available: false, error: errors.join(" | ") };
}

async function requireServiceAuth(c: { req: { header: (name: string) => string | undefined }; env: Env }) {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;
  const apiKey = authHeader.slice(7).trim();
  return validateServiceApiKey(c.env.DB, apiKey);
}

/**
 * GET /v1/namespaces/claims
 * Get approved claims for a service across namespaces (used by SDK cache).
 */
namespacesRouter.get("/claims", async (c) => {
  const serviceAuth = await requireServiceAuth(c);
  if (!serviceAuth) {
    return c.json(createErrorResponse("Missing or invalid service API key", "UNAUTHORIZED"), 401);
  }

  const requestedService = c.req.query("service");
  const service = requestedService ?? serviceAuth.slug;
  if (service !== serviceAuth.slug) {
    return c.json(createErrorResponse("Requested service does not match API key service", "FORBIDDEN"), 403);
  }

  const status = "approved";
  const limit = Math.min(parseInt(c.req.query("limit") ?? "500", 10), 2000);
  const offset = parseInt(c.req.query("offset") ?? "0", 10);

  const rows = await c.env.DB.prepare(
    `SELECT claim_id, namespace, public_key, service, status, approved_at
     FROM authorizations
     WHERE service = ? AND status = ?
     ORDER BY approved_at DESC, created_at DESC
     LIMIT ? OFFSET ?`,
  )
    .bind(service, status, limit, offset)
    .all();

  const totalRow = await c.env.DB.prepare(
    "SELECT COUNT(*) AS cnt FROM authorizations WHERE service = ? AND status = ?",
  )
    .bind(service, status)
    .first<{ cnt: number }>();

  const claims = rows.results.map((row) => ({
    claim_id: row.claim_id,
    namespace: row.namespace,
    public_key: row.public_key,
    service: row.service,
    approved_at: row.approved_at,
  }));

  return c.json({
    claims,
    pagination: {
      limit,
      offset,
      total: totalRow?.cnt ?? 0,
      has_more: offset + limit < (totalRow?.cnt ?? 0),
    },
  });
});

/**
 * GET /v1/namespaces/:namespace/claims
 * Get claims for a namespace, optionally filtered by status and service.
 * Defined before /:namespace so this path is matched first.
 */
namespacesRouter.get("/:namespace/claims", async (c) => {
  const namespace = c.req.param("namespace");

  if (!NAMESPACE_RE.test(namespace)) {
    return c.json(createErrorResponse("Invalid namespace format", "VALIDATION_ERROR"), 400);
  }

  const status = c.req.query("status") ?? undefined;
  const service = c.req.query("service") ?? undefined;
  const limit = parsePositiveInt(c.req.query("limit"), 50, 200);
  const offset = parseNonNegativeInt(c.req.query("offset"), 0);

  const lookup = await lookupNamespaceClaims(c.env, namespace, status, service, limit, offset);
  if (!lookup.available) {
    console.error(`Namespace claims lookup failed for ${namespace}:`, lookup.error);
    return c.json(createErrorResponse("Authorization store unavailable", "DB_UNAVAILABLE"), 503);
  }

  return c.json({
    claims: lookup.claims,
    pagination: {
      limit,
      offset,
      total: lookup.total,
      has_more: offset + limit < lookup.total,
    },
  });
});

/**
 * GET /v1/namespaces/:namespace
 * Resolve a namespace from D1 (system-of-record).
 */
namespacesRouter.get("/:namespace", async (c) => {
  const namespace = c.req.param("namespace");

  if (!NAMESPACE_RE.test(namespace)) {
    return c.json(createErrorResponse("Invalid namespace format", "VALIDATION_ERROR"), 400);
  }

  const user = await c.env.DB.prepare(
    "SELECT id, namespace, created_at FROM users WHERE namespace = ? LIMIT 1",
  ).bind(namespace).first<{ id: string; namespace: string; created_at?: string }>();

  if (!user) {
    return c.json(createErrorResponse("Namespace not found", "NOT_FOUND"), 404);
  }

  const approved = await countApprovedClaims(c.env, namespace);
  if (!approved.available) {
    console.error(`Approved claims lookup failed for namespace ${namespace}:`, approved.error);
    return c.json(createErrorResponse("Authorization store unavailable", "DB_UNAVAILABLE"), 503);
  }

  c.header("Cache-Control", "public, max-age=300");
  return c.json({
    did: `did:sigilum:${namespace}`,
    namespace,
    owner: user.id,
    created_at: user.created_at ?? new Date().toISOString(),
    active: true,
    active_claims: approved.count,
  });
});
