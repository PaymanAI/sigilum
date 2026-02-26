import { Hono } from "hono";
import type { Env } from "../types.js";
import { createErrorResponse } from "../utils/validation.js";
import { validateServiceApiKey } from "./services.js";
import { getBearerToken, verifyJWT } from "./auth.js";

/** Namespace must be 3-64 characters, alphanumeric and hyphens only. */
const NAMESPACE_RE = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,62}[a-zA-Z0-9]$/;

export const namespacesRouter = new Hono<{ Bindings: Env }>();

type NamespaceClaimsLookup =
  | {
    available: true;
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

function parsePositiveInt(raw: string | undefined, defaultValue: number, max: number): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return defaultValue;
  return Math.min(parsed, max);
}

function parseNonNegativeInt(raw: string | undefined, defaultValue: number): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isFinite(parsed) || parsed < 0) return defaultValue;
  return parsed;
}

type UsageSort = "recent" | "calls_desc" | "subject_asc";

function parseUsageSort(raw: string | undefined): UsageSort {
  const normalized = (raw ?? "").trim().toLowerCase();
  if (normalized === "calls_desc") return "calls_desc";
  if (normalized === "subject_asc") return "subject_asc";
  return "recent";
}

function parseISODateTime(raw: string | undefined): string | null {
  const value = (raw ?? "").trim();
  if (!value) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  return new Date(parsed).toISOString();
}

async function selectNamespaceClaims(
  env: Env,
  namespace: string,
  status: string | undefined,
  service: string | undefined,
  limit: number,
  offset: number,
): Promise<Array<Record<string, unknown>>> {
  let sql = `SELECT claim_id, namespace, service, public_key, agent_ip, subject, agent_id, agent_name, status, created_at, approved_at, revoked_at
             FROM authorizations
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
  namespace: string,
  status: string | undefined,
  service: string | undefined,
): Promise<number> {
  let sql = "SELECT COUNT(*) as cnt FROM authorizations WHERE namespace = ?";
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
  try {
    const [claims, total] = await Promise.all([
      selectNamespaceClaims(env, namespace, status, service, limit, offset),
      countNamespaceClaims(env, namespace, status, service),
    ]);
    return { available: true, claims, total };
  } catch (err) {
    return { available: false, error: toErrorMessage(err) };
  }
}

async function countApprovedClaims(
  env: Env,
  namespace: string,
): Promise<ApprovedClaimsCountLookup> {
  try {
    const row = await env.DB.prepare(
      `SELECT COUNT(*) as cnt
       FROM authorizations
       WHERE namespace = ? AND status = 'approved'`,
    ).bind(namespace).first<{ cnt: number }>();
    return { available: true, count: row?.cnt ?? 0 };
  } catch (err) {
    return { available: false, error: toErrorMessage(err) };
  }
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
    `SELECT claim_id, namespace, public_key, service, subject, agent_id, agent_name, status, approved_at
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
    subject: row.subject,
    agent_id: row.agent_id,
    agent_name: row.agent_name,
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

  const token = getBearerToken(c);
  if (!token) {
    return c.json(createErrorResponse("Authentication required", "UNAUTHORIZED"), 401);
  }
  const payload = await verifyJWT(c.env, token);
  if (!payload) {
    return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);
  }
  if (payload.namespace !== namespace) {
    return c.json(createErrorResponse("Not authorized to view claims in this namespace", "FORBIDDEN"), 403);
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
 * GET /v1/namespaces/:namespace/usage
 * Aggregated usage/audit view grouped by subject + provider + agent.
 * Query params:
 * - subject: partial subject match
 * - provider: exact service slug
 * - agent: partial agent_id/public_key match
 * - from, to: ISO date-time bounds
 * - sort: recent | calls_desc | subject_asc
 * - limit, offset: pagination over grouped rows
 */
namespacesRouter.get("/:namespace/usage", async (c) => {
  const namespace = c.req.param("namespace");

  if (!NAMESPACE_RE.test(namespace)) {
    return c.json(createErrorResponse("Invalid namespace format", "VALIDATION_ERROR"), 400);
  }

  const token = getBearerToken(c);
  if (!token) {
    return c.json(createErrorResponse("Authentication required", "UNAUTHORIZED"), 401);
  }
  const payload = await verifyJWT(c.env, token);
  if (!payload) {
    return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);
  }
  if (payload.namespace !== namespace) {
    return c.json(createErrorResponse("Not authorized to view usage in this namespace", "FORBIDDEN"), 403);
  }

  const subjectFilter = (c.req.query("subject") ?? "").trim().toLowerCase();
  const providerFilter = (c.req.query("provider") ?? "").trim();
  const agentFilter = (c.req.query("agent") ?? "").trim().toLowerCase();
  const sort = parseUsageSort(c.req.query("sort"));
  const limit = parsePositiveInt(c.req.query("limit"), 50, 200);
  const offset = parseNonNegativeInt(c.req.query("offset"), 0);

  const from = c.req.query("from") ? parseISODateTime(c.req.query("from")) : null;
  const to = c.req.query("to") ? parseISODateTime(c.req.query("to")) : null;
  if (c.req.query("from") && !from) {
    return c.json(createErrorResponse("Invalid 'from' date-time; expected ISO format", "VALIDATION_ERROR"), 400);
  }
  if (c.req.query("to") && !to) {
    return c.json(createErrorResponse("Invalid 'to' date-time; expected ISO format", "VALIDATION_ERROR"), 400);
  }

  const where: string[] = ["namespace = ?"];
  const params: Array<string | number> = [namespace];

  if (subjectFilter) {
    where.push("LOWER(subject) LIKE ?");
    params.push(`%${subjectFilter}%`);
  }
  if (providerFilter) {
    where.push("service = ?");
    params.push(providerFilter);
  }
  if (agentFilter) {
    where.push("(LOWER(COALESCE(agent_id, '')) LIKE ? OR LOWER(public_key) LIKE ?)");
    params.push(`%${agentFilter}%`, `%${agentFilter}%`);
  }
  if (from) {
    where.push("created_at >= ?");
    params.push(from);
  }
  if (to) {
    where.push("created_at <= ?");
    params.push(to);
  }

  const whereSQL = where.join(" AND ");
  const orderBy =
    sort === "calls_desc"
      ? "total_calls DESC, last_used_at DESC"
      : sort === "subject_asc"
        ? "subject ASC, provider ASC, total_calls DESC"
        : "last_used_at DESC, total_calls DESC";

  const [rows, totalRow, summaryRow] = await Promise.all([
    c.env.DB.prepare(
      `SELECT
         subject,
         service AS provider,
         CASE
           WHEN TRIM(COALESCE(agent_id, '')) = '' THEN NULL
           ELSE agent_id
         END AS agent_id,
         public_key,
         COUNT(*) AS total_calls,
         SUM(CASE WHEN outcome = 'success' THEN 1 ELSE 0 END) AS success_calls,
         SUM(CASE WHEN outcome != 'success' THEN 1 ELSE 0 END) AS error_calls,
         MAX(created_at) AS last_used_at
       FROM usage_events
       WHERE ${whereSQL}
       GROUP BY subject, provider, public_key, agent_id
       ORDER BY ${orderBy}
       LIMIT ? OFFSET ?`,
    )
      .bind(...params, limit, offset)
      .all(),
    c.env.DB.prepare(
      `SELECT COUNT(*) AS cnt FROM (
         SELECT 1
         FROM usage_events
         WHERE ${whereSQL}
         GROUP BY subject, service, public_key, agent_id
       )`,
    )
      .bind(...params)
      .first<{ cnt: number }>(),
    c.env.DB.prepare(
      `SELECT
         COUNT(*) AS total_events,
         SUM(CASE WHEN outcome = 'success' THEN 1 ELSE 0 END) AS successful_events,
         SUM(CASE WHEN outcome != 'success' THEN 1 ELSE 0 END) AS failed_events,
         COUNT(DISTINCT subject) AS unique_subjects,
         COUNT(DISTINCT service) AS unique_providers,
         COUNT(DISTINCT CASE
           WHEN TRIM(COALESCE(agent_id, '')) = '' THEN public_key
           ELSE agent_id
         END) AS unique_agents
       FROM usage_events
       WHERE ${whereSQL}`,
    )
      .bind(...params)
      .first<{
        total_events: number;
        successful_events: number;
        failed_events: number;
        unique_subjects: number;
        unique_providers: number;
        unique_agents: number;
      }>(),
  ]);

  const total = Number(totalRow?.cnt ?? 0);
  return c.json({
    rows: rows.results.map((row) => ({
      subject: row.subject,
      provider: row.provider,
      agent_id: row.agent_id ?? null,
      public_key: row.public_key,
      total_calls: Number(row.total_calls ?? 0),
      success_calls: Number(row.success_calls ?? 0),
      error_calls: Number(row.error_calls ?? 0),
      last_used_at: row.last_used_at,
    })),
    summary: {
      total_events: Number(summaryRow?.total_events ?? 0),
      successful_events: Number(summaryRow?.successful_events ?? 0),
      failed_events: Number(summaryRow?.failed_events ?? 0),
      unique_subjects: Number(summaryRow?.unique_subjects ?? 0),
      unique_providers: Number(summaryRow?.unique_providers ?? 0),
      unique_agents: Number(summaryRow?.unique_agents ?? 0),
    },
    pagination: {
      limit,
      offset,
      total,
      has_more: offset + limit < total,
    },
    applied_filters: {
      subject: subjectFilter || null,
      provider: providerFilter || null,
      agent: agentFilter || null,
      from: from ?? null,
      to: to ?? null,
      sort,
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
