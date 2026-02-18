import { Hono } from "hono";
import type { Env } from "../types.js";
import { createErrorResponse } from "../utils/validation.js";

const NAMESPACE_RE = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,62}[a-zA-Z0-9]$/;
const SERVICE_RE = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;

type SeedUpsert = {
  namespace: string;
  service: string;
  public_key: string;
  claim_id?: string;
  agent_ip?: string;
};

type SeedDelete = {
  namespace: string;
  service: string;
  public_key: string;
};

type SeedPayload = {
  upserts?: SeedUpsert[];
  deletes?: SeedDelete[];
};

export const testSeedRouter = new Hono<{ Bindings: Env }>();

function isLocalOrTestEnvironment(environment: string | undefined): boolean {
  const value = (environment ?? "").trim().toLowerCase();
  return value === "local" || value === "test";
}

export function isTestSeedEndpointEnabled(env: Pick<Env, "ENVIRONMENT" | "ENABLE_TEST_SEED_ENDPOINT">): boolean {
  const enabled = (env.ENABLE_TEST_SEED_ENDPOINT ?? "").trim().toLowerCase() === "true";
  return enabled && isLocalOrTestEnvironment(env.ENVIRONMENT);
}

function isLoopbackHost(rawUrl: string): boolean {
  let hostname = "";
  try {
    hostname = new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return false;
  }
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function isValidUpsert(value: unknown): value is SeedUpsert {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.namespace === "string" &&
    typeof record.service === "string" &&
    typeof record.public_key === "string"
  );
}

function isValidDelete(value: unknown): value is SeedDelete {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.namespace === "string" &&
    typeof record.service === "string" &&
    typeof record.public_key === "string"
  );
}

function normalizeToken(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  if (!normalized) return undefined;
  return normalized;
}

testSeedRouter.post("/seed", async (c) => {
  if (!isTestSeedEndpointEnabled(c.env)) {
    return c.json(createErrorResponse("Not found", "NOT_FOUND"), 404);
  }
  if (!isLoopbackHost(c.req.raw.url)) {
    return c.json(createErrorResponse("Not found", "NOT_FOUND"), 404);
  }

  const expectedToken = normalizeToken(c.env.SIGILUM_TEST_SEED_TOKEN);
  if (!expectedToken) {
    return c.json(createErrorResponse("Not found", "NOT_FOUND"), 404);
  }
  const suppliedToken = c.req.header("X-Sigilum-Test-Seed-Token")?.trim() ?? "";
  if (suppliedToken !== expectedToken) {
    return c.json(createErrorResponse("Invalid test seed token", "UNAUTHORIZED"), 401);
  }

  let payload: SeedPayload;
  try {
    payload = await c.req.json<SeedPayload>();
  } catch {
    return c.json(createErrorResponse("Invalid JSON body", "VALIDATION_ERROR"), 400);
  }

  const upserts = payload.upserts ?? [];
  const deletes = payload.deletes ?? [];
  if (!Array.isArray(upserts) || !Array.isArray(deletes)) {
    return c.json(createErrorResponse("upserts and deletes must be arrays", "VALIDATION_ERROR"), 400);
  }
  if (upserts.length > 500 || deletes.length > 500) {
    return c.json(createErrorResponse("Seed batch too large", "VALIDATION_ERROR"), 400);
  }

  for (const upsert of upserts) {
    if (!isValidUpsert(upsert)) {
      return c.json(createErrorResponse("Invalid upsert payload item", "VALIDATION_ERROR"), 400);
    }
    if (!NAMESPACE_RE.test(upsert.namespace) || !SERVICE_RE.test(upsert.service) || upsert.public_key.trim() === "") {
      return c.json(createErrorResponse("Invalid upsert identifiers", "VALIDATION_ERROR"), 400);
    }
  }
  for (const del of deletes) {
    if (!isValidDelete(del)) {
      return c.json(createErrorResponse("Invalid delete payload item", "VALIDATION_ERROR"), 400);
    }
    if (!NAMESPACE_RE.test(del.namespace) || !SERVICE_RE.test(del.service) || del.public_key.trim() === "") {
      return c.json(createErrorResponse("Invalid delete identifiers", "VALIDATION_ERROR"), 400);
    }
  }

  for (const upsert of upserts) {
    const claimId = upsert.claim_id?.trim() || `cl_sim_${crypto.randomUUID().replace(/-/g, "").slice(0, 20)}`;
    const agentIP = upsert.agent_ip?.trim() || "127.0.0.1";
    await c.env.DB.prepare(
      `INSERT INTO authorizations (namespace, service, public_key, claim_id, agent_ip, status, approved_at, revoked_at)
       VALUES (?, ?, ?, ?, ?, 'approved', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL)
       ON CONFLICT(namespace, service, public_key)
       DO UPDATE SET
         claim_id = excluded.claim_id,
         agent_ip = excluded.agent_ip,
         status = 'approved',
         approved_at = excluded.approved_at,
         revoked_at = NULL`,
    )
      .bind(upsert.namespace, upsert.service, upsert.public_key, claimId, agentIP)
      .run();
  }

  for (const del of deletes) {
    await c.env.DB.prepare(
      "DELETE FROM authorizations WHERE namespace = ? AND service = ? AND public_key = ?",
    )
      .bind(del.namespace, del.service, del.public_key)
      .run();
  }

  return c.json({
    ok: true,
    upserts: upserts.length,
    deletes: deletes.length,
  });
});
