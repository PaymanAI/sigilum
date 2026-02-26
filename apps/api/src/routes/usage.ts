import { Hono } from "hono";
import { z } from "zod";
import type { Env } from "../types.js";
import { validateServiceApiKey } from "./services.js";
import { createErrorResponse } from "../utils/validation.js";

const usageEventSchema = z.object({
  event_id: z.string().trim().min(1).max(128),
  namespace: z.string().trim().min(3).max(64),
  service: z.string().trim().min(1).max(128),
  public_key: z.string().trim().min(1).max(256),
  subject: z.string().trim().min(1).max(256),
  agent_id: z.string().trim().min(1).max(128).optional(),
  protocol: z.enum(["http", "mcp"]),
  action: z.string().trim().min(1).max(64),
  outcome: z.string().trim().min(1).max(32),
  status_code: z.number().int().min(100).max(599).optional(),
  duration_ms: z.number().int().min(0).max(3_600_000).optional(),
  response_bytes: z.number().int().min(0).max(100_000_000).optional(),
  request_method: z.string().trim().min(1).max(16).optional(),
  request_path: z.string().trim().min(1).max(512).optional(),
  remote_ip: z.string().trim().min(1).max(128).optional(),
});

export const usageRouter = new Hono<{ Bindings: Env }>();

/**
 * POST /v1/usage/events
 * Ingest a single gateway usage event for usage/audit analytics.
 * Requires a valid service API key.
 */
usageRouter.post("/events", async (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json(
      createErrorResponse("Missing or invalid Authorization header. Use: Bearer <service_api_key>", "UNAUTHORIZED"),
      401,
    );
  }

  const apiKey = authHeader.slice(7).trim();
  const serviceInfo = await validateServiceApiKey(c.env.DB, apiKey);
  if (!serviceInfo) {
    return c.json(createErrorResponse("Invalid or revoked API key", "FORBIDDEN"), 403);
  }

  let body: z.infer<typeof usageEventSchema>;
  try {
    body = usageEventSchema.parse(await c.req.json());
  } catch (err) {
    if (err instanceof z.ZodError) {
      const fields = err.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      }));
      return c.json(createErrorResponse("Validation failed", "VALIDATION_ERROR", fields), 400);
    }
    return c.json(createErrorResponse("Invalid request body", "INVALID_JSON"), 400);
  }

  if (body.service !== serviceInfo.slug) {
    return c.json(
      createErrorResponse(`API key belongs to service "${serviceInfo.slug}" but event is for "${body.service}"`, "FORBIDDEN"),
      403,
    );
  }

  const method = body.request_method?.toUpperCase().trim() || null;
  const agentID = body.agent_id?.trim() || null;
  const result = await c.env.DB.prepare(
    `INSERT INTO usage_events (
      event_id, namespace, service, public_key, subject, agent_id,
      protocol, action, outcome, status_code, duration_ms, response_bytes,
      request_method, request_path, remote_ip
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(event_id) DO NOTHING`,
  )
    .bind(
      body.event_id,
      body.namespace,
      body.service,
      body.public_key,
      body.subject,
      agentID,
      body.protocol,
      body.action,
      body.outcome,
      body.status_code ?? null,
      body.duration_ms ?? null,
      body.response_bytes ?? null,
      method,
      body.request_path?.trim() || null,
      body.remote_ip?.trim() || null,
    )
    .run();

  const inserted = (result.meta.changes ?? 0) > 0;
  return c.json(
    {
      event_id: body.event_id,
      accepted: true,
      duplicate: !inserted,
    },
    inserted ? 201 : 200,
  );
});
