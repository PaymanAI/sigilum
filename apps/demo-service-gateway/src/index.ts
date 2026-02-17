/**
 * Demo Service (Gateway)
 *
 * This service intentionally does not use the Sigilum SDK.
 * It relies on Sigilum Gateway to inject an upstream credential header.
 */

import { serve } from "@hono/node-server";
import { Hono } from "hono";
import type { Context } from "hono";
import { logger } from "hono/logger";

const app = new Hono();

const port = Number(process.env.PORT ?? 11100);
const upstreamHeader = process.env.DEMO_UPSTREAM_HEADER ?? "X-Demo-Service-Gateway-Key";
const expectedUpstreamKey = process.env.DEMO_UPSTREAM_KEY ?? "";
const gatewayConnectionID =
  process.env.DEMO_GATEWAY_CONNECTION_ID ??
  process.env.DEMO_PROXY_CONNECTION_ID ??
  "demo-service-gateway";

const balances = new Map<string, number>();
balances.set("main", 10_000);

function parsePingPayload(rawBody: string): { ok: true } | { ok: false; error: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return { ok: false, error: "Invalid or malformed JSON body" };
  }
  if (parsed !== "ping") {
    return { ok: false, error: "Expected JSON body to be the string \"ping\"" };
  }
  return { ok: true };
}

function requireGatewayCredential(c: Context): Response | null {
  const supplied =
    c.req.header(upstreamHeader) ??
    c.req.header(upstreamHeader.toLowerCase());
  if (expectedUpstreamKey !== "" && supplied === expectedUpstreamKey) {
    return null;
  }
  return c.json(
    {
      error: "Unauthorized upstream credential",
      hint:
        `Use local gateway /proxy/${gatewayConnectionID}/* routes so gateway can inject the upstream secret.`,
    },
    401,
  );
}

app.use("*", logger());

app.get("/", (c) => {
  return c.json({
    name: "Demo Service (Gateway)",
    description: "Non-native demo service that requires Sigilum Gateway",
    endpoints: {
      "GET /health": "Service status",
      "POST /v1/ping": "Ping endpoint (requires gateway upstream credential)",
      "GET /v1/balance": "Get balance (requires gateway-injected upstream credential)",
      "POST /v1/transfer": "Transfer funds (requires gateway-injected upstream credential)",
    },
  });
});

app.get("/health", (c) => {
  return c.json({
    ok: true,
    mode: "gateway-only",
    upstream_header: upstreamHeader,
    upstream_key_configured: expectedUpstreamKey !== "",
  });
});

app.get("/v1/balance", (c) => {
  const authError = requireGatewayCredential(c);
  if (authError) return authError;

  const account = c.req.query("account") ?? "main";
  const balance = balances.get(account) ?? 0;
  return c.json({
    account,
    balance,
    currency: "USD",
    via: "gateway",
  });
});

app.post("/v1/ping", async (c) => {
  const authError = requireGatewayCredential(c);
  if (authError) return authError;

  const body = await c.req.text();
  const parsed = parsePingPayload(body);
  if (!parsed.ok) {
    return c.json({ error: parsed.error }, 400);
  }
  return c.json("pong");
});

app.post("/v1/transfer", async (c) => {
  const authError = requireGatewayCredential(c);
  if (authError) return authError;

  let body: { to: string; amount: number; from?: string };
  try {
    body = await c.req.json<{ to: string; amount: number; from?: string }>();
  } catch {
    return c.json({ error: "Invalid or malformed JSON body" }, 400);
  }

  const from = body.from ?? "main";
  const to = body.to?.trim();
  const amount = Number(body.amount);

  if (!to || !Number.isFinite(amount) || amount <= 0) {
    return c.json({ error: "to and amount (> 0) are required" }, 400);
  }

  const current = balances.get(from) ?? 0;
  if (amount > current) {
    return c.json({ error: "Insufficient funds" }, 400);
  }

  balances.set(from, current - amount);
  console.log(`[Demo Service Gateway] Transfer: ${from} -> ${to}: $${amount}`);

  return c.json({
    status: "success",
    from,
    to,
    amount,
    remaining_balance: current - amount,
    currency: "USD",
    via: "gateway",
  });
});

if (!expectedUpstreamKey) {
  console.warn(
    "[Demo Service Gateway] DEMO_UPSTREAM_KEY is not set. Requests will be rejected until configured.",
  );
}

console.log(`
╔══════════════════════════════════════════════════╗
║          Demo Service (Gateway)                 ║
║       Non-native (via local gateway)            ║
╠══════════════════════════════════════════════════╣
║  http://localhost:${port}                              ║
╚══════════════════════════════════════════════════╝
`);

serve({ fetch: app.fetch, port });
