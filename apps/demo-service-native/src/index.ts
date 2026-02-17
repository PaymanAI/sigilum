/**
 * Demo Service (Native Sigilum)
 *
 * A mock banking service that demonstrates Sigilum integration.
 * Agents register, humans approve on Sigilum, and agents can
 * then make authenticated requests.
 */

import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { logger } from "hono/logger";
import {
  SigilumVerifier,
  SigilumService,
  SigilumVerificationError,
  SigilumServiceError,
} from "@sigilum/sdk";

const app = new Hono();

// ─── Configuration ───────────────────────────────────────────────────────────

const SERVICE_NAME = "demo-service-native";
const VERIFY_REFRESH_INTERVAL_SECONDS = Number(
  process.env.SIGILUM_VERIFY_REFRESH_INTERVAL_SECONDS ?? 5,
);

// ─── In-memory state ─────────────────────────────────────────────────────────

interface RegisteredAgent {
  publicKey: string;
  namespace: string;
  registeredAt: string;
  claimId?: string;
  claimStatus: "pending" | "approved" | "revoked";
}

const agents = new Map<string, RegisteredAgent>();
const balances = new Map<string, number>();

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

// ─── Sigilum Service (for submitting claims) ─────────────────────────────────
// Automatically uses API mode if SIGILUM_API_KEY is set, or chain mode if SIGILUM_SERVICE_SIGNER_KEY is set

const sigilumService = new SigilumService({
  serviceName: SERVICE_NAME,
  // API mode (recommended) - provide apiKey
  apiKey: process.env.SIGILUM_API_KEY,
  apiUrl: process.env.SIGILUM_API_URL, // Optional override

  // Chain mode (advanced) - provide signerKey instead of apiKey
  signerKey: process.env.SIGILUM_SERVICE_SIGNER_KEY as `0x${string}` | undefined,
  rpcUrl: process.env.SIGILUM_RPC_URL,
  contractAddress: process.env.SIGILUM_CONTRACT_ADDRESS as `0x${string}` | undefined,
});

// ─── Verifier (for verifying agent signatures) ──────────────────────────────
// Uses cache-first architecture: fast local verification with background refresh

const verifier = new SigilumVerifier({
  serviceName: SERVICE_NAME,
  // Production defaults are hardcoded, but you can override for testing:
  apiUrl: process.env.SIGILUM_API_URL, // Defaults to 'https://api.sigilum.id'
  apiKey: process.env.SIGILUM_API_KEY,
  rpcUrl: process.env.SIGILUM_RPC_URL, // Defaults to 'https://mainnet.base.org'
  contractAddress: process.env.SIGILUM_CONTRACT_ADDRESS as `0x${string}` | undefined,
  refreshInterval: VERIFY_REFRESH_INTERVAL_SECONDS,
});

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use("*", logger());

// ─── Public Endpoints ────────────────────────────────────────────────────────

app.get("/", (c) => {
  return c.json({
    name: "Demo Service (Native)",
    description: "A mock banking service protected by Sigilum",
    endpoints: {
      "POST /agents/register": "Register an agent (public_key, namespace)",
      "POST /v1/ping": "Ping endpoint (requires Sigilum auth)",
      "GET /v1/balance": "Check balance (requires Sigilum auth)",
      "POST /v1/transfer": "Transfer funds (requires Sigilum auth)",
    },
  });
});

/**
 * POST /agents/register
 * Agent registers with the demo service. The service submits an authorization request to Sigilum.
 */
app.post("/agents/register", async (c) => {
  let body: { public_key: string; namespace: string };
  try {
    body = await c.req.json<{ public_key: string; namespace: string }>();
  } catch {
    return c.json({ error: "Invalid or malformed JSON body" }, 400);
  }

  const { public_key, namespace } = body;

  if (!public_key || !namespace) {
    return c.json({ error: "public_key and namespace are required" }, 400);
  }

  // Check if already registered
  if (agents.has(public_key)) {
    const existing = agents.get(public_key)!;
    return c.json(
      {
        status: existing.claimStatus,
        message:
          existing.claimStatus === "approved"
            ? "Agent already approved"
            : "Registration pending approval",
        public_key,
        namespace,
        claim_id: existing.claimId,
      },
      200,
    );
  }

  // Get client IP for Sigilum claim
  const clientIP =
    c.req.header("x-forwarded-for")?.split(",")[0].trim() ||
    c.req.header("x-real-ip") ||
    "127.0.0.1";

  console.log(
    `[Demo Service] Agent registering: ${public_key.slice(0, 20)}... for namespace: ${namespace} from IP: ${clientIP}`,
  );

  // Submit claim to Sigilum
  let claimId: string;
  try {
    const result = await sigilumService.submitClaim({
      namespace,
      publicKey: public_key,
      agentIP: clientIP,
    });
    claimId = result.claimId;

    console.log(
      `[Demo Service] ✓ Authorization request submitted to Sigilum. Claim ID: ${claimId}`,
    );
  } catch (err) {
    if (err instanceof SigilumServiceError) {
      console.error(`[Demo Service] Failed to submit authorization request:`, err.message);
      return c.json(
        {
          error: "Failed to submit authorization request to Sigilum",
          details: err.message,
        },
        500,
      );
    }
    throw err;
  }

  // Store the agent locally
  agents.set(public_key, {
    publicKey: public_key,
    namespace,
    registeredAt: new Date().toISOString(),
    claimId,
    claimStatus: "pending",
  });

  // Initialize balance for the namespace
  if (!balances.has(namespace)) {
    balances.set(namespace, 10_000); // Start with $10,000
  }

  return c.json(
    {
      status: "pending",
      message:
        "Claim submitted to Sigilum. Awaiting owner approval at https://app.sigilum.id",
      public_key,
      namespace,
      claim_id: claimId,
    },
    201,
  );
});

// ─── Protected Endpoints (require Sigilum auth) ─────────────────────────────

/**
 * POST /v1/ping
 * Ping endpoint for integration testing. Requires Sigilum authentication.
 * Request body must be JSON string: "ping"
 */
app.post("/v1/ping", async (c) => {
  try {
    const body = await c.req.text();
    await verifier.verify({
      method: c.req.method,
      url: c.req.url,
      headers: Object.fromEntries(
        [...c.req.raw.headers.entries()],
      ),
      body,
    });

    const parsed = parsePingPayload(body);
    if (!parsed.ok) {
      return c.json({ error: parsed.error }, 400);
    }
    return c.json("pong");
  } catch (err) {
    if (err instanceof SigilumVerificationError) {
      return c.json({ error: err.message }, 401);
    }
    if (err instanceof SyntaxError) {
      return c.json({ error: "Invalid or malformed JSON body" }, 400);
    }
    console.error("[Demo Service] Unexpected error in /v1/ping:", err);
    return c.json({ error: "Internal server error" }, 500);
  }
});

/**
 * GET /v1/balance
 * Check account balance. Requires Sigilum authentication.
 */
app.get("/v1/balance", async (c) => {
  try {
    const result = await verifier.verify({
      method: c.req.method,
      url: c.req.url,
      headers: Object.fromEntries(
        [...c.req.raw.headers.entries()],
      ),
    });

    const balance = balances.get(result.namespace) ?? 0;

    return c.json({
      namespace: result.namespace,
      balance,
      currency: "USD",
    });
  } catch (err) {
    if (err instanceof SigilumVerificationError) {
      return c.json({ error: err.message }, 401);
    }
    console.error("[Demo Service] Unexpected error in /v1/balance:", err);
    return c.json({ error: "Internal server error" }, 500);
  }
});

/**
 * POST /v1/transfer
 * Transfer funds. Requires Sigilum authentication.
 */
app.post("/v1/transfer", async (c) => {
  try {
    const body = await c.req.text();
    const result = await verifier.verify({
      method: c.req.method,
      url: c.req.url,
      headers: Object.fromEntries(
        [...c.req.raw.headers.entries()],
      ),
      body,
    });

    let parsed: { to: string; amount: number };
    try {
      parsed = JSON.parse(body) as { to: string; amount: number };
    } catch {
      return c.json({ error: "Invalid or malformed JSON body" }, 400);
    }
    const { to, amount } = parsed;

    const balance = balances.get(result.namespace) ?? 0;
    if (amount > balance) {
      return c.json({ error: "Insufficient funds" }, 400);
    }

    balances.set(result.namespace, balance - amount);

    console.log(
      `[Demo Service] Transfer: ${result.namespace} -> ${to}: $${amount}`,
    );

    return c.json({
      status: "success",
      from: result.namespace,
      to,
      amount,
      remaining_balance: balance - amount,
      currency: "USD",
    });
  } catch (err) {
    if (err instanceof SigilumVerificationError) {
      return c.json({ error: err.message }, 401);
    }
    if (err instanceof SyntaxError) {
      return c.json({ error: "Invalid or malformed JSON body" }, 400);
    }
    console.error("[Demo Service] Unexpected error in /v1/transfer:", err);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// ─── Start Server ────────────────────────────────────────────────────────────

const port = Number(process.env.PORT ?? 11000);

// Initialize verifier (fetch claims + start background refresh)
await verifier.start();

console.log(`
╔══════════════════════════════════════════╗
║      Demo Service (Native Sigilum)       ║
║     Protected by Sigilum Identity        ║
╠══════════════════════════════════════════╣
║  http://localhost:${port}                    ║
╚══════════════════════════════════════════╝

Cache-first verification enabled ✨
- Initial claims loaded: ${verifier.getCacheStats().size}
- Refresh interval: ${VERIFY_REFRESH_INTERVAL_SECONDS} seconds
`);

serve({ fetch: app.fetch, port });

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("\n[Demo Service] Shutting down...");
  verifier.stop();
  process.exit(0);
});
