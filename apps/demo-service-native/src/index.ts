import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { logger } from "hono/logger";
import path from "node:path";
import {
  certify,
  init,
  verifyHttpSignature,
  type SigilumAgentBindings,
} from "@sigilum/sdk";

const app = new Hono();

const SERVICE_NAME = "demo-service-native";
const DEFAULT_BALANCE = 10_000;
const CLAIMS_PAGE_SIZE = 500;
const port = Number(process.env.PORT ?? 11000);
const sigilumApiUrl = process.env.SIGILUM_API_URL ?? "http://127.0.0.1:8787";
const sigilumApiKey = process.env.SIGILUM_API_KEY;
const signerNamespace =
  process.env.SIGILUM_SERVICE_SIGNER_NAMESPACE ?? "demo-service-native-signer";
const signerHome =
  process.env.SIGILUM_SERVICE_SIGNER_HOME ??
  process.env.SIGILUM_HOME ??
  path.resolve(process.cwd(), "..", "..", ".sigilum-workspace");
const claimsRefreshMs = Number(process.env.SIGILUM_CLAIMS_REFRESH_MS ?? "10000");
const signatureMaxAgeSeconds = Number(
  process.env.SIGILUM_SIGNATURE_MAX_AGE_SECONDS ?? "300",
);

if (!sigilumApiKey) {
  throw new Error("SIGILUM_API_KEY is required for demo-service-native");
}
if (!Number.isFinite(claimsRefreshMs) || claimsRefreshMs < 1000) {
  throw new Error("SIGILUM_CLAIMS_REFRESH_MS must be >= 1000");
}
if (!Number.isFinite(signatureMaxAgeSeconds) || signatureMaxAgeSeconds <= 0) {
  throw new Error("SIGILUM_SIGNATURE_MAX_AGE_SECONDS must be > 0");
}

const approvedAuthorizations = new Set<string>();
const balances = new Map<string, number>();
let refreshTimer: ReturnType<typeof setInterval> | null = null;
let refreshInFlight: Promise<void> | null = null;

function authorizationKey(namespace: string, publicKey: string): string {
  return `${namespace}::${publicKey}`;
}

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

function parseTransferPayload(rawBody: string): { ok: true; to: string; amount: number } | { ok: false; error: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return { ok: false, error: "Invalid or malformed JSON body" };
  }
  if (!parsed || typeof parsed !== "object") {
    return { ok: false, error: "Expected JSON object body" };
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.to !== "string" || !record.to.trim()) {
    return { ok: false, error: "Field \"to\" must be a non-empty string" };
  }
  if (typeof record.amount !== "number" || !Number.isFinite(record.amount) || record.amount <= 0) {
    return { ok: false, error: "Field \"amount\" must be a positive number" };
  }
  return { ok: true, to: record.to, amount: record.amount };
}

async function fetchClaimsPage(
  signer: SigilumAgentBindings,
  offset: number,
): Promise<{
  claims: Array<{ namespace?: string; public_key?: string }>;
  pagination?: { has_more?: boolean; offset?: number; limit?: number };
}> {
  const url = `${sigilumApiUrl}/v1/namespaces/claims?service=${encodeURIComponent(
    SERVICE_NAME,
  )}&limit=${CLAIMS_PAGE_SIZE}&offset=${offset}`;
  const response = await signer.fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${sigilumApiKey}`,
    },
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(
      `Failed to fetch approved authorizations (status=${response.status} body=${text.slice(
        0,
        200,
      )})`,
    );
  }
  return response.json() as Promise<{
    claims: Array<{ namespace?: string; public_key?: string }>;
    pagination?: { has_more?: boolean; offset?: number; limit?: number };
  }>;
}

async function refreshApprovedAuthorizations(signer: SigilumAgentBindings): Promise<void> {
  const next = new Set<string>();
  let offset = 0;
  while (true) {
    const page = await fetchClaimsPage(signer, offset);
    for (const claim of page.claims ?? []) {
      if (typeof claim.namespace !== "string" || typeof claim.public_key !== "string") {
        continue;
      }
      next.add(authorizationKey(claim.namespace, claim.public_key));
      if (!balances.has(claim.namespace)) {
        balances.set(claim.namespace, DEFAULT_BALANCE);
      }
    }
    const hasMore = Boolean(page.pagination?.has_more);
    if (!hasMore) break;
    const step = Number(page.pagination?.limit ?? CLAIMS_PAGE_SIZE);
    offset += Number.isFinite(step) && step > 0 ? step : CLAIMS_PAGE_SIZE;
  }

  approvedAuthorizations.clear();
  for (const value of next) {
    approvedAuthorizations.add(value);
  }
}

function refreshApprovedAuthorizationsShared(
  signer: SigilumAgentBindings,
): Promise<void> {
  if (!refreshInFlight) {
    refreshInFlight = refreshApprovedAuthorizations(signer).finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

async function requireAuthorizedAgent(
  method: string,
  url: string,
  headers: Headers,
  signer: SigilumAgentBindings,
  body?: string,
): Promise<{ ok: true; namespace: string } | { ok: false; status: number; error: string }> {
  const verification = verifyHttpSignature({
    method,
    url,
    headers,
    body: body ?? null,
    strict: {
      maxAgeSeconds: signatureMaxAgeSeconds,
    },
  });

  if (!verification.valid || !verification.namespace) {
    return { ok: false, status: 401, error: "Unauthorized" };
  }

  const publicKey = headers.get("sigilum-agent-key");
  if (!publicKey) {
    return { ok: false, status: 401, error: "Unauthorized" };
  }

  const approved = approvedAuthorizations.has(
    authorizationKey(verification.namespace, publicKey),
  );
  if (!approved) {
    try {
      await refreshApprovedAuthorizationsShared(signer);
    } catch (error) {
      console.error("[Demo Service] Failed refresh during auth check:", error);
      return { ok: false, status: 503, error: "Authorization cache unavailable" };
    }
  }

  const approvedAfterRefresh = approvedAuthorizations.has(
    authorizationKey(verification.namespace, publicKey),
  );
  if (!approvedAfterRefresh) {
    return { ok: false, status: 401, error: "Unauthorized" };
  }

  return { ok: true, namespace: verification.namespace };
}

app.use("*", logger());

app.get("/", (c) => {
  return c.json({
    name: "Demo Service (Native)",
    description: "Bundled demo service with native Sigilum verification",
    endpoints: {
      "POST /v1/ping": "Ping endpoint (requires Sigilum auth)",
      "GET /v1/balance": "Check balance (requires Sigilum auth)",
      "POST /v1/transfer": "Transfer funds (requires Sigilum auth)",
    },
    cache_size: approvedAuthorizations.size,
  });
});

app.post("/v1/ping", async (c) => {
  const body = await c.req.text();
  const auth = await requireAuthorizedAgent(
    c.req.method,
    c.req.url,
    c.req.raw.headers,
    serviceSigner,
    body,
  );
  if (!auth.ok) {
    return c.json({ error: auth.error }, auth.status);
  }
  const parsed = parsePingPayload(body);
  if (!parsed.ok) {
    return c.json({ error: parsed.error }, 400);
  }
  return c.json("pong");
});

app.get("/v1/balance", async (c) => {
  const auth = await requireAuthorizedAgent(
    c.req.method,
    c.req.url,
    c.req.raw.headers,
    serviceSigner,
  );
  if (!auth.ok) {
    return c.json({ error: auth.error }, auth.status);
  }
  const balance = balances.get(auth.namespace) ?? DEFAULT_BALANCE;
  return c.json({
    namespace: auth.namespace,
    balance,
    currency: "USD",
  });
});

app.post("/v1/transfer", async (c) => {
  const body = await c.req.text();
  const auth = await requireAuthorizedAgent(
    c.req.method,
    c.req.url,
    c.req.raw.headers,
    serviceSigner,
    body,
  );
  if (!auth.ok) {
    return c.json({ error: auth.error }, auth.status);
  }

  const parsed = parseTransferPayload(body);
  if (!parsed.ok) {
    return c.json({ error: parsed.error }, 400);
  }

  const current = balances.get(auth.namespace) ?? DEFAULT_BALANCE;
  if (parsed.amount > current) {
    return c.json({ error: "Insufficient funds" }, 400);
  }

  const remaining = current - parsed.amount;
  balances.set(auth.namespace, remaining);
  return c.json({
    status: "success",
    from: auth.namespace,
    to: parsed.to,
    amount: parsed.amount,
    remaining_balance: remaining,
    currency: "USD",
  });
});

init({ namespace: signerNamespace, homeDir: signerHome });
const serviceSigner = certify(
  {},
  {
    namespace: signerNamespace,
    homeDir: signerHome,
    apiBaseUrl: sigilumApiUrl,
  },
).sigilum;

await refreshApprovedAuthorizationsShared(serviceSigner);
refreshTimer = setInterval(() => {
  void refreshApprovedAuthorizationsShared(serviceSigner).catch((error: unknown) => {
    console.error("[Demo Service] Failed to refresh approved authorizations:", error);
  });
}, claimsRefreshMs);

console.log(`
╔══════════════════════════════════════════╗
║      Demo Service (Native Sigilum)       ║
║     Protected by Sigilum Identity        ║
╠══════════════════════════════════════════╣
║  http://localhost:${port}                    ║
╚══════════════════════════════════════════╝

Initial approved auth cache size: ${approvedAuthorizations.size}
Refresh interval: ${claimsRefreshMs}ms
`);

serve({ fetch: app.fetch, port });

process.on("SIGTERM", () => {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
  process.exit(0);
});
