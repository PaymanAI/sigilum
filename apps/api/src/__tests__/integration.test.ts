import { beforeEach, describe, expect, it, vi } from "vitest";
import { SignJWT } from "jose";
import { app } from "../index.js";

type Row = Record<string, unknown>;

class MockStatement {
  private params: unknown[] = [];

  constructor(
    private readonly db: MockD1Database,
    private readonly sql: string,
  ) {}

  bind(...params: unknown[]) {
    this.params = params;
    return this;
  }

  async first<T = Row>() {
    return this.db.first<T>(this.sql, this.params);
  }

  async all<T = Row>() {
    return this.db.all<T>(this.sql, this.params);
  }

  async run() {
    return this.db.run(this.sql, this.params);
  }
}

class MockD1Database {
  serviceApiKeys: Array<Row> = [];
  services: Array<Row> = [];
  webhooks: Array<Row> = [];
  authorizations: Array<Row> = [];
  users: Array<Row> = [];

  prepare(sql: string) {
    return new MockStatement(this, sql);
  }

  async first<T>(sql: string, params: unknown[]): Promise<T | null> {
    if (sql.includes("FROM service_api_keys k") && sql.includes("JOIN services s")) {
      const keyHash = params[0];
      const key = this.serviceApiKeys.find(
        (k) => k.key_hash === keyHash && !k.revoked_at,
      );
      if (!key) return null;
      const service = this.services.find((s) => s.id === key.service_id);
      if (!service) return null;
      return {
        key_id: key.id,
        service_id: key.service_id,
        slug: service.slug,
      } as T;
    }

    if (sql.includes("SELECT COUNT(*) as cnt FROM webhooks WHERE service_id = ? AND active = 1")) {
      const serviceId = params[0];
      const cnt = this.webhooks.filter(
        (w) => w.service_id === serviceId && w.active === 1,
      ).length;
      return { cnt } as T;
    }

    if (sql.includes("SELECT COUNT(*) as cnt FROM webhooks WHERE service_id = ?")) {
      const serviceId = params[0];
      const cnt = this.webhooks.filter((w) => w.service_id === serviceId).length;
      return { cnt } as T;
    }

    if (sql.includes("SELECT id FROM webhooks WHERE id = ? AND service_id = ?")) {
      const [id, serviceId] = params;
      const row = this.webhooks.find((w) => w.id === id && w.service_id === serviceId);
      return (row ? { id } : null) as T | null;
    }

    if (sql.includes("SELECT COUNT(*) AS cnt FROM authorizations WHERE service = ? AND status = ?")) {
      const [service, status] = params;
      const cnt = this.authorizations.filter(
        (a) => a.service === service && a.status === status,
      ).length;
      return { cnt } as T;
    }

    if (
      sql.includes("FROM authorizations") &&
      sql.includes("public_key = ?") &&
      sql.includes("status = 'approved'")
    ) {
      const [namespace, publicKey, service] = params as [string, string, string];
      const found = this.authorizations.find(
        (a) =>
          a.namespace === namespace &&
          a.public_key === publicKey &&
          a.service === service &&
          a.status === "approved",
      );
      return (
        found
          ? {
            claim_id: found.claim_id,
            approved_at: found.approved_at ?? null,
          }
          : null
      ) as T | null;
    }

    if (sql.includes("FROM users WHERE namespace = ?")) {
      const [namespace] = params as [string];
      const user = this.users.find((u) => u.namespace === namespace);
      return (user
        ? {
          id: user.id,
          namespace: user.namespace,
          created_at: user.created_at,
          updated_at: user.updated_at,
        }
        : null) as T | null;
    }

    if (sql.includes("COUNT(*) as cnt") && sql.includes("FROM authorizations") && sql.includes("namespace = ?")) {
      const [namespace] = params as [string];
      const cnt = this.authorizations.filter(
        (a) => a.namespace === namespace && a.status === "approved",
      ).length;
      return { cnt } as T;
    }

    return null;
  }

  async all<T>(sql: string, params: unknown[]): Promise<{ results: T[] }> {
    if (sql.includes("SELECT id, url, events, active, failure_count")) {
      const [serviceId, limit, offset] = params as [string, number, number];
      const rows = this.webhooks
        .filter((w) => w.service_id === serviceId)
        .slice(offset, offset + limit);
      return { results: rows as T[] };
    }

    if (
      sql.includes("SELECT claim_id, namespace, public_key, service, status, approved_at") &&
      sql.includes("FROM authorizations")
    ) {
      const [service, status, limit, offset] = params as [string, string, number, number];
      const rows = this.authorizations
        .filter((a) => a.service === service && a.status === status)
        .slice(offset, offset + limit);
      return { results: rows as T[] };
    }

    if (sql.includes("SELECT * FROM authorizations WHERE namespace = ?")) {
      const [namespace] = params;
      let rows = this.authorizations.filter((a) => a.namespace === namespace);
      if (sql.includes("AND status = ?")) {
        const status = params[1];
        rows = rows.filter((a) => a.status === status);
      }
      if (sql.includes("AND service = ?")) {
        const service = params[sql.includes("AND status = ?") ? 2 : 1];
        rows = rows.filter((a) => a.service === service);
      }
      return { results: rows as T[] };
    }

    if (
      sql.includes("FROM authorizations") &&
      sql.includes("WHERE namespace = ?") &&
      sql.includes("LIMIT ? OFFSET ?")
    ) {
      const [namespace] = params as [string];
      let rows = this.authorizations.filter((a) => a.namespace === namespace);
      if (sql.includes("AND status = ?")) {
        rows = rows.filter((a) => a.status === params[1]);
      }
      if (sql.includes("AND service = ?")) {
        const serviceParam = sql.includes("AND status = ?") ? params[2] : params[1];
        rows = rows.filter((a) => a.service === serviceParam);
      }
      const limit = Number(params[params.length - 2] ?? 50);
      const offset = Number(params[params.length - 1] ?? 0);
      return { results: rows.slice(offset, offset + limit) as T[] };
    }

    if (
      sql.includes("SELECT claim_id, service, status, public_key") &&
      sql.includes("FROM authorizations") &&
      sql.includes("status = 'approved'")
    ) {
      const [namespace] = params as [string];
      const rows = this.authorizations.filter(
        (a) => a.namespace === namespace && a.status === "approved",
      );
      return { results: rows as T[] };
    }

    return { results: [] };
  }

  async run(sql: string, params: unknown[]): Promise<{ meta: { changes: number } }> {
    if (sql.startsWith("INSERT INTO webhooks")) {
      const [id, serviceId, url, events, secretHash, authName, authValue] = params;
      this.webhooks.push({
        id,
        service_id: serviceId,
        url,
        events,
        secret_hash: secretHash,
        auth_header_name: authName ?? null,
        auth_header_value: authValue ?? null,
        active: 1,
        failure_count: 0,
        last_triggered_at: null,
        last_failure_at: null,
        created_at: new Date().toISOString(),
      });
      return { meta: { changes: 1 } };
    }

    if (sql.startsWith("DELETE FROM webhooks WHERE id = ?")) {
      const id = params[0];
      const before = this.webhooks.length;
      this.webhooks = this.webhooks.filter((w) => w.id !== id);
      return { meta: { changes: before - this.webhooks.length } };
    }

    if (sql.startsWith("UPDATE service_api_keys SET last_used_at")) {
      return { meta: { changes: 1 } };
    }

    return { meta: { changes: 0 } };
  }
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function createSessionCookie(
  env: { JWT_SECRET: string },
  claims?: { userId?: string; email?: string; namespace?: string },
): Promise<string> {
  const token = await new SignJWT({
    email: claims?.email ?? "alice@example.com",
    namespace: claims?.namespace ?? "alice",
  })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(claims?.userId ?? "user_1")
    .setIssuer("sigilum-api")
    .setAudience("sigilum-dashboard")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(new TextEncoder().encode(env.JWT_SECRET));
  return `sigilum_token=${token}`;
}

let fetchMock: ReturnType<typeof vi.fn>;
let db: MockD1Database;
let signingContexts: Map<string, {
  namespace: string;
  did: string;
  keyId: string;
  publicKey: string;
  privateKey: CryptoKey;
  certificateHeader: string;
}>;
let nonceSeen: Set<string>;

function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function certificatePayload(input: {
  namespace: string;
  did: string;
  keyId: string;
  publicKey: string;
  issuedAt: string;
  expiresAt: string | null;
}): string {
  return [
    "sigilum-certificate-v1",
    `namespace:${input.namespace}`,
    `did:${input.did}`,
    `key-id:${input.keyId}`,
    `public-key:${input.publicKey}`,
    `issued-at:${input.issuedAt}`,
    `expires-at:${input.expiresAt ?? ""}`,
  ].join("\n");
}

async function buildSigningContext(namespace = "alice") {
  const keyPair = (await crypto.subtle.generateKey(
    "Ed25519",
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const privateKey = keyPair.privateKey;
  const publicRaw = new Uint8Array(
    (await crypto.subtle.exportKey("raw", keyPair.publicKey)) as ArrayBuffer,
  );
  const publicKey = `ed25519:${toBase64(publicRaw)}`;
  const did = `did:sigilum:${namespace}`;
  const keyId = `${did}#ed25519-test`;
  const issuedAt = new Date().toISOString();
  const certBase = {
    version: 1,
    namespace,
    did,
    keyId,
    publicKey,
    issuedAt,
    expiresAt: null as string | null,
  };
  const certSig = new Uint8Array(
    await crypto.subtle.sign(
      "Ed25519",
      privateKey,
      new TextEncoder().encode(certificatePayload(certBase)),
    ),
  );
  const certificate = {
    ...certBase,
    proof: {
      alg: "ed25519",
      sig: toBase64Url(certSig),
    },
  };
  return {
    namespace,
    did,
    keyId,
    publicKey,
    privateKey,
    certificateHeader: toBase64Url(new TextEncoder().encode(JSON.stringify(certificate))),
  };
}

async function signRequest(path: string, init?: RequestInit): Promise<RequestInit> {
  const base = new URL(path, "http://localhost");
  const method = (init?.method ?? "GET").toUpperCase();
  const headers = new Headers(init?.headers);
  const bodyText =
    typeof init?.body === "string" ? init.body : init?.body ? String(init.body) : "";

  const extractNamespace = (): string => {
    if (base.pathname === "/v1/verify") {
      return base.searchParams.get("namespace") ?? "alice";
    }
    if (base.pathname.startsWith("/v1/namespaces/")) {
      const rest = base.pathname.slice("/v1/namespaces/".length);
      const first = rest.split("/")[0];
      if (first && first !== "claims") return decodeURIComponent(first);
    }
    if (base.pathname.startsWith("/.well-known/did/")) {
      const did = decodeURIComponent(base.pathname.slice("/.well-known/did/".length));
      if (did.startsWith("did:sigilum:")) return did.slice("did:sigilum:".length);
    }
    if (base.pathname === "/v1/claims" && method === "POST" && bodyText) {
      try {
        const parsed = JSON.parse(bodyText) as { namespace?: string };
        if (parsed.namespace) return parsed.namespace;
      } catch {
        // ignore malformed test body
      }
    }
    return "alice";
  };

  const namespace = extractNamespace();
  let signingContext = signingContexts.get(namespace);
  if (!signingContext) {
    signingContext = await buildSigningContext(namespace);
    signingContexts.set(namespace, signingContext);
  }

  if (bodyText) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(bodyText)));
    headers.set("content-digest", `sha-256=:${toBase64(digest)}:`);
  }

  headers.set("sigilum-namespace", signingContext.namespace);
  headers.set("sigilum-agent-key", signingContext.publicKey);
  headers.set("sigilum-agent-cert", signingContext.certificateHeader);

  const components = bodyText
    ? ["@method", "@target-uri", "content-digest", "sigilum-namespace", "sigilum-agent-key", "sigilum-agent-cert"]
    : ["@method", "@target-uri", "sigilum-namespace", "sigilum-agent-key", "sigilum-agent-cert"];
  const created = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomUUID();
  const signatureParams =
    `(${components.map((c) => `"${c}"`).join(" ")});created=${created};` +
    `keyid="${signingContext.keyId}";alg="ed25519";nonce="${nonce}"`;

  const lines = components.map((component) => {
    if (component === "@method") return `"@method": ${method.toLowerCase()}`;
    if (component === "@target-uri") return `"@target-uri": ${base.toString()}`;
    return `"${component}": ${headers.get(component)}`;
  });
  lines.push(`"@signature-params": ${signatureParams}`);
  const signingBase = new TextEncoder().encode(lines.join("\n"));
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", signingContext.privateKey, signingBase));
  headers.set("signature-input", `sig1=${signatureParams}`);
  headers.set("signature", `sig1=:${toBase64(signature)}:`);

  return { ...init, method, headers };
}

beforeEach(async () => {
  fetchMock = vi.fn(async (input: string | URL | Request) => {
    const requestUrl = typeof input === "string"
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url;

    // DNS resolution used by webhook SSRF validation.
    if (requestUrl.startsWith("https://cloudflare-dns.com/dns-query")) {
      const url = new URL(requestUrl);
      const recordType = (url.searchParams.get("type") ?? "A").toUpperCase();
      const answers = recordType === "AAAA"
        ? []
        : [{ type: 1, data: "93.184.216.34" }];

      return new Response(JSON.stringify({ Status: 0, Answer: answers }), {
        status: 200,
        headers: { "Content-Type": "application/dns-json" },
      });
    }

    throw new Error(`Unexpected fetch in integration test: ${requestUrl}`);
  });
  vi.stubGlobal("fetch", fetchMock);

  db = new MockD1Database();
  signingContexts = new Map();
  signingContexts.set("alice", await buildSigningContext("alice"));
  nonceSeen = new Set();
  db.services.push({
    id: "svc_1",
    slug: "my-service",
  });
  db.serviceApiKeys.push({
    id: "key_1",
    service_id: "svc_1",
    key_hash: await sha256Hex("test-api-key"),
    revoked_at: null,
  });
  db.authorizations.push(
    {
      claim_id: "cl_1",
      namespace: "alice",
      public_key: "ed25519:pk1",
      service: "my-service",
      status: "approved",
      approved_at: "2026-01-01T00:00:00.000Z",
      created_at: "2026-01-01T00:00:00.000Z",
    },
    {
      claim_id: "cl_2",
      namespace: "bob",
      public_key: "ed25519:pk2",
      service: "my-service",
      status: "pending",
      approved_at: null,
      created_at: "2026-01-01T00:00:00.000Z",
    },
  );
  db.users.push({
    id: "user_1",
    email: "alice@example.com",
    namespace: "alice",
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-02T00:00:00.000Z",
  });
});

function req(path: string, init?: RequestInit) {
  const nonceNamespace = {
    idFromName(name: string) {
      return name;
    },
    get(name: string) {
      return {
        fetch: async (_url: string, reqInit?: RequestInit) => {
          const raw = typeof reqInit?.body === "string" ? reqInit.body : "{}";
          const parsed = JSON.parse(raw) as { nonce?: string };
          const nonce = parsed.nonce ?? "";
          const key = `${name}:${nonce}`;
          const replay = nonceSeen.has(key);
          if (!replay) nonceSeen.add(key);
          return new Response(JSON.stringify({ replay }), { status: 200 });
        },
      };
    },
  };

  const signedPromise = path === "/health" ? Promise.resolve(init ?? {}) : signRequest(path, init);
  const env = {
    ENVIRONMENT: "test",
    ALLOWED_ORIGINS: "https://dashboard.sigilum.id,http://localhost:3000",
    JWT_SECRET: "test-jwt-secret",
    WEBAUTHN_ALLOWED_ORIGINS: "http://localhost:3000",
    WEBAUTHN_RP_ID: "localhost",
    WEBHOOK_SECRET_ENCRYPTION_KEY: "test-webhook-secret",
    DB: db as unknown as D1Database,
    NONCE_STORE_DO: nonceNamespace as unknown as DurableObjectNamespace,
  };

  return signedPromise.then((signedInit) => app.request(path, signedInit, env));
}

function testEnv(overrides: Record<string, unknown> = {}) {
  const nonceNamespace = {
    idFromName(name: string) {
      return name;
    },
    get(name: string) {
      return {
        fetch: async (_url: string, reqInit?: RequestInit) => {
          const raw = typeof reqInit?.body === "string" ? reqInit.body : "{}";
          const parsed = JSON.parse(raw) as { nonce?: string };
          const nonce = parsed.nonce ?? "";
          const key = `${name}:${nonce}`;
          const replay = nonceSeen.has(key);
          if (!replay) nonceSeen.add(key);
          return new Response(JSON.stringify({ replay }), { status: 200 });
        },
      };
    },
  };

  return {
    ENVIRONMENT: "test",
    ALLOWED_ORIGINS: "https://dashboard.sigilum.id,http://localhost:3000",
    JWT_SECRET: "test-jwt-secret",
    WEBAUTHN_ALLOWED_ORIGINS: "http://localhost:3000",
    WEBAUTHN_RP_ID: "localhost",
    WEBHOOK_SECRET_ENCRYPTION_KEY: "test-webhook-secret",
    DB: db as unknown as D1Database,
    NONCE_STORE_DO: nonceNamespace as unknown as DurableObjectNamespace,
    ...overrides,
  };
}

describe("Health and basic routing", () => {
  it("GET /health returns health status", async () => {
    const res = await req("/health");
    expect(res.status).toBe(200);
    const data = (await res.json()) as Record<string, unknown>;
    expect(data.status).toBe("ok");
    expect(typeof data.timestamp).toBe("string");
  });

  it("unknown route returns 404", async () => {
    const res = await req("/v1/nope");
    expect(res.status).toBe(404);
    const data = (await res.json()) as Record<string, unknown>;
    expect(data.error).toBe("Not found");
  });
});

describe("Claims endpoint auth", () => {
  it("requires auth for GET /v1/claims/:claimId", async () => {
    const res = await req("/v1/claims/cl_1");
    expect(res.status).toBe(401);
  });
});

describe("Namespaces claims cache endpoint", () => {
  it("requires service API key", async () => {
    const res = await req("/v1/namespaces/claims?service=my-service");
    expect(res.status).toBe(401);
  });

  it("returns only approved claims for authenticated service", async () => {
    const res = await req("/v1/namespaces/claims?service=my-service", {
      headers: { Authorization: "Bearer test-api-key" },
    });
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      claims: Array<{ claim_id: string; status?: string }>;
    };
    expect(data.claims.length).toBe(1);
    expect(data.claims[0]?.claim_id).toBe("cl_1");
  });

  it("rejects service mismatch between API key and query", async () => {
    const res = await req("/v1/namespaces/claims?service=other-service", {
      headers: { Authorization: "Bearer test-api-key" },
    });
    expect(res.status).toBe(403);
  });
});

describe("Namespaces upstream behavior", () => {
  it("requires namespace-owner auth for namespace claims listing", async () => {
    const res = await req("/v1/namespaces/alice/claims");
    expect(res.status).toBe(401);
  });

  it("forbids namespace claims listing for other namespaces", async () => {
    const cookie = await createSessionCookie({ JWT_SECRET: "test-jwt-secret" }, {
      userId: "user_1",
      email: "alice@example.com",
      namespace: "alice",
    });
    const res = await req("/v1/namespaces/bob/claims", {
      headers: { Cookie: cookie },
    });
    expect(res.status).toBe(403);
  });

  it("allows namespace-owner claims listing", async () => {
    const cookie = await createSessionCookie({ JWT_SECRET: "test-jwt-secret" });
    const res = await req("/v1/namespaces/alice/claims", {
      headers: { Cookie: cookie },
    });
    expect(res.status).toBe(200);
    const data = (await res.json()) as { claims: Array<{ claim_id: string }> };
    expect(data.claims.some((claim) => claim.claim_id === "cl_1")).toBe(true);
  });

  it("resolves namespace from D1", async () => {
    const res = await req("/v1/namespaces/alice");
    expect(res.status).toBe(200);
    const data = (await res.json()) as Record<string, unknown>;
    expect(data).toMatchObject({
      did: "did:sigilum:alice",
      namespace: "alice",
      active: true,
      active_claims: 1,
    });
  });
});

describe("Verify endpoint behavior", () => {
  it("verifies from authorizations table", async () => {
    const res = await req("/v1/verify?namespace=alice&public_key=ed25519:pk1&service=my-service");
    expect(res.status).toBe(200);
    const data = (await res.json()) as Record<string, unknown>;
    expect(data.authorized).toBe(true);
    expect(data.claim_id).toBe("cl_1");
  });
});

describe("DID resolution", () => {
  it("returns DID document from D1", async () => {
    const res = await req("/.well-known/did/did:sigilum:alice");
    expect(res.status).toBe(200);
    const data = (await res.json()) as Record<string, unknown>;
    expect(data.id).toBe("did:sigilum:alice");
    expect(data.controller).toBe("did:sigilum:alice");
    expect(Array.isArray(data.verificationMethod)).toBe(true);
  });
});

describe("Removed redundant webhook surface", () => {
  it("returns 404 for removed /v1/webhooks endpoints", async () => {
    const res = await req("/v1/webhooks", {
      headers: { Authorization: "Bearer test-api-key" },
    });
    expect(res.status).toBe(404);
  });
});

describe("Service bootstrap webhook validation", () => {
  it("rejects non-public webhook targets during service creation", async () => {
    const cookie = await createSessionCookie({ JWT_SECRET: "test-jwt-secret" });
    const res = await req("/v1/services", {
      method: "POST",
      headers: {
        Cookie: cookie,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: "Payments",
        slug: "payments-service",
        domain: "payments.example.com",
        description: "Payment service",
        webhook: {
          url: "http://10.0.0.10/webhook",
          secret: "0123456789abcdef",
        },
      }),
    });
    expect(res.status).toBe(400);
    const data = (await res.json()) as { code?: string };
    expect(data.code).toBe("INVALID_WEBHOOK_URL");
  });
});

describe("Auth payload hardening", () => {
  it("returns add-passkey options for authenticated users", async () => {
    const cookie = await createSessionCookie({ JWT_SECRET: "test-jwt-secret" });
    const res = await req("/v1/auth/passkeys/options", {
      headers: { Cookie: cookie },
    });
    expect(res.status).toBe(200);
    const data = (await res.json()) as { challenge?: string };
    expect(typeof data.challenge).toBe("string");
    expect(data.challenge?.length).toBeGreaterThan(0);
  });

  it("rejects invalid namespace format in signup options", async () => {
    const res = await req("/v1/auth/signup/options?email=test@example.com&namespace=alice_");
    expect(res.status).toBe(400);
    const data = (await res.json()) as { code?: string };
    expect(data.code).toBe("VALIDATION_ERROR");
  });

  it("rejects uppercase namespace in signup options", async () => {
    const res = await req("/v1/auth/signup/options?email=test@example.com&namespace=Alice");
    expect(res.status).toBe(400);
    const data = (await res.json()) as { code?: string };
    expect(data.code).toBe("VALIDATION_ERROR");
  });

  it("returns controlled 400 for malformed signup clientDataJSON", async () => {
    const res = await req("/v1/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "new-user@example.com",
        namespace: "new-user",
        credential: {
          id: "cred_1",
          rawId: "cred_1",
          type: "public-key",
          response: {
            attestationObject: "AA==",
            clientDataJSON: "!!!not-base64url!!!",
          },
        },
      }),
    });
    expect(res.status).toBe(400);
    const data = (await res.json()) as { code?: string };
    expect(data.code).toBe("INVALID_CREDENTIAL");
  });
});

describe("Test seed endpoint hardening", () => {
  const endpoint = "/v1/test/seed";
  const payload = JSON.stringify({ upserts: [], deletes: [] });

  it("returns 404 when endpoint is disabled", async () => {
    const res = await app.request(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-sigilum-test-seed-token": "seed_token",
      },
      body: payload,
    }, testEnv());
    expect(res.status).toBe(404);
  });

  it("returns 404 outside local/test environments even if enabled", async () => {
    const res = await app.request(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-sigilum-test-seed-token": "seed_token",
      },
      body: payload,
    }, testEnv({
      ENVIRONMENT: "development",
      ENABLE_TEST_SEED_ENDPOINT: "true",
      SIGILUM_TEST_SEED_TOKEN: "seed_token",
    }));
    expect(res.status).toBe(404);
  });

  it("returns 401 when enabled but token is invalid", async () => {
    const res = await app.request(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-sigilum-test-seed-token": "wrong",
      },
      body: payload,
    }, testEnv({
      ENABLE_TEST_SEED_ENDPOINT: "true",
      SIGILUM_TEST_SEED_TOKEN: "seed_token",
    }));
    expect(res.status).toBe(401);
  });

  it("returns 404 on non-loopback host even when enabled and token is valid", async () => {
    const res = await app.request("https://example.com/v1/test/seed", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-sigilum-test-seed-token": "seed_token",
      },
      body: payload,
    }, testEnv({
      ENVIRONMENT: "local",
      ENABLE_TEST_SEED_ENDPOINT: "true",
      SIGILUM_TEST_SEED_TOKEN: "seed_token",
    }));
    expect(res.status).toBe(404);
  });

  it("allows seeded writes only with endpoint enabled and valid token", async () => {
    const res = await app.request(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-sigilum-test-seed-token": "seed_token",
      },
      body: payload,
    }, testEnv({
      ENVIRONMENT: "local",
      ENABLE_TEST_SEED_ENDPOINT: "true",
      SIGILUM_TEST_SEED_TOKEN: "seed_token",
    }));
    expect(res.status).toBe(200);
    const data = (await res.json()) as { ok: boolean; upserts: number; deletes: number };
    expect(data.ok).toBe(true);
    expect(data.upserts).toBe(0);
    expect(data.deletes).toBe(0);
  });
});
