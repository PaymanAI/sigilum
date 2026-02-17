import { beforeEach, describe, expect, it, vi } from "vitest";
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
  claims: Array<Row> = [];
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

    if (
      sql.includes("FROM claims") &&
      sql.includes("public_key = ?") &&
      sql.includes("status = 'approved'")
    ) {
      const [namespace, publicKey, service] = params as [string, string, string];
      const found = this.claims.find(
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

    if (sql.includes("COUNT(*) as cnt") && sql.includes("FROM claims") && sql.includes("namespace = ?")) {
      const [namespace] = params as [string];
      const cnt = this.claims.filter(
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

  return signedPromise.then((signedInit) => app.request(path, signedInit, {
    ENVIRONMENT: "test",
    ALLOWED_ORIGINS: "https://dashboard.sigilum.id,http://localhost:3000",
    JWT_SECRET: "test-jwt-secret",
    WEBHOOK_SECRET_ENCRYPTION_KEY: "test-webhook-secret",
    DB: db as unknown as D1Database,
    NONCE_STORE_DO: nonceNamespace as unknown as DurableObjectNamespace,
  }));
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

describe("Verify endpoint fallback behavior", () => {
  it("verifies from authorizations table", async () => {
    const res = await req("/v1/verify?namespace=alice&public_key=ed25519:pk1&service=my-service");
    expect(res.status).toBe(200);
    const data = (await res.json()) as Record<string, unknown>;
    expect(data.authorized).toBe(true);
    expect(data.claim_id).toBe("cl_1");
  });

  it("falls back to legacy claims table if authorizations table is unavailable", async () => {
    db.claims.push({
      claim_id: "legacy_cl_1",
      namespace: "legacy",
      public_key: "ed25519:legacy",
      service: "my-service",
      status: "approved",
    });

    const originalFirst = db.first.bind(db);
    db.first = async <T>(sql: string, params: unknown[]): Promise<T | null> => {
      if (sql.includes("FROM authorizations") && sql.includes("status = 'approved'")) {
        throw new Error("no such table: authorizations");
      }
      return originalFirst<T>(sql, params);
    };

    const res = await req("/v1/verify?namespace=legacy&public_key=ed25519:legacy&service=my-service");
    expect(res.status).toBe(200);
    const data = (await res.json()) as Record<string, unknown>;
    expect(data.authorized).toBe(true);
    expect(data.claim_id).toBe("legacy_cl_1");
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
  it("returns 404 for legacy /v1/webhooks endpoints", async () => {
    const res = await req("/v1/webhooks", {
      headers: { Authorization: "Bearer test-api-key" },
    });
    expect(res.status).toBe(404);
  });
});
