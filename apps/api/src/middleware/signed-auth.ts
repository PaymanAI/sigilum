import type { Context, Next } from "hono";
import type { Env } from "../types.js";
import { createErrorResponse } from "../utils/validation.js";
import { getConfig } from "../utils/config.js";
import { getAdapters } from "../adapters/index.js";
import { verifySignedHttpRequest } from "../utils/http-signatures.js";

type BindingExpectations = {
  expectedNamespace?: string;
  expectedPublicKey?: string;
};

function maybeParseDidNamespace(pathname: string): string | undefined {
  if (!pathname.startsWith("/.well-known/did/")) return undefined;
  const did = decodeURIComponent(pathname.slice("/.well-known/did/".length));
  if (!did.startsWith("did:sigilum:")) return undefined;
  return did.slice("did:sigilum:".length);
}

function extractNamespaceFromPath(pathname: string): string | undefined {
  if (!pathname.startsWith("/v1/namespaces/")) return undefined;
  const rest = pathname.slice("/v1/namespaces/".length);
  const first = rest.split("/")[0];
  if (!first) return undefined;
  if (first === "claims") return undefined;
  return decodeURIComponent(first);
}

function extractExpectations(
  url: URL,
  method: string,
  body: Record<string, unknown> | null,
): BindingExpectations {
  const pathname = url.pathname;

  if (pathname === "/v1/verify") {
    const expectedNamespace = url.searchParams.get("namespace") ?? undefined;
    return { expectedNamespace };
  }

  if (pathname === "/v1/claims" && method === "POST") {
    const expectedNamespace = typeof body?.namespace === "string" ? body.namespace : undefined;
    const expectedPublicKey = typeof body?.public_key === "string" ? body.public_key : undefined;
    return { expectedNamespace, expectedPublicKey };
  }

  const namespaceFromPath = extractNamespaceFromPath(pathname);
  if (namespaceFromPath) {
    return { expectedNamespace: namespaceFromPath };
  }

  const didNamespace = maybeParseDidNamespace(pathname);
  if (didNamespace) {
    return { expectedNamespace: didNamespace };
  }

  return {};
}

async function parseJsonBody(rawBody: string): Promise<Record<string, unknown> | null> {
  if (!rawBody) return null;
  try {
    const parsed = JSON.parse(rawBody) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

export async function requireSignedHeaders(c: Context<{ Bindings: Env }>, next: Next) {
  const request = c.req.raw;
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  const rawBody =
    method === "GET" || method === "HEAD" ? "" : await request.clone().text().catch(() => "");
  const parsedBody = await parseJsonBody(rawBody);
  const expectations = extractExpectations(url, method, parsedBody);

  const config = getConfig(c.env);
  const signatureResult = await verifySignedHttpRequest({
    request,
    bodyBytes: rawBody ? new TextEncoder().encode(rawBody) : null,
    expectedNamespace: expectations.expectedNamespace,
    expectedPublicKey: expectations.expectedPublicKey,
    maxAgeSeconds: config.signatureMaxAgeSeconds,
  });

  if (!signatureResult.valid) {
    return c.json(signatureResult.error, signatureResult.status as any);
  }

  // Global signature nonce replay protection.
  try {
    const replay = await getAdapters(c.env).nonceStore.check({
      service: `sig:${signatureResult.namespace}`,
      nonce: `sig:${signatureResult.nonce}`,
      ttlSeconds: config.signatureNonceTtlSeconds,
    });
    if (replay.replay) {
      return c.json(
        createErrorResponse("Replay detected: signature nonce has already been used", "SIGNATURE_NONCE_REPLAY"),
        409,
      );
    }
  } catch (error) {
    console.error("Signature nonce validation failed:", error);
    return c.json(
      createErrorResponse("Signature nonce store unavailable", "NONCE_STORE_UNAVAILABLE"),
      503,
    );
  }

  await next();
}
