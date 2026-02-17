import { getNamespaceApiBase, loadIdentity } from "./identity-store.js";
import { signHttpRequest } from "./http-signatures.js";
import type {
  CertifiedAgent,
  CertifyOptions,
  SigilumAgentBindings,
  SignRequestInput,
  SignedRequest,
} from "./types.js";

export const SIGILUM_CONTEXT_SYMBOL = Symbol.for("sigilum.context");

function resolveApiBaseUrl(explicitApiBaseUrl?: string): string {
  return explicitApiBaseUrl ?? process.env.SIGILUM_API_URL ?? "https://api.sigilum.id";
}

function resolveUrl(input: string | URL, apiBaseUrl: string): URL {
  if (input instanceof URL) {
    return new URL(input.toString());
  }

  if (/^https?:\/\//i.test(input)) {
    return new URL(input);
  }

  const base = `${apiBaseUrl.replace(/\/+$/, "")}/`;
  const path = input.startsWith("/") ? input.slice(1) : input;
  return new URL(path, base);
}

function isRequest(input: unknown): input is Request {
  return typeof Request !== "undefined" && input instanceof Request;
}

function toSignRequestInput(
  input: string | URL | Request,
  init: RequestInit | undefined,
  apiBaseUrl: string,
): SignRequestInput {
  if (isRequest(input)) {
    if (input.body !== null) {
      throw new Error(
        "Request objects with streaming bodies are not supported by Sigilum signing. Pass url + init.body as string/bytes.",
      );
    }

    const headers = new Headers(input.headers);
    if (init?.headers) {
      const override = new Headers(init.headers);
      override.forEach((value, key) => {
        headers.set(key, value);
      });
    }

    return {
      url: resolveUrl(input.url, apiBaseUrl),
      method: init?.method ?? input.method,
      headers,
      body: (init?.body ?? null) as SignRequestInput["body"],
    };
  }

  return {
    url: resolveUrl(input, apiBaseUrl),
    method: init?.method,
    headers: init?.headers,
    body: (init?.body ?? null) as SignRequestInput["body"],
  };
}

function toRequestInit(signed: SignedRequest, init?: RequestInit): RequestInit {
  return {
    ...init,
    method: signed.method,
    headers: signed.headers,
    body: signed.body ?? undefined,
  };
}

function buildBindings(options: CertifyOptions): SigilumAgentBindings {
  const identity = loadIdentity({
    namespace: options.namespace,
    homeDir: options.homeDir,
  });

  const apiBaseUrl = resolveApiBaseUrl(options.apiBaseUrl);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;

  if (!fetchImpl) {
    throw new Error(
      "Fetch API is not available. Provide fetchImpl in certify() options.",
    );
  }

  return {
    namespace: identity.namespace,
    did: identity.did,
    keyId: identity.keyId,
    publicKey: identity.publicKey,
    certificate: identity.certificate,
    apiBaseUrl,
    sign(request: SignRequestInput): SignedRequest {
      return signHttpRequest(identity, {
        ...request,
        url: resolveUrl(request.url, apiBaseUrl),
      });
    },
    async fetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
      const signable = toSignRequestInput(input, init, apiBaseUrl);
      const signed = signHttpRequest(identity, signable);
      return fetchImpl(signed.url, toRequestInit(signed, init));
    },
    async request(path: string, init?: RequestInit): Promise<Response> {
      const namespaceBase = getNamespaceApiBase(apiBaseUrl, identity.namespace);
      const url = resolveUrl(path, namespaceBase);
      const signable = toSignRequestInput(url, init, namespaceBase);
      const signed = signHttpRequest(identity, signable);
      return fetchImpl(signed.url, toRequestInit(signed, init));
    },
  };
}

export function certify<T extends object>(
  agent: T,
  options: CertifyOptions = {},
): CertifiedAgent<T> {
  if (!agent || typeof agent !== "object") {
    throw new Error("certify(agent): agent must be an object");
  }

  const existing = (agent as Record<PropertyKey, unknown>)[
    SIGILUM_CONTEXT_SYMBOL
  ] as SigilumAgentBindings | undefined;

  if (existing) {
    return agent as CertifiedAgent<T>;
  }

  const bindings = buildBindings(options);

  Object.defineProperty(agent, SIGILUM_CONTEXT_SYMBOL, {
    value: bindings,
    writable: false,
    enumerable: false,
    configurable: true,
  });

  Object.defineProperty(agent, "sigilum", {
    value: bindings,
    writable: false,
    enumerable: false,
    configurable: true,
  });

  return agent as CertifiedAgent<T>;
}

export function getSigilum(agent: object): SigilumAgentBindings {
  const value = (agent as Record<PropertyKey, unknown>)[
    SIGILUM_CONTEXT_SYMBOL
  ] as SigilumAgentBindings | undefined;

  if (!value) {
    throw new Error("Agent is not certified. Call sigilum.certify(agent) first.");
  }

  return value;
}
