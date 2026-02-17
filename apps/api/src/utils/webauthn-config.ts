import type { Env } from "../types.js";

const DEFAULT_WEBAUTHN_ORIGIN = "http://localhost:5000";

export type ResolvedWebAuthnConfig = {
  rpID: string;
  origins: string[];
  expectedOrigin: string | string[];
};

function parseOrigins(input: string): string[] {
  const origins: string[] = [];

  for (const raw of input.split(",")) {
    const value = raw.trim();
    if (!value) continue;

    let parsed: URL;
    try {
      parsed = new URL(value);
    } catch {
      throw new Error(`Invalid WebAuthn origin URL: "${value}"`);
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
      throw new Error(`Invalid WebAuthn origin protocol in "${value}"`);
    }

    origins.push(parsed.origin);
  }

  return [...new Set(origins)];
}

function isRpIdCompatible(originHost: string, rpID: string): boolean {
  const host = originHost.toLowerCase();
  const rp = rpID.toLowerCase();
  return host === rp || host.endsWith(`.${rp}`);
}

export function resolveWebAuthnConfig(
  env: Pick<Env, "WEBAUTHN_ALLOWED_ORIGINS" | "WEBAUTHN_RP_ID" | "ALLOWED_ORIGINS">,
): ResolvedWebAuthnConfig {
  const originsInput =
    env.WEBAUTHN_ALLOWED_ORIGINS?.trim() ??
    env.ALLOWED_ORIGINS?.trim() ??
    DEFAULT_WEBAUTHN_ORIGIN;

  const origins = parseOrigins(originsInput);
  if (origins.length === 0) {
    throw new Error("WebAuthn origins are not configured");
  }

  const rpID = (env.WEBAUTHN_RP_ID?.trim() || new URL(origins[0]!).hostname).toLowerCase();
  if (!rpID) {
    throw new Error("WebAuthn RP ID is not configured");
  }

  for (const origin of origins) {
    const host = new URL(origin).hostname;
    if (!isRpIdCompatible(host, rpID)) {
      throw new Error(
        `WebAuthn origin "${origin}" is not compatible with rpID "${rpID}"`,
      );
    }
  }

  return {
    rpID,
    origins,
    expectedOrigin: origins.length === 1 ? origins[0]! : origins,
  };
}
