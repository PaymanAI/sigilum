import { Hono } from "hono";
import { z } from "zod";
import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { SignJWT, jwtVerify } from "jose";
import type { Env } from "../types.js";
import { createErrorResponse } from "../utils/validation.js";
import { getConfig } from "../utils/config.js";
import { enqueueRegisterNamespace } from "../utils/blockchain-queue.js";
import { checkNamespaceOnChain } from "../utils/blockchain.js";
import { resolveWebAuthnConfig } from "../utils/webauthn-config.js";

export const authRouter = new Hono<{ Bindings: Env }>();

const RP_NAME = "Sigilum";

const JWT_ISSUER = "sigilum-api";
const JWT_AUDIENCE = "sigilum-dashboard";
const JWT_COOKIE_NAME = "sigilum_token";
const NAMESPACE_PATTERN = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;

/**
 * Set JWT as httpOnly cookie.
 * Cookie settings: httpOnly, secure (in production), sameSite=lax, max-age=7d
 */
function setAuthCookie(c: { header: (name: string, value: string) => void; req: { header: (name: string) => string | undefined } }, token: string) {
  const isProduction = c.req.header("Host")?.includes("sigilum.dev") || c.req.header("Host")?.includes("sigilum.com");
  const isLocalhost = c.req.header("Host")?.includes("localhost");
  const maxAge = 7 * 24 * 60 * 60; // 7 days in seconds

  // Build cookie string
  let cookieValue = `${JWT_COOKIE_NAME}=${token}; HttpOnly; Path=/; Max-Age=${maxAge}`;

  if (isProduction) {
    // Production: use SameSite=Lax for better security
    cookieValue += "; SameSite=Lax; Secure";
  } else if (isLocalhost) {
    // Localhost development: use SameSite=None to allow cross-origin (localhost:3000 -> localhost:8787)
    // Modern browsers allow Secure on localhost even without HTTPS
    cookieValue += "; SameSite=None; Secure";
  } else {
    // Other dev environments: use SameSite=Lax
    cookieValue += "; SameSite=Lax";
  }

  c.header("Set-Cookie", cookieValue);
}

/**
 * Clear auth cookie (for logout).
 */
function clearAuthCookie(c: { header: (name: string, value: string) => void }) {
  c.header("Set-Cookie", `${JWT_COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
}

async function signJWT(env: Env, userId: string, email: string, namespace: string): Promise<string> {
  const secret = env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET environment variable is required");
  }
  const config = getConfig(env);
  const key = new TextEncoder().encode(secret);
  return new SignJWT({ email, namespace })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(userId)
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .setExpirationTime(config.jwtExpiry)
    .setIssuedAt()
    .sign(key);
}

export async function verifyJWT(env: Env, token: string): Promise<{ userId: string; email: string; namespace: string } | null> {
  try {
    const secret = env.JWT_SECRET;
    if (!secret) {
      throw new Error("JWT_SECRET environment variable is required");
    }
    const key = new TextEncoder().encode(secret);
    const { payload } = await jwtVerify(token, key, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    const userId = payload.sub;
    const email = payload.email as string;
    const namespace = payload.namespace as string;
    if (!userId || !email || !namespace) return null;
    return { userId, email, namespace };
  } catch {
    return null;
  }
}

/**
 * Extract JWT token from the httpOnly session cookie.
 */
export function getBearerToken(c: { req: { header: (name: string) => string | undefined } }): string | null {
  const cookies = c.req.header("Cookie");
  if (cookies) {
    const match = cookies.match(new RegExp(`(?:^|;)\\s*${JWT_COOKIE_NAME}=([^;]+)`));
    if (match?.[1]) {
      return match[1].trim();
    }
  }
  return null;
}

function decodeClientDataJSON(raw: string): { challenge?: string } | null {
  try {
    const normalized = raw.replace(/-/g, "+").replace(/_/g, "/");
    const padLen = (4 - (normalized.length % 4)) % 4;
    const padded = normalized + "=".repeat(padLen);
    const decoded = atob(padded);
    const bytes = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    return parsed as { challenge?: string };
  } catch {
    return null;
  }
}

/**
 * GET /v1/auth/signup/options
 * Returns registration options (challenge, etc.) for passkey creation.
 * Query: email, namespace.
 */
authRouter.get("/signup/options", async (c) => {
  const email = c.req.query("email");
  const namespace = c.req.query("namespace")?.trim();
  if (!email || !namespace || !NAMESPACE_PATTERN.test(namespace)) {
    return c.json(
      createErrorResponse(
        "Query params email and namespace are required. Namespace must match ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$",
        "VALIDATION_ERROR",
      ),
      400,
    );
  }

  // Early conflict checks so users don't hit passkey prompt for already-registered identities.
  const existingNamespace = await c.env.DB.prepare(
    "SELECT id FROM users WHERE namespace = ?",
  )
    .bind(namespace)
    .first();
  if (existingNamespace) {
    return c.json(
      createErrorResponse(
        "Namespace already registered. Choose a different namespace.",
        "NAMESPACE_ALREADY_REGISTERED",
      ),
      409,
    );
  }

  const existingEmail = await c.env.DB.prepare(
    "SELECT id FROM users WHERE email = ?",
  )
    .bind(email)
    .first();
  if (existingEmail) {
    return c.json(
      createErrorResponse(
        "Email already registered. Sign in instead.",
        "EMAIL_ALREADY_REGISTERED",
      ),
      409,
    );
  }

  let webAuthnConfig;
  try {
    webAuthnConfig = resolveWebAuthnConfig(c.env);
  } catch (err) {
    console.error("Invalid WebAuthn configuration:", err);
    return c.json(createErrorResponse("WebAuthn is not configured correctly", "SERVER_MISCONFIGURED"), 500);
  }

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: webAuthnConfig.rpID,
    userName: email,
    userID: crypto.getRandomValues(new Uint8Array(32)),
    userDisplayName: namespace,
    attestationType: "none",
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      userVerification: "preferred",
      residentKey: "preferred",
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  const challenge = options.challenge;
  await c.env.DB.prepare(
    "INSERT INTO webauthn_challenges (challenge, type, email, namespace) VALUES (?, 'registration', ?, ?)",
  )
    .bind(challenge, email, namespace)
    .run();

  return c.json(options);
});

const signupBodySchema = z.object({
  email: z.string().email(),
  namespace: z
    .string()
    .trim()
    .min(3)
    .max(64)
    .regex(NAMESPACE_PATTERN, "Namespace must match ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$"),
  passkeyName: z.string().min(1).max(100).optional(),
  credential: z.object({
    id: z.string(),
    rawId: z.string(),
    type: z.literal("public-key"),
    response: z.object({
      attestationObject: z.string(),
      clientDataJSON: z.string(),
    }),
  }),
});

/**
 * POST /v1/auth/signup
 * Verify passkey credential, create user and credential in D1, return JWT + user.
 */
authRouter.post("/signup", async (c) => {
  let body: z.infer<typeof signupBodySchema>;
  try {
    body = signupBodySchema.parse(await c.req.json());
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json(createErrorResponse("Validation failed", "VALIDATION_ERROR", err.issues), 400);
    }
    return c.json(createErrorResponse("Invalid request body", "INVALID_JSON"), 400);
  }

  let webAuthnConfig;
  try {
    webAuthnConfig = resolveWebAuthnConfig(c.env);
  } catch (err) {
    console.error("Invalid WebAuthn configuration:", err);
    return c.json(createErrorResponse("WebAuthn is not configured correctly", "SERVER_MISCONFIGURED"), 500);
  }

  const clientDataJSON = decodeClientDataJSON(body.credential.response.clientDataJSON);
  if (!clientDataJSON) {
    return c.json(createErrorResponse("Invalid credential: malformed clientDataJSON", "INVALID_CREDENTIAL"), 400);
  }
  const challengeFromClient = clientDataJSON.challenge;
  if (!challengeFromClient) {
    return c.json(createErrorResponse("Invalid credential: no challenge in clientDataJSON", "INVALID_CREDENTIAL"), 400);
  }

  const row = await c.env.DB.prepare(
    "SELECT challenge FROM webauthn_challenges WHERE challenge = ? AND type = 'registration'",
  )
    .bind(challengeFromClient)
    .first();
  if (!row) {
    return c.json(createErrorResponse("Invalid or expired challenge. Please start signup again.", "CHALLENGE_EXPIRED"), 400);
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body.credential as unknown as RegistrationResponseJSON,
      expectedChallenge: challengeFromClient,
      expectedOrigin: webAuthnConfig.expectedOrigin,
      expectedRPID: webAuthnConfig.rpID,
    });
  } catch (err) {
    console.error("Registration verification failed:", err);
    return c.json(
      createErrorResponse(err instanceof Error ? err.message : "Verification failed", "VERIFICATION_FAILED"),
      400,
    );
  }

  if (!verification.verified || !verification.registrationInfo) {
    return c.json(createErrorResponse("Verification failed", "VERIFICATION_FAILED"), 400);
  }

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  // Check for duplicate namespace first (primary onboarding error), then email.
  const existingNamespace = await c.env.DB.prepare(
    "SELECT id FROM users WHERE namespace = ?",
  )
    .bind(body.namespace)
    .first();
  if (existingNamespace) {
    return c.json(
      createErrorResponse(
        "Namespace already registered. Choose a different namespace.",
        "NAMESPACE_ALREADY_REGISTERED",
      ),
      409,
    );
  }

  const existingEmail = await c.env.DB.prepare(
    "SELECT id FROM users WHERE email = ?",
  )
    .bind(body.email)
    .first();
  if (existingEmail) {
    return c.json(
      createErrorResponse(
        "Email already registered. Sign in instead.",
        "EMAIL_ALREADY_REGISTERED",
      ),
      409,
    );
  }

  const userId = crypto.randomUUID();

  await c.env.DB.prepare("DELETE FROM webauthn_challenges WHERE challenge = ?").bind(challengeFromClient).run();

  const publicKeyBlob = new Uint8Array(credential.publicKey);
  const passkeyName = body.passkeyName || "My Passkey";

  // Use batch transaction to ensure atomicity
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO users (id, email, namespace, settings, updated_at) VALUES (?, ?, ?, NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
    ).bind(userId, body.email, body.namespace),
    c.env.DB.prepare(
      "INSERT INTO webauthn_credentials (id, user_id, public_key, counter, device_type, backed_up, transports, name) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(
      credential.id,
      userId,
      publicKeyBlob,
      credential.counter,
      credentialDeviceType ?? null,
      credentialBackedUp ? 1 : 0,
      credential.transports?.join(",") ?? null,
      passkeyName,
    ),
  ]);

  // Queue namespace registration on blockchain (async, non-blocking).
  // In local/dev setups, blockchain may be disabled or unconfigured.
  const blockchainMode = c.env.BLOCKCHAIN_MODE?.toLowerCase() ?? "";
  const isBlockchainDisabled = blockchainMode === "disabled";
  const hasRegistryAddress = Boolean(c.env.SIGILUM_REGISTRY_ADDRESS?.trim());
  const isProductionLike =
    c.env.ENVIRONMENT === "production" || c.env.ENVIRONMENT === "staging";

  if (isBlockchainDisabled) {
    console.log(
      `[Auth] Skipping namespace registration for "${body.namespace}" (BLOCKCHAIN_MODE=disabled)`,
    );
  } else if (!hasRegistryAddress) {
    const message =
      `[Auth] Skipping namespace registration for "${body.namespace}" ` +
      `(SIGILUM_REGISTRY_ADDRESS is not configured)`;
    if (isProductionLike) {
      console.error(message);
    } else {
      console.warn(message);
    }
  } else {
    // First check if namespace is already registered on-chain.
    try {
      const onChainStatus = await checkNamespaceOnChain(c.env, body.namespace);

      if (onChainStatus.exists) {
        console.log(
          `Namespace "${body.namespace}" already registered on-chain, skipping registration`,
        );
      } else {
        await enqueueRegisterNamespace(c.env, body.namespace, userId);
        console.log(
          `Namespace "${body.namespace}" registration queued for blockchain submission`,
        );
      }
    } catch (error) {
      // Log error but don't fail signup - namespace is in database.
      console.error("Failed to check/queue namespace registration:", error);
    }
  }

  const token = await signJWT(c.env, userId, body.email, body.namespace);

  // Fetch complete user profile
  const userRow = await c.env.DB.prepare("SELECT id, email, namespace, settings, registration_tx_hash, created_at, updated_at FROM users WHERE id = ?")
    .bind(userId)
    .first();

  // Fetch passkeys for this user
  const passkeys = await c.env.DB.prepare(
    "SELECT id, name, device_type, backed_up, created_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC",
  )
    .bind(userId)
    .all();

  let settings: Record<string, unknown> = {};
  try {
    if (userRow?.settings) settings = JSON.parse(userRow.settings as string);
  } catch { /* ignore bad JSON */ }

  // Set httpOnly cookie (secure, XSS-resistant)
  setAuthCookie(c, token);

  return c.json(
    {
      user: {
        id: userId,
        email: body.email,
        namespace: body.namespace,
        settings,
        registration_tx_hash: userRow?.registration_tx_hash ?? null,
        created_at: userRow?.created_at,
        updated_at: userRow?.updated_at,
        passkeys: passkeys.results.map((p) => ({
          id: p.id,
          name: p.name,
          device_type: p.device_type,
          backed_up: p.backed_up === 1,
          created_at: p.created_at,
        })),
      },
    },
    201,
  );
});

/**
 * GET /v1/auth/login/options
 * Returns authentication options (challenge) for passkey sign-in.
 */
authRouter.get("/login/options", async (c) => {
  let webAuthnConfig;
  try {
    webAuthnConfig = resolveWebAuthnConfig(c.env);
  } catch (err) {
    console.error("Invalid WebAuthn configuration:", err);
    return c.json(createErrorResponse("WebAuthn is not configured correctly", "SERVER_MISCONFIGURED"), 500);
  }

  const options = await generateAuthenticationOptions({
    rpID: webAuthnConfig.rpID,
    userVerification: "preferred",
  });

  await c.env.DB.prepare("INSERT INTO webauthn_challenges (challenge, type) VALUES (?, 'authentication')")
    .bind(options.challenge)
    .run();

  return c.json(options);
});

const loginBodySchema = z.object({
  credential: z.object({
    id: z.string(),
    rawId: z.string(),
    type: z.literal("public-key"),
    response: z.object({
      authenticatorData: z.string(),
      clientDataJSON: z.string(),
      signature: z.string(),
    }),
  }),
});

/**
 * POST /v1/auth/login
 * Verify passkey assertion, return JWT + user.
 */
authRouter.post("/login", async (c) => {
  let body: z.infer<typeof loginBodySchema>;
  try {
    body = loginBodySchema.parse(await c.req.json());
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json(createErrorResponse("Validation failed", "VALIDATION_ERROR", err.issues), 400);
    }
    return c.json(createErrorResponse("Invalid request body", "INVALID_JSON"), 400);
  }

  const credentialId = body.credential.id;
  const credRow = await c.env.DB.prepare(
    "SELECT user_id, public_key, counter FROM webauthn_credentials WHERE id = ?",
  )
    .bind(credentialId)
    .first();
  if (!credRow) {
    return c.json(createErrorResponse("Credential not found", "CREDENTIAL_NOT_FOUND"), 401);
  }

  const clientDataJSON = decodeClientDataJSON(body.credential.response.clientDataJSON);
  if (!clientDataJSON) {
    return c.json(createErrorResponse("Invalid credential: malformed clientDataJSON", "INVALID_CREDENTIAL"), 400);
  }
  const challengeFromClient = clientDataJSON.challenge;
  if (!challengeFromClient) {
    return c.json(createErrorResponse("Invalid credential", "INVALID_CREDENTIAL"), 400);
  }

  const challengeRow = await c.env.DB.prepare(
    "SELECT challenge FROM webauthn_challenges WHERE challenge = ? AND type = 'authentication'",
  )
    .bind(challengeFromClient)
    .first();
  if (!challengeRow) {
    return c.json(createErrorResponse("Invalid or expired challenge. Please try again.", "CHALLENGE_EXPIRED"), 400);
  }

  const rawKey = credRow.public_key;
  const publicKey: Uint8Array =
    rawKey instanceof ArrayBuffer
      ? new Uint8Array(rawKey)
      : rawKey instanceof Uint8Array
        ? rawKey
        : new Uint8Array(rawKey as ArrayBuffer);

  let webAuthnConfig;
  try {
    webAuthnConfig = resolveWebAuthnConfig(c.env);
  } catch (err) {
    console.error("Invalid WebAuthn configuration:", err);
    return c.json(createErrorResponse("WebAuthn is not configured correctly", "SERVER_MISCONFIGURED"), 500);
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: body.credential as unknown as AuthenticationResponseJSON,
      expectedChallenge: challengeFromClient,
      expectedOrigin: webAuthnConfig.expectedOrigin,
      expectedRPID: webAuthnConfig.rpID,
      credential: {
        id: credentialId,
        publicKey: publicKey as Uint8Array<ArrayBuffer>,
        counter: (credRow.counter as number) ?? 0,
        transports: undefined,
      },
    });
  } catch (err) {
    console.error("Authentication verification failed:", err);
    return c.json(
      createErrorResponse(err instanceof Error ? err.message : "Verification failed", "VERIFICATION_FAILED"),
      400,
    );
  }

  if (!verification.verified) {
    return c.json(createErrorResponse("Verification failed", "VERIFICATION_FAILED"), 401);
  }

  await c.env.DB.prepare("DELETE FROM webauthn_challenges WHERE challenge = ?").bind(challengeFromClient).run();
  await c.env.DB.prepare("UPDATE webauthn_credentials SET counter = ? WHERE id = ?")
    .bind(verification.authenticationInfo.newCounter, credentialId)
    .run();

  const userRow = await c.env.DB.prepare("SELECT id, email, namespace, settings, registration_tx_hash, created_at, updated_at FROM users WHERE id = ?")
    .bind(credRow.user_id)
    .first();
  if (!userRow) {
    return c.json(createErrorResponse("User not found", "USER_NOT_FOUND"), 500);
  }

  // Fetch passkeys for this user
  const passkeys = await c.env.DB.prepare(
    "SELECT id, name, device_type, backed_up, created_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC",
  )
    .bind(credRow.user_id)
    .all();

  let settings: Record<string, unknown> = {};
  try {
    if (userRow.settings) settings = JSON.parse(userRow.settings as string);
  } catch { /* ignore bad JSON */ }

  const token = await signJWT(
    c.env,
    userRow.id as string,
    userRow.email as string,
    userRow.namespace as string,
  );

  // Set httpOnly cookie (secure, XSS-resistant)
  setAuthCookie(c, token);

  return c.json({
    user: {
      id: userRow.id,
      email: userRow.email,
      namespace: userRow.namespace,
      settings,
      registration_tx_hash: userRow.registration_tx_hash ?? null,
      created_at: userRow.created_at,
      updated_at: userRow.updated_at,
      passkeys: passkeys.results.map((p) => ({
        id: p.id,
        name: p.name,
        device_type: p.device_type,
        backed_up: p.backed_up === 1,
        created_at: p.created_at,
      })),
    },
  });
});

/**
 * GET /v1/auth/me
 * Return current user from the auth cookie JWT.
 */
authRouter.get("/me", async (c) => {
  const token = getBearerToken(c);
  if (!token) {
    return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);
  }

  const payload = await verifyJWT(c.env, token);
  if (!payload) {
    return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);
  }

  const row = await c.env.DB.prepare("SELECT id, email, namespace, settings, registration_tx_hash, created_at, updated_at FROM users WHERE id = ?")
    .bind(payload.userId)
    .first();
  if (!row) {
    return c.json(createErrorResponse("User not found", "USER_NOT_FOUND"), 401);
  }

  const passkeys = await c.env.DB.prepare(
    "SELECT id, name, device_type, backed_up, created_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC",
  )
    .bind(payload.userId)
    .all();

  let settings: Record<string, unknown> = {};
  try {
    if (row.settings) settings = JSON.parse(row.settings as string);
  } catch { /* ignore bad JSON */ }

  return c.json({
    id: row.id,
    email: row.email,
    namespace: row.namespace,
    settings,
    registration_tx_hash: row.registration_tx_hash ?? null,
    created_at: row.created_at,
    updated_at: row.updated_at,
    passkeys: passkeys.results.map((p) => ({
      id: p.id,
      name: p.name,
      device_type: p.device_type,
      backed_up: p.backed_up === 1,
      created_at: p.created_at,
    })),
  });
});

/**
 * GET /v1/auth/passkeys/options
 * Returns registration options for adding an additional passkey to the current account.
 */
authRouter.get("/passkeys/options", async (c) => {
  const token = getBearerToken(c);
  if (!token) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);
  const payload = await verifyJWT(c.env, token);
  if (!payload) return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);

  let webAuthnConfig;
  try {
    webAuthnConfig = resolveWebAuthnConfig(c.env);
  } catch (err) {
    console.error("Invalid WebAuthn configuration:", err);
    return c.json(createErrorResponse("WebAuthn is not configured correctly", "SERVER_MISCONFIGURED"), 500);
  }

  const existingCredentials = await c.env.DB.prepare(
    "SELECT id FROM webauthn_credentials WHERE user_id = ?",
  )
    .bind(payload.userId)
    .all<{ id: string }>();

  const excludeCredentials = existingCredentials.results
    .map((cred) => {
      if (!cred.id) return null;
      return { id: cred.id, type: "public-key" as const };
    })
    .filter((cred): cred is { id: string; type: "public-key" } => cred !== null);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: webAuthnConfig.rpID,
    userName: payload.email,
    userID: crypto.getRandomValues(new Uint8Array(32)),
    userDisplayName: payload.namespace,
    attestationType: "none",
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      userVerification: "preferred",
      residentKey: "preferred",
    },
    supportedAlgorithmIDs: [-7, -257],
    excludeCredentials,
  });

  await c.env.DB.prepare(
    "INSERT INTO webauthn_challenges (challenge, type, email, namespace) VALUES (?, 'registration', ?, ?)",
  )
    .bind(options.challenge, payload.email, payload.namespace)
    .run();

  return c.json(options);
});

/**
 * POST /v1/auth/passkeys
 * Add a new passkey to the current user's account.
 */
authRouter.post("/passkeys", async (c) => {
  const token = getBearerToken(c);
  if (!token) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);
  const payload = await verifyJWT(c.env, token);
  if (!payload) return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);

  let body: { name?: string; credential: unknown };
  try {
    body = await c.req.json<{ name?: string; credential: unknown }>();
  } catch {
    return c.json(createErrorResponse("Invalid request body", "INVALID_JSON"), 400);
  }
  const passkeyName = body.name?.trim() || "My Passkey";
  const credential = body.credential as RegistrationResponseJSON;

  if (!credential?.id || !credential?.response) {
    return c.json(createErrorResponse("Invalid credential", "INVALID_CREDENTIAL"), 400);
  }

  let webAuthnConfig;
  try {
    webAuthnConfig = resolveWebAuthnConfig(c.env);
  } catch (err) {
    console.error("Invalid WebAuthn configuration:", err);
    return c.json(createErrorResponse("WebAuthn is not configured correctly", "SERVER_MISCONFIGURED"), 500);
  }

  const clientDataJSON = decodeClientDataJSON(credential.response.clientDataJSON);
  if (!clientDataJSON) {
    return c.json(createErrorResponse("Invalid credential: malformed clientDataJSON", "INVALID_CREDENTIAL"), 400);
  }
  const challengeFromClient = clientDataJSON.challenge;
  if (!challengeFromClient) {
    return c.json(createErrorResponse("Invalid credential: no challenge in clientDataJSON", "INVALID_CREDENTIAL"), 400);
  }

  const challengeRow = await c.env.DB.prepare(
    "SELECT challenge FROM webauthn_challenges WHERE challenge = ? AND type = 'registration'",
  )
    .bind(challengeFromClient)
    .first();
  if (!challengeRow) {
    return c.json(createErrorResponse("Invalid or expired challenge", "CHALLENGE_EXPIRED"), 400);
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: challengeFromClient,
      expectedOrigin: webAuthnConfig.expectedOrigin,
      expectedRPID: webAuthnConfig.rpID,
    });
  } catch (err) {
    console.error("Passkey verification failed:", err);
    return c.json(
      createErrorResponse(err instanceof Error ? err.message : "Verification failed", "VERIFICATION_FAILED"),
      400,
    );
  }

  if (!verification.verified || !verification.registrationInfo) {
    return c.json(createErrorResponse("Verification failed", "VERIFICATION_FAILED"), 400);
  }

  const { credential: cred, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  const publicKeyBlob = new Uint8Array(cred.publicKey);

  await c.env.DB.prepare("DELETE FROM webauthn_challenges WHERE challenge = ?").bind(challengeFromClient).run();

  await c.env.DB.prepare(
    "INSERT INTO webauthn_credentials (id, user_id, public_key, counter, device_type, backed_up, transports, name) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      cred.id,
      payload.userId,
      publicKeyBlob,
      cred.counter,
      credentialDeviceType ?? null,
      credentialBackedUp ? 1 : 0,
      cred.transports?.join(",") ?? null,
      passkeyName,
    )
    .run();

  return c.json({ success: true, id: cred.id, name: passkeyName }, 201);
});

/**
 * GET /v1/auth/passkeys
 * List all passkeys for the current user.
 */
authRouter.get("/passkeys", async (c) => {
  const token = getBearerToken(c);
  if (!token) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);
  const payload = await verifyJWT(c.env, token);
  if (!payload) return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);

  const limit = Math.min(parseInt(c.req.query("limit") ?? "50", 10), 200);
  const offset = parseInt(c.req.query("offset") ?? "0", 10);

  const passkeys = await c.env.DB.prepare(
    "SELECT id, name, device_type, backed_up, created_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC LIMIT ? OFFSET ?",
  )
    .bind(payload.userId, limit, offset)
    .all();

  const totalCount = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM webauthn_credentials WHERE user_id = ?",
  )
    .bind(payload.userId)
    .first<{ cnt: number }>();

  return c.json({
    passkeys: passkeys.results.map((p) => ({
      id: p.id,
      name: p.name,
      device_type: p.device_type,
      backed_up: p.backed_up === 1,
      created_at: p.created_at,
    })),
    pagination: {
      limit,
      offset,
      total: totalCount?.cnt ?? 0,
      has_more: offset + limit < (totalCount?.cnt ?? 0),
    },
  });
});

/**
 * PATCH /v1/auth/passkeys/:id
 * Rename a passkey.
 */
authRouter.patch("/passkeys/:id", async (c) => {
  const token = getBearerToken(c);
  if (!token) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);
  const payload = await verifyJWT(c.env, token);
  if (!payload) return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);

  const passkeyId = c.req.param("id");
  let body: { name?: string };
  try {
    body = await c.req.json<{ name?: string }>();
  } catch {
    return c.json(createErrorResponse("Invalid request body", "INVALID_JSON"), 400);
  }
  const name = body.name?.trim();
  if (!name || name.length < 1 || name.length > 100) {
    return c.json(createErrorResponse("Name must be 1-100 characters", "VALIDATION_ERROR"), 400);
  }

  const existing = await c.env.DB.prepare(
    "SELECT id FROM webauthn_credentials WHERE id = ? AND user_id = ?",
  )
    .bind(passkeyId, payload.userId)
    .first();
  if (!existing) {
    return c.json(createErrorResponse("Passkey not found", "NOT_FOUND"), 404);
  }

  await c.env.DB.prepare("UPDATE webauthn_credentials SET name = ? WHERE id = ? AND user_id = ?")
    .bind(name, passkeyId, payload.userId)
    .run();

  return c.json({ success: true, name });
});

/**
 * DELETE /v1/auth/passkeys/:id
 * Delete a passkey. Cannot delete the last remaining passkey.
 */
authRouter.delete("/passkeys/:id", async (c) => {
  const token = getBearerToken(c);
  if (!token) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);
  const payload = await verifyJWT(c.env, token);
  if (!payload) return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);

  const passkeyId = c.req.param("id");

  const existing = await c.env.DB.prepare(
    "SELECT id FROM webauthn_credentials WHERE id = ? AND user_id = ?",
  )
    .bind(passkeyId, payload.userId)
    .first();
  if (!existing) {
    return c.json(createErrorResponse("Passkey not found", "NOT_FOUND"), 404);
  }

  const countResult = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM webauthn_credentials WHERE user_id = ?",
  )
    .bind(payload.userId)
    .first<{ cnt: number }>();
  if (!countResult || countResult.cnt <= 1) {
    return c.json(createErrorResponse("Cannot delete your only passkey. Add another passkey first.", "LAST_PASSKEY"), 400);
  }

  await c.env.DB.prepare("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?")
    .bind(passkeyId, payload.userId)
    .run();

  return c.json({ success: true });
});

/**
 * PATCH /v1/auth/settings
 * Merge-update the user's settings JSON. Accepts a partial object.
 */
authRouter.patch("/settings", async (c) => {
  const token = getBearerToken(c);
  if (!token) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);
  const payload = await verifyJWT(c.env, token);
  if (!payload) return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);

  let incoming: Record<string, unknown>;
  try {
    incoming = await c.req.json<Record<string, unknown>>();
  } catch {
    return c.json(createErrorResponse("Invalid request body", "INVALID_JSON"), 400);
  }

  const row = await c.env.DB.prepare("SELECT settings FROM users WHERE id = ?")
    .bind(payload.userId)
    .first();

  let existing: Record<string, unknown> = {};
  try {
    if (row?.settings) existing = JSON.parse(row.settings as string);
  } catch { /* ignore */ }

  const merged = { ...existing, ...incoming };

  await c.env.DB.prepare("UPDATE users SET settings = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?")
    .bind(JSON.stringify(merged), payload.userId)
    .run();

  return c.json({ success: true, settings: merged });
});

/**
 * DELETE /v1/auth/account
 * Delete the current user's account and all associated data.
 * This is irreversible: removes user, credentials, services, API keys, webhooks, and authorizations.
 */
authRouter.delete("/account", async (c) => {
  const token = getBearerToken(c);
  if (!token) return c.json(createErrorResponse("Not authenticated", "UNAUTHORIZED"), 401);
  const payload = await verifyJWT(c.env, token);
  if (!payload) return c.json(createErrorResponse("Invalid or expired token", "TOKEN_EXPIRED"), 401);

  const db = c.env.DB;

  // Delete all webhooks for user's services
  await db.prepare(
    "DELETE FROM webhooks WHERE service_id IN (SELECT id FROM services WHERE owner_user_id = ?)",
  ).bind(payload.userId).run();

  // Delete all API keys for user's services
  await db.prepare(
    "DELETE FROM service_api_keys WHERE service_id IN (SELECT id FROM services WHERE owner_user_id = ?)",
  ).bind(payload.userId).run();

  // Delete all services owned by the user
  await db.prepare("DELETE FROM services WHERE owner_user_id = ?")
    .bind(payload.userId).run();

  // Delete all authorizations in the user's namespace
  await db.prepare("DELETE FROM authorizations WHERE namespace = ?")
    .bind(payload.namespace).run();

  // Delete all WebAuthn credentials
  await db.prepare("DELETE FROM webauthn_credentials WHERE user_id = ?")
    .bind(payload.userId).run();

  // Delete the user
  await db.prepare("DELETE FROM users WHERE id = ?")
    .bind(payload.userId).run();

  return c.json({ success: true, message: "Account and all associated data have been permanently deleted." });
});

/**
 * POST /v1/auth/logout
 * Clear httpOnly auth cookie and return success.
 */
authRouter.post("/logout", async (c) => {
  clearAuthCookie(c);
  return c.json({ success: true });
});
