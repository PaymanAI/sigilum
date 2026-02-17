import type { Env } from "../types.js";

const PREFIX = "enc:v1";

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function deriveKeyMaterial(secret: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(secret),
  );
  return new Uint8Array(digest);
}

type AesUsage = "encrypt" | "decrypt";

async function getAesKey(env: Env, usage: AesUsage[]): Promise<CryptoKey> {
  const masterSecret = env.WEBHOOK_SECRET_ENCRYPTION_KEY;
  if (!masterSecret) {
    throw new Error("WEBHOOK_SECRET_ENCRYPTION_KEY must be configured for webhook secret encryption.");
  }
  const keyMaterial = await deriveKeyMaterial(masterSecret);
  return crypto.subtle.importKey(
    "raw",
    keyMaterial,
    { name: "AES-GCM" },
    false,
    usage,
  );
}

export async function encryptWebhookSecret(
  env: Env,
  plaintext: string,
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await getAesKey(env, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext),
  );
  return `${PREFIX}:${toBase64(iv)}:${toBase64(new Uint8Array(ciphertext))}`;
}

export async function decryptWebhookSecret(
  env: Env,
  storedValue: string,
): Promise<string> {
  if (!storedValue.startsWith(`${PREFIX}:`)) {
    return storedValue;
  }

  const parts = storedValue.split(":");
  if (parts.length !== 4) {
    throw new Error("Invalid encrypted webhook secret format.");
  }
  const version = parts[1];
  const ivEncoded = parts[2];
  const ciphertextEncoded = parts[3];
  if (!version || !ivEncoded || !ciphertextEncoded) {
    throw new Error("Invalid encrypted webhook secret format.");
  }
  if (version !== "v1") {
    throw new Error("Unsupported encrypted webhook secret version.");
  }

  const iv = fromBase64(ivEncoded);
  const ciphertext = fromBase64(ciphertextEncoded);
  const key = await getAesKey(env, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext,
  );
  return new TextDecoder().decode(plaintext);
}
