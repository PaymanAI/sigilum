import type {
  NonceCheckRequest,
  NonceCheckResult,
  NonceStoreAdapter,
} from "../interfaces.js";

export class CloudflareNonceStoreAdapter implements NonceStoreAdapter {
  constructor(private readonly binding?: DurableObjectNamespace) {}

  async check(request: NonceCheckRequest): Promise<NonceCheckResult> {
    if (!this.binding) {
      throw new Error("NONCE_STORE_DO binding is not configured");
    }

    const objectId = this.binding.idFromName(request.service);
    const stub = this.binding.get(objectId);
    const response = await stub.fetch("https://nonce-store/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Nonce store request failed with status ${response.status}: ${body}`);
    }

    const payload = await response.json();
    return payload as NonceCheckResult;
  }
}
