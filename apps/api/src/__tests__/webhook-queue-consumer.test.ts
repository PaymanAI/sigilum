import { describe, expect, it, vi } from "vitest";
import { handleWebhookQueue } from "../webhook-queue-consumer.js";
import type { WebhookDeliveryMessage } from "../utils/webhook-delivery.js";

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

  async run() {
    return this.db.run(this.sql, this.params);
  }
}

class MockD1Database {
  webhook: Row | null = null;
  deactivatedWebhookIds: string[] = [];

  prepare(sql: string) {
    return new MockStatement(this, sql);
  }

  async first<T>(sql: string, params: unknown[]): Promise<T | null> {
    if (sql.includes("FROM webhooks") && sql.includes("WHERE id = ?")) {
      const [id] = params as [string];
      if (this.webhook?.id === id) return this.webhook as T;
      return null;
    }
    return null;
  }

  async run(sql: string, params: unknown[]) {
    if (sql.includes("UPDATE webhooks SET active = 0")) {
      const [id] = params as [string];
      if (this.webhook?.id === id) {
        this.webhook.active = 0;
        this.deactivatedWebhookIds.push(id);
      }
    }
    return { success: true };
  }
}

describe("Webhook queue consumer hardening", () => {
  it("blocks delivery to invalid private webhook targets and deactivates webhook", async () => {
    const db = new MockD1Database();
    db.webhook = {
      id: "wh_1",
      url: "http://10.0.0.10/webhook",
      events: JSON.stringify(["claim.approved"]),
      secret_hash: "enc_secret",
      auth_header_name: null,
      auth_header_value: null,
      active: 1,
    };

    const ack = vi.fn();
    const message = {
      body: {
        type: "webhook_delivery",
        webhookId: "wh_1",
        event: "claim.approved",
        payload: { namespace: "alice" },
        occurredAt: new Date().toISOString(),
        firstAttemptAt: new Date().toISOString(),
        attempt: 0,
      } satisfies WebhookDeliveryMessage,
      ack,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const env = {
      DB: db as unknown as D1Database,
    } as Record<string, unknown>;

    await handleWebhookQueue(
      { messages: [message] } as never,
      env as never,
    );

    expect(ack).toHaveBeenCalledTimes(1);
    expect(db.deactivatedWebhookIds).toEqual(["wh_1"]);
    expect(db.webhook?.active).toBe(0);
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });
});
