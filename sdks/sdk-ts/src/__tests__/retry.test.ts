import { describe, expect, it } from "vitest";
import { retryWithBackoff, shouldRetryHttpStatus } from "../retry.js";

describe("retryWithBackoff", () => {
  it("retries retryable errors for idempotent operations", async () => {
    let attempts = 0;
    const result = await retryWithBackoff(
      async () => {
        attempts += 1;
        if (attempts < 3) {
          throw new Error("temporary failure");
        }
        return "ok";
      },
      {
        idempotent: true,
        attempts: 3,
        sleep: async () => {},
        shouldRetryError: () => true,
      },
    );

    expect(result).toBe("ok");
    expect(attempts).toBe(3);
  });

  it("requires idempotent=true when attempts > 1", async () => {
    await expect(
      retryWithBackoff(
        async () => "ok",
        {
          idempotent: false,
          attempts: 2,
        },
      ),
    ).rejects.toThrow(/idempotent/i);
  });

  it("retries retryable HTTP status results", async () => {
    let attempts = 0;
    const result = await retryWithBackoff(
      async () => {
        attempts += 1;
        return { status: attempts < 2 ? 503 : 200 };
      },
      {
        idempotent: true,
        attempts: 3,
        sleep: async () => {},
        shouldRetryResult: (response) => shouldRetryHttpStatus(response.status),
      },
    );

    expect(result.status).toBe(200);
    expect(attempts).toBe(2);
  });
});

describe("shouldRetryHttpStatus", () => {
  it("matches retryable status codes", () => {
    expect(shouldRetryHttpStatus(429)).toBe(true);
    expect(shouldRetryHttpStatus(502)).toBe(true);
    expect(shouldRetryHttpStatus(503)).toBe(true);
    expect(shouldRetryHttpStatus(504)).toBe(true);
    expect(shouldRetryHttpStatus(400)).toBe(false);
  });
});
