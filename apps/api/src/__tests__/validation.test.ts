import { afterEach, describe, expect, it, vi } from "vitest";
import { isValidWebhookUrl } from "../utils/validation.js";

type RecordSet = {
  A?: string[];
  AAAA?: string[];
};

function stubDns(records: Record<string, RecordSet>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL | Request) => {
      const requestUrl = typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
      const url = new URL(requestUrl);
      const hostname = (url.searchParams.get("name") ?? "").toLowerCase();
      const recordType = (url.searchParams.get("type") ?? "A").toUpperCase();
      const entry = records[hostname];

      const answers = (entry?.[recordType as "A" | "AAAA"] ?? []).map((ip) => ({
        type: recordType === "AAAA" ? 28 : 1,
        data: ip,
      }));

      const status = answers.length > 0 ? 0 : 3;
      return new Response(JSON.stringify({ Status: status, Answer: answers }), {
        status: 200,
        headers: { "Content-Type": "application/dns-json" },
      });
    }),
  );
}

describe("isValidWebhookUrl", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("rejects direct private IPv4 addresses", async () => {
    const result = await isValidWebhookUrl("http://10.0.0.10/webhook");
    expect(result.valid).toBe(false);
    expect(result.error).toContain("non-public IPv4");
  });

  it("rejects hostnames that resolve to private IPv4 addresses", async () => {
    stubDns({
      "internal.example.com": { A: ["10.1.2.3"] },
    });

    const result = await isValidWebhookUrl("https://internal.example.com/webhook");
    expect(result.valid).toBe(false);
    expect(result.error).toContain("non-public IP address");
  });

  it("rejects hostnames that resolve to private IPv6 addresses", async () => {
    stubDns({
      "internal-v6.example.com": { AAAA: ["fd00::1"] },
    });

    const result = await isValidWebhookUrl("https://internal-v6.example.com/webhook");
    expect(result.valid).toBe(false);
    expect(result.error).toContain("non-public IP address");
  });

  it("allows hostnames that resolve only to public addresses", async () => {
    stubDns({
      "public.example.com": { A: ["93.184.216.34"] },
    });

    const result = await isValidWebhookUrl("https://public.example.com/webhook");
    expect(result.valid).toBe(true);
  });

  it("fails closed when DNS resolution errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("resolver unavailable");
      }),
    );

    const result = await isValidWebhookUrl("https://example.com/webhook");
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Unable to resolve hostname safely");
  });
});
