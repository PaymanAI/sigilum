import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { certify } from "../certify.js";
import { initIdentity } from "../identity-store.js";
import { verifyHttpSignature } from "../http-signatures.js";

describe("certify(agent)", () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop();
      if (dir && fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }
  });

  function makeHomeDir(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sigilum-sdk-"));
    tempDirs.push(dir);
    return dir;
  }

  it("attaches sigilum identity without wrapping the agent", async () => {
    const homeDir = makeHomeDir();
    initIdentity({ namespace: "alice", homeDir });

    const calls: Array<{ input: string; init?: RequestInit }> = [];

    const fetchImpl: typeof fetch = async (
      input: Parameters<typeof fetch>[0],
      init?: RequestInit,
    ): Promise<Response> => {
      calls.push({ input: String(input), init });
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    const agent = {
      framework: "langchain",
      invoke: async (prompt: string) => ({ output: prompt }),
    };

    const certified = certify(agent, {
      namespace: "alice",
      homeDir,
      apiBaseUrl: "https://api.sigilum.local",
      fetchImpl,
    });

    expect(certified).toBe(agent);
    expect(certified.sigilum.namespace).toBe("alice");
    expect(certified.sigilum.did).toBe("did:sigilum:alice");

    await certified.sigilum.request("/claims", {
      method: "GET",
    });

    expect(calls).toHaveLength(1);

    const call = calls[0];
    expect(call).toBeDefined();
    if (!call) {
      throw new Error("Expected a recorded fetch call");
    }
    expect(call.input).toBe("https://api.sigilum.local/v1/namespaces/alice/claims");

    const verification = verifyHttpSignature({
      url: call.input,
      method: String(call.init?.method ?? "GET"),
      headers: call.init?.headers ?? {},
      body: (call.init?.body ?? null) as string,
      expectedNamespace: "alice",
    });

    expect(verification.valid).toBe(true);
    expect(verification.namespace).toBe("alice");
  });

  it("supports per-request subject override", async () => {
    const homeDir = makeHomeDir();
    initIdentity({ namespace: "alice", homeDir });

    const calls: Array<{ input: string; init?: RequestInit }> = [];
    const fetchImpl: typeof fetch = async (
      input: Parameters<typeof fetch>[0],
      init?: RequestInit,
    ): Promise<Response> => {
      calls.push({ input: String(input), init });
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    const certified = certify({}, {
      namespace: "alice",
      homeDir,
      apiBaseUrl: "https://api.sigilum.local",
      fetchImpl,
    });

    await certified.sigilum.request("/claims", {
      method: "GET",
      subject: "customer-12345",
    });

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call).toBeDefined();
    if (!call) {
      throw new Error("Expected a recorded fetch call");
    }

    const verification = verifyHttpSignature({
      url: call.input,
      method: String(call.init?.method ?? "GET"),
      headers: call.init?.headers ?? {},
      body: (call.init?.body ?? null) as string,
      expectedNamespace: "alice",
      expectedSubject: "customer-12345",
    });

    expect(verification.valid).toBe(true);
    expect(verification.subject).toBe("customer-12345");
    expect((call.init as Record<string, unknown> | undefined)?.subject).toBeUndefined();
  });

  it("is idempotent when called multiple times", () => {
    const homeDir = makeHomeDir();
    initIdentity({ namespace: "alice", homeDir });

    const agent = { role: "crewai" };
    const first = certify(agent, { namespace: "alice", homeDir });
    const second = certify(agent, { namespace: "alice", homeDir });

    expect(first).toBe(second);
    expect(first.sigilum.keyId).toBe(second.sigilum.keyId);
  });
});
