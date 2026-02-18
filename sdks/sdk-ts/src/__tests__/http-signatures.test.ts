import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { initIdentity, loadIdentity } from "../identity-store.js";
import { signHttpRequest, verifyHttpSignature } from "../http-signatures.js";

describe("RFC 9421 signing", () => {
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

  it("signs and verifies a request", () => {
    const homeDir = makeHomeDir();
    initIdentity({ namespace: "alice", homeDir });
    const identity = loadIdentity({ namespace: "alice", homeDir });

    const signed = signHttpRequest(identity, {
      url: "https://api.sigilum.local/v1/namespaces/alice/claims",
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"action":"approve"}',
    });

    const verified = verifyHttpSignature({
      url: signed.url,
      method: signed.method,
      headers: signed.headers,
      body: signed.body ?? null,
      expectedNamespace: "alice",
    });

    expect(verified.valid).toBe(true);
    expect(verified.namespace).toBe("alice");
    expect(verified.subject).toBe("alice");
  });

  it("fails verification when body is tampered", () => {
    const homeDir = makeHomeDir();
    initIdentity({ namespace: "alice", homeDir });
    const identity = loadIdentity({ namespace: "alice", homeDir });

    const signed = signHttpRequest(identity, {
      url: "https://api.sigilum.local/v1/namespaces/alice/claims",
      method: "POST",
      body: '{"action":"approve"}',
    });

    const verified = verifyHttpSignature({
      url: signed.url,
      method: signed.method,
      headers: signed.headers,
      body: '{"action":"tampered"}',
      expectedNamespace: "alice",
    });

    expect(verified.valid).toBe(false);
    expect(verified.reason).toMatch(/digest/i);
  });

  it("fails verification when namespace does not match", () => {
    const homeDir = makeHomeDir();
    initIdentity({ namespace: "alice", homeDir });
    const identity = loadIdentity({ namespace: "alice", homeDir });

    const signed = signHttpRequest(identity, {
      url: "https://api.sigilum.local/v1/namespaces/alice/claims",
      method: "GET",
    });

    const verified = verifyHttpSignature({
      url: signed.url,
      method: signed.method,
      headers: signed.headers,
      expectedNamespace: "bob",
    });

    expect(verified.valid).toBe(false);
    expect(verified.reason).toMatch(/namespace mismatch/i);
  });

  it("fails verification when subject does not match", () => {
    const homeDir = makeHomeDir();
    initIdentity({ namespace: "alice", homeDir });
    const identity = loadIdentity({ namespace: "alice", homeDir });

    const signed = signHttpRequest(identity, {
      url: "https://api.sigilum.local/v1/namespaces/alice/claims",
      method: "GET",
      subject: "user:123",
    });

    const verified = verifyHttpSignature({
      url: signed.url,
      method: signed.method,
      headers: signed.headers,
      expectedNamespace: "alice",
      expectedSubject: "user:999",
    });

    expect(verified.valid).toBe(false);
    expect(verified.reason).toMatch(/subject mismatch/i);
  });
});
