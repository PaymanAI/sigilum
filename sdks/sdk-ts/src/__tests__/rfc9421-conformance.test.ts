import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { initIdentity, loadIdentity } from "../identity-store.js";
import { signHttpRequest, verifyHttpSignature } from "../http-signatures.js";

type Vector = {
  name: string;
  method: string;
  url: string;
  body: string | null;
  expected_target_uri: string;
  expected_method_component: string;
  expected_content_digest?: string;
  expected_components: string[];
};

type NegativeVector = {
  name: string;
  source_vector: string;
  mutation: "method" | "header" | "body";
  field?: string;
  value: string;
  expected_reason_contains: string;
};

type Fixture = {
  fixed: { created: number; nonce: string };
  vectors: Vector[];
  negative_vectors?: NegativeVector[];
};

function readFixture(): Fixture {
  const fixturePath = path.resolve(
    process.cwd(),
    "../test-vectors/http-signatures-rfc9421.json",
  );
  return JSON.parse(fs.readFileSync(fixturePath, "utf8")) as Fixture;
}

describe("RFC 9421 profile conformance", () => {
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

  it("matches shared vectors and enforces strict replay/timestamp", () => {
    const fixture = readFixture();
    const homeDir = makeHomeDir();
    initIdentity({ namespace: "alice", homeDir });
    const identity = loadIdentity({ namespace: "alice", homeDir });
    const signedByName = new Map<string, ReturnType<typeof signHttpRequest>>();

    for (const vector of fixture.vectors) {
      const signed = signHttpRequest(identity, {
        url: vector.url,
        method: vector.method,
        body: vector.body,
        created: fixture.fixed.created,
        nonce: fixture.fixed.nonce,
      });

      expect(signed.url).toBe(vector.expected_target_uri);
      expect(signed.method.toLowerCase()).toBe(vector.expected_method_component);
      signedByName.set(vector.name, signed);

      const signatureInput = signed.headers.get("signature-input");
      expect(signatureInput).toBeTruthy();
      expect(signatureInput).toContain(`created=${fixture.fixed.created}`);
      expect(signatureInput).toContain(`nonce="${fixture.fixed.nonce}"`);
      const expectedComponents = vector.expected_components
        .map((c) => `"${c}"`)
        .join(" ");
      expect(signatureInput).toContain(`(${expectedComponents})`);

      if (vector.expected_content_digest) {
        expect(signed.headers.get("content-digest")).toBe(vector.expected_content_digest);
      }

      const nonceStore = new Set<string>();
      const verifyOk = verifyHttpSignature({
        url: signed.url,
        method: signed.method,
        headers: signed.headers,
        body: signed.body ?? null,
        expectedNamespace: "alice",
        strict: {
          now: fixture.fixed.created + 5,
          maxAgeSeconds: 60,
          nonceStore,
        },
      });
      expect(verifyOk.valid).toBe(true);

      const replay = verifyHttpSignature({
        url: signed.url,
        method: signed.method,
        headers: signed.headers,
        body: signed.body ?? null,
        expectedNamespace: "alice",
        strict: {
          now: fixture.fixed.created + 5,
          maxAgeSeconds: 60,
          nonceStore,
        },
      });
      expect(replay.valid).toBe(false);
      expect(replay.reason).toMatch(/replay/i);

      const stale = verifyHttpSignature({
        url: signed.url,
        method: signed.method,
        headers: signed.headers,
        body: signed.body ?? null,
        expectedNamespace: "alice",
        strict: {
          now: fixture.fixed.created + 500,
          maxAgeSeconds: 60,
        },
      });
      expect(stale.valid).toBe(false);
      expect(stale.reason).toMatch(/expired|valid/i);
    }

    for (const negative of fixture.negative_vectors ?? []) {
      const baseSigned = signedByName.get(negative.source_vector);
      expect(baseSigned, `${negative.name}: source vector not found`).toBeTruthy();
      if (!baseSigned) {
        continue;
      }

      const headers = new Headers(baseSigned.headers);
      let method = baseSigned.method;
      let body = baseSigned.body ?? null;

      if (negative.mutation === "method") {
        method = negative.value;
      } else if (negative.mutation === "header") {
        const field = (negative.field ?? "").trim().toLowerCase();
        expect(field.length, `${negative.name}: missing header field`).toBeGreaterThan(0);
        headers.set(field, negative.value);
      } else if (negative.mutation === "body") {
        body = negative.value;
      }

      const result = verifyHttpSignature({
        url: baseSigned.url,
        method,
        headers,
        body,
        expectedNamespace: "alice",
        strict: {
          now: fixture.fixed.created + 5,
          maxAgeSeconds: 60,
        },
      });
      expect(result.valid, `${negative.name}: expected verify failure`).toBe(false);
      const normalizedReason = (result.reason?.toLowerCase() ?? "")
        .replace(/[^a-z0-9]+/g, " ")
        .trim();
      const normalizedExpected = negative.expected_reason_contains
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, " ")
        .trim();
      expect(normalizedReason).toContain(normalizedExpected);
    }
  });
});
