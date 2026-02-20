import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { initIdentity, loadIdentity, listNamespaces } from "../identity-store.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const identityFixturePath = path.resolve(testDir, "../../../test-vectors/identity-record-v1.json");

describe("identity init", () => {
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

  it("creates a local identity for a namespace", () => {
    const homeDir = makeHomeDir();

    const result = initIdentity({ namespace: "alice", homeDir });

    expect(result.created).toBe(true);
    expect(result.namespace).toBe("alice");
    expect(result.did).toBe("did:sigilum:alice");
    expect(fs.existsSync(result.identityPath)).toBe(true);
  });

  it("reuses existing identity without force", () => {
    const homeDir = makeHomeDir();

    const first = initIdentity({ namespace: "alice", homeDir });
    const second = initIdentity({ namespace: "alice", homeDir });

    expect(first.created).toBe(true);
    expect(second.created).toBe(false);
    expect(second.publicKey).toBe(first.publicKey);
  });

  it("rotates identity when force is enabled", () => {
    const homeDir = makeHomeDir();

    const first = initIdentity({ namespace: "alice", homeDir });
    const second = initIdentity({ namespace: "alice", homeDir, force: true });

    expect(second.created).toBe(true);
    expect(second.publicKey).not.toBe(first.publicKey);
  });

  it("loads identity and discovers namespaces", () => {
    const homeDir = makeHomeDir();

    initIdentity({ namespace: "alice", homeDir });
    initIdentity({ namespace: "bob", homeDir });

    const identity = loadIdentity({ namespace: "alice", homeDir });
    const namespaces = listNamespaces(homeDir);

    expect(identity.namespace).toBe("alice");
    expect(namespaces).toEqual(["alice", "bob"]);
  });

  it("loads shared identity fixture for v1 format compatibility", () => {
    const homeDir = makeHomeDir();
    const fixture = JSON.parse(fs.readFileSync(identityFixturePath, "utf8")) as {
      namespace: string;
      did: string;
      keyId: string;
    };

    const fixtureDir = path.join(homeDir, "identities", fixture.namespace);
    fs.mkdirSync(fixtureDir, { recursive: true });
    fs.writeFileSync(
      path.join(fixtureDir, "identity.json"),
      `${JSON.stringify(fixture, null, 2)}\n`,
      { mode: 0o600 },
    );

    const loaded = loadIdentity({ namespace: fixture.namespace, homeDir });
    expect(loaded.namespace).toBe(fixture.namespace);
    expect(loaded.did).toBe(fixture.did);
    expect(loaded.keyId).toBe(fixture.keyId);
  });
});
