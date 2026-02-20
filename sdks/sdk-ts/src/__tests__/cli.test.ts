import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { runCLI } from "../cli.js";

type CapturedOutput = {
  stdout: string[];
  stderr: string[];
  output: {
    stdout: (line: string) => void;
    stderr: (line: string) => void;
  };
};

function captureOutput(): CapturedOutput {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    stdout,
    stderr,
    output: {
      stdout: (line: string) => stdout.push(line),
      stderr: (line: string) => stderr.push(line),
    },
  };
}

describe("cli", () => {
  let homeDir = "";
  let previousSigilumHome: string | undefined;

  beforeEach(() => {
    homeDir = mkdtempSync(path.join(os.tmpdir(), "sigilum-cli-"));
    previousSigilumHome = process.env.SIGILUM_HOME;
    process.env.SIGILUM_HOME = homeDir;
  });

  afterEach(() => {
    if (previousSigilumHome === undefined) {
      delete process.env.SIGILUM_HOME;
    } else {
      process.env.SIGILUM_HOME = previousSigilumHome;
    }
    rmSync(homeDir, { recursive: true, force: true });
  });

  it("emits stable json for list", () => {
    const captured = captureOutput();

    runCLI(["list", "--json"], captured.output);

    expect(captured.stderr).toEqual([]);
    expect(captured.stdout).toHaveLength(1);
    const payload = JSON.parse(captured.stdout[0]) as {
      command: string;
      count: number;
      namespaces: string[];
    };
    expect(payload.command).toBe("list");
    expect(payload.count).toBe(0);
    expect(payload.namespaces).toEqual([]);
  });

  it("emits stable json for init", () => {
    const captured = captureOutput();

    runCLI(["init", "alice", "--json"], captured.output);

    expect(captured.stderr).toEqual([]);
    expect(captured.stdout).toHaveLength(1);
    const payload = JSON.parse(captured.stdout[0]) as {
      command: string;
      created: boolean;
      namespace: string;
      did: string;
      keyId: string;
      publicKey: string;
      identityPath: string;
    };
    expect(payload.command).toBe("init");
    expect(payload.created).toBe(true);
    expect(payload.namespace).toBe("alice");
    expect(payload.did).toMatch(/^did:sigilum:alice$/);
    expect(payload.keyId).toMatch(/#ed25519-/);
    expect(payload.publicKey.length).toBeGreaterThan(10);
    expect(payload.identityPath).toContain(path.join("identities", "alice", "identity.json"));
  });
});
