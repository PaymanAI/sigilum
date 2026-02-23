#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function usage() {
  process.stdout.write(
    [
      "Usage:",
      "  node openclaw/lib/bootstrap-openclaw-agent-keys.mjs --config <openclaw.json> [--key-root <path>] [--agent-id <id>]",
      "",
      "Options:",
      "  --config <path>    Path to openclaw.json",
      "  --key-root <path>  Override key root directory",
      "  --agent-id <id>    Bootstrap only this one agent id",
    ].join("\n"),
  );
}

function asObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value;
}

function asString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function sanitizeAgentID(agentID) {
  const sanitized = asString(agentID).replace(/[^a-zA-Z0-9._-]/g, "_");
  return sanitized.length > 0 ? sanitized : "default";
}

function keyObjectFromSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) {
    throw new Error("Ed25519 seed must be 32 bytes");
  }
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function derivePublicRaw(privateKeyObj) {
  const der = crypto.createPublicKey(privateKeyObj).export({ format: "der", type: "spki" });
  const bytes = Buffer.from(der);
  if (
    bytes.length === ED25519_SPKI_PREFIX.length + 32 &&
    bytes.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    return bytes.subarray(ED25519_SPKI_PREFIX.length);
  }
  throw new Error("Unexpected Ed25519 public key format");
}

function fingerprintForPublicKey(publicKeyRaw) {
  return crypto.createHash("sha256").update(publicKeyRaw).digest("hex").slice(0, 16);
}

function readExistingKeypair(keyDir) {
  if (!fs.existsSync(keyDir)) {
    return null;
  }
  const files = fs
    .readdirSync(keyDir)
    .filter((entry) => entry.endsWith(".key"))
    .sort((left, right) => left.localeCompare(right));
  for (const file of files) {
    const fingerprint = file.replace(/\.key$/, "");
    const pubPath = path.join(keyDir, `${fingerprint}.pub`);
    if (!fs.existsSync(pubPath)) {
      continue;
    }
    const publicKeyBase64 = fs.readFileSync(pubPath, "utf8").trim();
    if (!publicKeyBase64) {
      continue;
    }
    return { fingerprint, publicKey: `ed25519:${publicKeyBase64}` };
  }
  return null;
}

function ensureAgentKeypair(agentID, keyRoot) {
  const normalizedID = sanitizeAgentID(agentID);
  const keyDir = path.join(keyRoot, normalizedID);
  fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(keyDir, 0o700);
  } catch {
    // Best-effort on non-posix filesystems.
  }

  const existing = readExistingKeypair(keyDir);
  if (existing) {
    return {
      agentID: normalizedID,
      keyDir,
      fingerprint: existing.fingerprint,
      publicKey: existing.publicKey,
      created: false,
    };
  }

  const privateKeySeed = crypto.randomBytes(32);
  const privateKeyObj = keyObjectFromSeed(privateKeySeed);
  const publicKeyRaw = derivePublicRaw(privateKeyObj);
  const fingerprint = fingerprintForPublicKey(publicKeyRaw);
  const publicKeyBase64 = publicKeyRaw.toString("base64");
  const keyPath = path.join(keyDir, `${fingerprint}.key`);
  const pubPath = path.join(keyDir, `${fingerprint}.pub`);

  fs.writeFileSync(keyPath, `${privateKeySeed.toString("base64")}\n`, { mode: 0o600 });
  fs.writeFileSync(pubPath, `${publicKeyBase64}\n`, { mode: 0o644 });
  try {
    fs.chmodSync(keyPath, 0o600);
    fs.chmodSync(pubPath, 0o644);
  } catch {
    // Best-effort on non-posix filesystems.
  }

  return {
    agentID: normalizedID,
    keyDir,
    fingerprint,
    publicKey: `ed25519:${publicKeyBase64}`,
    created: true,
  };
}

function collectAllowedSubagentIDs(source, ids) {
  const subagents = asObject(source.subagents);
  const allowAgents = subagents.allowAgents;
  if (!Array.isArray(allowAgents)) {
    return;
  }
  for (const entry of allowAgents) {
    const id = asString(entry);
    if (id) {
      ids.add(id);
    }
  }
}

function collectAgentIDs(config, overrideAgentID) {
  if (asString(overrideAgentID)) {
    return [asString(overrideAgentID)];
  }

  const ids = new Set();
  ids.add("default");
  ids.add("main");

  const agents = asObject(config.agents);
  const defaults = asObject(agents.defaults);
  const defaultsId = asString(defaults.id);
  if (defaultsId) {
    ids.add(defaultsId);
  }
  collectAllowedSubagentIDs(defaults, ids);

  const list = agents.list;
  if (Array.isArray(list)) {
    for (const item of list) {
      const agent = asObject(item);
      const id = asString(agent.id);
      if (id) {
        ids.add(id);
      }
      collectAllowedSubagentIDs(agent, ids);
    }
  }

  return [...ids];
}

function resolveKeyRoot(configPath, config, overrideKeyRoot) {
  if (asString(overrideKeyRoot)) {
    return asString(overrideKeyRoot);
  }
  const pluginKeyRoot = asString(
    asObject(asObject(asObject(config.hooks).internal).entries)["sigilum-plugin"]?.env?.SIGILUM_KEY_ROOT,
  );
  if (pluginKeyRoot) {
    return pluginKeyRoot;
  }
  const openclawHome = path.dirname(configPath);
  return path.join(openclawHome || path.join(os.homedir(), ".openclaw"), ".sigilum", "keys");
}

function main() {
  let configPath = "";
  let keyRoot = "";
  let agentIDOverride = "";

  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--config") {
      configPath = args[i + 1] || "";
      i += 1;
      continue;
    }
    if (arg === "--key-root") {
      keyRoot = args[i + 1] || "";
      i += 1;
      continue;
    }
    if (arg === "--agent-id") {
      agentIDOverride = args[i + 1] || "";
      i += 1;
      continue;
    }
    if (arg === "-h" || arg === "--help") {
      usage();
      process.exit(0);
    }
    process.stderr.write(`Unknown option: ${arg}\n`);
    usage();
    process.exit(1);
  }

  configPath = asString(configPath);
  if (!configPath) {
    process.stderr.write("--config is required\n");
    usage();
    process.exit(1);
  }
  if (!fs.existsSync(configPath)) {
    process.stderr.write(`Config file not found: ${configPath}\n`);
    process.exit(1);
  }

  let parsed = {};
  try {
    parsed = JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch (error) {
    process.stderr.write(`Failed to parse ${configPath}: ${String(error)}\n`);
    process.exit(1);
  }

  const cfg = asObject(parsed);
  const resolvedKeyRoot = resolveKeyRoot(configPath, cfg, keyRoot);
  const agentIDs = collectAgentIDs(cfg, agentIDOverride);
  const results = [];

  for (const id of agentIDs) {
    results.push(ensureAgentKeypair(id, resolvedKeyRoot));
  }

  const created = results.filter((entry) => entry.created).map((entry) => entry.agentID);
  const existing = results.filter((entry) => !entry.created).map((entry) => entry.agentID);
  const payload = {
    key_root: resolvedKeyRoot,
    created,
    existing,
    total: results.length,
  };
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

main();
