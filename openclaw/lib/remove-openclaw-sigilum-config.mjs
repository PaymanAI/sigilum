#!/usr/bin/env node
import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const configPath = process.argv[2];

if (!configPath) {
  console.error("Usage: remove-openclaw-sigilum-config.mjs <openclaw-config-path>");
  process.exit(1);
}

if (!fs.existsSync(configPath)) {
  process.exit(0);
}

const asObject = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value;
};

const parseConfig = (raw, filePath) => {
  const trimmed = String(raw || "").trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed);
  } catch (jsonErr) {
    try {
      const json5 = require("json5");
      return json5.parse(trimmed);
    } catch (json5Err) {
      const hint =
        json5Err && json5Err.code === "MODULE_NOT_FOUND"
          ? "Install json5 support or use strict JSON."
          : "Ensure the file is valid JSON/JSON5.";
      throw new Error(`Failed to parse ${filePath}: ${String(jsonErr)}. ${hint}`);
    }
  }
};

const isEmptyObject = (value) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0;

const pruneEmpty = (obj) => {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return;
  }
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      pruneEmpty(value);
      if (isEmptyObject(value)) {
        delete obj[key];
      }
    }
  }
};

const parsed = parseConfig(fs.readFileSync(configPath, "utf8"), configPath);
const config = asObject(parsed);

config.hooks = asObject(config.hooks);
config.hooks.internal = asObject(config.hooks.internal);
config.hooks.internal.entries = asObject(config.hooks.internal.entries);
delete config.hooks.internal.entries["sigilum-plugin"];
delete config.hooks.internal.entries["sigilum-authz-notify"];

config.skills = asObject(config.skills);
config.skills.entries = asObject(config.skills.entries);
delete config.skills.entries.sigilum;

config.env = asObject(config.env);
config.env.vars = asObject(config.env.vars);
delete config.env.vars.SIGILUM_GATEWAY_URL;
delete config.env.vars.SIGILUM_AGENT_ID;
delete config.env.vars.SIGILUM_RUNTIME_ROOT;
delete config.env.vars.SIGILUM_RUNTIME_BIN;
delete config.env.vars.SIGILUM_GATEWAY_HELPER_BIN;
delete config.env.vars.SIGILUM_HOME;

pruneEmpty(config);

fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
try {
  fs.chmodSync(configPath, 0o600);
} catch {
  // Best effort on non-posix filesystems.
}
