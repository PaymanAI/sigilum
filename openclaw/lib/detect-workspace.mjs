#!/usr/bin/env node
import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const configPath = process.argv[2];

const asObject = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value;
};

const asString = (value) => (typeof value === "string" ? value.trim() : "");

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

let parsed = {};
try {
  parsed = parseConfig(fs.readFileSync(configPath, "utf8"), configPath);
} catch {
  process.exit(0);
}

const cfg = asObject(parsed);
const agents = asObject(cfg.agents);
const agentDefaults = asObject(agents.defaults);
const rootDefaults = asObject(cfg.defaults);
const workspace = asString(agentDefaults.workspace) || asString(rootDefaults.workspace);
if (workspace) process.stdout.write(workspace);
