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

const firstNonEmpty = (...values) => {
  for (const value of values) {
    const normalized = asString(value);
    if (normalized) return normalized;
  }
  return "";
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

if (!configPath || !fs.existsSync(configPath)) {
  process.stdout.write("\t\t\t\n");
  process.exit(0);
}

try {
  const parsed = parseConfig(fs.readFileSync(configPath, "utf8"), configPath);
  const cfg = asObject(parsed);

  const hooks = asObject(cfg.hooks);
  const internal = asObject(hooks.internal);
  const hookEntries = asObject(internal.entries);
  const plugin = asObject(hookEntries["sigilum-plugin"]);
  const pluginEnv = asObject(plugin.env);

  const skills = asObject(cfg.skills);
  const skillEntries = asObject(skills.entries);
  const sigilumSkill = asObject(skillEntries.sigilum);
  const skillEnv = asObject(sigilumSkill.env);

  const env = asObject(cfg.env);
  const envVars = asObject(env.vars);

  const agents = asObject(cfg.agents);
  const agentDefaults = asObject(agents.defaults);
  const rootDefaults = asObject(cfg.defaults);

  const workspace = firstNonEmpty(agentDefaults.workspace, rootDefaults.workspace);
  const keyRoot = firstNonEmpty(pluginEnv.SIGILUM_KEY_ROOT, skillEnv.SIGILUM_KEY_ROOT);
  const runtimeRoot = firstNonEmpty(skillEnv.SIGILUM_RUNTIME_ROOT, envVars.SIGILUM_RUNTIME_ROOT);
  const sigilumHome = firstNonEmpty(skillEnv.SIGILUM_HOME, envVars.SIGILUM_HOME);

  process.stdout.write(`${workspace}\t${keyRoot}\t${runtimeRoot}\t${sigilumHome}\n`);
} catch {
  process.stdout.write("\t\t\t\n");
}
