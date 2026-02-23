#!/usr/bin/env node
import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

const [
  configPath,
  mode,
  namespace,
  gatewayUrl,
  apiUrl,
  keyRoot,
  enableAuthzNotify,
  ownerToken,
  dashboardUrl,
  sigilumRuntimeRoot,
  sigilumGatewayHelperBin,
  sigilumHomeDir,
] = process.argv.slice(2);

const asObject = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value;
};

const asString = (value) => (typeof value === "string" ? value.trim() : "");
const asArray = (value) => (Array.isArray(value) ? value : []);

const mapLocalhostToDockerHost = (rawUrl) => {
  const value = asString(rawUrl);
  if (!value) return value;
  try {
    const url = new URL(value);
    if (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1") {
      url.hostname = "host.docker.internal";
      return String(url).replace(/\/+$/g, "");
    }
  } catch {
    // keep original value if it is not a valid URL
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

const parsed = parseConfig(fs.readFileSync(configPath, "utf8"), configPath);
const config = asObject(parsed);
const runtimeBin = `${String(sigilumRuntimeRoot || "").replace(/\/+$/g, "")}/sigilum`;
const gatewayHelperBin = String(sigilumGatewayHelperBin || "").trim();
const sigilumHome = String(sigilumHomeDir || "").trim();

config.agents = asObject(config.agents);
config.agents.defaults = asObject(config.agents.defaults);
config.agents.defaults.sandbox = asObject(config.agents.defaults.sandbox);
config.agents.defaults.sandbox.docker = asObject(config.agents.defaults.sandbox.docker);

const sandboxMode = asString(config.agents.defaults.sandbox.mode);
const sandboxed = sandboxMode !== "" && sandboxMode !== "off";
let skillGatewayUrl = gatewayUrl;

if (sandboxed) {
  skillGatewayUrl = mapLocalhostToDockerHost(gatewayUrl);

  const dockerCfg = asObject(config.agents.defaults.sandbox.docker);
  const network = asString(dockerCfg.network).toLowerCase();
  if (!network || network === "none") {
    dockerCfg.network = "bridge";
  }

  const extraHosts = asArray(dockerCfg.extraHosts).filter((value) => typeof value === "string" && value.trim());
  if (!extraHosts.includes("host.docker.internal:host-gateway")) {
    extraHosts.push("host.docker.internal:host-gateway");
  }
  dockerCfg.extraHosts = extraHosts;
  config.agents.defaults.sandbox.docker = dockerCfg;
}

config.env = asObject(config.env);
const existingGlobalEnv = asObject(config.env.vars);
delete existingGlobalEnv.SIGILUM_SKILL_DIR;
config.env.vars = {
  ...existingGlobalEnv,
  SIGILUM_GATEWAY_URL: skillGatewayUrl,
  SIGILUM_RUNTIME_ROOT: sigilumRuntimeRoot,
  SIGILUM_RUNTIME_BIN: runtimeBin,
  SIGILUM_GATEWAY_HELPER_BIN: gatewayHelperBin,
};
if (sigilumHome) {
  config.env.vars.SIGILUM_HOME = sigilumHome;
}

config.hooks = asObject(config.hooks);
config.hooks.internal = asObject(config.hooks.internal);
config.hooks.internal.enabled = true;
config.hooks.internal.entries = asObject(config.hooks.internal.entries);

const pluginEntry = asObject(config.hooks.internal.entries["sigilum-plugin"]);
pluginEntry.enabled = true;
pluginEntry.env = {
  ...asObject(pluginEntry.env),
  SIGILUM_MODE: mode,
  SIGILUM_NAMESPACE: namespace,
  SIGILUM_GATEWAY_URL: gatewayUrl,
  SIGILUM_API_URL: apiUrl,
  SIGILUM_DASHBOARD_URL: dashboardUrl,
  SIGILUM_KEY_ROOT: keyRoot,
  SIGILUM_AUTO_BOOTSTRAP_AGENTS: "true",
};
config.hooks.internal.entries["sigilum-plugin"] = pluginEntry;

const authzEntry = asObject(config.hooks.internal.entries["sigilum-authz-notify"]);
const authzEnabled = enableAuthzNotify === "true";
authzEntry.enabled = authzEnabled;
authzEntry.env = {
  ...asObject(authzEntry.env),
  SIGILUM_MODE: mode,
  SIGILUM_NAMESPACE: namespace,
  SIGILUM_API_URL: apiUrl,
  SIGILUM_DASHBOARD_URL: dashboardUrl,
};
if (authzEnabled && ownerToken && ownerToken.trim()) {
  authzEntry.env.SIGILUM_OWNER_TOKEN = ownerToken.trim();
} else {
  delete authzEntry.env.SIGILUM_OWNER_TOKEN;
}
config.hooks.internal.entries["sigilum-authz-notify"] = authzEntry;

config.skills = asObject(config.skills);
config.skills.entries = asObject(config.skills.entries);

const sigilumSkill = asObject(config.skills.entries.sigilum);
sigilumSkill.enabled = true;
const existingSkillEnv = asObject(sigilumSkill.env);
delete existingSkillEnv.SIGILUM_CLI_PATH;
delete existingSkillEnv.SIGILUM_REPO_ROOT;
delete existingSkillEnv.SIGILUM_SKILL_DIR;
sigilumSkill.env = {
  ...existingSkillEnv,
  SIGILUM_MODE: mode,
  SIGILUM_NAMESPACE: namespace,
  SIGILUM_GATEWAY_URL: skillGatewayUrl,
  SIGILUM_API_URL: apiUrl,
  SIGILUM_KEY_ROOT: keyRoot,
  SIGILUM_RUNTIME_ROOT: sigilumRuntimeRoot,
  SIGILUM_RUNTIME_BIN: runtimeBin,
  SIGILUM_GATEWAY_HELPER_BIN: gatewayHelperBin,
};
if (sigilumHome) {
  sigilumSkill.env.SIGILUM_HOME = sigilumHome;
}
config.skills.entries.sigilum = sigilumSkill;

fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
try {
  fs.chmodSync(configPath, 0o600);
} catch {
  // Best effort on non-posix filesystems.
}
