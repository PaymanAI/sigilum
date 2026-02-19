#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

HOOK_PLUGIN_SRC="${ROOT_DIR}/openclaw/hooks/sigilum-plugin"
HOOK_AUTHZ_NOTIFY_SRC="${ROOT_DIR}/openclaw/hooks/sigilum-authz-notify"
SKILL_SIGILUM_SRC="${ROOT_DIR}/openclaw/skills/sigilum"
SIGILUM_LAUNCHER_SRC="${ROOT_DIR}/sigilum"
SIGILUM_SCRIPTS_SRC="${ROOT_DIR}/scripts"

OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
CONFIG_PATH=""
MODE="${SIGILUM_MODE:-managed}"
NAMESPACE="${SIGILUM_NAMESPACE:-${USER:-default}}"
GATEWAY_URL="${SIGILUM_GATEWAY_URL:-}"
API_URL="${SIGILUM_API_URL:-}"
KEY_ROOT=""
RUNTIME_ROOT="${SIGILUM_RUNTIME_ROOT:-}"
AGENT_WORKSPACE=""
ENABLE_AUTHZ_NOTIFY="false"
OWNER_TOKEN="${SIGILUM_OWNER_TOKEN:-}"
DASHBOARD_URL="${SIGILUM_DASHBOARD_URL:-}"
AUTO_OWNER_TOKEN="${SIGILUM_AUTO_OWNER_TOKEN:-}"
OWNER_EMAIL="${SIGILUM_OWNER_EMAIL:-}"
FORCE="false"
RESTART="false"
STOP_CMD=""
START_CMD=""

usage() {
  cat <<'USAGE'
Install Sigilum OpenClaw hooks + skills from local source.

Usage:
  ./openclaw/install-openclaw-sigilum.sh [options]

Options:
  --openclaw-home PATH            Target OpenClaw home (default: ~/.openclaw)
  --config PATH                   Path to openclaw.json (default: <openclaw-home>/openclaw.json)
  --mode MODE                     Sigilum mode: managed|oss-local (default: managed)
  --namespace VALUE               Sigilum namespace (default: $SIGILUM_NAMESPACE, then $USER)
  --gateway-url URL               Sigilum gateway URL (mode default: http://localhost:38100)
  --api-url URL                   Sigilum API URL (managed default: https://api.sigilum.id, oss-local default: http://127.0.0.1:8787)
  --key-root PATH                 Agent key root (default: <openclaw-home>/.sigilum/keys)
  --runtime-root PATH             Bundled runtime destination (default: <agent-workspace>/.sigilum/runtime, else <openclaw-home>/skills/sigilum/runtime)
  --enable-authz-notify BOOL      Enable authz notify hook (true|false, default: false)
  --owner-token TOKEN             Namespace-owner JWT for authz notify hook
  --auto-owner-token BOOL         Auto-issue local owner JWT in oss-local mode (default: true in oss-local when --owner-token is not provided)
  --owner-email VALUE             Owner email for local auto-registration (default: <namespace>@local.sigilum)
  --dashboard-url URL             Dashboard URL shown in authz notifications
  --force                         Replace existing Sigilum hook/skill directories without backup
  --restart                       Restart OpenClaw after install
  --stop-cmd CMD                  Command used with --restart to stop OpenClaw
  --start-cmd CMD                 Command used with --restart to start OpenClaw
  -h, --help                      Show help

Environment overrides:
  OPENCLAW_HOME, SIGILUM_MODE, SIGILUM_NAMESPACE, SIGILUM_GATEWAY_URL, SIGILUM_API_URL,
  SIGILUM_OWNER_TOKEN, SIGILUM_AUTO_OWNER_TOKEN, SIGILUM_OWNER_EMAIL, SIGILUM_DASHBOARD_URL
USAGE
}

require_dir() {
  local path="$1"
  if [[ ! -d "$path" ]]; then
    echo "Missing required source directory: $path" >&2
    exit 1
  fi
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "Missing required source file: $path" >&2
    exit 1
  fi
}

is_bool() {
  local lower
  lower="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    true|false) return 0 ;;
    *) return 1 ;;
  esac
}

normalize_bool() {
  local lower
  lower="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  if [[ "$lower" == "true" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

backup_path() {
  local path="$1"
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  printf '%s.bak.%s' "$path" "$ts"
}

tree_backup_path() {
  local dest="$1"
  local bucket="$2"
  local ts base backup_dir
  ts="$(date +%Y%m%d-%H%M%S)"
  base="$(basename "$dest")"
  backup_dir="${OPENCLAW_HOME}/backups/${bucket}"
  mkdir -p "$backup_dir"
  printf '%s/%s.bak.%s' "$backup_dir" "$base" "$ts"
}

install_tree() {
  local src="$1"
  local dest="$2"
  local backup_bucket="${3:-artifacts}"

  if [[ -e "$dest" ]]; then
    if [[ "$FORCE" == "true" ]]; then
      rm -rf "$dest"
    else
      local backup
      backup="$(tree_backup_path "$dest" "$backup_bucket")"
      mv "$dest" "$backup"
      echo "Backed up existing: $dest -> $backup"
    fi
  fi

  mkdir -p "$(dirname "$dest")"
  cp -R "$src" "$dest"
}

build_runtime_bundle() {
  local dest="$1"
  local tmp_runtime
  tmp_runtime="$(mktemp -d "${TMPDIR:-/tmp}/sigilum-openclaw-runtime-XXXXXX")"

  # Lean sandbox runtime: launcher + command scripts only.
  # This avoids copying full monorepo sources into OpenClaw workspace.
  cp "$SIGILUM_LAUNCHER_SRC" "${tmp_runtime}/sigilum"
  chmod +x "${tmp_runtime}/sigilum"
  cp -R "$SIGILUM_SCRIPTS_SRC" "${tmp_runtime}/scripts"

  install_tree "${tmp_runtime}" "$dest" "skills"
  chmod -R u+rwX,go+rX "$dest" 2>/dev/null || true
  rm -rf "$tmp_runtime"
}

runtime_home_from_root() {
  local root="$1"
  root="${root%/}"
  if [[ "$root" == */runtime ]]; then
    printf '%s' "${root%/runtime}"
    return 0
  fi
  printf '%s' "$root"
}

detect_service_key_source_home() {
  local -a candidates=()
  if [[ -n "${SIGILUM_HOME:-}" ]]; then
    candidates+=("${SIGILUM_HOME}")
  fi
  if [[ -n "${GATEWAY_SIGILUM_HOME:-}" ]]; then
    candidates+=("${GATEWAY_SIGILUM_HOME}")
  fi
  candidates+=(
    "${ROOT_DIR}/.sigilum-workspace"
    "${HOME}/.sigilum"
    "${OPENCLAW_HOME}/workspace/.sigilum"
  )

  local candidate
  shopt -s nullglob
  for candidate in "${candidates[@]}"; do
    [[ -z "$candidate" ]] && continue
    if [[ -d "$candidate" ]]; then
      local files=("${candidate%/}"/service-api-key-*)
      if (( ${#files[@]} > 0 )); then
        printf '%s' "${candidate%/}"
        shopt -u nullglob
        return 0
      fi
    fi
  done
  shopt -u nullglob
  return 1
}

sync_service_api_keys() {
  local source_home="$1"
  local destination_home="$2"
  if [[ -z "$source_home" || -z "$destination_home" ]]; then
    printf '0'
    return 0
  fi
  mkdir -p "$destination_home"
  chmod 700 "$destination_home" 2>/dev/null || true

  local copied=0 file target
  shopt -s nullglob
  for file in "${source_home%/}"/service-api-key-*; do
    target="${destination_home%/}/$(basename "$file")"
    cp "$file" "$target"
    chmod 600 "$target" 2>/dev/null || true
    copied=$((copied + 1))
  done
  shopt -u nullglob
  printf '%s' "$copied"
}

run_cmd() {
  local cmd="$1"
  echo "Running: $cmd"
  sh -c "$cmd"
}

dashboard_origin_from_url() {
  local raw="$1"
  node - "$raw" <<'NODE'
const raw = (process.argv[2] || "").trim();
if (!raw) process.exit(0);
try {
  const url = new URL(raw);
  process.stdout.write(`${url.protocol}//${url.host}`.replace(/\/+$/g, ""));
} catch {
  process.stdout.write(raw.replace(/\/+$/g, ""));
}
NODE
}

build_passkey_setup_url() {
  local dashboard_url="$1"
  local namespace="$2"
  node - "$dashboard_url" "$namespace" <<'NODE'
const dashboardRaw = (process.argv[2] || "").trim();
const namespace = (process.argv[3] || "").trim();
if (!dashboardRaw) process.exit(0);
let origin = dashboardRaw;
try {
  const url = new URL(dashboardRaw);
  origin = `${url.protocol}//${url.host}`;
} catch {
  // fall through with original string
}
process.stdout.write(`${origin.replace(/\/+$/g, "")}/bootstrap/passkey?namespace=${encodeURIComponent(namespace)}`);
NODE
}

detect_default_runtime_root() {
  local config_path="$1"
  local fallback="$2"
  node - "$config_path" "$fallback" <<'NODE'
const fs = require("fs");
const configPath = process.argv[2];
const fallback = process.argv[3];

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
  process.stdout.write(fallback);
  process.exit(0);
}

const cfg = asObject(parsed);
const agents = asObject(cfg.agents);
const agentDefaults = asObject(agents.defaults);
const rootDefaults = asObject(cfg.defaults);
const workspace = asString(agentDefaults.workspace) || asString(rootDefaults.workspace);
if (!workspace) {
  process.stdout.write(fallback);
  process.exit(0);
}
process.stdout.write(`${workspace.replace(/\/+$/g, "")}/.sigilum/runtime`);
NODE
}

detect_agent_workspace() {
  local config_path="$1"
  node - "$config_path" <<'NODE'
const fs = require("fs");
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
NODE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --openclaw-home)
      OPENCLAW_HOME="${2:-}"
      shift 2
      ;;
    --config)
      CONFIG_PATH="${2:-}"
      shift 2
      ;;
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --namespace)
      NAMESPACE="${2:-}"
      shift 2
      ;;
    --gateway-url)
      GATEWAY_URL="${2:-}"
      shift 2
      ;;
    --api-url)
      API_URL="${2:-}"
      shift 2
      ;;
    --key-root)
      KEY_ROOT="${2:-}"
      shift 2
      ;;
    --runtime-root)
      RUNTIME_ROOT="${2:-}"
      shift 2
      ;;
    --enable-authz-notify)
      ENABLE_AUTHZ_NOTIFY="${2:-}"
      shift 2
      ;;
    --owner-token)
      OWNER_TOKEN="${2:-}"
      shift 2
      ;;
    --auto-owner-token)
      AUTO_OWNER_TOKEN="${2:-}"
      shift 2
      ;;
    --owner-email)
      OWNER_EMAIL="${2:-}"
      shift 2
      ;;
    --dashboard-url)
      DASHBOARD_URL="${2:-}"
      shift 2
      ;;
    --restart)
      RESTART="true"
      shift
      ;;
    --stop-cmd)
      STOP_CMD="${2:-}"
      shift 2
      ;;
    --start-cmd)
      START_CMD="${2:-}"
      shift 2
      ;;
    --force)
      FORCE="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$CONFIG_PATH" ]]; then
  CONFIG_PATH="${OPENCLAW_HOME}/openclaw.json"
fi

case "$MODE" in
  managed|oss-local)
    ;;
  *)
    echo "--mode must be managed or oss-local" >&2
    exit 1
    ;;
esac

if [[ -z "$GATEWAY_URL" ]]; then
  GATEWAY_URL="http://localhost:38100"
fi
if [[ -z "$API_URL" ]]; then
  if [[ "$MODE" == "oss-local" ]]; then
    API_URL="http://127.0.0.1:8787"
  else
    API_URL="https://api.sigilum.id"
  fi
fi
if [[ -z "$DASHBOARD_URL" ]]; then
  DASHBOARD_URL="https://sigilum.id/dashboard"
fi
if [[ -z "$KEY_ROOT" ]]; then
  KEY_ROOT="${OPENCLAW_HOME}/.sigilum/keys"
fi
if [[ -z "$OWNER_EMAIL" ]]; then
  OWNER_EMAIL="${NAMESPACE}@local.sigilum"
fi

DASHBOARD_BASE_URL="$(dashboard_origin_from_url "$DASHBOARD_URL")"
PASSKEY_SETUP_URL="$(build_passkey_setup_url "$DASHBOARD_URL" "$NAMESPACE")"
OWNER_TOKEN_FILE_HINT="${OPENCLAW_HOME}/.sigilum/owner-token-${NAMESPACE}.jwt"
if [[ -z "$AUTO_OWNER_TOKEN" ]]; then
  if [[ "$MODE" == "oss-local" && -z "$OWNER_TOKEN" ]]; then
    AUTO_OWNER_TOKEN="true"
  else
    AUTO_OWNER_TOKEN="false"
  fi
fi

if ! is_bool "$ENABLE_AUTHZ_NOTIFY"; then
  echo "--enable-authz-notify must be true or false" >&2
  exit 1
fi
if ! is_bool "$AUTO_OWNER_TOKEN"; then
  echo "--auto-owner-token must be true or false" >&2
  exit 1
fi
ENABLE_AUTHZ_NOTIFY="$(normalize_bool "$ENABLE_AUTHZ_NOTIFY")"
AUTO_OWNER_TOKEN="$(normalize_bool "$AUTO_OWNER_TOKEN")"

if [[ "$AUTO_OWNER_TOKEN" == "true" && -z "$OWNER_TOKEN" ]]; then
  if [[ "$MODE" != "oss-local" ]]; then
    echo "--auto-owner-token=true requires --mode oss-local or explicit --owner-token" >&2
    exit 1
  fi
  AUTH_SCRIPT="${ROOT_DIR}/scripts/sigilum-auth.sh"
  if [[ ! -x "$AUTH_SCRIPT" ]]; then
    echo "Missing auth helper script: ${AUTH_SCRIPT}" >&2
    exit 1
  fi
  OWNER_TOKEN="$("$AUTH_SCRIPT" login \
    --mode "oss-local" \
    --namespace "$NAMESPACE" \
    --email "$OWNER_EMAIL" \
    --api-url "$API_URL" \
    --openclaw-home "$OPENCLAW_HOME" \
    --write-openclaw false \
    --print-token false \
    --token-only)"
  if [[ -z "$OWNER_TOKEN" ]]; then
    echo "Failed to auto-issue local owner token." >&2
    exit 1
  fi
  echo "Auto-issued local namespace-owner token for ${NAMESPACE}."
fi

if [[ "$ENABLE_AUTHZ_NOTIFY" == "true" && -z "$OWNER_TOKEN" ]]; then
  echo "--owner-token is required when --enable-authz-notify=true" >&2
  exit 1
fi

require_dir "$HOOK_PLUGIN_SRC"
require_dir "$HOOK_AUTHZ_NOTIFY_SRC"
require_dir "$SKILL_SIGILUM_SRC"
require_file "$SIGILUM_LAUNCHER_SRC"
require_dir "$SIGILUM_SCRIPTS_SRC"

HOOKS_DIR="${OPENCLAW_HOME}/hooks"
SKILLS_DIR="${OPENCLAW_HOME}/skills"
mkdir -p "$HOOKS_DIR" "$SKILLS_DIR" "$KEY_ROOT"
chmod 700 "$KEY_ROOT" 2>/dev/null || true

if [[ ! -f "$CONFIG_PATH" ]]; then
  mkdir -p "$(dirname "$CONFIG_PATH")"
  printf '{}\n' >"$CONFIG_PATH"
fi

CONFIG_BACKUP="$(backup_path "$CONFIG_PATH")"
cp "$CONFIG_PATH" "$CONFIG_BACKUP"

echo "Installing hooks..."
install_tree "$HOOK_PLUGIN_SRC" "${HOOKS_DIR}/sigilum-plugin" "hooks"
install_tree "$HOOK_AUTHZ_NOTIFY_SRC" "${HOOKS_DIR}/sigilum-authz-notify" "hooks"

echo "Installing skills..."
install_tree "$SKILL_SIGILUM_SRC" "${SKILLS_DIR}/sigilum" "skills"

AGENT_WORKSPACE="$(detect_agent_workspace "$CONFIG_PATH")"
if [[ -n "$AGENT_WORKSPACE" ]]; then
  WORKSPACE_SKILLS_DIR="${AGENT_WORKSPACE%/}/skills"
  echo "Installing workspace skill mirror..."
  install_tree "$SKILL_SIGILUM_SRC" "${WORKSPACE_SKILLS_DIR}/sigilum" "skills"
fi

DEFAULT_RUNTIME_ROOT="${SKILLS_DIR}/sigilum/runtime"
if [[ -z "$RUNTIME_ROOT" ]]; then
  RUNTIME_ROOT="$(detect_default_runtime_root "$CONFIG_PATH" "$DEFAULT_RUNTIME_ROOT")"
fi
if [[ -z "$RUNTIME_ROOT" ]]; then
  RUNTIME_ROOT="$DEFAULT_RUNTIME_ROOT"
fi

SKILL_HELPER_BIN="${SKILLS_DIR}/sigilum/bin/gateway-admin.sh"
if [[ -n "$AGENT_WORKSPACE" ]]; then
  SKILL_HELPER_BIN="${AGENT_WORKSPACE%/}/skills/sigilum/bin/gateway-admin.sh"
fi

echo "Installing bundled Sigilum runtime..."
build_runtime_bundle "$RUNTIME_ROOT"
RUNTIME_HOME="$(runtime_home_from_root "$RUNTIME_ROOT")"
KEY_SOURCE_HOME="$(detect_service_key_source_home || true)"
if [[ -n "$KEY_SOURCE_HOME" ]]; then
  SYNCED_KEYS_COUNT="$(sync_service_api_keys "$KEY_SOURCE_HOME" "$RUNTIME_HOME")"
  echo "Synced ${SYNCED_KEYS_COUNT} service API key file(s) into runtime home: ${RUNTIME_HOME}"
else
  echo "No service API key source found to sync into runtime home."
fi

node - "$CONFIG_PATH" "$MODE" "$NAMESPACE" "$GATEWAY_URL" "$API_URL" "$KEY_ROOT" "$ENABLE_AUTHZ_NOTIFY" "$OWNER_TOKEN" "$DASHBOARD_URL" "$RUNTIME_ROOT" "$SKILL_HELPER_BIN" "$RUNTIME_HOME" <<'NODE'
const fs = require("fs");

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

let parsed = {};
parsed = parseConfig(fs.readFileSync(configPath, "utf8"), configPath);

const config = asObject(parsed);
const runtimeBin = `${String(sigilumRuntimeRoot || "").replace(/\/+$/g, "")}/sigilum`;
const gatewayHelperBin = String(sigilumGatewayHelperBin || "").trim();
const sigilumHome = String(sigilumHomeDir || "").trim();

config.agents = asObject(config.agents);
config.agents.defaults = asObject(config.agents.defaults);
config.agents.defaults.sandbox = asObject(config.agents.defaults.sandbox);
config.agents.defaults.sandbox.docker = asObject(config.agents.defaults.sandbox.docker);
const defaultAgentID = asString(config.agents.defaults.id) || "main";

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
  SIGILUM_AGENT_ID: defaultAgentID,
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
authzEntry.enabled = enableAuthzNotify === "true";
authzEntry.env = {
  ...asObject(authzEntry.env),
  SIGILUM_MODE: mode,
  SIGILUM_NAMESPACE: namespace,
  SIGILUM_API_URL: apiUrl,
  SIGILUM_DASHBOARD_URL: dashboardUrl,
};
if (ownerToken && ownerToken.trim()) {
  authzEntry.env.SIGILUM_OWNER_TOKEN = ownerToken.trim();
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
  SIGILUM_AGENT_ID: defaultAgentID,
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
NODE

if [[ "$RESTART" == "true" ]]; then
  stop_cmd="${STOP_CMD:-openclaw gateway stop}"
  start_cmd="${START_CMD:-openclaw gateway start}"
  run_cmd "$stop_cmd" || true
  run_cmd "$start_cmd"
fi

printf '\nSigilum OpenClaw integration installed.\n\n'
printf 'OpenClaw home:\n  %s\n' "$OPENCLAW_HOME"
printf 'Config updated:\n  %s\n' "$CONFIG_PATH"
printf 'Config backup:\n  %s\n\n' "$CONFIG_BACKUP"
printf 'Installed hooks:\n  %s\n  %s (enabled=%s)\n\n' \
  "${HOOKS_DIR}/sigilum-plugin" \
  "${HOOKS_DIR}/sigilum-authz-notify" \
  "$ENABLE_AUTHZ_NOTIFY"
printf 'Installed skills:\n  %s\n' "${SKILLS_DIR}/sigilum"
if [[ -n "$AGENT_WORKSPACE" ]]; then
  printf '  %s\n' "${AGENT_WORKSPACE%/}/skills/sigilum"
fi
printf 'Bundled runtime:\n  %s\n' "$RUNTIME_ROOT"
printf '\nSigilum settings:\n  mode=%s\n  namespace=%s\n  gateway=%s\n  api=%s\n  key_root=%s\n\n' \
  "$MODE" "$NAMESPACE" "$GATEWAY_URL" "$API_URL" "$KEY_ROOT"
printf 'Dashboard:\n  claims=%s\n  passkey_setup=%s\n\n' \
  "$DASHBOARD_URL" "$PASSKEY_SETUP_URL"

if [[ "$MODE" == "oss-local" ]]; then
  printf 'Seeded namespace passkey setup:\n'
  printf '  1) Open: %s\n' "$PASSKEY_SETUP_URL"
  if [[ -f "$OWNER_TOKEN_FILE_HINT" ]]; then
    printf '  2) Paste JWT from: %s\n' "$OWNER_TOKEN_FILE_HINT"
  else
    printf '  2) Paste JWT from: sigilum auth show --namespace %s\n' "$NAMESPACE"
  fi
  printf '  3) Register passkey, then sign in at: %s/login\n\n' "$DASHBOARD_BASE_URL"
fi

if [[ "$MODE" == "managed" ]]; then
  printf 'Managed onboarding:\n'
  printf '  1) Open %s\n' "$DASHBOARD_BASE_URL"
  printf '  2) Sign in and reserve namespace "%s"\n' "$NAMESPACE"
  if [[ -n "$OWNER_TOKEN" ]]; then
    printf '  3) Namespace-owner token already configured for OpenClaw hooks\n\n'
  else
    printf '  3) Run: sigilum auth login --mode managed --namespace %s --owner-token-stdin\n\n' "$NAMESPACE"
  fi
fi

if [[ -n "$OWNER_TOKEN" ]]; then
  printf 'Namespace-owner JWT:\n  %s\n\n' "$OWNER_TOKEN"
fi
if [[ "$ENABLE_AUTHZ_NOTIFY" != "true" ]]; then
  printf 'authz-notify hook is disabled by default (recommended): avoids loading namespace-owner token into OpenClaw runtime.\n'
  printf 'Enable later with: sigilum openclaw install --namespace %s --mode %s --enable-authz-notify true --owner-token <jwt>\n\n' "$NAMESPACE" "$MODE"
fi
printf 'OpenClaw usually hot-reloads config. If hooks/skills do not appear immediately, run: openclaw gateway restart\n'
