#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

HOOK_PLUGIN_SRC="${ROOT_DIR}/openclaw/hooks/sigilum-plugin"
HOOK_AUTHZ_NOTIFY_SRC="${ROOT_DIR}/openclaw/hooks/sigilum-authz-notify"
SKILL_SIGILUM_SRC="${ROOT_DIR}/openclaw/skills/sigilum"
SKILL_LINEAR_SRC="${ROOT_DIR}/openclaw/skills/sigilum-linear"
SIGILUM_CLI_PATH_DEFAULT="${ROOT_DIR}/sigilum"

OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
CONFIG_PATH=""
MODE="${SIGILUM_MODE:-managed}"
NAMESPACE="${SIGILUM_NAMESPACE:-${USER:-default}}"
GATEWAY_URL="${SIGILUM_GATEWAY_URL:-}"
API_URL="${SIGILUM_API_URL:-}"
KEY_ROOT=""
ENABLE_AUTHZ_NOTIFY="false"
OWNER_TOKEN="${SIGILUM_OWNER_TOKEN:-}"
DASHBOARD_URL="${SIGILUM_DASHBOARD_URL:-https://sigilum.id/claims}"
AUTO_OWNER_TOKEN="${SIGILUM_AUTO_OWNER_TOKEN:-}"
OWNER_EMAIL="${SIGILUM_OWNER_EMAIL:-}"
INSTALL_LINEAR_SKILL="true"
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
  --enable-authz-notify BOOL      Enable authz notify hook (true|false, default: false)
  --owner-token TOKEN             Namespace-owner JWT for authz notify hook
  --auto-owner-token BOOL         Auto-issue local owner JWT in oss-local mode (default: true in oss-local when --owner-token is not provided)
  --owner-email VALUE             Owner email for local auto-registration (default: <namespace>@local.sigilum)
  --dashboard-url URL             Dashboard URL shown in authz notifications
  --install-linear-skill BOOL     Install sigilum-linear skill (true|false, default: true)
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

run_cmd() {
  local cmd="$1"
  echo "Running: $cmd"
  sh -c "$cmd"
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
    --install-linear-skill)
      INSTALL_LINEAR_SKILL="${2:-}"
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
if [[ -z "$KEY_ROOT" ]]; then
  KEY_ROOT="${OPENCLAW_HOME}/.sigilum/keys"
fi
if [[ -z "$OWNER_EMAIL" ]]; then
  OWNER_EMAIL="${NAMESPACE}@local.sigilum"
fi
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
if ! is_bool "$INSTALL_LINEAR_SKILL"; then
  echo "--install-linear-skill must be true or false" >&2
  exit 1
fi

ENABLE_AUTHZ_NOTIFY="$(normalize_bool "$ENABLE_AUTHZ_NOTIFY")"
AUTO_OWNER_TOKEN="$(normalize_bool "$AUTO_OWNER_TOKEN")"
INSTALL_LINEAR_SKILL="$(normalize_bool "$INSTALL_LINEAR_SKILL")"

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
if [[ "$INSTALL_LINEAR_SKILL" == "true" ]]; then
  require_dir "$SKILL_LINEAR_SRC"
fi

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
if [[ "$INSTALL_LINEAR_SKILL" == "true" ]]; then
  install_tree "$SKILL_LINEAR_SRC" "${SKILLS_DIR}/sigilum-linear" "skills"
fi

SIGILUM_CLI_PATH=""
if [[ -x "$SIGILUM_CLI_PATH_DEFAULT" ]]; then
  SIGILUM_CLI_PATH="$SIGILUM_CLI_PATH_DEFAULT"
fi

node - "$CONFIG_PATH" "$MODE" "$NAMESPACE" "$GATEWAY_URL" "$API_URL" "$KEY_ROOT" "$ENABLE_AUTHZ_NOTIFY" "$OWNER_TOKEN" "$DASHBOARD_URL" "$INSTALL_LINEAR_SKILL" "$SIGILUM_CLI_PATH" "$ROOT_DIR" <<'NODE'
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
  installLinearSkill,
  sigilumCliPath,
  sigilumRepoRoot,
] = process.argv.slice(2);

const asObject = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value;
};

let parsed = {};
const raw = fs.readFileSync(configPath, "utf8");
if (raw.trim()) {
  try {
    parsed = JSON.parse(raw);
  } catch {
    try {
      const json5 = require("json5");
      parsed = json5.parse(raw);
    } catch (err) {
      try {
        parsed = Function(`\"use strict\"; return (${raw});`)();
      } catch (evalErr) {
        throw new Error(`Failed to parse ${configPath}: ${String(err)} / ${String(evalErr)}`);
      }
    }
  }
}

const config = asObject(parsed);

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
sigilumSkill.env = {
  ...asObject(sigilumSkill.env),
  SIGILUM_MODE: mode,
  SIGILUM_NAMESPACE: namespace,
  SIGILUM_GATEWAY_URL: gatewayUrl,
  SIGILUM_API_URL: apiUrl,
  SIGILUM_KEY_ROOT: keyRoot,
  ...(sigilumCliPath ? { SIGILUM_CLI_PATH: sigilumCliPath } : {}),
  ...(sigilumRepoRoot ? { SIGILUM_REPO_ROOT: sigilumRepoRoot } : {}),
};
config.skills.entries.sigilum = sigilumSkill;

if (installLinearSkill === "true") {
  const linearSkill = asObject(config.skills.entries["sigilum-linear"]);
  linearSkill.enabled = true;
  linearSkill.env = {
    ...asObject(linearSkill.env),
    SIGILUM_MODE: mode,
    SIGILUM_NAMESPACE: namespace,
    SIGILUM_GATEWAY_URL: gatewayUrl,
    SIGILUM_API_URL: apiUrl,
  };
  config.skills.entries["sigilum-linear"] = linearSkill;
}

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
if [[ "$INSTALL_LINEAR_SKILL" == "true" ]]; then
  printf '  %s\n' "${SKILLS_DIR}/sigilum-linear"
fi
printf '\nSigilum settings:\n  mode=%s\n  namespace=%s\n  gateway=%s\n  api=%s\n  key_root=%s\n\n' \
  "$MODE" "$NAMESPACE" "$GATEWAY_URL" "$API_URL" "$KEY_ROOT"

if [[ "$MODE" == "managed" ]]; then
  printf 'Managed onboarding:\n'
  printf '  1) Open https://sigilum.id\n'
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
