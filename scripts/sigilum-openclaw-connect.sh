#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Sigilum OpenClaw Connect (Managed)

Usage:
  sigilum openclaw connect \
    --session-id <id> \
    --pair-code <code> \
    --namespace <namespace> \
    [--api-url <url>] \
    [--openclaw-home <path>] \
    [--config <path>] \
    [--gateway-admin-url <url>] \
    [--home <path>] \
    [--addr <addr>] \
    [--gateway-start-timeout-seconds <n>] \
    [--key-root <path>] \
    [--agent-id <id>] \
    [--enable-authz-notify <true|false>] \
    [--owner-token <jwt>] \
    [--lifecycle-mode <auto|stable|compat>] \
    [--force-install]

What it does:
  1) Preflights lifecycle mode and host readiness
  2) Runs: sigilum openclaw install --mode managed --non-interactive (skips if already configured)
  3) Bootstraps OpenClaw agent keypairs immediately
  4) Runs: sigilum gateway connect (after install/reload window)
  5) Verifies pair bridge + gateway health; retries reconcile with backoff on failure
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

RUN_DIR="${SIGILUM_CONFIG_HOME:-$HOME/.sigilum}/run"
mkdir -p "$RUN_DIR"
LOG_FILE="${RUN_DIR}/openclaw-connect.log"
touch "$LOG_FILE"

LAST_CMD=""
CONNECT_RETRY_MAX=4
CONNECT_RETRY_DELAY_SECONDS=3
SYSTEMD_USER_HELP=""

run() {
  LAST_CMD="$*"
  echo "+ $*" | tee -a "$LOG_FILE"
  "$@" 2>&1 | tee -a "$LOG_FILE"
}

run_check() {
  LAST_CMD="$*"
  echo "+ $*" | tee -a "$LOG_FILE"
  "$@" 2>&1 | tee -a "$LOG_FILE"
}

is_linux_systemd_host() {
  [[ "$(uname -s)" == "Linux" ]] || return 1
  [[ -d "/run/systemd/system" ]] || return 1
  command -v systemctl >/dev/null 2>&1
}

configure_systemd_user_env() {
  local uid runtime_dir
  uid="$(id -u)"
  runtime_dir="/run/user/${uid}"
  if [[ -z "${XDG_RUNTIME_DIR:-}" && -d "$runtime_dir" ]]; then
    export XDG_RUNTIME_DIR="$runtime_dir"
  fi
  if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" && -n "${XDG_RUNTIME_DIR:-}" && -S "${XDG_RUNTIME_DIR}/bus" ]]; then
    export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
  fi
}

build_systemd_user_help() {
  local user linger
  user="$(id -un 2>/dev/null || true)"
  linger=""
  if command -v loginctl >/dev/null 2>&1 && [[ -n "$user" ]]; then
    linger="$(loginctl show-user "$user" -p Linger --value 2>/dev/null || true)"
  fi

  if [[ -n "$user" && "$linger" != "yes" ]]; then
    SYSTEMD_USER_HELP="Run: sudo loginctl enable-linger ${user}"
    return 0
  fi

  SYSTEMD_USER_HELP="Ensure systemd user manager is running and user D-Bus is reachable (XDG_RUNTIME_DIR + DBUS_SESSION_BUS_ADDRESS)."
}

systemd_user_available() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 1
  fi
  systemctl --user show-environment >/dev/null 2>&1
}

ensure_systemd_user_available() {
  SYSTEMD_USER_HELP=""
  if ! is_linux_systemd_host; then
    return 1
  fi
  configure_systemd_user_env
  if systemd_user_available; then
    return 0
  fi
  build_systemd_user_help
  return 1
}

valid_lifecycle_mode() {
  case "${1:-}" in
    auto|stable|compat)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

resolve_lifecycle_mode() {
  local requested_mode="${1:-auto}"

  if ! valid_lifecycle_mode "$requested_mode"; then
    echo "Invalid --lifecycle-mode: ${requested_mode}" >&2
    echo "Expected one of: auto, stable, compat" >&2
    return 1
  fi

  if ensure_systemd_user_available; then
    printf 'stable'
    return 0
  fi

  if is_linux_systemd_host; then
    if [[ "$requested_mode" == "stable" ]]; then
      echo "Systemd host detected, but user manager is unavailable." >&2
      if [[ -n "$SYSTEMD_USER_HELP" ]]; then
        echo "$SYSTEMD_USER_HELP" >&2
      fi
      echo "--lifecycle-mode stable requires a working systemd --user manager." >&2
      return 1
    fi
    if [[ "$requested_mode" == "auto" ]]; then
      echo "Preflight: systemd user manager is unavailable; falling back to compat mode for this run." | tee -a "$LOG_FILE"
      if [[ -n "$SYSTEMD_USER_HELP" ]]; then
        echo "Hint: $SYSTEMD_USER_HELP" | tee -a "$LOG_FILE"
      fi
    fi
  fi

  printf 'compat'
  return 0
}

openclaw_install_is_configured() {
  local config_path="$1"
  local expected_namespace="$2"
  local expected_api_url="$3"
  local hooks_dir="${OPENCLAW_HOME%/}/hooks/sigilum-plugin"
  local skills_dir="${OPENCLAW_HOME%/}/skills/sigilum"

  if [[ ! -f "$config_path" ]]; then
    return 1
  fi
  if [[ ! -d "$hooks_dir" || ! -d "$skills_dir" ]]; then
    return 1
  fi

  node - "$config_path" "$expected_namespace" "$expected_api_url" <<'NODE'
const fs = require("node:fs");
const configPath = process.argv[2] || "";
const expectedNamespace = (process.argv[3] || "").trim();
const expectedApiUrl = (process.argv[4] || "").trim().replace(/\/+$/g, "");
const trim = (value) => (typeof value === "string" ? value.trim() : "");
const normalizeUrl = (value) => trim(value).replace(/\/+$/g, "");

if (!configPath || !expectedNamespace) process.exit(1);

let cfg;
try {
  cfg = JSON.parse(fs.readFileSync(configPath, "utf8"));
} catch {
  process.exit(1);
}

const plugin = cfg?.hooks?.internal?.entries?.["sigilum-plugin"];
const skill = cfg?.skills?.entries?.sigilum;
if (plugin?.enabled !== true || skill?.enabled !== true) process.exit(1);

const namespaceCandidates = [trim(plugin?.env?.SIGILUM_NAMESPACE), trim(skill?.env?.SIGILUM_NAMESPACE)].filter(Boolean);
if (!namespaceCandidates.includes(expectedNamespace)) process.exit(1);

const modeCandidates = [trim(plugin?.env?.SIGILUM_MODE), trim(skill?.env?.SIGILUM_MODE)].filter(Boolean);
if (modeCandidates.length > 0 && !modeCandidates.includes("managed")) process.exit(1);

const configuredApiUrl = normalizeUrl(plugin?.env?.SIGILUM_API_URL) || normalizeUrl(skill?.env?.SIGILUM_API_URL);
if (configuredApiUrl && expectedApiUrl && configuredApiUrl !== expectedApiUrl) process.exit(1);

process.exit(0);
NODE
}

normalize_gateway_admin_url() {
  local raw
  raw="$(printf '%s' "${1:-}" | tr -d '[:space:]')"
  if [[ -z "$raw" ]]; then
    printf 'http://127.0.0.1:38100'
    return 0
  fi
  if [[ "$raw" =~ ^https?:// ]]; then
    printf '%s' "${raw%/}"
    return 0
  fi
  if [[ "$raw" =~ ^:[0-9]+$ ]]; then
    printf 'http://127.0.0.1%s' "$raw"
    return 0
  fi
  if [[ "$raw" =~ ^[^/:]+:[0-9]+$ ]]; then
    printf 'http://%s' "$raw"
    return 0
  fi
  return 1
}

verify_gateway_connect_state() {
  local gateway_health_url="$1"
  local ok="true"

  if ! run_check sigilum gateway pair --status; then
    ok="false"
  fi

  if command -v curl >/dev/null 2>&1; then
    if ! run_check curl -fsS "$gateway_health_url"; then
      ok="false"
    fi
  fi

  [[ "$ok" == "true" ]]
}

reconcile_gateway_connect() {
  local gateway_health_url="$1"
  shift
  local connect_cmd=("$@")
  local attempt=1

  while (( attempt <= CONNECT_RETRY_MAX )); do
    echo "Gateway connect attempt ${attempt}/${CONNECT_RETRY_MAX}..." | tee -a "$LOG_FILE"
    run "${connect_cmd[@]}"
    if verify_gateway_connect_state "$gateway_health_url"; then
      return 0
    fi

    if (( attempt < CONNECT_RETRY_MAX )); then
      echo "Gateway verification failed for attempt ${attempt}; waiting ${CONNECT_RETRY_DELAY_SECONDS}s before retry..." | tee -a "$LOG_FILE"
      echo "+ sleep ${CONNECT_RETRY_DELAY_SECONDS}" | tee -a "$LOG_FILE"
      sleep "$CONNECT_RETRY_DELAY_SECONDS"
    fi
    attempt=$((attempt + 1))
  done

  return 1
}

print_file_or_missing() {
  local file="$1"
  if [[ -f "$file" ]]; then
    sed -n "1,240p" "$file"
  else
    echo "(missing)"
  fi
}

diagnostics() {
  local code="${1:-1}"
  echo "" | tee -a "$LOG_FILE"
  echo "===== SIGILUM OPENCLAW CONNECT FAILED =====" | tee -a "$LOG_FILE"
  echo "Failed command: ${LAST_CMD:-<unknown>}" | tee -a "$LOG_FILE"
  echo "" | tee -a "$LOG_FILE"

  echo "----- ~/.sigilum/run/gateway-start.log -----" | tee -a "$LOG_FILE"
  print_file_or_missing "$HOME/.sigilum/run/gateway-start.log" | tee -a "$LOG_FILE"
  echo "" | tee -a "$LOG_FILE"

  echo "----- ~/.sigilum/run/gateway-pair-bridge.log -----" | tee -a "$LOG_FILE"
  print_file_or_missing "$HOME/.sigilum/run/gateway-pair-bridge.log" | tee -a "$LOG_FILE"
  echo "" | tee -a "$LOG_FILE"

  echo "----- sigilum gateway pair --status -----" | tee -a "$LOG_FILE"
  if command -v sigilum >/dev/null 2>&1; then
    sigilum gateway pair --status 2>&1 | tee -a "$LOG_FILE" || true
  else
    echo "sigilum not found" | tee -a "$LOG_FILE"
  fi
  echo "" | tee -a "$LOG_FILE"

  echo "----- curl -i http://127.0.0.1:38100/health -----" | tee -a "$LOG_FILE"
  if command -v curl >/dev/null 2>&1; then
    curl -i http://127.0.0.1:38100/health 2>&1 | tee -a "$LOG_FILE" || true
  else
    echo "curl not found" | tee -a "$LOG_FILE"
  fi
  echo "" | tee -a "$LOG_FILE"

  echo "Full log: $LOG_FILE"
  exit "$code"
}

trap 'diagnostics $?' ERR

SESSION_ID=""
PAIR_CODE=""
NAMESPACE=""
API_URL="https://api.sigilum.id"
OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
CONFIG_PATH=""
GATEWAY_ADMIN_URL=""
GATEWAY_HOME=""
GATEWAY_ADDR=""
START_TIMEOUT_SECONDS=""
KEY_ROOT=""
AGENT_ID=""
ENABLE_AUTHZ_NOTIFY="false"
OWNER_TOKEN=""
LIFECYCLE_MODE="auto"
FORCE_INSTALL="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --session-id)
      SESSION_ID="${2:-}"
      shift 2
      ;;
    --pair-code)
      PAIR_CODE="${2:-}"
      shift 2
      ;;
    --namespace)
      NAMESPACE="${2:-}"
      shift 2
      ;;
    --api-url)
      API_URL="${2:-}"
      shift 2
      ;;
    --openclaw-home)
      OPENCLAW_HOME="${2:-}"
      shift 2
      ;;
    --config)
      CONFIG_PATH="${2:-}"
      shift 2
      ;;
    --gateway-admin-url)
      GATEWAY_ADMIN_URL="${2:-}"
      shift 2
      ;;
    --home)
      GATEWAY_HOME="${2:-}"
      shift 2
      ;;
    --addr)
      GATEWAY_ADDR="${2:-}"
      shift 2
      ;;
    --gateway-start-timeout-seconds)
      START_TIMEOUT_SECONDS="${2:-}"
      shift 2
      ;;
    --key-root)
      KEY_ROOT="${2:-}"
      shift 2
      ;;
    --agent-id)
      AGENT_ID="${2:-}"
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
    --lifecycle-mode)
      LIFECYCLE_MODE="${2:-}"
      shift 2
      ;;
    --force-install)
      FORCE_INSTALL="true"
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

if [[ -z "$SESSION_ID" || -z "$PAIR_CODE" || -z "$NAMESPACE" ]]; then
  usage >&2
  exit 1
fi

if [[ "$ENABLE_AUTHZ_NOTIFY" != "true" && "$ENABLE_AUTHZ_NOTIFY" != "false" ]]; then
  echo "--enable-authz-notify must be true or false" >&2
  exit 1
fi

if [[ "$ENABLE_AUTHZ_NOTIFY" == "true" && -z "$OWNER_TOKEN" ]]; then
  echo "--owner-token is required when --enable-authz-notify=true" >&2
  exit 1
fi
if ! valid_lifecycle_mode "$LIFECYCLE_MODE"; then
  echo "Invalid --lifecycle-mode: ${LIFECYCLE_MODE}" >&2
  echo "Expected one of: auto, stable, compat" >&2
  exit 1
fi

if [[ -z "$CONFIG_PATH" ]]; then
  CONFIG_PATH="${OPENCLAW_HOME}/openclaw.json"
fi

if [[ -n "$GATEWAY_ADMIN_URL" ]]; then
  if ! GATEWAY_ADMIN_URL="$(normalize_gateway_admin_url "$GATEWAY_ADMIN_URL")"; then
    echo "Invalid --gateway-admin-url: ${GATEWAY_ADMIN_URL}" >&2
    exit 1
  fi
else
  GATEWAY_ADMIN_URL="http://127.0.0.1:38100"
fi
gateway_health_url="${GATEWAY_ADMIN_URL%/}/health"

require_cmd node
require_cmd sigilum

effective_lifecycle_mode="$(resolve_lifecycle_mode "$LIFECYCLE_MODE")"

gateway_connect_cmd=(sigilum gateway connect
  --session-id "$SESSION_ID"
  --pair-code "$PAIR_CODE"
  --namespace "$NAMESPACE"
  --api-url "$API_URL"
  --lifecycle-mode "$effective_lifecycle_mode"
)
if [[ -n "$GATEWAY_ADMIN_URL" ]]; then
  gateway_connect_cmd+=(--gateway-admin-url "$GATEWAY_ADMIN_URL")
fi
if [[ -n "$GATEWAY_HOME" ]]; then
  gateway_connect_cmd+=(--home "$GATEWAY_HOME")
fi
if [[ -n "$GATEWAY_ADDR" ]]; then
  gateway_connect_cmd+=(--addr "$GATEWAY_ADDR")
fi
if [[ -n "$START_TIMEOUT_SECONDS" ]]; then
  gateway_connect_cmd+=(--gateway-start-timeout-seconds "$START_TIMEOUT_SECONDS")
fi

openclaw_install_cmd=(sigilum openclaw install
  --namespace "$NAMESPACE"
  --mode managed
  --non-interactive
  --openclaw-home "$OPENCLAW_HOME"
  --config "$CONFIG_PATH"
  --api-url "$API_URL"
  --enable-authz-notify "$ENABLE_AUTHZ_NOTIFY"
)
if [[ -n "$KEY_ROOT" ]]; then
  openclaw_install_cmd+=(--key-root "$KEY_ROOT")
fi
if [[ -n "$OWNER_TOKEN" ]]; then
  openclaw_install_cmd+=(--owner-token "$OWNER_TOKEN")
fi

if [[ "$FORCE_INSTALL" == "true" ]]; then
  echo "Force install enabled; running OpenClaw install." | tee -a "$LOG_FILE"
  run "${openclaw_install_cmd[@]}"
elif openclaw_install_is_configured "$CONFIG_PATH" "$NAMESPACE" "$API_URL"; then
  echo "OpenClaw Sigilum install already configured for namespace=${NAMESPACE}; skipping install." | tee -a "$LOG_FILE"
else
  run "${openclaw_install_cmd[@]}"
fi

key_bootstrap_cmd=(node "$ROOT_DIR/openclaw/lib/bootstrap-openclaw-agent-keys.mjs" --config "$CONFIG_PATH")
if [[ -n "$KEY_ROOT" ]]; then
  key_bootstrap_cmd+=(--key-root "$KEY_ROOT")
fi
if [[ -n "$AGENT_ID" ]]; then
  key_bootstrap_cmd+=(--agent-id "$AGENT_ID")
fi
run "${key_bootstrap_cmd[@]}"

echo "+ sleep 2" | tee -a "$LOG_FILE"
sleep 2
if ! reconcile_gateway_connect "$gateway_health_url" "${gateway_connect_cmd[@]}"; then
  echo "Gateway verification failed after ${CONNECT_RETRY_MAX} attempts." >&2
  exit 1
fi

echo ""
echo "===== SIGILUM OPENCLAW CONNECT COMPLETE ====="
echo "Namespace: $NAMESPACE"
echo "OpenClaw config: $CONFIG_PATH"
echo "Log file: $LOG_FILE"
echo ""
echo "Next:"
echo "  - Open OpenClaw and run a provider check."
echo "  - If access is blocked, approve the exact APPROVAL_PUBLIC_KEY shown by signed tools checks."
