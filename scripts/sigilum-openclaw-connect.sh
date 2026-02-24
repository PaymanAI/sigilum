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
    [--owner-token <jwt>]

What it does:
  1) Runs: sigilum openclaw install --mode managed --non-interactive
  2) Bootstraps OpenClaw agent keypairs immediately
  3) Runs: sigilum gateway connect (after install/reload window)
  4) Verifies pair bridge + gateway health; retries reconcile once on failure
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

gateway_connect_cmd=(sigilum gateway connect
  --session-id "$SESSION_ID"
  --pair-code "$PAIR_CODE"
  --namespace "$NAMESPACE"
  --api-url "$API_URL"
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

run "${openclaw_install_cmd[@]}"

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
run "${gateway_connect_cmd[@]}"

if ! verify_gateway_connect_state "$gateway_health_url"; then
  echo "Gateway verification failed after initial connect; attempting one reconcile pass..." | tee -a "$LOG_FILE"
  run "${gateway_connect_cmd[@]}"
  if ! verify_gateway_connect_state "$gateway_health_url"; then
    echo "Gateway verification failed after reconcile retry." >&2
    exit 1
  fi
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
