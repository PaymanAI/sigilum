#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Sigilum Gateway Connect (Managed)

Usage:
  sigilum gateway connect \
    --session-id <id> \
    --pair-code <code> \
    --namespace <namespace> \
    [--api-url <url>] \
    [--gateway-admin-url <url>] \
    [--home <path>] \
    [--addr <addr>] \
    [--gateway-start-timeout-seconds <n>]

What it does:
  1) Ensures local gateway is running (starts it if needed)
  2) Starts pairing bridge in daemon mode
  3) Prints status and next steps
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

has_http_client() {
  command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1
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

parse_health_url() {
  local gateway_admin_url="$1"
  printf '%s/health' "${gateway_admin_url%/}"
}

parse_admin_port() {
  local gateway_admin_url="$1"
  if [[ "$gateway_admin_url" =~ ^https?://[^/:]+:([0-9]+)(/.*)?$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$gateway_admin_url" =~ ^http:// ]]; then
    printf '80'
    return 0
  fi
  if [[ "$gateway_admin_url" =~ ^https:// ]]; then
    printf '443'
    return 0
  fi
  printf ''
}

http_code() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -sS --connect-timeout 2 --max-time 4 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || printf '000'
    return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q -O /dev/null --timeout=4 "$url" >/dev/null 2>&1 && printf '200' || printf '000'
    return 0
  fi
  printf '000'
}

wait_for_gateway() {
  local health_url="$1"
  local timeout_seconds="$2"
  local elapsed=0
  local code
  while (( elapsed < timeout_seconds )); do
    code="$(http_code "$health_url")"
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

start_detached_process() {
  local log_file="$1"
  shift

  local pid=""
  if command -v setsid >/dev/null 2>&1; then
    setsid "$@" >"$log_file" 2>&1 < /dev/null &
    pid=$!
  else
    nohup "$@" >"$log_file" 2>&1 < /dev/null &
    pid=$!
  fi

  # Best effort: avoid shell job control ownership for long-running daemons.
  disown "$pid" 2>/dev/null || true
  printf '%s' "$pid"
}

SESSION_ID=""
PAIR_CODE=""
NAMESPACE=""
API_URL="https://api.sigilum.id"
GATEWAY_ADMIN_URL="http://127.0.0.1:38100"
GATEWAY_HOME=""
GATEWAY_ADDR=":38100"
START_TIMEOUT_SECONDS=20
ADDR_SET="false"

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
      ADDR_SET="true"
      shift 2
      ;;
    --gateway-start-timeout-seconds)
      START_TIMEOUT_SECONDS="${2:-}"
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
if [[ ! "$START_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || [[ "$START_TIMEOUT_SECONDS" -lt 1 ]]; then
  echo "--gateway-start-timeout-seconds must be a positive integer" >&2
  exit 1
fi

require_cmd node
if ! has_http_client; then
  echo "Missing required command: curl or wget" >&2
  exit 1
fi

if ! GATEWAY_ADMIN_URL="$(normalize_gateway_admin_url "$GATEWAY_ADMIN_URL")"; then
  echo "Invalid --gateway-admin-url: ${GATEWAY_ADMIN_URL}" >&2
  echo "Expected forms: http://host:port, https://host:port, host:port, or :port" >&2
  exit 1
fi

if [[ "$ADDR_SET" != "true" ]]; then
  admin_port="$(parse_admin_port "$GATEWAY_ADMIN_URL")"
  if [[ -n "$admin_port" ]]; then
    GATEWAY_ADDR=":${admin_port}"
  fi
fi

health_url="$(parse_health_url "$GATEWAY_ADMIN_URL")"
code="$(http_code "$health_url")"

if [[ "$code" != "200" ]]; then
  echo "Gateway is not healthy at ${health_url}; starting gateway..."
  if ! command -v nohup >/dev/null 2>&1 && ! command -v setsid >/dev/null 2>&1; then
    echo "Missing required command for auto-start: need 'setsid' or 'nohup'" >&2
    exit 1
  fi

  run_dir="${SIGILUM_CONFIG_HOME:-$HOME/.sigilum}/run"
  mkdir -p "$run_dir"
  gateway_log="${run_dir}/gateway-start.log"
  gateway_pid_file="${run_dir}/gateway-start.pid"
  if [[ -f "$gateway_pid_file" ]]; then
    existing_pid="$(tr -d '\r\n' <"$gateway_pid_file" 2>/dev/null || true)"
    if [[ "$existing_pid" =~ ^[0-9]+$ ]] && kill -0 "$existing_pid" 2>/dev/null; then
      echo "Gateway start process already running (pid=${existing_pid}); waiting for health..."
    else
      rm -f "$gateway_pid_file"
    fi
  fi

  if [[ ! -f "$gateway_pid_file" ]]; then
    start_args=(--namespace "$NAMESPACE" --api-url "$API_URL" --addr "$GATEWAY_ADDR")
    if [[ -n "$GATEWAY_HOME" ]]; then
      start_args+=(--home "$GATEWAY_HOME")
    fi
    gateway_pid="$(start_detached_process "$gateway_log" "$ROOT_DIR/scripts/sigilum-gateway-start.sh" "${start_args[@]}")"
    echo "$gateway_pid" >"$gateway_pid_file"
    echo "Gateway starting in background (pid=${gateway_pid}, log=${gateway_log})"
  fi

  if ! wait_for_gateway "$health_url" "$START_TIMEOUT_SECONDS"; then
    echo "Gateway did not become healthy within ${START_TIMEOUT_SECONDS}s at ${health_url}" >&2
    echo "Inspect gateway logs at ${gateway_log}" >&2
    exit 1
  fi
fi

echo "Gateway is healthy at ${health_url}"
"$ROOT_DIR/scripts/sigilum-gateway-pair.sh" --stop >/dev/null 2>&1 || true
"$ROOT_DIR/scripts/sigilum-gateway-pair.sh" --daemon \
  --session-id "$SESSION_ID" \
  --pair-code "$PAIR_CODE" \
  --namespace "$NAMESPACE" \
  --api-url "$API_URL" \
  --gateway-admin-url "$GATEWAY_ADMIN_URL"

echo "Connect complete."
echo "  gateway health: ${health_url}"
echo "  pair status:    sigilum gateway pair --status"
