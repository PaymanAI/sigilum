#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSTEMD_GATEWAY_UNIT_BASENAME="sigilum-gateway"
SYSTEMD_GATEWAY_UNIT="${SYSTEMD_GATEWAY_UNIT_BASENAME}.service"

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

systemd_user_available() {
  if ! command -v systemctl >/dev/null 2>&1 || ! command -v systemd-run >/dev/null 2>&1; then
    return 1
  fi
  systemctl --user show-environment >/dev/null 2>&1
}

systemd_gateway_is_active() {
  systemctl --user is-active --quiet "$SYSTEMD_GATEWAY_UNIT"
}

systemd_gateway_main_pid() {
  local pid=""
  pid="$(systemctl --user show --property MainPID --value "$SYSTEMD_GATEWAY_UNIT" 2>/dev/null || true)"
  if [[ "$pid" =~ ^[0-9]+$ ]] && [[ "$pid" -gt 0 ]]; then
    printf '%s' "$pid"
    return 0
  fi
  return 1
}

write_systemd_log_hint() {
  local log_file="$1"
  mkdir -p "$(dirname "$log_file")"
  cat >"$log_file" <<EOF
[sigilum] Gateway is managed by systemd user service: ${SYSTEMD_GATEWAY_UNIT}
[sigilum] View logs with:
  journalctl --user -u ${SYSTEMD_GATEWAY_UNIT} -n 200 --no-pager
EOF
}

start_gateway_systemd_service() {
  local log_file="$1"
  shift
  local start_args=("$@")

  systemctl --user stop "$SYSTEMD_GATEWAY_UNIT" >/dev/null 2>&1 || true
  systemctl --user reset-failed "$SYSTEMD_GATEWAY_UNIT" >/dev/null 2>&1 || true

  if ! systemd-run --user \
    --unit "$SYSTEMD_GATEWAY_UNIT_BASENAME" \
    --description "Sigilum Gateway" \
    --property Restart=always \
    --property RestartSec=2 \
    --property KillMode=process \
    --property WorkingDirectory="$ROOT_DIR" \
    "$ROOT_DIR/scripts/sigilum-gateway-start.sh" "${start_args[@]}" >/dev/null; then
    echo "Failed to start systemd user service: ${SYSTEMD_GATEWAY_UNIT}" >&2
    return 1
  fi

  sleep 1
  if ! systemd_gateway_is_active; then
    echo "Gateway service is not active after start: ${SYSTEMD_GATEWAY_UNIT}" >&2
    echo "Inspect logs: journalctl --user -u ${SYSTEMD_GATEWAY_UNIT} -n 200 --no-pager" >&2
    return 1
  fi

  write_systemd_log_hint "$log_file"
  return 0
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

  run_dir="${SIGILUM_CONFIG_HOME:-$HOME/.sigilum}/run"
  mkdir -p "$run_dir"
  gateway_log="${run_dir}/gateway-start.log"
  gateway_pid_file="${run_dir}/gateway-start.pid"
  start_args=(--namespace "$NAMESPACE" --api-url "$API_URL" --addr "$GATEWAY_ADDR")
  if [[ -n "$GATEWAY_HOME" ]]; then
    start_args+=(--home "$GATEWAY_HOME")
  fi

  if systemd_user_available; then
    rm -f "$gateway_pid_file"
    start_gateway_systemd_service "$gateway_log" "${start_args[@]}"
    gateway_pid="$(systemd_gateway_main_pid || true)"
    echo "Gateway started as systemd user service (unit=${SYSTEMD_GATEWAY_UNIT}, pid=${gateway_pid:-unknown})."
    echo "Gateway logs: journalctl --user -u ${SYSTEMD_GATEWAY_UNIT} -n 200 --no-pager"
  else
    if ! command -v nohup >/dev/null 2>&1 && ! command -v setsid >/dev/null 2>&1; then
      echo "Missing required command for auto-start: need systemd user manager, 'setsid', or 'nohup'" >&2
      exit 1
    fi

    if [[ -f "$gateway_pid_file" ]]; then
      existing_pid="$(tr -d '\r\n' <"$gateway_pid_file" 2>/dev/null || true)"
      if [[ "$existing_pid" =~ ^[0-9]+$ ]] && kill -0 "$existing_pid" 2>/dev/null; then
        echo "Gateway start process already running (pid=${existing_pid}); waiting for health..."
      else
        rm -f "$gateway_pid_file"
      fi
    fi

    if [[ ! -f "$gateway_pid_file" ]]; then
      gateway_pid="$(start_detached_process "$gateway_log" "$ROOT_DIR/scripts/sigilum-gateway-start.sh" "${start_args[@]}")"
      echo "$gateway_pid" >"$gateway_pid_file"
      echo "Gateway starting in background (pid=${gateway_pid}, log=${gateway_log})"
    fi
  fi

  if ! wait_for_gateway "$health_url" "$START_TIMEOUT_SECONDS"; then
    echo "Gateway did not become healthy within ${START_TIMEOUT_SECONDS}s at ${health_url}" >&2
    if systemd_user_available; then
      echo "Inspect gateway logs with: journalctl --user -u ${SYSTEMD_GATEWAY_UNIT} -n 200 --no-pager" >&2
    else
      echo "Inspect gateway logs at ${gateway_log}" >&2
    fi
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
