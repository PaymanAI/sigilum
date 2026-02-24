#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${SIGILUM_CONFIG_HOME:-$HOME/.sigilum}/run"
LOG_FILE_DEFAULT="${RUN_DIR}/gateway-pair-bridge.log"
PID_FILE_DEFAULT="${RUN_DIR}/gateway-pair-bridge.pid"

usage() {
  cat <<'EOF'
Sigilum Gateway Pair Helper

Usage:
  sigilum gateway pair [bridge args]
  sigilum gateway pair --daemon [bridge args]
  sigilum gateway pair --status
  sigilum gateway pair --stop

Bridge args:
  --session-id <id>
  --pair-code <code>
  --namespace <namespace>
  [--api-url <url>]
  [--gateway-admin-url <url>]
  [--reconnect-ms <ms>]
  [--connect-timeout-ms <ms>]
  [--heartbeat-ms <ms>]
  [--relay-timeout-ms <ms>]

Helper options:
  --daemon                 Run bridge in background and return immediately
  --foreground             Force foreground mode (default)
  --log-file <path>        Daemon log file (default: ~/.sigilum/run/gateway-pair-bridge.log)
  --pid-file <path>        Daemon pid file (default: ~/.sigilum/run/gateway-pair-bridge.pid)
  --status                 Print daemon status
  --stop                   Stop daemon process from pid file
  -h, --help               Show help
EOF
}

read_pid() {
  local pid_file="$1"
  if [[ ! -f "$pid_file" ]]; then
    return 1
  fi
  local pid
  pid="$(tr -d '\r\n' <"$pid_file" 2>/dev/null || true)"
  if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  printf '%s' "$pid"
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

MODE="foreground"
ACTION="run"
LOG_FILE="$LOG_FILE_DEFAULT"
PID_FILE="$PID_FILE_DEFAULT"
BRIDGE_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --daemon)
      MODE="daemon"
      shift
      ;;
    --foreground)
      MODE="foreground"
      shift
      ;;
    --log-file)
      LOG_FILE="${2:-}"
      shift 2
      ;;
    --pid-file)
      PID_FILE="${2:-}"
      shift 2
      ;;
    --status)
      ACTION="status"
      shift
      ;;
    --stop)
      ACTION="stop"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      BRIDGE_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ "$ACTION" == "status" ]]; then
  if pid="$(read_pid "$PID_FILE")" && kill -0 "$pid" 2>/dev/null; then
    echo "Gateway pair bridge is running (pid=${pid})."
    echo "  pid_file: ${PID_FILE}"
    echo "  log_file: ${LOG_FILE}"
    exit 0
  fi
  echo "Gateway pair bridge is not running."
  exit 1
fi

if [[ "$ACTION" == "stop" ]]; then
  if pid="$(read_pid "$PID_FILE")" && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
    echo "Stopped gateway pair bridge (pid=${pid})."
    exit 0
  fi
  rm -f "$PID_FILE"
  echo "Gateway pair bridge is not running."
  exit 0
fi

if [[ "$MODE" == "foreground" ]]; then
  exec node "$ROOT_DIR/scripts/gateway-pair-bridge.mjs" "${BRIDGE_ARGS[@]}"
fi

if ! command -v nohup >/dev/null 2>&1; then
  echo "Missing required command for --daemon: nohup" >&2
  exit 1
fi

if pid="$(read_pid "$PID_FILE")" && kill -0 "$pid" 2>/dev/null; then
  echo "Gateway pair bridge already running (pid=${pid}). Use --stop first." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$PID_FILE")" "$RUN_DIR"
pid="$(start_detached_process "$LOG_FILE" node "$ROOT_DIR/scripts/gateway-pair-bridge.mjs" "${BRIDGE_ARGS[@]}")"
echo "$pid" >"$PID_FILE"
sleep 1
if ! kill -0 "$pid" 2>/dev/null; then
  echo "Gateway pair bridge failed to start. Check logs: ${LOG_FILE}" >&2
  exit 1
fi

echo "Gateway pair bridge started in background."
echo "  pid:      ${pid}"
echo "  pid_file: ${PID_FILE}"
echo "  log_file: ${LOG_FILE}"
