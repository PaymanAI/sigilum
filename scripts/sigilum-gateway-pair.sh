#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${SIGILUM_CONFIG_HOME:-$HOME/.sigilum}/run"
LOG_FILE_DEFAULT="${RUN_DIR}/gateway-pair-bridge.log"
PID_FILE_DEFAULT="${RUN_DIR}/gateway-pair-bridge.pid"
SYSTEMD_PAIR_UNIT_BASENAME="sigilum-gateway-pair"
SYSTEMD_PAIR_UNIT="${SYSTEMD_PAIR_UNIT_BASENAME}.service"

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

systemd_user_available() {
  if ! command -v systemctl >/dev/null 2>&1 || ! command -v systemd-run >/dev/null 2>&1; then
    return 1
  fi
  systemctl --user show-environment >/dev/null 2>&1
}

systemd_pair_is_active() {
  systemctl --user is-active --quiet "$SYSTEMD_PAIR_UNIT"
}

systemd_pair_main_pid() {
  local pid=""
  pid="$(systemctl --user show --property MainPID --value "$SYSTEMD_PAIR_UNIT" 2>/dev/null || true)"
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
[sigilum] Gateway pair bridge is managed by systemd user service: ${SYSTEMD_PAIR_UNIT}
[sigilum] View logs with:
  journalctl --user -u ${SYSTEMD_PAIR_UNIT} -n 200 --no-pager
EOF
}

start_systemd_pair_service() {
  local log_file="$1"
  shift
  local bridge_args=("$@")

  systemctl --user stop "$SYSTEMD_PAIR_UNIT" >/dev/null 2>&1 || true
  systemctl --user reset-failed "$SYSTEMD_PAIR_UNIT" >/dev/null 2>&1 || true

  if ! systemd-run --user \
    --unit "$SYSTEMD_PAIR_UNIT_BASENAME" \
    --description "Sigilum Gateway Pair Bridge" \
    --property Restart=always \
    --property RestartSec=2 \
    --property KillMode=process \
    --property WorkingDirectory="$ROOT_DIR" \
    node "$ROOT_DIR/scripts/gateway-pair-bridge.mjs" "${bridge_args[@]}" >/dev/null; then
    echo "Failed to start systemd user service: ${SYSTEMD_PAIR_UNIT}" >&2
    return 1
  fi

  sleep 1
  if ! systemd_pair_is_active; then
    echo "Gateway pair bridge service is not active after start: ${SYSTEMD_PAIR_UNIT}" >&2
    echo "Inspect logs: journalctl --user -u ${SYSTEMD_PAIR_UNIT} -n 200 --no-pager" >&2
    return 1
  fi

  write_systemd_log_hint "$log_file"
  return 0
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
  if systemd_user_available && systemd_pair_is_active; then
    pid="$(systemd_pair_main_pid || true)"
    echo "Gateway pair bridge is running (systemd unit=${SYSTEMD_PAIR_UNIT}, pid=${pid:-unknown})."
    echo "  logs: journalctl --user -u ${SYSTEMD_PAIR_UNIT} -n 200 --no-pager"
    exit 0
  fi

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
  systemd_was_active="false"
  if systemd_user_available; then
    if systemd_pair_is_active; then
      systemd_was_active="true"
    fi
    systemctl --user stop "$SYSTEMD_PAIR_UNIT" >/dev/null 2>&1 || true
    systemctl --user reset-failed "$SYSTEMD_PAIR_UNIT" >/dev/null 2>&1 || true
  fi

  if pid="$(read_pid "$PID_FILE")" && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
    echo "Stopped gateway pair bridge (pid=${pid})."
    if systemd_user_available; then
      echo "Stopped gateway pair bridge systemd unit (${SYSTEMD_PAIR_UNIT})."
    fi
    exit 0
  fi
  rm -f "$PID_FILE"
  if systemd_user_available; then
    if [[ "$systemd_was_active" == "true" ]]; then
      echo "Stopped gateway pair bridge systemd unit (${SYSTEMD_PAIR_UNIT})."
    else
      echo "Gateway pair bridge is not running."
    fi
  else
    echo "Gateway pair bridge is not running."
  fi
  exit 0
fi

if [[ "$MODE" == "foreground" ]]; then
  exec node "$ROOT_DIR/scripts/gateway-pair-bridge.mjs" "${BRIDGE_ARGS[@]}"
fi

mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$PID_FILE")" "$RUN_DIR"
if systemd_user_available; then
  rm -f "$PID_FILE"
  start_systemd_pair_service "$LOG_FILE" "${BRIDGE_ARGS[@]}"
  pid="$(systemd_pair_main_pid || true)"
  echo "Gateway pair bridge started as systemd user service."
  echo "  unit: ${SYSTEMD_PAIR_UNIT}"
  echo "  pid:  ${pid:-unknown}"
  echo "  logs: journalctl --user -u ${SYSTEMD_PAIR_UNIT} -n 200 --no-pager"
  exit 0
fi

if ! command -v nohup >/dev/null 2>&1 && ! command -v setsid >/dev/null 2>&1; then
  echo "Missing required command for --daemon: need systemd user manager, 'setsid', or 'nohup'" >&2
  exit 1
fi

if pid="$(read_pid "$PID_FILE")" && kill -0 "$pid" 2>/dev/null; then
  echo "Gateway pair bridge already running (pid=${pid}). Use --stop first." >&2
  exit 1
fi

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
