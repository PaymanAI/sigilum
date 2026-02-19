#!/usr/bin/env bash
set -euo pipefail

: "${API_PORT:=8787}"
: "${GATEWAY_PORT:=38100}"
: "${NATIVE_PORT:=11000}"
: "${UPSTREAM_PORT:=11100}"
: "${ENVOY_INGRESS_PORT:=38000}"
: "${ENVOY_ADMIN_PORT:=38200}"

usage() {
  cat <<'EOF'
Sigilum Local Shutdown

Usage:
  sigilum down [options]

Stops local listeners on default Sigilum dev ports:
  API: 8787
  Gateway: 38100
  Demo native: 11000
  Demo upstream: 11100
  Envoy ingress: 38000
  Envoy admin: 38200

Options:
  -h, --help  Show help
EOF
}

listener_pids_for_port() {
  local port="$1"
  if [[ "$(uname -s)" != "Darwin" ]] && command -v fuser >/dev/null 2>&1; then
    fuser -n tcp "${port}" 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) printf "%s ", $i}' | sed -E 's/[[:space:]]+$//' || true
    return 0
  fi
  lsof -tiTCP:"${port}" 2>/dev/null | tr '\n' ' ' | sed -E 's/[[:space:]]+$//' || true
}

kill_listeners_on_port() {
  local port="$1"
  local label="$2"
  local pids
  pids="$(listener_pids_for_port "$port")"
  if [[ -z "$pids" ]]; then
    echo "[ok] ${label}: no listeners on :${port}"
    return 0
  fi

  echo "[info] stopping ${label} listener(s) on :${port}: ${pids}"
  if [[ "$(uname -s)" != "Darwin" ]] && command -v fuser >/dev/null 2>&1; then
    fuser -k -TERM -n tcp "${port}" >/dev/null 2>&1 || true
  else
    kill ${pids} 2>/dev/null || true
  fi

  for _ in $(seq 1 8); do
    sleep 1
    pids="$(listener_pids_for_port "$port")"
    if [[ -z "$pids" ]]; then
      echo "[ok] ${label}: stopped"
      return 0
    fi
  done

  echo "[warn] force-stopping lingering ${label} listener(s) on :${port}: ${pids}"
  if [[ "$(uname -s)" != "Darwin" ]] && command -v fuser >/dev/null 2>&1; then
    fuser -k -KILL -n tcp "${port}" >/dev/null 2>&1 || true
  else
    kill -9 ${pids} 2>/dev/null || true
  fi

  sleep 1
  pids="$(listener_pids_for_port "$port")"
  if [[ -n "$pids" ]]; then
    echo "[fail] unable to reclaim ${label} port :${port}; still listening PID(s): ${pids}" >&2
    return 1
  fi

  echo "[ok] ${label}: stopped"
  return 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

kill_listeners_on_port "$API_PORT" "API"
kill_listeners_on_port "$GATEWAY_PORT" "Gateway"
kill_listeners_on_port "$NATIVE_PORT" "Demo native service"
kill_listeners_on_port "$UPSTREAM_PORT" "Demo gateway upstream"
kill_listeners_on_port "$ENVOY_INGRESS_PORT" "Envoy ingress"
kill_listeners_on_port "$ENVOY_ADMIN_PORT" "Envoy admin"

echo "Sigilum local stack shutdown complete."
