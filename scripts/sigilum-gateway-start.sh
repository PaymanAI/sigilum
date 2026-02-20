#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CONFIG_HOME="${SIGILUM_CONFIG_HOME:-$HOME/.sigilum}"
CONFIG_FILE="${SIGILUM_CONFIG_FILE:-${CONFIG_HOME}/config.env}"

usage() {
  cat <<'EOF'
Sigilum Gateway starter

Usage:
  sigilum gateway start [options]

Options:
  --namespace <value>     Namespace (default: SIGILUM_NAMESPACE / GATEWAY_SIGILUM_NAMESPACE / ~/.sigilum/config.env)
  --home <path>           Gateway Sigilum home dir (default: ~/.sigilum-workspace)
  --api-url <url>         Sigilum API base URL (default: https://api.sigilum.id)
  --addr <addr>           Listen address (default: :38100)
  -h, --help              Show help

Notes:
  - This command sets env vars internally (no manual exports required).
  - It creates/reads a master key file at: <home>/gateway-master-key
EOF
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

read_env_file_value() {
  local file_path="$1"
  local key="$2"
  local line lhs rhs first_char last_char

  [[ -f "$file_path" ]] || return 1

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" == *"="* ]] || continue

    lhs="$(trim "${line%%=*}")"
    [[ -n "$lhs" ]] || continue
    [[ "${lhs:0:1}" != "#" ]] || continue
    [[ "$lhs" == "$key" ]] || continue

    rhs="$(trim "${line#*=}")"
    if [[ ${#rhs} -ge 2 ]]; then
      first_char="${rhs:0:1}"
      last_char="${rhs: -1}"
      if [[ "$first_char" == "\"" && "$last_char" == "\"" ]]; then
        rhs="${rhs:1:${#rhs}-2}"
      elif [[ "$first_char" == "'" && "$last_char" == "'" ]]; then
        rhs="${rhs:1:${#rhs}-2}"
      fi
    fi

    printf '%s' "$rhs"
    return 0
  done <"$file_path"

  return 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

is_tty() {
  [[ -t 0 && -t 1 ]]
}

generate_master_key() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
    return 0
  fi
  if command -v python >/dev/null 2>&1; then
    python - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
    return 0
  fi
  head -c 32 /dev/urandom | od -An -tx1 -v | tr -d ' \n'
}

NAMESPACE="${SIGILUM_NAMESPACE:-${GATEWAY_SIGILUM_NAMESPACE:-}}"
GATEWAY_HOME="${GATEWAY_SIGILUM_HOME:-}"
API_URL="${SIGILUM_API_URL:-${SIGILUM_REGISTRY_URL:-}}"
ADDR="${GATEWAY_ADDR:-:38100}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)
      NAMESPACE="${2:-}"
      shift 2
      ;;
    --home)
      GATEWAY_HOME="${2:-}"
      shift 2
      ;;
    --api-url)
      API_URL="${2:-}"
      shift 2
      ;;
    --addr)
      ADDR="${2:-}"
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

if [[ -z "$NAMESPACE" && -f "$CONFIG_FILE" ]]; then
  NAMESPACE="$(read_env_file_value "$CONFIG_FILE" "SIGILUM_NAMESPACE" || true)"
  if [[ -z "$NAMESPACE" ]]; then
    NAMESPACE="$(read_env_file_value "$CONFIG_FILE" "GATEWAY_SIGILUM_NAMESPACE" || true)"
  fi
fi

if [[ -z "$API_URL" && -f "$CONFIG_FILE" ]]; then
  API_URL="$(read_env_file_value "$CONFIG_FILE" "SIGILUM_API_URL" || true)"
  if [[ -z "$API_URL" ]]; then
    API_URL="$(read_env_file_value "$CONFIG_FILE" "SIGILUM_REGISTRY_URL" || true)"
  fi
fi
API_URL="$(trim "${API_URL:-}")"
if [[ -z "$API_URL" ]]; then
  API_URL="https://api.sigilum.id"
fi

if [[ -z "$GATEWAY_HOME" ]]; then
  GATEWAY_HOME="$HOME/.sigilum-workspace"
fi

NAMESPACE="$(trim "${NAMESPACE:-}")"
if [[ -z "$NAMESPACE" ]]; then
  if ! is_tty; then
    echo "Missing namespace. Provide --namespace or set SIGILUM_NAMESPACE." >&2
    exit 1
  fi
  read -r -p "Sigilum namespace: " NAMESPACE
  NAMESPACE="$(trim "$NAMESPACE")"
fi

if [[ -z "$NAMESPACE" ]]; then
  echo "Namespace cannot be empty." >&2
  exit 1
fi

mkdir -p "$GATEWAY_HOME"
chmod 700 "$GATEWAY_HOME" 2>/dev/null || true

MASTER_KEY_FILE="${GATEWAY_HOME%/}/gateway-master-key"
MASTER_KEY="${GATEWAY_MASTER_KEY:-}"
if [[ -z "$MASTER_KEY" && -f "$MASTER_KEY_FILE" ]]; then
  MASTER_KEY="$(trim "$(cat "$MASTER_KEY_FILE" 2>/dev/null || true)")"
fi
if [[ -z "$MASTER_KEY" ]]; then
  if ! is_tty; then
    echo "Missing GATEWAY_MASTER_KEY and no ${MASTER_KEY_FILE} present." >&2
    exit 1
  fi
  echo "Generating gateway master key (stored at ${MASTER_KEY_FILE})..."
  MASTER_KEY="$(generate_master_key)"
  printf '%s\n' "$MASTER_KEY" >"$MASTER_KEY_FILE"
  chmod 600 "$MASTER_KEY_FILE" 2>/dev/null || true
fi

require_cmd sigilum-gateway

export SIGILUM_NAMESPACE="$NAMESPACE"
export GATEWAY_SIGILUM_NAMESPACE="$NAMESPACE"
export GATEWAY_SIGILUM_HOME="$GATEWAY_HOME"
export GATEWAY_MASTER_KEY="$MASTER_KEY"
export SIGILUM_API_URL="$API_URL"
export SIGILUM_REGISTRY_URL="$API_URL"
export GATEWAY_ADDR="$ADDR"

echo "Starting Sigilum gateway."
echo "  namespace: ${SIGILUM_NAMESPACE}"
echo "  api:       ${SIGILUM_API_URL}"
echo "  addr:      ${GATEWAY_ADDR}"
echo "  home:      ${GATEWAY_SIGILUM_HOME}"
echo ""

exec sigilum-gateway

