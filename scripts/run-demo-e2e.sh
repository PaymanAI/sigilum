#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd pnpm
require_cmd node
require_cmd curl

: "${API_PORT:=8787}"
: "${GATEWAY_PORT:=38100}"
: "${NATIVE_PORT:=11000}"
: "${UPSTREAM_PORT:=11100}"
: "${BLOCKCHAIN_MODE:=disabled}"
: "${SIGILUM_WORKSPACE_DIR:=${ROOT_DIR}/.sigilum-workspace}"

API_URL="http://127.0.0.1:${API_PORT}"
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"
NATIVE_URL="http://127.0.0.1:${NATIVE_PORT}"
UPSTREAM_URL="http://127.0.0.1:${UPSTREAM_PORT}"

RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${TMPDIR:-/tmp}/sigilum-demo-e2e-${RUN_ID}"
mkdir -p "$LOG_DIR"

STACK_STARTED="false"
STACK_PID=""
NATIVE_PID=""
GW_DEMO_PID=""

cleanup() {
  set +e

  if [[ -n "${GW_DEMO_PID}" ]] && kill -0 "${GW_DEMO_PID}" 2>/dev/null; then
    kill "${GW_DEMO_PID}" 2>/dev/null || true
  fi
  if [[ -n "${NATIVE_PID}" ]] && kill -0 "${NATIVE_PID}" 2>/dev/null; then
    kill "${NATIVE_PID}" 2>/dev/null || true
  fi
  if [[ "${STACK_STARTED}" == "true" ]] && [[ -n "${STACK_PID}" ]] && kill -0 "${STACK_PID}" 2>/dev/null; then
    kill "${STACK_PID}" 2>/dev/null || true
  fi

  wait "${GW_DEMO_PID}" "${NATIVE_PID}" "${STACK_PID}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait_for_url() {
  local name="$1"
  local url="$2"
  local timeout_seconds="$3"
  local log_file="${4:-}"

  for i in $(seq 1 "${timeout_seconds}"); do
    if curl -sf "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "${name} did not become ready at ${url}" >&2
  if [[ -n "${log_file}" ]] && [[ -f "${log_file}" ]]; then
    echo "--- ${name} log tail (${log_file}) ---" >&2
    tail -n 200 "${log_file}" >&2 || true
  fi
  return 1
}

ensure_demo_gateway_connection() {
  local connection_id="demo-service-gateway"
  local response_file status delete_status payload

  payload="$(CONNECTION_ID="$connection_id" \
    CONNECTION_NAME="Demo Service (Gateway)" \
    BASE_URL="$UPSTREAM_URL" \
    AUTH_MODE="header_key" \
    AUTH_HEADER_NAME="X-Demo-Service-Gateway-Key" \
    AUTH_PREFIX="" \
    AUTH_SECRET_KEY="upstream_key" \
    AUTH_SECRET_VALUE="$UPSTREAM_KEY" \
    node -e '
const payload = {
  id: process.env.CONNECTION_ID,
  name: process.env.CONNECTION_NAME,
  base_url: process.env.BASE_URL,
  auth_mode: process.env.AUTH_MODE,
  auth_header_name: process.env.AUTH_HEADER_NAME,
  auth_prefix: process.env.AUTH_PREFIX,
  auth_secret_key: process.env.AUTH_SECRET_KEY,
  secrets: { [process.env.AUTH_SECRET_KEY]: process.env.AUTH_SECRET_VALUE },
};
process.stdout.write(JSON.stringify(payload));
')"

  delete_status="$(curl -sS -o /dev/null -w "%{http_code}" \
    -X DELETE "${GATEWAY_URL}/api/admin/connections/${connection_id}" || true)"
  if [[ "$delete_status" != "200" && "$delete_status" != "204" && "$delete_status" != "404" ]]; then
    echo "Warning: delete of existing ${connection_id} returned HTTP ${delete_status}" >&2
  fi

  response_file="$(mktemp "${TMPDIR:-/tmp}/sigilum-e2e-connection-XXXXXX.json")"
  status="$(curl -sS -o "$response_file" -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -X POST "${GATEWAY_URL}/api/admin/connections" \
    --data "$payload")"
  if [[ "$status" != "201" ]]; then
    echo "Failed to ensure ${connection_id} via gateway admin API (HTTP ${status})" >&2
    cat "$response_file" >&2 || true
    rm -f "$response_file"
    return 1
  fi
  rm -f "$response_file"

  echo "Ensured gateway connection ${connection_id} -> ${UPSTREAM_URL}"
}

echo "Logs: ${LOG_DIR}"

if curl -sf "${API_URL}/health" >/dev/null 2>&1 && curl -sf "${GATEWAY_URL}/health" >/dev/null 2>&1; then
  echo "API and gateway already running; reusing existing stack."
else
  echo "Starting local API + gateway stack..."
  (
    cd "${ROOT_DIR}"
    BLOCKCHAIN_MODE="${BLOCKCHAIN_MODE}" "${ROOT_DIR}/scripts/run-local-api-gateway.sh"
  ) >"${LOG_DIR}/stack.log" 2>&1 &
  STACK_PID=$!
  STACK_STARTED="true"

  wait_for_url "API" "${API_URL}/health" 180 "${LOG_DIR}/stack.log"
  wait_for_url "Gateway" "${GATEWAY_URL}/health" 180 "${LOG_DIR}/stack.log"
fi

NATIVE_KEY_FILE="${SIGILUM_WORKSPACE_DIR}/service-api-key-demo-service-native"
UPSTREAM_KEY_FILE="${SIGILUM_WORKSPACE_DIR}/gateway-connection-secret-demo-service-gateway"

if [[ ! -f "${NATIVE_KEY_FILE}" ]]; then
  echo "Missing native demo service API key file: ${NATIVE_KEY_FILE}" >&2
  echo "Run ${ROOT_DIR}/scripts/run-local-api-gateway.sh once to bootstrap local keys." >&2
  exit 1
fi
if [[ ! -f "${UPSTREAM_KEY_FILE}" ]]; then
  echo "Missing gateway demo upstream key file: ${UPSTREAM_KEY_FILE}" >&2
  echo "Run ${ROOT_DIR}/scripts/run-local-api-gateway.sh once to bootstrap local keys." >&2
  exit 1
fi

NATIVE_KEY="$(tr -d '\r\n' <"${NATIVE_KEY_FILE}")"
UPSTREAM_KEY="$(tr -d '\r\n' <"${UPSTREAM_KEY_FILE}")"

echo "Ensuring gateway demo connection points at ${UPSTREAM_URL}..."
ensure_demo_gateway_connection

echo "Starting demo-service-native on ${NATIVE_URL}..."
(
  cd "${ROOT_DIR}/apps/demo-service-native"
  PORT="${NATIVE_PORT}" \
  SIGILUM_API_URL="${API_URL}" \
  SIGILUM_API_KEY="${NATIVE_KEY}" \
  pnpm exec tsx src/index.ts
) >"${LOG_DIR}/native.log" 2>&1 &
NATIVE_PID=$!

echo "Starting demo-service-gateway on ${UPSTREAM_URL}..."
(
  cd "${ROOT_DIR}/apps/demo-service-gateway"
  PORT="${UPSTREAM_PORT}" \
  DEMO_GATEWAY_CONNECTION_ID="demo-service-gateway" \
  DEMO_UPSTREAM_HEADER="X-Demo-Service-Gateway-Key" \
  DEMO_UPSTREAM_KEY="${UPSTREAM_KEY}" \
  pnpm exec tsx src/index.ts
) >"${LOG_DIR}/gateway-demo.log" 2>&1 &
GW_DEMO_PID=$!

wait_for_url "Native demo service" "${NATIVE_URL}/" 120 "${LOG_DIR}/native.log"
wait_for_url "Gateway demo service" "${UPSTREAM_URL}/health" 120 "${LOG_DIR}/gateway-demo.log"

echo "Running end-to-end simulator..."
if SIM_API_URL="${API_URL}" \
  SIM_GATEWAY_URL="${GATEWAY_URL}" \
  SIM_NATIVE_URL="${NATIVE_URL}" \
  SIM_GATEWAY_UPSTREAM_URL="${UPSTREAM_URL}" \
  node "${ROOT_DIR}/scripts/test-agent-simulator.mjs" | tee "${LOG_DIR}/simulator.log"; then
  echo "E2E simulator passed."
else
  echo "E2E simulator failed. See logs in ${LOG_DIR}" >&2
  exit 1
fi
