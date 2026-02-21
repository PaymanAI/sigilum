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
if ! command -v fuser >/dev/null 2>&1 && ! command -v lsof >/dev/null 2>&1; then
  echo "Missing required command: install either fuser or lsof" >&2
  exit 1
fi

: "${API_PORT:=8787}"
: "${GATEWAY_PORT:=38100}"
: "${NATIVE_PORT:=11000}"
: "${UPSTREAM_PORT:=11100}"
: "${BLOCKCHAIN_MODE:=disabled}"
: "${SIGILUM_WORKSPACE_DIR:=${ROOT_DIR}/.sigilum-workspace}"
: "${SIGILUM_E2E_CLEAN_START:=true}"
: "${SIM_SEED_TOKEN:=}"
: "${CURL_CONNECT_TIMEOUT_SECONDS:=5}"
: "${CURL_MAX_TIME_SECONDS:=30}"

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

generate_seed_token() {
  node -e "const crypto=require('node:crypto'); process.stdout.write('seed_'+crypto.randomBytes(24).toString('hex'));"
}

curl_with_timeout() {
  curl --connect-timeout "$CURL_CONNECT_TIMEOUT_SECONDS" --max-time "$CURL_MAX_TIME_SECONDS" "$@"
}

if [[ -z "${SIM_SEED_TOKEN}" ]]; then
  SIM_SEED_TOKEN="$(generate_seed_token)"
fi

wait_for_url() {
  local name="$1"
  local url="$2"
  local timeout_seconds="$3"
  local log_file="${4:-}"

  local attempt
  for ((attempt = 1; attempt <= timeout_seconds; attempt += 1)); do
    if curl_with_timeout -sf "${url}" >/dev/null 2>&1; then
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

probe_status() {
  local name="$1"
  local expected_status="$2"
  local method="$3"
  local url="$4"
  local body="${5:-}"
  local status

  if [[ -n "$body" ]]; then
    status="$(curl_with_timeout -sS -o /dev/null -w "%{http_code}" \
      -H "Content-Type: application/json" \
      -X "$method" "$url" \
      --data "$body" || true)"
  else
    status="$(curl_with_timeout -sS -o /dev/null -w "%{http_code}" -X "$method" "$url" || true)"
  fi

  if [[ "$status" != "$expected_status" ]]; then
    echo "${name} expected HTTP ${expected_status}, got ${status} (${method} ${url})" >&2
    return 1
  fi
}

listener_pids_for_port() {
  local port="$1"
  if command -v fuser >/dev/null 2>&1; then
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
    return 0
  fi

  echo "Stopping existing ${label} listener(s) on :${port}: ${pids}"
  if command -v fuser >/dev/null 2>&1; then
    fuser -k -TERM -n tcp "${port}" >/dev/null 2>&1 || true
  else
    local -a pid_list=()
    read -r -a pid_list <<<"$pids"
    kill "${pid_list[@]}" 2>/dev/null || true
  fi

  for _ in $(seq 1 8); do
    sleep 1
    pids="$(listener_pids_for_port "$port")"
    if [[ -z "$pids" ]]; then
      return 0
    fi
  done

  echo "Force-stopping lingering ${label} listener(s) on :${port}: ${pids}"
  if command -v fuser >/dev/null 2>&1; then
    fuser -k -KILL -n tcp "${port}" >/dev/null 2>&1 || true
  else
    local -a pid_list=()
    read -r -a pid_list <<<"$pids"
    kill -9 "${pid_list[@]}" 2>/dev/null || true
  fi

  sleep 1
  pids="$(listener_pids_for_port "$port")"
  if [[ -n "$pids" ]]; then
    echo "Unable to reclaim ${label} port :${port}; still listening PID(s): ${pids}" >&2
    return 1
  fi

  return 0
}

clean_start_ports() {
  kill_listeners_on_port "$API_PORT" "API"
  kill_listeners_on_port "$GATEWAY_PORT" "gateway"
  kill_listeners_on_port "$NATIVE_PORT" "native demo"
  kill_listeners_on_port "$UPSTREAM_PORT" "gateway demo upstream"
}

ensure_stack_alive() {
  if [[ "${STACK_STARTED}" == "true" ]] && [[ -n "${STACK_PID}" ]] && ! kill -0 "${STACK_PID}" 2>/dev/null; then
    echo "Local API+gateway stack exited unexpectedly during e2e bootstrap." >&2
    if [[ -f "${LOG_DIR}/stack.log" ]]; then
      echo "--- stack log tail (${LOG_DIR}/stack.log) ---" >&2
      tail -n 200 "${LOG_DIR}/stack.log" >&2 || true
    fi
    exit 1
  fi
}

ensure_demo_gateway_connection() {
  local connection_id="demo-service-gateway"
  local response_file status delete_status payload
  local max_attempts=20
  local attempt=1

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

  while [[ "$attempt" -le "$max_attempts" ]]; do
    ensure_stack_alive

    delete_status="$(curl_with_timeout -sS -o /dev/null -w "%{http_code}" \
      -X DELETE "${GATEWAY_URL}/api/admin/connections/${connection_id}" || true)"
    if [[ "$delete_status" != "200" && "$delete_status" != "204" && "$delete_status" != "404" && "$delete_status" != "000" ]]; then
      echo "Warning: delete of existing ${connection_id} returned HTTP ${delete_status}" >&2
    fi

    response_file="$(mktemp "${TMPDIR:-/tmp}/sigilum-e2e-connection-XXXXXX.json")"
    status="$(curl_with_timeout -sS -o "$response_file" -w "%{http_code}" \
      -H "Content-Type: application/json" \
      -X POST "${GATEWAY_URL}/api/admin/connections" \
      --data "$payload" || true)"
    if [[ "$status" == "201" ]]; then
      rm -f "$response_file"
      echo "Ensured gateway connection ${connection_id} -> ${UPSTREAM_URL}"
      return 0
    fi

    if [[ "$status" == "000" || "$status" == "502" || "$status" == "503" || "$status" == "504" ]]; then
      rm -f "$response_file"
      if [[ "$attempt" -lt "$max_attempts" ]]; then
        echo "Gateway admin endpoint not ready (attempt ${attempt}/${max_attempts}, HTTP ${status}); retrying..."
        sleep 1
        attempt=$((attempt + 1))
        continue
      fi
      echo "Failed to reach gateway admin endpoint after ${max_attempts} attempts (last HTTP ${status})." >&2
      if [[ -f "${LOG_DIR}/stack.log" ]]; then
        echo "--- stack log tail (${LOG_DIR}/stack.log) ---" >&2
        tail -n 200 "${LOG_DIR}/stack.log" >&2 || true
      fi
      return 1
    fi

    echo "Failed to ensure ${connection_id} via gateway admin API (HTTP ${status})" >&2
    cat "$response_file" >&2 || true
    rm -f "$response_file"
    return 1
  done

  echo "Failed to ensure ${connection_id}: retry loop exhausted unexpectedly." >&2
  return 1
}

wait_for_gateway_admin() {
  local admin_url="${GATEWAY_URL}/api/admin/connections"
  wait_for_url "Gateway admin API" "${admin_url}" 90 "${LOG_DIR}/stack.log"
  ensure_stack_alive
  probe_status "Gateway admin API probe" "200" "GET" "${admin_url}"
}

echo "Logs: ${LOG_DIR}"

if [[ "${SIGILUM_E2E_CLEAN_START}" == "true" ]]; then
  echo "Clean start enabled: terminating existing listeners on Sigilum e2e ports."
  clean_start_ports
fi

api_ready="false"
gateway_ready="false"
if curl_with_timeout -sf "${API_URL}/health" >/dev/null 2>&1; then
  api_ready="true"
fi
if curl_with_timeout -sf "${GATEWAY_URL}/health" >/dev/null 2>&1; then
  gateway_ready="true"
fi

if [[ "$api_ready" == "true" && "$gateway_ready" == "true" ]]; then
  echo "API and gateway already running; reusing existing stack."
elif [[ "$api_ready" == "false" && "$gateway_ready" == "false" ]]; then
  echo "Starting local API + gateway stack..."
  (
    cd "${ROOT_DIR}"
    BLOCKCHAIN_MODE="${BLOCKCHAIN_MODE}" \
      ENVIRONMENT="local" \
      ENABLE_TEST_SEED_ENDPOINT="true" \
      SIGILUM_TEST_SEED_TOKEN="${SIM_SEED_TOKEN}" \
      "${ROOT_DIR}/scripts/run-local-api-gateway.sh"
  ) >"${LOG_DIR}/stack.log" 2>&1 &
  STACK_PID=$!
  STACK_STARTED="true"

  wait_for_url "API" "${API_URL}/health" 180 "${LOG_DIR}/stack.log"
  wait_for_url "Gateway" "${GATEWAY_URL}/health" 180 "${LOG_DIR}/stack.log"
  ensure_stack_alive
else
  echo "Detected partial stack state (API ready=${api_ready}, gateway ready=${gateway_ready})." >&2
  echo "Stop existing local processes or run a clean stack, then rerun e2e tests." >&2
  exit 1
fi

wait_for_gateway_admin

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

if curl_with_timeout -sf "${NATIVE_URL}/" >/dev/null 2>&1; then
  echo "Native demo service already running at ${NATIVE_URL}; reusing."
else
  echo "Starting demo-service-native on ${NATIVE_URL}..."
  (
    cd "${ROOT_DIR}/apps/demo-service-native"
    PORT="${NATIVE_PORT}" \
    SIGILUM_API_URL="${API_URL}" \
    SIGILUM_API_KEY="${NATIVE_KEY}" \
    pnpm exec tsx src/index.ts
  ) >"${LOG_DIR}/native.log" 2>&1 &
  NATIVE_PID=$!

  wait_for_url "Native demo service" "${NATIVE_URL}/" 120 "${LOG_DIR}/native.log"
fi

if curl_with_timeout -sf "${UPSTREAM_URL}/health" >/dev/null 2>&1; then
  echo "Gateway demo upstream already running at ${UPSTREAM_URL}; reusing."
else
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

  wait_for_url "Gateway demo service" "${UPSTREAM_URL}/health" 120 "${LOG_DIR}/gateway-demo.log"
fi

PING_BODY='"ping"'
probe_status "Gateway connection lookup" "200" "GET" "${GATEWAY_URL}/api/admin/connections/demo-service-gateway"
probe_status "Native unsigned probe" "401" "POST" "${NATIVE_URL}/v1/ping" "${PING_BODY}"
probe_status "Gateway unsigned probe" "403" "POST" "${GATEWAY_URL}/proxy/demo-service-gateway/v1/ping" "${PING_BODY}"

echo "Running end-to-end simulator..."
if SIM_API_URL="${API_URL}" \
  SIM_GATEWAY_URL="${GATEWAY_URL}" \
  SIM_NATIVE_URL="${NATIVE_URL}" \
  SIM_GATEWAY_UPSTREAM_URL="${UPSTREAM_URL}" \
  SIM_SEED_TOKEN="${SIM_SEED_TOKEN}" \
  node "${ROOT_DIR}/scripts/test-agent-simulator.mjs" | tee "${LOG_DIR}/simulator.log"; then
  echo "E2E simulator passed."
else
  echo "E2E simulator failed. See logs in ${LOG_DIR}" >&2
  exit 1
fi
