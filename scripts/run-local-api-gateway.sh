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
require_cmd go
require_cmd node

ensure_api_wrangler_config() {
  local api_dir="${ROOT_DIR}/apps/api"
  local config_path="${api_dir}/wrangler.toml"
  local template_path="${api_dir}/wrangler.toml.example"

  if [[ -f "$config_path" ]]; then
    return 0
  fi
  if [[ ! -f "$template_path" ]]; then
    echo "Missing Wrangler config template: ${template_path}" >&2
    exit 1
  fi

  cp "$template_path" "$config_path"
  echo "Created ${config_path} from template."
}

ensure_api_wrangler_config

: "${API_PORT:=8787}"
: "${API_HOST:=127.0.0.1}"
: "${BLOCKCHAIN_MODE:=disabled}"
: "${ENVIRONMENT:=local}"
: "${ENABLE_TEST_SEED_ENDPOINT:=false}"
: "${SIGILUM_TEST_SEED_TOKEN:=}"
: "${SIGILUM_REGISTRY_URL:=http://127.0.0.1:${API_PORT}}"
: "${SIGILUM_API_URL:=${SIGILUM_REGISTRY_URL}}"
# Local dashboard/API defaults. Override these env vars if you need different origins.
: "${ALLOWED_ORIGINS:=http://localhost:5000,http://127.0.0.1:5000,http://localhost:3000,http://127.0.0.1:3000}"
: "${WEBAUTHN_ALLOWED_ORIGINS:=http://localhost:5000}"
: "${WEBAUTHN_RP_ID:=localhost}"
: "${GATEWAY_ALLOWED_ORIGINS:=http://localhost:5000,http://127.0.0.1:5000,http://localhost:3000,http://127.0.0.1:3000,http://localhost:38000,http://127.0.0.1:38000,https://sigilum.id}"

: "${GATEWAY_ADDR:=:38100}"
: "${GATEWAY_DATA_DIR:=${ROOT_DIR}/.local/gateway-data}"
: "${GATEWAY_SERVICE_CATALOG_FILE:=${GATEWAY_DATA_DIR}/service-catalog.json}"
: "${GATEWAY_BUILD_BINARIES:=true}"
: "${GATEWAY_BIN_DIR:=${ROOT_DIR}/.local/bin}"
: "${GATEWAY_SERVICE_BINARY:=${GATEWAY_BIN_DIR}/sigilum-gateway}"
: "${GATEWAY_CLI_BINARY:=${GATEWAY_BIN_DIR}/sigilum-gateway-cli}"
# Namespace for the gateway's own Sigilum signer identity used on gateway->API requests.
# This is NOT the service slug and does not restrict incoming agent namespaces.
: "${GATEWAY_SIGILUM_NAMESPACE:=johndee}"
: "${GATEWAY_SIGILUM_HOME:=${ROOT_DIR}/.sigilum-workspace}"
: "${GATEWAY_MASTER_KEY:=sigilum-local-dev-master-key}"
: "${GATEWAY_LOCAL_BOOTSTRAP:=true}"
: "${GATEWAY_SERVICE_NAME:=Sigilum Gateway}"
: "${GATEWAY_LOCAL_EMAIL:=${GATEWAY_SIGILUM_NAMESPACE}@local.sigilum}"
: "${GATEWAY_ALLOW_UNSIGNED_PROXY:=false}"
: "${GATEWAY_ALLOW_UNSIGNED_CONNECTIONS:=}"
: "${GATEWAY_NATIVE_DEMO_SERVICE_SLUG:=demo-service-native}"
: "${GATEWAY_NATIVE_DEMO_SERVICE_NAME:=Demo Service (Native)}"
: "${GATEWAY_PROXY_DEMO_CONNECTION_ID:=demo-service-gateway}"
: "${GATEWAY_PROXY_DEMO_SERVICE_NAME:=Demo Service (Gateway)}"
: "${GATEWAY_PROXY_DEMO_BASE_URL:=http://127.0.0.1:11100}"
: "${GATEWAY_PROXY_DEMO_AUTH_HEADER:=X-Demo-Service-Gateway-Key}"
: "${GATEWAY_PROXY_DEMO_AUTH_SECRET_KEY:=upstream_key}"
: "${GATEWAY_PROXY_DEMO_UPSTREAM_KEY:=}"
: "${GATEWAY_PROXY_DEMO_SECRET_FILE:=${GATEWAY_SIGILUM_HOME}/gateway-connection-secret-${GATEWAY_PROXY_DEMO_CONNECTION_ID}}"

sql_escape() {
  printf "%s" "$1" | sed "s/'/''/g"
}

run_local_d1() {
  local query="$1"
  (
    cd "$ROOT_DIR/apps/api"
    pnpm exec wrangler d1 execute sigilum-api --local --command "$query" >/dev/null
  )
}

is_valid_slug() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$ ]]
}

service_api_key_env_suffix() {
  local value="$1"
  local normalized
  normalized="$(printf "%s" "$value" | tr '[:lower:]' '[:upper:]' | sed -E 's/[^A-Z0-9]+/_/g; s/^_+//; s/_+$//')"
  if [[ -z "$normalized" ]]; then
    normalized="DEFAULT"
  fi
  printf "%s" "$normalized"
}

generate_service_api_key() {
  node -e "const crypto=require('node:crypto'); process.stdout.write('sk_live_'+crypto.randomBytes(24).toString('hex'));"
}

generate_proxy_demo_secret() {
  node -e "const crypto=require('node:crypto'); process.stdout.write('gw_demo_'+crypto.randomBytes(24).toString('hex'));"
}

generate_seed_token() {
  node -e "const crypto=require('node:crypto'); process.stdout.write('seed_'+crypto.randomBytes(24).toString('hex'));"
}

gateway_binary_needs_rebuild() {
  local binary_path="$1"
  if [[ ! -x "$binary_path" ]]; then
    return 0
  fi
  if find "$ROOT_DIR/apps/gateway/service" -type f \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \) -newer "$binary_path" -print -quit | grep -q .; then
    return 0
  fi
  return 1
}

build_gateway_binaries() {
  if [[ "${GATEWAY_BUILD_BINARIES}" != "true" ]]; then
    return 0
  fi

  mkdir -p "$GATEWAY_BIN_DIR"
  local build_service="false"
  local build_cli="false"

  if gateway_binary_needs_rebuild "$GATEWAY_SERVICE_BINARY"; then
    build_service="true"
  fi
  if gateway_binary_needs_rebuild "$GATEWAY_CLI_BINARY"; then
    build_cli="true"
  fi

  if [[ "$build_service" == "false" && "$build_cli" == "false" ]]; then
    return 0
  fi

  echo "Building gateway binaries before startup (lower memory than go run)..."
  (
    cd "$ROOT_DIR/apps/gateway/service"
    if [[ "$build_service" == "true" ]]; then
      go build -o "$GATEWAY_SERVICE_BINARY" ./cmd/sigilum-gateway
    fi
    if [[ "$build_cli" == "true" ]]; then
      go build -o "$GATEWAY_CLI_BINARY" ./cmd/sigilum-gateway-cli
    fi
  )
}

load_or_create_value() {
  local file_path="$1"
  local variable_name="$2"
  local generator_func="$3"
  local value="${!variable_name:-}"

  if [[ -z "$value" && -f "$file_path" ]]; then
    value="$(tr -d '\r\n' <"$file_path")"
  fi
  if [[ -z "$value" ]]; then
    value="$("$generator_func")"
  fi

  if [[ ! -f "$file_path" ]]; then
    umask 077
    printf "%s\n" "$value" >"$file_path"
  fi

  printf -v "$variable_name" "%s" "$value"
  export "$variable_name"
}

sha256_hex() {
  local value="$1"
  VALUE_TO_HASH="$value" \
    node -e "const crypto=require('node:crypto'); process.stdout.write(crypto.createHash('sha256').update(process.env.VALUE_TO_HASH,'utf8').digest('hex'));"
}

ensure_local_service_and_key() {
  local namespace="$1"
  local email="$2"
  local service_slug="$3"
  local service_name="$4"
  local service_description="$5"
  local key_name="$6"
  local key_value="$7"

  local key_hash key_prefix key_id user_id service_id
  key_hash="$(sha256_hex "$key_value")"
  key_prefix="...${key_value: -4}"
  key_id="key_local_${service_slug}_${key_hash:0:12}"
  user_id="user_local_${namespace}"
  service_id="svc_local_${service_slug}"

  local ns_sql email_sql slug_sql name_sql desc_sql key_name_sql key_id_sql service_id_sql user_id_sql key_prefix_sql key_hash_sql
  ns_sql="$(sql_escape "$namespace")"
  email_sql="$(sql_escape "$email")"
  slug_sql="$(sql_escape "$service_slug")"
  name_sql="$(sql_escape "$service_name")"
  desc_sql="$(sql_escape "$service_description")"
  key_name_sql="$(sql_escape "$key_name")"
  key_id_sql="$(sql_escape "$key_id")"
  service_id_sql="$(sql_escape "$service_id")"
  user_id_sql="$(sql_escape "$user_id")"
  key_prefix_sql="$(sql_escape "$key_prefix")"
  key_hash_sql="$(sql_escape "$key_hash")"

  run_local_d1 "INSERT OR IGNORE INTO users (id, email, namespace, plan, settings) VALUES ('${user_id_sql}', '${email_sql}', '${ns_sql}', 'free', '{}');"
  run_local_d1 "INSERT OR IGNORE INTO services (id, owner_user_id, name, slug, domain, description) SELECT '${service_id_sql}', id, '${name_sql}', '${slug_sql}', 'localhost', '${desc_sql}' FROM users WHERE namespace = '${ns_sql}' LIMIT 1;"
  run_local_d1 "UPDATE services SET name = '${name_sql}', description = '${desc_sql}', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE slug = '${slug_sql}' AND owner_user_id IN (SELECT id FROM users WHERE namespace = '${ns_sql}' LIMIT 1);"
  run_local_d1 "INSERT OR IGNORE INTO service_api_keys (id, service_id, name, key_prefix, key_hash) SELECT '${key_id_sql}', id, '${key_name_sql}', '${key_prefix_sql}', '${key_hash_sql}' FROM services WHERE slug = '${slug_sql}' LIMIT 1;"
  run_local_d1 "UPDATE service_api_keys SET name = '${key_name_sql}' WHERE service_id IN (SELECT id FROM services WHERE slug = '${slug_sql}' AND owner_user_id IN (SELECT id FROM users WHERE namespace = '${ns_sql}' LIMIT 1) LIMIT 1) AND key_hash = '${key_hash_sql}' AND revoked_at IS NULL;"

  echo "  - registered service=${service_slug} api_key=${key_prefix}"
}

gateway_cli() {
  if [[ "${GATEWAY_BUILD_BINARIES}" == "true" && -x "$GATEWAY_CLI_BINARY" ]]; then
    GATEWAY_DATA_DIR="$GATEWAY_DATA_DIR" \
      GATEWAY_MASTER_KEY="$GATEWAY_MASTER_KEY" \
      "$GATEWAY_CLI_BINARY" "$@"
    return 0
  fi

  (
    cd "$ROOT_DIR/apps/gateway/service"
    GATEWAY_DATA_DIR="$GATEWAY_DATA_DIR" \
      GATEWAY_MASTER_KEY="$GATEWAY_MASTER_KEY" \
      go run ./cmd/sigilum-gateway-cli "$@"
  )
}

create_demo_gateway_connection() {
  gateway_cli add \
    --id "$GATEWAY_PROXY_DEMO_CONNECTION_ID" \
    --name "$GATEWAY_PROXY_DEMO_SERVICE_NAME" \
    --base-url "$GATEWAY_PROXY_DEMO_BASE_URL" \
    --auth-mode header_key \
    --auth-header-name "$GATEWAY_PROXY_DEMO_AUTH_HEADER" \
    --auth-secret-key "$GATEWAY_PROXY_DEMO_AUTH_SECRET_KEY" \
    --secret "${GATEWAY_PROXY_DEMO_AUTH_SECRET_KEY}=${GATEWAY_PROXY_DEMO_UPSTREAM_KEY}" >/dev/null
}

bootstrap_gateway_demo_connection() {
  local connection_id="$GATEWAY_PROXY_DEMO_CONNECTION_ID"
  local scoped_key_env="SIGILUM_SERVICE_API_KEY_$(service_api_key_env_suffix "$connection_id")"

  if ! is_valid_slug "$connection_id"; then
    echo "Invalid GATEWAY_PROXY_DEMO_CONNECTION_ID: ${connection_id}" >&2
    return 1
  fi

  load_or_create_value "$GATEWAY_PROXY_DEMO_SECRET_FILE" GATEWAY_PROXY_DEMO_UPSTREAM_KEY generate_proxy_demo_secret
  DEMO_GATEWAY_UPSTREAM_KEY="$GATEWAY_PROXY_DEMO_UPSTREAM_KEY"
  export DEMO_GATEWAY_UPSTREAM_KEY

  if gateway_cli get --id "$connection_id" >/dev/null 2>&1; then
    if ! gateway_cli rotate --id "$connection_id" --secret "${GATEWAY_PROXY_DEMO_AUTH_SECRET_KEY}=${GATEWAY_PROXY_DEMO_UPSTREAM_KEY}" >/dev/null 2>&1; then
      gateway_cli delete --id "$connection_id" >/dev/null 2>&1 || true
      create_demo_gateway_connection
    else
      gateway_cli update \
        --id "$connection_id" \
        --name "$GATEWAY_PROXY_DEMO_SERVICE_NAME" \
        --auth-secret-key "$GATEWAY_PROXY_DEMO_AUTH_SECRET_KEY" \
        --status active >/dev/null 2>&1 || true
    fi
  else
    create_demo_gateway_connection
  fi

  echo "Bundled gateway demo ready: connection=${connection_id} base_url=${GATEWAY_PROXY_DEMO_BASE_URL} service_api_key_env=${scoped_key_env}"
  echo "  upstream secret file: ${GATEWAY_PROXY_DEMO_SECRET_FILE}"
}

bootstrap_local_registry_access() {
  local namespace="$GATEWAY_SIGILUM_NAMESPACE"
  local email="$GATEWAY_LOCAL_EMAIL"
  local gateway_service_slug="sigilum-gateway"
  local native_service_slug="$GATEWAY_NATIVE_DEMO_SERVICE_SLUG"
  local proxy_service_slug="$GATEWAY_PROXY_DEMO_CONNECTION_ID"
  local gateway_key_file="${GATEWAY_SIGILUM_HOME}/service-api-key-${gateway_service_slug}"
  local native_key_file="${GATEWAY_SIGILUM_HOME}/service-api-key-${native_service_slug}"
  local proxy_key_file="${GATEWAY_SIGILUM_HOME}/service-api-key-${proxy_service_slug}"
  local proxy_key_env="SIGILUM_SERVICE_API_KEY_$(service_api_key_env_suffix "$proxy_service_slug")"

  if ! is_valid_slug "$namespace"; then
    echo "Invalid GATEWAY_SIGILUM_NAMESPACE: ${namespace}" >&2
    return 1
  fi
  if ! is_valid_slug "$native_service_slug"; then
    echo "Invalid GATEWAY_NATIVE_DEMO_SERVICE_SLUG: ${native_service_slug}" >&2
    return 1
  fi
  if ! is_valid_slug "$proxy_service_slug"; then
    echo "Invalid GATEWAY_PROXY_DEMO_CONNECTION_ID: ${proxy_service_slug}" >&2
    return 1
  fi

  echo "Applying local API migrations..."
  (
    cd "$ROOT_DIR/apps/api"
    pnpm exec wrangler d1 migrations apply sigilum-api --local >/dev/null
  )

  load_or_create_value "$gateway_key_file" SIGILUM_SERVICE_API_KEY generate_service_api_key
  load_or_create_value "$native_key_file" DEMO_NATIVE_SIGILUM_API_KEY generate_service_api_key
  load_or_create_value "$proxy_key_file" "$proxy_key_env" generate_service_api_key
  DEMO_PROXY_SIGILUM_API_KEY="${!proxy_key_env}"
  export DEMO_PROXY_SIGILUM_API_KEY

  local gateway_service_description native_service_description proxy_service_description
  local gateway_key_name native_key_name proxy_key_name
  gateway_service_description="Local Sigilum gateway service identity for signed claims-cache lookups."
  native_service_description="Bundled native Sigilum demo service (localhost:11000)."
  proxy_service_description="Bundled non-native demo service behind local gateway (upstream localhost:11100)."
  gateway_key_name="Gateway claims cache key (local bootstrap)"
  native_key_name="Demo native service key (local bootstrap)"
  proxy_key_name="Demo gateway service key (local bootstrap)"

  echo "Local bootstrap complete for namespace=${namespace}:"
  ensure_local_service_and_key "$namespace" "$email" "$gateway_service_slug" "$GATEWAY_SERVICE_NAME" "$gateway_service_description" "$gateway_key_name" "$SIGILUM_SERVICE_API_KEY"
  ensure_local_service_and_key "$namespace" "$email" "$native_service_slug" "$GATEWAY_NATIVE_DEMO_SERVICE_NAME" "$native_service_description" "$native_key_name" "$DEMO_NATIVE_SIGILUM_API_KEY"
  ensure_local_service_and_key "$namespace" "$email" "$proxy_service_slug" "$GATEWAY_PROXY_DEMO_SERVICE_NAME" "$proxy_service_description" "$proxy_key_name" "${!proxy_key_env}"
  echo "  - native demo api key file: ${native_key_file}"
  echo "  - proxy demo api key file:  ${proxy_key_file}"
}

mkdir -p "$GATEWAY_SIGILUM_HOME"

IDENTITY_PATH="${GATEWAY_SIGILUM_HOME}/identities/${GATEWAY_SIGILUM_NAMESPACE}/identity.json"
if [[ ! -f "$IDENTITY_PATH" ]]; then
  echo "Gateway signer identity not found. Bootstrapping ${GATEWAY_SIGILUM_NAMESPACE} in ${GATEWAY_SIGILUM_HOME}..."
  tmp_go_file="$(mktemp "${TMPDIR:-/tmp}/sigilum-init-XXXXXX.go")"
  cat >"$tmp_go_file" <<'EOF'
package main

import (
	"fmt"
	"os"

	"sigilum.local/sdk-go/sigilum"
)

func main() {
	namespace := os.Getenv("SIGILUM_INIT_NAMESPACE")
	homeDir := os.Getenv("SIGILUM_INIT_HOME")
	if namespace == "" {
		fmt.Fprintln(os.Stderr, "SIGILUM_INIT_NAMESPACE is required")
		os.Exit(1)
	}

	result, err := sigilum.InitIdentity(sigilum.InitIdentityOptions{
		Namespace: namespace,
		HomeDir:   homeDir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize identity: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Initialized Sigilum identity %q at %s\n", result.Namespace, result.IdentityPath)
}
EOF

  (
    cd "$ROOT_DIR/sdks/sdk-go"
    SIGILUM_INIT_NAMESPACE="$GATEWAY_SIGILUM_NAMESPACE" \
    SIGILUM_INIT_HOME="$GATEWAY_SIGILUM_HOME" \
    go run "$tmp_go_file"
  )
  rm -f "$tmp_go_file"

  if [[ ! -f "$IDENTITY_PATH" ]]; then
    echo "Failed to initialize gateway signer identity at ${IDENTITY_PATH}" >&2
    exit 1
  fi
fi

mkdir -p "$GATEWAY_DATA_DIR"
build_gateway_binaries

if [[ "${GATEWAY_LOCAL_BOOTSTRAP}" == "true" ]]; then
  bootstrap_local_registry_access
  bootstrap_gateway_demo_connection
fi

if [[ -z "${SIGILUM_SERVICE_API_KEY:-}" ]]; then
  if [[ "${GATEWAY_ALLOW_UNSIGNED_PROXY}" == "false" ]]; then
    GATEWAY_ALLOW_UNSIGNED_PROXY="true"
    GATEWAY_ALLOW_UNSIGNED_CONNECTIONS=""
    echo "SIGILUM_SERVICE_API_KEY is not set. Enabling local unsigned proxy mode (GATEWAY_ALLOW_UNSIGNED_PROXY=true)." >&2
  else
    echo "SIGILUM_SERVICE_API_KEY is not set. Using configured unsigned proxy mode." >&2
  fi
fi

if [[ "${ENABLE_TEST_SEED_ENDPOINT}" == "true" ]] && [[ -z "${SIGILUM_TEST_SEED_TOKEN}" ]]; then
  SIGILUM_TEST_SEED_TOKEN="$(generate_seed_token)"
fi

api_dev_args=(
  --ip "${API_HOST}"
  --port "${API_PORT}"
  --var "ENVIRONMENT:${ENVIRONMENT}"
  --var "ALLOWED_ORIGINS:${ALLOWED_ORIGINS}"
  --var "WEBAUTHN_ALLOWED_ORIGINS:${WEBAUTHN_ALLOWED_ORIGINS}"
  --var "WEBAUTHN_RP_ID:${WEBAUTHN_RP_ID}"
  --var "ENABLE_TEST_SEED_ENDPOINT:${ENABLE_TEST_SEED_ENDPOINT}"
  --var "BLOCKCHAIN_MODE:${BLOCKCHAIN_MODE}"
)
if [[ "${ENABLE_TEST_SEED_ENDPOINT}" == "true" ]]; then
  api_dev_args+=(--var "SIGILUM_TEST_SEED_TOKEN:${SIGILUM_TEST_SEED_TOKEN}")
fi

echo "Starting API on http://${API_HOST}:${API_PORT} (ENVIRONMENT=${ENVIRONMENT}, BLOCKCHAIN_MODE=${BLOCKCHAIN_MODE}, test_seed=${ENABLE_TEST_SEED_ENDPOINT})"
(
  cd "$ROOT_DIR/apps/api"
  pnpm exec wrangler dev "${api_dev_args[@]}"
) &
API_PID=$!

gateway_start_cmd="go run ./cmd/sigilum-gateway"
if [[ "${GATEWAY_BUILD_BINARIES}" == "true" && -x "$GATEWAY_SERVICE_BINARY" ]]; then
  gateway_start_cmd="$GATEWAY_SERVICE_BINARY"
fi

echo "Starting Gateway on ${GATEWAY_ADDR} (registry=${SIGILUM_REGISTRY_URL}, cmd=${gateway_start_cmd})"
(
  cd "$ROOT_DIR/apps/gateway/service"
  export BLOCKCHAIN_MODE="$BLOCKCHAIN_MODE"
  export SIGILUM_REGISTRY_URL="$SIGILUM_REGISTRY_URL"
  export SIGILUM_API_URL="$SIGILUM_API_URL"
  export GATEWAY_ADDR="$GATEWAY_ADDR"
  export GATEWAY_DATA_DIR="$GATEWAY_DATA_DIR"
  export GATEWAY_SERVICE_CATALOG_FILE="$GATEWAY_SERVICE_CATALOG_FILE"
  export GATEWAY_MASTER_KEY="$GATEWAY_MASTER_KEY"
  export GATEWAY_SIGILUM_NAMESPACE="$GATEWAY_SIGILUM_NAMESPACE"
  export GATEWAY_SIGILUM_HOME="$GATEWAY_SIGILUM_HOME"
  export GATEWAY_ALLOWED_ORIGINS="$GATEWAY_ALLOWED_ORIGINS"
  export GATEWAY_ALLOW_UNSIGNED_PROXY="$GATEWAY_ALLOW_UNSIGNED_PROXY"
  export GATEWAY_ALLOW_UNSIGNED_CONNECTIONS="$GATEWAY_ALLOW_UNSIGNED_CONNECTIONS"
  export SIGILUM_SERVICE_API_KEY="${SIGILUM_SERVICE_API_KEY:-}"

  if [[ "${GATEWAY_BUILD_BINARIES}" == "true" && -x "$GATEWAY_SERVICE_BINARY" ]]; then
    "$GATEWAY_SERVICE_BINARY"
  else
    go run ./cmd/sigilum-gateway
  fi
) &
GATEWAY_PID=$!

cleanup() {
  set +e
  if [[ -n "${GATEWAY_PID:-}" ]] && kill -0 "$GATEWAY_PID" 2>/dev/null; then
    kill "$GATEWAY_PID" 2>/dev/null || true
  fi
  if [[ -n "${API_PID:-}" ]] && kill -0 "$API_PID" 2>/dev/null; then
    kill "$API_PID" 2>/dev/null || true
  fi
  wait "$GATEWAY_PID" "$API_PID" 2>/dev/null || true
}

trap cleanup INT TERM EXIT

exit_code=0
while true; do
  if ! kill -0 "$API_PID" 2>/dev/null; then
    wait "$API_PID" || exit_code=$?
    echo "API process exited."
    break
  fi
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    wait "$GATEWAY_PID" || exit_code=$?
    echo "Gateway process exited."
    break
  fi
  sleep 1
done

exit "$exit_code"
