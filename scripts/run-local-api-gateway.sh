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

: "${API_PORT:=8787}"
: "${BLOCKCHAIN_MODE:=disabled}"
: "${SIGILUM_REGISTRY_URL:=http://127.0.0.1:${API_PORT}}"
: "${SIGILUM_API_URL:=${SIGILUM_REGISTRY_URL}}"

: "${GATEWAY_ADDR:=:38100}"
: "${GATEWAY_DATA_DIR:=${ROOT_DIR}/.local/gateway-data}"
: "${GATEWAY_SERVICE_CATALOG_FILE:=${GATEWAY_DATA_DIR}/service-catalog.json}"
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

bootstrap_local_registry_access() {
  local namespace="$GATEWAY_SIGILUM_NAMESPACE"
  local service_slug="sigilum-gateway"
  local service_name="$GATEWAY_SERVICE_NAME"
  local email="$GATEWAY_LOCAL_EMAIL"
  local key_file="${GATEWAY_SIGILUM_HOME}/service-api-key-${service_slug}"

  if [[ ! "$namespace" =~ ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$ ]]; then
    echo "Invalid GATEWAY_SIGILUM_NAMESPACE: ${namespace}" >&2
    return 1
  fi
  echo "Applying local API migrations..."
  (
    cd "$ROOT_DIR/apps/api"
    pnpm exec wrangler d1 migrations apply sigilum-api --local >/dev/null
  )

  if [[ -z "${SIGILUM_SERVICE_API_KEY:-}" && -f "$key_file" ]]; then
    SIGILUM_SERVICE_API_KEY="$(tr -d '\r\n' <"$key_file")"
  fi
  if [[ -z "${SIGILUM_SERVICE_API_KEY:-}" ]]; then
    SIGILUM_SERVICE_API_KEY="$(
      node -e "const crypto=require('node:crypto'); process.stdout.write('sk_live_'+crypto.randomBytes(24).toString('hex'));"
    )"
    umask 077
    printf "%s\n" "$SIGILUM_SERVICE_API_KEY" >"$key_file"
  fi
  export SIGILUM_SERVICE_API_KEY

  local key_hash
  key_hash="$(
    SIGILUM_SERVICE_API_KEY="$SIGILUM_SERVICE_API_KEY" \
      node -e "const crypto=require('node:crypto'); process.stdout.write(crypto.createHash('sha256').update(process.env.SIGILUM_SERVICE_API_KEY,'utf8').digest('hex'));"
  )"
  local key_prefix="...${SIGILUM_SERVICE_API_KEY: -4}"
  local key_id="key_local_${service_slug}_${key_hash:0:12}"
  local user_id="user_local_${namespace}"
  local service_id="svc_local_${service_slug}"

  local ns_sql email_sql slug_sql name_sql key_id_sql service_id_sql user_id_sql key_prefix_sql key_hash_sql
  ns_sql="$(sql_escape "$namespace")"
  email_sql="$(sql_escape "$email")"
  slug_sql="$(sql_escape "$service_slug")"
  name_sql="$(sql_escape "$service_name")"
  key_id_sql="$(sql_escape "$key_id")"
  service_id_sql="$(sql_escape "$service_id")"
  user_id_sql="$(sql_escape "$user_id")"
  key_prefix_sql="$(sql_escape "$key_prefix")"
  key_hash_sql="$(sql_escape "$key_hash")"

  run_local_d1 "INSERT OR IGNORE INTO users (id, email, namespace, plan, settings) VALUES ('${user_id_sql}', '${email_sql}', '${ns_sql}', 'free', '{}');"
  run_local_d1 "INSERT OR IGNORE INTO services (id, owner_user_id, name, slug, domain, description) SELECT '${service_id_sql}', id, '${name_sql}', '${slug_sql}', 'localhost', 'Local bootstrap service' FROM users WHERE namespace = '${ns_sql}' LIMIT 1;"
  run_local_d1 "INSERT OR IGNORE INTO service_api_keys (id, service_id, name, key_prefix, key_hash) SELECT '${key_id_sql}', id, 'Local bootstrap key', '${key_prefix_sql}', '${key_hash_sql}' FROM services WHERE slug = '${slug_sql}' LIMIT 1;"

  echo "Local bootstrap complete: namespace=${namespace}, service=${service_slug}, service_api_key=${key_prefix}"
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

if [[ "${GATEWAY_LOCAL_BOOTSTRAP}" == "true" ]]; then
  bootstrap_local_registry_access
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

echo "Starting API on http://127.0.0.1:${API_PORT} (BLOCKCHAIN_MODE=${BLOCKCHAIN_MODE})"
(
  cd "$ROOT_DIR/apps/api"
  BLOCKCHAIN_MODE="$BLOCKCHAIN_MODE" pnpm dev -- --port "$API_PORT"
) &
API_PID=$!

echo "Starting Gateway on ${GATEWAY_ADDR} (registry=${SIGILUM_REGISTRY_URL})"
(
  cd "$ROOT_DIR/apps/gateway/service"
  BLOCKCHAIN_MODE="$BLOCKCHAIN_MODE" \
  SIGILUM_REGISTRY_URL="$SIGILUM_REGISTRY_URL" \
  SIGILUM_API_URL="$SIGILUM_API_URL" \
  GATEWAY_ADDR="$GATEWAY_ADDR" \
  GATEWAY_DATA_DIR="$GATEWAY_DATA_DIR" \
  GATEWAY_SERVICE_CATALOG_FILE="$GATEWAY_SERVICE_CATALOG_FILE" \
  GATEWAY_MASTER_KEY="$GATEWAY_MASTER_KEY" \
  GATEWAY_SIGILUM_NAMESPACE="$GATEWAY_SIGILUM_NAMESPACE" \
  GATEWAY_SIGILUM_HOME="$GATEWAY_SIGILUM_HOME" \
  GATEWAY_ALLOW_UNSIGNED_PROXY="$GATEWAY_ALLOW_UNSIGNED_PROXY" \
  GATEWAY_ALLOW_UNSIGNED_CONNECTIONS="$GATEWAY_ALLOW_UNSIGNED_CONNECTIONS" \
  SIGILUM_SERVICE_API_KEY="${SIGILUM_SERVICE_API_KEY:-}" \
  go run ./cmd/sigilum-gateway
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
