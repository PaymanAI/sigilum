#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Sigilum Local Service CLI

Usage:
  sigilum service add [options]
  sigilum service help

Options for add:
  --service-slug <slug>          Required. Lowercase slug (3-64 chars).
  --service-name <name>          Optional. Defaults to slug.
  --description <text>           Optional. Service description.
  --domain <domain>              Optional. Defaults to localhost.
  --namespace <namespace>        Optional. Defaults to GATEWAY_SIGILUM_NAMESPACE or johndee.
  --email <email>                Optional. Defaults to <namespace>@local.sigilum.
  --mode <native|gateway>        Optional. Defaults to native.

Gateway mode options:
  --upstream-base-url <url>      Required when --mode gateway.
  --auth-mode <mode>             Optional. bearer|header_key (default: bearer).
  --upstream-header <name>       Optional. Defaults depend on auth mode.
  --auth-prefix <value>          Optional. Defaults depend on auth mode.
  --upstream-secret-key <key>    Optional. Secret key name used by gateway.
  --upstream-secret <value>      Optional. Upstream token/secret value.
  --upstream-secret-env <name>   Optional. Read token/secret from env var.
  --upstream-secret-file <path>  Optional. Read token/secret from file.
                                 If no secret source is set, a random secret is generated.
  --gateway-admin-url <url>      Optional. Defaults to http://127.0.0.1:38100.
  --gateway-data-dir <path>      Optional. Defaults to .local/gateway-data.
  --gateway-master-key <value>   Optional. Defaults to sigilum-local-dev-master-key.

Examples:
  sigilum service add \
    --service-slug my-native-service \
    --service-name "My Native Service" \
    --mode native

  sigilum service add \
    --service-slug my-proxy-service \
    --service-name "My Proxy Service" \
    --mode gateway \
    --upstream-base-url http://127.0.0.1:12000 \
    --auth-mode bearer \
    --upstream-secret-env LINEAR_TOKEN
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

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

generate_upstream_secret() {
  node -e "const crypto=require('node:crypto'); process.stdout.write('gw_'+crypto.randomBytes(24).toString('hex'));"
}

sha256_hex() {
  local value="$1"
  VALUE_TO_HASH="$value" \
    node -e "const crypto=require('node:crypto'); process.stdout.write(crypto.createHash('sha256').update(process.env.VALUE_TO_HASH,'utf8').digest('hex'));"
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

  umask 077
  printf "%s\n" "$value" >"$file_path"

  printf -v "$variable_name" "%s" "$value"
  export "$variable_name"
}

ensure_local_user_service_and_key() {
  local namespace="$1"
  local email="$2"
  local service_slug="$3"
  local service_name="$4"
  local domain="$5"
  local service_description="$6"
  local key_name="$7"
  local key_value="$8"

  local key_hash key_prefix key_id user_id service_id
  key_hash="$(sha256_hex "$key_value")"
  key_prefix="...${key_value: -4}"
  key_id="key_local_${service_slug}_${key_hash:0:12}"
  user_id="user_local_${namespace}"
  service_id="svc_local_${service_slug}"

  local ns_sql email_sql slug_sql name_sql domain_sql desc_sql key_name_sql key_id_sql service_id_sql user_id_sql key_prefix_sql key_hash_sql
  ns_sql="$(sql_escape "$namespace")"
  email_sql="$(sql_escape "$email")"
  slug_sql="$(sql_escape "$service_slug")"
  name_sql="$(sql_escape "$service_name")"
  domain_sql="$(sql_escape "$domain")"
  desc_sql="$(sql_escape "$service_description")"
  key_name_sql="$(sql_escape "$key_name")"
  key_id_sql="$(sql_escape "$key_id")"
  service_id_sql="$(sql_escape "$service_id")"
  user_id_sql="$(sql_escape "$user_id")"
  key_prefix_sql="$(sql_escape "$key_prefix")"
  key_hash_sql="$(sql_escape "$key_hash")"

  run_local_d1 "INSERT OR IGNORE INTO users (id, email, namespace, plan, settings) VALUES ('${user_id_sql}', '${email_sql}', '${ns_sql}', 'free', '{}');"
  run_local_d1 "INSERT OR IGNORE INTO services (id, owner_user_id, name, slug, domain, description, updated_at) SELECT '${service_id_sql}', id, '${name_sql}', '${slug_sql}', '${domain_sql}', '${desc_sql}', strftime('%Y-%m-%dT%H:%M:%fZ', 'now') FROM users WHERE namespace = '${ns_sql}' LIMIT 1;"
  run_local_d1 "UPDATE services SET name = '${name_sql}', domain = '${domain_sql}', description = '${desc_sql}', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE slug = '${slug_sql}' AND owner_user_id IN (SELECT id FROM users WHERE namespace = '${ns_sql}' LIMIT 1);"
  run_local_d1 "INSERT OR IGNORE INTO service_api_keys (id, service_id, name, key_prefix, key_hash) SELECT '${key_id_sql}', s.id, '${key_name_sql}', '${key_prefix_sql}', '${key_hash_sql}' FROM services s JOIN users u ON u.id = s.owner_user_id WHERE s.slug = '${slug_sql}' AND u.namespace = '${ns_sql}' LIMIT 1;"
  run_local_d1 "UPDATE service_api_keys SET name = '${key_name_sql}', revoked_at = NULL WHERE service_id IN (SELECT s.id FROM services s JOIN users u ON u.id = s.owner_user_id WHERE s.slug = '${slug_sql}' AND u.namespace = '${ns_sql}' LIMIT 1) AND key_hash = '${key_hash_sql}';"

  echo "Registered service in local API DB:"
  echo "  namespace: ${namespace}"
  echo "  service:   ${service_slug}"
  echo "  key:       ${key_prefix}"
}

gateway_cli() {
  (
    cd "$ROOT_DIR/apps/gateway/service"
    GATEWAY_DATA_DIR="$GATEWAY_DATA_DIR" \
    GATEWAY_MASTER_KEY="$GATEWAY_MASTER_KEY" \
    go run ./cmd/sigilum-gateway-cli "$@"
  )
}

gateway_admin_upsert_connection() {
  local connection_id="$1"
  local connection_name="$2"
  local upstream_base_url="$3"
  local auth_mode="$4"
  local upstream_header="$5"
  local auth_prefix="$6"
  local upstream_secret_key="$7"
  local upstream_secret="$8"

  local get_status
  get_status="$(curl -sS -o /dev/null -w "%{http_code}" "${GATEWAY_ADMIN_URL}/api/admin/connections/${connection_id}" || true)"
  if [[ "$get_status" == "200" ]]; then
    curl -sS -X DELETE "${GATEWAY_ADMIN_URL}/api/admin/connections/${connection_id}" >/dev/null
  fi

  local payload
  payload="$(CONNECTION_ID="$connection_id" \
    CONNECTION_NAME="$connection_name" \
    BASE_URL="$upstream_base_url" \
    AUTH_MODE="$auth_mode" \
    AUTH_HEADER="$upstream_header" \
    AUTH_PREFIX="$auth_prefix" \
    AUTH_SECRET_KEY="$upstream_secret_key" \
    AUTH_SECRET_VALUE="$upstream_secret" \
    node -e '
const payload = {
  id: process.env.CONNECTION_ID,
  name: process.env.CONNECTION_NAME,
  base_url: process.env.BASE_URL,
  auth_mode: process.env.AUTH_MODE,
  auth_header_name: process.env.AUTH_HEADER,
  auth_prefix: process.env.AUTH_PREFIX,
  auth_secret_key: process.env.AUTH_SECRET_KEY,
  secrets: { [process.env.AUTH_SECRET_KEY]: process.env.AUTH_SECRET_VALUE },
};
process.stdout.write(JSON.stringify(payload));
')"

  local response_file
  response_file="$(mktemp "${TMPDIR:-/tmp}/sigilum-gw-admin-XXXXXX.json")"
  local status
  status="$(curl -sS -o "$response_file" -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -X POST "${GATEWAY_ADMIN_URL}/api/admin/connections" \
    --data "$payload")"
  if [[ "$status" != "201" ]]; then
    echo "Failed to configure gateway connection via admin API (HTTP ${status})" >&2
    cat "$response_file" >&2 || true
    rm -f "$response_file"
    return 1
  fi
  rm -f "$response_file"
}

gateway_cli_upsert_connection() {
  local connection_id="$1"
  local connection_name="$2"
  local upstream_base_url="$3"
  local auth_mode="$4"
  local upstream_header="$5"
  local auth_prefix="$6"
  local upstream_secret_key="$7"
  local upstream_secret="$8"

  gateway_cli get --id "$connection_id" >/dev/null 2>&1 && gateway_cli delete --id "$connection_id" >/dev/null 2>&1 || true
  local -a args
  args=(
    add
    --id "$connection_id"
    --name "$connection_name"
    --base-url "$upstream_base_url"
    --auth-mode "$auth_mode"
    --auth-header-name "$upstream_header"
    --auth-secret-key "$upstream_secret_key"
    --secret "${upstream_secret_key}=${upstream_secret}"
  )
  if [[ -n "$auth_prefix" ]]; then
    args+=(--auth-prefix "$auth_prefix")
  fi
  gateway_cli "${args[@]}" >/dev/null
}

configure_gateway_connection() {
  local connection_id="$1"
  local connection_name="$2"
  local upstream_base_url="$3"
  local auth_mode="$4"
  local upstream_header="$5"
  local auth_prefix="$6"
  local upstream_secret_key="$7"
  local upstream_secret="$8"

  if curl -sf "${GATEWAY_ADMIN_URL}/health" >/dev/null 2>&1; then
    gateway_admin_upsert_connection "$connection_id" "$connection_name" "$upstream_base_url" "$auth_mode" "$upstream_header" "$auth_prefix" "$upstream_secret_key" "$upstream_secret"
    echo "Configured gateway connection via admin API at ${GATEWAY_ADMIN_URL}: ${connection_id}"
    return 0
  fi

  require_cmd go
  gateway_cli_upsert_connection "$connection_id" "$connection_name" "$upstream_base_url" "$auth_mode" "$upstream_header" "$auth_prefix" "$upstream_secret_key" "$upstream_secret"
  echo "Configured gateway connection via CLI store (${GATEWAY_DATA_DIR}): ${connection_id}"
}

add_service() {
  require_cmd pnpm
  require_cmd node

  local namespace="${GATEWAY_SIGILUM_NAMESPACE:-johndee}"
  local service_slug=""
  local service_name=""
  local description=""
  local domain="localhost"
  local email=""
  local mode="native"

  local upstream_base_url=""
  local auth_mode="bearer"
  local upstream_header=""
  local auth_prefix=""
  local upstream_secret_key=""
  local upstream_secret=""
  local upstream_secret_env=""
  local upstream_secret_input_file=""

  GATEWAY_ADMIN_URL="${GATEWAY_ADMIN_URL:-http://127.0.0.1:38100}"
  GATEWAY_DATA_DIR="${GATEWAY_DATA_DIR:-${ROOT_DIR}/.local/gateway-data}"
  GATEWAY_MASTER_KEY="${GATEWAY_MASTER_KEY:-sigilum-local-dev-master-key}"
  SIGILUM_HOME_DIR="${GATEWAY_SIGILUM_HOME:-${ROOT_DIR}/.sigilum-workspace}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --service-slug)
        service_slug="${2:-}"
        shift 2
        ;;
      --service-name)
        service_name="${2:-}"
        shift 2
        ;;
      --description)
        description="${2:-}"
        shift 2
        ;;
      --domain)
        domain="${2:-}"
        shift 2
        ;;
      --namespace)
        namespace="${2:-}"
        shift 2
        ;;
      --email)
        email="${2:-}"
        shift 2
        ;;
      --mode)
        mode="${2:-}"
        shift 2
        ;;
      --upstream-base-url)
        upstream_base_url="${2:-}"
        shift 2
        ;;
      --auth-mode)
        auth_mode="${2:-}"
        shift 2
        ;;
      --upstream-header)
        upstream_header="${2:-}"
        shift 2
        ;;
      --auth-prefix)
        auth_prefix="${2:-}"
        shift 2
        ;;
      --upstream-secret-key)
        upstream_secret_key="${2:-}"
        shift 2
        ;;
      --upstream-secret)
        upstream_secret="${2:-}"
        shift 2
        ;;
      --upstream-secret-env)
        upstream_secret_env="${2:-}"
        shift 2
        ;;
      --upstream-secret-file)
        upstream_secret_input_file="${2:-}"
        shift 2
        ;;
      --gateway-admin-url)
        GATEWAY_ADMIN_URL="${2:-}"
        shift 2
        ;;
      --gateway-data-dir)
        GATEWAY_DATA_DIR="${2:-}"
        shift 2
        ;;
      --gateway-master-key)
        GATEWAY_MASTER_KEY="${2:-}"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        echo "Unknown option: $1" >&2
        usage
        exit 1
        ;;
    esac
  done

  if [[ -z "$service_slug" ]]; then
    echo "--service-slug is required" >&2
    usage
    exit 1
  fi
  if ! is_valid_slug "$service_slug"; then
    echo "Invalid --service-slug: ${service_slug}" >&2
    echo "Expected: lowercase [a-z0-9-], 3-64 chars, must start/end with alnum." >&2
    exit 1
  fi
  if ! is_valid_slug "$namespace"; then
    echo "Invalid --namespace: ${namespace}" >&2
    exit 1
  fi
  if [[ "$mode" != "native" && "$mode" != "gateway" ]]; then
    echo "Invalid --mode: ${mode} (expected native or gateway)" >&2
    exit 1
  fi
  if [[ "$auth_mode" != "bearer" && "$auth_mode" != "header_key" ]]; then
    echo "Invalid --auth-mode: ${auth_mode} (expected bearer or header_key)" >&2
    exit 1
  fi
  if [[ -z "$service_name" ]]; then
    service_name="$service_slug"
  fi
  if [[ -z "$email" ]]; then
    email="${namespace}@local.sigilum"
  fi
  if [[ -z "$description" ]]; then
    if [[ "$mode" == "gateway" ]]; then
      description="Local proxy service routed through Sigilum gateway."
    else
      description="Local native Sigilum service."
    fi
  fi

  mkdir -p "$SIGILUM_HOME_DIR"

  echo "Applying local API migrations..."
  (
    cd "$ROOT_DIR/apps/api"
    pnpm exec wrangler d1 migrations apply sigilum-api --local >/dev/null
  )

  local key_name api_key_file
  if [[ "$mode" == "gateway" ]]; then
    key_name="Gateway proxy service key (local cli)"
  else
    key_name="Native service key (local cli)"
  fi
  api_key_file="${SIGILUM_HOME_DIR}/service-api-key-${service_slug}"
  load_or_create_value "$api_key_file" SERVICE_API_KEY generate_service_api_key

  ensure_local_user_service_and_key \
    "$namespace" \
    "$email" \
    "$service_slug" \
    "$service_name" \
    "$domain" \
    "$description" \
    "$key_name" \
    "$SERVICE_API_KEY"

  if [[ "$mode" == "gateway" ]]; then
    if [[ -z "$upstream_base_url" ]]; then
      echo "--upstream-base-url is required when --mode gateway" >&2
      exit 1
    fi
    if [[ -z "$upstream_secret_key" ]]; then
      if [[ "$auth_mode" == "bearer" ]]; then
        upstream_secret_key="access_token"
      else
        upstream_secret_key="upstream_key"
      fi
    fi
    if [[ -z "$upstream_header" ]]; then
      if [[ "$auth_mode" == "bearer" ]]; then
        upstream_header="Authorization"
      else
        upstream_header="X-${service_slug}-Key"
      fi
    fi
    if [[ -z "$auth_prefix" ]]; then
      if [[ "$auth_mode" == "bearer" ]]; then
        auth_prefix="Bearer "
      else
        auth_prefix=""
      fi
    fi

    local persisted_upstream_secret_file
    persisted_upstream_secret_file="${SIGILUM_HOME_DIR}/gateway-connection-secret-${service_slug}"
    local secret_sources=0
    if [[ -n "$upstream_secret" ]]; then
      secret_sources=$((secret_sources + 1))
    fi
    if [[ -n "$upstream_secret_env" ]]; then
      secret_sources=$((secret_sources + 1))
    fi
    if [[ -n "$upstream_secret_input_file" ]]; then
      secret_sources=$((secret_sources + 1))
    fi
    if [[ "$secret_sources" -gt 1 ]]; then
      echo "Use only one of: --upstream-secret, --upstream-secret-env, --upstream-secret-file" >&2
      exit 1
    fi

    UPSTREAM_SECRET=""
    if [[ -n "$upstream_secret" ]]; then
      UPSTREAM_SECRET="$upstream_secret"
    elif [[ -n "$upstream_secret_env" ]]; then
      if [[ -z "${!upstream_secret_env:-}" ]]; then
        echo "Environment variable ${upstream_secret_env} is not set" >&2
        exit 1
      fi
      UPSTREAM_SECRET="${!upstream_secret_env}"
    elif [[ -n "$upstream_secret_input_file" ]]; then
      if [[ ! -f "$upstream_secret_input_file" ]]; then
        echo "Upstream secret file not found: ${upstream_secret_input_file}" >&2
        exit 1
      fi
      UPSTREAM_SECRET="$(tr -d '\r\n' <"$upstream_secret_input_file")"
    fi
    load_or_create_value "$persisted_upstream_secret_file" UPSTREAM_SECRET generate_upstream_secret

    configure_gateway_connection \
      "$service_slug" \
      "$service_name" \
      "$upstream_base_url" \
      "$auth_mode" \
      "$upstream_header" \
      "$auth_prefix" \
      "$upstream_secret_key" \
      "$UPSTREAM_SECRET"

    echo ""
    echo "Gateway mode configured:"
    echo "  connection id: ${service_slug}"
    echo "  upstream url:  ${upstream_base_url}"
    echo "  auth mode:     ${auth_mode}"
    echo "  auth header:   ${upstream_header}"
    echo "  auth prefix:   ${auth_prefix}"
    echo "  secret key:    ${upstream_secret_key}"
    echo "  secret file:   ${persisted_upstream_secret_file}"
  fi

  local scoped_env
  scoped_env="SIGILUM_SERVICE_API_KEY_$(service_api_key_env_suffix "$service_slug")"

  echo ""
  echo "Service registration complete."
  echo "  mode:                 ${mode}"
  echo "  namespace:            ${namespace}"
  echo "  service slug:         ${service_slug}"
  echo "  service name:         ${service_name}"
  echo "  API key file:         ${api_key_file}"
  echo "  gateway scoped env:   ${scoped_env}"
  echo "  API key value:        ${SERVICE_API_KEY}"
  echo ""
  echo "Usage hints:"
  if [[ "$mode" == "native" ]]; then
    echo "  native service env:   SIGILUM_API_KEY=\$(cat ${api_key_file})"
    echo "  gateway env (optional): export ${scoped_env}=\$(cat ${api_key_file})"
    echo "  gateway also auto-resolves key from: ${api_key_file}"
  else
    echo "  gateway env (optional): export ${scoped_env}=\$(cat ${api_key_file})"
    echo "  gateway auto-resolves key from: ${api_key_file}"
    echo "  upstream secret:      \$(cat ${SIGILUM_HOME_DIR}/gateway-connection-secret-${service_slug})"
  fi
}

main() {
  local command="${1:-help}"
  shift || true

  case "$command" in
    add)
      add_service "$@"
      ;;
    help|-h|--help)
      usage
      ;;
    *)
      echo "Unknown command: ${command}" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
