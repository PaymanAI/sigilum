#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sigilum-service-common.sh
source "${SCRIPT_DIR}/sigilum-service-common.sh"

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
  get_status="$(curl_with_timeout -sS -o /dev/null -w "%{http_code}" "${GATEWAY_ADMIN_URL}/api/admin/connections/${connection_id}" || true)"
  if [[ "$get_status" == "200" ]]; then
    curl_with_timeout -sS -X DELETE "${GATEWAY_ADMIN_URL}/api/admin/connections/${connection_id}" >/dev/null
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
  status="$(curl_with_timeout -sS -o "$response_file" -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -X POST "${GATEWAY_ADMIN_URL}/api/admin/connections" \
    --data "$payload")"
  if [[ "$status" != "201" ]]; then
    log_error "Failed to configure gateway connection via admin API (HTTP ${status})"
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

  if gateway_cli get --id "$connection_id" >/dev/null 2>&1; then
    gateway_cli delete --id "$connection_id" >/dev/null 2>&1 || true
  fi
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

  if curl_with_timeout -sf "${GATEWAY_ADMIN_URL}/health" >/dev/null 2>&1; then
    gateway_admin_upsert_connection "$connection_id" "$connection_name" "$upstream_base_url" "$auth_mode" "$upstream_header" "$auth_prefix" "$upstream_secret_key" "$upstream_secret"
    log_ok "Configured gateway connection via admin API at ${GATEWAY_ADMIN_URL}: ${connection_id}"
    return 0
  fi

  require_cmd go
  gateway_cli_upsert_connection "$connection_id" "$connection_name" "$upstream_base_url" "$auth_mode" "$upstream_header" "$auth_prefix" "$upstream_secret_key" "$upstream_secret"
  log_ok "Configured gateway connection via CLI store (${GATEWAY_DATA_DIR}): ${connection_id}"
}

add_service() {
  require_cmd pnpm
  require_cmd node
  ensure_api_wrangler_config

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
  local reveal_secrets="false"

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
      --reveal-secrets|--reveal)
        reveal_secrets="true"
        shift
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
        log_error "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done

  if [[ -z "$service_slug" ]]; then
    log_error "--service-slug is required"
    usage
    exit 1
  fi
  if ! is_valid_slug "$service_slug"; then
    log_error "Invalid --service-slug: ${service_slug}"
    log_error "Expected: lowercase [a-z0-9-], 3-64 chars, must start/end with alnum."
    exit 1
  fi
  if ! is_valid_slug "$namespace"; then
    log_error "Invalid --namespace: ${namespace}"
    exit 1
  fi
  if [[ "$mode" != "native" && "$mode" != "gateway" ]]; then
    log_error "Invalid --mode: ${mode} (expected native or gateway)"
    exit 1
  fi
  if [[ "$auth_mode" != "bearer" && "$auth_mode" != "header_key" && "$auth_mode" != "query_param" ]]; then
    log_error "Invalid --auth-mode: ${auth_mode} (expected bearer, header_key, or query_param)"
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

  log_step "Applying local API migrations..."
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
      log_error "--upstream-base-url is required when --mode gateway"
      exit 1
    fi
    if [[ -z "$upstream_secret_key" ]]; then
      if [[ "$auth_mode" == "bearer" ]]; then
        upstream_secret_key="access_token"
      elif [[ "$auth_mode" == "query_param" ]]; then
        upstream_secret_key="api_key"
      else
        upstream_secret_key="upstream_key"
      fi
    fi
    if [[ -z "$upstream_header" ]]; then
      if [[ "$auth_mode" == "bearer" ]]; then
        upstream_header="Authorization"
      elif [[ "$auth_mode" == "query_param" ]]; then
        upstream_header="api_key"
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
      log_error "Use only one of: --upstream-secret, --upstream-secret-env, --upstream-secret-file"
      exit 1
    fi

    UPSTREAM_SECRET=""
    if [[ -n "$upstream_secret" ]]; then
      UPSTREAM_SECRET="$upstream_secret"
    elif [[ -n "$upstream_secret_env" ]]; then
      if [[ -z "${!upstream_secret_env:-}" ]]; then
        log_error "Environment variable ${upstream_secret_env} is not set"
        exit 1
      fi
      UPSTREAM_SECRET="${!upstream_secret_env}"
    elif [[ -n "$upstream_secret_input_file" ]]; then
      if [[ ! -f "$upstream_secret_input_file" ]]; then
        log_error "Upstream secret file not found: ${upstream_secret_input_file}"
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

    print_section "Gateway Mode Configured"
    print_kv "connection id:" "${service_slug}"
    print_kv "upstream url:" "${upstream_base_url}"
    print_kv "auth mode:" "${auth_mode}"
    print_kv "auth header:" "${upstream_header}"
    print_kv "auth prefix:" "${auth_prefix}"
    print_kv "secret key:" "${upstream_secret_key}"
    print_kv "secret file:" "${persisted_upstream_secret_file}"
  fi

  local scoped_env
  scoped_env="SIGILUM_SERVICE_API_KEY_$(service_api_key_env_suffix "$service_slug")"

  print_section "Service Registration Complete"
  print_kv "mode:" "${mode}"
  print_kv "namespace:" "${namespace}"
  print_kv "service slug:" "${service_slug}"
  print_kv "service name:" "${service_name}"
  print_kv "API key file:" "${api_key_file}"
  print_kv "gateway env:" "${scoped_env}"
  if [[ "$reveal_secrets" == "true" ]]; then
    print_kv "API key value:" "${SERVICE_API_KEY}"
  else
    print_kv "API key value:" "$(mask_secret "$SERVICE_API_KEY") (hidden; use --reveal-secrets to print)"
  fi
  print_section "Usage Hints"
  if [[ "$mode" == "native" ]]; then
    print_kv "native env:" "SIGILUM_API_KEY=\$(cat ${api_key_file})"
    print_kv "gateway env:" "export ${scoped_env}=\$(cat ${api_key_file})"
    print_kv "key fallback:" "${api_key_file}"
  else
    print_kv "gateway env:" "export ${scoped_env}=\$(cat ${api_key_file})"
    print_kv "key fallback:" "${api_key_file}"
    print_kv "upstream secret:" "\$(cat ${SIGILUM_HOME_DIR}/gateway-connection-secret-${service_slug})"
  fi
}


main() {
  if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
    usage
    exit 0
  fi
  add_service "$@"
}

main "$@"
