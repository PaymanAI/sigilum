#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/sigilum-service-common.sh"

set_service_secret() {
  require_cmd node

  local service_slug=""
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
    exit 1
  fi
  if ! is_valid_slug "$service_slug"; then
    log_error "Invalid --service-slug: ${service_slug}"
    exit 1
  fi

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
  if [[ "$secret_sources" -ne 1 ]]; then
    log_error "Provide exactly one secret source: --upstream-secret, --upstream-secret-env, or --upstream-secret-file"
    exit 1
  fi

  local resolved_secret
  if [[ -n "$upstream_secret" ]]; then
    resolved_secret="$upstream_secret"
  elif [[ -n "$upstream_secret_env" ]]; then
    if [[ -z "${!upstream_secret_env:-}" ]]; then
      log_error "Environment variable ${upstream_secret_env} is not set"
      exit 1
    fi
    resolved_secret="${!upstream_secret_env}"
  else
    if [[ ! -f "$upstream_secret_input_file" ]]; then
      log_error "Upstream secret file not found: ${upstream_secret_input_file}"
      exit 1
    fi
    resolved_secret="$(tr -d '\r\n' <"$upstream_secret_input_file")"
  fi

  if [[ -z "$resolved_secret" ]]; then
    log_error "Resolved secret is empty."
    exit 1
  fi

  local connection_json
  if ! connection_json="$(gateway_get_connection_json "$service_slug" 2>/dev/null)"; then
    log_error "Gateway connection not found: ${service_slug}"
    log_error "Create it first with: sigilum service add --service-slug ${service_slug} --mode gateway ..."
    exit 1
  fi

  if [[ -z "$upstream_secret_key" ]]; then
    upstream_secret_key="$(printf "%s" "$connection_json" | node -e '
const fs = require("fs");
const raw = fs.readFileSync(0, "utf8");
let parsed = {};
try {
  parsed = JSON.parse(raw);
} catch {}
const key = typeof parsed.auth_secret_key === "string" ? parsed.auth_secret_key.trim() : "";
process.stdout.write(key);
')"
  fi
  if [[ -z "$upstream_secret_key" ]]; then
    upstream_secret_key="access_token"
  fi

  if ! gateway_rotate_connection_secret "$service_slug" "$upstream_secret_key" "$resolved_secret"; then
    exit 1
  fi

  mkdir -p "$SIGILUM_HOME_DIR"
  local persisted_upstream_secret_file
  persisted_upstream_secret_file="${SIGILUM_HOME_DIR}/gateway-connection-secret-${service_slug}"
  umask 077
  printf "%s\n" "$resolved_secret" >"$persisted_upstream_secret_file"

  print_section "Gateway Connection Secret Updated"
  print_kv "connection id:" "${service_slug}"
  print_kv "secret key:" "${upstream_secret_key}"
  print_kv "secret file:" "${persisted_upstream_secret_file}"
  if [[ "$reveal_secrets" == "true" ]]; then
    print_kv "secret value:" "${resolved_secret}"
  else
    print_kv "secret value:" "$(mask_secret "$resolved_secret") (hidden; use --reveal-secrets to print)"
  fi
}


main() {
  local secret_command="${1:-set}"
  if [[ $# -gt 0 ]]; then
    shift
  fi
  case "$secret_command" in
    set)
      set_service_secret "$@"
      ;;
    help|-h|--help|"")
      usage
      ;;
    *)
      echo "Unknown service secret command: ${secret_command}" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
