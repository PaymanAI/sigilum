#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Sigilum Local Service CLI

Usage:
  sigilum service add [options]
  sigilum service list [options]
  sigilum service secret set [options]
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
  --auth-mode <mode>             Optional. bearer|header_key|query_param (default: bearer).
  --upstream-header <name>       Optional. Header name (header modes) or query key (query_param mode).
  --auth-prefix <value>          Optional. Defaults depend on auth mode.
  --upstream-secret-key <key>    Optional. Secret key name used by gateway.
  --upstream-secret <value>      Optional. Upstream token/secret value.
  --upstream-secret-env <name>   Optional. Read token/secret from env var.
  --upstream-secret-file <path>  Optional. Read token/secret from file.
                                 If no secret source is set, a random secret is generated.
  --reveal-secrets               Optional. Print raw generated/resolved secret values.
  --gateway-admin-url <url>      Optional. Defaults to http://127.0.0.1:38100.
  --gateway-data-dir <path>      Optional. Defaults to .local/gateway-data.
  --gateway-master-key <value>   Optional. Defaults to sigilum-local-dev-master-key.

Options for list:
  --namespace <namespace>        Optional. Defaults to GATEWAY_SIGILUM_NAMESPACE or johndee.
  --gateway-admin-url <url>      Optional. Defaults to http://127.0.0.1:38100.
  --gateway-data-dir <path>      Optional. Defaults to .local/gateway-data.
  --gateway-master-key <value>   Optional. Defaults to sigilum-local-dev-master-key.
  --json                         Optional. Print machine-readable JSON output.

Options for secret set:
  --service-slug <slug>          Required. Service/connection id.
  --upstream-secret-key <key>    Optional. Defaults to connection auth_secret_key.
  --upstream-secret <value>      Optional. Set secret value directly.
  --upstream-secret-env <name>   Optional. Read secret value from env var.
  --upstream-secret-file <path>  Optional. Read secret value from file.
  --reveal-secrets               Optional. Print raw secret value.
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

  sigilum service list --namespace johndee

  sigilum service secret set \
    --service-slug linear \
    --upstream-secret-env LINEAR_TOKEN
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

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

sql_escape() {
  printf "%s" "$1" | sed "s/'/''/g"
}

run_local_d1() {
  local query="$1"
  ensure_api_wrangler_config
  (
    cd "$ROOT_DIR/apps/api"
    pnpm exec wrangler d1 execute sigilum-api --local --command "$query" >/dev/null
  )
}

run_local_d1_json() {
  local query="$1"
  ensure_api_wrangler_config
  (
    cd "$ROOT_DIR/apps/api"
    pnpm exec wrangler d1 execute sigilum-api --local --command "$query" --json
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

mask_secret() {
  local value="$1"
  if [[ -z "$value" ]]; then
    printf "(empty)"
    return 0
  fi
  local len="${#value}"
  if (( len <= 8 )); then
    printf "****"
    return 0
  fi
  printf "%s...%s" "${value:0:4}" "${value: -4}"
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

gateway_list_connections_json() {
  if curl -sf "${GATEWAY_ADMIN_URL}/health" >/dev/null 2>&1; then
    curl -sS "${GATEWAY_ADMIN_URL}/api/admin/connections"
    return 0
  fi
  if ! command -v go >/dev/null 2>&1; then
    return 1
  fi
  gateway_cli list
}

gateway_get_connection_json() {
  local connection_id="$1"
  if curl -sf "${GATEWAY_ADMIN_URL}/health" >/dev/null 2>&1; then
    local response_file
    response_file="$(mktemp "${TMPDIR:-/tmp}/sigilum-gw-get-XXXXXX.json")"
    local status
    status="$(curl -sS -o "$response_file" -w "%{http_code}" "${GATEWAY_ADMIN_URL}/api/admin/connections/${connection_id}" || true)"
    if [[ "$status" != "200" ]]; then
      rm -f "$response_file"
      return 1
    fi
    cat "$response_file"
    rm -f "$response_file"
    return 0
  fi
  if ! command -v go >/dev/null 2>&1; then
    return 1
  fi
  gateway_cli get --id "$connection_id"
}

gateway_rotate_connection_secret() {
  local connection_id="$1"
  local secret_key="$2"
  local secret_value="$3"

  if curl -sf "${GATEWAY_ADMIN_URL}/health" >/dev/null 2>&1; then
    local payload
    payload="$(SECRET_KEY="$secret_key" SECRET_VALUE="$secret_value" node -e '
const payload = {
  secrets: {
    [process.env.SECRET_KEY]: process.env.SECRET_VALUE,
  },
  rotated_by: "sigilum-service-cli",
  rotation_reason: "manual-secret-set",
};
process.stdout.write(JSON.stringify(payload));
')"

    local response_file
    response_file="$(mktemp "${TMPDIR:-/tmp}/sigilum-gw-rotate-XXXXXX.json")"
    local status
    status="$(curl -sS -o "$response_file" -w "%{http_code}" \
      -H "Content-Type: application/json" \
      -X POST "${GATEWAY_ADMIN_URL}/api/admin/connections/${connection_id}/rotate" \
      --data "$payload" || true)"
    if [[ "$status" != "200" ]]; then
      echo "Failed to rotate gateway secret via admin API (HTTP ${status})" >&2
      cat "$response_file" >&2 || true
      rm -f "$response_file"
      return 1
    fi
    rm -f "$response_file"
    return 0
  fi

  require_cmd go
  gateway_cli rotate --id "$connection_id" --secret "${secret_key}=${secret_value}" >/dev/null
}

