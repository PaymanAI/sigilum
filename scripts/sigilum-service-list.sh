#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/sigilum-service-common.sh"

list_services() {
  require_cmd pnpm
  require_cmd node
  ensure_api_wrangler_config

  local namespace="${GATEWAY_SIGILUM_NAMESPACE:-johndee}"
  local output_json="false"
  GATEWAY_ADMIN_URL="${GATEWAY_ADMIN_URL:-http://127.0.0.1:38100}"
  GATEWAY_DATA_DIR="${GATEWAY_DATA_DIR:-${ROOT_DIR}/.local/gateway-data}"
  GATEWAY_MASTER_KEY="${GATEWAY_MASTER_KEY:-sigilum-local-dev-master-key}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --namespace)
        namespace="${2:-}"
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
      --json)
        output_json="true"
        shift
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

  if ! is_valid_slug "$namespace"; then
    echo "Invalid --namespace: ${namespace}" >&2
    exit 1
  fi

  local ns_sql query services_raw connections_raw
  ns_sql="$(sql_escape "$namespace")"
  query="SELECT s.slug AS service_slug, s.name AS service_name, s.domain AS domain, s.description AS description, (SELECT COUNT(*) FROM service_api_keys k WHERE k.service_id = s.id AND k.revoked_at IS NULL) AS active_api_keys FROM services s JOIN users u ON u.id = s.owner_user_id WHERE u.namespace = '${ns_sql}' ORDER BY s.slug;"
  services_raw="$(run_local_d1_json "$query")"
  connections_raw="$(gateway_list_connections_json 2>/dev/null || printf '{"connections":[]}')"

  SERVICES_RAW="$services_raw" CONNECTIONS_RAW="$connections_raw" OUTPUT_JSON="$output_json" NAMESPACE="$namespace" node <<'NODE'
const servicesRaw = process.env.SERVICES_RAW || "[]";
const connectionsRaw = process.env.CONNECTIONS_RAW || '{"connections":[]}';
const namespace = process.env.NAMESPACE || "";
const outputJson = process.env.OUTPUT_JSON === "true";

const parseJson = (value, fallback) => {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
};

const servicePayload = parseJson(servicesRaw, []);
const serviceRows = Array.isArray(servicePayload) && servicePayload[0] && Array.isArray(servicePayload[0].results)
  ? servicePayload[0].results
  : [];

const connectionPayload = parseJson(connectionsRaw, { connections: [] });
const connections = Array.isArray(connectionPayload.connections) ? connectionPayload.connections : [];
const connectionIds = new Set(connections.map((entry) => String(entry.id || "").trim()).filter(Boolean));

const rows = serviceRows.map((row) => {
  const slug = String(row.service_slug || "").trim();
  return {
    service_slug: slug,
    service_name: String(row.service_name || ""),
    domain: String(row.domain || ""),
    description: String(row.description || ""),
    active_api_keys: Number(row.active_api_keys || 0),
    mode: connectionIds.has(slug) ? "gateway" : "native",
  };
});

if (outputJson) {
  process.stdout.write(`${JSON.stringify({ namespace, services: rows }, null, 2)}\n`);
  process.exit(0);
}

if (rows.length === 0) {
  process.stdout.write(`No services registered for namespace "${namespace}".\n`);
  process.exit(0);
}

const slugWidth = Math.max("SERVICE".length, ...rows.map((row) => row.service_slug.length));
const modeWidth = Math.max("MODE".length, ...rows.map((row) => row.mode.length));
const keysWidth = Math.max("API_KEYS".length, ...rows.map((row) => String(row.active_api_keys).length));

const pad = (value, width) => value.padEnd(width, " ");
process.stdout.write(`Services for namespace "${namespace}":\n`);
process.stdout.write(`${pad("SERVICE", slugWidth)}  ${pad("MODE", modeWidth)}  ${pad("API_KEYS", keysWidth)}  NAME\n`);
for (const row of rows) {
  process.stdout.write(`${pad(row.service_slug, slugWidth)}  ${pad(row.mode, modeWidth)}  ${pad(String(row.active_api_keys), keysWidth)}  ${row.service_name}\n`);
}
NODE
}


main() {
  if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
    usage
    exit 0
  fi
  list_services "$@"
}

main "$@"
