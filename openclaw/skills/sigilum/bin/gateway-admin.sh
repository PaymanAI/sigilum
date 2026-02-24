#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  gateway-admin.sh tools <connection_id> [gateway_url]
  gateway-admin.sh call <connection_id> <tool_name> [arguments_json] [gateway_url]
  gateway-admin.sh proxy <connection_id> <method> <upstream_path> [body_json] [gateway_url]
  gateway-admin.sh mcp-tools <connection_id> [gateway_url]
  gateway-admin.sh mcp-call <connection_id> <tool_name> [arguments_json] [gateway_url]

Legacy insecure admin helpers (disabled by default):
  gateway-admin.sh list [gateway_url]
  gateway-admin.sh test <connection_id> [gateway_url]
  gateway-admin.sh discover <connection_id> [gateway_url]

Defaults:
  gateway_url = ${SIGILUM_GATEWAY_URL:-http://localhost:38100}
  namespace   = ${SIGILUM_NAMESPACE}
  key_root    = ${SIGILUM_KEY_ROOT:-$HOME/.openclaw/.sigilum/keys}
  agent_id    = ${SIGILUM_AGENT_ID:-${OPENCLAW_AGENT_ID:-${OPENCLAW_AGENT:-main}}}
  subject     = ${SIGILUM_SUBJECT:-<agent_id>}

Notes:
  - This helper prefers `curl` (supports HTTP/HTTPS); falls back to bash /dev/tcp for HTTP when curl is unavailable.
  - `tools`, `call`, and `proxy` sign requests with the selected per-agent key.
  - `tools`/`call` auto-check protocol when admin metadata is readable (mcp/http).
  - For `protocol=http`, use `proxy` for upstream API calls via /proxy/{connection_id}/...
  - On `401/403 AUTH_FORBIDDEN`, `tools`/`call` print `APPROVAL_*` fields to guide namespace-owner approval.
  - `list`, `test`, `discover` require SIGILUM_ALLOW_INSECURE_ADMIN=true.
EOF
}

gateway_url_default() {
  printf '%s' "${SIGILUM_GATEWAY_URL:-http://localhost:38100}"
}

ensure_cmd() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "Missing required command: ${name}" >&2
    exit 2
  fi
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

append_trap() {
  local new_handler="$1"
  local signal="${2:-EXIT}"
  local existing
  existing="$(trap -p "$signal" | awk -F"'" '{print $2}')"
  if [[ -n "$existing" ]]; then
    trap "${existing}; ${new_handler}" "$signal"
  else
    trap "${new_handler}" "$signal"
  fi
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

sanitize_agent_id() {
  local value
  value="$(trim "$1")"
  value="${value//[^a-zA-Z0-9._-]/_}"
  printf '%s' "$value"
}

preferred_agent_from_openclaw_config() {
  if ! has_cmd node; then
    return 0
  fi

  local config_path="${OPENCLAW_CONFIG_PATH:-${OPENCLAW_HOME:-$HOME/.openclaw}/openclaw.json}"
  if [[ ! -f "$config_path" ]]; then
    return 0
  fi

  local resolved
  resolved="$(node - "$config_path" <<'NODE'
const fs = require("fs");

const asObject = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value;
};
const asString = (value) => (typeof value === "string" ? value.trim() : "");
const sanitize = (value) => asString(value).replace(/[^a-zA-Z0-9._-]/g, "_");

const configPath = process.argv[2];
if (!configPath) process.exit(0);

let parsed = {};
try {
  parsed = JSON.parse(fs.readFileSync(configPath, "utf8"));
} catch {
  process.exit(0);
}

const cfg = asObject(parsed);
const agents = asObject(cfg.agents);
const defaults = asObject(agents.defaults);
const defaultID = sanitize(defaults.id);
if (defaultID) {
  process.stdout.write(defaultID);
  process.exit(0);
}

const list = Array.isArray(agents.list) ? agents.list : [];
for (const entry of list) {
  const agent = asObject(entry);
  const id = sanitize(agent.id);
  if (id) {
    process.stdout.write(id);
    process.exit(0);
  }
}
NODE
)"
  resolved="$(sanitize_agent_id "$resolved")"
  if [[ -n "$resolved" ]]; then
    printf '%s' "$resolved"
  fi
}

hex_from_file() {
  local file="$1"
  od -An -tx1 -v "$file" | tr -d ' \n'
}

write_hex_to_file() {
  local hex="$1"
  local out="$2"
  : >"$out"
  local i
  for ((i=0; i<${#hex}; i+=2)); do
    printf '%b' "\\x${hex:i:2}" >>"$out"
  done
}

b64_from_file() {
  local file="$1"
  openssl base64 -A <"$file" | tr -d '\n'
}

b64url_from_file() {
  local file="$1"
  b64_from_file "$file" | tr '+/' '-_' | tr -d '='
}

parse_url() {
  local raw="$1"
  local without_scheme hostport path

  case "$raw" in
    http://*)
      without_scheme="${raw#http://}"
      URL_SCHEME="http"
      ;;
    https://*)
      without_scheme="${raw#https://}"
      URL_SCHEME="https"
      ;;
    *)
      without_scheme="$raw"
      URL_SCHEME="http"
      ;;
  esac

  hostport="${without_scheme%%/*}"
  path=""
  if [[ "$without_scheme" != "$hostport" ]]; then
    path="/${without_scheme#*/}"
    path="${path%/}"
  fi

  URL_HOST="${hostport%%:*}"
  URL_PORT="${hostport##*:}"
  if [[ "$URL_HOST" == "$URL_PORT" ]]; then
    if [[ "$URL_SCHEME" == "https" ]]; then
      URL_PORT="443"
    else
      URL_PORT="80"
    fi
  fi
  if [[ -z "$URL_HOST" ]]; then
    echo "Invalid URL host: ${raw}" >&2
    return 2
  fi
  if [[ "$URL_SCHEME" == "https" ]] && ! has_cmd curl; then
    echo "HTTPS target requires curl, but curl is not installed in this runtime." >&2
    echo "Install curl or use an http:// gateway URL for local-only /dev/tcp fallback." >&2
    return 2
  fi
  URL_BASE_PATH="$path"
}

normalize_connection_protocol() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  value="$(trim "$value")"
  case "$value" in
    mcp|http)
      printf '%s' "$value"
      ;;
    *)
      printf 'unknown'
      ;;
  esac
}

request_path_for_endpoint() {
  local endpoint="$1"
  local path="${URL_BASE_PATH}${endpoint}"
  if [[ -z "$path" ]]; then
    path="/"
  fi
  printf '%s' "$path"
}

request_url_for_endpoint() {
  local endpoint="$1"
  local req_path
  req_path="$(request_path_for_endpoint "$endpoint")"
  printf '%s://%s:%s%s' "$URL_SCHEME" "$URL_HOST" "$URL_PORT" "$req_path"
}

normalize_upstream_path() {
  local raw="$1"
  raw="$(trim "$raw")"
  if [[ -z "$raw" ]]; then
    printf '/'
    return 0
  fi
  if [[ "$raw" == /* ]]; then
    printf '%s' "$raw"
    return 0
  fi
  printf '/%s' "$raw"
}

detect_connection_protocol() {
  local connection_id="$1"
  local override token request_url response_file status_code protocol
  override="$(normalize_connection_protocol "${SIGILUM_CONNECTION_PROTOCOL:-}")"
  if [[ "$override" != "unknown" ]]; then
    printf '%s' "$override"
    return 0
  fi

  if ! has_cmd curl; then
    printf 'unknown'
    return 0
  fi

  request_url="$(request_url_for_endpoint "/api/admin/connections/${connection_id}")"
  response_file="$(mktemp "${TMPDIR:-/tmp}/sigilum-gateway-connection-XXXXXX")"
  token="$(trim "${SIGILUM_GATEWAY_ADMIN_TOKEN:-}")"
  if [[ -n "$token" ]]; then
    status_code="$(curl -sS -o "$response_file" -w "%{http_code}" \
      -H "Accept: application/json" \
      -H "Authorization: Bearer ${token}" \
      "$request_url" || true)"
  else
    status_code="$(curl -sS -o "$response_file" -w "%{http_code}" \
      -H "Accept: application/json" \
      "$request_url" || true)"
  fi
  status_code="$(trim "${status_code:-}")"
  if [[ "$status_code" != "200" ]]; then
    rm -f "${response_file:-}"
    printf 'unknown'
    return 0
  fi

  protocol="$(awk '
    match($0, /"protocol"[[:space:]]*:[[:space:]]*"[^"]+"/) {
      value = substr($0, RSTART, RLENGTH)
      gsub(/^.*"protocol"[[:space:]]*:[[:space:]]*"/, "", value)
      gsub(/".*$/, "", value)
      print value
      exit
    }
  ' "$response_file")"
  rm -f "${response_file:-}"
  normalize_connection_protocol "$protocol"
}

response_body_from_file() {
  local file="$1"
  awk 'BEGIN{body=0} /^\r?$/{if(!body){body=1;next}} body{print}' "$file"
}

read_socket_response() {
  local out_file="$1"
  local timeout_seconds="${SIGILUM_HTTP_TIMEOUT_SECONDS:-20}"
  if [[ ! "$timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
    timeout_seconds=20
  fi

  if has_cmd timeout; then
    timeout "${timeout_seconds}" cat <&3 >"$out_file" 2>/dev/null
    return $?
  fi

  : >"$out_file"
  local line
  while IFS= read -r -t "$timeout_seconds" line <&3; do
    printf '%s\n' "$line" >>"$out_file"
  done
  local rc=$?
  if (( rc > 128 )); then
    return 124
  fi
  if [[ $rc -eq 0 || $rc -eq 1 ]]; then
    return 0
  fi
  return $rc
}

http_request_with_curl() {
  local method="$1"
  local endpoint="$2"
  local body="${3:-}"
  shift 3 || true
  local -a headers=("$@")
  local request_url response_headers response_body status_code
  request_url="$(request_url_for_endpoint "$endpoint")"
  response_headers="$(mktemp "${TMPDIR:-/tmp}/sigilum-gateway-http-headers-XXXXXX")"
  response_body="$(mktemp "${TMPDIR:-/tmp}/sigilum-gateway-http-body-XXXXXX")"
  trap 'rm -f "${response_headers:-}" "${response_body:-}"' RETURN

  local -a args
  args=(
    -sS
    -D "$response_headers"
    -o "$response_body"
    -X "$method"
  )
  local header
  for header in "${headers[@]-}"; do
    args+=(-H "$header")
  done
  if [[ -n "$body" ]]; then
    args+=(--data-binary "$body")
  fi
  status_code="$(curl "${args[@]}" "$request_url" -w "%{http_code}" || true)"
  HTTP_STATUS="$(trim "${status_code:-}")"
  HTTP_STATUS_LINE="$(awk 'toupper($1) ~ /^HTTP\// {line=$0} END {gsub(/\r/, "", line); print line}' "$response_headers")"
  HTTP_BODY="$(cat "$response_body")"
}

http_request_with_devtcp() {
  local method="$1"
  local endpoint="$2"
  local body="${3:-}"
  shift 3 || true
  local -a headers=("$@")
  local path request_file

  if [[ -z "${URL_HOST:-}" || -z "${URL_PORT:-}" ]]; then
    echo "Invalid gateway URL." >&2
    exit 2
  fi
  if [[ "${URL_SCHEME}" != "http" ]]; then
    echo "HTTPS requests require curl in this helper runtime." >&2
    exit 2
  fi

  path="$(request_path_for_endpoint "$endpoint")"
  request_file="$(mktemp "${TMPDIR:-/tmp}/sigilum-gateway-http-XXXXXX")"
  trap 'rm -f "${request_file:-}"' RETURN

  if ! exec 3<>"/dev/tcp/${URL_HOST}/${URL_PORT}"; then
    echo "Unable to open TCP socket to ${URL_HOST}:${URL_PORT} (scheme=${URL_SCHEME})." >&2
    echo "Install curl for robust HTTP/HTTPS transport in restricted runtimes." >&2
    exit 2
  fi
  {
    printf '%s %s HTTP/1.0\r\n' "$method" "$path"
    printf 'Host: %s:%s\r\n' "$URL_HOST" "$URL_PORT"
    local header
    for header in "${headers[@]-}"; do
      printf '%s\r\n' "$header"
    done
    if [[ -n "$body" ]]; then
      printf 'Content-Length: %s\r\n' "${#body}"
    fi
    printf '\r\n'
    if [[ -n "$body" ]]; then
      printf '%s' "$body"
    fi
  } >&3

  local read_status=0
  if ! read_socket_response "$request_file"; then
    read_status=$?
  fi
  exec 3<&-
  exec 3>&-
  if [[ $read_status -ne 0 ]]; then
    if [[ $read_status -eq 124 ]]; then
      echo "Gateway response timed out after ${SIGILUM_HTTP_TIMEOUT_SECONDS:-20}s (set SIGILUM_HTTP_TIMEOUT_SECONDS to adjust)." >&2
    else
      echo "Failed to read gateway response from socket (status=$read_status)." >&2
    fi
    exit 2
  fi

  HTTP_STATUS_LINE="$(head -n 1 "$request_file" | tr -d '\r')"
  HTTP_STATUS="$(printf '%s' "$HTTP_STATUS_LINE" | awk '{print $2}')"
  HTTP_BODY="$(response_body_from_file "$request_file")"
}

http_request() {
  local method="$1"
  local endpoint="$2"
  local body="${3:-}"
  shift 3 || true
  local -a headers=("$@")

  if has_cmd curl; then
    http_request_with_curl "$method" "$endpoint" "$body" "${headers[@]}"
    return 0
  fi
  http_request_with_devtcp "$method" "$endpoint" "$body" "${headers[@]}"
}

create_nonce() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:upper:]' '[:lower:]'
    return 0
  fi
  local raw
  raw="$(openssl rand -hex 16)"
  printf '%s-%s-%s-%s-%s' \
    "${raw:0:8}" "${raw:8:4}" "${raw:12:4}" "${raw:16:4}" "${raw:20:12}"
}

resolve_identity_files() {
  local key_root="${SIGILUM_KEY_ROOT:-$HOME/.openclaw/.sigilum/keys}"
  local explicit_agent
  explicit_agent="$(trim "${SIGILUM_AGENT_ID:-}")"
  local candidates=()
  if [[ -n "$explicit_agent" ]]; then
    candidates+=("$explicit_agent")
  fi
  if [[ -n "${OPENCLAW_AGENT_ID:-}" ]]; then
    candidates+=("$(trim "${OPENCLAW_AGENT_ID}")")
  fi
  if [[ -n "${OPENCLAW_AGENT:-}" ]]; then
    candidates+=("$(trim "${OPENCLAW_AGENT}")")
  fi
  local configured_agent
  configured_agent="$(preferred_agent_from_openclaw_config)"
  if [[ -n "$configured_agent" ]]; then
    candidates+=("$configured_agent")
  fi
  candidates+=("main" "default")
  local normalized_candidates=()
  local seen_candidates=" "
  local candidate normalized_candidate
  for candidate in "${candidates[@]}"; do
    normalized_candidate="$(sanitize_agent_id "$candidate")"
    [[ -z "$normalized_candidate" ]] && continue
    case "$seen_candidates" in
      *" ${normalized_candidate} "*) continue ;;
    esac
    seen_candidates="${seen_candidates}${normalized_candidate} "
    normalized_candidates+=("$normalized_candidate")
  done

  local key_dir key_path pub_path
  local keys
  shopt -s nullglob
  for candidate in "${normalized_candidates[@]}"; do
    key_dir="${key_root%/}/${candidate}"
    keys=("${key_dir}"/*.key)
    if (( ${#keys[@]} == 0 )); then
      continue
    fi
    key_path="${keys[0]}"
    pub_path="${key_path%.key}.pub"
    if [[ ! -f "$pub_path" ]]; then
      continue
    fi
    AGENT_ID="$candidate"
    IDENTITY_KEY_PATH="$key_path"
    IDENTITY_PUB_PATH="$pub_path"
    shopt -u nullglob
    return 0
  done
  shopt -u nullglob

  echo "No Sigilum agent keypair found under ${key_root}." >&2
  echo "Expected files like: ${key_root}/main/<fingerprint>.key and .pub" >&2
  exit 2
}

build_signing_context() {
  ensure_cmd openssl
  ensure_cmd od
  ensure_cmd awk

  local namespace
  namespace="$(trim "${SIGILUM_NAMESPACE:-}")"
  if [[ -z "$namespace" ]]; then
    echo "SIGILUM_NAMESPACE is required for signed gateway requests." >&2
    exit 2
  fi

  resolve_identity_files

  PRIVATE_SEED_B64="$(tr -d '\r\n' <"${IDENTITY_KEY_PATH}")"
  PUBLIC_RAW_B64="$(tr -d '\r\n' <"${IDENTITY_PUB_PATH}")"
  if [[ -z "$PRIVATE_SEED_B64" || -z "$PUBLIC_RAW_B64" ]]; then
    echo "Invalid keypair files for agent ${AGENT_ID}." >&2
    exit 2
  fi

  TMP_SIGN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sigilum-gateway-sign-XXXXXX")"
  append_trap 'rm -rf "${TMP_SIGN_DIR}"' EXIT

  printf '%s' "$PRIVATE_SEED_B64" | openssl base64 -d -A >"${TMP_SIGN_DIR}/seed.bin"
  local seed_hex der_hex
  seed_hex="$(hex_from_file "${TMP_SIGN_DIR}/seed.bin")"
  der_hex="302e020100300506032b657004220420${seed_hex}"
  write_hex_to_file "$der_hex" "${TMP_SIGN_DIR}/private.der"
  openssl pkey -inform DER -in "${TMP_SIGN_DIR}/private.der" -out "${TMP_SIGN_DIR}/private.pem" >/dev/null 2>&1

  openssl pkey -in "${TMP_SIGN_DIR}/private.pem" -pubout -outform DER >"${TMP_SIGN_DIR}/public.der" 2>/dev/null
  local pub_der_hex pub_prefix pub_raw_hex
  pub_der_hex="$(hex_from_file "${TMP_SIGN_DIR}/public.der")"
  pub_prefix="302a300506032b6570032100"
  if [[ "${pub_der_hex#${pub_prefix}}" == "$pub_der_hex" ]]; then
    echo "Failed to parse Ed25519 public key." >&2
    exit 2
  fi
  pub_raw_hex="${pub_der_hex#${pub_prefix}}"
  write_hex_to_file "$pub_raw_hex" "${TMP_SIGN_DIR}/public.raw"
  local derived_public_b64
  derived_public_b64="$(b64_from_file "${TMP_SIGN_DIR}/public.raw")"
  if [[ "$derived_public_b64" != "$PUBLIC_RAW_B64" ]]; then
    PUBLIC_RAW_B64="$derived_public_b64"
  fi

  local hash_hex fp did key_id public_key issued_at cert_sig cert_json cert_header cert_payload
  hash_hex="$(openssl dgst -sha256 -binary "${TMP_SIGN_DIR}/public.raw" | od -An -tx1 -v | tr -d ' \n')"
  fp="${hash_hex:0:16}"
  did="did:sigilum:${namespace}"
  key_id="${did}#ed25519-${fp}"
  public_key="ed25519:${PUBLIC_RAW_B64}"
  issued_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  cert_payload="${TMP_SIGN_DIR}/cert-payload.txt"
  {
    printf 'sigilum-certificate-v1\n'
    printf 'namespace:%s\n' "$namespace"
    printf 'did:%s\n' "$did"
    printf 'key-id:%s\n' "$key_id"
    printf 'public-key:%s\n' "$public_key"
    printf 'issued-at:%s\n' "$issued_at"
    # Intentionally omit trailing newline so payload matches SDK verification.
    printf 'expires-at:'
  } >"$cert_payload"

  openssl pkeyutl -sign -inkey "${TMP_SIGN_DIR}/private.pem" -rawin -in "$cert_payload" -out "${TMP_SIGN_DIR}/cert.sig" >/dev/null 2>&1
  cert_sig="$(b64url_from_file "${TMP_SIGN_DIR}/cert.sig")"
  cert_json="$(printf '{"version":1,"namespace":"%s","did":"%s","keyId":"%s","publicKey":"%s","issuedAt":"%s","expiresAt":null,"proof":{"alg":"ed25519","sig":"%s"}}' \
    "$namespace" "$did" "$key_id" "$public_key" "$issued_at" "$cert_sig")"
  cert_header="$(printf '%s' "$cert_json" | openssl base64 -A | tr '+/' '-_' | tr -d '=')"

  SIG_NAMESPACE="$namespace"
  SIG_SUBJECT="$(trim "${SIGILUM_SUBJECT:-}")"
  if [[ -z "$SIG_SUBJECT" ]]; then
    SIG_SUBJECT="$AGENT_ID"
  fi
  SIG_PUBLIC_KEY="$public_key"
  SIG_KEY_ID="$key_id"
  SIG_CERT_HEADER="$cert_header"
  SIG_PRIVATE_PEM="${TMP_SIGN_DIR}/private.pem"
}

build_content_digest() {
  local body="$1"
  local digest_b64
  digest_b64="$(printf '%s' "$body" | openssl dgst -sha256 -binary | openssl base64 -A)"
  printf 'sha-256=:%s:' "$digest_b64"
}

signed_request() {
  local method="$1"
  local endpoint="$2"
  local body="${3:-}"
  shift 3 || true
  local -a extra_headers=("$@")
  local req_path
  req_path="$(request_path_for_endpoint "$endpoint")"
  local method_component
  method_component="$(printf '%s' "$method" | tr '[:upper:]' '[:lower:]')"

  local target_uri
  target_uri="${URL_SCHEME}://${URL_HOST}:${URL_PORT}${req_path}"
  local created nonce sig_params signing_base sig_b64
  created="$(date +%s)"
  nonce="$(create_nonce)"

  local -a components
  local content_digest=""
  if [[ -n "$body" ]]; then
    content_digest="$(build_content_digest "$body")"
    components=("@method" "@target-uri" "content-digest" "sigilum-namespace" "sigilum-subject" "sigilum-agent-key" "sigilum-agent-cert")
  else
    components=("@method" "@target-uri" "sigilum-namespace" "sigilum-subject" "sigilum-agent-key" "sigilum-agent-cert")
  fi

  local quoted_components=()
  local component
  for component in "${components[@]}"; do
    quoted_components+=("\"${component}\"")
  done
  sig_params="($(printf '%s ' "${quoted_components[@]}" | sed 's/ $//'));created=${created};keyid=\"${SIG_KEY_ID}\";alg=\"ed25519\";nonce=\"${nonce}\""

  signing_base="${TMP_SIGN_DIR}/signing-base.txt"
  {
    printf '"@method": %s\n' "$method_component"
    printf '"@target-uri": %s\n' "$target_uri"
    if [[ -n "$content_digest" ]]; then
      printf '"content-digest": %s\n' "$content_digest"
    fi
    printf '"sigilum-namespace": %s\n' "$SIG_NAMESPACE"
    printf '"sigilum-subject": %s\n' "$SIG_SUBJECT"
    printf '"sigilum-agent-key": %s\n' "$SIG_PUBLIC_KEY"
    printf '"sigilum-agent-cert": %s\n' "$SIG_CERT_HEADER"
    # Intentionally omit trailing newline so payload matches SDK verification.
    printf '"@signature-params": %s' "$sig_params"
  } >"$signing_base"

  openssl pkeyutl -sign -inkey "$SIG_PRIVATE_PEM" -rawin -in "$signing_base" -out "${TMP_SIGN_DIR}/req.sig" >/dev/null 2>&1
  sig_b64="$(b64_from_file "${TMP_SIGN_DIR}/req.sig")"

  local -a headers
  headers=(
    "signature-input: sig1=${sig_params}"
    "signature: sig1=:${sig_b64}:"
    "sigilum-namespace: ${SIG_NAMESPACE}"
    "sigilum-subject: ${SIG_SUBJECT}"
    "sigilum-agent-key: ${SIG_PUBLIC_KEY}"
    "sigilum-agent-cert: ${SIG_CERT_HEADER}"
  )
  if [[ -n "$content_digest" ]]; then
    headers+=("content-digest: ${content_digest}" "content-type: application/json")
  fi
  local header
  for header in "${extra_headers[@]-}"; do
    [[ -z "$header" ]] && continue
    headers+=("$header")
  done

  http_request "$method" "$endpoint" "$body" "${headers[@]}"
}

is_auth_forbidden_response() {
  local status="${HTTP_STATUS:-}"
  if [[ "$status" != "401" && "$status" != "403" ]]; then
    return 1
  fi
  case "${HTTP_BODY:-}" in
    *"# AUTH_FORBIDDEN: Sigilum Authorization Required"*|*"Sigilum verified your signature"*)
      return 0
      ;;
  esac
  return 1
}

print_approval_required_context() {
  local connection_id="${1:-}"
  if ! is_auth_forbidden_response; then
    return 0
  fi
  printf 'APPROVAL_REQUIRED=true\n'
  printf 'APPROVAL_NAMESPACE=%s\n' "${SIG_NAMESPACE:-}"
  printf 'APPROVAL_AGENT_ID=%s\n' "${AGENT_ID:-}"
  printf 'APPROVAL_SUBJECT=%s\n' "${SIG_SUBJECT:-}"
  printf 'APPROVAL_PUBLIC_KEY=%s\n' "${SIG_PUBLIC_KEY:-}"
  printf 'APPROVAL_SERVICE=%s\n' "${connection_id}"
  printf 'APPROVAL_MESSAGE=%s\n' "HTTP 403 AUTH_FORBIDDEN: this key has no active approval for the service (new, revoked, or expired). Ask namespace owner to approve/re-approve and retry."
}

print_response() {
  local connection_id="${1:-}"
  printf 'HTTP_STATUS=%s\n' "${HTTP_STATUS:-0}"
  if [[ -n "${HTTP_BODY:-}" ]]; then
    printf '%s\n' "$HTTP_BODY"
  fi
  print_approval_required_context "$connection_id"
  return 0
}

deny_insecure_admin() {
  if [[ "${SIGILUM_ALLOW_INSECURE_ADMIN:-false}" != "true" ]]; then
    echo "Insecure admin command is disabled by default." >&2
    echo "Set SIGILUM_ALLOW_INSECURE_ADMIN=true only for trusted local maintenance." >&2
    exit 2
  fi
}

cmd="${1:-}"
case "$cmd" in
  tools)
    connection_id="${2:-}"
    if [[ -z "$connection_id" ]]; then
      echo "Missing connection id for tools command." >&2
      usage
      exit 2
    fi
    gateway_url="${3:-$(gateway_url_default)}"
    parse_url "$gateway_url" || exit 2
    build_signing_context
    protocol="$(detect_connection_protocol "$connection_id")"
    if [[ "$protocol" == "http" ]]; then
      probe_path="$(normalize_upstream_path "${SIGILUM_PROXY_TOOLS_PATH:-/}")"
      signed_request "GET" "/proxy/${connection_id}${probe_path}" ""
    else
      signed_request "GET" "/mcp/${connection_id}/tools" ""
    fi
    print_response "$connection_id"
    ;;
  call)
    connection_id="${2:-}"
    tool_name="${3:-}"
    _args_default='{}'; args_json="${4:-$_args_default}"
    gateway_url="${5:-$(gateway_url_default)}"
    if [[ -z "$connection_id" || -z "$tool_name" ]]; then
      echo "Usage: gateway-admin.sh call <connection_id> <tool_name> [arguments_json] [gateway_url]" >&2
      exit 2
    fi
    parse_url "$gateway_url" || exit 2
    build_signing_context
    protocol="$(detect_connection_protocol "$connection_id")"
    if [[ "$protocol" == "http" ]]; then
      echo "Connection ${connection_id} uses protocol=http." >&2
      echo "Use: gateway-admin.sh proxy ${connection_id} POST /<upstream_path> '<json_body>' [gateway_url]" >&2
      exit 2
    fi
    signed_request "POST" "/mcp/${connection_id}/tools/${tool_name}/call" "$args_json"
    print_response "$connection_id"
    ;;
  proxy)
    connection_id="${2:-}"
    method="${3:-GET}"
    upstream_path_raw="${4:-/}"
    body_json="${5:-}"
    gateway_url="${6:-$(gateway_url_default)}"
    method="$(printf '%s' "$method" | tr '[:lower:]' '[:upper:]')"
    if [[ -z "$connection_id" || -z "$method" ]]; then
      echo "Usage: gateway-admin.sh proxy <connection_id> <method> <upstream_path> [body_json] [gateway_url]" >&2
      exit 2
    fi
    case "$method" in
      GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)
        ;;
      *)
        echo "Unsupported HTTP method for proxy command: ${method}" >&2
        exit 2
        ;;
    esac
    upstream_path="$(normalize_upstream_path "$upstream_path_raw")"
    parse_url "$gateway_url" || exit 2
    build_signing_context
    signed_request "$method" "/proxy/${connection_id}${upstream_path}" "$body_json"
    print_response "$connection_id"
    ;;
  mcp-tools)
    connection_id="${2:-}"
    if [[ -z "$connection_id" ]]; then
      echo "Missing connection id for mcp-tools command." >&2
      usage
      exit 2
    fi
    gateway_url="${3:-$(gateway_url_default)}"
    parse_url "$gateway_url" || exit 2
    build_signing_context
    signed_request "GET" "/mcp/${connection_id}/tools" ""
    print_response "$connection_id"
    ;;
  mcp-call)
    connection_id="${2:-}"
    tool_name="${3:-}"
    _args_default='{}'; args_json="${4:-$_args_default}"
    gateway_url="${5:-$(gateway_url_default)}"
    if [[ -z "$connection_id" || -z "$tool_name" ]]; then
      echo "Usage: gateway-admin.sh mcp-call <connection_id> <tool_name> [arguments_json] [gateway_url]" >&2
      exit 2
    fi
    parse_url "$gateway_url" || exit 2
    build_signing_context
    signed_request "POST" "/mcp/${connection_id}/tools/${tool_name}/call" "$args_json"
    print_response "$connection_id"
    ;;
  list)
    deny_insecure_admin
    gateway_url="${2:-$(gateway_url_default)}"
    parse_url "$gateway_url" || exit 2
    http_request "GET" "/api/admin/connections" ""
    print_response
    ;;
  test)
    deny_insecure_admin
    connection_id="${2:-}"
    if [[ -z "$connection_id" ]]; then
      echo "Missing connection id for test command." >&2
      usage
      exit 2
    fi
    gateway_url="${3:-$(gateway_url_default)}"
    parse_url "$gateway_url" || exit 2
    http_request "POST" "/api/admin/connections/${connection_id}/test" "{}"
    print_response "$connection_id"
    ;;
  discover)
    deny_insecure_admin
    connection_id="${2:-}"
    if [[ -z "$connection_id" ]]; then
      echo "Missing connection id for discover command." >&2
      usage
      exit 2
    fi
    gateway_url="${3:-$(gateway_url_default)}"
    parse_url "$gateway_url" || exit 2
    http_request "POST" "/api/admin/connections/${connection_id}/discover" "{}"
    print_response "$connection_id"
    ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    usage
    exit 2
    ;;
esac
