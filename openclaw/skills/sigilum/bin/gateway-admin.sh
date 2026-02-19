#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  gateway-admin.sh tools <connection_id> [gateway_url]
  gateway-admin.sh call <connection_id> <tool_name> [arguments_json] [gateway_url]

Legacy insecure admin helpers (disabled by default):
  gateway-admin.sh list [gateway_url]
  gateway-admin.sh test <connection_id> [gateway_url]
  gateway-admin.sh discover <connection_id> [gateway_url]

Defaults:
  gateway_url = ${SIGILUM_GATEWAY_URL:-http://localhost:38100}
  namespace   = ${SIGILUM_NAMESPACE}
  key_root    = ${SIGILUM_KEY_ROOT:-$HOME/.openclaw/.sigilum/keys}
  agent_id    = ${SIGILUM_AGENT_ID:-main}
  subject     = ${SIGILUM_SUBJECT:-<agent_id>}

Notes:
  - This helper prefers `curl` (supports HTTP/HTTPS); falls back to bash /dev/tcp for HTTP when curl is unavailable.
  - `tools` and `call` sign requests with the selected per-agent key.
  - On `401/403 AUTH_FORBIDDEN`, `tools`/`call` auto-attempt claim submission to
    `${SIGILUM_API_URL:-${SIGILUM_REGISTRY_URL}}` using service API key env/file.
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
  candidates+=("main" "default")

  local candidate key_dir key_path pub_path
  local keys
  shopt -s nullglob
  for candidate in "${candidates[@]}"; do
    [[ -z "$candidate" ]] && continue
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

service_api_key_env_suffix() {
  local value
  value="$(trim "$1")"
  if [[ -z "$value" ]]; then
    printf 'DEFAULT'
    return 0
  fi
  printf '%s' "$value" \
    | tr '[:lower:]' '[:upper:]' \
    | sed -E 's/[^A-Z0-9]+/_/g; s/^_+//; s/_+$//' \
    | awk '{ if (length($0)==0) print "DEFAULT"; else print $0 }'
}

is_safe_service_key_id() {
  local value
  value="$(trim "$1")"
  if (( ${#value} < 3 || ${#value} > 64 )); then
    return 1
  fi
  if [[ ! "$value" =~ ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$ ]]; then
    return 1
  fi
  return 0
}

runtime_home_from_root() {
  local root
  root="$(trim "${SIGILUM_RUNTIME_ROOT:-}")"
  if [[ -z "$root" ]]; then
    return 1
  fi
  root="${root%/}"
  if [[ "$root" == */runtime ]]; then
    printf '%s' "${root%/runtime}"
    return 0
  fi
  printf '%s' "$root"
}

resolve_service_api_key() {
  local connection_id="$1"
  local scoped_env suffix
  suffix="$(service_api_key_env_suffix "$connection_id")"
  scoped_env="SIGILUM_SERVICE_API_KEY_${suffix}"
  if [[ -n "${!scoped_env:-}" ]]; then
    printf '%s' "$(trim "${!scoped_env}")"
    return 0
  fi
  if ! is_safe_service_key_id "$connection_id"; then
    if [[ -n "${SIGILUM_SERVICE_API_KEY:-}" ]]; then
      printf '%s' "$(trim "${SIGILUM_SERVICE_API_KEY}")"
      return 0
    fi
    return 1
  fi

  local -a key_homes=()
  if [[ -n "${SIGILUM_HOME:-}" ]]; then
    key_homes+=("$(trim "${SIGILUM_HOME}")")
  fi
  if runtime_home="$(runtime_home_from_root)"; then
    key_homes+=("$runtime_home")
  fi
  key_homes+=("${HOME}/.sigilum" "${HOME}/.openclaw/.sigilum" "${HOME}/.openclaw/workspace/.sigilum")

  local home_dir key_file raw
  for home_dir in "${key_homes[@]}"; do
    [[ -z "$home_dir" ]] && continue
    key_file="${home_dir%/}/service-api-key-${connection_id}"
    if [[ -f "$key_file" ]]; then
      raw="$(tr -d '\r\n' <"$key_file")"
      if [[ -n "$raw" ]]; then
        printf '%s' "$raw"
        return 0
      fi
    fi
  done
  if [[ -n "${SIGILUM_SERVICE_API_KEY:-}" ]]; then
    printf '%s' "$(trim "${SIGILUM_SERVICE_API_KEY}")"
    return 0
  fi
  return 1
}

auto_register_claim_enabled() {
  local raw
  raw="$(printf '%s' "${SIGILUM_AUTO_REGISTER_CLAIM:-true}" | tr '[:upper:]' '[:lower:]')"
  case "$raw" in
    0|false|no|off)
      return 1
      ;;
    *)
      return 0
      ;;
  esac
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
    printf '"@method": %s\n' "$method"
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

should_attempt_claim_registration() {
  local status="${HTTP_STATUS:-}"
  if [[ "$status" != "401" && "$status" != "403" ]]; then
    return 1
  fi
  case "${HTTP_BODY:-}" in
    *AUTH_FORBIDDEN*)
      return 0
      ;;
  esac
  return 1
}

submit_authorization_claim() {
  local connection_id="$1"
  CLAIM_HTTP_STATUS=""
  CLAIM_HTTP_BODY=""
  CLAIM_ERROR=""

  local api_url
  api_url="$(trim "${SIGILUM_API_URL:-${SIGILUM_REGISTRY_URL:-}}")"
  if [[ -z "$api_url" ]]; then
    CLAIM_ERROR="SIGILUM_API_URL or SIGILUM_REGISTRY_URL is not set; cannot submit authorization claim."
    return 1
  fi

  local service_api_key
  if ! service_api_key="$(resolve_service_api_key "$connection_id")" || [[ -z "$service_api_key" ]]; then
    CLAIM_ERROR="No service API key found for ${connection_id}; set SIGILUM_SERVICE_API_KEY or SIGILUM_SERVICE_API_KEY_$(service_api_key_env_suffix "$connection_id")."
    return 1
  fi

  local saved_scheme="$URL_SCHEME"
  local saved_host="$URL_HOST"
  local saved_port="$URL_PORT"
  local saved_base="$URL_BASE_PATH"

  if ! parse_url "$api_url"; then
    CLAIM_ERROR="Unsupported or invalid SIGILUM_API_URL (${api_url}); claim submission supports plain HTTP in this helper."
    URL_SCHEME="$saved_scheme"
    URL_HOST="$saved_host"
    URL_PORT="$saved_port"
    URL_BASE_PATH="$saved_base"
    return 1
  fi

  local claim_nonce agent_ip service_slug claim_body
  claim_nonce="$(create_nonce)"
  agent_ip="$(trim "${SIGILUM_AGENT_IP:-127.0.0.1}")"
  service_slug="$(trim "${SIGILUM_SERVICE_SLUG:-${connection_id}}")"
  claim_body="$(printf '{"namespace":"%s","public_key":"%s","service":"%s","agent_ip":"%s","nonce":"%s"}' \
    "$SIG_NAMESPACE" "$SIG_PUBLIC_KEY" "$service_slug" "$agent_ip" "$claim_nonce")"

  local gateway_status="${HTTP_STATUS:-}"
  local gateway_body="${HTTP_BODY:-}"

  signed_request "POST" "/v1/claims" "$claim_body" "authorization: Bearer ${service_api_key}"
  CLAIM_HTTP_STATUS="${HTTP_STATUS:-}"
  CLAIM_HTTP_BODY="${HTTP_BODY:-}"

  HTTP_STATUS="$gateway_status"
  HTTP_BODY="$gateway_body"
  URL_SCHEME="$saved_scheme"
  URL_HOST="$saved_host"
  URL_PORT="$saved_port"
  URL_BASE_PATH="$saved_base"
  return 0
}

attempt_claim_registration_if_needed() {
  local connection_id="$1"
  CLAIM_HTTP_STATUS=""
  CLAIM_HTTP_BODY=""
  CLAIM_ERROR=""

  if ! auto_register_claim_enabled; then
    return 0
  fi
  if ! should_attempt_claim_registration; then
    return 0
  fi
  if ! submit_authorization_claim "$connection_id"; then
    return 1
  fi
  return 0
}

print_approval_required_context() {
  local connection_id="${1:-}"
  if ! should_attempt_claim_registration; then
    return 0
  fi
  printf 'APPROVAL_REQUIRED=true\n'
  printf 'APPROVAL_NAMESPACE=%s\n' "${SIG_NAMESPACE:-}"
  printf 'APPROVAL_AGENT_ID=%s\n' "${AGENT_ID:-}"
  printf 'APPROVAL_SUBJECT=%s\n' "${SIG_SUBJECT:-}"
  printf 'APPROVAL_PUBLIC_KEY=%s\n' "${SIG_PUBLIC_KEY:-}"
  printf 'APPROVAL_SERVICE=%s\n' "${connection_id}"
  printf 'APPROVAL_MESSAGE=%s\n' "Namespace-owner approval is required for this agent key/service claim."
}

print_response() {
  local connection_id="${1:-}"
  printf 'HTTP_STATUS=%s\n' "${HTTP_STATUS:-0}"
  if [[ -n "${HTTP_BODY:-}" ]]; then
    printf '%s\n' "$HTTP_BODY"
  fi
  print_approval_required_context "$connection_id"
  if [[ -n "${CLAIM_HTTP_STATUS:-}" ]]; then
    printf 'CLAIM_HTTP_STATUS=%s\n' "${CLAIM_HTTP_STATUS}"
    if [[ -n "${CLAIM_HTTP_BODY:-}" ]]; then
      printf '%s\n' "${CLAIM_HTTP_BODY}"
    fi
  fi
  if [[ -n "${CLAIM_ERROR:-}" ]]; then
    printf 'CLAIM_ERROR=%s\n' "${CLAIM_ERROR}"
  fi
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
    signed_request "GET" "/mcp/${connection_id}/tools" ""
    attempt_claim_registration_if_needed "$connection_id" || true
    print_response "$connection_id"
    ;;
  call)
    connection_id="${2:-}"
    tool_name="${3:-}"
    args_json="${4:-{}}"
    gateway_url="${5:-$(gateway_url_default)}"
    if [[ -z "$connection_id" || -z "$tool_name" ]]; then
      echo "Usage: gateway-admin.sh call <connection_id> <tool_name> [arguments_json] [gateway_url]" >&2
      exit 2
    fi
    parse_url "$gateway_url" || exit 2
    build_signing_context
    signed_request "POST" "/mcp/${connection_id}/tools/${tool_name}/call" "$args_json"
    attempt_claim_registration_if_needed "$connection_id" || true
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
