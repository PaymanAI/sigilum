#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${API_PORT:=8787}"
: "${GATEWAY_PORT:=38100}"
: "${OPENCLAW_HOME:=$HOME/.openclaw}"
: "${GATEWAY_SIGILUM_NAMESPACE:=johndee}"
: "${GATEWAY_SIGILUM_HOME:=${ROOT_DIR}/.sigilum-workspace}"
: "${CURL_CONNECT_TIMEOUT_SECONDS:=5}"
: "${CURL_MAX_TIME_SECONDS:=15}"

OPENCLAW_CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-${OPENCLAW_HOME}/openclaw.json}"
IDENTITY_PATH="${GATEWAY_SIGILUM_HOME}/identities/${GATEWAY_SIGILUM_NAMESPACE}/identity.json"
GATEWAY_KEY_PATH="${GATEWAY_SIGILUM_HOME}/service-api-key-sigilum-gateway"
NATIVE_KEY_PATH="${GATEWAY_SIGILUM_HOME}/service-api-key-demo-service-native"
PROXY_KEY_PATH="${GATEWAY_SIGILUM_HOME}/service-api-key-demo-service-gateway"

ok_count=0
warn_count=0
fail_count=0

declare -a action_items=()
declare -a applied_fixes=()
declare -a check_statuses=()
declare -a check_labels=()
declare -a check_details=()

NO_COLOR_FLAG="false"
JSON_OUTPUT_FLAG="false"
FIX_MODE_FLAG="false"
TERM_COLS=120
LABEL_WIDTH=30

CLR_RESET=""
CLR_BOLD=""
CLR_DIM=""
CLR_RED=""
CLR_GREEN=""
CLR_YELLOW=""
CLR_BLUE=""
CLR_CYAN=""

usage() {
  cat <<'EOF'
Sigilum Doctor

Usage:
  sigilum doctor [options]

Checks local prerequisites, runtime status, token posture, and common misconfiguration.

Options:
  --json      Emit machine-readable JSON report
  --fix       Apply safe automated remediations where available
  --no-color  Disable ANSI colors
  -h, --help  Show help
EOF
}

setup_colors() {
  if [[ "$NO_COLOR_FLAG" == "true" || -n "${NO_COLOR:-}" || ! -t 1 || "${TERM:-}" == "dumb" ]]; then
    return 0
  fi

  CLR_RESET=$'\033[0m'
  CLR_BOLD=$'\033[1m'
  CLR_DIM=$'\033[2m'
  CLR_RED=$'\033[31m'
  CLR_GREEN=$'\033[32m'
  CLR_YELLOW=$'\033[33m'
  CLR_BLUE=$'\033[34m'
  CLR_CYAN=$'\033[36m'
}

detect_terminal_width() {
  local cols
  cols=""
  if command -v tput >/dev/null 2>&1; then
    cols="$(tput cols 2>/dev/null || true)"
  fi
  if [[ -z "$cols" && -n "${COLUMNS:-}" ]]; then
    cols="${COLUMNS}"
  fi
  if [[ "$cols" =~ ^[0-9]+$ ]] && (( cols >= 80 )); then
    TERM_COLS="$cols"
  else
    TERM_COLS=120
  fi
}

repeat_char() {
  local char="$1"
  local count="$2"
  local out=""
  local i
  for ((i = 0; i < count; i += 1)); do
    out="${out}${char}"
  done
  printf '%s' "$out"
}

section() {
  if [[ "$JSON_OUTPUT_FLAG" == "true" ]]; then
    return 0
  fi
  printf '\n%s%s%s\n' "${CLR_BOLD}${CLR_CYAN}" "$1" "${CLR_RESET}"
}

rule() {
  if [[ "$JSON_OUTPUT_FLAG" == "true" ]]; then
    return 0
  fi
  local width="$TERM_COLS"
  if (( width > 80 )); then
    width=80
  fi
  printf '%s\n' "$(repeat_char "-" "$width")"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

curl_with_timeout() {
  curl --connect-timeout "$CURL_CONNECT_TIMEOUT_SECONDS" --max-time "$CURL_MAX_TIME_SECONDS" "$@"
}

shorten_path() {
  local value="$1"
  if [[ "$value" == "$HOME"* ]]; then
    value="~${value#"$HOME"}"
  fi
  if [[ "$value" == "$ROOT_DIR"* ]]; then
    value=".${value#"$ROOT_DIR"}"
  fi
  printf '%s' "$value"
}

normalize_text() {
  printf '%s' "$1" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'
}

json_escape() {
  local value="${1:-}"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "$value"
}

add_check() {
  check_statuses+=("$1")
  check_labels+=("$(normalize_text "$2")")
  check_details+=("$(normalize_text "$3")")
}

print_json_report() {
  local overall_status="ok"
  local i

  if (( fail_count > 0 )); then
    overall_status="fail"
  elif (( warn_count > 0 )); then
    overall_status="warn"
  fi

  printf '{'
  printf '"status":"%s",' "$overall_status"
  printf '"ok":%d,' "$ok_count"
  printf '"warnings":%d,' "$warn_count"
  printf '"failures":%d,' "$fail_count"
  printf '"checks":['
  for ((i = 0; i < ${#check_statuses[@]}; i += 1)); do
    if (( i > 0 )); then
      printf ','
    fi
    printf '{"status":"%s","label":"%s","detail":"%s"}' \
      "$(json_escape "${check_statuses[$i]}")" \
      "$(json_escape "${check_labels[$i]}")" \
      "$(json_escape "${check_details[$i]}")"
  done
  printf '],'
  printf '"applied_fixes":['
  for ((i = 0; i < ${#applied_fixes[@]}; i += 1)); do
    if (( i > 0 )); then
      printf ','
    fi
    printf '"%s"' "$(json_escape "${applied_fixes[$i]}")"
  done
  printf '],'
  printf '"actions":['
  for ((i = 0; i < ${#action_items[@]}; i += 1)); do
    if (( i > 0 )); then
      printf ','
    fi
    printf '"%s"' "$(json_escape "${action_items[$i]}")"
  done
  printf ']'
  printf '}\n'
}

truncate_middle() {
  local text="$1"
  local max_len="$2"
  local text_len
  text_len=${#text}

  if (( text_len <= max_len )); then
    printf '%s' "$text"
    return 0
  fi
  if (( max_len <= 3 )); then
    printf '%s' "${text:0:max_len}"
    return 0
  fi

  local left right suffix
  left=$(( (max_len - 3) / 2 ))
  right=$(( max_len - 3 - left ))
  suffix=""
  if (( right > 0 )); then
    suffix="${text: -right}"
  fi
  printf '%s...%s' "${text:0:left}" "$suffix"
}

format_detail() {
  local raw="$1"
  local clean available
  clean="$(shorten_path "$raw")"
  clean="$(normalize_text "$clean")"

  available=$((TERM_COLS - 2 - 4 - 2 - LABEL_WIDTH - 2))
  if (( available < 24 )); then
    available=24
  fi
  truncate_middle "$clean" "$available"
}

print_row() {
  if [[ "$JSON_OUTPUT_FLAG" == "true" ]]; then
    return 0
  fi
  local status="$1"
  local label="$2"
  local detail="$3"
  local color="$CLR_RESET"
  local detail_fmt

  case "$status" in
    OK) color="$CLR_GREEN" ;;
    WARN) color="$CLR_YELLOW" ;;
    FAIL) color="$CLR_RED" ;;
    INFO) color="$CLR_BLUE" ;;
  esac

  detail_fmt="$(format_detail "$detail")"
  printf '  %s%-4s%s  %-*.*s  %s\n' \
    "${color}${CLR_BOLD}" \
    "$status" \
    "${CLR_RESET}" \
    "$LABEL_WIDTH" \
    "$LABEL_WIDTH" \
    "$label" \
    "$detail_fmt"
}

record_ok() {
  ok_count=$((ok_count + 1))
  add_check "OK" "$1" "$2"
  print_row "OK" "$1" "$2"
}

record_warn() {
  warn_count=$((warn_count + 1))
  add_check "WARN" "$1" "$2"
  print_row "WARN" "$1" "$2"
}

record_fail() {
  fail_count=$((fail_count + 1))
  add_check "FAIL" "$1" "$2"
  print_row "FAIL" "$1" "$2"
}

record_info() {
  add_check "INFO" "$1" "$2"
  print_row "INFO" "$1" "$2"
}

add_action() {
  local item
  item="$(normalize_text "$1")"
  if [[ -z "$item" ]]; then
    return 0
  fi
  action_items+=("$item")
}

add_fix() {
  local item
  item="$(normalize_text "$1")"
  if [[ -z "$item" ]]; then
    return 0
  fi
  applied_fixes+=("$item")
}

check_cmd() {
  local cmd="$1"
  local label="$2"
  local required="${3:-true}"
  local path
  if command -v "$cmd" >/dev/null 2>&1; then
    path="$(command -v "$cmd")"
    record_ok "$label" "$path"
    return 0
  fi

  if [[ "$required" == "true" ]]; then
    record_fail "$label" "Missing command '${cmd}'"
  else
    record_warn "$label" "Missing optional command '${cmd}'"
  fi
}

file_mode() {
  local path="$1"
  if stat -f "%Lp" "$path" >/dev/null 2>&1; then
    stat -f "%Lp" "$path"
    return 0
  fi
  if stat -c "%a" "$path" >/dev/null 2>&1; then
    stat -c "%a" "$path"
    return 0
  fi
  echo ""
  return 1
}

check_http_ok() {
  local label="$1"
  local url="$2"
  local status
  status="$(curl_with_timeout -sS -o /dev/null -w "%{http_code}" "$url" || true)"
  if [[ "$status" == "200" ]]; then
    record_ok "$label" "${url} (HTTP 200)"
  else
    if [[ ! "$status" =~ ^[0-9]{3}$ ]]; then
      status="000"
    fi
    record_warn "$label" "${url} returned HTTP ${status}"
  fi
}

json_field() {
  local json="$1"
  local key="$2"
  printf "%s" "$json" | node -e "
const fs=require('fs');
const v=JSON.parse(fs.readFileSync(0,'utf8'));
const key=process.argv[1];
const val=v[key];
if (typeof val === 'boolean') { process.stdout.write(val ? 'true' : 'false'); process.exit(0); }
if (val === null || val === undefined) { process.stdout.write(''); process.exit(0); }
process.stdout.write(String(val).trim());
" "$key"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)
      JSON_OUTPUT_FLAG="true"
      shift
      ;;
    --fix)
      FIX_MODE_FLAG="true"
      shift
      ;;
    --no-color)
      NO_COLOR_FLAG="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

setup_colors
detect_terminal_width

if [[ "$JSON_OUTPUT_FLAG" != "true" ]]; then
  printf '%sSigilum Doctor%s\n' "${CLR_BOLD}" "${CLR_RESET}"
  printf '%sLocal readiness report for API, gateway, keys, and OpenClaw config.%s\n' "${CLR_DIM}" "${CLR_RESET}"
  if [[ "$FIX_MODE_FLAG" == "true" ]]; then
    printf '%sAuto-remediation mode enabled (--fix).%s\n' "${CLR_DIM}" "${CLR_RESET}"
  fi
  rule
fi

section "Toolchain"
check_cmd node "Node.js" true
check_cmd pnpm "pnpm" true
check_cmd go "Go" true
check_cmd java "Java (sdk-java)" false
check_cmd mvn "Maven (sdk-java)" false
check_cmd curl "curl" true

section "Sigilum Workspace"
if [[ -f "${ROOT_DIR}/apps/api/wrangler.toml" ]]; then
  record_ok "Wrangler config" "${ROOT_DIR}/apps/api/wrangler.toml"
elif [[ -f "${ROOT_DIR}/apps/api/wrangler.toml.example" ]]; then
  if [[ "$FIX_MODE_FLAG" == "true" ]]; then
    if cp "${ROOT_DIR}/apps/api/wrangler.toml.example" "${ROOT_DIR}/apps/api/wrangler.toml" 2>/dev/null; then
      record_ok "Wrangler config" "${ROOT_DIR}/apps/api/wrangler.toml (created from template)"
      add_fix "Created apps/api/wrangler.toml from wrangler.toml.example"
    else
      record_fail "Wrangler config" "Failed to create wrangler.toml from template"
      add_action "Create local API config manually: cp apps/api/wrangler.toml.example apps/api/wrangler.toml"
    fi
  else
    record_warn "Wrangler config" "Missing wrangler.toml; template exists at ${ROOT_DIR}/apps/api/wrangler.toml.example"
    add_action "Create local API config: cp apps/api/wrangler.toml.example apps/api/wrangler.toml"
  fi
else
  record_fail "Wrangler config" "Missing wrangler.toml and wrangler.toml.example under ${ROOT_DIR}/apps/api"
fi

if [[ -f "$IDENTITY_PATH" ]]; then
  record_ok "Gateway identity" "$IDENTITY_PATH"
else
  record_warn "Gateway identity" "Missing ${IDENTITY_PATH}"
  add_action "Bootstrap local stack to create identity: ./sigilum up"
fi

if [[ -f "$GATEWAY_KEY_PATH" ]]; then
  record_ok "Gateway key file" "$GATEWAY_KEY_PATH"
else
  record_warn "Gateway key file" "Missing ${GATEWAY_KEY_PATH}"
fi
if [[ -f "$NATIVE_KEY_PATH" ]]; then
  record_ok "Demo native key file" "$NATIVE_KEY_PATH"
else
  record_warn "Demo native key file" "Missing ${NATIVE_KEY_PATH}"
fi
if [[ -f "$PROXY_KEY_PATH" ]]; then
  record_ok "Demo gateway key file" "$PROXY_KEY_PATH"
else
  record_warn "Demo gateway key file" "Missing ${PROXY_KEY_PATH}"
fi

section "Local Services"
if has_cmd curl; then
  check_http_ok "API health" "http://127.0.0.1:${API_PORT}/health"
  check_http_ok "Gateway health" "http://127.0.0.1:${GATEWAY_PORT}/health"
else
  record_warn "Health checks" "Skipping API/gateway probes because curl is missing"
fi

section "OpenClaw Config"
if [[ -f "$OPENCLAW_CONFIG_PATH" ]]; then
  local_mode="$(file_mode "$OPENCLAW_CONFIG_PATH" || true)"
  if [[ -n "$local_mode" ]] && [[ "$local_mode" == "600" ]]; then
    record_ok "Config permissions" "${OPENCLAW_CONFIG_PATH} (600)"
  elif [[ -n "$local_mode" ]]; then
    if [[ "$FIX_MODE_FLAG" == "true" ]]; then
      if chmod 600 "$OPENCLAW_CONFIG_PATH" 2>/dev/null; then
        record_ok "Config permissions" "${OPENCLAW_CONFIG_PATH} (normalized to 600)"
        add_fix "Normalized OpenClaw config permissions to 600 (${OPENCLAW_CONFIG_PATH})"
      else
        record_warn "Config permissions" "${OPENCLAW_CONFIG_PATH} (${local_mode}; chmod 600 failed)"
      fi
    else
      record_warn "Config permissions" "${OPENCLAW_CONFIG_PATH} (${local_mode}; recommended 600)"
    fi
  else
    record_warn "Config permissions" "Unable to read permissions for ${OPENCLAW_CONFIG_PATH}"
  fi

  if has_cmd node; then
    summary_json="$(
      OPENCLAW_CONFIG_PATH="$OPENCLAW_CONFIG_PATH" node <<'NODE'
const fs = require("fs");
const configPath = process.env.OPENCLAW_CONFIG_PATH;
const out = {
  parse_ok: false,
  parse_error: "",
  mode: "",
  namespace: "",
  authz_enabled: false,
  has_owner_token: false,
};
try {
  const raw = fs.readFileSync(configPath, "utf8");
  let parsed = {};
  if (raw.trim()) {
    try {
      parsed = JSON.parse(raw);
    } catch (jsonErr) {
      try {
        const json5 = require("json5");
        parsed = json5.parse(raw);
      } catch (json5Err) {
        const hint =
          json5Err && json5Err.code === "MODULE_NOT_FOUND"
            ? "Install json5 support or use strict JSON."
            : "Ensure the file is valid JSON/JSON5.";
        out.parse_error = `Failed to parse ${configPath}: ${String(jsonErr)}. ${hint}`;
        process.stdout.write(JSON.stringify(out));
        process.exit(0);
      }
    }
  }
  const hooks = (parsed && parsed.hooks && parsed.hooks.internal && parsed.hooks.internal.entries) || {};
  const plugin = hooks["sigilum-plugin"] || {};
  const notify = hooks["sigilum-authz-notify"] || {};
  const pluginEnv = (plugin && plugin.env) || {};
  const notifyEnv = (notify && notify.env) || {};
  out.parse_ok = true;
  out.mode = String(pluginEnv.SIGILUM_MODE || "");
  out.namespace = String(pluginEnv.SIGILUM_NAMESPACE || "");
  out.authz_enabled = Boolean(notify && notify.enabled);
  out.has_owner_token = String(notifyEnv.SIGILUM_OWNER_TOKEN || "").trim().length > 0;
} catch {}
process.stdout.write(JSON.stringify(out));
NODE
    )"

    parse_ok="$(json_field "$summary_json" "parse_ok")"
    parse_error="$(json_field "$summary_json" "parse_error")"
    authz_enabled="$(json_field "$summary_json" "authz_enabled")"
    has_owner_token="$(json_field "$summary_json" "has_owner_token")"
    config_mode="$(json_field "$summary_json" "mode")"
    config_namespace="$(json_field "$summary_json" "namespace")"

    if [[ "$parse_ok" != "true" ]]; then
      record_fail "Config parse" "${parse_error:-Unknown parse error}"
    else
      record_info "Detected mode" "${config_mode:-unset}"
      record_info "Detected namespace" "${config_namespace:-unset}"

      if [[ "$authz_enabled" == "true" && "$has_owner_token" != "true" ]]; then
        record_fail "authz-notify" "Enabled but SIGILUM_OWNER_TOKEN is missing"
        add_action "Disable authz-notify or provide owner token via sigilum openclaw install --enable-authz-notify true --owner-token <jwt>"
      elif [[ "$authz_enabled" == "true" && "$has_owner_token" == "true" ]]; then
        record_ok "authz-notify" "Enabled with owner token configured"
        record_warn "Owner token exposure" "Owner token is loaded in OpenClaw runtime"
      elif [[ "$authz_enabled" != "true" && "$has_owner_token" == "true" ]]; then
        record_warn "Owner token residue" "Owner token exists in config while authz-notify is disabled"
      else
        record_ok "authz-notify" "Disabled (default-safe posture)"
      fi

      if [[ "$config_mode" == "managed" && "$has_owner_token" != "true" ]]; then
        record_warn "Managed onboarding" "Managed mode detected without owner token"
        add_action "Open https://sigilum.id and reserve namespace '${config_namespace:-<namespace>}'"
        if [[ -n "$config_namespace" ]]; then
          add_action "Run: sigilum auth login --mode managed --namespace ${config_namespace} --owner-token-stdin"
        else
          add_action "Run: sigilum auth login --mode managed --namespace <namespace> --owner-token-stdin"
        fi
      fi
    fi
  fi
else
  record_warn "OpenClaw config" "Not found at ${OPENCLAW_CONFIG_PATH}"
fi

if [[ "$JSON_OUTPUT_FLAG" == "true" ]]; then
  print_json_report
else
  rule
  if [[ "$fail_count" -gt 0 ]]; then
    printf '%sSummary:%s %d ok, %d warnings, %d failures\n' "${CLR_BOLD}${CLR_RED}" "${CLR_RESET}" "$ok_count" "$warn_count" "$fail_count"
  elif [[ "$warn_count" -gt 0 ]]; then
    printf '%sSummary:%s %d ok, %d warnings, %d failures\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}" "$ok_count" "$warn_count" "$fail_count"
  else
    printf '%sSummary:%s %d ok, %d warnings, %d failures\n' "${CLR_BOLD}${CLR_GREEN}" "${CLR_RESET}" "$ok_count" "$warn_count" "$fail_count"
  fi

  if (( ${#applied_fixes[@]} > 0 )); then
    section "Applied Fixes"
    for i in "${!applied_fixes[@]}"; do
      printf '  %d) %s\n' "$((i + 1))" "${applied_fixes[$i]}"
    done
  fi

  if (( ${#action_items[@]} > 0 )); then
    section "Recommended Actions"
    for i in "${!action_items[@]}"; do
      printf '  %d) %s\n' "$((i + 1))" "${action_items[$i]}"
    done
  fi
fi

if [[ "$fail_count" -gt 0 ]]; then
  exit 1
fi
exit 0
