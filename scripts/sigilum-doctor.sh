#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${API_PORT:=8787}"
: "${GATEWAY_PORT:=38100}"
: "${OPENCLAW_HOME:=$HOME/.openclaw}"
: "${GATEWAY_SIGILUM_NAMESPACE:=johndee}"
: "${GATEWAY_SIGILUM_HOME:=${ROOT_DIR}/.sigilum-workspace}"

OPENCLAW_CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-${OPENCLAW_HOME}/openclaw.json}"
IDENTITY_PATH="${GATEWAY_SIGILUM_HOME}/identities/${GATEWAY_SIGILUM_NAMESPACE}/identity.json"
GATEWAY_KEY_PATH="${GATEWAY_SIGILUM_HOME}/service-api-key-sigilum-gateway"
NATIVE_KEY_PATH="${GATEWAY_SIGILUM_HOME}/service-api-key-demo-service-native"
PROXY_KEY_PATH="${GATEWAY_SIGILUM_HOME}/service-api-key-demo-service-gateway"

ok_count=0
warn_count=0
fail_count=0

usage() {
  cat <<'EOF'
Sigilum Doctor

Usage:
  sigilum doctor [options]

Checks local prerequisites, runtime status, token posture, and common misconfiguration.

Options:
  -h, --help  Show help
EOF
}

log_ok() {
  ok_count=$((ok_count + 1))
  echo "[ok]   $1"
}

log_warn() {
  warn_count=$((warn_count + 1))
  echo "[warn] $1"
}

log_fail() {
  fail_count=$((fail_count + 1))
  echo "[fail] $1"
}

check_cmd() {
  local cmd="$1"
  local label="$2"
  local required="${3:-true}"
  if command -v "$cmd" >/dev/null 2>&1; then
    log_ok "${label}: $(command -v "$cmd")"
    return 0
  fi
  if [[ "$required" == "true" ]]; then
    log_fail "${label}: missing command '${cmd}'"
  else
    log_warn "${label}: missing optional command '${cmd}'"
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
  status="$(curl -sS -o /dev/null -w "%{http_code}" "$url" || true)"
  if [[ "$status" == "200" ]]; then
    log_ok "${label}: ${url} (HTTP 200)"
  else
    log_warn "${label}: ${url} returned HTTP ${status:-000}"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

echo "Sigilum doctor checks:"

check_cmd node "Node.js" true
check_cmd pnpm "pnpm" true
check_cmd go "Go" true
check_cmd java "Java (for sdk-java tests)" false
check_cmd mvn "Maven (for sdk-java tests)" false
check_cmd curl "curl" true

if [[ -f "${ROOT_DIR}/apps/api/wrangler.toml" ]]; then
  log_ok "Wrangler config present: ${ROOT_DIR}/apps/api/wrangler.toml"
elif [[ -f "${ROOT_DIR}/apps/api/wrangler.toml.example" ]]; then
  log_warn "Wrangler config missing; template exists at ${ROOT_DIR}/apps/api/wrangler.toml.example"
else
  log_fail "Wrangler config and template are missing under ${ROOT_DIR}/apps/api"
fi

if [[ -f "$IDENTITY_PATH" ]]; then
  log_ok "Gateway signer identity present: ${IDENTITY_PATH}"
else
  log_warn "Gateway signer identity missing: ${IDENTITY_PATH}"
fi

if [[ -f "$GATEWAY_KEY_PATH" ]]; then
  log_ok "Gateway service API key file present: ${GATEWAY_KEY_PATH}"
else
  log_warn "Gateway service API key file missing: ${GATEWAY_KEY_PATH}"
fi
if [[ -f "$NATIVE_KEY_PATH" ]]; then
  log_ok "Demo native service key file present: ${NATIVE_KEY_PATH}"
else
  log_warn "Demo native service key file missing: ${NATIVE_KEY_PATH}"
fi
if [[ -f "$PROXY_KEY_PATH" ]]; then
  log_ok "Demo gateway service key file present: ${PROXY_KEY_PATH}"
else
  log_warn "Demo gateway service key file missing: ${PROXY_KEY_PATH}"
fi

if command -v curl >/dev/null 2>&1; then
  check_http_ok "API health" "http://127.0.0.1:${API_PORT}/health"
  check_http_ok "Gateway health" "http://127.0.0.1:${GATEWAY_PORT}/health"
fi

if [[ -f "$OPENCLAW_CONFIG_PATH" ]]; then
  local_mode="$(file_mode "$OPENCLAW_CONFIG_PATH" || true)"
  if [[ -n "$local_mode" ]] && [[ "$local_mode" == "600" ]]; then
    log_ok "OpenClaw config permissions are strict (600): ${OPENCLAW_CONFIG_PATH}"
  elif [[ -n "$local_mode" ]]; then
    log_warn "OpenClaw config permissions are ${local_mode}; recommended 600: ${OPENCLAW_CONFIG_PATH}"
  else
    log_warn "Unable to determine permissions for ${OPENCLAW_CONFIG_PATH}"
  fi

  if command -v node >/dev/null 2>&1; then
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

    parse_ok="$(printf "%s" "$summary_json" | node -e 'const fs=require("fs"); const v=JSON.parse(fs.readFileSync(0,"utf8")); process.stdout.write(v.parse_ok ? "true" : "false");')"
    parse_error="$(printf "%s" "$summary_json" | node -e 'const fs=require("fs"); const v=JSON.parse(fs.readFileSync(0,"utf8")); process.stdout.write((v.parse_error || "").trim());')"
    authz_enabled="$(printf "%s" "$summary_json" | node -e 'const fs=require("fs"); const v=JSON.parse(fs.readFileSync(0,"utf8")); process.stdout.write(v.authz_enabled ? "true" : "false");')"
    has_owner_token="$(printf "%s" "$summary_json" | node -e 'const fs=require("fs"); const v=JSON.parse(fs.readFileSync(0,"utf8")); process.stdout.write(v.has_owner_token ? "true" : "false");')"
    config_mode="$(printf "%s" "$summary_json" | node -e 'const fs=require("fs"); const v=JSON.parse(fs.readFileSync(0,"utf8")); process.stdout.write((v.mode || "").trim());')"
    config_namespace="$(printf "%s" "$summary_json" | node -e 'const fs=require("fs"); const v=JSON.parse(fs.readFileSync(0,"utf8")); process.stdout.write((v.namespace || "").trim());')"

    if [[ "$parse_ok" != "true" ]]; then
      log_fail "OpenClaw config parse failed: ${parse_error:-unknown parse error}"
    else
      if [[ "$authz_enabled" == "true" && "$has_owner_token" != "true" ]]; then
        log_fail "sigilum-authz-notify is enabled but SIGILUM_OWNER_TOKEN is missing."
      elif [[ "$authz_enabled" == "true" && "$has_owner_token" == "true" ]]; then
        log_ok "sigilum-authz-notify enabled with owner token configured."
        log_warn "Owner token is loaded in OpenClaw runtime; disable authz-notify if not required."
      elif [[ "$authz_enabled" != "true" && "$has_owner_token" == "true" ]]; then
        log_warn "Owner token exists in OpenClaw config while authz-notify is disabled."
      else
        log_ok "sigilum-authz-notify is disabled (default-safe posture)."
      fi

      if [[ "$config_mode" == "managed" && "$has_owner_token" != "true" ]]; then
        log_warn "Managed mode detected without owner token."
        echo "       Onboarding:"
        echo "       1) Open https://sigilum.id"
        if [[ -n "$config_namespace" ]]; then
          echo "       2) Sign in and reserve namespace '${config_namespace}'"
          echo "       3) Run: sigilum auth login --mode managed --namespace ${config_namespace} --owner-token-stdin"
        else
          echo "       2) Sign in and reserve your namespace"
          echo "       3) Run: sigilum auth login --mode managed --namespace <namespace> --owner-token-stdin"
        fi
      fi
    fi
  fi
else
  log_warn "OpenClaw config not found at ${OPENCLAW_CONFIG_PATH}"
fi

echo ""
echo "Summary: ${ok_count} ok, ${warn_count} warnings, ${fail_count} failures."
if [[ "$fail_count" -gt 0 ]]; then
  exit 1
fi
exit 0
