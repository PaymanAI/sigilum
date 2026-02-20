#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR_CANDIDATE="${SIGILUM_SOURCE_HOME:-$SCRIPT_ROOT}"
if [[ ! -d "$ROOT_DIR_CANDIDATE" ]]; then
  printf '[ERROR] SIGILUM_SOURCE_HOME directory not found: %s\n' "${ROOT_DIR_CANDIDATE}" >&2
  exit 1
fi
ROOT_DIR="$(cd "$ROOT_DIR_CANDIDATE" && pwd)"
cd "$ROOT_DIR"

CLR_RESET=""
CLR_BOLD=""
CLR_DIM=""
CLR_RED=""
CLR_GREEN=""
CLR_YELLOW=""
CLR_BLUE=""
CLR_CYAN=""

setup_colors() {
  if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-}" != "dumb" ]]; then
    CLR_RESET=$'\033[0m'
    CLR_BOLD=$'\033[1m'
    CLR_DIM=$'\033[2m'
    CLR_RED=$'\033[31m'
    CLR_GREEN=$'\033[32m'
    CLR_YELLOW=$'\033[33m'
    CLR_BLUE=$'\033[34m'
    CLR_CYAN=$'\033[36m'
  fi
}

log_ok() {
  printf '%s[ok]%s %s\n' "${CLR_BOLD}${CLR_GREEN}" "${CLR_RESET}" "$1"
}

log_info() {
  printf '%s[i]%s %s\n' "${CLR_BOLD}${CLR_BLUE}" "${CLR_RESET}" "$1"
}

log_error() {
  printf '%s[ERROR]%s %s\n' "${CLR_BOLD}${CLR_RED}" "${CLR_RESET}" "$1" >&2
}

print_kv() {
  printf '  %s%-20s%s %s\n' "${CLR_BOLD}" "$1" "${CLR_RESET}" "$2"
}

usage() {
  cat <<'USAGE'
Sigilum Auth CLI

Usage:
  sigilum auth login [options]
  sigilum auth refresh [options]
  sigilum auth show [options]

Commands:
  login      Bootstrap/store a namespace-owner JWT token.
  refresh    Issue a new local JWT token (oss-local) and store it.
  show       Print the stored namespace-owner JWT token.

Options (login/refresh):
  --mode <managed|oss-local>        Sigilum mode (default: managed)
  --namespace <value>               Namespace (default: $SIGILUM_NAMESPACE, then $GATEWAY_SIGILUM_NAMESPACE, then $USER)
  --email <value>                   Owner email (default: <namespace>@local.sigilum)
  --api-url <url>                   API base URL (mode default)
  --owner-token <jwt>               Explicit owner token (required for managed unless --owner-token-stdin)
  --owner-token-stdin               Read owner token from stdin
  --ttl-seconds <n>                 Local token TTL in seconds (default: 604800)
  --openclaw-home <path>            OpenClaw home (default: ~/.openclaw)
  --config <path>                   OpenClaw config path (default: <openclaw-home>/openclaw.json)
  --token-file <path>               Token file path (default: <openclaw-home>/.sigilum/owner-token-<namespace>.jwt)
  --write-openclaw <true|false>     Update openclaw.json hook env (default: true)
  --enable-authz-notify <true|false|preserve>
                                    Set hook enabled state (default: preserve)
  --print-token <true|false>        Print token in command output (default: true)
  --token-only                      Print only the JWT token (for script capture)

Options (show):
  --namespace <value>               Namespace for default token file
  --openclaw-home <path>            OpenClaw home (default: ~/.openclaw)
  --token-file <path>               Token file path override

Examples:
  sigilum auth login --mode oss-local --namespace johndee
  sigilum auth refresh --mode oss-local --namespace johndee
  sigilum auth login --mode managed --namespace johndee --owner-token-stdin
USAGE
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log_error "Missing required command: $1"
    exit 1
  fi
}

ensure_local_oss_source_layout() {
  local api_dir="${ROOT_DIR}/apps/api"
  local wrangler_template="${api_dir}/wrangler.toml.example"
  if [[ -d "$api_dir" && -f "$wrangler_template" ]]; then
    return 0
  fi

  log_error "oss-local mode requires a full Sigilum source checkout."
  log_error "Current runtime root does not include local API sources:"
  log_error "  expected directory: ${api_dir}"
  log_error "  expected file:      ${wrangler_template}"
  log_error ""
  log_error "Use one of these paths:"
  log_error "  1) managed mode from this install:"
  log_error "     sigilum openclaw install --mode managed"
  log_error "  2) oss-local from a source checkout:"
  log_error "     git clone https://github.com/PaymanAI/sigilum.git"
  log_error "     cd sigilum"
  log_error "     ./sigilum openclaw install --mode oss-local --api-url http://127.0.0.1:8787"
  log_error "  3) point global CLI to source checkout:"
  log_error "     SIGILUM_SOURCE_HOME=/path/to/sigilum sigilum openclaw install --mode oss-local --source-home /path/to/sigilum --api-url http://127.0.0.1:8787"
  exit 1
}

is_bool() {
  local lower
  lower="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    true|false) return 0 ;;
    *) return 1 ;;
  esac
}

normalize_bool() {
  local lower
  lower="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  if [[ "$lower" == "true" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

is_bool_or_preserve() {
  local lower
  lower="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    true|false|preserve) return 0 ;;
    *) return 1 ;;
  esac
}

normalize_bool_or_preserve() {
  local lower
  lower="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    true) printf 'true' ;;
    false) printf 'false' ;;
    *) printf 'preserve' ;;
  esac
}

ensure_api_wrangler_config() {
  ensure_local_oss_source_layout
  local api_dir="${ROOT_DIR}/apps/api"
  local config_path="${api_dir}/wrangler.toml"
  local template_path="${api_dir}/wrangler.toml.example"

  if [[ -f "$config_path" ]]; then
    return 0
  fi
  if [[ ! -f "$template_path" ]]; then
    log_error "Missing Wrangler config template: ${template_path}"
    exit 1
  fi

  cp "$template_path" "$config_path"
  log_ok "Created ${config_path} from template."
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

read_env_file_var() {
  local file_path="$1"
  local key="$2"
  node - "$file_path" "$key" <<'NODE'
const fs = require("fs");
const [filePath, key] = process.argv.slice(2);
if (!filePath || !key || !fs.existsSync(filePath)) {
  process.exit(0);
}
const raw = fs.readFileSync(filePath, "utf8");
for (const line of raw.split(/\r?\n/)) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) continue;
  const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
  if (!match || match[1] !== key) continue;
  let value = match[2].trim();
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1);
  }
  process.stdout.write(value);
  process.exit(0);
}
NODE
}

resolve_local_jwt_secret() {
  if [[ -n "${JWT_SECRET:-}" ]]; then
    printf "%s" "$JWT_SECRET"
    return 0
  fi

  local dev_vars="${ROOT_DIR}/apps/api/.dev.vars"
  local secret=""
  if [[ -f "$dev_vars" ]]; then
    secret="$(read_env_file_var "$dev_vars" "JWT_SECRET")"
  fi
  if [[ -n "$secret" ]]; then
    printf "%s" "$secret"
    return 0
  fi

  log_error "Unable to resolve JWT_SECRET for local token issuance."
  log_error "Set JWT_SECRET env var or configure apps/api/.dev.vars with JWT_SECRET."
  exit 1
}

ensure_local_owner_user() {
  ensure_local_oss_source_layout
  local namespace="$1"
  local email="$2"
  local user_id="user_local_${namespace}"
  local ns_sql email_sql user_id_sql
  ns_sql="$(sql_escape "$namespace")"
  email_sql="$(sql_escape "$email")"
  user_id_sql="$(sql_escape "$user_id")"

  (
    cd "$ROOT_DIR/apps/api"
    pnpm exec wrangler d1 migrations apply sigilum-api --local >/dev/null
  )
  run_local_d1 "INSERT OR IGNORE INTO users (id, email, namespace, plan, settings) VALUES ('${user_id_sql}', '${email_sql}', '${ns_sql}', 'free', '{}');"
  printf "%s" "$user_id"
}

issue_local_owner_token() {
  local secret="$1"
  local user_id="$2"
  local email="$3"
  local namespace="$4"
  local ttl_seconds="$5"

  node - "$secret" "$user_id" "$email" "$namespace" "$ttl_seconds" <<'NODE'
const crypto = require("node:crypto");
const [secret, userId, email, namespace, ttlRaw] = process.argv.slice(2);
const ttlSeconds = Number.parseInt(ttlRaw, 10);
if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
  throw new Error("ttl-seconds must be a positive integer");
}
const now = Math.floor(Date.now() / 1000);
const header = { alg: "HS256", typ: "JWT" };
const payload = {
  sub: userId,
  email,
  namespace,
  iss: "sigilum-api",
  aud: "sigilum-dashboard",
  iat: now,
  exp: now + ttlSeconds,
};
const encode = (value) =>
  Buffer.from(JSON.stringify(value), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
const unsigned = `${encode(header)}.${encode(payload)}`;
const signature = crypto
  .createHmac("sha256", secret)
  .update(unsigned)
  .digest("base64")
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/g, "");
process.stdout.write(`${unsigned}.${signature}`);
NODE
}

write_token_file() {
  local token="$1"
  local token_file="$2"
  local token_dir
  token_dir="$(dirname "$token_file")"
  mkdir -p "$token_dir"
  chmod 700 "$token_dir" 2>/dev/null || true
  umask 077
  printf "%s\n" "$token" >"$token_file"
}

update_openclaw_config_token() {
  local config_path="$1"
  local namespace="$2"
  local api_url="$3"
  local token="$4"
  local enable_authz_notify="$5"

  if [[ ! -f "$config_path" ]]; then
    mkdir -p "$(dirname "$config_path")"
    printf '{}\n' >"$config_path"
    chmod 600 "$config_path" 2>/dev/null || true
  fi

  node - "$config_path" "$namespace" "$api_url" "$token" "$enable_authz_notify" <<'NODE'
const fs = require("fs");

const [configPath, namespace, apiUrl, token, enableAuthzNotify] = process.argv.slice(2);

const asObject = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value;
};

const parseConfig = (raw, filePath) => {
  const trimmed = String(raw || "").trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed);
  } catch (jsonErr) {
    try {
      const json5 = require("json5");
      return json5.parse(trimmed);
    } catch (json5Err) {
      const hint =
        json5Err && json5Err.code === "MODULE_NOT_FOUND"
          ? "Install json5 support or use strict JSON."
          : "Ensure the file is valid JSON/JSON5.";
      throw new Error(`Failed to parse ${filePath}: ${String(jsonErr)}. ${hint}`);
    }
  }
};

let parsed = {};
parsed = parseConfig(fs.readFileSync(configPath, "utf8"), configPath);

const config = asObject(parsed);
config.hooks = asObject(config.hooks);
config.hooks.internal = asObject(config.hooks.internal);
config.hooks.internal.enabled = true;
config.hooks.internal.entries = asObject(config.hooks.internal.entries);

const authzEntry = asObject(config.hooks.internal.entries["sigilum-authz-notify"]);
authzEntry.env = {
  ...asObject(authzEntry.env),
  SIGILUM_NAMESPACE: namespace,
  SIGILUM_API_URL: apiUrl,
};
if (enableAuthzNotify === "true") {
  authzEntry.enabled = true;
} else if (enableAuthzNotify === "false") {
  authzEntry.enabled = false;
}
if (authzEntry.enabled === true && token && String(token).trim()) {
  authzEntry.env.SIGILUM_OWNER_TOKEN = String(token).trim();
} else {
  delete authzEntry.env.SIGILUM_OWNER_TOKEN;
}
config.hooks.internal.entries["sigilum-authz-notify"] = authzEntry;

fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
try {
  fs.chmodSync(configPath, 0o600);
} catch {
  // Best effort on non-posix filesystems.
}
NODE
}

validate_namespace() {
  local namespace="$1"
  if [[ ! "$namespace" =~ ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$ ]]; then
    log_error "Invalid namespace: ${namespace}"
    log_error "Namespace must match ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$"
    exit 1
  fi
}

setup_colors

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

command="$1"
shift || true

case "$command" in
  login|refresh)
    MODE="${SIGILUM_MODE:-managed}"
    NAMESPACE="${SIGILUM_NAMESPACE:-${GATEWAY_SIGILUM_NAMESPACE:-${USER:-default}}}"
    EMAIL="${SIGILUM_OWNER_EMAIL:-}"
    API_URL="${SIGILUM_API_URL:-}"
    OWNER_TOKEN="${SIGILUM_OWNER_TOKEN:-}"
    OWNER_TOKEN_STDIN="false"
    TTL_SECONDS="${SIGILUM_OWNER_TOKEN_TTL_SECONDS:-604800}"
    OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
    CONFIG_PATH=""
    TOKEN_FILE=""
    WRITE_OPENCLAW="true"
    ENABLE_AUTHZ_NOTIFY="preserve"
    PRINT_TOKEN="true"
    TOKEN_ONLY="false"

    while [[ $# -gt 0 ]]; do
      case "$1" in
        --mode)
          MODE="${2:-}"
          shift 2
          ;;
        --namespace)
          NAMESPACE="${2:-}"
          shift 2
          ;;
        --email)
          EMAIL="${2:-}"
          shift 2
          ;;
        --api-url)
          API_URL="${2:-}"
          shift 2
          ;;
        --owner-token)
          OWNER_TOKEN="${2:-}"
          shift 2
          ;;
        --owner-token-stdin)
          OWNER_TOKEN_STDIN="true"
          shift
          ;;
        --ttl-seconds)
          TTL_SECONDS="${2:-}"
          shift 2
          ;;
        --openclaw-home)
          OPENCLAW_HOME="${2:-}"
          shift 2
          ;;
        --config)
          CONFIG_PATH="${2:-}"
          shift 2
          ;;
        --token-file)
          TOKEN_FILE="${2:-}"
          shift 2
          ;;
        --write-openclaw)
          WRITE_OPENCLAW="${2:-}"
          shift 2
          ;;
        --enable-authz-notify)
          ENABLE_AUTHZ_NOTIFY="${2:-}"
          shift 2
          ;;
        --print-token)
          PRINT_TOKEN="${2:-}"
          shift 2
          ;;
        --token-only)
          TOKEN_ONLY="true"
          shift
          ;;
        -h|--help)
          usage
          exit 0
          ;;
        *)
          log_error "Unknown option: $1"
          usage >&2
          exit 1
          ;;
      esac
    done

    case "$MODE" in
      managed|oss-local)
        ;;
      *)
        log_error "--mode must be managed or oss-local"
        exit 1
        ;;
    esac

    if ! is_bool "$WRITE_OPENCLAW"; then
      log_error "--write-openclaw must be true or false"
      exit 1
    fi
    if ! is_bool "$PRINT_TOKEN"; then
      log_error "--print-token must be true or false"
      exit 1
    fi
    if ! is_bool_or_preserve "$ENABLE_AUTHZ_NOTIFY"; then
      log_error "--enable-authz-notify must be true, false, or preserve"
      exit 1
    fi

    WRITE_OPENCLAW="$(normalize_bool "$WRITE_OPENCLAW")"
    PRINT_TOKEN="$(normalize_bool "$PRINT_TOKEN")"
    ENABLE_AUTHZ_NOTIFY="$(normalize_bool_or_preserve "$ENABLE_AUTHZ_NOTIFY")"

    if [[ -z "$EMAIL" ]]; then
      EMAIL="${NAMESPACE}@local.sigilum"
    fi
    if [[ -z "$API_URL" ]]; then
      if [[ "$MODE" == "oss-local" ]]; then
        API_URL="http://127.0.0.1:8787"
      else
        API_URL="https://api.sigilum.id"
      fi
    fi
    if [[ -z "$CONFIG_PATH" ]]; then
      CONFIG_PATH="${OPENCLAW_HOME}/openclaw.json"
    fi
    if [[ -z "$TOKEN_FILE" ]]; then
      TOKEN_FILE="${OPENCLAW_HOME}/.sigilum/owner-token-${NAMESPACE}.jwt"
    fi

    if [[ "$OWNER_TOKEN_STDIN" == "true" ]]; then
      OWNER_TOKEN="$(cat | tr -d '\r\n')"
    fi

    if [[ "$MODE" == "oss-local" ]]; then
      ensure_local_oss_source_layout
      validate_namespace "$NAMESPACE"
      if [[ "$command" == "refresh" || -z "$OWNER_TOKEN" ]]; then
        require_cmd pnpm
        require_cmd node
        local_user_id="$(ensure_local_owner_user "$NAMESPACE" "$EMAIL")"
        local_jwt_secret="$(resolve_local_jwt_secret)"
        OWNER_TOKEN="$(issue_local_owner_token "$local_jwt_secret" "$local_user_id" "$EMAIL" "$NAMESPACE" "$TTL_SECONDS")"
      fi
    else
      if [[ -z "$OWNER_TOKEN" ]]; then
        log_error "Managed mode requires an explicit owner JWT."
        log_error "Run browser/passkey login first, then pass token via --owner-token or --owner-token-stdin."
        exit 1
      fi
    fi

    if [[ -z "$OWNER_TOKEN" ]]; then
      log_error "Owner token is empty."
      exit 1
    fi

    write_token_file "$OWNER_TOKEN" "$TOKEN_FILE"

    if [[ "$WRITE_OPENCLAW" == "true" ]]; then
      update_openclaw_config_token "$CONFIG_PATH" "$NAMESPACE" "$API_URL" "$OWNER_TOKEN" "$ENABLE_AUTHZ_NOTIFY"
    fi

    if [[ "$TOKEN_ONLY" == "true" ]]; then
      printf "%s\n" "$OWNER_TOKEN"
      exit 0
    fi

    log_ok "Namespace-owner token ready."
    print_kv "mode:" "${MODE}"
    print_kv "namespace:" "${NAMESPACE}"
    print_kv "api:" "${API_URL}"
    print_kv "token_file:" "${TOKEN_FILE}"
    if [[ "$WRITE_OPENCLAW" == "true" ]]; then
      print_kv "openclaw_config:" "${CONFIG_PATH}"
      print_kv "authz_notify_enabled:" "${ENABLE_AUTHZ_NOTIFY}"
    fi
    if [[ "$PRINT_TOKEN" == "true" ]]; then
      printf '\n'
      log_info "JWT:"
      printf '%s\n' "$OWNER_TOKEN"
    fi
    ;;
  show)
    NAMESPACE="${SIGILUM_NAMESPACE:-${GATEWAY_SIGILUM_NAMESPACE:-${USER:-default}}}"
    OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
    TOKEN_FILE=""

    while [[ $# -gt 0 ]]; do
      case "$1" in
        --namespace)
          NAMESPACE="${2:-}"
          shift 2
          ;;
        --openclaw-home)
          OPENCLAW_HOME="${2:-}"
          shift 2
          ;;
        --token-file)
          TOKEN_FILE="${2:-}"
          shift 2
          ;;
        -h|--help)
          usage
          exit 0
          ;;
        *)
          log_error "Unknown option: $1"
          usage >&2
          exit 1
          ;;
      esac
    done

    if [[ -z "$TOKEN_FILE" ]]; then
      TOKEN_FILE="${OPENCLAW_HOME}/.sigilum/owner-token-${NAMESPACE}.jwt"
    fi
    if [[ ! -f "$TOKEN_FILE" ]]; then
      log_error "Token file not found: ${TOKEN_FILE}"
      exit 1
    fi
    cat "$TOKEN_FILE"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    log_error "Unknown auth command: ${command}"
    usage >&2
    exit 1
    ;;
esac
