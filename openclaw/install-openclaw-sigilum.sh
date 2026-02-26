#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

HOOK_PLUGIN_SRC="${ROOT_DIR}/openclaw/hooks/sigilum-plugin"
HOOK_AUTHZ_NOTIFY_SRC="${ROOT_DIR}/openclaw/hooks/sigilum-authz-notify"
SKILL_SIGILUM_SRC="${ROOT_DIR}/openclaw/skills/sigilum"
SIGILUM_LAUNCHER_SRC="${ROOT_DIR}/sigilum"
SIGILUM_SCRIPTS_SRC="${ROOT_DIR}/scripts"
OPENCLAW_LIB_DIR="${ROOT_DIR}/openclaw/lib"
DETECT_RUNTIME_ROOT_SCRIPT="${OPENCLAW_LIB_DIR}/detect-runtime-root.mjs"
DETECT_WORKSPACE_SCRIPT="${OPENCLAW_LIB_DIR}/detect-workspace.mjs"
UPDATE_OPENCLAW_CONFIG_SCRIPT="${OPENCLAW_LIB_DIR}/update-openclaw-config.mjs"

OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
CONFIG_PATH=""
MODE="${SIGILUM_MODE:-managed}"
NAMESPACE="${SIGILUM_NAMESPACE:-${USER:-default}}"
SIGILUM_SOURCE_HOME="${SIGILUM_SOURCE_HOME:-}"
OSS_SOURCE_HOME="$ROOT_DIR"
GATEWAY_URL="${SIGILUM_GATEWAY_URL:-}"
API_URL="${SIGILUM_API_URL:-}"
SIGILUM_CONFIG_HOME="${SIGILUM_CONFIG_HOME:-$HOME/.sigilum}"
SIGILUM_CONFIG_FILE="${SIGILUM_CONFIG_FILE:-${SIGILUM_CONFIG_HOME}/config.env}"
KEY_ROOT=""
RUNTIME_ROOT="${SIGILUM_RUNTIME_ROOT:-}"
AGENT_WORKSPACE=""
ENABLE_AUTHZ_NOTIFY="false"
OWNER_TOKEN="${SIGILUM_OWNER_TOKEN:-}"
DASHBOARD_URL="${SIGILUM_DASHBOARD_URL:-}"
AUTO_OWNER_TOKEN="${SIGILUM_AUTO_OWNER_TOKEN:-}"
OWNER_EMAIL="${SIGILUM_OWNER_EMAIL:-}"
FORCE="false"
RESTART="false"
STOP_CMD=""
START_CMD=""
AUTO_START_SIGILUM="${SIGILUM_AUTO_START:-true}"
SIGILUM_UP_LOG_FILE=""
PERSISTED_SIGILUM_CONFIG_PATH=""
INTERACTIVE_MODE="auto"
CLR_RESET=""
CLR_BOLD=""
CLR_DIM=""
CLR_RED=""
CLR_GREEN=""
CLR_YELLOW=""
CLR_BLUE=""
CLR_MAGENTA=""
CLR_CYAN=""

usage() {
  cat <<'USAGE'
Install Sigilum OpenClaw hooks + skills from local source.

Usage:
  ./openclaw/install-openclaw-sigilum.sh [options]

Options:
  --openclaw-home PATH            Target OpenClaw home (default: ~/.openclaw)
  --config PATH                   Path to openclaw.json (default: <openclaw-home>/openclaw.json)
  --mode MODE                     Sigilum mode: managed|oss-local (default: managed)
  --source-home PATH              Sigilum source checkout root for oss-local mode (must contain apps/api)
  --namespace VALUE               Sigilum namespace (default: $SIGILUM_NAMESPACE, then $USER)
  --gateway-url URL               Sigilum gateway URL (mode default: http://localhost:38100)
  --api-url URL                   Sigilum API URL (default: https://api.sigilum.id)
  --key-root PATH                 Agent key root (default: <openclaw-home>/.sigilum/keys)
  --runtime-root PATH             Bundled runtime destination (default: <agent-workspace>/.sigilum/runtime, else <openclaw-home>/skills/sigilum/runtime)
  --enable-authz-notify BOOL      Enable authz notify hook (true|false, default: false)
  --owner-token TOKEN             Namespace-owner JWT for authz notify hook
  --auto-owner-token BOOL         Auto-issue local owner JWT in oss-local mode (default: true in oss-local when --owner-token is not provided)
  --auto-start-sigilum BOOL       Auto-start local Sigilum stack when API/gateway local defaults are down (true|false, default: true)
  --owner-email VALUE             Owner email for local auto-registration (default: <namespace>@local.sigilum)
  --dashboard-url URL             Dashboard URL shown in authz notifications
  --interactive                   Force interactive onboarding prompts
  --non-interactive               Disable onboarding prompts
  --force                         Replace existing Sigilum hook/skill directories without backup
  --restart                       Restart OpenClaw after install
  --stop-cmd CMD                  Command used with --restart to stop OpenClaw
  --start-cmd CMD                 Command used with --restart to start OpenClaw
  -h, --help                      Show help

Environment overrides:
  OPENCLAW_HOME, SIGILUM_MODE, SIGILUM_SOURCE_HOME, SIGILUM_NAMESPACE, SIGILUM_GATEWAY_URL, SIGILUM_API_URL,
  SIGILUM_OWNER_TOKEN, SIGILUM_AUTO_OWNER_TOKEN, SIGILUM_AUTO_START, SIGILUM_OWNER_EMAIL, SIGILUM_DASHBOARD_URL,
  SIGILUM_CONFIG_HOME, SIGILUM_CONFIG_FILE
USAGE
}

setup_colors() {
  if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-}" != "dumb" ]]; then
    CLR_RESET=$'\033[0m'
    CLR_BOLD=$'\033[1m'
    CLR_DIM=$'\033[2m'
    CLR_RED=$'\033[31m'
    CLR_GREEN=$'\033[32m'
    CLR_YELLOW=$'\033[33m'
    CLR_BLUE=$'\033[34m'
    CLR_MAGENTA=$'\033[35m'
    CLR_CYAN=$'\033[36m'
  fi
}

log_step() {
  printf '%s✧%s %s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}" "$1"
}

log_info() {
  printf '%s[i]%s %s\n' "${CLR_BOLD}${CLR_BLUE}" "${CLR_RESET}" "$1"
}

log_ok() {
  printf '%s[ok]%s %s\n' "${CLR_BOLD}${CLR_GREEN}" "${CLR_RESET}" "$1"
}

log_warn() {
  printf '%s[warn]%s %s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}" "$1"
}

log_error() {
  printf '%s[ERROR]%s %s\n' "${CLR_BOLD}${CLR_RED}" "${CLR_RESET}" "$1" >&2
}

print_section() {
  printf '\n%s%s%s\n' "${CLR_BOLD}${CLR_MAGENTA}" "$1" "${CLR_RESET}"
}

print_labeled_block() {
  local label="$1"
  local value="$2"
  printf '%s%s:%s\n' "${CLR_BOLD}${CLR_CYAN}" "$label" "${CLR_RESET}"
  printf '  %s%s%s\n\n' "${CLR_DIM}" "$value" "${CLR_RESET}"
}

print_command_line() {
  printf '     %s%s%s\n' "${CLR_BOLD}${CLR_YELLOW}" "$1" "${CLR_RESET}"
}

require_dir() {
  local path="$1"
  if [[ ! -d "$path" ]]; then
    log_error "Missing required source directory: $path"
    exit 1
  fi
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    log_error "Missing required source file: $path"
    exit 1
  fi
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

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

has_local_oss_source_layout() {
  local source_root="$1"
  local api_dir="${source_root}/apps/api"
  local wrangler_template="${api_dir}/wrangler.toml.example"
  [[ -d "$api_dir" && -f "$wrangler_template" ]]
}

resolve_oss_source_home() {
  local candidate
  candidate="$(trim "${SIGILUM_SOURCE_HOME:-}")"
  if [[ -z "$candidate" ]]; then
    candidate="$ROOT_DIR"
  fi
  if [[ -d "$candidate" ]]; then
    OSS_SOURCE_HOME="$(cd "$candidate" && pwd)"
  else
    OSS_SOURCE_HOME="$candidate"
  fi
}

require_local_oss_source_layout() {
  local source_root="$1"
  if has_local_oss_source_layout "$source_root"; then
    return 0
  fi

  local api_dir="${source_root}/apps/api"
  local wrangler_template="${api_dir}/wrangler.toml.example"

  log_error "oss-local mode requires a full Sigilum source checkout."
  printf '%sCurrent runtime does not include local API sources:%s\n' "${CLR_BOLD}${CLR_RED}" "${CLR_RESET}" >&2
  printf '  %sexpected directory:%s %s\n' "${CLR_BOLD}" "${CLR_RESET}" "$api_dir" >&2
  printf '  %sexpected file:%s      %s\n\n' "${CLR_BOLD}" "${CLR_RESET}" "$wrangler_template" >&2
  printf '%sRun oss-local from a source checkout directory:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}" >&2
  printf '  %sgit clone https://github.com/PaymanAI/sigilum.git%s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}" >&2
  printf '  %scd sigilum%s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}" >&2
  printf '  %s./sigilum openclaw install --mode oss-local --api-url http://127.0.0.1:8787%s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}" >&2
  printf '\n'
  printf '%sIf Sigilum CLI is globally installed, pass source explicitly:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}" >&2
  printf '  %ssigilum openclaw install --mode oss-local --source-home /path/to/sigilum --api-url http://127.0.0.1:8787%s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}" >&2
  exit 1
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

should_prompt_interactive() {
  case "$INTERACTIVE_MODE" in
    true)
      return 0
      ;;
    false)
      return 1
      ;;
    auto)
      [[ -t 0 && -t 1 ]]
      return $?
      ;;
    *)
      return 1
      ;;
  esac
}

print_banner() {
  cat <<BANNER
${CLR_BOLD}${CLR_YELLOW}✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧${CLR_RESET}
${CLR_BOLD}${CLR_YELLOW}✧${CLR_RESET}                                                          ${CLR_BOLD}${CLR_YELLOW}✧${CLR_RESET}
${CLR_BOLD}${CLR_YELLOW}✧${CLR_RESET}                                                          ${CLR_BOLD}${CLR_YELLOW}✧${CLR_RESET}
${CLR_BOLD}${CLR_YELLOW}✧${CLR_RESET}                  ${CLR_BOLD}${CLR_YELLOW}✧${CLR_RESET} ${CLR_BOLD}S I G I L U M${CLR_YELLOW}.${CLR_RESET}                        ${CLR_BOLD}${CLR_YELLOW}✧${CLR_RESET}
${CLR_BOLD}${CLR_YELLOW}✧${CLR_RESET}            ${CLR_DIM}Auditable Identity for AI Agents${CLR_RESET}              ${CLR_BOLD}${CLR_YELLOW}✧${CLR_RESET}
${CLR_BOLD}${CLR_YELLOW}✧${CLR_RESET}                                                          ${CLR_BOLD}${CLR_YELLOW}✧${CLR_RESET}
${CLR_BOLD}${CLR_YELLOW}✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧${CLR_RESET}
BANNER
}

prompt_required_value() {
  local label="$1"
  local default_value="${2:-}"
  local raw=""
  while true; do
    if [[ -n "$default_value" ]]; then
      read -r -p "${CLR_BOLD}${CLR_CYAN}${label}${CLR_RESET} [${CLR_YELLOW}${default_value}${CLR_RESET}]: " raw || return 1
      raw="${raw:-$default_value}"
    else
      read -r -p "${CLR_BOLD}${CLR_CYAN}${label}${CLR_RESET}: " raw || return 1
    fi
    raw="$(trim "$raw")"
    if [[ -n "$raw" ]]; then
      printf '%s' "$raw"
      return 0
    fi
    log_warn "Value is required."
  done
}

prompt_install_inputs() {
  local namespace_default openclaw_home_default api_default source_home_default
  namespace_default="$(trim "${NAMESPACE:-${USER:-default}}")"
  openclaw_home_default="$(trim "${OPENCLAW_HOME:-$HOME/.openclaw}")"
  api_default="$(trim "${API_URL:-https://api.sigilum.id}")"

  print_banner
  printf '\n'
  printf '%sSigilum will now install OpenClaw hooks + skills, with mode defaults.%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
  printf '%sPress Enter to accept defaults, or type overrides.%s\n\n' "${CLR_DIM}" "${CLR_RESET}"

  printf '%sYour namespace is your Sigilum account. All your agents and%s\n' "${CLR_DIM}" "${CLR_RESET}"
  printf '%sservice keys are managed under this namespace.%s\n\n' "${CLR_DIM}" "${CLR_RESET}"
  NAMESPACE="$(prompt_required_value "Namespace" "$namespace_default")"
  OPENCLAW_HOME="$(prompt_required_value "OpenClaw home directory (.openclaw path)" "$openclaw_home_default")"
  API_URL="$(prompt_required_value "Sigilum API URL (not dashboard URL)" "$api_default")"
  if [[ "$MODE" == "oss-local" ]]; then
    source_home_default="$(trim "${SIGILUM_SOURCE_HOME:-$ROOT_DIR}")"
    SIGILUM_SOURCE_HOME="$(prompt_required_value "Sigilum source checkout path (contains apps/api)" "$source_home_default")"
  fi
  if [[ -z "$DASHBOARD_URL" ]]; then
    DASHBOARD_URL="https://sigilum.id"
  fi

  printf '\n'
  log_info "Managed onboarding is default; pass --mode oss-local only for local API development."
  if [[ "$MODE" == "oss-local" ]]; then
    log_warn "oss-local requires running this installer from a full Sigilum source checkout (apps/api present)."
  fi
  log_info "Demo services are not started by this installer."
  printf '\n'
}

backup_path() {
  local path="$1"
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  printf '%s.bak.%s' "$path" "$ts"
}

escape_env_value() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

persist_sigilum_cli_defaults() {
  local config_file config_dir tmp_file
  config_file="$SIGILUM_CONFIG_FILE"
  config_dir="$(dirname "$config_file")"

  mkdir -p "$config_dir"
  chmod 700 "$config_dir" 2>/dev/null || true

  tmp_file="$(mktemp "${TMPDIR:-/tmp}/sigilum-config-XXXXXX")"
  {
    printf '# Sigilum CLI defaults (managed by sigilum openclaw install)\n'
    printf 'SIGILUM_OPENCLAW_MANAGED=true\n'
    printf 'SIGILUM_NAMESPACE="%s"\n' "$(escape_env_value "$NAMESPACE")"
    printf 'GATEWAY_SIGILUM_NAMESPACE="%s"\n' "$(escape_env_value "$NAMESPACE")"
    printf 'SIGILUM_API_URL="%s"\n' "$(escape_env_value "$API_URL")"
    printf 'SIGILUM_GATEWAY_URL="%s"\n' "$(escape_env_value "$GATEWAY_URL")"
  } >"$tmp_file"

  mv "$tmp_file" "$config_file"
  chmod 600 "$config_file" 2>/dev/null || true
  PERSISTED_SIGILUM_CONFIG_PATH="$config_file"
}

tree_backup_path() {
  local dest="$1"
  local bucket="$2"
  local ts base backup_dir
  ts="$(date +%Y%m%d-%H%M%S)"
  base="$(basename "$dest")"
  backup_dir="${OPENCLAW_HOME}/backups/${bucket}"
  mkdir -p "$backup_dir"
  printf '%s/%s.bak.%s' "$backup_dir" "$base" "$ts"
}

install_tree() {
  local src="$1"
  local dest="$2"
  local backup_bucket="${3:-artifacts}"

  if [[ -e "$dest" ]]; then
    if [[ "$FORCE" == "true" ]]; then
      rm -rf "$dest"
    else
      local backup
      backup="$(tree_backup_path "$dest" "$backup_bucket")"
      mv "$dest" "$backup"
      log_info "Backed up existing: $dest -> $backup"
    fi
  fi

  mkdir -p "$(dirname "$dest")"
  cp -R "$src" "$dest"
}

normalize_runtime_permissions() {
  local runtime_root="$1"
  [[ -z "$runtime_root" ]] && return 0
  if [[ ! -d "$runtime_root" ]]; then
    return 0
  fi

  chmod -R u+rwX,go-rwx "$runtime_root" 2>/dev/null || true
  if [[ -f "${runtime_root}/sigilum" ]]; then
    chmod 700 "${runtime_root}/sigilum" 2>/dev/null || true
  fi
  if [[ -d "${runtime_root}/scripts" ]]; then
    find "${runtime_root}/scripts" -type f -name "*.sh" -exec chmod 700 {} + 2>/dev/null || true
    find "${runtime_root}/scripts" -type f ! -name "*.sh" -exec chmod 600 {} + 2>/dev/null || true
  fi
}

normalize_skill_permissions() {
  local skill_root="$1"
  [[ -z "$skill_root" ]] && return 0
  if [[ ! -d "$skill_root" ]]; then
    return 0
  fi

  chmod -R u+rwX,go-rwx "$skill_root" 2>/dev/null || true
  if [[ -d "${skill_root}/bin" ]]; then
    find "${skill_root}/bin" -type f -name "*.sh" -exec chmod 700 {} + 2>/dev/null || true
  fi
}

normalize_hook_permissions() {
  local hook_root="$1"
  [[ -z "$hook_root" ]] && return 0
  if [[ ! -d "$hook_root" ]]; then
    return 0
  fi

  chmod -R u+rwX,go-rwx "$hook_root" 2>/dev/null || true
  find "$hook_root" -type f -name "*.sh" -exec chmod 700 {} + 2>/dev/null || true
  find "$hook_root" -type f ! -name "*.sh" -exec chmod 600 {} + 2>/dev/null || true
}

build_runtime_bundle() {
  local dest="$1"
  local tmp_runtime
  tmp_runtime="$(mktemp -d "${TMPDIR:-/tmp}/sigilum-openclaw-runtime-XXXXXX")"

  # Lean sandbox runtime: launcher + command scripts only.
  # This avoids copying full monorepo sources into OpenClaw workspace.
  cp "$SIGILUM_LAUNCHER_SRC" "${tmp_runtime}/sigilum"
  chmod +x "${tmp_runtime}/sigilum"
  cp -R "$SIGILUM_SCRIPTS_SRC" "${tmp_runtime}/scripts"

  install_tree "${tmp_runtime}" "$dest" "skills"
  normalize_runtime_permissions "$dest"
  rm -rf "$tmp_runtime"
}

runtime_home_from_root() {
  local root="$1"
  root="${root%/}"
  if [[ "$root" == */runtime ]]; then
    printf '%s' "${root%/runtime}"
    return 0
  fi
  printf '%s' "$root"
}

detect_service_key_source_home() {
  local -a candidates=()
  if [[ -n "${SIGILUM_HOME:-}" ]]; then
    candidates+=("${SIGILUM_HOME}")
  fi
  if [[ -n "${GATEWAY_SIGILUM_HOME:-}" ]]; then
    candidates+=("${GATEWAY_SIGILUM_HOME}")
  fi
  candidates+=(
    "${ROOT_DIR}/.sigilum-workspace"
    "${HOME}/.sigilum"
    "${OPENCLAW_HOME}/workspace/.sigilum"
  )

  local candidate
  shopt -s nullglob
  for candidate in "${candidates[@]}"; do
    [[ -z "$candidate" ]] && continue
    if [[ -d "$candidate" ]]; then
      local files=("${candidate%/}"/service-api-key-*)
      if (( ${#files[@]} > 0 )); then
        printf '%s' "${candidate%/}"
        shopt -u nullglob
        return 0
      fi
    fi
  done
  shopt -u nullglob
  return 1
}

sync_service_api_keys() {
  local source_home="$1"
  local destination_home="$2"
  if [[ -z "$source_home" || -z "$destination_home" ]]; then
    printf '0'
    return 0
  fi
  mkdir -p "$destination_home"
  chmod 700 "$destination_home" 2>/dev/null || true

  local copied=0 file target
  shopt -s nullglob
  for file in "${source_home%/}"/service-api-key-*; do
    target="${destination_home%/}/$(basename "$file")"
    cp "$file" "$target"
    chmod 600 "$target" 2>/dev/null || true
    copied=$((copied + 1))
  done
  shopt -u nullglob
  printf '%s' "$copied"
}

count_service_api_keys() {
  local home="$1"
  if [[ -z "$home" || ! -d "$home" ]]; then
    printf '0'
    return 0
  fi
  local files
  shopt -s nullglob
  files=("${home%/}"/service-api-key-*)
  shopt -u nullglob
  printf '%s' "${#files[@]}"
}

run_cmd() {
  local cmd="$1"
  local -a parts=()
  read -r -a parts <<<"$cmd"
  if (( ${#parts[@]} == 0 )); then
    log_error "Command is empty"
    return 1
  fi
  log_step "Running: ${parts[*]}"
  "${parts[@]}"
}

normalize_url_for_parse() {
  local raw="$1"
  node - "$raw" <<'NODE'
const input = (process.argv[2] || "").trim();
if (!input) process.exit(0);
if (/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) {
  process.stdout.write(input);
  process.exit(0);
}
process.stdout.write(`http://${input}`);
NODE
}

url_host_from_string() {
  local raw="$1"
  local normalized
  normalized="$(normalize_url_for_parse "$raw")"
  if [[ -z "$normalized" ]]; then
    return 0
  fi
  node - "$normalized" <<'NODE'
const raw = (process.argv[2] || "").trim();
if (!raw) process.exit(0);
try {
  const parsed = new URL(raw);
  process.stdout.write(String(parsed.hostname || "").trim().toLowerCase());
} catch {
  process.exit(0);
}
NODE
}

url_port_from_string() {
  local raw="$1"
  local normalized
  normalized="$(normalize_url_for_parse "$raw")"
  if [[ -z "$normalized" ]]; then
    return 0
  fi
  node - "$normalized" <<'NODE'
const raw = (process.argv[2] || "").trim();
if (!raw) process.exit(0);
try {
  const parsed = new URL(raw);
  if (parsed.port) {
    process.stdout.write(parsed.port);
    process.exit(0);
  }
  process.stdout.write(parsed.protocol === "https:" ? "443" : "80");
} catch {
  process.exit(0);
}
NODE
}

health_url_from_base() {
  local raw="$1"
  local normalized
  normalized="$(normalize_url_for_parse "$raw")"
  if [[ -z "$normalized" ]]; then
    return 0
  fi
  node - "$normalized" <<'NODE'
const raw = (process.argv[2] || "").trim();
if (!raw) process.exit(0);
try {
  const parsed = new URL(raw);
  parsed.pathname = "/health";
  parsed.search = "";
  parsed.hash = "";
  process.stdout.write(parsed.toString());
} catch {
  process.exit(0);
}
NODE
}

is_loopback_host() {
  local host
  host="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$host" in
    localhost|127.0.0.1|::1)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_loopback_url() {
  local host
  host="$(url_host_from_string "$1")"
  [[ -n "$host" ]] && is_loopback_host "$host"
}

health_status_code() {
  local base_url="$1"
  local health_url
  local code
  health_url="$(health_url_from_base "$base_url")"
  if [[ -z "$health_url" ]]; then
    printf '000'
    return 0
  fi
  if ! has_cmd curl; then
    printf '000'
    return 0
  fi
  code="$(curl -sS --max-time 4 -o /dev/null -w "%{http_code}" "$health_url" 2>/dev/null || true)"
  if [[ ! "$code" =~ ^[0-9]{3}$ ]]; then
    code="000"
  fi
  printf '%s' "$code"
}

wait_for_health_ok() {
  local base_url="$1"
  local label="$2"
  local timeout_seconds="$3"
  local health_url code elapsed
  health_url="$(health_url_from_base "$base_url")"
  elapsed=0
  while (( elapsed < timeout_seconds )); do
    code="$(health_status_code "$base_url")"
    if [[ "$code" == "200" ]]; then
      log_ok "${label} is healthy: ${health_url}"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  code="$(health_status_code "$base_url")"
  log_warn "${label} health check timed out after ${timeout_seconds}s at ${health_url} (last HTTP ${code})."
  return 1
}

start_local_sigilum_stack_in_background() {
  local api_port gateway_port run_script log_dir log_file up_pid stack_source_home
  stack_source_home="$ROOT_DIR"
  if [[ "$MODE" == "oss-local" ]]; then
    stack_source_home="$OSS_SOURCE_HOME"
  fi
  run_script="${stack_source_home}/scripts/run-local-api-gateway.sh"
  if [[ ! -x "$run_script" ]]; then
    log_warn "Cannot auto-start Sigilum stack: missing executable ${run_script}"
    return 1
  fi
  if ! has_cmd nohup; then
    log_warn "Cannot auto-start Sigilum stack: nohup is not available on PATH."
    return 1
  fi

  api_port="$(url_port_from_string "$API_URL")"
  gateway_port="$(url_port_from_string "$GATEWAY_URL")"
  if [[ -z "$api_port" || -z "$gateway_port" ]]; then
    log_warn "Cannot auto-start Sigilum stack: unable to parse local API/gateway ports."
    return 1
  fi

  log_dir="${OPENCLAW_HOME}/logs"
  mkdir -p "$log_dir"
  log_file="${log_dir}/sigilum-up-$(date +%Y%m%d-%H%M%S).log"

  log_step "Starting local Sigilum stack in background (api=${API_URL}, gateway=${GATEWAY_URL})..."
  API_PORT="$api_port" \
  API_HOST="127.0.0.1" \
  SIGILUM_NAMESPACE="$NAMESPACE" \
  SIGILUM_SOURCE_HOME="$stack_source_home" \
  SIGILUM_REGISTRY_URL="$API_URL" \
  SIGILUM_API_URL="$API_URL" \
  GATEWAY_SIGILUM_NAMESPACE="$NAMESPACE" \
  GATEWAY_ADDR=":${gateway_port}" \
  nohup "$run_script" >"$log_file" 2>&1 < /dev/null &
  up_pid=$!
  disown "$up_pid" 2>/dev/null || true

  SIGILUM_UP_LOG_FILE="$log_file"
  log_info "Sigilum stack launch requested (pid=${up_pid})."
  log_info "Sigilum stack logs: ${log_file}"
  return 0
}

ensure_local_sigilum_stack_ready() {
  local api_local gateway_local api_code gateway_code api_port gateway_port
  local need_start=false wait_ok=true

  if [[ "$AUTO_START_SIGILUM" != "true" ]]; then
    return 0
  fi

  api_local=false
  gateway_local=false
  if is_loopback_url "$API_URL"; then
    api_local=true
  fi
  if is_loopback_url "$GATEWAY_URL"; then
    gateway_local=true
  fi

  if [[ "$api_local" != "true" && "$gateway_local" != "true" ]]; then
    return 0
  fi

  api_code="$(health_status_code "$API_URL")"
  gateway_code="$(health_status_code "$GATEWAY_URL")"

  if [[ "$api_local" == "true" && "$api_code" == "200" && "$gateway_local" == "true" && "$gateway_code" == "200" ]]; then
    log_ok "Sigilum local stack already running; reusing existing API/gateway services."
    return 0
  fi

  if [[ "$api_local" == "true" && "$api_code" != "200" ]]; then
    log_warn "Sigilum API is not healthy at ${API_URL} (HTTP ${api_code})."
  fi
  if [[ "$gateway_local" == "true" && "$gateway_code" != "200" ]]; then
    log_warn "Sigilum gateway is not healthy at ${GATEWAY_URL} (HTTP ${gateway_code})."
  fi

  if [[ "$api_local" != "true" || "$gateway_local" != "true" ]]; then
    log_warn "Auto-start only runs when both API and gateway URLs are loopback/local."
    return 0
  fi

  api_port="$(url_port_from_string "$API_URL")"
  gateway_port="$(url_port_from_string "$GATEWAY_URL")"
  if [[ "$api_port" != "8787" || "$gateway_port" != "38100" ]]; then
    if [[ "$api_code" != "200" && "$api_code" != "000" ]]; then
      log_warn "Local API URL ${API_URL} is reachable but not healthy (HTTP ${api_code}); skipping auto-start to avoid clobbering a non-Sigilum service on that port."
      return 0
    fi
    if [[ "$gateway_code" != "200" && "$gateway_code" != "000" ]]; then
      log_warn "Local gateway URL ${GATEWAY_URL} is reachable but not healthy (HTTP ${gateway_code}); skipping auto-start to avoid clobbering a non-Sigilum service on that port."
      return 0
    fi
    log_info "Auto-start will use non-default local ports (API ${api_port}, gateway ${gateway_port})."
  fi

  if [[ "$api_code" != "200" || "$gateway_code" != "200" ]]; then
    need_start=true
  fi

  if [[ "$need_start" == "true" ]]; then
    start_local_sigilum_stack_in_background || return 0
  fi

  if [[ "$api_code" != "200" ]]; then
    wait_for_health_ok "$API_URL" "Sigilum API" 60 || wait_ok=false
  fi
  if [[ "$gateway_code" != "200" ]]; then
    wait_for_health_ok "$GATEWAY_URL" "Sigilum gateway" 60 || wait_ok=false
  fi

  if [[ "$wait_ok" == "false" ]]; then
    if [[ -n "$SIGILUM_UP_LOG_FILE" ]]; then
      log_warn "Sigilum auto-start did not become healthy in time. Inspect logs: ${SIGILUM_UP_LOG_FILE}"
    else
      log_warn "Sigilum auto-start did not become healthy in time."
    fi
  fi
}

dashboard_origin_from_url() {
  local raw="$1"
  node - "$raw" <<'NODE'
const raw = (process.argv[2] || "").trim();
if (!raw) process.exit(0);
try {
  const url = new URL(raw);
  process.stdout.write(`${url.protocol}//${url.host}`.replace(/\/+$/g, ""));
} catch {
  process.stdout.write(raw.replace(/\/+$/g, ""));
}
NODE
}

build_passkey_setup_url() {
  local dashboard_url="$1"
  local namespace="$2"
  node - "$dashboard_url" "$namespace" <<'NODE'
const dashboardRaw = (process.argv[2] || "").trim();
const namespace = (process.argv[3] || "").trim();
if (!dashboardRaw) process.exit(0);
let origin = dashboardRaw;
try {
  const url = new URL(dashboardRaw);
  origin = `${url.protocol}//${url.host}`;
} catch {
  // fall through with original string
}
process.stdout.write(`${origin.replace(/\/+$/g, "")}/bootstrap/passkey?namespace=${encodeURIComponent(namespace)}`);
NODE
}

detect_default_runtime_root() {
  local config_path="$1"
  local fallback="$2"
  node "$DETECT_RUNTIME_ROOT_SCRIPT" "$config_path" "$fallback"
}

detect_agent_workspace() {
  local config_path="$1"
  node "$DETECT_WORKSPACE_SCRIPT" "$config_path"
}

setup_colors

while [[ $# -gt 0 ]]; do
  case "$1" in
    --openclaw-home)
      OPENCLAW_HOME="${2:-}"
      shift 2
      ;;
    --config)
      CONFIG_PATH="${2:-}"
      shift 2
      ;;
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --source-home)
      SIGILUM_SOURCE_HOME="${2:-}"
      shift 2
      ;;
    --namespace)
      NAMESPACE="${2:-}"
      shift 2
      ;;
    --gateway-url)
      GATEWAY_URL="${2:-}"
      shift 2
      ;;
    --api-url)
      API_URL="${2:-}"
      shift 2
      ;;
    --key-root)
      KEY_ROOT="${2:-}"
      shift 2
      ;;
    --runtime-root)
      RUNTIME_ROOT="${2:-}"
      shift 2
      ;;
    --enable-authz-notify)
      ENABLE_AUTHZ_NOTIFY="${2:-}"
      shift 2
      ;;
    --owner-token)
      OWNER_TOKEN="${2:-}"
      shift 2
      ;;
    --auto-owner-token)
      AUTO_OWNER_TOKEN="${2:-}"
      shift 2
      ;;
    --auto-start-sigilum)
      AUTO_START_SIGILUM="${2:-}"
      shift 2
      ;;
    --owner-email)
      OWNER_EMAIL="${2:-}"
      shift 2
      ;;
    --dashboard-url)
      DASHBOARD_URL="${2:-}"
      shift 2
      ;;
    --interactive)
      INTERACTIVE_MODE="true"
      shift
      ;;
    --non-interactive)
      INTERACTIVE_MODE="false"
      shift
      ;;
    --restart)
      RESTART="true"
      shift
      ;;
    --stop-cmd)
      STOP_CMD="${2:-}"
      shift 2
      ;;
    --start-cmd)
      START_CMD="${2:-}"
      shift 2
      ;;
    --force)
      FORCE="true"
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

if should_prompt_interactive; then
  prompt_install_inputs
fi

if [[ -z "$CONFIG_PATH" ]]; then
  CONFIG_PATH="${OPENCLAW_HOME}/openclaw.json"
fi

case "$MODE" in
  managed|oss-local)
    ;;
  *)
    log_error "--mode must be managed or oss-local"
    exit 1
    ;;
esac

if [[ -z "$GATEWAY_URL" ]]; then
  GATEWAY_URL="http://localhost:38100"
fi
if [[ -z "$API_URL" ]]; then
  API_URL="https://api.sigilum.id"
fi
if [[ -z "$DASHBOARD_URL" ]]; then
  DASHBOARD_URL="https://sigilum.id"
fi
if [[ -z "$KEY_ROOT" ]]; then
  KEY_ROOT="${OPENCLAW_HOME}/.sigilum/keys"
fi
if [[ -z "$OWNER_EMAIL" ]]; then
  OWNER_EMAIL="${NAMESPACE}@local.sigilum"
fi

DASHBOARD_BASE_URL="$(dashboard_origin_from_url "$DASHBOARD_URL")"
PASSKEY_SETUP_URL="$(build_passkey_setup_url "$DASHBOARD_URL" "$NAMESPACE")"
OWNER_TOKEN_FILE_HINT="${OPENCLAW_HOME}/.sigilum/owner-token-${NAMESPACE}.jwt"
if [[ -z "$AUTO_OWNER_TOKEN" ]]; then
  if [[ "$MODE" == "oss-local" && -z "$OWNER_TOKEN" ]]; then
    AUTO_OWNER_TOKEN="true"
  else
    AUTO_OWNER_TOKEN="false"
  fi
fi

if ! is_bool "$ENABLE_AUTHZ_NOTIFY"; then
  log_error "--enable-authz-notify must be true or false"
  exit 1
fi
if ! is_bool "$AUTO_OWNER_TOKEN"; then
  log_error "--auto-owner-token must be true or false"
  exit 1
fi
if ! is_bool "$AUTO_START_SIGILUM"; then
  log_error "--auto-start-sigilum must be true or false"
  exit 1
fi
ENABLE_AUTHZ_NOTIFY="$(normalize_bool "$ENABLE_AUTHZ_NOTIFY")"
AUTO_OWNER_TOKEN="$(normalize_bool "$AUTO_OWNER_TOKEN")"
AUTO_START_SIGILUM="$(normalize_bool "$AUTO_START_SIGILUM")"

resolve_oss_source_home

if [[ "$MODE" == "oss-local" ]]; then
  require_local_oss_source_layout "$OSS_SOURCE_HOME"
fi

ensure_local_sigilum_stack_ready

if [[ "$AUTO_OWNER_TOKEN" == "true" && -z "$OWNER_TOKEN" ]]; then
  if [[ "$MODE" != "oss-local" ]]; then
    log_error "--auto-owner-token=true requires --mode oss-local or explicit --owner-token"
    exit 1
  fi
  AUTH_SCRIPT="${OSS_SOURCE_HOME}/scripts/sigilum-auth.sh"
  if [[ ! -x "$AUTH_SCRIPT" ]]; then
    log_error "Missing auth helper script: ${AUTH_SCRIPT}"
    exit 1
  fi
  OWNER_TOKEN="$(SIGILUM_SOURCE_HOME="$OSS_SOURCE_HOME" "$AUTH_SCRIPT" login \
    --mode "oss-local" \
    --namespace "$NAMESPACE" \
    --email "$OWNER_EMAIL" \
    --api-url "$API_URL" \
    --openclaw-home "$OPENCLAW_HOME" \
    --write-openclaw false \
    --print-token false \
    --token-only)"
  if [[ -z "$OWNER_TOKEN" ]]; then
    log_error "Failed to auto-issue local owner token."
    exit 1
  fi
  log_ok "Auto-issued local namespace-owner token for ${NAMESPACE}."
fi

if [[ "$ENABLE_AUTHZ_NOTIFY" == "true" && -z "$OWNER_TOKEN" ]]; then
  log_error "--owner-token is required when --enable-authz-notify=true"
  exit 1
fi

require_dir "$HOOK_PLUGIN_SRC"
require_dir "$HOOK_AUTHZ_NOTIFY_SRC"
require_dir "$SKILL_SIGILUM_SRC"
require_dir "$OPENCLAW_LIB_DIR"
require_file "$SIGILUM_LAUNCHER_SRC"
require_dir "$SIGILUM_SCRIPTS_SRC"
require_file "$DETECT_RUNTIME_ROOT_SCRIPT"
require_file "$DETECT_WORKSPACE_SCRIPT"
require_file "$UPDATE_OPENCLAW_CONFIG_SCRIPT"

HOOKS_DIR="${OPENCLAW_HOME}/hooks"
SKILLS_DIR="${OPENCLAW_HOME}/skills"
mkdir -p "$HOOKS_DIR" "$SKILLS_DIR" "$KEY_ROOT"
chmod 700 "$KEY_ROOT" 2>/dev/null || true

if [[ ! -f "$CONFIG_PATH" ]]; then
  mkdir -p "$(dirname "$CONFIG_PATH")"
  printf '{}\n' >"$CONFIG_PATH"
  chmod 600 "$CONFIG_PATH" 2>/dev/null || true
fi

CONFIG_BACKUP="$(backup_path "$CONFIG_PATH")"
cp "$CONFIG_PATH" "$CONFIG_BACKUP"

log_step "Installing hooks..."
install_tree "$HOOK_PLUGIN_SRC" "${HOOKS_DIR}/sigilum-plugin" "hooks"
install_tree "$HOOK_AUTHZ_NOTIFY_SRC" "${HOOKS_DIR}/sigilum-authz-notify" "hooks"
normalize_hook_permissions "${HOOKS_DIR}/sigilum-plugin"
normalize_hook_permissions "${HOOKS_DIR}/sigilum-authz-notify"

log_step "Installing skills..."
install_tree "$SKILL_SIGILUM_SRC" "${SKILLS_DIR}/sigilum" "skills"
normalize_skill_permissions "${SKILLS_DIR}/sigilum"

AGENT_WORKSPACE="$(detect_agent_workspace "$CONFIG_PATH")"
if [[ -n "$AGENT_WORKSPACE" ]]; then
  WORKSPACE_SKILLS_DIR="${AGENT_WORKSPACE%/}/skills"
  log_step "Installing workspace skill mirror..."
  install_tree "$SKILL_SIGILUM_SRC" "${WORKSPACE_SKILLS_DIR}/sigilum" "skills"
  normalize_skill_permissions "${WORKSPACE_SKILLS_DIR}/sigilum"
fi

DEFAULT_RUNTIME_ROOT="${SKILLS_DIR}/sigilum/runtime"
if [[ -z "$RUNTIME_ROOT" ]]; then
  RUNTIME_ROOT="$(detect_default_runtime_root "$CONFIG_PATH" "$DEFAULT_RUNTIME_ROOT")"
fi
if [[ -z "$RUNTIME_ROOT" ]]; then
  RUNTIME_ROOT="$DEFAULT_RUNTIME_ROOT"
fi

SKILL_HELPER_BIN="${SKILLS_DIR}/sigilum/bin/gateway-admin.sh"
SKILL_SUBJECT_RESOLVER_BIN="${SKILLS_DIR}/sigilum/bin/resolve-subject.mjs"
if [[ -n "$AGENT_WORKSPACE" ]]; then
  SKILL_HELPER_BIN="${AGENT_WORKSPACE%/}/skills/sigilum/bin/gateway-admin.sh"
  SKILL_SUBJECT_RESOLVER_BIN="${AGENT_WORKSPACE%/}/skills/sigilum/bin/resolve-subject.mjs"
fi

log_step "Installing bundled Sigilum runtime..."
build_runtime_bundle "$RUNTIME_ROOT"
RUNTIME_HOME="$(runtime_home_from_root "$RUNTIME_ROOT")"
KEY_SOURCE_HOME="$(detect_service_key_source_home || true)"
if [[ -n "$KEY_SOURCE_HOME" ]]; then
  SYNCED_KEYS_COUNT="$(sync_service_api_keys "$KEY_SOURCE_HOME" "$RUNTIME_HOME")"
  printf '\n'
  log_ok "Synced ${SYNCED_KEYS_COUNT} service API key file(s) into runtime home: ${RUNTIME_HOME}"
else
  EXISTING_RUNTIME_KEYS="$(count_service_api_keys "$RUNTIME_HOME")"
  if [[ "$EXISTING_RUNTIME_KEYS" != "0" ]]; then
    log_ok "Using ${EXISTING_RUNTIME_KEYS} existing service API key file(s) in runtime home: ${RUNTIME_HOME}"
  elif [[ "$MODE" == "managed" ]]; then
    log_error "No service API key source found and runtime home has no service API key files."
    log_error "Managed mode requires a service API key before signed gateway authorization can work."
    printf '\n'
    printf '%sProvision a service API key, then rerun install:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}" >&2
    printf '  %ssigilum gateway connect --session-id <id> --pair-code <code> --namespace %s --api-url %s%s\n' "${CLR_BOLD}${CLR_YELLOW}" "$NAMESPACE" "$API_URL" "${CLR_RESET}" >&2
    exit 1
  else
    log_warn "No service API key source found to sync into runtime home."
  fi
fi

node "$UPDATE_OPENCLAW_CONFIG_SCRIPT" \
  "$CONFIG_PATH" \
  "$MODE" \
  "$NAMESPACE" \
  "$GATEWAY_URL" \
  "$API_URL" \
  "$KEY_ROOT" \
  "$ENABLE_AUTHZ_NOTIFY" \
  "$OWNER_TOKEN" \
  "$DASHBOARD_URL" \
  "$RUNTIME_ROOT" \
  "$SKILL_HELPER_BIN" \
  "$SKILL_SUBJECT_RESOLVER_BIN" \
  "$RUNTIME_HOME"

persist_sigilum_cli_defaults
if [[ -n "$PERSISTED_SIGILUM_CONFIG_PATH" ]]; then
  log_ok "Persisted Sigilum CLI defaults: ${PERSISTED_SIGILUM_CONFIG_PATH}"
fi

if [[ "$RESTART" == "true" ]]; then
  stop_cmd="${STOP_CMD:-openclaw gateway stop}"
  start_cmd="${START_CMD:-openclaw gateway start}"
  run_cmd "$stop_cmd" || true
  run_cmd "$start_cmd"
fi

if [[ -n "$SIGILUM_UP_LOG_FILE" ]]; then
  print_labeled_block "Sigilum auto-start logs" "$SIGILUM_UP_LOG_FILE"
fi

printf '\n%s✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧%s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}"
printf '%s✧ Sigilum OpenClaw integration completed ✅✅✅%s\n' "${CLR_BOLD}${CLR_GREEN}" "${CLR_RESET}"
printf '%s✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧%s\n\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}"
print_labeled_block "OpenClaw home" "$OPENCLAW_HOME"
print_labeled_block "Config updated" "$CONFIG_PATH"
print_labeled_block "Config backup" "$CONFIG_BACKUP"

printf '\n%sInstalled hooks:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
printf '  %s%s%s\n' "${CLR_DIM}" "${HOOKS_DIR}/sigilum-plugin" "${CLR_RESET}"
printf '  %s%s%s (enabled=%s%s%s)\n\n' \
  "${CLR_DIM}" \
  "${HOOKS_DIR}/sigilum-authz-notify" \
  "${CLR_RESET}" \
  "${CLR_YELLOW}" \
  "$ENABLE_AUTHZ_NOTIFY" \
  "${CLR_RESET}"

printf '%sInstalled skills:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
printf '  %s%s%s\n' "${CLR_DIM}" "${SKILLS_DIR}/sigilum" "${CLR_RESET}"
if [[ -n "$AGENT_WORKSPACE" ]]; then
  printf '  %s%s%s\n' "${CLR_DIM}" "${AGENT_WORKSPACE%/}/skills/sigilum" "${CLR_RESET}"
fi
printf '\n'
print_labeled_block "Bundled runtime" "$RUNTIME_ROOT"

print_section "Sigilum settings"
printf '  %smode%s=%s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$MODE" "${CLR_RESET}"
printf '  %snamespace%s=%s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$NAMESPACE" "${CLR_RESET}"
printf '  %sgateway%s=%s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$GATEWAY_URL" "${CLR_RESET}"
printf '  %sapi%s=%s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$API_URL" "${CLR_RESET}"
printf '  %skey_root%s=%s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$KEY_ROOT" "${CLR_RESET}"
if [[ -n "$PERSISTED_SIGILUM_CONFIG_PATH" ]]; then
  printf '  %sdefaults%s=%s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$PERSISTED_SIGILUM_CONFIG_PATH" "${CLR_RESET}"
fi
if [[ "$MODE" == "oss-local" ]]; then
  printf '  %ssource_home%s=%s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$OSS_SOURCE_HOME" "${CLR_RESET}"
fi

print_section "Dashboard"
printf '  %surl%s=%s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$DASHBOARD_URL" "${CLR_RESET}"
printf '  %spasskey_setup%s=%s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$PASSKEY_SETUP_URL" "${CLR_RESET}"

if [[ "$MODE" == "oss-local" ]]; then
  print_section "Seeded namespace passkey setup"
  printf '  %s1)%s Open: %s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$PASSKEY_SETUP_URL" "${CLR_RESET}"
  if [[ -f "$OWNER_TOKEN_FILE_HINT" ]]; then
    printf '  %s2)%s Paste JWT from: %s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$OWNER_TOKEN_FILE_HINT" "${CLR_RESET}"
  else
    printf '  %s2)%s Paste JWT from: %ssigilum auth show --namespace %s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_YELLOW}" "$NAMESPACE" "${CLR_RESET}"
  fi
  printf '  %s3)%s Register passkey, then sign in at: %s%s/login%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$DASHBOARD_BASE_URL" "${CLR_RESET}"
fi

if [[ "$MODE" == "managed" ]]; then
  print_section "Managed onboarding"
  printf '  %s1)%s Navigate to %s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$DASHBOARD_BASE_URL" "${CLR_RESET}"
  printf '  %s2)%s Sign in and reserve namespace %s"%s"%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$NAMESPACE" "${CLR_RESET}"
  if [[ -n "$OWNER_TOKEN" ]]; then
    printf '  %s3)%s Namespace-owner token already configured for OpenClaw hooks\n' "${CLR_BOLD}" "${CLR_RESET}"
  else
    printf '  %s3)%s Run this command on your terminal:\n' "${CLR_BOLD}" "${CLR_RESET}"
    print_command_line "sigilum auth login --mode managed --namespace ${NAMESPACE} --owner-token-stdin"
  fi
fi

print_section "Next commands"
printf '  %s1)%s Pair gateway requests from the dashboard pairing prompt:\n' "${CLR_BOLD}" "${CLR_RESET}"
print_command_line "sigilum gateway pair --session-id <session-id> --pair-code <pair-code> --namespace ${NAMESPACE} --api-url ${API_URL}"
printf '\n'
if [[ "$MODE" == "managed" ]]; then
  printf '  %s2)%s Navigate to %s%s%s and register a passkey\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$PASSKEY_SETUP_URL" "${CLR_RESET}"
  printf '\n'
  if [[ -n "$OWNER_TOKEN" ]]; then
    printf '  %s3)%s Namespace-owner token already configured for OpenClaw hooks\n' "${CLR_BOLD}" "${CLR_RESET}"
  else
    printf '  %s3)%s Run this command and copy-paste the JWT token in the Sigilum dashboard to access your namespace:\n' "${CLR_BOLD}" "${CLR_RESET}"
    print_command_line "sigilum auth login --mode managed --namespace ${NAMESPACE} --owner-token-stdin"
  fi
  printf '\n'
else
  printf '  %s2)%s Navigate to %s%s%s and register a passkey for the seeded namespace\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$PASSKEY_SETUP_URL" "${CLR_RESET}"
  printf '\n'
fi

if [[ -n "$OWNER_TOKEN" ]]; then
  if [[ -f "$OWNER_TOKEN_FILE_HINT" ]]; then
    print_labeled_block "Namespace-owner JWT stored at" "$OWNER_TOKEN_FILE_HINT"
  else
    log_ok "Namespace-owner JWT provided (value hidden in output)."
  fi
fi
log_info "OpenClaw usually hot-reloads config. If hooks/skills do not appear immediately, run:"
print_command_line "openclaw gateway restart"
printf '\n'
