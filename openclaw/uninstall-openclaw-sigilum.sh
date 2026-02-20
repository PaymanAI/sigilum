#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OPENCLAW_LIB_DIR="${ROOT_DIR}/openclaw/lib"

DETECT_WORKSPACE_SCRIPT="${OPENCLAW_LIB_DIR}/detect-workspace.mjs"
DETECT_SIGILUM_PATHS_SCRIPT="${OPENCLAW_LIB_DIR}/detect-sigilum-paths.mjs"
REMOVE_OPENCLAW_CONFIG_SCRIPT="${OPENCLAW_LIB_DIR}/remove-openclaw-sigilum-config.mjs"

OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
SIGILUM_CONFIG_HOME="${SIGILUM_CONFIG_HOME:-$HOME/.sigilum}"
SIGILUM_CONFIG_FILE="${SIGILUM_CONFIG_FILE:-${SIGILUM_CONFIG_HOME}/config.env}"
CONFIG_PATH=""
WORKSPACE_PATH=""
KEY_ROOT=""
RUNTIME_ROOT=""
SIGILUM_HOME=""
SIGILUM_CONFIG_REMOVED=""
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
Remove Sigilum footprint from an OpenClaw installation.

Usage:
  ./openclaw/uninstall-openclaw-sigilum.sh [options]

Options:
  --openclaw-home PATH    Target OpenClaw home (default: ~/.openclaw)
  --config PATH           Path to openclaw.json (default: <openclaw-home>/openclaw.json)
  --workspace PATH        Override workspace path for cleanup
  --key-root PATH         Override key root path for cleanup
  --runtime-root PATH     Override runtime root path for cleanup
  --sigilum-home PATH     Override SIGILUM_HOME path for cleanup
  --sigilum-config-file PATH  Override managed Sigilum defaults file cleanup path
  -h, --help              Show help
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "Missing required file: $path" >&2
    exit 1
  fi
}

backup_path() {
  local path="$1"
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  printf '%s.bak.%s' "$path" "$ts"
}

safe_remove_path() {
  local target="$1"
  node - "$target" <<'NODE'
const fs = require("fs");
const target = String(process.argv[2] || "").trim();
if (!target || target === "/" || target === "." || target === "..") {
  process.exit(2);
}
fs.rmSync(target, { recursive: true, force: true, maxRetries: 2, retryDelay: 50 });
NODE
}

append_unique_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    return 0
  fi
  if [[ "$path" == "/" || "$path" == "." || "$path" == ".." ]]; then
    return 0
  fi
  case "${REMOVE_PATHS}" in
    *$'\n'"${path}"$'\n'*)
      ;;
    *)
      REMOVE_PATHS="${REMOVE_PATHS}${path}"$'\n'
      ;;
  esac
}

read_env_file_value() {
  local file_path="$1"
  local key="$2"
  local line lhs rhs first_char last_char

  [[ -f "$file_path" ]] || return 1

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" == *"="* ]] || continue

    lhs="$(trim "${line%%=*}")"
    [[ -n "$lhs" ]] || continue
    [[ "${lhs:0:1}" != "#" ]] || continue
    [[ "$lhs" == "$key" ]] || continue

    rhs="$(trim "${line#*=}")"
    if [[ ${#rhs} -ge 2 ]]; then
      first_char="${rhs:0:1}"
      last_char="${rhs: -1}"
      if [[ "$first_char" == "\"" && "$last_char" == "\"" ]]; then
        rhs="${rhs:1:${#rhs}-2}"
      elif [[ "$first_char" == "'" && "$last_char" == "'" ]]; then
        rhs="${rhs:1:${#rhs}-2}"
      fi
    fi

    printf '%s' "$rhs"
    return 0
  done < "$file_path"

  return 1
}

remove_managed_sigilum_cli_defaults() {
  local managed_flag
  if [[ ! -f "$SIGILUM_CONFIG_FILE" ]]; then
    return 0
  fi

  managed_flag="$(read_env_file_value "$SIGILUM_CONFIG_FILE" "SIGILUM_OPENCLAW_MANAGED" || true)"
  managed_flag="$(trim "$managed_flag")"
  managed_flag="$(printf '%s' "$managed_flag" | tr '[:upper:]' '[:lower:]')"
  if [[ "$managed_flag" != "true" ]]; then
    return 0
  fi

  rm -f "$SIGILUM_CONFIG_FILE"
  SIGILUM_CONFIG_REMOVED="$SIGILUM_CONFIG_FILE"

  local config_dir
  config_dir="$(dirname "$SIGILUM_CONFIG_FILE")"
  rmdir "$config_dir" 2>/dev/null || true
  return 0
}

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
    --workspace)
      WORKSPACE_PATH="${2:-}"
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
    --sigilum-home)
      SIGILUM_HOME="${2:-}"
      shift 2
      ;;
    --sigilum-config-file)
      SIGILUM_CONFIG_FILE="${2:-}"
      shift 2
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

setup_colors

OPENCLAW_HOME="$(trim "$OPENCLAW_HOME")"
if [[ -z "$OPENCLAW_HOME" ]]; then
  echo "--openclaw-home cannot be empty" >&2
  exit 1
fi

if [[ -z "$CONFIG_PATH" ]]; then
  CONFIG_PATH="${OPENCLAW_HOME}/openclaw.json"
fi

require_file "$DETECT_WORKSPACE_SCRIPT"
require_file "$DETECT_SIGILUM_PATHS_SCRIPT"
require_file "$REMOVE_OPENCLAW_CONFIG_SCRIPT"

DETECTED_WORKSPACE=""
DETECTED_KEY_ROOT=""
DETECTED_RUNTIME_ROOT=""
DETECTED_SIGILUM_HOME=""

if [[ -f "$CONFIG_PATH" ]]; then
  if detected_values="$(node "$DETECT_SIGILUM_PATHS_SCRIPT" "$CONFIG_PATH" 2>/dev/null || true)"; then
    IFS=$'\t' read -r DETECTED_WORKSPACE DETECTED_KEY_ROOT DETECTED_RUNTIME_ROOT DETECTED_SIGILUM_HOME <<<"$detected_values"
  fi
  if [[ -z "$DETECTED_WORKSPACE" ]]; then
    DETECTED_WORKSPACE="$(node "$DETECT_WORKSPACE_SCRIPT" "$CONFIG_PATH" 2>/dev/null || true)"
  fi
fi

WORKSPACE_PATH="$(trim "${WORKSPACE_PATH:-$DETECTED_WORKSPACE}")"
KEY_ROOT="$(trim "${KEY_ROOT:-$DETECTED_KEY_ROOT}")"
RUNTIME_ROOT="$(trim "${RUNTIME_ROOT:-$DETECTED_RUNTIME_ROOT}")"
SIGILUM_HOME="$(trim "${SIGILUM_HOME:-$DETECTED_SIGILUM_HOME}")"

if [[ -z "$KEY_ROOT" ]]; then
  KEY_ROOT="${OPENCLAW_HOME}/.sigilum/keys"
fi

REMOVE_PATHS=$'\n'
append_unique_path "${OPENCLAW_HOME}/hooks/sigilum-plugin"
append_unique_path "${OPENCLAW_HOME}/hooks/sigilum-authz-notify"
append_unique_path "${OPENCLAW_HOME}/skills/sigilum"
append_unique_path "$KEY_ROOT"
append_unique_path "${OPENCLAW_HOME}/.sigilum"
append_unique_path "$RUNTIME_ROOT"
append_unique_path "$SIGILUM_HOME"
if [[ -n "$WORKSPACE_PATH" ]]; then
  append_unique_path "${WORKSPACE_PATH%/}/skills/sigilum"
  append_unique_path "${WORKSPACE_PATH%/}/.sigilum"
fi

print_banner
printf '\n'
printf '%s⚠  Uninstalling Sigilum will remove agent identity keys%s\n' "${CLR_BOLD}${CLR_RED}" "${CLR_RESET}"
printf '%s   and service endpoints exposed and without protection.%s\n\n' "${CLR_BOLD}${CLR_RED}" "${CLR_RESET}"

printf '%sOpenClaw home:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
printf '  %s%s%s\n\n' "${CLR_DIM}" "$OPENCLAW_HOME" "${CLR_RESET}"
if [[ -n "$WORKSPACE_PATH" ]]; then
  printf '%sWorkspace:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
  printf '  %s%s%s\n\n' "${CLR_DIM}" "$WORKSPACE_PATH" "${CLR_RESET}"
fi

removed_count=0
missing_count=0
failed_count=0

while IFS= read -r path; do
  path="$(trim "$path")"
  [[ -z "$path" ]] && continue

  if [[ "$path" == "$HOME" || "$path" == "${OPENCLAW_HOME%/}" || ( -n "$WORKSPACE_PATH" && "$path" == "${WORKSPACE_PATH%/}" ) ]]; then
    echo "[skip] unsafe target: $path"
    continue
  fi

  if [[ -e "$path" ]]; then
    if safe_remove_path "$path"; then
      printf '%s✧ removed%s %s%s%s\n' "${CLR_BOLD}${CLR_GREEN}" "${CLR_RESET}" "${CLR_DIM}" "$path" "${CLR_RESET}"
      removed_count=$((removed_count + 1))
    else
      printf '%s✧ failed%s  %s%s%s\n' "${CLR_BOLD}${CLR_RED}" "${CLR_RESET}" "${CLR_DIM}" "$path" "${CLR_RESET}"
      failed_count=$((failed_count + 1))
    fi
  else
    printf '%s✧ missing%s %s%s%s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}" "${CLR_DIM}" "$path" "${CLR_RESET}"
    missing_count=$((missing_count + 1))
  fi
done <<<"$REMOVE_PATHS"

sigilum_defaults_status="skipped"
if remove_managed_sigilum_cli_defaults; then
  if [[ -n "$SIGILUM_CONFIG_REMOVED" ]]; then
    sigilum_defaults_status="removed"
  else
    sigilum_defaults_status="unchanged"
  fi
else
  sigilum_defaults_status="failed"
  failed_count=$((failed_count + 1))
fi

config_status="skipped (missing config)"
config_backup=""
if [[ -f "$CONFIG_PATH" ]]; then
  config_backup="$(backup_path "$CONFIG_PATH")"
  cp "$CONFIG_PATH" "$config_backup"
  if node "$REMOVE_OPENCLAW_CONFIG_SCRIPT" "$CONFIG_PATH"; then
    config_status="cleaned"
  else
    config_status="failed"
    failed_count=$((failed_count + 1))
  fi
fi

printf '\n%sUninstall summary:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
printf '  %sremoved%s=%s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$removed_count" "${CLR_RESET}"
printf '  %smissing%s=%s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_YELLOW}" "$missing_count" "${CLR_RESET}"
printf '  %sfailed%s=%s%s%s\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_RED}" "$failed_count" "${CLR_RESET}"
printf '  %sconfig%s=%s%s%s\n\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$config_status" "${CLR_RESET}"
printf '  %sdefaults%s=%s%s%s\n\n' "${CLR_BOLD}" "${CLR_RESET}" "${CLR_GREEN}" "$sigilum_defaults_status" "${CLR_RESET}"
if [[ -n "$config_backup" ]]; then
  printf '%sConfig backup:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
  printf '  %s%s%s\n\n' "${CLR_DIM}" "$config_backup" "${CLR_RESET}"
fi
if [[ -n "$SIGILUM_CONFIG_REMOVED" ]]; then
  printf '%sRemoved defaults file:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
  printf '  %s%s%s\n\n' "${CLR_DIM}" "$SIGILUM_CONFIG_REMOVED" "${CLR_RESET}"
fi

if (( failed_count > 0 )); then
  exit 1
fi
