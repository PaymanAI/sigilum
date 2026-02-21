#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/shell-common.sh
source "${SCRIPT_DIR}/shell-common.sh"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_PATH="${ROOT_DIR}/sigilum"

usage() {
  cat <<'EOF'
Install Sigilum CLI into your shell environment.

Usage:
  sigilum install [options]

Options:
  --bin-dir <path>      Install symlink location (default: ~/.local/bin)
  --rc-file <path>      Shell rc file to update (default: inferred from $SHELL)
  --with-alias          Also add alias: alias sigilum="<repo>/sigilum"
  -h, --help            Show help

Examples:
  sigilum install
  sigilum install --with-alias
  sigilum install --bin-dir "$HOME/bin" --rc-file "$HOME/.zshrc"
EOF
}

BIN_DIR="$HOME/.local/bin"
RC_FILE=""
WITH_ALIAS="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir)
      BIN_DIR="${2:-}"
      shift 2
      ;;
    --rc-file)
      RC_FILE="${2:-}"
      shift 2
      ;;
    --with-alias)
      WITH_ALIAS="true"
      shift
      ;;
    -h|--help)
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

setup_colors

if [[ ! -x "$CLI_PATH" ]]; then
  log_error "sigilum launcher not found or not executable: ${CLI_PATH}"
  exit 1
fi

if [[ -z "$RC_FILE" ]]; then
  RC_FILE="$(detect_primary_rc_file)"
fi

mkdir -p "$BIN_DIR"
ln -sf "$CLI_PATH" "$BIN_DIR/sigilum"

path_line="export PATH=\"${BIN_DIR}:\$PATH\""
append_if_missing "$RC_FILE" "$path_line" "$BIN_DIR"

if [[ "$WITH_ALIAS" == "true" ]]; then
  alias_line="alias sigilum=\"${CLI_PATH}\""
  append_if_missing "$RC_FILE" "$alias_line" "alias sigilum="
fi

log_ok "Sigilum CLI installed."
print_kv "symlink:" "${BIN_DIR}/sigilum -> ${CLI_PATH}"
print_kv "rc file:" "${RC_FILE}"
if [[ "$WITH_ALIAS" == "true" ]]; then
  print_kv "alias:" "enabled"
fi
printf '\n%sRun this to activate in current shell:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
printf '  %ssource "%s"%s\n\n' "${CLR_BOLD}${CLR_YELLOW}" "${RC_FILE}" "${CLR_RESET}"
printf '%sThen verify:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
printf '  %ssigilum --help%s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}"
