#!/usr/bin/env bash
set -euo pipefail

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

detect_rc_file() {
  local shell_name
  shell_name="$(basename "${SHELL:-}")"
  case "$shell_name" in
    zsh)
      echo "$HOME/.zshrc"
      ;;
    bash)
      echo "$HOME/.bashrc"
      ;;
    *)
      echo "$HOME/.zshrc"
      ;;
  esac
}

append_if_missing() {
  local file_path="$1"
  local exact_line="$2"
  local grep_pattern="$3"

  touch "$file_path"
  if grep -Fq "$grep_pattern" "$file_path" 2>/dev/null; then
    return 0
  fi

  {
    echo ""
    echo "$exact_line"
  } >>"$file_path"
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
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ ! -x "$CLI_PATH" ]]; then
  echo "sigilum launcher not found or not executable: ${CLI_PATH}" >&2
  exit 1
fi

if [[ -z "$RC_FILE" ]]; then
  RC_FILE="$(detect_rc_file)"
fi

mkdir -p "$BIN_DIR"
ln -sf "$CLI_PATH" "$BIN_DIR/sigilum"

path_line="export PATH=\"${BIN_DIR}:\$PATH\""
append_if_missing "$RC_FILE" "$path_line" "$BIN_DIR"

if [[ "$WITH_ALIAS" == "true" ]]; then
  alias_line="alias sigilum=\"${CLI_PATH}\""
  append_if_missing "$RC_FILE" "$alias_line" "alias sigilum="
fi

echo "Sigilum CLI installed."
echo "  symlink: ${BIN_DIR}/sigilum -> ${CLI_PATH}"
echo "  rc file: ${RC_FILE}"
if [[ "$WITH_ALIAS" == "true" ]]; then
  echo "  alias:   enabled"
fi
echo ""
echo "Run this to activate in current shell:"
echo "  source \"${RC_FILE}\""
echo ""
echo "Then verify:"
echo "  sigilum --help"

