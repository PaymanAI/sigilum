#!/usr/bin/env bash

# Shared shell helpers for installer and operational scripts.

CLR_RESET="${CLR_RESET:-}"
CLR_BOLD="${CLR_BOLD:-}"
CLR_DIM="${CLR_DIM:-}"
CLR_RED="${CLR_RED:-}"
CLR_GREEN="${CLR_GREEN:-}"
CLR_YELLOW="${CLR_YELLOW:-}"
CLR_CYAN="${CLR_CYAN:-}"

setup_colors() {
  if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-}" != "dumb" ]]; then
    CLR_RESET=$'\033[0m'
    CLR_BOLD=$'\033[1m'
    CLR_DIM=$'\033[2m'
    CLR_RED=$'\033[31m'
    CLR_GREEN=$'\033[32m'
    CLR_YELLOW=$'\033[33m'
    CLR_CYAN=$'\033[36m'
  fi
}

log_step() {
  printf '%s✧%s %s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}" "$1"
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

print_kv() {
  printf '  %s%-9s%s %s\n' "${CLR_BOLD}" "$1" "${CLR_RESET}" "$2"
}

detect_rc_files() {
  local files=()
  local shell_name
  shell_name="$(basename "${SHELL:-zsh}")"

  case "$shell_name" in
    zsh)
      [[ -f "$HOME/.zshrc" ]] && files+=("$HOME/.zshrc")
      [[ ${#files[@]} -eq 0 ]] && files+=("$HOME/.zshrc")
      ;;
    bash)
      [[ -f "$HOME/.bashrc" ]] && files+=("$HOME/.bashrc")
      [[ ${#files[@]} -eq 0 ]] && files+=("$HOME/.bashrc")
      ;;
    *)
      [[ -f "$HOME/.zshrc" ]] && files+=("$HOME/.zshrc")
      [[ -f "$HOME/.bashrc" ]] && files+=("$HOME/.bashrc")
      [[ ${#files[@]} -eq 0 ]] && files+=("$HOME/.profile")
      ;;
  esac

  printf '%s\n' "${files[@]}"
}

detect_primary_rc_file() {
  local rc_file
  rc_file="$(detect_rc_files | head -n 1)"
  if [[ -n "$rc_file" ]]; then
    printf '%s\n' "$rc_file"
    return 0
  fi
  printf '%s\n' "$HOME/.profile"
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
