#!/usr/bin/env bash
set -euo pipefail

GITHUB_REPO="PaymanAI/sigilum"
DEFAULT_INSTALL_DIR="$HOME/.sigilum"
INSTALL_DIR=""
VERSION=""
TARBALL_URL=""
TARBALL_FILE=""

CLR_RESET=""
CLR_BOLD=""
CLR_DIM=""
CLR_RED=""
CLR_GREEN=""
CLR_YELLOW=""
CLR_CYAN=""

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

usage() {
  cat <<'EOF'
Install Sigilum CLI from GitHub Releases.

Usage:
  curl -fsSL https://raw.githubusercontent.com/PaymanAI/sigilum/main/scripts/install-curl.sh | bash
  curl -fsSL ... | bash -s -- [options]

Options:
  --prefix <path>       Install location (default: ~/.sigilum)
  --repo <owner/name>   GitHub repo override (default: PaymanAI/sigilum)
  --version <tag>       Install a specific version (default: latest)
  --tarball-url <url>   Install from explicit tarball URL (skip GitHub release lookup)
  --tarball-file <path> Install from local tarball file (skip network download)
  -h, --help            Show help
EOF
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

resolve_latest_version() {
  local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
  local tag

  if command -v curl &>/dev/null; then
    tag="$(curl -fsSL "$api_url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/')"
  elif command -v wget &>/dev/null; then
    tag="$(wget -qO- "$api_url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/')"
  else
    log_error "Neither curl nor wget found. Cannot download."
    exit 1
  fi

  if [[ -z "$tag" ]]; then
    log_error "Could not resolve latest release from GitHub."
    log_error "Check https://github.com/${GITHUB_REPO}/releases"
    exit 1
  fi

  printf '%s' "$tag"
}

download_tarball() {
  local version="$1"
  local dest="$2"
  local url="https://github.com/${GITHUB_REPO}/releases/download/${version}/sigilum-${version}.tar.gz"

  log_step "Downloading sigilum ${version}..."
  printf '  %s%s%s\n' "${CLR_DIM}" "$url" "${CLR_RESET}"

  if command -v curl &>/dev/null; then
    curl -fSL --progress-bar "$url" -o "$dest"
  elif command -v wget &>/dev/null; then
    wget -q --show-progress "$url" -O "$dest"
  else
    log_error "Neither curl nor wget found."
    exit 1
  fi
}

download_explicit_tarball() {
  local source="$1"
  local dest="$2"

  if [[ -f "$source" ]]; then
    log_step "Using local tarball..."
    printf '  %s%s%s\n' "${CLR_DIM}" "$source" "${CLR_RESET}"
    cp "$source" "$dest"
    return 0
  fi

  if [[ "$source" =~ ^https?:// ]]; then
    log_step "Downloading tarball from explicit URL..."
    printf '  %s%s%s\n' "${CLR_DIM}" "$source" "${CLR_RESET}"
    if command -v curl &>/dev/null; then
      curl -fSL --progress-bar "$source" -o "$dest"
    elif command -v wget &>/dev/null; then
      wget -q --show-progress "$source" -O "$dest"
    else
      log_error "Neither curl nor wget found."
      exit 1
    fi
    return 0
  fi

  log_error "Invalid --tarball-file/--tarball-url source: ${source}"
  exit 1
}

setup_colors

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      INSTALL_DIR="${2:-}"
      shift 2
      ;;
    --repo)
      GITHUB_REPO="${2:-}"
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --tarball-url)
      TARBALL_URL="${2:-}"
      shift 2
      ;;
    --tarball-file)
      TARBALL_FILE="${2:-}"
      shift 2
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

INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
INSTALL_DIR="${INSTALL_DIR%/}"

if [[ -n "$TARBALL_URL" && -n "$TARBALL_FILE" ]]; then
  log_error "Use only one of --tarball-url or --tarball-file."
  exit 1
fi

if [[ -n "$TARBALL_FILE" ]]; then
  if [[ ! -f "$TARBALL_FILE" ]]; then
    log_error "--tarball-file not found: ${TARBALL_FILE}"
    exit 1
  fi
fi

print_banner
printf '\n'

if [[ -z "$TARBALL_URL" && -z "$TARBALL_FILE" && -z "$VERSION" ]]; then
  log_step "Resolving latest version..."
  VERSION="$(resolve_latest_version)"
fi

if [[ -n "$TARBALL_URL" || -n "$TARBALL_FILE" ]]; then
  VERSION="${VERSION:-local}"
fi

log_ok "Version: ${VERSION}"
printf '\n'

TMPDIR_DL="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_DL"' EXIT

TARBALL="${TMPDIR_DL}/sigilum-${VERSION}.tar.gz"
if [[ -n "$TARBALL_URL" ]]; then
  download_explicit_tarball "$TARBALL_URL" "$TARBALL"
elif [[ -n "$TARBALL_FILE" ]]; then
  download_explicit_tarball "$TARBALL_FILE" "$TARBALL"
else
  download_tarball "$VERSION" "$TARBALL"
fi
printf '\n'

log_step "Installing to ${INSTALL_DIR}..."

mkdir -p "$INSTALL_DIR"

tar xzf "$TARBALL" -C "$INSTALL_DIR" --strip-components=1

chmod +x "$INSTALL_DIR/sigilum"

log_ok "Extracted to ${INSTALL_DIR}"
printf '\n'

if ! command -v node &>/dev/null; then
  log_warn "node is not installed. Some features (openclaw hooks/skills) require Node.js."
  printf '\n'
fi

log_step "Configuring shell environment..."

SIGILUM_HOME_LINE="export SIGILUM_HOME=\"${INSTALL_DIR}\""
PATH_LINE="export PATH=\"\$SIGILUM_HOME/bin:\$SIGILUM_HOME:\$PATH\""
UPDATED_FILES=()

while IFS= read -r rc_file; do
  [[ -z "$rc_file" ]] && continue

  append_if_missing "$rc_file" "# Sigilum" "# Sigilum"
  append_if_missing "$rc_file" "$SIGILUM_HOME_LINE" "SIGILUM_HOME="
  append_if_missing "$rc_file" "$PATH_LINE" "SIGILUM_HOME/bin:\$SIGILUM_HOME:\$PATH"

  UPDATED_FILES+=("$rc_file")
done < <(detect_rc_files)

for f in "${UPDATED_FILES[@]}"; do
  log_ok "Updated ${f}"
done

printf '\n'
printf '%s✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧%s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}"
printf '%s✧ Sigilum %s installed ✅%s\n' "${CLR_BOLD}${CLR_GREEN}" "$VERSION" "${CLR_RESET}"
printf '%s✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧%s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}"
printf '\n'

printf '%sSIGILUM_HOME:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
printf '  %s%s%s\n\n' "${CLR_DIM}" "$INSTALL_DIR" "${CLR_RESET}"

printf '%sActivate in current shell:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
if [[ ${#UPDATED_FILES[@]} -gt 0 ]]; then
  printf '  %ssource "%s"%s\n\n' "${CLR_BOLD}${CLR_YELLOW}" "${UPDATED_FILES[0]}" "${CLR_RESET}"
fi

printf '%sVerify:%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
printf '  %ssigilum --help%s\n\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}"
