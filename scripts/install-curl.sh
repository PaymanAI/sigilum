#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./shell-common.sh
source "${SCRIPT_DIR}/shell-common.sh"

GITHUB_REPO="PaymanAI/sigilum"
DEFAULT_INSTALL_DIR="$HOME/.sigilum"
INSTALL_DIR=""
VERSION=""
TARBALL_URL=""
TARBALL_FILE=""
CHECKSUM=""
CHECKSUM_URL=""
CHECKSUM_FILE=""
RELEASE_PUBKEY_FILE="${SIGILUM_RELEASE_PUBKEY_FILE:-}"
REQUIRE_SIGNATURE="false"
CURL_CONNECT_TIMEOUT_SECONDS="${CURL_CONNECT_TIMEOUT_SECONDS:-5}"
CURL_MAX_TIME_SECONDS="${CURL_MAX_TIME_SECONDS:-30}"

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
  --checksum <sha256>   Expected SHA-256 for tarball
  --checksum-url <url>  URL to checksum file (`sha256 [file]` format)
  --checksum-file <path> Local checksum file (`sha256 [file]` format)
  --release-pubkey-file <path>
                        PEM public key for release checksum signature verification
  --require-signature   Require release checksum signature verification
  -h, --help            Show help

Environment:
  SIGILUM_RELEASE_PUBKEY_FILE  Default path for --release-pubkey-file
EOF
}

resolve_latest_version() {
  local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
  local tag

  if command -v curl &>/dev/null; then
    tag="$(curl --connect-timeout "$CURL_CONNECT_TIMEOUT_SECONDS" --max-time "$CURL_MAX_TIME_SECONDS" -fsSL "$api_url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/')"
  elif command -v wget &>/dev/null; then
    tag="$(wget -qO- --timeout="$CURL_MAX_TIME_SECONDS" "$api_url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/')"
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

download_to_file() {
  local source_url="$1"
  local dest="$2"

  if command -v curl &>/dev/null; then
    curl --connect-timeout "$CURL_CONNECT_TIMEOUT_SECONDS" --max-time "$CURL_MAX_TIME_SECONDS" -fSL --progress-bar "$source_url" -o "$dest"
  elif command -v wget &>/dev/null; then
    wget -q --show-progress --timeout="$CURL_MAX_TIME_SECONDS" "$source_url" -O "$dest"
  else
    log_error "Neither curl nor wget found."
    exit 1
  fi
}

download_tarball() {
  local version="$1"
  local dest="$2"
  local url="https://github.com/${GITHUB_REPO}/releases/download/${version}/sigilum-${version}.tar.gz"

  log_step "Downloading sigilum ${version}..."
  printf '  %s%s%s\n' "${CLR_DIM}" "$url" "${CLR_RESET}"

  download_to_file "$url" "$dest"
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
    download_to_file "$source" "$dest"
    return 0
  fi

  log_error "Invalid --tarball-file/--tarball-url source: ${source}"
  exit 1
}

download_release_checksum() {
  local version="$1"
  local dest="$2"
  local url="https://github.com/${GITHUB_REPO}/releases/download/${version}/sigilum-${version}.tar.gz.sha256"

  log_step "Downloading release checksum..."
  printf '  %s%s%s\n' "${CLR_DIM}" "$url" "${CLR_RESET}"
  download_to_file "$url" "$dest"
}

download_release_checksum_signature() {
  local version="$1"
  local dest="$2"
  local url="https://github.com/${GITHUB_REPO}/releases/download/${version}/sigilum-${version}.tar.gz.sha256.sig"

  log_step "Downloading release checksum signature..."
  printf '  %s%s%s\n' "${CLR_DIM}" "$url" "${CLR_RESET}"

  if command -v curl &>/dev/null; then
    curl --connect-timeout "$CURL_CONNECT_TIMEOUT_SECONDS" --max-time "$CURL_MAX_TIME_SECONDS" -fSL --progress-bar "$url" -o "$dest" >/dev/null 2>&1
    return $?
  fi
  if command -v wget &>/dev/null; then
    wget -q --timeout="$CURL_MAX_TIME_SECONDS" "$url" -O "$dest" >/dev/null 2>&1
    return $?
  fi
  log_error "Neither curl nor wget found."
  exit 1
}

sha256_file() {
  local target_file="$1"
  if command -v sha256sum &>/dev/null; then
    sha256sum "$target_file" | awk '{print tolower($1)}'
    return 0
  fi
  if command -v shasum &>/dev/null; then
    shasum -a 256 "$target_file" | awk '{print tolower($1)}'
    return 0
  fi
  if command -v openssl &>/dev/null; then
    openssl dgst -sha256 "$target_file" | awk '{print tolower($2)}'
    return 0
  fi
  log_error "No SHA-256 tool found. Install sha256sum, shasum, or openssl."
  exit 1
}

extract_checksum_value() {
  local checksum_file="$1"
  local checksum
  checksum="$(awk 'NF > 0 {print tolower($1); exit}' "$checksum_file" | tr -d '[:space:]')"
  if [[ ! "$checksum" =~ ^[0-9a-f]{64}$ ]]; then
    log_error "Invalid checksum format in ${checksum_file}. Expected SHA-256 in first column."
    exit 1
  fi
  printf '%s' "$checksum"
}

verify_tarball_checksum() {
  local tarball="$1"
  local expected_checksum="$2"
  local actual_checksum
  actual_checksum="$(sha256_file "$tarball")"
  if [[ "$actual_checksum" != "$expected_checksum" ]]; then
    log_error "Checksum mismatch for downloaded tarball."
    log_error "Expected: ${expected_checksum}"
    log_error "Actual:   ${actual_checksum}"
    exit 1
  fi
  log_ok "Checksum verified (sha256)."
}

verify_checksum_signature() {
  local checksum_file="$1"
  local signature_file="$2"
  local pubkey_file="$3"
  if ! command -v openssl &>/dev/null; then
    log_error "openssl is required for signature verification."
    exit 1
  fi
  if ! openssl dgst -sha256 -verify "$pubkey_file" -signature "$signature_file" "$checksum_file" >/dev/null 2>&1; then
    log_error "Release checksum signature verification failed."
    exit 1
  fi
  log_ok "Release checksum signature verified."
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
    --checksum)
      CHECKSUM="${2:-}"
      shift 2
      ;;
    --checksum-url)
      CHECKSUM_URL="${2:-}"
      shift 2
      ;;
    --checksum-file)
      CHECKSUM_FILE="${2:-}"
      shift 2
      ;;
    --release-pubkey-file)
      RELEASE_PUBKEY_FILE="${2:-}"
      shift 2
      ;;
    --require-signature)
      REQUIRE_SIGNATURE="true"
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

INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
INSTALL_DIR="${INSTALL_DIR%/}"

if [[ -n "$TARBALL_URL" && -n "$TARBALL_FILE" ]]; then
  log_error "Use only one of --tarball-url or --tarball-file."
  exit 1
fi

if [[ -n "$CHECKSUM" && ( -n "$CHECKSUM_URL" || -n "$CHECKSUM_FILE" ) ]]; then
  log_error "Use only one checksum source: --checksum, --checksum-url, or --checksum-file."
  exit 1
fi
if [[ -n "$CHECKSUM_URL" && -n "$CHECKSUM_FILE" ]]; then
  log_error "Use only one checksum source: --checksum-url or --checksum-file."
  exit 1
fi

if [[ -n "$TARBALL_FILE" ]]; then
  if [[ ! -f "$TARBALL_FILE" ]]; then
    log_error "--tarball-file not found: ${TARBALL_FILE}"
    exit 1
  fi
fi

if [[ -n "$CHECKSUM_FILE" && ! -f "$CHECKSUM_FILE" ]]; then
  log_error "--checksum-file not found: ${CHECKSUM_FILE}"
  exit 1
fi

if [[ -n "$RELEASE_PUBKEY_FILE" && ! -f "$RELEASE_PUBKEY_FILE" ]]; then
  log_error "--release-pubkey-file not found: ${RELEASE_PUBKEY_FILE}"
  exit 1
fi

if [[ "$REQUIRE_SIGNATURE" == "true" && -z "$RELEASE_PUBKEY_FILE" ]]; then
  log_error "--require-signature requires --release-pubkey-file (or SIGILUM_RELEASE_PUBKEY_FILE)."
  exit 1
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
IS_RELEASE_DOWNLOAD="false"
if [[ -n "$TARBALL_URL" ]]; then
  download_explicit_tarball "$TARBALL_URL" "$TARBALL"
elif [[ -n "$TARBALL_FILE" ]]; then
  download_explicit_tarball "$TARBALL_FILE" "$TARBALL"
else
  IS_RELEASE_DOWNLOAD="true"
  download_tarball "$VERSION" "$TARBALL"
fi
printf '\n'

CHECKSUM_PATH="${TMPDIR_DL}/sigilum-${VERSION}.tar.gz.sha256"
CHECKSUM_EXPECTED=""
if [[ -n "$CHECKSUM" ]]; then
  CHECKSUM_EXPECTED="$(printf '%s' "$CHECKSUM" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
elif [[ -n "$CHECKSUM_URL" ]]; then
  log_step "Downloading checksum file..."
  printf '  %s%s%s\n' "${CLR_DIM}" "$CHECKSUM_URL" "${CLR_RESET}"
  download_to_file "$CHECKSUM_URL" "$CHECKSUM_PATH"
  CHECKSUM_EXPECTED="$(extract_checksum_value "$CHECKSUM_PATH")"
elif [[ -n "$CHECKSUM_FILE" ]]; then
  cp "$CHECKSUM_FILE" "$CHECKSUM_PATH"
  CHECKSUM_EXPECTED="$(extract_checksum_value "$CHECKSUM_PATH")"
elif [[ "$IS_RELEASE_DOWNLOAD" == "true" ]]; then
  download_release_checksum "$VERSION" "$CHECKSUM_PATH"
  CHECKSUM_EXPECTED="$(extract_checksum_value "$CHECKSUM_PATH")"
fi

if [[ -n "$CHECKSUM_EXPECTED" ]]; then
  if [[ ! "$CHECKSUM_EXPECTED" =~ ^[0-9a-f]{64}$ ]]; then
    log_error "Invalid --checksum value; expected 64 hex chars."
    exit 1
  fi
  verify_tarball_checksum "$TARBALL" "$CHECKSUM_EXPECTED"
else
  log_warn "No checksum was provided for this install source; skipping checksum verification."
fi

if [[ -n "$RELEASE_PUBKEY_FILE" || "$REQUIRE_SIGNATURE" == "true" ]]; then
  if [[ "$IS_RELEASE_DOWNLOAD" != "true" ]]; then
    log_error "Signature verification is currently supported only for GitHub release downloads."
    exit 1
  fi
  CHECKSUM_SIG_PATH="${CHECKSUM_PATH}.sig"
  if ! download_release_checksum_signature "$VERSION" "$CHECKSUM_SIG_PATH"; then
    log_error "Release checksum signature asset was not found for ${VERSION}."
    exit 1
  fi
  verify_checksum_signature "$CHECKSUM_PATH" "$CHECKSUM_SIG_PATH" "$RELEASE_PUBKEY_FILE"
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
