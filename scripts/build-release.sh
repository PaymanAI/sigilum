#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/release-version.sh
source "${SCRIPT_DIR}/release-version.sh"

usage() {
  cat <<'EOF'
Build a Sigilum release tarball for distribution.

Usage:
  ./scripts/build-release.sh <version>

Arguments:
  version     Release version tag (YYYY-MM-DD with optional suffix, e.g. v2026-02-20-beta.1)

Options:
  --out-dir <path>             Output directory (default: ./releases)
  --platform <id>              Optional platform suffix for tarball name (e.g. macos-apple-silicon)
  --gateway-bin-dir <path>     Optional dir containing sigilum-gateway and sigilum-gateway-cli
  --signing-key-file <path>    Optional PEM private key for checksum signature
  -h, --help                   Show help

Examples:
  ./scripts/build-release.sh v2026-02-20
  ./scripts/build-release.sh v2026-02-20 --platform macos-apple-silicon --gateway-bin-dir ./.release-bin
  ./scripts/build-release.sh v2026-02-20-beta.1 --out-dir /tmp/builds
  ./scripts/build-release.sh v2026-02-20-beta.1 --signing-key-file ./release-private.pem
EOF
}

OUT_DIR="${ROOT_DIR}/releases"
VERSION=""
PLATFORM=""
GATEWAY_BIN_DIR=""
SIGNING_KEY_FILE="${SIGILUM_RELEASE_SIGNING_KEY_FILE:-}"
COMPONENT_VERSION=""

sha256_file() {
  local target_file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$target_file" | awk '{print tolower($1)}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$target_file" | awk '{print tolower($1)}'
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$target_file" | awk '{print tolower($2)}'
    return 0
  fi
  echo "Error: no SHA-256 tool found (sha256sum/shasum/openssl)." >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --platform)
      PLATFORM="${2:-}"
      shift 2
      ;;
    --gateway-bin-dir)
      GATEWAY_BIN_DIR="${2:-}"
      shift 2
      ;;
    --signing-key-file)
      SIGNING_KEY_FILE="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
    *)
      if [[ -z "$VERSION" ]]; then
        VERSION="$1"
        shift
      else
        echo "Unexpected argument: $1" >&2
        usage
        exit 1
      fi
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  echo "Error: version argument is required" >&2
  usage
  exit 1
fi

validate_release_version "$VERSION"
COMPONENT_VERSION="$(normalize_component_version "$VERSION")"
if [[ -z "$COMPONENT_VERSION" ]]; then
  echo "Error: derived component version is empty from input: ${VERSION}" >&2
  exit 1
fi

if [[ -n "$SIGNING_KEY_FILE" && ! -f "$SIGNING_KEY_FILE" ]]; then
  echo "Error: signing key file not found: ${SIGNING_KEY_FILE}" >&2
  exit 1
fi

if [[ -n "$PLATFORM" && ! "$PLATFORM" =~ ^[a-z0-9._-]+$ ]]; then
  echo "Error: invalid --platform value: ${PLATFORM}" >&2
  exit 1
fi

if [[ -n "$GATEWAY_BIN_DIR" ]]; then
  if [[ ! -d "$GATEWAY_BIN_DIR" ]]; then
    echo "Error: gateway bin dir not found: ${GATEWAY_BIN_DIR}" >&2
    exit 1
  fi
  for required in sigilum-gateway sigilum-gateway-cli; do
    if [[ ! -f "${GATEWAY_BIN_DIR}/${required}" ]]; then
      echo "Error: missing ${required} in ${GATEWAY_BIN_DIR}" >&2
      exit 1
    fi
  done
fi

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

ARCHIVE_ROOT="${STAGE_DIR}/sigilum"
mkdir -p "$ARCHIVE_ROOT"

cp "$ROOT_DIR/sigilum" "$ARCHIVE_ROOT/sigilum"
chmod +x "$ARCHIVE_ROOT/sigilum"

cp -R "$ROOT_DIR/scripts" "$ARCHIVE_ROOT/scripts"

cp -R "$ROOT_DIR/openclaw" "$ARCHIVE_ROOT/openclaw"

if [[ -n "$GATEWAY_BIN_DIR" ]]; then
  mkdir -p "$ARCHIVE_ROOT/bin"
  cp "${GATEWAY_BIN_DIR}/sigilum-gateway" "$ARCHIVE_ROOT/bin/sigilum-gateway"
  cp "${GATEWAY_BIN_DIR}/sigilum-gateway-cli" "$ARCHIVE_ROOT/bin/sigilum-gateway-cli"
  chmod +x "$ARCHIVE_ROOT/bin/sigilum-gateway" "$ARCHIVE_ROOT/bin/sigilum-gateway-cli"
  printf '%s\n' "$COMPONENT_VERSION" > "$ARCHIVE_ROOT/bin/.version"
fi

printf '%s\n' "$VERSION" > "$ARCHIVE_ROOT/VERSION"
printf '%s\n' "$COMPONENT_VERSION" > "$ARCHIVE_ROOT/.version"

while IFS= read -r -d '' version_file; do
  printf '%s\n' "$COMPONENT_VERSION" > "$version_file"
done < <(find "$ARCHIVE_ROOT" -type f \( -name ".version" -o -name "*.version" \) -print0)

mkdir -p "$OUT_DIR"

TARBALL_NAME="sigilum-${VERSION}.tar.gz"
if [[ -n "$PLATFORM" ]]; then
  TARBALL_NAME="sigilum-${VERSION}-${PLATFORM}.tar.gz"
fi
TARBALL_PATH="${OUT_DIR}/${TARBALL_NAME}"

tar czf "$TARBALL_PATH" -C "$STAGE_DIR" sigilum

CHECKSUM_PATH="${TARBALL_PATH}.sha256"
CHECKSUM_VALUE="$(sha256_file "$TARBALL_PATH")"
printf '%s  %s\n' "$CHECKSUM_VALUE" "$TARBALL_NAME" >"$CHECKSUM_PATH"

CHECKSUM_SIG_PATH=""
if [[ -n "$SIGNING_KEY_FILE" ]]; then
  if ! command -v openssl >/dev/null 2>&1; then
    echo "Error: openssl is required to sign release checksum." >&2
    exit 1
  fi
  CHECKSUM_SIG_PATH="${CHECKSUM_PATH}.sig"
  openssl dgst -sha256 -sign "$SIGNING_KEY_FILE" -out "$CHECKSUM_SIG_PATH" "$CHECKSUM_PATH"
fi

TARBALL_SIZE="$(du -h "$TARBALL_PATH" | cut -f1 | tr -d '[:space:]')"

echo "Release tarball built:"
echo "  version:  ${VERSION}"
if [[ -n "$PLATFORM" ]]; then
  echo "  platform: ${PLATFORM}"
fi
if [[ -n "$GATEWAY_BIN_DIR" ]]; then
  echo "  gateway:  ${GATEWAY_BIN_DIR} (sigilum-gateway, sigilum-gateway-cli)"
fi
echo "  output:   ${TARBALL_PATH}"
echo "  checksum: ${CHECKSUM_PATH}"
if [[ -n "$CHECKSUM_SIG_PATH" ]]; then
  echo "  signature:${CHECKSUM_SIG_PATH}"
fi
echo "  size:     ${TARBALL_SIZE}"
echo ""
echo "Upload to GitHub Releases:"
if [[ -n "$CHECKSUM_SIG_PATH" ]]; then
  echo "  gh release create ${VERSION} ${TARBALL_PATH} ${CHECKSUM_PATH} ${CHECKSUM_SIG_PATH} --title \"Sigilum ${VERSION}\""
else
  echo "  gh release create ${VERSION} ${TARBALL_PATH} ${CHECKSUM_PATH} --title \"Sigilum ${VERSION}\""
fi
