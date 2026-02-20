#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Build a Sigilum release tarball for distribution.

Usage:
  ./scripts/build-release.sh <version>

Arguments:
  version     Release version tag (e.g. v0.1.0)

Options:
  --out-dir <path>    Output directory (default: ./releases)
  -h, --help          Show help

Examples:
  ./scripts/build-release.sh v0.1.0
  ./scripts/build-release.sh v0.2.0 --out-dir /tmp/builds
EOF
}

OUT_DIR="${ROOT_DIR}/releases"
VERSION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      OUT_DIR="${2:-}"
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

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

ARCHIVE_ROOT="${STAGE_DIR}/sigilum"
mkdir -p "$ARCHIVE_ROOT"

cp "$ROOT_DIR/sigilum" "$ARCHIVE_ROOT/sigilum"
chmod +x "$ARCHIVE_ROOT/sigilum"

cp -R "$ROOT_DIR/scripts" "$ARCHIVE_ROOT/scripts"

cp -R "$ROOT_DIR/openclaw" "$ARCHIVE_ROOT/openclaw"

printf '%s\n' "$VERSION" > "$ARCHIVE_ROOT/VERSION"

mkdir -p "$OUT_DIR"

TARBALL_NAME="sigilum-${VERSION}.tar.gz"
TARBALL_PATH="${OUT_DIR}/${TARBALL_NAME}"

tar czf "$TARBALL_PATH" -C "$STAGE_DIR" sigilum

TARBALL_SIZE="$(du -h "$TARBALL_PATH" | cut -f1 | tr -d '[:space:]')"

echo "Release tarball built:"
echo "  version:  ${VERSION}"
echo "  output:   ${TARBALL_PATH}"
echo "  size:     ${TARBALL_SIZE}"
echo ""
echo "Upload to GitHub Releases:"
echo "  gh release create ${VERSION} ${TARBALL_PATH} --title \"Sigilum ${VERSION}\""
