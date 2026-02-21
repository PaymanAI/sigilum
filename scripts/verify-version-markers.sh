#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/release-version.sh
source "${SCRIPT_DIR}/release-version.sh"

usage() {
  cat <<'EOF'
Verify tracked .version and *.version marker files across the repo.

Usage:
  ./scripts/verify-version-markers.sh <version>

Arguments:
  version     Release version (YYYY-MM-DD with optional suffix, e.g. v2026-02-20-beta.1)
EOF
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

RAW_VERSION="$1"
validate_release_version "$RAW_VERSION"
EXPECTED_VERSION="$(normalize_component_version "$RAW_VERSION")"

if [[ -z "$EXPECTED_VERSION" ]]; then
  echo "Error: derived expected version is empty from input: ${RAW_VERSION}" >&2
  exit 1
fi

cd "$ROOT_DIR"

VERSION_FILES=()
while IFS= read -r file; do
  VERSION_FILES+=("$file")
done < <(git ls-files ':(glob)**/.version' ':(glob)**/*.version')

if [[ ${#VERSION_FILES[@]} -eq 0 ]]; then
  echo "No tracked version marker files found." >&2
  exit 1
fi

MISMATCHES=0
for file in "${VERSION_FILES[@]}"; do
  current_value="$(tr -d '\r\n' < "$file")"
  if [[ "$current_value" != "$EXPECTED_VERSION" ]]; then
    echo "Version mismatch: ${file} (expected ${EXPECTED_VERSION}, got ${current_value:-<empty>})" >&2
    MISMATCHES=$((MISMATCHES + 1))
  fi
done

if [[ "$MISMATCHES" -ne 0 ]]; then
  echo "Found ${MISMATCHES} version marker mismatches." >&2
  exit 1
fi

echo "Verified ${#VERSION_FILES[@]} version marker files at ${EXPECTED_VERSION}"
