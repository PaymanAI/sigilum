#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v git >/dev/null 2>&1; then
  echo "Missing required command: git" >&2
  exit 1
fi

config_files=()
while IFS= read -r file; do
  config_files+=("$file")
done < <(git ls-files "apps/api/.dev.vars*" "apps/api/wrangler*.toml")

if [[ "${#config_files[@]}" -eq 0 ]]; then
  echo "No API config files found to validate."
  exit 0
fi

is_prod_like_file() {
  local file="$1"
  awk '
    {
      line=$0
      sub(/[[:space:]]*#.*/, "", line)
      if (line ~ /^[[:space:]]*$/) next
      norm=tolower(line)
      if (norm ~ /^[[:space:]]*environment[[:space:]]*=[[:space:]]*"?((production)|(staging))"?[[:space:]]*$/) {
        found=1
      }
    }
    END { exit(found ? 0 : 1) }
  ' "$file"
}

has_seed_enabled() {
  local file="$1"
  awk '
    {
      line=$0
      sub(/[[:space:]]*#.*/, "", line)
      if (line ~ /^[[:space:]]*$/) next
      norm=tolower(line)
      if (norm ~ /^[[:space:]]*enable_test_seed_endpoint[[:space:]]*=[[:space:]]*"?(true|1)"?[[:space:]]*$/) {
        found=1
      }
    }
    END { exit(found ? 0 : 1) }
  ' "$file"
}

failures=0
for file in "${config_files[@]}"; do
  if is_prod_like_file "$file" && has_seed_enabled "$file"; then
    echo "Config guard violation in ${file}: prod/staging config must not enable test seeding." >&2
    awk '
      {
        raw=$0
        line=$0
        sub(/[[:space:]]*#.*/, "", line)
        if (line ~ /^[[:space:]]*$/) next
        norm=tolower(line)
        if (norm ~ /^[[:space:]]*environment[[:space:]]*=[[:space:]]*"?((production)|(staging))"?[[:space:]]*$/ ||
            norm ~ /^[[:space:]]*enable_test_seed_endpoint[[:space:]]*=[[:space:]]*"?(true|1)"?[[:space:]]*$/) {
          printf("  %d: %s\n", NR, raw)
        }
      }
    ' "$file" >&2
    failures=$((failures + 1))
  fi
done

if [[ "$failures" -gt 0 ]]; then
  exit 1
fi

echo "Config guard check passed."
