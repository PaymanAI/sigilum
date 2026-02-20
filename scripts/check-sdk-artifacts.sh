#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

pattern='(^|/)(node_modules|dist|build|coverage|\.pytest_cache|__pycache__|target)(/|$)|(\.pyc|\.pyo|\.class|\.tsbuildinfo|\.DS_Store)$'

offending_files=()
while IFS= read -r file; do
  if [[ -n "$file" ]]; then
    offending_files+=("$file")
  fi
done < <(git ls-files sdks | grep -E "$pattern" || true)

if [[ ${#offending_files[@]} -gt 0 ]]; then
  echo "Tracked SDK artifacts/caches detected:" >&2
  for file in "${offending_files[@]}"; do
    echo "  - ${file}" >&2
  done
  echo >&2
  echo "Remove generated artifacts from git and keep source/test vectors only under sdks/." >&2
  exit 1
fi

echo "SDK artifact guard passed: no generated artifacts are tracked under sdks/."
