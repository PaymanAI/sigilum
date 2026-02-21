#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRANGLER_FILE="${ROOT_DIR}/apps/api/wrangler.toml"

usage() {
  cat <<'EOF'
Generate a single-line base64 payload for apps/api/wrangler.toml.

Usage:
  ./scripts/generate-wrangler-toml-b64.sh [--file <path>] [--as-env]

Options:
  --file <path>  Wrangler TOML path (default: apps/api/wrangler.toml)
  --as-env       Print as WRANGLER_TOML_B64=<value>
  -h, --help     Show help
EOF
}

AS_ENV="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --file)
      WRANGLER_FILE="${2:-}"
      shift 2
      ;;
    --as-env)
      AS_ENV="true"
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

if [[ ! -f "$WRANGLER_FILE" ]]; then
  echo "wrangler.toml not found: $WRANGLER_FILE" >&2
  exit 1
fi

ENCODED="$(base64 < "$WRANGLER_FILE" | tr -d '\r\n')"

if [[ -z "$ENCODED" ]]; then
  echo "Failed to encode $WRANGLER_FILE" >&2
  exit 1
fi

if [[ "$AS_ENV" == "true" ]]; then
  printf 'WRANGLER_TOML_B64=%s\n' "$ENCODED"
else
  printf '%s\n' "$ENCODED"
fi
