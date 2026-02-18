#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Sigilum Gateway helper

Usage:
  sigilum gateway pair --session-id <id> --pair-code <code> --namespace <namespace> [options]

Options:
  --api-url <url>            Sigilum API base URL
  --gateway-admin-url <url>  Local gateway admin URL (default: http://127.0.0.1:38100)
  --reconnect-ms <ms>        WebSocket reconnect delay (default: 2000)
  -h, --help
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

subcommand="$1"
shift || true

case "$subcommand" in
  pair)
    exec node "$ROOT_DIR/scripts/gateway-pair-bridge.mjs" "$@"
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "Unknown gateway command: $subcommand" >&2
    usage
    exit 1
    ;;
esac
