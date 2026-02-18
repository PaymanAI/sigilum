#!/usr/bin/env bash
set -euo pipefail

if command -v sigilum >/dev/null 2>&1; then
  exec sigilum "$@"
fi

if [[ -n "${SIGILUM_CLI_PATH:-}" ]] && [[ -x "${SIGILUM_CLI_PATH}" ]]; then
  exec "${SIGILUM_CLI_PATH}" "$@"
fi

if [[ -n "${SIGILUM_REPO_ROOT:-}" ]] && [[ -x "${SIGILUM_REPO_ROOT}/sigilum" ]]; then
  exec "${SIGILUM_REPO_ROOT}/sigilum" "$@"
fi

echo "sigilum CLI not found. Install it or set SIGILUM_CLI_PATH/SIGILUM_REPO_ROOT." >&2
exit 127
