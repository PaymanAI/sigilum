#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OPENCLAW_HOME_DIR="${OPENCLAW_HOME:-${HOME}/.openclaw}"
WORKSPACE_RUNTIME="${OPENCLAW_HOME_DIR}/workspace/.sigilum/runtime/sigilum"

# Resolution order (highest to lowest priority):
# 1) SIGILUM_RUNTIME_BIN
# 2) SIGILUM_RUNTIME_ROOT/sigilum
# 3) Bundled skill runtime
# 4) OpenClaw workspace runtime
# 5) SIGILUM_CLI_PATH
# 6) SIGILUM_REPO_ROOT/sigilum
# 7) sigilum from PATH
if [[ -n "${SIGILUM_RUNTIME_BIN:-}" ]] && [[ -x "${SIGILUM_RUNTIME_BIN}" ]]; then
  exec "${SIGILUM_RUNTIME_BIN}" "$@"
fi

if [[ -n "${SIGILUM_RUNTIME_ROOT:-}" ]] && [[ -x "${SIGILUM_RUNTIME_ROOT}/sigilum" ]]; then
  exec "${SIGILUM_RUNTIME_ROOT}/sigilum" "$@"
fi

if [[ -x "${SKILL_ROOT}/runtime/sigilum" ]]; then
  exec "${SKILL_ROOT}/runtime/sigilum" "$@"
fi

if [[ -x "${WORKSPACE_RUNTIME}" ]]; then
  exec "${WORKSPACE_RUNTIME}" "$@"
fi

if [[ -n "${SIGILUM_CLI_PATH:-}" ]] && [[ -x "${SIGILUM_CLI_PATH}" ]]; then
  exec "${SIGILUM_CLI_PATH}" "$@"
fi

if [[ -n "${SIGILUM_REPO_ROOT:-}" ]] && [[ -x "${SIGILUM_REPO_ROOT}/sigilum" ]]; then
  exec "${SIGILUM_REPO_ROOT}/sigilum" "$@"
fi

if command -v sigilum >/dev/null 2>&1; then
  exec sigilum "$@"
fi

echo "sigilum CLI not found. Re-run sigilum openclaw install to bundle runtime or set SIGILUM_RUNTIME_ROOT." >&2
exit 127
