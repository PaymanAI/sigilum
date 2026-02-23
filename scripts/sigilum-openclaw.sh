#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"

CLR_RESET=""
CLR_BOLD=""
CLR_GREEN=""
CLR_YELLOW=""
CLR_BLUE=""
CLR_CYAN=""

setup_colors() {
  if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-}" != "dumb" ]]; then
    CLR_RESET=$'\033[0m'
    CLR_BOLD=$'\033[1m'
    CLR_GREEN=$'\033[32m'
    CLR_YELLOW=$'\033[33m'
    CLR_BLUE=$'\033[34m'
    CLR_CYAN=$'\033[36m'
  fi
}

log_info() {
  printf '%s[i]%s %s\n' "${CLR_BOLD}${CLR_BLUE}" "${CLR_RESET}" "$1"
}

log_ok() {
  printf '%s[ok]%s %s\n' "${CLR_BOLD}${CLR_GREEN}" "${CLR_RESET}" "$1"
}

log_warn() {
  printf '%s[warn]%s %s\n' "${CLR_BOLD}${CLR_YELLOW}" "${CLR_RESET}" "$1"
}

usage() {
  cat <<'USAGE'
Sigilum OpenClaw helpers

Usage:
  sigilum openclaw <command> [options]

Commands:
  connect [options]             One-command managed onboarding:
                                gateway connect + openclaw install + key bootstrap
                                Use: sigilum openclaw connect --help
  install [options]             Install Sigilum hooks/skills into OpenClaw
                                Use: sigilum openclaw install --help
  uninstall [options]           Remove Sigilum hooks/skills/runtime/keys from OpenClaw
                                Use: sigilum openclaw uninstall --help
  status                        Show current OpenClaw Sigilum install status

Common install options:
  --mode <managed|oss-local>    Sigilum mode (default: managed)
  --source-home <path>          Sigilum source checkout root for oss-local mode
  --namespace <value>           Target namespace
  --gateway-url <url>           Gateway URL
  --api-url <url>               API URL
  --dashboard-url <url>         Dashboard URL
  --interactive                 Force onboarding prompts
  --non-interactive             Disable onboarding prompts
  --auto-start-sigilum <bool>   Auto-start local Sigilum stack when local defaults are down
  --enable-authz-notify <bool>  Enable notification hook
  --owner-token <jwt>           Owner JWT (required if notify enabled)
  --restart                     Restart OpenClaw after install

Common uninstall options:
  --openclaw-home <path>        Target OpenClaw home (default: ~/.openclaw)
  --config <path>               Path to openclaw.json
  --workspace <path>            Override workspace cleanup path
  --key-root <path>             Override key-root cleanup path
  --runtime-root <path>         Override runtime-root cleanup path
  --sigilum-home <path>         Override SIGILUM_HOME cleanup path

Examples:
  sigilum openclaw --help
  sigilum openclaw connect --help
  sigilum openclaw connect --session-id <id> --pair-code <code> --namespace johndee
  sigilum openclaw install --help
  sigilum openclaw install --restart
  sigilum openclaw install --mode oss-local --api-url http://127.0.0.1:8787
  sigilum openclaw uninstall
  sigilum openclaw status
USAGE
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

setup_colors

command="$1"
shift || true

case "$command" in
  connect)
    if [[ "${1:-}" == "help" ]]; then
      shift || true
      exec "${ROOT_DIR}/scripts/sigilum-openclaw-connect.sh" --help "$@"
    fi
    exec "${ROOT_DIR}/scripts/sigilum-openclaw-connect.sh" "$@"
    ;;
  install)
    if [[ "${1:-}" == "help" ]]; then
      shift || true
      exec "${ROOT_DIR}/openclaw/install-openclaw-sigilum.sh" --help "$@"
    fi
    exec "${ROOT_DIR}/openclaw/install-openclaw-sigilum.sh" "$@"
    ;;
  uninstall)
    if [[ "${1:-}" == "help" ]]; then
      shift || true
      exec "${ROOT_DIR}/openclaw/uninstall-openclaw-sigilum.sh" --help "$@"
    fi
    exec "${ROOT_DIR}/openclaw/uninstall-openclaw-sigilum.sh" "$@"
    ;;
  status)
    config_path="${OPENCLAW_HOME}/openclaw.json"
    printf '%sOpenClaw status%s\n' "${CLR_BOLD}${CLR_CYAN}" "${CLR_RESET}"
    printf '  %shome:%s   %s\n' "${CLR_BOLD}" "${CLR_RESET}" "${OPENCLAW_HOME}"
    printf '  %sconfig:%s %s\n' "${CLR_BOLD}" "${CLR_RESET}" "${config_path}"
    for path in \
      "${OPENCLAW_HOME}/hooks/sigilum-plugin" \
      "${OPENCLAW_HOME}/hooks/sigilum-authz-notify" \
      "${OPENCLAW_HOME}/skills/sigilum"; do
      if [[ -d "$path" ]]; then
        log_ok "${path}"
      else
        log_warn "missing ${path}"
      fi
    done
    if [[ -f "$config_path" ]]; then
      log_info "OpenClaw config summary:"
      node - "$config_path" <<'NODE'
const fs = require("fs");
const configPath = process.argv[2];
let cfg = {};
try {
  cfg = JSON.parse(fs.readFileSync(configPath, "utf8"));
} catch {
  // ignore parse issues in status command
}
const plugin = cfg?.hooks?.internal?.entries?.["sigilum-plugin"];
const notify = cfg?.hooks?.internal?.entries?.["sigilum-authz-notify"];
const skill = cfg?.skills?.entries?.sigilum;
const mode = plugin?.env?.SIGILUM_MODE ?? skill?.env?.SIGILUM_MODE ?? "unknown";
const namespace = plugin?.env?.SIGILUM_NAMESPACE ?? skill?.env?.SIGILUM_NAMESPACE ?? "unknown";
const dashboardUrl = plugin?.env?.SIGILUM_DASHBOARD_URL ?? notify?.env?.SIGILUM_DASHBOARD_URL ?? "unset";
const runtimeRoot = skill?.env?.SIGILUM_RUNTIME_ROOT ?? "unset";
const runtimeRootExists = typeof runtimeRoot === "string" && runtimeRoot !== "unset" && fs.existsSync(runtimeRoot);
const dashboardOrigin = (() => {
  if (typeof dashboardUrl !== "string" || !dashboardUrl || dashboardUrl === "unset") return "";
  try {
    const parsed = new URL(dashboardUrl);
    return `${parsed.protocol}//${parsed.host}`.replace(/\/+$/g, "");
  } catch {
    return dashboardUrl.replace(/\/+$/g, "");
  }
})();
console.log("Config summary:");
console.log(`  mode: ${mode}`);
console.log(`  namespace: ${namespace}`);
console.log(`  dashboard: ${dashboardUrl}`);
console.log(`  runtime_root: ${runtimeRoot}`);
console.log(`  runtime_root_exists: ${runtimeRootExists}`);
if (dashboardOrigin && namespace !== "unknown") {
  console.log(`  passkey setup: ${dashboardOrigin}/bootstrap/passkey?namespace=${encodeURIComponent(namespace)}`);
}
console.log(`  hook sigilum-plugin enabled: ${plugin?.enabled === true}`);
console.log(`  hook sigilum-authz-notify enabled: ${notify?.enabled === true}`);
console.log(`  skill sigilum enabled: ${skill?.enabled === true}`);
NODE
    else
      log_warn "Config file not found: ${config_path}"
    fi
    ;;
  -h|--help|help)
    if [[ "${1:-}" == "connect" ]]; then
      shift || true
      exec "${ROOT_DIR}/scripts/sigilum-openclaw-connect.sh" --help "$@"
    fi
    if [[ "${1:-}" == "install" ]]; then
      shift || true
      exec "${ROOT_DIR}/openclaw/install-openclaw-sigilum.sh" --help "$@"
    fi
    if [[ "${1:-}" == "uninstall" ]]; then
      shift || true
      exec "${ROOT_DIR}/openclaw/uninstall-openclaw-sigilum.sh" --help "$@"
    fi
    usage
    ;;
  *)
    echo "Unknown openclaw command: ${command}" >&2
    usage
    exit 1
    ;;
esac
