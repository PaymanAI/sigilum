#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/sigilum-service-common.sh"

main() {
  local command="${1:-help}"
  if [[ $# -gt 0 ]]; then
    shift
  fi

  case "$command" in
    add)
      exec "${SCRIPT_DIR}/sigilum-service-add.sh" "$@"
      ;;
    list)
      exec "${SCRIPT_DIR}/sigilum-service-list.sh" "$@"
      ;;
    secret)
      exec "${SCRIPT_DIR}/sigilum-service-secret.sh" "$@"
      ;;
    help|-h|--help)
      usage
      ;;
    *)
      echo "Unknown command: ${command}" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
