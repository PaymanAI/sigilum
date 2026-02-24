#!/usr/bin/env bash

release_version_pattern='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'

normalize_component_version() {
  local raw_version="$1"
  printf '%s' "${raw_version#v}"
}

normalize_release_tag() {
  local raw_version="$1"
  if [[ "$raw_version" == v* ]]; then
    printf '%s' "$raw_version"
  else
    printf 'v%s' "$raw_version"
  fi
}

validate_release_version() {
  local raw_version="$1"
  local component_version
  component_version="$(normalize_component_version "$raw_version")"
  if [[ "$component_version" =~ $release_version_pattern ]]; then
    return 0
  fi

  cat >&2 <<EOF
Error: invalid release version: ${raw_version}
Expected format: SemVer (MAJOR.MINOR.PATCH with optional pre-release/build metadata)
Examples:
  0.1.0
  0.1.1-beta.1
  v0.1.0
  v0.1.1-rc.1
EOF
  return 1
}
