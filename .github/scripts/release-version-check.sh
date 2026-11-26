#!/usr/bin/env bash
# Release version preconditions (docs/release-strategy.md「版本节奏与候选版」).
#
#   release-version-check.sh <vVERSION> [repo-root]   check one release version
#   release-version-check.sh --self-test              run the fixture tests
#
# A release version vX.Y.Z[-rc.N] is published only when
#   1. [workspace.package] version in Cargo.toml is X.Y.Z[-rc.N], so every binary in
#      the release prints the version it is published under, and
#   2. CHANGELOG.md has a "## vX.Y.Z[-rc.N] - YYYY-MM-DD" section, so the release has
#      notes a user can decide an upgrade from.

set -euo pipefail

check_version() {
  local version="$1"
  local root="${2:-.}"
  local cargo="${root}/Cargo.toml"
  local changelog="${root}/CHANGELOG.md"

  if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[1-9][0-9]*)?$ ]]; then
    echo "::error::release version ${version} is not vMAJOR.MINOR.PATCH[-(alpha|beta|rc).N]." >&2
    return 1
  fi
  [[ -f "${cargo}" ]] || { echo "::error::missing ${cargo}." >&2; return 1; }
  [[ -f "${changelog}" ]] || { echo "::error::missing ${changelog}." >&2; return 1; }

  # The version line of the [workspace.package] table, and only that table.
  local workspace_version
  workspace_version="$(awk '
    /^\[/ { in_table = ($0 == "[workspace.package]"); next }
    in_table && /^version[[:space:]]*=/ {
      line = $0
      sub(/^version[[:space:]]*=[[:space:]]*"/, "", line)
      sub(/".*$/, "", line)
      print line
      exit
    }
  ' "${cargo}")"
  if [[ -z "${workspace_version}" ]]; then
    echo "::error::Cargo.toml has no [workspace.package] version." >&2
    return 1
  fi
  if [[ "v${workspace_version}" != "${version}" ]]; then
    echo "::error::Cargo.toml [workspace.package] version is ${workspace_version}; release ${version} needs ${version#v}. Bump the version in a pull request before tagging." >&2
    return 1
  fi

  local heading_pattern="^## ${version//./\\.} - [0-9]{4}-[0-9]{2}-[0-9]{2}\$"
  if ! grep -Eq "${heading_pattern}" "${changelog}"; then
    echo "::error::CHANGELOG.md has no \"## ${version} - YYYY-MM-DD\" section. Move the release's entries out of Unreleased before tagging." >&2
    return 1
  fi
  echo "release version ${version}: Cargo.toml and CHANGELOG.md agree."
}

self_test() {
  local dir
  dir="$(mktemp -d)"

  write_fixture() {
    local cargo_version="$1"
    local heading="$2"
    cat > "${dir}/Cargo.toml" <<EOF
[workspace]
members = ["a"]

[workspace.package]
version = "${cargo_version}"
edition = "2021"

[package]
version = "9.9.9"
EOF
    printf '# Changelog\n\n## Unreleased\n\n%s\n\n- entry\n' "${heading}" > "${dir}/CHANGELOG.md"
  }

  local failures=0
  expect() {
    local want="$1" version="$2" label="$3"
    if check_version "${version}" "${dir}" >/dev/null 2>&1; then got=pass; else got=fail; fi
    if [[ "${got}" != "${want}" ]]; then
      echo "self-test: ${label}: expected ${want}, got ${got}" >&2
      failures=$((failures + 1))
    fi
  }

  write_fixture "0.3.0-rc.1" "## v0.3.0-rc.1 - 2026-11-26"
  expect pass v0.3.0-rc.1 "rc matches"
  expect fail v0.3.0 "stable tag on rc version"
  expect fail v0.3.0-rc.2 "next rc before bump"
  expect fail 0.3.0-rc.1 "missing v prefix"
  expect fail v0.3.0-rc.01 "leading zero"

  write_fixture "0.3.0" "## v0.3.0-rc.1 - 2026-11-26"
  expect fail v0.3.0 "changelog section missing"

  write_fixture "0.3.1" "## v0.3.1 - 2026-12-01"
  expect pass v0.3.1 "patch matches"
  expect fail v0.3.10 "prefix is not a match"

  write_fixture "0.3.1" "## v0.3.1"
  expect fail v0.3.1 "heading without date"

  write_fixture "0.3.1" "## v0.3.1 - 2026-12-01 extra"
  expect fail v0.3.1 "heading with trailing text"

  # Only [workspace.package] counts, not a later [package] table.
  write_fixture "0.3.0" "## v9.9.9 - 2026-12-01"
  expect fail v9.9.9 "package table is not the workspace version"

  rm -rf "${dir}"
  if (( failures > 0 )); then
    echo "::error::release-version-check self-test: ${failures} case(s) failed." >&2
    return 1
  fi
  echo "release-version-check self-test: all cases passed."
}

case "${1:-}" in
  --self-test) self_test ;;
  "" | -h | --help) echo "usage: $0 <vVERSION> [repo-root] | --self-test" >&2; exit 2 ;;
  *) check_version "$1" "${2:-.}" ;;
esac
