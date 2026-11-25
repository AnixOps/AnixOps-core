#!/usr/bin/env bash
# Builds anixops-mesh for one target and writes
#   <out-dir>/anixops-mesh-<version>-<target>[.exe]
#   <out-dir>/anixops-mesh-<version>-<target>[.exe].sha256
#   <out-dir>/anixops-mesh-<version>-<target>.buildinfo.json
# Linux targets are static musl programs, built on a Linux runner; macOS
# targets are built on a macOS runner and link only the system's own
# libraries; Windows targets are built on a Windows runner with the C
# runtime linked in, so no redistributable is needed. CI runs it on every
# Rust change, the release workflow on every tag, so the release path is
# exercised before a tag exists. See docs/deploy/mesh-node.md.
#
#   build-mesh-node.sh TARGET VERSION OUT_DIR

set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 TARGET VERSION OUT_DIR" >&2
  exit 2
fi
target="$1"
version="$2"
out_dir="$3"

case "${version}" in
  "" | */* | *" "*)
    echo "::error::invalid version '${version}'"
    exit 1
    ;;
esac

# sha256sum where there is one (Linux, Git Bash), shasum on macOS; both
# print and check the same format.
sha256() {
  if command -v sha256sum > /dev/null; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

suffix=""
case "${target}" in
  x86_64-unknown-linux-musl | aarch64-unknown-linux-musl) kind=linux ;;
  x86_64-apple-darwin | aarch64-apple-darwin) kind=macos ;;
  x86_64-pc-windows-msvc | aarch64-pc-windows-msvc)
    kind=windows
    suffix=".exe"
    # The C runtime linked in: no Visual C++ redistributable on the target.
    export RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static"
    ;;
  *)
    echo "::error::unsupported mesh node target ${target}"
    exit 1
    ;;
esac

if [ "${kind}" = linux ]; then
  # No aarch64 musl C toolchain on the runner: musl targets ship their own C
  # runtime objects, so the bundled lld links it.
  if [ "${target}" = aarch64-unknown-linux-musl ]; then
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
  fi
  # The one C dependency is the crypto library's own code, which needs no C
  # library headers: clang compiles it for any target as freestanding code,
  # so neither target needs a musl C toolchain. llvm-ar writes the symbol
  # index lld needs for objects of another architecture.
  command -v clang > /dev/null || {
    echo "::error::clang is required to build ${target}"
    exit 1
  }
  llvm_ar="$(command -v llvm-ar || true)"
  if [ -z "${llvm_ar}" ]; then
    llvm_ar="$(compgen -c llvm-ar- | sort -t- -k3 -n | tail -n 1)"
  fi
  if [ -z "${llvm_ar}" ]; then
    echo "::error::llvm-ar is required to build ${target}"
    exit 1
  fi
  target_env="${target//-/_}"
  export "CC_${target_env}=clang"
  export "AR_${target_env}=${llvm_ar}"
  export "CFLAGS_${target_env}=-ffreestanding"
fi

rustup target add "${target}"
cargo build --locked --release --package mesh-node --bin anixops-mesh --target "${target}"

binary="target/${target}/release/anixops-mesh${suffix}"
test -f "${binary}"
if [ -L "${binary}" ]; then
  echo "::error::release binary must not be a symlink"
  exit 1
fi
case "${kind}" in
  linux)
    # A static program has no program interpreter (dynamic loader) segment.
    if readelf --program-headers "${binary}" | grep -q INTERP; then
      echo "::error::anixops-mesh for ${target} is dynamically linked"
      exit 1
    fi
    ;;
  macos)
    # Only the system's own libraries, which every Mac has.
    if otool -L "${binary}" | tail -n +2 | awk '{print $1}' | grep -v -E '^(/usr/lib/|/System/Library/)'; then
      echo "::error::anixops-mesh for ${target} links a library outside the system"
      exit 1
    fi
    ;;
  windows)
    # No C runtime DLLs: only libraries every Windows has.
    rustup component add llvm-tools > /dev/null
    sysroot="$(rustc --print sysroot)"
    # Git Bash runs programs by Unix-style paths.
    if command -v cygpath > /dev/null; then
      sysroot="$(cygpath -u "${sysroot}")"
    fi
    readobj="${sysroot}/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-readobj"
    imports="$("${readobj}" --coff-imports "${binary}" | sed -n 's/^ *Name: //p' | tr '[:upper:]' '[:lower:]')"
    echo "imports: ${imports//$'\n'/ }"
    if grep -E '^(vcruntime|msvcp|ucrtbase|api-ms-win-crt-)' <<< "${imports}"; then
      echo "::error::anixops-mesh for ${target} needs the C runtime DLLs"
      exit 1
    fi
    ;;
esac

name="anixops-mesh-${version}-${target}"
file="${name}${suffix}"
mkdir -p "${out_dir}"
install -m 0755 "${binary}" "${out_dir}/${file}"
(
  cd "${out_dir}" || exit 1
  sha256 "${file}" > "${file}.sha256"
  sha256 -c "${file}.sha256"
)
# The exact toolchain, not the channel name: a rebuild needs the same one.
rustc_version="$(rustc -V)"
cargo_version="$(cargo -V)"
echo "rustc: ${rustc_version}; cargo: ${cargo_version}"
jq -n \
  --arg file "${file}" \
  --arg target "${target}" \
  --arg version "${version}" \
  --arg commit "$(git rev-parse HEAD)" \
  --arg rustc "${rustc_version}" \
  --arg rustc_verbose "$(rustc -Vv)" \
  --arg cargo "${cargo_version}" \
  '{schema_version: 1, file: $file, target: $target, version: $version, commit_sha: $commit, rustc: $rustc, rustc_verbose: $rustc_verbose, cargo: $cargo}' \
  > "${out_dir}/${name}.buildinfo.json"

# A build for the runner's own architecture must start and list its
# subcommands, which the installers read before anything else.
host="$(rustc -vV | sed -n 's/^host: //p')"
case "${target}" in
  x86_64-unknown-linux-musl | "${host}")
    "${out_dir}/${file}" capabilities | grep -q '"commands"'
    ;;
esac
echo "built ${out_dir}/${file}"
