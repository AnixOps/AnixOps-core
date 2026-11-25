#!/usr/bin/env bash
# Builds the static anixops-mesh program for one musl target and writes
#   <out-dir>/anixops-mesh-<version>-<target>
#   <out-dir>/anixops-mesh-<version>-<target>.sha256
# CI runs it on every Rust change, the release workflow on every tag, so the
# release path is exercised before a tag exists. See docs/deploy/mesh-node.md.
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

case "${target}" in
  x86_64-unknown-linux-musl) ;;
  # No aarch64 musl C toolchain on the runner: the program is pure Rust and
  # musl targets ship their own C runtime objects, so the bundled lld links it.
  aarch64-unknown-linux-musl) export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld ;;
  *)
    echo "::error::unsupported mesh node target ${target}"
    exit 1
    ;;
esac
case "${version}" in
  "" | */* | *" "*)
    echo "::error::invalid version '${version}'"
    exit 1
    ;;
esac

rustup target add "${target}"
cargo build --locked --release --package mesh-node --bin anixops-mesh --target "${target}"

binary="target/${target}/release/anixops-mesh"
test -f "${binary}"
if [ -L "${binary}" ]; then
  echo "::error::release binary must not be a symlink"
  exit 1
fi
# A static program has no program interpreter (dynamic loader) segment.
if readelf --program-headers "${binary}" | grep -q INTERP; then
  echo "::error::anixops-mesh for ${target} is dynamically linked"
  exit 1
fi

name="anixops-mesh-${version}-${target}"
mkdir -p "${out_dir}"
install -m 0755 "${binary}" "${out_dir}/${name}"
(
  cd "${out_dir}"
  sha256sum "${name}" > "${name}.sha256"
  sha256sum -c "${name}.sha256"
)

# The x86_64 build runs on the runner itself: it must start and list its
# subcommands, which the installer reads before anything else.
if [ "${target}" = x86_64-unknown-linux-musl ]; then
  "${out_dir}/${name}" capabilities | grep -q '"commands"'
fi
echo "built ${out_dir}/${name}"
