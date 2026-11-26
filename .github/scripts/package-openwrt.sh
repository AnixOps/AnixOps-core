#!/usr/bin/env bash
# Builds the OpenWrt packages of the mesh device (docs/deploy/openwrt.md):
#
#   anixops-mesh_<version>_<arch>.ipk / .apk   the static program, procd
#                                              service and UCI defaults, one
#                                              per line of arches.txt whose
#                                              build is in BIN_DIR
#   luci-app-anixops-mesh_<version>_all.ipk / .apk   the web plugin
#   SHA256SUMS
#
# ipk (opkg, OpenWrt 24.10 and older) is written here; apk (OpenWrt 25.12
# and newer) is written by `apk mkpkg` of apk-tools 3 inside the image given
# with APK_IMAGE (a digest-pinned Alpine image: OpenWrt's own apk on the
# device is built without mkpkg, and its build system uses the same
# apk-tools 3 on the host). The workflow installs the result with the
# device's apk on every OpenWrt release it tests. Without APK_IMAGE only ipk
# is written.
#
#   package-openwrt.sh VERSION BIN_DIR OUT_DIR
#
# VERSION is the program version (x.y.z, optionally v-prefixed, optionally
# -alpha.N, -beta.N or -rc.N); the packages are release 1 of it. BIN_DIR
# holds anixops-mesh-<version>-<rust target> from build-mesh-node.sh, with
# or without its .sha256 and .buildinfo.json files.

set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 VERSION BIN_DIR OUT_DIR" >&2
  exit 2
fi
version="$1"
bin_dir="$2"
out_dir="$3"

# The release tag form (v0.5.0, v0.5.0-rc.1) or the bare version. A
# pre-release must sort before its release in both package managers: opkg
# sorts "~" first (0.5.0~rc.1), apk has its own suffixes (0.5.0_rc1).
version="${version#v}"
if [[ "${version}" =~ ^([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  ipk_version="${version}-r1"
  apk_version="${version}-r1"
elif [[ "${version}" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-(alpha|beta|rc)\.([0-9]+)$ ]]; then
  ipk_version="${BASH_REMATCH[1]}~${BASH_REMATCH[2]}.${BASH_REMATCH[3]}-r1"
  apk_version="${BASH_REMATCH[1]}_${BASH_REMATCH[2]}${BASH_REMATCH[3]}-r1"
else
  echo "::error::package version must be x.y.z or x.y.z-(alpha|beta|rc).N, got '${version}'"
  exit 1
fi
# File names carry the release version as tagged: "~" does not survive as a
# release asset name, and the package managers read the version inside.
file_version="${version}-r1"

repo="$(git rev-parse --show-toplevel)"
src="${repo}/apps/mesh-node/openwrt"
# Reproducible archives: fixed time, owner and order.
epoch="${SOURCE_DATE_EPOCH:-$(git -C "${repo}" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH="${epoch}"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
mkdir -p "${out_dir}"
out_dir="$(cd "${out_dir}" && pwd)"

url="https://github.com/AnixOps/networkcore_anixops"
license="Apache-2.0"
maintainer="AnixOps"

# Package scripts. The same templates OpenWrt's own build writes
# (include/package-pack.mk), so groups, init scripts and uci-defaults are
# handled by the device's /lib/functions.sh exactly as for any package.
ipk_postinst() {
  cat <<'EOF'
#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
default_postinst $0 $@
EOF
}
ipk_prerm() { # REMOVAL
  cat <<'EOF'
#!/bin/sh
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
default_prerm $0 $@
EOF
  if [ "$1" = 1 ]; then
    echo 'ret=$?'
    removal_cleanup
    cat <<'EOF'
exit ${ret}
EOF
  fi
}
apk_postinst() { # NAME UPGRADE
  cat <<EOF
#!/bin/sh
[ "\${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s \${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. \${IPKG_INSTROOT}/lib/functions.sh
export root="\${IPKG_INSTROOT}"
export pkgname="$1"
EOF
  if [ "$2" = 1 ]; then
    echo 'export PKG_UPGRADE=1'
  fi
  cat <<'EOF'
add_group_and_user
default_postinst
EOF
}
apk_prerm() { # NAME REMOVAL
  cat <<EOF
#!/bin/sh
[ -s \${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. \${IPKG_INSTROOT}/lib/functions.sh
export root="\${IPKG_INSTROOT}"
export pkgname="$1"
default_prerm
EOF
  if [ "$2" = 1 ]; then
    echo 'ret=$?'
    removal_cleanup
    cat <<'EOF'
exit ${ret}
EOF
  fi
}
# Removal of the mesh device package (opkg runs prerm only on removal,
# including a forced reinstall; apk runs pre-deinstall only on removal).
# The service is already stopped. Its firewall rules and zone go, and so
# does the device state: the device token, device key and network keys must
# not stay on the flash of a router that may change hands. The panel still
# lists the device until an administrator revokes it there.
removal_cleanup() {
  cat <<'EOF'
if [ -z "${IPKG_INSTROOT}" ]; then
	/usr/libexec/anixops-mesh/firewall remove || true
	rm -rf /etc/anixops-mesh
	logger -t anixops-mesh -p daemon.notice "removed with its device identity; revoke the device in the panel" 2>/dev/null || true
fi
EOF
}
# The web plugin also drops the interface caches and reloads rpcd so that
# the new menu, permissions and backend apply without a reboot (as LuCI's
# own luci.mk does).
luci_refresh() {
  cat <<'EOF'
[ -n "${IPKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	killall -HUP rpcd 2>/dev/null || true
}
EOF
}

tar_gz() { # DIR OUT [ENTRIES...]: deterministic gzip'd tar of DIR
  local dir="$1" out="$2"
  shift 2
  tar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@${epoch}" --format=gnu -C "${dir}" -cf - "$@" | gzip -9n > "${out}"
}

# NAME ARCH DATA_DIR DEPENDS DESCRIPTION RUSERS LUCI REMOVAL
build_ipk() {
  local name="$1" arch="$2" data="$3" depends="$4" description="$5" rusers="$6" luci="$7" removal="$8"
  local stage="${work}/ipk-${name}-${arch}"
  mkdir -p "${stage}/control"
  local size
  size="$(du -sb --apparent-size "${data}" | cut -f1)"
  {
    echo "Package: ${name}"
    echo "Version: ${ipk_version}"
    if [ -n "${depends}" ]; then
      echo "Depends: ${depends//\ /, }"
    fi
    echo "Source: apps/mesh-node/openwrt"
    echo "SourceName: ${name}"
    echo "License: ${license}"
    echo "Section: net"
    echo "URL: ${url}"
    echo "Maintainer: ${maintainer}"
    echo "Architecture: ${arch}"
    echo "Installed-Size: ${size}"
    if [ -n "${rusers}" ]; then
      echo "Require-User: ${rusers}"
    fi
    echo "Description:  ${description}"
  } > "${stage}/control/control"
  ipk_postinst > "${stage}/control/postinst"
  ipk_prerm "${removal}" > "${stage}/control/prerm"
  if [ "${luci}" = 1 ]; then
    # postinst-pkg runs inside default_postinst, whose result is its
    # result: it must not exit and must succeed when rpcd is not running.
    luci_refresh > "${stage}/control/postinst-pkg"
    chmod 0755 "${stage}/control/postinst-pkg"
  fi
  chmod 0755 "${stage}/control/postinst" "${stage}/control/prerm"
  echo "2.0" > "${stage}/debian-binary"
  tar_gz "${data}" "${stage}/data.tar.gz" .
  tar_gz "${stage}/control" "${stage}/control.tar.gz" .
  tar_gz "${stage}" "${out_dir}/${name}_${file_version}_${arch}.ipk" ./debian-binary ./data.tar.gz ./control.tar.gz
  echo "wrote ${name}_${file_version}_${arch}.ipk"
}

# NAME ARCH DATA_DIR DEPENDS DESCRIPTION RUSERS LUCI REMOVAL
build_apk() {
  local name="$1" arch="$2" data="$3" depends="$4" description="$5" rusers="$6" luci="$7" removal="$8"
  local stage="${work}/apk-${name}-${arch}"
  mkdir -p "${stage}/scripts"
  cp -a "${data}" "${stage}/data"
  # apk records file times: fix them like the ipk archives do.
  find "${stage}/data" -exec touch -h -d "@${epoch}" {} +
  # OpenWrt's apk packages carry their file list (read by default_postinst
  # and sysupgrade) and required users in /lib/apk/packages.
  mkdir -p "${stage}/data/lib/apk/packages"
  (cd "${stage}/data" && find . -mindepth 1 \( -type f -o -type l \) -printf '/%P\n' | LC_ALL=C sort) \
    > "${stage}/list"
  echo "/lib/apk/packages/${name}.list" >> "${stage}/list"
  if [ -n "${rusers}" ]; then
    echo "${rusers}" > "${stage}/data/lib/apk/packages/${name}.rusers"
    echo "/lib/apk/packages/${name}.rusers" >> "${stage}/list"
  fi
  LC_ALL=C sort -o "${stage}/data/lib/apk/packages/${name}.list" "${stage}/list"
  apk_postinst "${name}" 0 > "${stage}/scripts/post-install"
  apk_postinst "${name}" 1 > "${stage}/scripts/post-upgrade"
  apk_prerm "${name}" "${removal}" > "${stage}/scripts/pre-deinstall"
  if [ "${luci}" = 1 ]; then
    for script in post-install post-upgrade; do
      luci_refresh >> "${stage}/scripts/${script}"
    done
  fi
  local output="${name}_${file_version}_${arch}.apk"
  # apk names the architecture-independent kind noarch (OpenWrt's
  # package-pack.mk does the same); the file keeps the ipk-style name.
  local apk_arch="${arch}"
  if [ "${arch}" = all ]; then
    apk_arch=noarch
  fi
  docker run --rm --network none \
    -v "${stage}:/stage:ro" -v "${out_dir}:/out" \
    -e "NAME=${name}" -e "VERSION=${apk_version}" -e "ARCH=${apk_arch}" \
    -e "DESCRIPTION=${description}" -e "DEPENDS=${depends}" -e "LICENSE=${license}" \
    -e "URL=${url}" -e "MAINTAINER=${maintainer}" -e "OUTPUT=${output}" \
    -e "OWNER=$(id -u):$(id -g)" \
    "${APK_IMAGE}" /bin/sh -euc '
      cp -a /stage /tmp/stage
      chown -R 0:0 /tmp/stage
      apk mkpkg \
        --info "name:${NAME}" \
        --info "version:${VERSION}" \
        --info "description:${DESCRIPTION}" \
        --info "arch:${ARCH}" \
        --info "license:${LICENSE}" \
        --info "origin:apps/mesh-node/openwrt" \
        --info "url:${URL}" \
        --info "maintainer:${MAINTAINER}" \
        --info "depends:${DEPENDS}" \
        --script "post-install:/tmp/stage/scripts/post-install" \
        --script "post-upgrade:/tmp/stage/scripts/post-upgrade" \
        --script "pre-deinstall:/tmp/stage/scripts/pre-deinstall" \
        --files /tmp/stage/data \
        --output "/out/${OUTPUT}"
      chown "${OWNER}" "/out/${OUTPUT}"
    '
  echo "wrote ${output}"
}

build_both() {
  build_ipk "$@"
  if [ -n "${APK_IMAGE:-}" ]; then
    build_apk "$@"
  fi
}

# --- anixops-mesh: one package per OpenWrt architecture -----------------

files="${src}/anixops-mesh/files"
built=0
while read -r arch target; do
  case "${arch}" in "" | \#*) continue ;; esac
  mapfile -t binaries < <(find "${bin_dir}" -maxdepth 1 -type f -name "anixops-mesh-*-${target}")
  if [ "${#binaries[@]}" -eq 0 ]; then
    continue
  fi
  if [ "${#binaries[@]}" -ne 1 ]; then
    echo "::error::more than one build for ${target} in ${bin_dir}"
    exit 1
  fi
  data="${work}/data-anixops-mesh-${arch}"
  mkdir -p "${data}/usr/bin"
  cp -a "${files}/." "${data}/"
  # Modes set here, not taken from the checkout or the umask.
  find "${data}" -type d -exec chmod 0755 {} +
  find "${data}" -type f -exec chmod 0644 {} +
  install -m 0755 "${binaries[0]}" "${data}/usr/bin/anixops-mesh"
  chmod 0755 "${data}/etc/init.d/anixops-mesh" "${data}/usr/libexec/anixops-mesh/service" \
    "${data}/usr/libexec/anixops-mesh/firewall" "${data}/etc/uci-defaults/90-anixops-mesh"
  # The virtual interface needs the kernel's TUN driver; the firewall rules
  # are kept by a ucode script (ucode comes with fw4).
  build_both anixops-mesh "${arch}" "${data}" "kmod-tun ucode ucode-mod-fs ucode-mod-uci" \
    "Intranet mesh device: joins the mesh networks a panel assigns to this router." \
    ":anixops-mesh" 0 1
  built=$((built + 1))
done < "${src}/arches.txt"
if [ "${built}" -eq 0 ]; then
  echo "::error::no program build in ${bin_dir} matches arches.txt"
  exit 1
fi

# --- luci-app-anixops-mesh ----------------------------------------------

app="${src}/luci-app-anixops-mesh"
data="${work}/data-luci"
mkdir -p "${data}/www" "${data}/usr/lib/lua/luci/i18n"
cp -a "${app}/root/." "${data}/"
cp -a "${app}/htdocs/." "${data}/www/"
for po in "${app}"/po/*/anixops-mesh.po; do
  lang="$(basename "$(dirname "${po}")")"
  case "${lang}" in
    templates) continue ;;
    # The web interface names Simplified Chinese zh-cn.
    zh_Hans) code=zh-cn ;;
    *) code="$(echo "${lang}" | tr '[:upper:]_' '[:lower:]-')" ;;
  esac
  python3 "${repo}/.github/scripts/openwrt-i18n.py" lmo "${po}" "${data}/usr/lib/lua/luci/i18n/anixops-mesh.${code}.lmo"
done
find "${data}" -type d -exec chmod 0755 {} +
find "${data}" -type f -exec chmod 0644 {} +
build_both luci-app-anixops-mesh all "${data}" "luci-base rpcd-mod-ucode anixops-mesh" \
  "Web interface of the intranet mesh device: status, enrollment and subnet requests." "" 1 0

(
  cd "${out_dir}"
  rm -f SHA256SUMS
  shopt -s nullglob
  packages=(*.ipk *.apk)
  sha256sum -- "${packages[@]}" > SHA256SUMS
  cat SHA256SUMS
)
