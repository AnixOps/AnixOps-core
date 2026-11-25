#!/bin/sh
# One-command installer of the intranet mesh node for Linux.
#
#   install-linux.sh --binary-url URL --binary-sha256 HEX
#                    [--profile-url URL --profile-sha256 HEX]
#                    [--config FILE] [--address CIDR] [--allow-unencrypted]
#                    [--accept-confirmations] [--dry-run]
#   install-linux.sh --uninstall
#
# The panel generates the command with the exact URLs and SHA-256 values,
# so every download is checked before it runs. With a takeover profile the
# script imports the existing installation and only takes it over when this
# build can run the node; if our service fails to start, the takeover is
# rolled back. See docs/deploy/mesh-node.md.

set -eu

PREFIX=/usr/local/bin
BIN="$PREFIX/anixops-mesh"
ETC=/etc/anixops-mesh
STATE=/var/lib/anixops-mesh
CONFIG="$ETC/mesh.json"
PROFILE="$ETC/takeover-profile.json"
UNIT=/etc/systemd/system/anixops-mesh.service
OPENRC=/etc/init.d/anixops-mesh

binary_url=""
binary_sha256=""
profile_url=""
profile_sha256=""
config=""
address=""
allow_unencrypted=0
accept_confirmations=0
dry_run=0
uninstall=0

log() { printf '%s\n' "anixops-mesh: $*" >&2; }
die() { log "$*"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --binary-url) binary_url="${2:?}"; shift 2 ;;
    --binary-sha256) binary_sha256="${2:?}"; shift 2 ;;
    --profile-url) profile_url="${2:?}"; shift 2 ;;
    --profile-sha256) profile_sha256="${2:?}"; shift 2 ;;
    --config) config="${2:?}"; shift 2 ;;
    --address) address="${2:?}"; shift 2 ;;
    --allow-unencrypted) allow_unencrypted=1; shift ;;
    --accept-confirmations) accept_confirmations=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    --uninstall) uninstall=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done

[ "$(uname -s)" = Linux ] || die "this installer is for Linux"
[ "$(id -u)" -eq 0 ] || die "run as root"

has() { command -v "$1" >/dev/null 2>&1; }

if [ -d /run/systemd/system ]; then
  manager=systemd
elif has openrc-run || [ -x /sbin/openrc-run ]; then
  manager=openrc
else
  die "no supported service manager (systemd or OpenRC)"
fi

stop_ours() {
  if [ "$manager" = systemd ]; then
    systemctl disable --now anixops-mesh.service >/dev/null 2>&1 || true
  else
    rc-service anixops-mesh stop >/dev/null 2>&1 || true
    rc-update del anixops-mesh default >/dev/null 2>&1 || true
  fi
}

if [ "$uninstall" -eq 1 ]; then
  stop_ours
  rm -f "$UNIT" "$OPENRC"
  [ "$manager" = systemd ] && systemctl daemon-reload
  if [ -x "$BIN" ] && [ -f "$STATE/takeover/takeover.json" ]; then
    log "restoring the programs that were taken over"
    "$BIN" rollback --state-dir "$STATE/takeover" --report "$STATE/rollback-report.json" >/dev/null \
      || die "rollback incomplete; see $STATE/rollback-report.json"
  fi
  log "removed the service; configuration kept in $ETC"
  exit 0
fi

if [ -z "$binary_url" ] || [ -z "$binary_sha256" ]; then
  die "--binary-url and --binary-sha256 are required"
fi
if [ -n "$profile_url" ] && [ -z "$profile_sha256" ]; then
  die "--profile-sha256 is required with --profile-url"
fi

case "$(uname -m)" in
  x86_64 | amd64 | aarch64 | arm64) ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

fetch() {
  if has curl; then
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$2" "$1"
  elif has wget; then
    case "$1" in https://*) ;; *) die "only https downloads are allowed" ;; esac
    # GNU wget can refuse a redirect to plain http; BusyBox wget has no such
    # switch, and the checksum check below still rejects whatever it fetched.
    if wget --help 2>&1 | grep -q -- '--https-only'; then
      wget -q --https-only -O "$2" "$1"
    else
      wget -q -O "$2" "$1"
    fi
  else
    die "curl or wget is required"
  fi
}

verify() {
  actual="$(sha256sum "$1" | cut -d' ' -f1)"
  expected="$(printf '%s' "$2" | tr 'A-F' 'a-f')"
  [ "$actual" = "$expected" ] || die "checksum mismatch for $3"
}

log "downloading the program"
fetch "$binary_url" "$work/anixops-mesh"
verify "$work/anixops-mesh" "$binary_sha256" "the program"
chmod 0755 "$work/anixops-mesh"
"$work/anixops-mesh" capabilities >"$work/capabilities.json" || die "the downloaded program does not run here"
can_run=0
grep -q '"run"' "$work/capabilities.json" && can_run=1

install -d -m 0700 "$ETC" "$STATE"

imported=""
if [ -n "$profile_url" ]; then
  log "downloading the takeover profile"
  fetch "$profile_url" "$work/profile.json"
  verify "$work/profile.json" "$profile_sha256" "the takeover profile"
  set -- import --profile "$work/profile.json" --out-dir "$work/imported" --report "$work/import-report.json"
  [ -n "$address" ] && set -- "$@" --address "$address"
  [ "$allow_unencrypted" -eq 1 ] && set -- "$@" --allow-unencrypted
  status=0
  "$work/anixops-mesh" "$@" >/dev/null || status=$?
  install -m 0600 "$work/import-report.json" "$STATE/import-report.json"
  case "$status" in
    0) ;;
    3) log "no existing installation found" ;;
    5)
      if [ "$accept_confirmations" -ne 1 ]; then
        die "the import needs confirmation; review $STATE/import-report.json, then rerun with --accept-confirmations"
      fi
      ;;
    6) die "this machine cannot be migrated automatically; see $STATE/import-report.json" ;;
    *) die "the import failed ($status); see $STATE/import-report.json" ;;
  esac
  if [ "$status" -ne 3 ]; then
    count="$(find "$work/imported" -maxdepth 1 -name '*.json' -type f | wc -l | tr -d ' ')"
    [ "$count" -eq 1 ] || die "found $count networks on this machine; one node per network is not supported yet"
    imported="$(find "$work/imported" -maxdepth 1 -name '*.json' -type f)"
  fi
fi

if [ -n "$config" ] && [ -n "$imported" ]; then
  die "--config and an imported configuration are both present; give one"
fi
source_config="${config:-$imported}"
[ -n "$source_config" ] || [ -f "$CONFIG" ] || die "no configuration: pass --config or a takeover profile"

if [ "$dry_run" -eq 1 ]; then
  log "dry run: checks passed; nothing was changed"
  [ -n "$profile_url" ] && "$work/anixops-mesh" takeover --profile "$work/profile.json" --state-dir "$STATE/takeover" --dry-run
  exit 0
fi

install -m 0755 "$work/anixops-mesh" "$BIN"
[ -n "$profile_url" ] && install -m 0600 "$work/profile.json" "$PROFILE"
[ -n "$source_config" ] && install -m 0600 "$source_config" "$CONFIG"

if [ "$can_run" -ne 1 ]; then
  log "installed the program and the configuration; this build cannot run the node yet, so nothing was taken over or started"
  exit 0
fi

if [ "$manager" = systemd ]; then
  cat >"$UNIT" <<EOF
[Unit]
Description=AnixOps intranet mesh node
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN run --config $CONFIG
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=2 3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
else
  cat >"$OPENRC" <<EOF
#!/sbin/openrc-run
description="AnixOps intranet mesh node"
command="$BIN"
command_args="run --config $CONFIG"
command_background=true
pidfile="/run/anixops-mesh.pid"
depend() {
  need net
}
EOF
  chmod 0755 "$OPENRC"
fi

if [ -n "$profile_url" ]; then
  log "taking over the existing installation"
  "$BIN" takeover --profile "$PROFILE" --state-dir "$STATE/takeover" --report "$STATE/takeover-report.json" >/dev/null \
    || die "takeover failed and was rolled back; see $STATE/takeover-report.json"
fi

started=0
if [ "$manager" = systemd ]; then
  systemctl enable --now anixops-mesh.service >/dev/null 2>&1 && started=1
  sleep 5
  systemctl is-active --quiet anixops-mesh.service || started=0
else
  rc-update add anixops-mesh default >/dev/null 2>&1 || true
  rc-service anixops-mesh start >/dev/null 2>&1 && started=1
  sleep 5
  rc-service anixops-mesh status >/dev/null 2>&1 || started=0
fi

if [ "$started" -ne 1 ]; then
  log "the node did not start; restoring the previous state"
  stop_ours
  if [ -n "$profile_url" ]; then
    "$BIN" rollback --state-dir "$STATE/takeover" --report "$STATE/rollback-report.json" >/dev/null \
      || die "rollback incomplete; see $STATE/rollback-report.json"
  fi
  die "installation failed; see the service log"
fi
log "installed and running"
