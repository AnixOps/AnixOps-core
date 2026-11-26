#!/bin/sh
# One-command installer of the intranet mesh node for macOS.
#
#   install-macos.sh --binary-url URL --binary-sha256 HEX
#                    [--profile-url URL --profile-sha256 HEX]
#                    [--config FILE] [--address CIDR] [--allow-unencrypted]
#                    [--accept-confirmations] [--dry-run]
#   install-macos.sh --uninstall
#
# The panel generates the command with the exact URLs and SHA-256 values,
# so every download is checked before it runs. The node runs as a launchd
# system daemon. With a takeover profile the script imports the existing
# installation and only takes it over when this build can run the node; if
# our daemon fails to start, the takeover is rolled back. See
# docs/deploy/mesh-node.md.
#
# /etc, /var and /tmp are links on macOS, and the program refuses state
# directories reached through a link, so everything lives under /Library,
# the program too: /usr/local/bin may belong to a user (a per-user package
# manager), who could then replace what root runs.

set -eu

HOME_DIR=/Library/AnixOps/mesh
PREFIX="$HOME_DIR/bin"
BIN="$PREFIX/anixops-mesh"
STATE="$HOME_DIR/state"
CONFIG="$HOME_DIR/mesh.json"
PROFILE="$HOME_DIR/takeover-profile.json"
LABEL=com.anixops.mesh
PLIST="/Library/LaunchDaemons/$LABEL.plist"
LOG=/Library/Logs/anixops-mesh.log

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

[ "$(uname -s)" = Darwin ] || die "this installer is for macOS"
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

stop_ours() {
  launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
}

if [ "$uninstall" -eq 1 ]; then
  stop_ours
  rm -f "$PLIST"
  # Put back the forwarding and pf rules a node that died left.
  if [ -x "$BIN" ]; then
    "$BIN" restore-host >/dev/null \
      || log "warning: host changes could not be restored; run '$BIN restore-host' as root"
  fi
  if [ -x "$BIN" ] && [ -f "$STATE/takeover/takeover.json" ]; then
    log "restoring the programs that were taken over"
    "$BIN" rollback --state-dir "$STATE/takeover" --report "$STATE/rollback-report.json" >/dev/null \
      || die "rollback incomplete; see $STATE/rollback-report.json"
  fi
  log "removed the daemon; configuration kept in $HOME_DIR"
  exit 0
fi

if [ -z "$binary_url" ] || [ -z "$binary_sha256" ]; then
  die "--binary-url and --binary-sha256 are required"
fi
if [ -n "$profile_url" ] && [ -z "$profile_sha256" ]; then
  die "--profile-sha256 is required with --profile-url"
fi

case "$(uname -m)" in
  x86_64 | arm64) ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

fetch() {
  case "$1" in https://*) ;; *) die "only https downloads are allowed" ;; esac
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$2" "$1"
}

verify() {
  actual="$(shasum -a 256 "$1" | cut -d' ' -f1)"
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

# Owned by root and closed to others all the way down: the program checks.
for dir in /Library/AnixOps "$HOME_DIR" "$PREFIX" "$STATE"; do
  [ ! -L "$dir" ] || die "$dir is a link; remove it and run again"
done
install -d -o root -g wheel -m 0755 /Library/AnixOps
install -d -o root -g wheel -m 0700 "$HOME_DIR" "$STATE"
install -d -o root -g wheel -m 0755 "$PREFIX"

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

# The takeover's own checks, before anything is installed: a process it
# could not put back on rollback refuses the takeover.
if [ -n "$profile_url" ] && [ "$can_run" -eq 1 ]; then
  if ! "$work/anixops-mesh" takeover --profile "$work/profile.json" --state-dir "$STATE/takeover" \
    --dry-run --report "$work/takeover-check.json" >/dev/null; then
    install -m 0600 "$work/takeover-check.json" "$STATE/takeover-check.json"
    die "the takeover would be refused; see $STATE/takeover-check.json"
  fi
fi

if [ "$dry_run" -eq 1 ]; then
  log "dry run: checks passed; nothing was changed"
  [ -n "$profile_url" ] && "$work/anixops-mesh" takeover --profile "$work/profile.json" --state-dir "$STATE/takeover" --dry-run
  exit 0
fi

install -o root -g wheel -m 0755 "$work/anixops-mesh" "$BIN"
[ -n "$profile_url" ] && install -m 0600 "$work/profile.json" "$PROFILE"
[ -n "$source_config" ] && install -m 0600 "$source_config" "$CONFIG"

if [ "$can_run" -ne 1 ]; then
  log "installed the program and the configuration; this build cannot run the node yet, so nothing was taken over or started"
  exit 0
fi

# Restarted after a failure, not after a clean exit; launchd waits its
# throttle interval between starts.
cat >"$work/daemon.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN</string>
    <string>run</string>
    <string>--config</string>
    <string>$CONFIG</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardErrorPath</key>
  <string>$LOG</string>
</dict>
</plist>
EOF
plutil -lint "$work/daemon.plist" >/dev/null || die "the daemon definition is invalid"
install -o root -g wheel -m 0644 "$work/daemon.plist" "$PLIST"

if [ -n "$profile_url" ]; then
  log "taking over the existing installation"
  status=0
  "$BIN" takeover --profile "$PROFILE" --state-dir "$STATE/takeover" --report "$STATE/takeover-report.json" >/dev/null \
    || status=$?
  case "$status" in
    0) ;;
    7) die "takeover failed and could not be fully undone; see $STATE/takeover-report.json, then run: $BIN rollback --state-dir $STATE/takeover" ;;
    *) die "takeover failed or was refused; nothing it changed is left changed; see $STATE/takeover-report.json" ;;
  esac
fi

started=0
launchctl enable "system/$LABEL" >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST" >/dev/null 2>&1 && started=1
sleep 5
launchctl print "system/$LABEL" 2>/dev/null | grep -q 'state = running' || started=0

if [ "$started" -ne 1 ]; then
  log "the node did not start; restoring the previous state"
  stop_ours
  rm -f "$PLIST"
  if [ -n "$profile_url" ]; then
    "$BIN" rollback --state-dir "$STATE/takeover" --report "$STATE/rollback-report.json" >/dev/null \
      || die "rollback incomplete; see $STATE/rollback-report.json"
  fi
  die "installation failed; see $LOG"
fi
log "installed and running"
