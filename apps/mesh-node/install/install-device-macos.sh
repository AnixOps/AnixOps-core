#!/bin/sh
# Installer of the mesh device without the Agent for macOS
# (docs/deploy/mesh-device.md).
#
#   install-device-macos.sh (--binary-url URL | --binary-file FILE) --binary-sha256 HEX
#                           --control URL [--token-file FILE]
#                           [--latency CODE=MS]... [--ca-file FILE]
#   install-device-macos.sh --uninstall [--purge]
#
# Places the program, enrolls the device with the one-time credential and
# starts it as the launchd system daemon com.anixops.mesh.device. The
# credential is read from --token-file, or asked for on the terminal; it
# never goes on a command line. A device already enrolled (its state
# directory holds a token) is not enrolled again: the program is replaced
# and the daemon restarted. --uninstall stops and removes the daemon and the
# program and keeps the state directory (the device identity), unless
# --purge is given. Run as root.
#
# /etc, /var and /tmp are links on macOS, and the program refuses state
# directories reached through a link, so everything lives under /Library.

set -eu

HOME_DIR="/Library/Application Support/AnixOps/mesh"
PREFIX="$HOME_DIR/bin"
BIN="$PREFIX/anixops-mesh"
STATE="$HOME_DIR/device"
CA="$HOME_DIR/control-ca.pem"
LABEL=com.anixops.mesh.device
PLIST="/Library/LaunchDaemons/$LABEL.plist"
LOG=/Library/Logs/anixops-mesh-device.log

binary_url=""
binary_file=""
binary_sha256=""
control=""
token_file=""
ca_file=""
latencies=""
uninstall=0
purge=0

log() { printf '%s\n' "anixops-mesh: $*" >&2; }
die() { log "$*"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --binary-url) binary_url="${2:?}"; shift 2 ;;
    --binary-file) binary_file="${2:?}"; shift 2 ;;
    --binary-sha256) binary_sha256="${2:?}"; shift 2 ;;
    --control) control="${2:?}"; shift 2 ;;
    --token-file) token_file="${2:?}"; shift 2 ;;
    --ca-file) ca_file="${2:?}"; shift 2 ;;
    --latency)
      case "${2:?}" in *[!A-Za-z0-9=.-]*) die "--latency takes CODE=MS" ;; esac
      latencies="$latencies $2"; shift 2 ;;
    --uninstall) uninstall=1; shift ;;
    --purge) purge=1; shift ;;
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
  rm -f "$PLIST" "$BIN"
  rmdir "$PREFIX" 2>/dev/null || true
  if [ "$purge" -eq 1 ]; then
    rm -rf "$STATE" "$CA" "$LOG"
    log "removed the daemon, the program and the device state; revoke the device in the panel"
  else
    log "removed the daemon and the program; the device identity is kept in $STATE (--purge removes it)"
  fi
  exit 0
fi

if [ -z "$binary_sha256" ] || { [ -z "$binary_url" ] && [ -z "$binary_file" ]; }; then
  die "--binary-url or --binary-file, and --binary-sha256, are required"
fi
[ -z "$binary_url" ] || [ -z "$binary_file" ] || die "give --binary-url or --binary-file, not both"

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

if [ -n "$binary_url" ]; then
  log "downloading the program"
  fetch "$binary_url" "$work/anixops-mesh"
else
  cp "$binary_file" "$work/anixops-mesh"
fi
verify "$work/anixops-mesh" "$binary_sha256" "the program"
chmod 0755 "$work/anixops-mesh"
"$work/anixops-mesh" capabilities >"$work/capabilities.json" || die "the program does not run here"
for command in enroll device device-status; do
  grep -q "\"$command\"" "$work/capabilities.json" || die "this build has no $command command"
done

# Owned by root and closed to others all the way down: the program checks.
# The state directory is open to the admin group for traversal only, so
# that administrators reach the status socket (0660, group admin) without
# sudo; they cannot list or read anything in it.
for dir in "/Library/Application Support/AnixOps" "$HOME_DIR" "$PREFIX" "$STATE"; do
  [ ! -L "$dir" ] || die "$dir is a link; remove it and run again"
done
install -d -o root -g wheel -m 0755 "/Library/Application Support/AnixOps" "$HOME_DIR" "$PREFIX"
install -d -o root -g admin -m 0710 "$STATE"

enrolled=0
[ -f "$STATE/token" ] && [ -f "$STATE/device.json" ] && enrolled=1

if [ "$enrolled" -eq 0 ]; then
  [ -n "$control" ] || die "--control is required to enroll"
  if [ -n "$token_file" ]; then
    install -m 0600 "$token_file" "$work/token"
  else
    [ -r /dev/tty ] || die "--token-file is required without a terminal"
    printf 'One-time credential: ' >/dev/tty
    stty -echo </dev/tty
    IFS= read -r credential </dev/tty || credential=""
    stty echo </dev/tty
    printf '\n' >/dev/tty
    (umask 077 && printf '%s\n' "$credential" >"$work/token")
    credential=""
  fi
  set -- enroll --control "$control" --token-file "$work/token" --state-dir "$STATE"
  # Each entry was checked to hold only CODE=MS characters above.
  # shellcheck disable=SC2086
  for latency in $latencies; do
    set -- "$@" --latency "$latency"
  done
  if [ -n "$ca_file" ]; then
    # Kept beside the state: the device trusts only this file from now on.
    install -o root -g wheel -m 0644 "$ca_file" "$CA"
    set -- "$@" --ca-file "$CA"
  fi
  log "enrolling the device"
  status=0
  "$work/anixops-mesh" "$@" >/dev/null || status=$?
  rm -f "$work/token"
  case "$status" in
    0) ;;
    8) die "the panel refused the credential; ask the administrator for a new one" ;;
    9) die "the panel could not be reached or answered wrongly; run again within 10 minutes with the same credential" ;;
    *) die "enrolment failed ($status)" ;;
  esac
else
  log "the device is already enrolled; replacing the program"
fi

stop_ours
install -o root -g wheel -m 0755 "$work/anixops-mesh" "$BIN"

# Kept alive while the device has a token: when the panel refuses the token
# the program removes it and stops with exit code 8, and launchd does not
# start it again until the device is enrolled again. launchd waits the
# throttle interval between starts. Umask 63 is 077.
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
    <string>device</string>
    <string>--state-dir</string>
    <string>$STATE</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>PathState</key>
    <dict>
      <key>$STATE/token</key>
      <true/>
    </dict>
  </dict>
  <key>Umask</key>
  <integer>63</integer>
  <key>ThrottleInterval</key>
  <integer>30</integer>
  <key>StandardErrorPath</key>
  <string>$LOG</string>
</dict>
</plist>
EOF
plutil -lint "$work/daemon.plist" >/dev/null || die "the daemon definition is invalid"
# The log is for the administrators only, like the state (umask 077 above
# keeps the files the program makes owner-only too).
[ ! -L "$LOG" ] || die "$LOG is a link; remove it and run again"
touch "$LOG"
chown root:admin "$LOG"
chmod 0640 "$LOG"
install -o root -g wheel -m 0644 "$work/daemon.plist" "$PLIST"

launchctl enable "system/$LABEL" >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST" >/dev/null 2>&1 || {
  rm -f "$PLIST"
  die "launchd refused the daemon; see $LOG"
}
# The daemon answers on its status socket once it runs.
answered=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if "$BIN" device-status --state-dir "$STATE" >/dev/null 2>&1; then
    answered=1
    break
  fi
  sleep 1
done
if [ "$answered" -ne 1 ]; then
  stop_ours
  rm -f "$PLIST"
  die "the device did not start or its status socket could not be made; see $LOG (the enrolment is kept; run again to retry)"
fi
log "installed and running"
