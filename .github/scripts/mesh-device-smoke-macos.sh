#!/usr/bin/env bash
# Smoke test of the device without the Agent on macOS: installs it with
# install-device-macos.sh against a stand-in for Control
# (mesh-device-mock-control.py, private CA), and checks that
#   - the device enrolls, runs as the launchd daemon and reports;
#   - the state directory is root:admin 0710 with owner-only files, and an
#     administrator reads the status socket without sudo;
#   - running the installer again keeps the enrolment;
#   - a revoked token stops the daemon with exit code 8, removes the token
#     and is not restarted;
#   - --uninstall removes the daemon and the program and keeps the state,
#     --purge removes the state.
# Needs passwordless sudo (GitHub's macOS runners).
#
#   mesh-device-smoke-macos.sh BINARY WORK_DIR

set -euo pipefail

binary="${1:?usage: $0 BINARY WORK_DIR}"
work="${2:?usage: $0 BINARY WORK_DIR}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
installer="${root}/apps/mesh-node/install/install-device-macos.sh"
home="/Library/Application Support/AnixOps/mesh"
state="${home}/device"
bin="${home}/bin/anixops-mesh"
label=com.anixops.mesh.device
plist="/Library/LaunchDaemons/${label}.plist"
log=/Library/Logs/anixops-mesh-device.log
mock="${work}/mock"

fail() {
  echo "::error::$*"
  sudo tail -n 50 "${log}" 2>/dev/null || true
  exit 1
}

wait_for() {
  local what="$1" tries="$2"
  shift 2
  for _ in $(seq "${tries}"); do
    if "$@"; then
      return 0
    fi
    sleep 1
  done
  fail "timed out waiting for ${what}"
}

counted() {
  [ -f "${mock}/$1.count" ] && [ "$(cat "${mock}/$1.count")" -ge "$2" ]
}

running() {
  sudo launchctl print "system/${label}" 2>/dev/null | grep -q 'state = running'
}

"${root}/.github/scripts/mesh-device-certs.sh" "${work}/certs"
mkdir -p "${mock}"
python3 "${root}/.github/scripts/mesh-device-mock-control.py" \
  --cert "${work}/certs/leaf.pem" --key "${work}/certs/leaf.key" --dir "${mock}" &
mock_pid=$!
cleanup() {
  kill "${mock_pid}" 2>/dev/null || true
  sudo sh "${installer}" --uninstall --purge >/dev/null 2>&1 || true
}
trap cleanup EXIT
wait_for "the mock Control" 20 test -s "${mock}/port"
control="https://localhost:$(cat "${mock}/port")"

sha="$(shasum -a 256 "${binary}" | cut -d' ' -f1)"
printf 'mse_ci-smoke\n' > "${work}/credential"
chmod 0600 "${work}/credential"

echo "::group::Install and enroll"
sudo sh "${installer}" --binary-file "${binary}" --binary-sha256 "${sha}" \
  --control "${control}" --token-file "${work}/credential" \
  --latency cn=30 --ca-file "${work}/certs/ca.pem"
echo "::endgroup::"

counted enroll 1 || fail "the device did not enroll"
running || fail "the daemon is not running"
[ "$(sudo stat -f '%Su:%Sg %Lp' "${state}")" = "root:admin 710" ] \
  || fail "state directory is $(sudo stat -f '%Su:%Sg %Lp' "${state}")"
for file in device.json token config.json instance_id; do
  [ "$(sudo stat -f '%Su %Lp' "${state}/${file}")" = "root 600" ] \
    || fail "${file} is $(sudo stat -f '%Su %Lp' "${state}/${file}")"
done
[ "$(sudo stat -f '%Su:%Sg %Lp' "${log}")" = "root:admin 640" ] \
  || fail "the log is $(sudo stat -f '%Su:%Sg %Lp' "${log}")"
[ "$(sudo stat -f '%Sg %Lp' "${state}/status.sock")" = "admin 660" ] \
  || fail "status.sock is $(sudo stat -f '%Sg %Lp' "${state}/status.sock")"
id -Gn | tr ' ' '\n' | grep -qx admin || fail "the runner account is not an administrator"

# An administrator reads the status without sudo.
status="$("${bin}" device-status --state-dir "${state}")"
echo "${status}"
python3 - "${status}" <<'PY'
import json, sys
status = json.loads(sys.argv[1])
assert status["ok"] is True, status
assert status["device"]["device_id"] == 5, status
assert status["device"]["control"].startswith("https://localhost:"), status
assert status["mesh"]["networks"] == [], status
text = json.dumps(status)
assert "msd_" not in text and "mse_" not in text, "a token in the status"
PY
# Others get nothing out of the state directory.
if sudo -u nobody "${bin}" device-status --state-dir "${state}" >/dev/null 2>&1; then
  fail "an account outside the admin group read the status"
fi
wait_for "the first report" 30 counted report 1
wait_for "control_state ok" 10 sh -c "'${bin}' device-status --state-dir '${state}' | grep -q '\"control_state\":\"ok\"'"

echo "::group::Install again"
sudo sh "${installer}" --binary-file "${binary}" --binary-sha256 "${sha}"
echo "::endgroup::"
[ "$(cat "${mock}/enroll.count")" -eq 1 ] || fail "an enrolled device enrolled again"
running || fail "the daemon is not running after the second install"

echo "::group::Revoked token"
touch "${mock}/revoke"
sudo launchctl kickstart -k "system/${label}"
wait_for "the token to go" 20 sudo test ! -e "${state}/token"
sleep 40
if running; then
  fail "the daemon runs again without a token"
fi
sudo launchctl print "system/${label}" | grep -E 'last exit code = 8' \
  || fail "the daemon did not stop with exit code 8"
if "${bin}" device-status --state-dir "${state}" >/dev/null 2>&1; then
  fail "device-status answered with the service stopped"
fi
echo "::endgroup::"

echo "::group::Uninstall"
sudo sh "${installer}" --uninstall
[ ! -e "${plist}" ] || fail "the daemon definition is still there"
[ ! -e "${bin}" ] || fail "the program is still there"
sudo test -f "${state}/device.json" || fail "the device identity was not kept"
if sudo launchctl print "system/${label}" >/dev/null 2>&1; then
  fail "launchd still knows the daemon"
fi
sudo sh "${installer}" --uninstall --purge
sudo test ! -e "${state}" || fail "--purge kept the state directory"
[ ! -e "${log}" ] || fail "--purge kept the log"
echo "::endgroup::"
echo "macOS device smoke test passed"
