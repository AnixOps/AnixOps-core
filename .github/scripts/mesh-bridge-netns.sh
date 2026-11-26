#!/usr/bin/env bash
# External network bridge (spec §15.12, crates/mesh-bridge) against the real
# Linux nftables, in three network namespaces:
#
#   member  m0 10.150.0.2/16 (+ 10.150.0.3, not allowed)
#     |
#   bridge  anixmesh-0 10.150.0.1/16 | ext0 100.100.0.1/24
#     |
#   extnet  x0 100.100.0.5/24 (+ 100.100.0.6, not a route)
#
# The external side has no route back to 10.150.0.0/16 at first, so a reply
# reaching the member proves the source was translated.
#
# Usage (root): BRIDGE_NETNS=path/to/bridge-netns mesh-bridge-netns.sh
set -euo pipefail

BIN="${BRIDGE_NETNS:?set BRIDGE_NETNS to the bridge-netns example binary}"
MESH_IF=anixmesh-0
table_mesh0=anixops_bridge_616e69786d6573682d30
failures=0

cleanup() {
  for ns in member bridge extnet; do
    ip netns del "${ns}" 2>/dev/null || true
  done
}
trap cleanup EXIT
cleanup

pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; failures=$((failures + 1)); }
reaches() { ip netns exec "$1" ping -c 1 -W 1 "${@:2}" >/dev/null 2>&1; }
expect_reach() { if reaches "$@"; then pass "$1 reaches ${*: -1} (${*:2})"; else fail "$1 should reach (${*:2})"; fi; }
expect_blocked() { if reaches "$@"; then fail "$1 should not reach (${*:2})"; else pass "$1 blocked (${*:2})"; fi; }
counters() { ip netns exec bridge "${BIN}" counters "${MESH_IF}"; }
digest() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
# Tracked connections in the bridge namespace from $1 to $2.
tracked() { ip netns exec bridge conntrack -L -s "$1" -d "$2" 2>/dev/null | grep -c . || true; }

for ns in member bridge extnet; do
  ip netns add "${ns}"
  ip -n "${ns}" link set lo up
done
ip link add m0 netns member type veth peer name "${MESH_IF}" netns bridge
ip link add ext0 netns bridge type veth peer name x0 netns extnet

ip -n member addr add 10.150.0.2/16 dev m0
ip -n member addr add 10.150.0.3/16 dev m0
ip -n member link set m0 up
ip -n member route add 100.100.0.0/24 via 10.150.0.1

ip -n bridge addr add 10.150.0.1/16 dev "${MESH_IF}"
ip -n bridge addr add 100.100.0.1/24 dev ext0
ip -n bridge link set "${MESH_IF}" up
ip -n bridge link set ext0 up

ip -n extnet addr add 100.100.0.5/24 dev x0
ip -n extnet addr add 100.100.0.6/24 dev x0
ip -n extnet link set x0 up

# A new namespace may inherit forwarding from the host (devconf_inherit_init_net);
# start from off so the check below shows the bridge turned it on.
ip netns exec bridge sysctl -qw net.ipv4.ip_forward=0
[[ "$(ip netns exec bridge cat /proc/sys/net/ipv4/ip_forward)" == 0 ]] || fail "forwarding starts off"
expect_blocked member -I 10.150.0.2 100.100.0.5

# Recheck #357 Y1: the capability probe loads inet NAT and leaves nothing.
if ip netns exec bridge "${BIN}" probe; then pass "probe succeeds"; else fail "probe succeeds"; fi
if [[ -z "$(ip netns exec bridge nft list tables)" ]]; then pass "probe leaves no table"; else fail "probe leaves no table"; fi

config='{"interface":"ext0","routes":["100.100.0.5"],"allow":["10.150.0.2/32"]}'
out="$(ip netns exec bridge "${BIN}" apply "${MESH_IF}" "${config}" 10.150.0.0/16 10.150.0.1)"
echo "${out}"
if [[ "$(ip netns exec bridge cat /proc/sys/net/ipv4/ip_forward)" == 1 ]]; then
  pass "IPv4 forwarding turned on"
else
  fail "IPv4 forwarding turned on"
fi
want="$(digest "10.150.0.2/32")"
if grep -q "\"allowDigest\":\"${want}\"" <<<"${out}"; then pass "allowDigest"; else fail "allowDigest ${want}"; fi
want="$(digest "100.100.0.5/32")"
if grep -q "\"routesDigest\":\"${want}\"" <<<"${out}"; then pass "routesDigest"; else fail "routesDigest ${want}"; fi
ip netns exec bridge nft list ruleset

# Allowed source to an advertised address: passes, translated.
expect_reach member -I 10.150.0.2 100.100.0.5
# Source not on the allow list: dropped and counted.
expect_blocked member -I 10.150.0.3 100.100.0.5
read -r source_denied inbound_denied < <(counters)
if (( source_denied >= 1 )); then pass "source_denied counted (${source_denied})"; else fail "source_denied counted"; fi
# External address that is not a route: dropped.
expect_blocked member -I 10.150.0.2 100.100.0.6

# One way: the external side cannot open connections into the mesh, not
# even with a route, and not to the bridge's own mesh address.
ip -n extnet route add 10.150.0.0/16 via 100.100.0.1
expect_blocked extnet 10.150.0.2
expect_blocked extnet 10.150.0.1
read -r source_denied inbound_denied < <(counters)
if (( inbound_denied >= 2 )); then pass "inbound_denied counted (${inbound_denied})"; else fail "inbound_denied counted"; fi
# The bridge's own external address is not ours to block.
expect_reach extnet 100.100.0.1

# Recheck #356 X3: narrowing the list also deletes the tracked connections
# it no longer allows; the external side's own connections stay.
n="$(tracked 10.150.0.2 100.100.0.5)"
if (( n >= 1 )); then pass "allowed source has tracked connections (${n})"; else fail "allowed source has tracked connections"; fi

# A new allow list replaces the old one at once.
config='{"interface":"ext0","routes":["100.100.0.5"],"allow":["10.150.0.3/32"]}'
ip netns exec bridge "${BIN}" apply "${MESH_IF}" "${config}" 10.150.0.0/16 10.150.0.1
ip -n extnet route del 10.150.0.0/16
n="$(tracked 10.150.0.2 100.100.0.5)"
if (( n == 0 )); then pass "removed source's tracked connections deleted"; else fail "removed source still has ${n} tracked connections"; fi
n="$(tracked 100.100.0.5 100.100.0.1)"
if (( n >= 1 )); then pass "external side's own connections kept (${n})"; else fail "external side's own connections kept"; fi
expect_blocked member -I 10.150.0.2 100.100.0.5
expect_reach member -I 10.150.0.3 100.100.0.5

# A config the checks refuse changes nothing.
bad='{"interface":"ext0","routes":["100.64.0.0/10"],"allow":[]}'
bad_out="$(ip netns exec bridge "${BIN}" apply "${MESH_IF}" "${bad}" 10.150.0.0/16 10.150.0.1 2>&1 || true)"
if grep -q external_bridge_overlay_range <<<"${bad_out}"; then
  pass "whole-range route refused"
else
  fail "whole-range route refused"
fi
expect_reach member -I 10.150.0.3 100.100.0.5

# Removal takes the table away and is idempotent.
ip netns exec bridge "${BIN}" remove "${MESH_IF}"
ip netns exec bridge "${BIN}" remove "${MESH_IF}"
if ip netns exec bridge nft list tables | grep -q anixops_bridge_; then
  fail "table removed"
else
  pass "table removed"
fi

# Spec §15.12 item 9: start-up and exit clear every table carrying our mark
# and nothing else. A run that crashed leaves two bridges' tables; another
# program has its own tables, one of them with a similar name.
ip netns exec bridge "${BIN}" apply "${MESH_IF}" "${config}" 10.150.0.0/16 10.150.0.1 >/dev/null
ip netns exec bridge "${BIN}" apply anixmesh-1 "${config}" 10.151.0.0/16 10.151.0.1 >/dev/null
ip netns exec bridge nft add table inet other_program
ip netns exec bridge nft add table inet anixops_bridge_other
ip netns exec bridge nft add table ip anixops_bridge_616e69786d6573682d30
expect_reach member -I 10.150.0.3 100.100.0.5
expect_reach extnet 100.100.0.1
n="$(tracked 10.150.0.3 100.100.0.5)"
if (( n >= 1 )); then pass "crashed run left tracked connections (${n})"; else fail "crashed run left tracked connections"; fi
removed="$(ip netns exec bridge "${BIN}" cleanup)"
n="$(tracked 10.150.0.3 100.100.0.5)"
if (( n == 0 )); then pass "cleanup deleted the bridged connections"; else fail "cleanup left ${n} bridged connections"; fi
n="$(tracked 100.100.0.5 100.100.0.1)"
if (( n >= 1 )); then pass "cleanup kept other connections (${n})"; else fail "cleanup kept other connections"; fi
if [[ "${removed}" == 2 ]]; then pass "cleanup removed our 2 tables"; else fail "cleanup removed ${removed}, want 2"; fi
left="$(ip netns exec bridge nft list tables)"
echo "${left}"
if grep -qx "table inet ${table_mesh0}" <<<"${left}" || grep -q "table inet anixops_bridge_616e69786d6573682d31" <<<"${left}"; then
  fail "our tables are gone"
else
  pass "our tables are gone"
fi
for keep in "table inet other_program" "table inet anixops_bridge_other" "table ip anixops_bridge_616e69786d6573682d30"; do
  if grep -qx "${keep}" <<<"${left}"; then pass "kept: ${keep}"; else fail "kept: ${keep}"; fi
done
expect_blocked member -I 10.150.0.3 100.100.0.5
removed="$(ip netns exec bridge "${BIN}" cleanup)"
if [[ "${removed}" == 0 ]]; then pass "second cleanup finds nothing"; else fail "second cleanup removed ${removed}"; fi

if (( failures > 0 )); then
  echo "${failures} check(s) failed"
  exit 1
fi
echo "all checks passed"
