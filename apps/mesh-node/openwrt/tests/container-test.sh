#!/bin/sh
# Installs the OpenWrt packages in an OpenWrt root file system container
# and checks the installed result (.github/workflows/openwrt.yml):
# package scripts, procd service definition, the procd wrapper's exit-code
# handling, the rpcd backend through a real ubusd and rpcd, translations
# through the web interface's own catalog loader, reinstall and removal.
#
#   container-test.sh PKG_DIR FORMAT ARCH
#
# FORMAT is ipk (opkg) or apk. PKG_DIR holds the packages and i18n-check.uc
# (generated from the catalog by the workflow).

set -eu

pkg_dir="$1"
format="$2"
arch="$3"

fail() {
	echo "::error::$*"
	exit 1
}

step() {
	echo "::group::$*"
}

end() {
	echo "::endgroup::"
}

# json FILE EXPR: one value from a JSON file.
json() {
	jsonfilter -i "$1" -e "$2"
}

case "${format}" in
	ipk)
		main_pkg="$(ls "${pkg_dir}"/anixops-mesh_*_"${arch}".ipk)"
		luci_pkg="$(ls "${pkg_dir}"/luci-app-anixops-mesh_*_all.ipk)"
		pm_update() { opkg update; }
		pm_install() { opkg install "$@"; }
		pm_reinstall() { opkg install --force-reinstall "$@"; }
		pm_remove() { opkg remove "$@"; }
		pm_installed() { opkg status "$1" | grep -q '^Status: .* installed'; }
		;;
	apk)
		main_pkg="$(ls "${pkg_dir}"/anixops-mesh_*_"${arch}".apk)"
		luci_pkg="$(ls "${pkg_dir}"/luci-app-anixops-mesh_*_all.apk)"
		pm_update() { apk update; }
		# Local packages are not signed by the OpenWrt build key.
		pm_install() { apk add --allow-untrusted "$@"; }
		pm_reinstall() { apk fix --reinstall "$@"; }
		pm_remove() { apk del "$@"; }
		pm_installed() { apk info -e "$1" > /dev/null; }
		;;
	*)
		fail "unknown format ${format}"
		;;
esac

# procd's lock and ubus's socket directories (tmpfs on a device).
mkdir -p /var/run/ubus /var/lock

# owner FILE: numeric owner:group (stat is not in every BusyBox build).
owner() {
	# shellcheck disable=SC2012 # BusyBox find has no -printf
	ls -lnd "$1" | awk '{ print $3 ":" $4 }'
}

# calls: the recorded ubus calls, with JSON's escaped slashes undone.
calls() {
	sed 's#\\/#/#g' /tmp/fakebin/calls 2> /dev/null
}

step "Install dependencies from the release feeds"
pm_update
# kmod-tun's own scripts load the module, which a container cannot do; the
# dependencies only have to be present so that our packages install.
pm_install kmod-tun luci-base rpcd-mod-ucode || true
for dep in kmod-tun luci-base rpcd-mod-ucode; do
	pm_installed "${dep}" || fail "dependency ${dep} not installed"
done
end

step "Install the packages"
pm_install "${main_pkg}" "${luci_pkg}" || fail "package installation failed"
pm_installed anixops-mesh || fail "anixops-mesh not installed"
pm_installed luci-app-anixops-mesh || fail "luci-app-anixops-mesh not installed"
end

step "Installed files"
for file in /usr/bin/anixops-mesh /etc/init.d/anixops-mesh /usr/libexec/anixops-mesh/service; do
	[ -x "${file}" ] || fail "${file} missing or not executable"
	[ "$(owner "${file}")" = 0:0 ] || fail "${file} not owned by root"
done
/usr/bin/anixops-mesh capabilities | grep -q '"commands"' || fail "program does not run"
[ -f /lib/upgrade/keep.d/anixops-mesh ] || fail "sysupgrade keep list missing"
grep -qx '/etc/anixops-mesh/' /lib/upgrade/keep.d/anixops-mesh || fail "state directory not kept on sysupgrade"
[ ! -e /etc/uci-defaults/90-anixops-mesh ] || fail "uci-defaults script was not run"
[ "$(uci -q get anixops-mesh.main)" = device ] || fail "default configuration missing"
[ "$(uci -q get anixops-mesh.main.enabled)" = 0 ] || fail "service must be off by default"
[ "$(uci -q get anixops-mesh.main.state_dir)" = /etc/anixops-mesh ] || fail "state_dir default"
grep -q '^anixops-mesh:' /etc/group || fail "group anixops-mesh not created"
ls /etc/rc.d/S95anixops-mesh > /dev/null 2>&1 || fail "init script not enabled"
for file in \
	/www/luci-static/resources/view/anixops-mesh/status.js \
	/www/luci-static/resources/view/anixops-mesh/settings.js \
	/usr/share/luci/menu.d/luci-app-anixops-mesh.json \
	/usr/share/rpcd/acl.d/luci-app-anixops-mesh.json \
	/usr/share/rpcd/ucode/luci.anixops-mesh.uc \
	/usr/lib/lua/luci/i18n/anixops-mesh.zh-cn.lmo; do
	[ -f "${file}" ] || fail "${file} missing"
done
end

# A stand-in for the program, for behaviour the installed build does not
# have yet or that needs a panel. Mode and records live in /tmp/stub.
stub_install() {
	mkdir -p /tmp/stub
	cp /usr/bin/anixops-mesh /tmp/stub/real
	cat > /usr/bin/anixops-mesh <<'EOF'
#!/bin/sh
mode="$(cat /tmp/stub/mode 2> /dev/null || echo ok)"
echo "$*" >> /tmp/stub/calls
case "$1" in
	capabilities)
		echo '{"version":"0.0.0","commands":["detect","import","takeover","rollback","run","enroll","device","device-status","subnet-request"]}'
		;;
	device)
		echo "$$" > /tmp/stub/pid
		trap 'echo term > /tmp/stub/term; exit 0' TERM
		if [ "${mode}" = sleep ]; then
			sleep 60 &
			wait $!
		fi
		exit "$(cat /tmp/stub/code 2> /dev/null || echo 0)"
		;;
	device-status)
		[ "${mode}" = stopped ] && exit 1
		echo '{"ok":true,"device":{"device_id":5,"control":"https://panel.example.com","control_state":"ok","advertise":["192.168.1.0/24"]},"mesh":{"instance_id":"i","networks":[{"tag":"mesh-eu","running":true,"address":"10.150.0.5/16","peers":[]}]}}'
		;;
	enroll)
		shift
		while [ "$#" -gt 0 ]; do
			case "$1" in
				--token-file)
					cp "$2" /tmp/stub/token-copy
					ls -l "$2" | cut -c1-10 > /tmp/stub/token-mode
					echo "$2" > /tmp/stub/token-path
					shift 2
					;;
				*) shift ;;
			esac
		done
		case "${mode}" in
			rejected) exit 8 ;;
			unreachable) exit 9 ;;
		esac
		;;
	subnet-request)
		case "${mode}" in
			refused)
				echo '{"error":"refused","detail":"not_full_node"}' >&2
				exit 10
				;;
		esac
		;;
esac
exit 0
EOF
	chmod 0755 /usr/bin/anixops-mesh
}

stub_remove() {
	cp /tmp/stub/real /usr/bin/anixops-mesh
	chmod 0755 /usr/bin/anixops-mesh
	rm -rf /tmp/stub
}

# A stand-in for ubus that records the calls procd would receive.
mkdir -p /tmp/fakebin
cat > /tmp/fakebin/ubus <<'EOF'
#!/bin/sh
echo "$*" >> /tmp/fakebin/calls
exit 0
EOF
chmod 0755 /tmp/fakebin/ubus

step "procd service definition"
rm -f /tmp/fakebin/calls
PATH="/tmp/fakebin:${PATH}" /etc/init.d/anixops-mesh start
# procd_open_service always sends an "instances" object; an instance
# would add its command.
if calls | grep -q '"command"'; then
	fail "disabled service must not start an instance"
fi
uci set anixops-mesh.main.enabled=1
uci commit anixops-mesh
rm -f /tmp/fakebin/calls
PATH="/tmp/fakebin:${PATH}" /etc/init.d/anixops-mesh start
# procd_open_service always sends an "instances" object; an instance
# would add its command.
if calls | grep -q '"command"'; then
	fail "service without a device token must not start an instance"
fi
mkdir -p /etc/anixops-mesh
chmod 0700 /etc/anixops-mesh
echo msd_test > /etc/anixops-mesh/token
rm -f /tmp/fakebin/calls
PATH="/tmp/fakebin:${PATH}" /etc/init.d/anixops-mesh start
calls
calls | grep -q '"command": \[ "/usr/libexec/anixops-mesh/service", "/etc/anixops-mesh" \]' || fail "instance command"
calls | grep -q '"respawn": \[ "3600", "5", "5" \]' || fail "respawn limits"
end

step "procd wrapper exit codes"
stub_install
echo 8 > /tmp/stub/code
rm -f /tmp/fakebin/calls
PATH="/tmp/fakebin:${PATH}" /usr/libexec/anixops-mesh/service /etc/anixops-mesh || fail "exit 8 must end the wrapper with 0"
calls | grep -q 'call service delete' || fail "exit 8 must stop the service"
echo 3 > /tmp/stub/code
rm -f /tmp/fakebin/calls
code=0
PATH="/tmp/fakebin:${PATH}" /usr/libexec/anixops-mesh/service /etc/anixops-mesh || code=$?
[ "${code}" = 3 ] || fail "other exit codes must pass through (got ${code})"
if calls | grep -q 'call service delete'; then
	fail "other exit codes must leave restarting to procd"
fi
echo sleep > /tmp/stub/mode
echo 0 > /tmp/stub/code
rm -f /tmp/stub/pid /tmp/stub/term
PATH="/tmp/fakebin:${PATH}" /usr/libexec/anixops-mesh/service /etc/anixops-mesh &
wrapper=$!
tries=0
while [ ! -s /tmp/stub/pid ]; do
	tries=$((tries + 1))
	[ "${tries}" -lt 20 ] || fail "program did not start"
	sleep 1
done
kill -TERM "${wrapper}"
code=0
wait "${wrapper}" || code=$?
[ -f /tmp/stub/term ] || fail "SIGTERM was not passed on to the program"
[ "${code}" = 0 ] || fail "wrapper must return the program's exit code after SIGTERM (got ${code})"
stub_remove
end

step "rpcd backend"
ubusd &
sleep 1
rpcd &
tries=0
until ubus list luci.anixops-mesh > /dev/null 2>&1; do
	tries=$((tries + 1))
	[ "${tries}" -lt 20 ] || fail "rpcd did not register luci.anixops-mesh"
	sleep 1
done
ubus -v list luci.anixops-mesh

call() { # METHOD [JSON]
	args="${2:-}"
	[ -n "${args}" ] || args='{}'
	ubus call luci.anixops-mesh "$1" "${args}" > /tmp/reply.json || fail "ubus call $1 failed"
	cat /tmp/reply.json
}

# The installed build: device subcommands not provided yet.
call status
[ "$(json /tmp/reply.json '@.supported.device_status')" = false ] || fail "real build: device_status"
[ "$(json /tmp/reply.json '@.service.result')" = unsupported ] || fail "real build: service result"
[ "$(json /tmp/reply.json '@.enrolled')" = true ] || fail "token file means enrolled"
call lan_networks
json /tmp/reply.json '@.networks' > /dev/null || fail "lan_networks must return a list"

call enroll '{"control":"http://panel.example.com","token":"mse_abc"}'
[ "$(json /tmp/reply.json '@.result')" = invalid_control ] || fail "http panel address must be refused"
call enroll '{"control":"https://panel.example.com/x?y","token":"mse_abc"}'
[ "$(json /tmp/reply.json '@.result')" = invalid_control ] || fail "query in panel address must be refused"
call enroll "{\"control\":\"https://panel.example.com'\",\"token\":\"mse_abc\"}"
[ "$(json /tmp/reply.json '@.result')" = invalid_control ] || fail "quote in panel address must be refused"
call enroll '{"control":"https://panel.example.com","token":"abc"}'
[ "$(json /tmp/reply.json '@.result')" = invalid_token ] || fail "credential without prefix must be refused"
call enroll '{"control":"https://panel.example.com","token":"mse_a b"}'
[ "$(json /tmp/reply.json '@.result')" = invalid_token ] || fail "credential with space must be refused"
call enroll '{"control":"https://panel.example.com","token":"mse_abc"}'
[ "$(json /tmp/reply.json '@.result')" = unsupported ] || fail "real build: enroll unsupported"

stub_install
call status
[ "$(json /tmp/reply.json '@.service.result')" = ok ] || fail "status through device-status"
[ "$(json /tmp/reply.json '@.service.mesh.networks[0].tag')" = mesh-eu ] || fail "snapshot passed on"
[ "$(json /tmp/reply.json '@.service.device.advertise[0]')" = 192.168.1.0/24 ] || fail "device fields passed on"
echo stopped > /tmp/stub/mode
call status
[ "$(json /tmp/reply.json '@.service.result')" = not_running ] || fail "stopped service"

echo ok > /tmp/stub/mode
uci set anixops-mesh.main.enabled=0
uci set anixops-mesh.main.control=''
uci commit anixops-mesh
call enroll '{"control":"https://panel.example.com:8443/base","token":"  mse_secret-1  "}'
[ "$(json /tmp/reply.json '@.result')" = ok ] || fail "enroll"
[ "$(cat /tmp/stub/token-copy)" = mse_secret-1 ] || fail "credential written to the file, trimmed"
[ "$(cat /tmp/stub/token-mode)" = -rw------- ] || fail "credential file must be 0600"
case "$(cat /tmp/stub/token-path)" in
	/tmp/anixops-mesh-enroll.*) ;;
	*) fail "credential file must be in /tmp" ;;
esac
[ ! -e "$(cat /tmp/stub/token-path)" ] || fail "credential file must be removed"
if grep -q 'mse_secret' /tmp/stub/calls; then
	fail "credential must not appear on a command line"
fi
grep -q -- "--control https://panel.example.com:8443/base --token-file /tmp/anixops-mesh-enroll\.[A-Za-z0-9]* --state-dir /etc/anixops-mesh" /tmp/stub/calls ||
	fail "enroll arguments"
[ "$(uci -q get anixops-mesh.main.control)" = https://panel.example.com:8443/base ] || fail "panel address saved"
[ "$(uci -q get anixops-mesh.main.enabled)" = 1 ] || fail "service enabled after enrollment"
echo rejected > /tmp/stub/mode
call enroll '{"control":"https://panel.example.com","token":"mse_abc"}'
[ "$(json /tmp/reply.json '@.result')" = rejected ] || fail "exit 8 means rejected"
echo unreachable > /tmp/stub/mode
call enroll '{"control":"https://panel.example.com","token":"mse_abc"}'
[ "$(json /tmp/reply.json '@.result')" = unreachable ] || fail "exit 9 means unreachable"
ls /tmp/anixops-mesh-enroll.* > /dev/null 2>&1 && fail "credential files left behind"

echo ok > /tmp/stub/mode
for bad in '["192.168.1.1/24"]' '["8.8.8.0/24"]' '["192.168.1.0/31"]' '["192.168.01.0/24"]' \
	'["192.168.1.0/24","192.168.1.0/24"]' '["10.0.0.0/8; reboot"]' '[1]' \
	'["10.0.1.0/24","10.0.2.0/24","10.0.3.0/24","10.0.4.0/24","10.0.5.0/24","10.0.6.0/24","10.0.7.0/24","10.0.8.0/24","10.0.9.0/24","10.0.10.0/24","10.0.11.0/24","10.0.12.0/24","10.0.13.0/24","10.0.14.0/24","10.0.15.0/24","10.0.16.0/24","10.0.17.0/24"]'; do
	call request_subnets "{\"cidrs\":${bad}}"
	[ "$(json /tmp/reply.json '@.result')" = invalid_subnets ] || fail "must refuse ${bad}"
done
call request_subnets '{"cidrs":["192.168.1.0/24","172.16.0.0/12"]}'
[ "$(json /tmp/reply.json '@.result')" = ok ] || fail "subnet request"
grep -q -- "subnet-request --state-dir /etc/anixops-mesh --cidr 192.168.1.0/24 --cidr 172.16.0.0/12" /tmp/stub/calls ||
	fail "subnet-request arguments"
[ "$(uci -q get anixops-mesh.main.advertise)" = "192.168.1.0/24 172.16.0.0/12" ] || fail "requested subnets recorded"
echo refused > /tmp/stub/mode
call request_subnets '{"cidrs":["10.1.0.0/16"]}'
[ "$(json /tmp/reply.json '@.result')" = refused ] || fail "exit 10 means refused"
[ "$(json /tmp/reply.json '@.reason')" = not_full_node ] || fail "panel reason passed on"
[ "$(uci -q get anixops-mesh.main.advertise)" = "192.168.1.0/24 172.16.0.0/12" ] || fail "refused request must not change the record"
echo ok > /tmp/stub/mode
call request_subnets '{"cidrs":[]}'
[ "$(json /tmp/reply.json '@.result')" = ok ] || fail "withdrawal"
[ -z "$(uci -q get anixops-mesh.main.advertise)" ] || fail "withdrawal clears the record"
rm /etc/anixops-mesh/token
call request_subnets '{"cidrs":["192.168.1.0/24"]}'
[ "$(json /tmp/reply.json '@.result')" = not_enrolled ] || fail "request without token"
stub_remove
end

step "Translations through the web interface's catalog loader"
ucode "${pkg_dir}/i18n-check.uc" || fail "translations"
end

step "Reinstall keeps the configuration"
uci set anixops-mesh.main.control=https://kept.example.com
uci commit anixops-mesh
pm_reinstall anixops-mesh || fail "reinstall failed"
[ "$(uci -q get anixops-mesh.main.control)" = https://kept.example.com ] || fail "configuration replaced on reinstall"
end

step "Removal"
pm_remove luci-app-anixops-mesh anixops-mesh || fail "removal failed"
[ ! -e /usr/bin/anixops-mesh ] || fail "program left behind"
[ ! -e /etc/init.d/anixops-mesh ] || fail "init script left behind"
if ls /etc/rc.d/*anixops-mesh > /dev/null 2>&1; then
	fail "init script still enabled"
fi
[ ! -e /usr/share/rpcd/ucode/luci.anixops-mesh.uc ] || fail "rpcd backend left behind"
end

echo "OpenWrt ${format} package checks passed"
