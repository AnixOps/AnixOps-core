// Firewall rules of the mesh device (docs/deploy/openwrt.md, 防火墙),
// kept in /etc/config/firewall for fw4:
//
//   zone anixmesh   every mesh interface (anixmesh-<n>): input REJECT, so
//                   mesh members reach no service of the router (web
//                   interface, SSH, DNS); output ACCEPT; forward REJECT
//   anixmesh_wan_*  full node only: the listening ports the panel assigned,
//                   accepted from the wan zone, nothing else
//   anixmesh_in_*   full node only: mesh to lan, to an approved advertised
//   anixmesh_out_*  subnet only, and lan to mesh from that subnet only
//
// Only rules named anixmesh_* and the zone anixmesh are ever changed. The
// configuration ($STATE_DIR/config.json) is the panel's answer as accepted
// by the program, which validated it; it holds the network keys and is
// only read here, never copied.

'use strict';

import { readfile, stat } from 'fs';
import { cursor } from 'uci';

const STATE_DIR = '/etc/anixops-mesh';
const ZONE = 'anixmesh';
const PREFIX = 'anixmesh_';
// The mesh module's listening port when the panel gives none.
const DEFAULT_PORT = 11010;

function valid_cidr(text) {
	if (type(text) != 'string')
		return false;
	const m = match(text, /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\/([0-9]{1,2})$/);
	if (!m)
		return false;
	for (let i = 1; i <= 4; i++)
		if (+m[i] > 255 || (length(m[i]) > 1 && substr(m[i], 0, 1) == '0'))
			return false;
	return +m[5] >= 8 && +m[5] <= 32;
}

function desired_rules() {
	const rules = {};
	const text = readfile(`${STATE_DIR}/config.json`);
	if (!text)
		return rules;
	let doc = null;
	try {
		doc = json(text);
	}
	catch (e) {
		return rules;
	}
	const networks = doc?.data?.networks;
	if (type(networks) != 'array')
		return rules;
	for (let network in networks) {
		if (network?.role != 'full')
			continue;
		for (let listen in (type(network.listen) == 'array' ? network.listen : [])) {
			const proto = listen?.transport;
			const port = listen?.port ?? DEFAULT_PORT;
			if ((proto != 'tcp' && proto != 'udp') || type(port) != 'int' || port < 1 || port > 65535)
				continue;
			rules[`${PREFIX}wan_${proto}_${port}`] = {
				name: `AnixOps-Mesh-${proto}-${port}`,
				src: 'wan',
				proto,
				dest_port: `${port}`,
				target: 'ACCEPT'
			};
		}
		const advertise = network.subnets?.advertise;
		for (let cidr in (type(advertise) == 'array' ? advertise : [])) {
			if (!valid_cidr(cidr))
				continue;
			const id = replace(cidr, /[.\/]/g, '_');
			rules[`${PREFIX}in_${id}`] = {
				name: `AnixOps-Mesh-to-${cidr}`,
				src: ZONE,
				dest: 'lan',
				dest_ip: cidr,
				proto: 'all',
				target: 'ACCEPT'
			};
			rules[`${PREFIX}out_${id}`] = {
				name: `AnixOps-Mesh-from-${cidr}`,
				src: 'lan',
				src_ip: cidr,
				dest: ZONE,
				proto: 'all',
				target: 'ACCEPT'
			};
		}
	}
	return rules;
}

// A section holds exactly these options (UCI's own .keys aside).
function same(section, options) {
	for (let key in keys(section))
		if (substr(key, 0, 1) != '.' && section[key] != options[key])
			return false;
	for (let key in keys(options))
		if (section[key] != options[key])
			return false;
	return true;
}

function apply(rules, zone) {
	// No firewall installed: nothing to keep in step.
	if (!stat('/etc/config/firewall'))
		return 0;
	const uci = cursor();
	if (!uci.load('firewall'))
		return 1;
	let changed = false;

	const existing = {};
	uci.foreach('firewall', 'rule', function(section) {
		if (index(section['.name'], PREFIX) == 0)
			existing[section['.name']] = section;
	});
	for (let name in keys(existing)) {
		if (!rules[name] || !same(existing[name], rules[name])) {
			uci.delete('firewall', name);
			changed = true;
		}
	}
	for (let name in keys(rules)) {
		if (existing[name] && same(existing[name], rules[name]))
			continue;
		uci.set('firewall', name, 'rule');
		for (let key in keys(rules[name]))
			uci.set('firewall', name, key, rules[name][key]);
		changed = true;
	}

	const have_zone = uci.get('firewall', ZONE) != null;
	if (zone == 'ensure' && !have_zone) {
		// Created once; options an operator changes later are kept.
		uci.set('firewall', ZONE, 'zone');
		uci.set('firewall', ZONE, 'name', ZONE);
		uci.set('firewall', ZONE, 'device', [ 'anixmesh-+' ]);
		uci.set('firewall', ZONE, 'input', 'REJECT');
		uci.set('firewall', ZONE, 'output', 'ACCEPT');
		uci.set('firewall', ZONE, 'forward', 'REJECT');
		changed = true;
	}
	else if (zone == 'remove' && have_zone) {
		uci.delete('firewall', ZONE);
		changed = true;
	}

	if (!changed)
		return 0;
	if (!uci.commit('firewall'))
		return 1;
	// The firewall may not run (for example while the image is built).
	system('/etc/init.d/firewall reload >/dev/null 2>&1');
	print(`firewall rules updated: ${length(keys(rules))} rule(s)\n`);
	return 0;
}

switch (ARGV[0]) {
case 'sync':
	exit(apply(desired_rules(), 'ensure'));
case 'clear':
	exit(apply({}, 'keep'));
case 'remove':
	exit(apply({}, 'remove'));
default:
	warn('usage: firewall.uc sync|clear|remove\n');
	exit(2);
}
