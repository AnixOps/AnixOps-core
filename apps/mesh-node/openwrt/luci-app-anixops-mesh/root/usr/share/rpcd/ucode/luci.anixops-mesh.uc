// rpcd backend of the LuCI plugin (docs/deploy/openwrt.md). It only runs
// the local anixops-mesh program: status comes from the device's local
// status socket (`device-status`), so no network port is opened (R11), and
// the panel is reached only by the program itself.

'use strict';

import { popen, writefile, unlink, stat } from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';

const PROGRAM = '/usr/bin/anixops-mesh';
const INIT = '/etc/init.d/anixops-mesh';
// Fixed, as in the init script: it holds the device token and keys, so no
// setting (which LuCI's UCI write access could change) may move it.
const STATE_DIR = '/etc/anixops-mesh';
// The panel takes at most 16 networks per request.
const MAX_SUBNETS = 16;

function quote(value) {
	return "'" + replace(`${value}`, "'", "'\\''") + "'";
}

// Runs a shell command line built only from constants and quoted values.
// Returns the exit code and the output (standard error is merged).
function run(command) {
	const proc = popen(command + ' 2>&1', 'r');
	if (!proc)
		return { code: -1, output: '' };
	const output = proc.read('all') ?? '';
	const code = proc.close();
	return { code, output };
}

// The program reports errors as one JSON line, the last line of standard
// error. Only its category is passed on: `detail` may name local paths.
function error_kind(output) {
	const lines = filter(split(trim(output), '\n'), length);
	if (!length(lines))
		return null;
	let parsed = null;
	try {
		parsed = json(lines[length(lines) - 1]);
	}
	catch (e) {
		return null;
	}
	if (type(parsed) != 'object')
		return null;
	const kind = parsed.error;
	return (type(kind) == 'string' && match(kind, /^[a-z0-9_]{1,64}$/)) ? kind : null;
}

// The program's subcommands, read once per installed program (rpcd keeps
// this script loaded): the status page polls every 5 seconds.
let capability_cache = null;

function capabilities() {
	const info = stat(PROGRAM);
	const key = info ? `${info.inode}:${info.size}:${info.mtime}` : null;
	if (key == null)
		return [];
	if (capability_cache?.key == key)
		return capability_cache.commands;
	const result = run(`${PROGRAM} capabilities`);
	let commands = [];
	if (result.code == 0) {
		try {
			const parsed = json(result.output);
			if (type(parsed?.commands) == 'array')
				commands = filter(parsed.commands, (c) => type(c) == 'string');
		}
		catch (e) {
			commands = [];
		}
	}
	capability_cache = { key, commands };
	return commands;
}

// Panel address as the program takes it (docs/deploy/mesh-device.md):
// https://host[:port], no path, user part, query or fragment.
function valid_control(value) {
	return type(value) == 'string' && length(value) <= 256 &&
		match(value, /^https:\/\/[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$/) != null;
}

// One-time enrollment credential (docs/deploy/mesh-device.md): `mse_`,
// visible ASCII, at most 256 bytes.
function valid_token(value) {
	return type(value) == 'string' && length(value) <= 256 &&
		match(value, /^mse_[!-~]+$/) != null;
}

function octets(text) {
	const m = match(text, /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\/([0-9]{1,2})$/);
	if (!m)
		return null;
	const parts = map(slice(m, 1, 5), (v) => +v);
	const prefix = +m[5];
	for (let v in parts)
		if (v > 255)
			return null;
	// No leading zeros: some parsers read them as octal.
	for (let i = 1; i <= 4; i++)
		if (length(m[i]) > 1 && substr(m[i], 0, 1) == '0')
			return null;
	if (prefix > 32)
		return null;
	return { parts, prefix };
}

function to_number(parts) {
	return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
}

function from_number(n) {
	return [ (n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255 ];
}

function network_of(parts, prefix) {
	const n = to_number(parts);
	const size = 1 << (32 - prefix);
	return n - (n % size);
}

// Private IPv4 ranges the panel accepts for advertised subnets.
const PRIVATE = [ [ [10, 0, 0, 0], 8 ], [ [172, 16, 0, 0], 12 ], [ [192, 168, 0, 0], 16 ] ];

function is_private(parts, prefix) {
	for (let range in PRIVATE)
		if (prefix >= range[1] && network_of(parts, range[1]) == to_number(range[0]))
			return true;
	return false;
}

// A subnet to request: private, prefix 8–30, host bits zero (the panel
// rejects host bits instead of normalising them).
function valid_subnet(text) {
	if (type(text) != 'string')
		return false;
	const parsed = octets(text);
	if (!parsed || parsed.prefix < 8 || parsed.prefix > 30)
		return false;
	if (network_of(parsed.parts, parsed.prefix) != to_number(parsed.parts))
		return false;
	return is_private(parsed.parts, parsed.prefix);
}

// UCI can also be changed outside this backend (LuCI's generic UCI access,
// the command line): values are checked again before they are returned.
function settings() {
	const uci = cursor();
	uci.load('anixops-mesh');
	let advertise = uci.get('anixops-mesh', 'main', 'advertise') ?? [];
	if (type(advertise) != 'array')
		advertise = [ advertise ];
	const control = uci.get('anixops-mesh', 'main', 'control') ?? '';
	return {
		enabled: uci.get('anixops-mesh', 'main', 'enabled') == '1',
		control: valid_control(control) ? control : '',
		advertise: filter(advertise, valid_subnet)
	};
}

function token_present(state_dir) {
	const info = stat(`${state_dir}/token`);
	return info != null && info.type == 'file' && info.size > 0;
}

const methods = {
	status: {
		call: function() {
			const conf = settings();
			const commands = capabilities();
			const result = {
				enabled: conf.enabled,
				control: conf.control,
				enrolled: token_present(STATE_DIR),
				requested: conf.advertise,
				supported: {
					device: index(commands, 'device') >= 0,
					enroll: index(commands, 'enroll') >= 0,
					device_status: index(commands, 'device-status') >= 0,
					subnet_request: index(commands, 'subnet-request') >= 0
				}
			};
			if (!result.supported.device_status) {
				result.service = { result: 'unsupported' };
				return result;
			}
			const out = run(`${PROGRAM} device-status --state-dir ${quote(STATE_DIR)}`);
			if (out.code == 1) {
				result.service = { result: 'not_running' };
				return result;
			}
			let snapshot = null;
			try {
				snapshot = json(out.output);
			}
			catch (e) {
				snapshot = null;
			}
			if (out.code != 0 || type(snapshot) != 'object' || snapshot.ok !== true)
				result.service = { result: 'error', error: error_kind(out.output) };
			else
				result.service = { result: 'ok', device: snapshot.device, mesh: snapshot.mesh };
			return result;
		}
	},

	// Private IPv4 networks of the router's own interfaces, offered as
	// subnets to request. The mesh interface and WAN-like interfaces with
	// public addresses are left out by the private-range check.
	lan_networks: {
		call: function() {
			const bus = connect();
			const dump = bus?.call('network.interface', 'dump');
			const networks = [];
			for (let iface in dump?.interface ?? []) {
				if (!iface.up || iface.interface == 'loopback')
					continue;
				for (let addr in iface['ipv4-address'] ?? []) {
					const parsed = octets(`${addr.address}/${addr.mask}`);
					if (!parsed || parsed.prefix < 8 || parsed.prefix > 30)
						continue;
					const network = join('.', from_number(network_of(parsed.parts, parsed.prefix)));
					const cidr = `${network}/${parsed.prefix}`;
					if (is_private(parsed.parts, parsed.prefix))
						push(networks, { interface: iface.interface, cidr });
				}
			}
			return { networks };
		}
	},

	enroll: {
		args: { control: 'control', token: 'token' },
		call: function(req) {
			const control = req.args?.control;
			const token = trim(req.args?.token ?? '');
			if (!valid_control(control))
				return { result: 'invalid_control' };
			if (!valid_token(token))
				return { result: 'invalid_token' };
			if (index(capabilities(), 'enroll') < 0)
				return { result: 'unsupported' };

			// The credential goes to a 0600 file in /tmp (memory, never the
			// flash) and is removed right after; it never appears in a
			// command line.
			const made = run('umask 077 && mktemp /tmp/anixops-mesh-enroll.XXXXXX');
			const path = trim(made.output);
			if (made.code != 0 || !match(path, /^\/tmp\/anixops-mesh-enroll\.[A-Za-z0-9]{6}$/))
				return { result: 'error' };
			let out;
			if (!writefile(path, token + '\n')) {
				unlink(path);
				return { result: 'error' };
			}
			run(`umask 077 && mkdir -p ${quote(STATE_DIR)}`);
			out = run(`${PROGRAM} enroll --control ${quote(control)} --token-file ${quote(path)} --state-dir ${quote(STATE_DIR)}`);
			unlink(path);

			if (out.code == 8)
				return { result: 'rejected' };
			if (out.code == 9)
				return { result: 'unreachable' };
			if (out.code != 0)
				return { result: 'error', error: error_kind(out.output) };

			const uci = cursor();
			uci.load('anixops-mesh');
			uci.set('anixops-mesh', 'main', 'control', control);
			uci.set('anixops-mesh', 'main', 'enabled', '1');
			uci.commit('anixops-mesh');
			run(`${INIT} enable`);
			run(`${INIT} restart`);
			return { result: 'ok' };
		}
	},

	// Asks the panel to advertise these LAN subnets from this device; an
	// administrator approves the request there. An empty list withdraws a
	// pending request.
	request_subnets: {
		args: { cidrs: [] },
		call: function(req) {
			const cidrs = req.args?.cidrs;
			if (type(cidrs) != 'array' || length(cidrs) > MAX_SUBNETS)
				return { result: 'invalid_subnets' };
			const seen = {};
			for (let cidr in cidrs) {
				if (!valid_subnet(cidr) || seen[cidr])
					return { result: 'invalid_subnets' };
				seen[cidr] = true;
			}
			if (index(capabilities(), 'subnet-request') < 0)
				return { result: 'unsupported' };

			if (!token_present(STATE_DIR))
				return { result: 'not_enrolled' };
			let command = `${PROGRAM} subnet-request --state-dir ${quote(STATE_DIR)}`;
			for (let cidr in cidrs)
				command += ` --cidr ${quote(cidr)}`;
			const out = run(command);
			if (out.code == 8)
				return { result: 'revoked' };
			if (out.code == 9)
				return { result: 'unreachable' };
			if (out.code == 10) {
				// The panel's own reason, e.g. not_full_node.
				const lines = split(trim(out.output), '\n');
				let detail = null;
				try {
					detail = json(lines[length(lines) - 1])?.detail;
				}
				catch (e) {
					detail = null;
				}
				const known = (type(detail) == 'string' && match(detail, /^[a-z0-9_]{1,64}$/)) ? detail : null;
				return { result: 'refused', reason: known };
			}
			if (out.code != 0)
				return { result: 'error', error: error_kind(out.output) };

			const uci = cursor();
			uci.load('anixops-mesh');
			if (length(cidrs))
				uci.set('anixops-mesh', 'main', 'advertise', cidrs);
			else
				uci.delete('anixops-mesh', 'main', 'advertise');
			uci.commit('anixops-mesh');
			return { result: 'ok' };
		}
	}
};

return { 'luci.anixops-mesh': methods };
