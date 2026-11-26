'use strict';
'require view';
'require rpc';
'require poll';
'require dom';

// Status of the intranet mesh device (docs/deploy/openwrt.md). Read-only:
// the data comes from the local status socket through rpcd, refreshed every
// 5 seconds; no network port is involved (R11).

const callStatus = rpc.declare({
	object: 'luci.anixops-mesh',
	method: 'status',
	expect: { '': {} }
});

const FAILURES = {
	secret_mismatch: _('Network name or key differs from the peer'),
	security_mismatch: _('Security mode differs from the peer'),
	unencrypted_refused: _('Peer without encryption refused'),
	port_in_use: _('Listening port in use'),
	tun_in_use: _('Virtual interface name in use'),
	native_keys_pending: _('Waiting for the administrator to admit this device'),
	peer_not_native: _('Peer not admitted to this network refused'),
	route_overlap: _('Route conflicts with an existing route'),
	address_in_use: _('Virtual address used by another interface'),
	identity_online: _('Device identity online elsewhere'),
	permission_denied: _('Insufficient permission'),
	unreachable_peers: _('No peer reachable')
};

const ALERTS = {
	address_conflict: _('Address conflict'),
	address_unmanaged: _('Address not managed'),
	start_refused: _('Start refused')
};

const CONTROL_STATES = {
	ok: _('Normal'),
	unreachable: _('Unreachable'),
	rejected: _('Latest configuration rejected')
};

function text(value) {
	return (value === null || value === undefined || value === '') ? '—' : String(value);
}

function time(value) {
	if (typeof value !== 'string' || value === '')
		return '—';
	const date = new Date(value);
	return isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

function yesNo(value) {
	return value ? _('Yes') : _('No');
}

function failureText(failure) {
	if (!failure || typeof failure.code !== 'string')
		return null;
	return FAILURES[failure.code] || failure.code;
}

function row(label, value) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td left', 'width': '33%' }, label),
		E('td', { 'class': 'td left' }, value)
	]);
}

function table(titles, rows, empty) {
	const head = E('tr', { 'class': 'tr table-titles' },
		titles.map(function(title) { return E('th', { 'class': 'th' }, title); }));
	if (!rows.length)
		return E('table', { 'class': 'table' }, [ head,
			E('tr', { 'class': 'tr placeholder' }, [ E('td', { 'class': 'td' }, E('em', {}, empty)) ]) ]);
	return E('table', { 'class': 'table' }, [ head ].concat(rows.map(function(cells) {
		return E('tr', { 'class': 'tr' }, cells.map(function(cell) {
			return E('td', { 'class': 'td' }, cell);
		}));
	})));
}

function overlapText(overlap) {
	if (typeof overlap === 'string')
		return overlap;
	if (overlap && typeof overlap.cidr === 'string')
		return overlap.cidr;
	return null;
}

function renderNetwork(network) {
	const failure = failureText(network.failure);
	const state = network.running ? _('Running') : _('Stopped');
	const peers = Array.isArray(network.peers) ? network.peers : [];
	const alerts = Array.isArray(network.alerts) ? network.alerts : [];
	const overlaps = (Array.isArray(network.overlaps) ? network.overlaps : [])
		.map(overlapText).filter(function(v) { return v; });

	const facts = [
		row(_('State'), failure ? state + ' (' + failure + ')' : state),
		row(_('Virtual address'), text(network.address)),
		row(_('Forward secrecy'), yesNo(network.forward_secrecy))
	];
	if (network.rejected_advertisements > 0)
		facts.push(row(_('Rejected subnet advertisements'), String(network.rejected_advertisements)));
	if (overlaps.length)
		facts.push(row(_('Overlapping subnets'), overlaps.join(', ')));
	alerts.forEach(function(alert) {
		const label = ALERTS[alert.code] || text(alert.code);
		facts.push(row(_('Alert'), alert.address ? label + ': ' + alert.address : label));
	});

	const members = peers.map(function(peer) {
		const latency = (typeof peer.latency_ms === 'number') ? peer.latency_ms + ' ms' : _('Not measured');
		return [
			text(peer.address),
			Array.isArray(peer.subnets) && peer.subnets.length ? peer.subnets.join(', ') : '—',
			peer.via ? peer.via : _('Direct'),
			text(peer.hops),
			latency,
			yesNo(peer.forward_secrecy)
		];
	});

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, text(network.tag)),
		E('table', { 'class': 'table' }, facts),
		E('h4', {}, _('Members')),
		table([ _('Virtual address'), _('Subnets'), _('Path'), _('Hops'), _('Latency'), _('Forward secrecy') ],
			members, _('No members'))
	]);
}

function renderStatus(data) {
	const nodes = [];
	const service = data.service || {};
	const device = service.device || {};

	let serviceText;
	switch (service.result) {
	case 'ok': serviceText = _('Running'); break;
	case 'not_running': serviceText = _('Not running'); break;
	case 'unsupported': serviceText = _('Not supported by the installed program version'); break;
	default: serviceText = _('Status unavailable');
	}

	const facts = [
		row(_('Enrollment'), data.enrolled ? _('Enrolled') : _('Not enrolled')),
		row(_('Panel address'), text(data.control)),
		row(_('Service'), serviceText)
	];
	if (service.result === 'ok') {
		facts.push(row(_('Panel connection'), CONTROL_STATES[device.control_state] || text(device.control_state)));
		facts.push(row(_('Last configuration'), time(device.last_config)));
		facts.push(row(_('Last report'), time(device.last_report)));
	}
	nodes.push(E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, _('Device')),
		E('table', { 'class': 'table' }, facts)
	]));

	const networks = (service.mesh && Array.isArray(service.mesh.networks)) ? service.mesh.networks : [];
	if (service.result === 'ok' && !networks.length)
		nodes.push(E('div', { 'class': 'cbi-section' }, E('em', {}, _('No network assigned to this device'))));
	networks.forEach(function(network) { nodes.push(renderNetwork(network)); });
	return nodes;
}

return view.extend({
	load: function() {
		return callStatus();
	},

	render: function(data) {
		const body = E('div', {}, renderStatus(data));
		poll.add(function() {
			return callStatus().then(function(next) {
				dom.content(body, renderStatus(next));
			});
		}, 5);
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('Intranet mesh')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Status of this device in the intranet mesh. Networks are assigned by the panel.')),
			body
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
