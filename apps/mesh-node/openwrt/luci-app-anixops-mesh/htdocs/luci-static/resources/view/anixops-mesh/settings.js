'use strict';
'require view';
'require form';
'require rpc';
'require ui';

// Settings of the intranet mesh device (docs/deploy/openwrt.md): service
// switch, enrollment with a one-time credential, and requests to advertise
// LAN subnets. Networks themselves are assigned by the panel; a subnet
// request takes effect only after an administrator approves it there.
//
// Every value that does not come from this file is passed to E() inside an
// array: LuCI turns array items into text nodes, while a lone string child
// is assigned to innerHTML.

const callStatus = rpc.declare({
	object: 'luci.anixops-mesh',
	method: 'status',
	expect: { '': {} }
});

const callLanNetworks = rpc.declare({
	object: 'luci.anixops-mesh',
	method: 'lan_networks',
	expect: { networks: [] }
});

const callEnroll = rpc.declare({
	object: 'luci.anixops-mesh',
	method: 'enroll',
	params: [ 'control', 'token' ],
	expect: { '': {} }
});

const callRequestSubnets = rpc.declare({
	object: 'luci.anixops-mesh',
	method: 'request_subnets',
	params: [ 'cidrs' ],
	expect: { '': {} }
});

const ENROLL_RESULTS = {
	ok: _('Enrollment completed. The service has been started.'),
	invalid_control: _('The panel address must be an https address.'),
	invalid_token: _('The enrollment credential is invalid.'),
	unsupported: _('Not supported by the installed program version.'),
	rejected: _('The panel rejected the enrollment credential. Request a new credential from the administrator.'),
	unreachable: _('The panel is unreachable or returned an invalid response.'),
	error: _('Enrollment failed.')
};

const REQUEST_RESULTS = {
	ok: _('Request submitted. The subnets take effect after an administrator approves them.'),
	invalid_subnets: _('Enter at most 16 private IPv4 subnets in network address form, for example 192.168.1.0/24.'),
	unsupported: _('Not supported by the installed program version.'),
	not_enrolled: _('This device is not enrolled.'),
	revoked: _('The device token has been revoked. Enroll the device again.'),
	unreachable: _('The panel is unreachable or returned an invalid response.'),
	refused: _('The panel refused the request.'),
	error: _('Request failed.')
};

const REFUSED_REASONS = {
	not_full_node: _('Only full nodes can advertise subnets.'),
	invalid_request: _('The panel rejected one or more subnets.')
};

function approvedSubnets(status) {
	const device = status.service && status.service.device;
	return (device && Array.isArray(device.advertise)) ? device.advertise : null;
}

function subnetState(cidr, requested, approved) {
	if (approved !== null && approved.indexOf(cidr) >= 0)
		return _('Approved');
	if (requested.indexOf(cidr) >= 0)
		return approved === null ? _('Requested') : _('Pending approval');
	return '';
}

return view.extend({
	load: function() {
		return Promise.all([ callStatus(), callLanNetworks() ]);
	},

	enrollDialog: function(status) {
		const control = E('input', {
			'class': 'cbi-input-text', 'type': 'text', 'value': status.control || '',
			'placeholder': 'https://panel.example.com'
		});
		const token = E('input', {
			'class': 'cbi-input-password', 'type': 'password', 'autocomplete': 'off'
		});
		ui.showModal(_('Enroll device'), [
			E('p', {}, [ _('Enter the panel address and the one-time enrollment credential issued by the administrator.') ]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, [ _('Panel address') ]),
				E('div', { 'class': 'cbi-value-field' }, [ control ])
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, [ _('Enrollment credential') ]),
				E('div', { 'class': 'cbi-value-field' }, [ token ])
			]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]),
				' ',
				E('button', {
					'class': 'btn cbi-button-action',
					'click': ui.createHandlerFn(this, function() {
						return callEnroll(control.value.trim(), token.value.trim()).then(function(res) {
							const message = ENROLL_RESULTS[res.result] || ENROLL_RESULTS.error;
							token.value = '';
							ui.hideModal();
							ui.addNotification(null, E('p', {}, [ message ]), res.result === 'ok' ? 'info' : 'danger');
							if (res.result === 'ok')
								window.setTimeout(function() { location.reload(); }, 1500);
						});
					})
				}, [ _('Enroll') ])
			])
		]);
	},

	renderSubnets: function(status, lans) {
		const requested = Array.isArray(status.requested) ? status.requested : [];
		const approved = approvedSubnets(status);
		const known = {};
		const boxes = [];

		function addRow(cidr, label) {
			if (known[cidr])
				return;
			known[cidr] = true;
			const box = E('input', { 'type': 'checkbox', 'value': cidr });
			box.checked = requested.indexOf(cidr) >= 0;
			boxes.push(box);
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td', 'width': '1%' }, [ box ]),
				E('td', { 'class': 'td' }, [ cidr ]),
				E('td', { 'class': 'td' }, [ label || '—' ]),
				E('td', { 'class': 'td' }, [ subnetState(cidr, requested, approved) || '—' ])
			]);
		}

		const rows = [];
		lans.forEach(function(lan) { const r = addRow(lan.cidr, lan.interface); if (r) rows.push(r); });
		requested.concat(approved || []).forEach(function(cidr) { const r = addRow(cidr, null); if (r) rows.push(r); });

		const other = E('input', {
			'class': 'cbi-input-text', 'type': 'text', 'placeholder': '192.168.10.0/24, 10.20.0.0/16'
		});

		const submit = E('button', {
			'class': 'btn cbi-button-action',
			'click': ui.createHandlerFn(this, function() {
				const cidrs = boxes.filter(function(b) { return b.checked; }).map(function(b) { return b.value; });
				other.value.split(/[\s,]+/).forEach(function(v) {
					if (v !== '' && cidrs.indexOf(v) < 0)
						cidrs.push(v);
				});
				return callRequestSubnets(cidrs).then(function(res) {
					let message = REQUEST_RESULTS[res.result] || REQUEST_RESULTS.error;
					if (res.result === 'refused' && REFUSED_REASONS[res.reason])
						message = REFUSED_REASONS[res.reason];
					ui.addNotification(null, E('p', {}, [ message ]), res.result === 'ok' ? 'info' : 'danger');
					if (res.result === 'ok')
						window.setTimeout(function() { location.reload(); }, 1500);
				});
			})
		}, [ _('Submit request') ]);

		const disabled = !status.enrolled || !status.supported || !status.supported.subnet_request;
		if (disabled)
			submit.setAttribute('disabled', 'disabled');

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ _('Advertised LAN subnets') ]),
			E('div', { 'class': 'cbi-section-descr' },
				[ _('Select the LAN subnets that other mesh members may reach through this router. The request is sent to the panel and takes effect after an administrator approves it. Submitting an empty selection withdraws a pending request.') ]),
			E('table', { 'class': 'table' }, [
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th' }, []),
					E('th', { 'class': 'th' }, [ _('Subnet') ]),
					E('th', { 'class': 'th' }, [ _('Interface') ]),
					E('th', { 'class': 'th' }, [ _('State') ])
				])
			].concat(rows.length ? rows : [
				E('tr', { 'class': 'tr placeholder' }, [ E('td', { 'class': 'td' }, [ E('em', {}, [ _('No private LAN subnet found') ]) ]) ])
			])),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, [ _('Other subnets') ]),
				E('div', { 'class': 'cbi-value-field' }, [ other ])
			]),
			E('div', { 'class': 'right' }, [ submit ])
		]);
	},

	render: function(data) {
		const status = data[0] || {};
		const lans = Array.isArray(data[1]) ? data[1] : [];
		const self = this;

		const m = new form.Map('anixops-mesh', _('Intranet mesh'),
			_('Networks, addresses and peers of this device are assigned by the panel. This page only controls the service, enrollment and subnet requests.'));
		const s = m.section(form.NamedSection, 'main', 'device', _('Service'));
		s.addremove = false;
		s.option(form.Flag, 'enabled', _('Enable service'),
			_('The service starts only after the device has been enrolled.'));

		const enrollment = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ _('Enrollment') ]),
			E('table', { 'class': 'table' }, [
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td left', 'width': '33%' }, [ _('State') ]),
					E('td', { 'class': 'td left' }, [ status.enrolled ? _('Enrolled') : _('Not enrolled') ])
				]),
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td left', 'width': '33%' }, [ _('Panel address') ]),
					E('td', { 'class': 'td left' }, [ status.control || '—' ])
				])
			]),
			E('div', { 'class': 'right' }, [ E('button', {
				'class': 'btn cbi-button-action',
				'click': function() { self.enrollDialog(status); }
			}, [ status.enrolled ? _('Enroll again') : _('Enroll') ]) ])
		]);

		return m.render().then(function(node) {
			return E('div', {}, [ node, enrollment, self.renderSubnets(status, lans) ]);
		});
	}
});
