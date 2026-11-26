// Renders the web plugin's views with data that carries HTML in every field
// that comes from outside the view (UCI values, the program's status
// snapshot, the router's interfaces) and fails when any of it reaches
// innerHTML instead of a text node (.github/workflows/openwrt.yml).
//
//   node render-test.js VIEW_DIR
//
// E() follows LuCI's dom.append(): array items become child nodes or text
// nodes; a lone non-node child is assigned to innerHTML.

'use strict';

const fs = require('fs');
const path = require('path');

const MARK = '<img src=x onerror=alert(1)>';
const failures = [];
let texts = [];

class Node {
	constructor(tag, attrs) {
		this.tag = tag;
		this.attrs = attrs || {};
		this.children = [];
		this.value = this.attrs.value || '';
		this.checked = false;
	}
	appendChild(child) {
		this.children.push(child);
		return child;
	}
	set innerHTML(html) {
		if (String(html).indexOf('<') >= 0)
			failures.push(`innerHTML of <${this.tag}> set to markup: ${html}`);
		this.children = [ new Text(String(html)) ];
	}
	setAttribute(name, value) {
		this.attrs[name] = value;
	}
}

class Text {
	constructor(text) {
		this.text = text;
		texts.push(text);
	}
}

function isNode(value) {
	return value instanceof Node || value instanceof Text;
}

function append(node, children) {
	if (Array.isArray(children)) {
		for (const child of children) {
			if (isNode(child))
				node.appendChild(child);
			else if (child !== null && child !== undefined)
				node.appendChild(new Text(String(child)));
		}
	}
	else if (isNode(children)) {
		node.appendChild(children);
	}
	else if (children !== null && children !== undefined) {
		node.innerHTML = '' + children;
	}
}

function E(tag, attrs, children) {
	const node = new Node(tag, attrs);
	append(node, children);
	return node;
}

// eslint-disable-next-line no-extend-native
String.prototype.format = function(...args) {
	let i = 0;
	return this.replace(/%s/g, () => String(args[i++]));
};

function stubs(replies) {
	return {
		view: { extend: (proto) => proto },
		rpc: {
			declare: (spec) => () => Promise.resolve(replies[spec.method])
		},
		poll: { add: () => {} },
		dom: { content: (node, children) => { node.children = []; append(node, children); } },
		ui: {
			showModal: () => {},
			hideModal: () => {},
			addNotification: () => {},
			createHandlerFn: (ctx, fn) => fn
		},
		form: {
			Map: class {
				section() {
					return { option: () => ({}) };
				}
				render() {
					return Promise.resolve(new Node('div'));
				}
			},
			NamedSection: class {},
			Flag: class {}
		},
		_: (text) => text
	};
}

function load(file, replies) {
	const s = stubs(replies);
	const source = fs.readFileSync(file, 'utf8');
	const fn = new Function('view', 'rpc', 'poll', 'dom', 'ui', 'form', 'E', '_', 'window', 'location', source);
	return fn(s.view, s.rpc, s.poll, s.dom, s.ui, s.form, E, s._, {}, {});
}

const status = {
	enabled: true,
	control: MARK,
	enrolled: true,
	requested: [ MARK ],
	supported: { device: true, enroll: true, device_status: true, subnet_request: true },
	service: {
		result: 'ok',
		device: {
			control_state: MARK,
			last_config: MARK,
			last_report: '2026-11-26T00:00:00Z',
			advertise: [ MARK ]
		},
		mesh: {
			networks: [ {
				tag: MARK,
				running: true,
				address: MARK,
				forward_secrecy: true,
				failure: { code: MARK },
				rejected_advertisements: 1,
				overlaps: [ MARK, { cidr: MARK } ],
				alerts: [ { code: MARK, address: MARK }, { code: 'start_refused' } ],
				peers: [ {
					address: MARK,
					subnets: [ MARK ],
					via: MARK,
					hops: MARK,
					latency_ms: 3,
					forward_secrecy: false
				} ]
			} ]
		}
	}
};
const lans = [ { interface: MARK, cidr: MARK } ];

function walk(node, visit) {
	visit(node);
	for (const child of node.children || [])
		walk(child, visit);
}

function check(name, root) {
	let seen = 0;
	walk(root, (node) => {
		if (node instanceof Text && node.text.indexOf(MARK) >= 0)
			seen++;
	});
	// The marked values must be on the page, as text.
	if (seen === 0)
		failures.push(`${name}: no marked value rendered as text`);
	console.log(`${name}: ${seen} marked value(s) rendered as text`);
}

async function main() {
	const dir = process.argv[2];
	const statusView = load(path.join(dir, 'status.js'), { status });
	check('status', statusView.render(status));

	const settingsView = load(path.join(dir, 'settings.js'), { status, lan_networks: lans });
	check('settings', await settingsView.render([ status, lans ]));

	for (const failure of failures)
		console.log(`::error::${failure}`);
	process.exit(failures.length ? 1 : 0);
}

main().catch((error) => {
	console.log(`::error::${error.stack}`);
	process.exit(1);
});
