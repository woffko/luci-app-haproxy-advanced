// SPDX-License-Identifier: MIT
// Builds the validated model of /etc/config/haproxy-advanced.
//
// Two kinds of problems are reported (decision D3 of goal A):
//  - errors: the configuration itself is wrong. Nothing is applied and the running
//    HAProxy keeps its last good configuration;
//  - skipped parts: a runtime condition (an interface without an address, a
//    certificate not issued yet, a port held by another program) affects one
//    listener or service. Only that part is left out; it comes back on the
//    matching trigger.

'use strict';

import * as u from './util.uc';

const LEGACY_TYPES = [ 'frontend', 'bind', 'acl', 'action', 'userlist' ];

function new_report() {
	return { errors: [], warnings: [], skipped: [] };
}

function err(rep, where, msg) {
	push(rep.errors, { where, message: msg });
}

function warn(rep, where, msg) {
	push(rep.warnings, { where, message: msg });
}

function skip(rep, where, msg) {
	push(rep.skipped, { where, message: msg });
}

function file_exists(env, path) {
	if (type(env.file_exists) == 'function')
		return env.file_exists(path);

	return path in (env.files ?? []);
}

// Validate a time option; returns the value, the default, or null on error.
function time_opt(rep, where, s, name, def) {
	let v = u.opt(s, name, null);

	if (v == null)
		return def;

	if (!u.is_time(v)) {
		err(rep, where, `${name}: '${v}' is not a time (examples: 500ms, 10s, 5m, 1h)`);
		return def;
	}

	return v;
}

function uint_opt(rep, where, s, name, def, max) {
	let v = u.opt(s, name, null);

	if (v == null)
		return def;

	if (!u.is_uint(v, max)) {
		err(rep, where, `${name}: '${v}' is not a whole number${max != null ? ` up to ${max}` : ''}`);
		return def;
	}

	return +v;
}

function enum_opt(rep, where, s, name, def, values) {
	let v = u.opt(s, name, null);

	if (v == null)
		return def;

	if (!(v in values)) {
		err(rep, where, `${name}: '${v}' is not one of ${join(', ', values)}`);
		return def;
	}

	return v;
}

function bool_opt(rep, where, s, name, def) {
	let v = u.opt(s, name, null);

	if (!u.is_bool_text(v))
		err(rep, where, `${name}: '${v}' is not 0 or 1`);

	return u.bool(s, name, def);
}

function advanced_opt(rep, where, s, kind) {
	let lines = u.text_lines(s?.advanced);

	for (let line in lines) {
		let problem = u.check_advanced_line(line, kind);

		if (problem)
			err(rep, where, `advanced line '${line}': ${problem}`);
	}

	return lines;
}

function networks(rep, where, s, name) {
	let out = [];

	for (let n in u.list(s, name)) {
		if (u.is_network(n))
			push(out, n);
		else
			err(rep, where, `${name}: '${n}' is not an IPv4 or IPv6 address or network`);
	}

	return out;
}

function path_prefixes(rep, where, s, name) {
	let out = [];

	for (let p in u.list(s, name)) {
		if (u.is_path_prefix(p))
			push(out, p);
		else if (substr(p, 0, 1) != '/')
			err(rep, where, `${name}: '${p}' must start with /`);
		else if (u.is_ambiguous_path(p))
			err(rep, where, `${name}: '${p}' contains //, /./ or /../`);
		else
			err(rep, where, `${name}: '${p}' contains characters that are not allowed (write the decoded path; no spaces, %, quotes, $, # or \\)`);
	}

	return out;
}

function parse_global(rep, sections) {
	let g = null;

	for (let s in sections) {
		if (s['.type'] == 'global') {
			g = s;
			break;
		}
	}

	let w = 'global';

	return {
		enabled: bool_opt(rep, w, g, 'enabled', false),
		maxconn: uint_opt(rep, w, g, 'maxconn', 2000, 1000000),
		log_level: enum_opt(rep, w, g, 'log_level', 'info', u.LOG_LEVELS),
		log_requests: enum_opt(rep, w, g, 'log_requests', 'errors', [ 'all', 'errors', 'none' ]),
		hardening: bool_opt(rep, w, g, 'hardening', true),
		timeout_connect: time_opt(rep, w, g, 'timeout_connect', '5s'),
		timeout_client: time_opt(rep, w, g, 'timeout_client', '60s'),
		timeout_server: time_opt(rep, w, g, 'timeout_server', '60s'),
		timeout_http_request: time_opt(rep, w, g, 'timeout_http_request', '10s'),
		timeout_http_keep_alive: time_opt(rep, w, g, 'timeout_http_keep_alive', '10s'),
		acme_port: (() => {
			let v = u.opt(g, 'acme_challenge_port', '18402');

			if (!u.is_port(v)) {
				err(rep, w, `acme_challenge_port: '${v}' is not a port`);
				return 18402;
			}

			return +v;
		})(),
		advanced: advanced_opt(rep, w, g, 'global')
	};
}

function parse_listener(rep, s) {
	let w = `listener ${s['.name']}`;
	let l = {
		name: s['.name'],
		enabled: bool_opt(rep, w, s, 'enabled', true),
		family: enum_opt(rep, w, s, 'family', 'ipv4', [ 'ipv4', 'ipv6', 'any' ]),
		bind_mode: enum_opt(rep, w, s, 'bind_mode', 'address', [ 'address', 'device' ]),
		tls: bool_opt(rep, w, s, 'tls', true),
		http2: bool_opt(rep, w, s, 'http2', true),
		firewall: bool_opt(rep, w, s, 'firewall', false),
		zone: u.opt(s, 'firewall_zone', 'wan'),
		timeout_client: time_opt(rep, w, s, 'timeout_client', null),
		advanced: advanced_opt(rep, w, s, 'listener'),
		tokens: [],
		port: null,
		redirect_port: null,
		default_cert: null
	};

	if (!u.is_name(l.name))
		err(rep, w, 'the section name must be 1-48 letters, digits or _');

	let port = u.opt(s, 'port', null);

	if (port == null)
		err(rep, w, 'port is required');
	else if (!u.is_port(port))
		err(rep, w, `port: '${port}' is not a port`);
	else
		l.port = +port;

	let rport = u.opt(s, 'redirect_port', null);

	if (rport != null) {
		if (!u.is_port(rport))
			err(rep, w, `redirect_port: '${rport}' is not a port`);
		else if (!l.tls)
			err(rep, w, 'redirect_port needs a TLS listener');
		else if (+rport == l.port)
			err(rep, w, 'redirect_port must differ from port');
		else
			l.redirect_port = +rport;
	}

	if (!u.is_zone(l.zone))
		err(rep, w, `firewall_zone: '${l.zone}' is not a zone name`);

	let dc = u.opt(s, 'default_certificate', null);

	if (dc != null) {
		if (!u.is_file_path(dc))
			err(rep, w, `default_certificate: '${dc}' is not an absolute path of plain characters`);
		else
			l.default_cert = dc;
	}

	let addrs = u.list(s, 'address');

	if (!length(addrs))
		addrs = [ '*' ];

	for (let a in addrs) {
		if (a == '*')
			push(l.tokens, { kind: 'any' });
		else if (u.is_ipv4(a))
			push(l.tokens, { kind: 'ip', addr: a, family: 'ipv4' });
		else if (u.is_ipv6(a))
			push(l.tokens, { kind: 'ip', addr: a, family: 'ipv6' });
		else if (u.is_iface(a))
			push(l.tokens, { kind: 'iface', iface: a });
		else
			err(rep, w, `address: '${a}' is not an interface name, an IP address or *`);
	}

	if (l.bind_mode == 'device') {
		for (let t in l.tokens)
			if (t.kind != 'iface') {
				err(rep, w, 'bind_mode device needs interface names in address');
				break;
			}
	}

	return l;
}

function parse_backend(rep, s) {
	let w = `backend ${s['.name']}`;
	let b = {
		name: s['.name'],
		balance: enum_opt(rep, w, s, 'balance', 'roundrobin', [ 'roundrobin', 'leastconn', 'source', 'first' ]),
		health_check: enum_opt(rep, w, s, 'health_check', 'none', [ 'none', 'tcp', 'http' ]),
		check_method: enum_opt(rep, w, s, 'check_method', 'GET', [ 'GET', 'HEAD', 'OPTIONS' ]),
		check_path: u.opt(s, 'check_path', '/'),
		check_host: u.opt(s, 'check_host', null),
		check_status: null,
		check_interval: time_opt(rep, w, s, 'check_interval', '10s'),
		timeout_connect: time_opt(rep, w, s, 'timeout_connect', null),
		timeout_server: time_opt(rep, w, s, 'timeout_server', null),
		timeout_tunnel: time_opt(rep, w, s, 'timeout_tunnel', null),
		advanced: advanced_opt(rep, w, s, 'backend'),
		servers: [],
		mode: null,
		used_by: []
	};

	if (!u.is_name(b.name))
		err(rep, w, 'the section name must be 1-48 letters, digits or _');

	if (!u.is_check_uri(b.check_path))
		err(rep, w, `check_path: '${b.check_path}' is not a path`);

	if (b.check_host != null) {
		b.check_host = lc(b.check_host);

		if (!u.is_hostname(b.check_host))
			err(rep, w, `check_host: '${b.check_host}' is not a host name`);
	}

	let statuses = u.list(s, 'check_status');

	b.check_status = u.check_status_regex(length(statuses) ? statuses : [ '2xx', '3xx' ]);

	if (!b.check_status)
		err(rep, w, `check_status: use codes like 200 or classes like 2xx`);

	return b;
}

function parse_server(rep, s, idx) {
	let name = u.opt(s, 'name', null);
	let w = `server ${name ?? ('#' + idx)} of backend ${u.opt(s, 'backend', '?')}`;
	let v = {
		backend: u.opt(s, 'backend', null),
		name: name,
		enabled: bool_opt(rep, w, s, 'enabled', true),
		address: u.opt(s, 'address', null),
		port: null,
		tls: bool_opt(rep, w, s, 'tls', false),
		verify: enum_opt(rep, w, s, 'verify', 'none', [ 'none', 'required' ]),
		ca_file: u.opt(s, 'ca_file', null),
		sni: u.opt(s, 'sni', null),
		verifyhost: u.opt(s, 'verifyhost', null),
		weight: uint_opt(rep, w, s, 'weight', null, 256),
		backup: bool_opt(rep, w, s, 'backup', false),
		maxconn: uint_opt(rep, w, s, 'maxconn', null, 1000000),
		send_proxy: bool_opt(rep, w, s, 'send_proxy', false),
		where: w
	};

	if (!v.enabled)
		return v;

	if (v.backend == null)
		err(rep, w, 'backend is required');

	if (!u.is_server_name(v.name))
		err(rep, w, 'name is required: 1-48 letters, digits, ., _ or -');

	if (v.address == null)
		err(rep, w, 'address is required');
	else if (!u.is_server_address(v.address))
		err(rep, w, `address: '${v.address}' is not an IP address or host name`);
	else if (!u.is_ipv6(v.address) && !u.is_ipv4(v.address))
		v.address = lc(v.address);

	let port = u.opt(s, 'port', null);

	if (port == null)
		err(rep, w, 'port is required');
	else if (!u.is_port(port))
		err(rep, w, `port: '${port}' is not a port`);
	else
		v.port = +port;

	if (v.ca_file != null && !u.is_ca_file(v.ca_file))
		err(rep, w, `ca_file: '${v.ca_file}' is not a path or @system-ca`);

	if (v.tls && v.verify == 'required' && v.ca_file == null)
		err(rep, w, 'verify required needs ca_file (a CA file, or @system-ca for public certificates)');

	if (v.sni != null && v.sni != 'host') {
		v.sni = lc(v.sni);

		if (!u.is_hostname(v.sni))
			err(rep, w, `sni: '${v.sni}' is not a host name or 'host'`);
	}

	if (v.verifyhost != null) {
		v.verifyhost = lc(v.verifyhost);

		if (!u.is_hostname(v.verifyhost))
			err(rep, w, `verifyhost: '${v.verifyhost}' is not a host name`);
	}

	return v;
}

function parse_rule(rep, s, idx) {
	let w = `rule #${idx} of service ${u.opt(s, 'service', '?')}`;
	let r = {
		service: u.opt(s, 'service', null),
		enabled: bool_opt(rep, w, s, 'enabled', true),
		order: uint_opt(rep, w, s, 'order', 100, 1000000),
		index: idx,
		action: enum_opt(rep, w, s, 'action', null, [ 'allow', 'deny', 'auth' ]),
		source: networks(rep, w, s, 'source'),
		path: path_prefixes(rep, w, s, 'path'),
		method: [],
		deny_status: enum_opt(rep, w, s, 'deny_status', '403', u.DENY_STATUSES),
		auth_group: u.opt(s, 'auth_group', null),
		where: w
	};

	if (!r.enabled)
		return r;

	if (r.service == null)
		err(rep, w, 'service is required');

	if (r.action == null)
		err(rep, w, 'action is required (allow, deny or auth)');

	for (let m in u.list(s, 'method')) {
		m = uc(m);

		if (m in u.HTTP_METHODS)
			push(r.method, m);
		else
			err(rep, w, `method: '${m}' is not a known HTTP method`);
	}

	if (!length(r.source) && !length(r.path) && !length(r.method) && r.action != 'auth')
		warn(rep, w, 'the rule has no criteria and matches every request');

	return r;
}

function parse_service(rep, s, g) {
	let w = `service ${s['.name']}`;
	let v = {
		name: s['.name'],
		enabled: bool_opt(rep, w, s, 'enabled', true),
		listener: u.opt(s, 'listener', null),
		hostnames: [],
		mode: enum_opt(rep, w, s, 'mode', 'http', [ 'http', 'passthrough' ]),
		backend: u.opt(s, 'backend', null),
		certificate: u.opt(s, 'certificate', null),
		acme_cert: u.opt(s, 'acme_cert', null),
		trusted: [],
		blocked: [],
		internal: [],
		public: [],
		auth_group: u.opt(s, 'auth_group', null),
		rate_limit: 0,
		auth_fail_limit: 10,
		conn_rate_limit: 0,
		hardening: g.hardening,
		hardening_set: false,
		forward_headers: true,
		hsts: false,
		hsts_max_age: 31536000,
		hsts_subdomains: false,
		timeout_client: null,
		headers: [],
		advanced: [],
		rules: [],
		cert_path: null,
		where: w
	};

	if (!v.enabled)
		return v;

	if (!u.is_name(v.name))
		err(rep, w, 'the section name must be 1-48 letters, digits or _');

	if (v.listener == null)
		err(rep, w, 'listener is required');

	if (v.backend == null)
		err(rep, w, 'backend is required');

	for (let h in u.list(s, 'hostname')) {
		let lh = lc(h);

		if (u.is_hostname(lh))
			push(v.hostnames, lh);
		else
			err(rep, w, `hostname: '${h}' is not a host name (wildcards are not supported)`);
	}

	v.hostnames = u.uniq(v.hostnames);

	if (!length(v.hostnames))
		err(rep, w, 'at least one hostname is required');

	v.trusted = networks(rep, w, s, 'trusted_network');
	v.blocked = path_prefixes(rep, w, s, 'blocked_path');
	v.internal = path_prefixes(rep, w, s, 'internal_path');
	v.public = path_prefixes(rep, w, s, 'public_path');
	v.rate_limit = uint_opt(rep, w, s, 'rate_limit', 0, 1000000);
	v.auth_fail_limit = uint_opt(rep, w, s, 'auth_fail_limit', 10, 100000);
	v.conn_rate_limit = uint_opt(rep, w, s, 'conn_rate_limit', 0, 1000000);
	v.forward_headers = bool_opt(rep, w, s, 'forward_headers', true);
	v.hsts = bool_opt(rep, w, s, 'hsts', false);
	v.hsts_max_age = uint_opt(rep, w, s, 'hsts_max_age', 31536000, 1000000000);
	v.hsts_subdomains = bool_opt(rep, w, s, 'hsts_subdomains', false);
	v.timeout_client = time_opt(rep, w, s, 'timeout_client', null);
	v.advanced = advanced_opt(rep, w, s, 'service');

	let hv = u.opt(s, 'hardening', null);

	if (hv != null) {
		if (!u.is_bool_text(hv))
			err(rep, w, `hardening: '${hv}' is not empty, 0 or 1`);

		v.hardening = u.bool(s, 'hardening', g.hardening);
		v.hardening_set = true;
	}

	for (let h in u.list(s, 'request_header')) {
		let ph = u.parse_header(h);

		if (ph)
			push(v.headers, ph);
		else
			err(rep, w, `request_header: '${h}' must be 'Name: value' with a plain value (no quotes, \\, $ or %)`);
	}

	if (v.certificate != null && !u.is_file_path(v.certificate))
		err(rep, w, `certificate: '${v.certificate}' is not an absolute path of plain characters`);

	if (v.acme_cert != null && !u.is_name(v.acme_cert))
		err(rep, w, `acme_cert: '${v.acme_cert}' is not a section name`);

	if (v.auth_group != null && !u.is_name(v.auth_group))
		err(rep, w, `auth_group: '${v.auth_group}' is not a section name`);

	return v;
}

// Address keys used to detect two listeners that would share an address and port.
function listener_keys(l) {
	let keys = [];
	let fams = (l.family == 'any') ? [ 'ipv4', 'ipv6' ] : [ l.family ];

	if (l.bind_mode == 'device') {
		for (let t in l.tokens)
			push(keys, { any: true, family: 'ipv4' }, { any: true, family: 'ipv6' });

		return keys;
	}

	for (let t in l.tokens) {
		if (t.kind == 'any')
			for (let f in fams)
				push(keys, { any: true, family: f });
		else if (t.kind == 'ip')
			push(keys, { key: 'ip:' + t.addr, family: t.family });
		else
			for (let f in fams)
				push(keys, { key: `if:${t.iface}:${f}`, family: f });
	}

	return keys;
}

function keys_overlap(ka, kb) {
	for (let a in ka) {
		for (let b in kb) {
			if (a.family != b.family)
				continue;

			if (a.any || b.any || a.key == b.key)
				return true;
		}
	}

	return false;
}

function listener_ports(l) {
	let p = [];

	if (l.port != null)
		push(p, l.port);

	if (l.redirect_port != null)
		push(p, l.redirect_port);

	return p;
}

// Resolve a listener's addresses against the current interface state.
function resolve_binds(rep, env, l) {
	let w = `listener ${l.name}`;
	let binds = [];
	let fams = (l.family == 'any') ? [ 'ipv4', 'ipv6' ] : [ l.family ];

	for (let t in l.tokens) {
		if (t.kind == 'any') {
			if (l.family == 'any')
				push(binds, { addr: '::', family: 'any' });
			else
				push(binds, { addr: (l.family == 'ipv4') ? '0.0.0.0' : '::', family: l.family });

			continue;
		}

		if (t.kind == 'ip') {
			push(binds, { addr: t.addr, family: t.family });
			continue;
		}

		let st = env.interfaces?.[t.iface];

		if (!st) {
			err(rep, w, `interface '${t.iface}' does not exist in /etc/config/network`);
			continue;
		}

		if (l.bind_mode == 'device') {
			if (!st.up || !st.device) {
				skip(rep, w, `interface '${t.iface}' is down; its device is left out until it comes up`);
				continue;
			}

			if (!u.is_iface(st.device) && !match(st.device, /^[A-Za-z0-9_.@-]{1,15}$/)) {
				err(rep, w, `interface '${t.iface}' has a device name that cannot be used: '${st.device}'`);
				continue;
			}

			push(binds, { addr: '::', family: 'any', device: st.device });
			continue;
		}

		let found = 0;

		for (let f in fams) {
			for (let a in (st[f] ?? [])) {
				if ((f == 'ipv4') ? u.is_ipv4(a) : u.is_ipv6(a)) {
					push(binds, { addr: a, family: f, iface: t.iface });
					found++;
				}
			}
		}

		if (!found)
			skip(rep, w, `interface '${t.iface}' has no ${join(' or ', fams)} address now; it is left out until it gets one`);
	}

	// Remove duplicates (an interface and a literal can name the same address).
	let seen = {}, out = [];

	for (let b in binds) {
		let k = `${b.addr}|${b.device ?? ''}`;

		if (seen[k]) {
			if (b.device == null && seen[k] != b.iface)
				warn(rep, w, `address ${b.addr} appears twice; it is bound once`);

			continue;
		}

		seen[k] = b.iface ?? true;
		push(out, b);
	}

	return out;
}

function addr_overlap(a, b) {
	let any = (x) => x == '0.0.0.0' || x == '::';

	if (a.device || b.device)
		return true;

	if (a.addr == b.addr)
		return true;

	let fa = u.is_ipv4(a.addr) ? 'ipv4' : 'ipv6';
	let fb = u.is_ipv4(b.addr) ? 'ipv4' : 'ipv6';

	// '::' listening sockets usually accept IPv4 too (v4v6).
	if (any(a.addr) && (fa == fb || a.addr == '::'))
		return true;

	if (any(b.addr) && (fa == fb || b.addr == '::'))
		return true;

	return false;
}

// A program other than this service listening where a listener would bind.
function foreign_owner(env, l, binds) {
	for (let p in listener_ports(l)) {
		for (let s in (env.listening ?? [])) {
			if (s.port != p)
				continue;

			for (let b in binds)
				if (addr_overlap(b, { addr: s.address }))
					return { port: p, address: s.address, owner: s.owner ?? 'another program' };
		}
	}

	return null;
}

export function build(sections, env) {
	let rep = new_report();
	let by_type = {};

	env ??= {};

	for (let i, s in sections) {
		let t = s['.type'];

		by_type[t] ??= [];
		push(by_type[t], s);
	}

	for (let t in LEGACY_TYPES) {
		if (length(by_type[t] ?? [])) {
			err(rep, 'configuration', `this is a version 0.1 configuration (it has '${t}' sections). ` +
				'Version 0.2 uses a new format and does not convert it: move the old file to ' +
				'/etc/config/haproxy-advanced.v01 (the GUI offers this) and set the services up again.');
			return { model: null, report: rep };
		}
	}

	let g = parse_global(rep, sections);
	let m = {
		global: g,
		listeners: [],
		services: [],
		backends: [],
		groups: {},
		firewall: [],
		interfaces: [],
		acme_used: false
	};

	// Auth groups and users.
	for (let s in (by_type.auth_group ?? [])) {
		let w = `auth_group ${s['.name']}`;
		let realm = u.opt(s, 'realm', 'Restricted');

		if (!u.is_name(s['.name']))
			err(rep, w, 'the section name must be 1-48 letters, digits or _');

		if (!u.is_quoted_text(realm, 64) || realm == '')
			err(rep, w, `realm: '${realm}' may only use letters, digits, spaces and . _ , ; : = + * @ ! ? ( ) / -`);

		m.groups[s['.name']] = { name: s['.name'], realm, users: [], used: false };
	}

	for (let i, s in (by_type.user ?? [])) {
		let grp = u.opt(s, 'group', null);
		let name = u.opt(s, 'username', null);
		let hash = u.opt(s, 'password_hash', null);
		let w = `user ${name ?? ('#' + (i + 1))}`;

		if (!u.bool(s, 'enabled', true))
			continue;

		if (grp == null || !m.groups[grp]) {
			err(rep, w, `group '${grp ?? ''}' does not exist`);
			continue;
		}

		if (!u.is_username(name)) {
			err(rep, w, 'username must be 1-64 letters, digits, ., _, @ or -');
			continue;
		}

		if (!u.is_password_hash(hash)) {
			err(rep, w, 'password_hash is not a crypt hash ($6$, $5$, $1$ or $2y$); make one with the GUI');
			continue;
		}

		for (let o in m.groups[grp].users)
			if (o.name == name)
				err(rep, w, `user '${name}' appears twice in group '${grp}'`);

		push(m.groups[grp].users, { name, hash });
	}

	// Backends and servers.
	let backends = {};

	for (let s in (by_type.backend ?? []))
		backends[s['.name']] = parse_backend(rep, s);

	for (let i, s in (by_type.server ?? [])) {
		let v = parse_server(rep, s, i + 1);

		if (!v.enabled)
			continue;

		if (v.backend != null && !backends[v.backend]) {
			err(rep, v.where, `backend '${v.backend}' does not exist`);
			continue;
		}

		if (v.backend == null)
			continue;

		for (let o in backends[v.backend].servers)
			if (o.name == v.name)
				err(rep, v.where, `server name '${v.name}' appears twice in backend '${v.backend}'`);

		push(backends[v.backend].servers, v);
	}

	// Listeners.
	let listeners = {};

	for (let s in (by_type.listener ?? [])) {
		let l = parse_listener(rep, s);

		l.services = [];
		listeners[l.name] = l;
	}

	// Services and their rules.
	let services = {};

	for (let s in (by_type.service ?? []))
		services[s['.name']] = parse_service(rep, s, g);

	for (let i, s in (by_type.rule ?? [])) {
		let r = parse_rule(rep, s, i + 1);

		if (!r.enabled || r.service == null)
			continue;

		let svc = services[r.service];

		if (!svc) {
			err(rep, r.where, `service '${r.service}' does not exist`);
			continue;
		}

		if (!svc.enabled)
			continue;

		if (r.action == 'auth') {
			r.auth_group ??= svc.auth_group;

			if (r.auth_group == null)
				err(rep, r.where, 'an auth rule needs auth_group, here or on its service');
			else if (!m.groups[r.auth_group])
				err(rep, r.where, `auth_group '${r.auth_group}' does not exist`);
			else
				m.groups[r.auth_group].used = true;
		}

		push(svc.rules, r);
	}

	// Attach services to listeners and check references.
	for (let name, svc in services) {
		if (!svc.enabled)
			continue;

		let l = listeners[svc.listener];

		if (svc.listener != null && !l) {
			err(rep, svc.where, `listener '${svc.listener}' does not exist`);
			continue;
		}

		if (!l)
			continue;

		if (!l.enabled) {
			warn(rep, svc.where, `listener '${l.name}' is disabled, so this service is not published`);
			continue;
		}

		let b = backends[svc.backend];

		if (svc.backend != null && !b) {
			err(rep, svc.where, `backend '${svc.backend}' does not exist`);
			continue;
		}

		if (svc.auth_group != null) {
			if (!m.groups[svc.auth_group])
				err(rep, svc.where, `auth_group '${svc.auth_group}' does not exist`);
			else
				m.groups[svc.auth_group].used = true;
		}

		if (svc.mode == 'passthrough') {
			if (!l.tls)
				err(rep, svc.where, `passthrough needs a TLS listener; '${l.name}' has tls off`);

			let ignored = [];

			if (svc.certificate != null || svc.acme_cert != null) push(ignored, 'certificate');
			if (length(svc.blocked) || length(svc.internal) || length(svc.public)) push(ignored, 'path lists');
			if (svc.auth_group != null) push(ignored, 'auth_group');
			if (svc.hsts) push(ignored, 'hsts');
			if (length(svc.headers)) push(ignored, 'request_header');
			if (length(svc.rules)) push(ignored, 'rules');
			if (length(svc.advanced)) push(ignored, 'advanced');
			if (svc.rate_limit) push(ignored, 'rate_limit (use conn_rate_limit)');

			if (length(ignored))
				warn(rep, svc.where, `passthrough services do not use: ${join(', ', ignored)}`);
		}
		else if (!l.tls) {
			if (svc.certificate != null || svc.acme_cert != null)
				warn(rep, svc.where, `listener '${l.name}' has no TLS, so the certificate is not used`);

			if (svc.hsts)
				warn(rep, svc.where, 'HSTS needs a TLS listener and is not sent');
		}

		if (b) {
			let want = (svc.mode == 'passthrough') ? 'tcp' : 'http';

			if (b.mode != null && b.mode != want)
				err(rep, svc.where, `backend '${b.name}' is used by both HTTP and passthrough services; give each kind its own backend`);
			else
				b.mode = want;

			push(b.used_by, svc.name);
		}

		push(l.services, svc);
	}

	// Host names are unique per listener.
	for (let ln, l in listeners) {
		let owner = {};

		for (let svc in l.services) {
			for (let h in svc.hostnames) {
				if (owner[h])
					err(rep, svc.where, `hostname '${h}' is also used by service '${owner[h]}' on listener '${ln}'`);
				else
					owner[h] = svc.name;
			}
		}
	}

	// Interfaces whose changes need a reload (also for listeners skipped now).
	for (let ln, l in listeners) {
		if (!l.enabled)
			continue;

		for (let t in l.tokens)
			if (t.kind == 'iface')
				push(m.interfaces, t.iface);
	}

	m.interfaces = u.uniq(m.interfaces);

	// Two listeners must not share an address and port.
	let active = filter(values(listeners), (l) => l.enabled && length(l.services) > 0);

	for (let i = 0; i < length(active); i++) {
		for (let j = i + 1; j < length(active); j++) {
			let a = active[i], b = active[j];
			let common = filter(listener_ports(a), (p) => p in listener_ports(b));

			if (length(common) && keys_overlap(listener_keys(a), listener_keys(b)))
				err(rep, `listener ${b.name}`, `shares port ${common[0]} and an address with listener '${a.name}'; ` +
					'publish both services on one listener instead (services are routed by host name)');
		}
	}

	for (let ln, l in listeners)
		if (l.enabled && !length(l.services))
			warn(rep, `listener ${ln}`, 'no enabled service uses this listener, so it is not started');

	// Certificates of HTTP services on TLS listeners.
	for (let l in active) {
		if (!l.tls)
			continue;

		for (let svc in l.services) {
			if (svc.mode != 'http')
				continue;

			if (svc.acme_cert != null) {
				let c = env.acme_certs?.[svc.acme_cert];

				if (!c) {
					err(rep, svc.where, `acme_cert '${svc.acme_cert}' is not a cert section of /etc/config/acme`);
					continue;
				}

				let d = c.domains?.[0];

				if (!d || !u.is_hostname(lc(d))) {
					err(rep, svc.where, `ACME certificate '${svc.acme_cert}' has no usable domain`);
					continue;
				}

				svc.cert_path = `/etc/ssl/acme/${lc(d)}.combined.crt`;
				m.acme_used = true;
				l.acme_used = true;
			}
			else if (svc.certificate != null) {
				svc.cert_path = svc.certificate;
			}
			else {
				err(rep, svc.where, `certificate or acme_cert is required on TLS listener '${l.name}'`);
			}
		}
	}

	// Stop here on configuration errors; runtime checks only make sense on a valid
	// configuration.
	if (length(rep.errors))
		return { model: m, report: rep };

	// Resolve addresses and apply runtime conditions.
	for (let l in active) {
		let w = `listener ${l.name}`;

		l.binds = resolve_binds(rep, env, l);

		if (length(rep.errors))
			break;

		if (!length(l.binds)) {
			skip(rep, w, 'no address is available now, so the listener and its services are left out');
			continue;
		}

		let foreign = foreign_owner(env, l, l.binds);

		if (foreign) {
			skip(rep, w, `port ${foreign.port} on ${foreign.address} is already used by ${foreign.owner}; ` +
				'the listener is left out (choose another port or address)');
			continue;
		}

		for (let p in listener_ports(l))
			for (let s in (env.configured_ports ?? []))
				if (s.port == p)
					for (let b in l.binds)
						if (addr_overlap(b, { addr: s.address })) {
							warn(rep, w, `${s.owner} is configured to listen on ${s.address}:${p} too`);
							break;
						}

		// Services whose certificate is missing are left out. The companion keeps
		// redirecting all of them and answering ACME challenges, which is how a
		// missing ACME certificate gets issued.
		let svcs = [];

		l.companion_services = l.services;

		for (let svc in l.services) {
			if (l.tls && svc.mode == 'http' && !file_exists(env, svc.cert_path)) {
				skip(rep, svc.where, `certificate ${svc.cert_path} does not exist yet; the service is left out until it does`);
				continue;
			}

			push(svcs, svc);
		}

		l.services = svcs;
		l.main_active = length(svcs) > 0;

		if (!l.main_active && l.redirect_port == null) {
			skip(rep, w, 'none of its services can run now, so the listener is left out');
			continue;
		}

		if (!l.main_active)
			skip(rep, w, `none of its services can run now; only the HTTP companion on port ${l.redirect_port} runs`);

		l.http_services = filter(svcs, (s) => s.mode == 'http');
		l.pt_services = filter(svcs, (s) => s.mode == 'passthrough');
		l.certs = [];

		if (l.tls && length(l.http_services)) {
			if (l.default_cert != null) {
				if (file_exists(env, l.default_cert))
					push(l.certs, l.default_cert);
				else
					warn(rep, w, `default_certificate ${l.default_cert} does not exist; the first service's certificate is the default`);
			}

			for (let svc in l.http_services)
				push(l.certs, svc.cert_path);

			l.certs = u.uniq(l.certs);
		}

		push(m.listeners, l);

		if (l.firewall) {
			if (l.main_active)
				push(m.firewall, { listener: l.name, zone: l.zone, port: l.port, family: l.family });

			if (l.redirect_port != null)
				push(m.firewall, { listener: l.name, zone: l.zone, port: l.redirect_port, family: l.family });
		}
	}

	// Concrete binds must still be unique across listeners.
	let seen = {};

	for (let l in m.listeners) {
		let ports = l.main_active ? listener_ports(l) : [ l.redirect_port ];

		for (let p in ports) {
			for (let b in l.binds) {
				let k = `${b.addr}|${b.device ?? ''}|${p}`;

				if (seen[k] && seen[k] != l.name)
					err(rep, `listener ${l.name}`, `${b.addr} port ${p} is also used by listener '${seen[k]}'`);

				seen[k] = l.name;
			}
		}
	}

	// Backends in use.
	for (let name, b in backends) {
		if (!length(b.used_by))
			continue;

		let users = filter(b.used_by, (sn) => length(filter(m.listeners, (l) =>
			length(filter(l.services, (s) => s.name == sn)))));

		if (!length(users))
			continue;

		if (!length(b.servers))
			warn(rep, `backend ${name}`, 'has no enabled server; requests get 503');

		if (b.mode == 'tcp') {
			for (let v in b.servers) {
				if (v.tls)
					err(rep, v.where, 'passthrough backends forward TLS as is; turn tls off on their servers');

				if (v.sni == 'host')
					err(rep, v.where, "sni 'host' needs an HTTP backend");
			}

			if (b.health_check == 'http')
				err(rep, `backend ${name}`, 'HTTP health checks need an HTTP backend; use tcp for passthrough');
		}

		push(m.backends, b);
	}

	for (let gn, grp in m.groups) {
		if (grp.used && !length(grp.users))
			warn(rep, `auth_group ${gn}`, 'has no enabled user, so nobody can log in');
	}

	m.services = [];

	for (let l in m.listeners)
		for (let s in l.services)
			push(m.services, s);

	return { model: m, report: rep };
};
