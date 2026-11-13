// SPDX-License-Identifier: MIT
// Renders the validated model (model.uc) as an HAProxy 3.2 configuration.
//
// Every value written here was checked by util.uc's validators, so it can be
// written without quoting unless the line quotes it explicitly.

'use strict';

import * as u from './util.uc';

export const RUN_DIR = '/var/run/haproxy-advanced';

// Ambiguous paths: //, /./, /../, a trailing /. or /.., a backslash (also when
// URL-encoded, because the decoded path is tested) and an encoded NUL.
const AMBIGUOUS_ACL = [
	"acl ha_ambiguous_path path,url_dec -m reg '(^|/)\\.\\.?(/|$)|//|\\\\'",
	'acl ha_ambiguous_path path -m sub -i %00'
];

// Path forms: deny lists compare the decoded, lower-cased path without ';'
// path parameters; allow lists compare the decoded path as is.
const DENY_PATH = 'path,url_dec,lower,regsub(;[^/]*,,g)';
const ALLOW_PATH = 'path,url_dec';

function bind_target(b, port) {
	if (b.device)
		return `:::${port} v4v6 interface ${b.device}`;

	if (b.addr == '::')
		return (b.family == 'any') ? `:::${port} v4v6` : `:::${port} v6only`;

	if (u.is_ipv6(b.addr))
		return `ipv6@${b.addr}:${port}`;

	return `${b.addr}:${port}`;
}

function server_target(v) {
	return u.is_ipv6(v.address) ? `ipv6@${v.address}:${v.port}` : `${v.address}:${v.port}`;
}

function lower_list(items) {
	return map(items, (p) => lc(p));
}

function uses_path_lists(svc) {
	if (length(svc.blocked) || length(svc.internal) || length(svc.public))
		return true;

	for (let r in svc.rules)
		if (length(r.path))
			return true;

	return false;
}

function needs_table(svc) {
	return svc.rate_limit > 0 || (svc.auth_group != null && svc.auth_fail_limit > 0);
}

function rule_criteria(r, deny_form) {
	let c = [];

	if (length(r.source))
		push(c, `{ src ${join(' ', r.source)} }`);

	if (length(r.path)) {
		if (deny_form)
			push(c, `{ ${DENY_PATH} -m beg ${join(' ', lower_list(r.path))} }`);
		else
			push(c, `{ ${ALLOW_PATH} -m beg ${join(' ', r.path)} }`);
	}

	if (length(r.method))
		push(c, `{ method ${join(' ', r.method)} }`);

	return length(c) ? ' ' + join(' ', c) : '';
}

function auth_lines(out, svc, group, cond, realm, count_failures) {
	let v = `txn.ha_auth_${group}`;

	push(out,
		`    http-request set-var(${v}) bool(true) if ${cond} { req.hdr(authorization) -m found } ha_login_${group}`);

	if (count_failures)
		push(out,
			`    http-request sc-inc-gpc(0,0) if ${cond} { req.hdr(authorization) -m found } !{ var(${v}) -m bool }`);

	push(out, `    http-request auth realm "${realm}" if ${cond} !{ var(${v}) -m bool }`);
}

// The ACLs and http-request rules of the HTTP services of one frontend.
function http_service_block(out, m, l, svcs, proto) {
	let g = m.global;
	let any_hsts = false;
	let groups = {};

	for (let line in AMBIGUOUS_ACL)
		push(out, `    ${line}`);

	for (let svc in svcs) {
		let n = svc.name;

		push(out, `    acl host_${n} req.hdr(host),host_only,lower -m str ${join(' ', svc.hostnames)}`);

		if (length(svc.trusted))
			push(out, `    acl trusted_${n} src ${join(' ', svc.trusted)}`);

		if (length(svc.blocked))
			push(out, `    acl blocked_${n} ${DENY_PATH} -m beg ${join(' ', lower_list(svc.blocked))}`);

		if (length(svc.internal))
			push(out, `    acl internal_${n} ${DENY_PATH} -m beg ${join(' ', lower_list(svc.internal))}`);

		if (length(svc.public))
			push(out, `    acl public_${n} ${ALLOW_PATH} -m beg ${join(' ', svc.public)}`);

		if (svc.auth_group != null)
			groups[svc.auth_group] = true;

		for (let r in svc.rules)
			if (r.action == 'auth')
				groups[r.auth_group] = true;

		if (svc.hsts && proto == 'https')
			any_hsts = true;
	}

	for (let grp in sort(keys(groups)))
		push(out, `    acl ha_login_${grp} http_auth(ul_${grp})`);

	push(out, `    http-request deny deny_status 404 if ${join(' ', map(svcs, (s) => '!host_' + s.name))}`);

	if (any_hsts)
		for (let svc in svcs)
			if (svc.hsts)
				push(out, `    http-request set-var(txn.ha_svc) str(${svc.name}) if host_${svc.name}`);

	for (let svc in svcs) {
		let n = svc.name;
		let h = `host_${n}`;

		push(out, `    # service ${n}`);

		if (svc.hardening || uses_path_lists(svc))
			push(out, `    http-request deny deny_status 400 if ${h} ha_ambiguous_path`);

		if (svc.hardening)
			for (let hd in [ 'X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto', 'X-Forwarded-Port', 'X-Real-IP', 'Forwarded' ])
				push(out, `    http-request del-header ${hd} if ${h}`);

		if (svc.forward_headers) {
			push(out, `    http-request ${svc.hardening ? 'set' : 'add'}-header X-Forwarded-For %[src] if ${h}`);
			push(out, `    http-request set-header X-Forwarded-Proto ${proto} if ${h}`);
			push(out, `    http-request set-header X-Forwarded-Port ${l.port} if ${h}`);
		}

		for (let hd in svc.headers)
			push(out, `    http-request set-header ${hd.name} "${hd.value}" if ${h}`);

		if (svc.timeout_client != null)
			push(out, `    http-request set-timeout client ${svc.timeout_client} if ${h}`);

		if (needs_table(svc)) {
			push(out, `    http-request track-sc0 src table st_${n} if ${h}`);

			if (svc.rate_limit > 0)
				push(out, `    http-request deny deny_status 429 if ${h} { sc_http_req_rate(0) gt ${svc.rate_limit} }`);

			if (svc.auth_group != null && svc.auth_fail_limit > 0)
				push(out, `    http-request deny deny_status 429 if ${h} { sc_gpc_rate(0,0) gt ${svc.auth_fail_limit} }`);
		}

		if (length(svc.blocked))
			push(out, `    http-request deny deny_status 403 if ${h} blocked_${n}`);

		for (let r in u.sort_by_order(svc.rules)) {
			if (r.action == 'allow')
				push(out, `    http-request allow if ${h}${rule_criteria(r, false)}`);
			else if (r.action == 'deny')
				push(out, `    http-request deny deny_status ${r.deny_status} if ${h}${rule_criteria(r, true)}`);
			else
				auth_lines(out, svc, r.auth_group, h + rule_criteria(r, true),
					m.groups[r.auth_group].realm, false);
		}

		if (length(svc.trusted))
			push(out, `    http-request allow if ${h} trusted_${n}`);

		if (length(svc.internal))
			push(out, `    http-request deny deny_status 403 if ${h} internal_${n}`);

		if (length(svc.public))
			push(out, `    http-request allow if ${h} public_${n}`);

		if (svc.auth_group != null)
			auth_lines(out, svc, svc.auth_group, h, m.groups[svc.auth_group].realm,
				svc.auth_fail_limit > 0);

		for (let line in svc.advanced)
			push(out, `    ${line} if ${h}`);
	}

	if (any_hsts) {
		for (let svc in svcs) {
			if (!svc.hsts)
				continue;

			let value = `max-age=${svc.hsts_max_age}${svc.hsts_subdomains ? '; includeSubDomains' : ''}`;

			push(out, `    http-response set-header Strict-Transport-Security "${value}" if { var(txn.ha_svc) -m str ${svc.name} }`);
		}
	}

	for (let svc in svcs)
		push(out, `    use_backend be_${svc.backend} if host_${svc.name}`);
}

function tls_bind_options(l) {
	let crts = join(' ', map(l.certs, (c) => `crt ${c}`));

	return ` ssl ${crts} alpn ${l.http2 ? 'h2,http/1.1' : 'http/1.1'}`;
}

function render_listener(out, m, l) {
	let n = l.name;
	let has_http = length(l.http_services ?? []) > 0;
	let has_pt = length(l.pt_services ?? []) > 0;

	if (l.main_active && l.tls && has_pt) {
		// TLS passthrough by SNI. Everything else goes through an internal loop to
		// the HTTPS frontend, with PROXY v2 so it still sees the client's address.
		push(out, '', `frontend fe_${n} from ha_tcp`);

		for (let b in l.binds)
			push(out, `    bind ${bind_target(b, l.port)}`);

		if (l.timeout_client != null)
			push(out, `    timeout client ${l.timeout_client}`);

		push(out, '    tcp-request inspect-delay 5s');

		for (let svc in l.pt_services)
			push(out, `    acl sni_${svc.name} req.ssl_sni,lower -m str ${join(' ', svc.hostnames)}`);

		for (let svc in l.pt_services) {
			let s = `sni_${svc.name}`;

			if (length(svc.trusted))
				push(out, `    tcp-request content reject if ${s} !{ src ${join(' ', svc.trusted)} }`);

			if (svc.conn_rate_limit > 0) {
				push(out, `    tcp-request content track-sc0 src table st_${svc.name} if ${s}`);
				push(out, `    tcp-request content reject if ${s} { sc0_conn_rate gt ${svc.conn_rate_limit} }`);
			}
		}

		if (!has_http)
			push(out, `    tcp-request content reject if ${join(' ', map(l.pt_services, (s) => '!sni_' + s.name))}`);

		push(out, '    tcp-request content accept if { req.ssl_hello_type 1 }');
		push(out, '    tcp-request content reject');

		for (let line in l.advanced)
			push(out, `    ${line}`);

		for (let svc in l.pt_services)
			push(out, `    use_backend be_${svc.backend} if sni_${svc.name}`);

		if (has_http) {
			push(out, `    default_backend be_${n}_loop`);

			let tunnel = '1h';

			push(out, '', `backend be_${n}_loop from ha_tcp`);
			push(out, `    timeout tunnel ${tunnel}`);
			push(out, `    server loop abns@haproxy-advanced-${n} send-proxy-v2`);

			push(out, '', `frontend fe_${n}_https from ha_http`);
			push(out, `    bind abns@haproxy-advanced-${n} accept-proxy${tls_bind_options(l)}`);

			if (l.timeout_client != null)
				push(out, `    timeout client ${l.timeout_client}`);

			http_service_block(out, m, l, l.http_services, 'https');
		}
	}
	else if (l.main_active) {
		push(out, '', `frontend fe_${n} from ha_http`);

		for (let b in l.binds)
			push(out, `    bind ${bind_target(b, l.port)}${l.tls ? tls_bind_options(l) : ''}`);

		if (l.timeout_client != null)
			push(out, `    timeout client ${l.timeout_client}`);

		for (let line in l.advanced)
			push(out, `    ${line}`);

		http_service_block(out, m, l, l.http_services, l.tls ? 'https' : 'http');
	}

	if (l.redirect_port != null) {
		let svcs = l.companion_services;
		let port = (l.port == 443) ? '' : `:${l.port}`;

		push(out, '', `frontend fe_${n}_redirect from ha_http`);

		for (let b in l.binds)
			push(out, `    bind ${bind_target(b, l.redirect_port)}`);

		push(out, '    acl ha_acme_challenge path_beg /.well-known/acme-challenge/');

		for (let svc in svcs)
			push(out, `    acl host_${svc.name} req.hdr(host),host_only,lower -m str ${join(' ', svc.hostnames)}`);

		push(out, `    http-request deny deny_status 404 if !ha_acme_challenge ${join(' ', map(svcs, (s) => '!host_' + s.name))}`);
		push(out, `    http-request redirect location https://%[req.hdr(host),host_only]${port}%[pathq] code 308 if !ha_acme_challenge`);
		push(out, '    use_backend be_ha_acme if ha_acme_challenge');
	}
}

function render_backend(out, m, b) {
	let mode = (b.mode == 'tcp') ? 'ha_tcp' : 'ha_http';

	push(out, '', `backend be_${b.name} from ${mode}`);
	push(out, `    balance ${b.balance}`);

	if (b.health_check == 'http') {
		let host = b.check_host;

		if (host == null) {
			for (let svc in m.services) {
				if (svc.backend == b.name) {
					host = svc.hostnames[0];
					break;
				}
			}
		}

		push(out, '    option httpchk');
		push(out, `    http-check send meth ${b.check_method} uri ${b.check_path} ver HTTP/1.1 hdr Host ${host}`);
		push(out, `    http-check expect rstatus '${b.check_status}'`);
	}

	if (b.health_check != 'none')
		push(out, `    default-server inter ${b.check_interval}`);

	if (b.timeout_connect != null)
		push(out, `    timeout connect ${b.timeout_connect}`);

	if (b.timeout_server != null)
		push(out, `    timeout server ${b.timeout_server}`);

	if (b.timeout_tunnel != null)
		push(out, `    timeout tunnel ${b.timeout_tunnel}`);

	for (let v in b.servers) {
		let line = `    server ${v.name} ${server_target(v)}`;

		if (v.tls) {
			line += ` ssl verify ${v.verify}`;

			if (v.ca_file != null)
				line += ` ca-file ${v.ca_file}`;

			if (v.sni == 'host')
				line += ' sni req.hdr(host),host_only';
			else if (v.sni != null)
				line += ` sni str(${v.sni})`;

			if (v.verifyhost != null)
				line += ` verifyhost ${v.verifyhost}`;
		}

		if (b.health_check != 'none')
			line += ' check';

		if (v.weight != null)
			line += ` weight ${v.weight}`;

		if (v.backup)
			line += ' backup';

		if (v.maxconn != null)
			line += ` maxconn ${v.maxconn}`;

		if (v.send_proxy)
			line += ' send-proxy-v2';

		push(out, line);
	}

	for (let line in b.advanced)
		push(out, `    ${line}`);
}

export function render(m) {
	let g = m.global;
	let out = [
		'# Generated by haproxy-advanced from /etc/config/haproxy-advanced.',
		'# Do not edit: the service rewrites this file.',
		'',
		'global',
		`    log /dev/log local0 ${g.log_level}`,
		'    log-tag haproxy-advanced',
		`    maxconn ${g.maxconn}`,
		'    user nobody',
		'    group nogroup',
		`    stats socket ${RUN_DIR}/admin.sock mode 600 level admin`,
		'    stats timeout 30s',
		'    tune.ssl.default-dh-param 2048',
		'    ssl-default-bind-options ssl-min-ver TLSv1.2'
	];

	for (let line in g.advanced)
		push(out, `    ${line}`);

	let common = [];

	if (g.log_requests == 'none')
		push(common, '    no log');
	else
		push(common, '    log global');

	push(common,
		'    option dontlognull',
		`    timeout connect ${g.timeout_connect}`,
		`    timeout client ${g.timeout_client}`,
		`    timeout server ${g.timeout_server}`,
		'    default-server init-addr last,libc,none');

	push(out, '', 'defaults ha_http', '    mode http', ...common,
		'    option httplog',
		`    timeout http-request ${g.timeout_http_request}`,
		`    timeout http-keep-alive ${g.timeout_http_keep_alive}`);

	if (g.log_requests == 'errors')
		push(out, '    option dontlog-normal', '    option log-separate-errors');

	push(out, '', 'defaults ha_tcp', '    mode tcp', ...common, '    option tcplog');

	if (g.log_requests == 'errors')
		push(out, '    option dontlog-normal');

	for (let l in m.listeners)
		render_listener(out, m, l);

	for (let b in m.backends)
		render_backend(out, m, b);

	if (length(filter(m.listeners, (l) => l.redirect_port != null))) {
		push(out, '', 'backend be_ha_acme from ha_http');
		push(out, `    server acme 127.0.0.1:${g.acme_port}`);
	}

	for (let svc in m.services) {
		if (svc.mode == 'passthrough' && svc.conn_rate_limit > 0) {
			push(out, '', `backend st_${svc.name}`);
			push(out, '    stick-table type ipv6 size 100k expire 10m store conn_rate(10s)');
		}
		else if (svc.mode == 'http' && needs_table(svc)) {
			push(out, '', `backend st_${svc.name}`);
			push(out, '    stick-table type ipv6 size 100k expire 10m store http_req_rate(10s),gpc(1),gpc_rate(1,1m)');
		}
	}

	for (let gn in sort(keys(m.groups))) {
		let grp = m.groups[gn];

		if (!grp.used)
			continue;

		push(out, '', `userlist ul_${gn}`);

		for (let usr in grp.users)
			push(out, `    user ${usr.name} password ${usr.hash}`);
	}

	push(out, '');

	return join('\n', out);
};
