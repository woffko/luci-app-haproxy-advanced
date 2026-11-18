// SPDX-License-Identifier: MIT
// Target-side helpers of haproxy-advanced: reading UCI (optionally with a LuCI
// session's unsaved changes), snapshotting the environment the generator needs,
// running `haproxy -c`, writing the apply result, and talking to HAProxy's
// master and stats sockets.

'use strict';

import * as fs from 'fs';
import * as socket from 'socket';
import { cursor } from 'uci';
import { connect } from 'ubus';
import { generate } from './core.uc';
import { RUN_DIR } from './render.uc';

export const CONFIG = 'haproxy-advanced';
export const CFG_FILE = '/var/etc/haproxy-advanced.cfg';
export const LAST_APPLY = `${RUN_DIR}/last-apply.json`;
export const MASTER_SOCK = `${RUN_DIR}/master.sock`;
export const STATS_SOCK = `${RUN_DIR}/admin.sock`;
export const PID_FILE = `${RUN_DIR}/haproxy.pid`;
export const HAPROXY = '/usr/sbin/haproxy';

// A LuCI session id, as passed in ubus_rpc_session.
export function is_session_id(v) {
	return type(v) == 'string' && !!match(v, /^[0-9a-f]{32}$/);
};

export function session_savedir(sid) {
	return is_session_id(sid) ? `/var/run/rpcd/uci-${sid}` : null;
};

// A configuration UCI cannot parse comes back as one '__uci_error' section,
// which the generator reports as an error instead of an empty configuration.
function sections_of(c, conf) {
	if (!c.load(conf))
		return [ { '.type': '__uci_error', '.name': 'uci_error', '.index': 0,
			message: `${c.error() ?? 'unknown error'} (run 'uci show ${conf}' to see the line)` } ];

	let all = c.get_all(conf) ?? {};
	let list = [];

	for (let name, s in all)
		push(list, s);

	return sort(list, (a, b) => a['.index'] - b['.index']);
}

// The sections of /etc/config/haproxy-advanced; with savedir, including the
// unsaved changes of that LuCI session.
export function load_sections(savedir) {
	let c = savedir ? cursor(null, savedir) : cursor();

	return sections_of(c, CONFIG);
};

// /proc/net/tcp prints each 32-bit word of an address in host byte order.
// Find the byte order from busybox's ELF header (byte 5: 1 little, 2 big).
let little_endian = null;

function is_little_endian() {
	if (little_endian == null) {
		let hdr = fs.readfile('/bin/busybox', 6) ?? fs.readfile('/bin/sh', 6) ?? '';

		little_endian = (ord(hdr, 5) != 2);
	}

	return little_endian;
}

function word_bytes(h) {
	let b = [];

	if (is_little_endian())
		for (let i = 6; i >= 0; i -= 2)
			push(b, hex(substr(h, i, 2)));
	else
		for (let i = 0; i <= 6; i += 2)
			push(b, hex(substr(h, i, 2)));

	return b;
}

function hex_to_ipv4(h) {
	return join('.', word_bytes(h));
}

function hex_to_ipv6(h) {
	let bytes = [];

	for (let w = 0; w < 4; w++)
		push(bytes, ...word_bytes(substr(h, w * 8, 8)));

	return arrtoip(bytes);
}

function our_haproxy_pids() {
	let pids = {};

	for (let p in (fs.lsdir('/proc') ?? [])) {
		if (!match(p, /^[0-9]+$/))
			continue;

		let cmd = fs.readfile(`/proc/${p}/cmdline`);

		if (cmd && index(cmd, CFG_FILE) >= 0)
			pids[p] = true;
	}

	return pids;
}

// Listening TCP sockets not owned by this service's HAProxy.
function foreign_listeners() {
	let socks = {};

	for (let f in [ '/proc/net/tcp', '/proc/net/tcp6' ]) {
		let lines = split(fs.readfile(f) ?? '', '\n');

		for (let i = 1; i < length(lines); i++) {
			let c = split(trim(lines[i]), /[ ]+/);

			if (length(c) < 10 || c[3] != '0A')
				continue;

			let ap = split(c[1], ':');
			let addr = (length(ap[0]) == 8) ? hex_to_ipv4(ap[0]) : hex_to_ipv6(ap[0]);

			socks[c[9]] = { address: addr, port: hex(ap[1]), owner: null };
		}
	}

	let ours = our_haproxy_pids();
	let out = [];

	for (let p in (fs.lsdir('/proc') ?? [])) {
		if (!match(p, /^[0-9]+$/))
			continue;

		for (let fd in (fs.lsdir(`/proc/${p}/fd`) ?? [])) {
			let m = match(fs.readlink(`/proc/${p}/fd/${fd}`) ?? '', /^socket:\[([0-9]+)\]$/);

			if (m && socks[m[1]] && socks[m[1]].owner == null)
				socks[m[1]].owner = ours[p] ? '' : trim(fs.readfile(`/proc/${p}/comm`) ?? 'another program');
		}
	}

	for (let ino, s in socks)
		if (s.owner !== '')
			push(out, { address: s.address, port: s.port, owner: s.owner ?? 'another program' });

	return out;
}

// Ports uhttpd is configured for, also when it is not running.
export function uhttpd_ports() {
	let out = [];
	let c = cursor();

	for (let s in sections_of(c, 'uhttpd')) {
		if (s['.type'] != 'uhttpd')
			continue;

		for (let opt in [ 'listen_http', 'listen_https' ]) {
			let v = s[opt];

			for (let item in (type(v) == 'array' ? v : (v ? [ v ] : []))) {
				let m = match(item, /^(\[([0-9A-Fa-f:.]+)\]|([0-9.]+))?:?([0-9]+)$/);

				if (m)
					push(out, { address: m[2] ?? m[3] ?? '0.0.0.0', port: +m[4], owner: `uhttpd (${s['.name']})` });
			}
		}
	}

	return out;
};

export function interface_state() {
	let bus = connect();
	let dump = bus ? bus.call('network.interface', 'dump', {}) : null;
	let out = {};

	for (let i in (dump?.interface ?? [])) {
		let st = { up: !!i.up, device: i.l3_device ?? i.device ?? null, ipv4: [], ipv6: [] };

		for (let a in (i['ipv4-address'] ?? []))
			push(st.ipv4, a.address);

		for (let a in (i['ipv6-address'] ?? []))
			push(st.ipv6, a.address);

		for (let p in (i['ipv6-prefix-assignment'] ?? []))
			if (p['local-address']?.address)
				push(st.ipv6, p['local-address'].address);

		out[i.interface] = st;
	}

	return out;
};

function acme_certs() {
	let out = {};
	let c = cursor();

	if (!fs.access('/etc/config/acme'))
		return out;

	for (let s in sections_of(c, 'acme')) {
		if (s['.type'] != 'cert')
			continue;

		let d = s.domains;

		out[s['.name']] = {
			domains: (type(d) == 'array') ? d : (d ? split(d, /[ ]+/) : []),
			enabled: s.enabled != '0'
		};
	}

	return out;
}

export function collect_env() {
	return {
		interfaces: interface_state(),
		file_exists: (p) => !!fs.access(p, 'r'),
		acme_certs: acme_certs(),
		listening: foreign_listeners(),
		configured_ports: uhttpd_ports()
	};
};

export function ensure_run_dir() {
	fs.mkdir('/var/etc');
	fs.mkdir(RUN_DIR, 0700);
	fs.chmod(RUN_DIR, 0700);
};

// Run `haproxy -c` on a configuration text. Returns { ok, output }.
export function haproxy_check(text) {
	ensure_run_dir();

	let now = clock();
	let tmp = `${RUN_DIR}/check-${now[0]}-${now[1]}.cfg`;

	if (!fs.writefile(tmp, text))
		return { ok: false, output: `cannot write ${tmp}: ${fs.error()}` };

	fs.chmod(tmp, 0600);

	let p = fs.popen(`${HAPROXY} -c -f '${tmp}' 2>&1`, 'r');
	let output = p ? p.read('all') : `cannot run ${HAPROXY}: ${fs.error()}`;
	let rc = p ? p.close() : -1;

	fs.unlink(tmp);

	return { ok: rc == 0, output: trim(output ?? '') };
};

export function read_json(path) {
	let t = fs.readfile(path);

	if (t == null)
		return null;

	try {
		return json(t);
	}
	catch (e) {
		return null;
	}
};

export function write_json(path, v) {
	let tmp = `${path}.tmp`;

	fs.writefile(tmp, sprintf('%.J\n', v));
	fs.rename(tmp, path);
};

export function write_last_apply(result) {
	ensure_run_dir();
	result.time = time();
	write_json(LAST_APPLY, result);
};

export function update_last_apply(fields) {
	let cur = read_json(LAST_APPLY) ?? {};

	for (let k, v in fields)
		cur[k] = v;

	write_json(LAST_APPLY, cur);
};

// Send one command to a HAProxy CLI socket and return the whole answer, or null.
export function cli(path, command, timeout) {
	let s = socket.connect({ path });

	if (!s)
		return null;

	s.setopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, { sec: timeout ?? 10, usec: 0 });
	s.send(command + '\n');

	let out = '';

	for (let chunk = s.recv(65536); chunk != null && chunk != ''; chunk = s.recv(65536))
		out += chunk;

	s.close();

	return out;
};

export function master_running() {
	let r = cli(MASTER_SOCK, 'show proc', 3);

	return r != null && index(r, 'master') >= 0;
};

// Reload through the master CLI; returns { ok, output }.
export function master_reload() {
	let r = cli(MASTER_SOCK, 'reload', 60);

	if (r == null)
		return { ok: false, output: 'the master socket did not answer' };

	let m = match(r, /Success=([01])/);

	return { ok: m?.[1] == '1', output: trim(r) };
};

export function stats_command(command) {
	return cli(STATS_SOCK, command, 10);
};

// Parse "show stat" CSV into rows of objects.
export function show_stat() {
	let text = stats_command('show stat');

	if (text == null)
		return null;

	let lines = filter(split(text, '\n'), (l) => l != '');

	if (!length(lines) || substr(lines[0], 0, 2) != '# ')
		return null;

	let head = split(substr(lines[0], 2), ',');
	let rows = [];

	for (let i = 1; i < length(lines); i++) {
		let c = split(lines[i], ',');
		let row = {};

		for (let j, h in head)
			if (h != '')
				row[h] = c[j];

		push(rows, row);
	}

	return rows;
};

export function stock_haproxy_state() {
	let enabled = false;

	for (let f in (fs.lsdir('/etc/rc.d') ?? []))
		if (match(f, /^S[0-9]+haproxy$/))
			enabled = true;

	let running = false;
	let bus = connect();
	let st = bus ? bus.call('service', 'list', { name: 'haproxy' }) : null;

	for (let n, inst in (st?.haproxy?.instances ?? {}))
		if (inst.running)
			running = true;

	return { installed: !!fs.access('/etc/init.d/haproxy'), enabled, running };
};

// Generate, check and, unless dry, install the configuration. Returns the
// result that is also written to last-apply.json.
export function apply(opts) {
	opts ??= {};

	let sections = load_sections(opts.savedir);
	let res = generate(sections, collect_env());
	let out = {
		state: 'failed',
		errors: res.errors,
		warnings: res.warnings,
		skipped: res.skipped,
		check: null
	};

	if (!res.ok)
		return { result: out, gen: res };

	if (!res.enabled) {
		out.state = 'disabled';
		return { result: out, gen: res };
	}

	out.check = haproxy_check(res.config);

	if (!out.check.ok)
		return { result: out, gen: res };

	if (!opts.dry) {
		ensure_run_dir();

		let tmp = `${CFG_FILE}.new`;

		fs.writefile(tmp, res.config);
		fs.chmod(tmp, 0600);

		let old = fs.readfile(CFG_FILE);

		if (old != null)
			fs.writefile(`${CFG_FILE}.last-good`, old);

		fs.rename(tmp, CFG_FILE);
	}

	out.state = 'applied';

	return { result: out, gen: res };
};
