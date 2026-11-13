// SPDX-License-Identifier: MIT
// Value helpers and validators of the haproxy-advanced generator.
//
// Everything the generator writes into HAProxy's configuration passes one of the
// validators below. They accept only characters that HAProxy's parser treats as
// plain text in the place the value goes: no whitespace (argument separator), no
// '#' (comment), no quotes, backslashes or '$' (escapes and environment
// expansion), and no control characters.

'use strict';

// UCI values: options are strings, lists are arrays. Accept both shapes.
export function opt(s, name, def) {
	let v = s?.[name];

	if (type(v) == 'array')
		v = join(' ', v);

	if (v == null || v == '')
		return def;

	return '' + v;
};

export function list(s, name) {
	let v = s?.[name];

	if (v == null || v == '')
		return [];

	if (type(v) != 'array')
		v = [ '' + v ];

	return filter(map(v, (x) => trim('' + x)), (x) => x != '');
};

export function bool(s, name, def) {
	let v = opt(s, name, null);

	if (v == null)
		return def;

	return (v == '1' || v == 'on' || v == 'yes' || v == 'true' || v == 'enabled');
};

// Tri-state flag: null when unset, so the caller can inherit.
export function tristate(s, name) {
	let v = opt(s, name, null);

	if (v == null)
		return null;

	return (v == '1' || v == 'on' || v == 'yes' || v == 'true');
};

export function is_bool_text(v) {
	return v == null || v in [ '0', '1', 'on', 'off', 'yes', 'no', 'true', 'false', 'enabled', 'disabled' ];
};

export function is_uint(v, max) {
	if (type(v) != 'string' || !match(v, /^[0-9]{1,10}$/))
		return false;

	let n = +v;

	return n >= 0 && (max == null || n <= max);
};

export function is_port(v) {
	return is_uint(v, 65535) && +v >= 1;
};

// HAProxy time: digits and an optional unit.
export function is_time(v) {
	return type(v) == 'string' && !!match(v, /^[0-9]{1,9}(us|ms|s|m|h|d)?$/);
};

// UCI section names and names derived from them.
export function is_name(v) {
	return type(v) == 'string' && !!match(v, /^[A-Za-z0-9_]{1,48}$/);
};

// Server names: HAProxy allows a little more than UCI.
export function is_server_name(v) {
	return type(v) == 'string' && !!match(v, /^[A-Za-z0-9_.-]{1,48}$/);
};

export function is_iface(v) {
	return type(v) == 'string' && !!match(v, /^[A-Za-z0-9_]{1,31}$/);
};

export function is_zone(v) {
	return type(v) == 'string' && !!match(v, /^[A-Za-z0-9_]{1,31}$/);
};

export function is_ipv4(v) {
	return type(v) == 'string' && !!match(v, /^[0-9.]+$/) && length(iptoarr(v) ?? []) == 4;
};

export function is_ipv6(v) {
	return type(v) == 'string' && !!match(v, /^[0-9A-Fa-f:.]+$/) && index(v, ':') >= 0 &&
		length(iptoarr(v) ?? []) == 16;
};

// A network: address with an optional prefix length.
export function parse_network(v) {
	if (type(v) != 'string')
		return null;

	let m = match(v, /^([0-9A-Fa-f:.]+)(\/([0-9]{1,3}))?$/);

	if (!m)
		return null;

	let fam = is_ipv4(m[1]) ? 4 : (is_ipv6(m[1]) ? 6 : null);

	if (!fam)
		return null;

	if (m[3] != null && +m[3] > (fam == 4 ? 32 : 128))
		return null;

	return { address: m[1], prefix: m[3], family: fam };
};

export function is_network(v) {
	return parse_network(v) != null;
};

// Host names: lower-case LDH labels. Upper case is folded by the caller.
export function is_hostname(v) {
	if (type(v) != 'string' || length(v) > 253)
		return false;

	for (let label in split(v, '.'))
		if (!match(label, /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/))
			return false;

	return true;
};

// Server address: an IP literal or a host name.
export function is_server_address(v) {
	return is_ipv4(v) || is_ipv6(v) || is_hostname(lc(v ?? ''));
};

export function is_ambiguous_path(v) {
	return !!match(v, /\/\/|(^|\/)\.\.?(\/|$)/);
};

// Decoded path prefixes for ACL patterns. '%' is excluded because patterns are
// compared with the URL-decoded path; '$' and quotes because of HAProxy's parser.
export function is_path_prefix(v) {
	if (type(v) != 'string' || length(v) > 200)
		return false;

	if (!match(v, /^\/[A-Za-z0-9._~!*+,;=:@\/-]*$/))
		return false;

	return !is_ambiguous_path(v);
};

// Health check URI: a path with an optional query.
export function is_check_uri(v) {
	return type(v) == 'string' && length(v) <= 200 &&
		!!match(v, /^\/[A-Za-z0-9._~!*+,;=:@\/?&-]*$/);
};

export function is_file_path(v) {
	return type(v) == 'string' && length(v) <= 200 &&
		!!match(v, /^\/[A-Za-z0-9._\/+@-]+$/) && !match(v, /(^|\/)\.\.?(\/|$)/);
};

export function is_ca_file(v) {
	return v == '@system-ca' || is_file_path(v);
};

export function is_username(v) {
	return type(v) == 'string' && !!match(v, /^[A-Za-z0-9._@-]{1,64}$/);
};

export function is_password_hash(v) {
	return type(v) == 'string' && length(v) <= 200 &&
		!!match(v, /^\$(1|5|6|2[aby])\$[A-Za-z0-9.\/$=]+$/);
};

// Text inside double quotes in HAProxy's configuration: no quotes, backslashes,
// '$' or '%', which would be escapes, variables or log-format tags.
export function is_quoted_text(v, max) {
	return type(v) == 'string' && length(v) <= (max ?? 128) &&
		!!match(v, /^[A-Za-z0-9 ._,;:=+*@!?()\/-]*$/);
};

export function is_header_name(v) {
	return type(v) == 'string' && !!match(v, /^[A-Za-z0-9-]{1,64}$/);
};

export function parse_header(v) {
	let m = match(v ?? '', /^([A-Za-z0-9-]{1,64}):[ ]*(.*)$/);

	if (!m || !is_quoted_text(m[2], 256))
		return null;

	return { name: m[1], value: m[2] };
};

export const HTTP_METHODS = [ 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS',
	'CONNECT', 'TRACE', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK',
	'REPORT', 'SEARCH' ];

export const DENY_STATUSES = [ '400', '401', '403', '404', '405', '429', '500', '503' ];

export const LOG_LEVELS = [ 'emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug' ];

// Status list of HTTP checks: codes like 200 or classes like 2xx.
export function check_status_regex(items) {
	let alts = [];

	for (let it in items) {
		let m = match(it, /^([1-5])xx$/);

		if (m)
			push(alts, m[1] + '[0-9][0-9]');
		else if (match(it, /^[1-5][0-9][0-9]$/))
			push(alts, it);
		else
			return null;
	}

	return length(alts) ? '^(' + join('|', alts) + ')$' : null;
};

// Lines of an 'advanced' text option.
export function text_lines(v) {
	if (v == null || v == '')
		return [];

	if (type(v) == 'array')
		v = join('\n', v);

	return filter(map(split(v, /\r?\n/), (l) => trim(l)), (l) => l != '');
};

// One advanced line: refuse control characters, section keywords and directives
// the service owns. This keeps the generated file well-formed; it is not a
// security boundary (an administrator who can edit these lines is root).
const SECTION_KEYWORDS = [ 'global', 'defaults', 'frontend', 'backend', 'listen', 'peers',
	'resolvers', 'userlist', 'mailers', 'program', 'ring', 'http-errors', 'cache',
	'crt-store', 'acme', 'traces', 'log-forward', 'fcgi-app' ];

const OWNED_GLOBAL = [ 'daemon', 'master-worker', 'user', 'group', 'uid', 'gid', 'chroot',
	'pidfile', 'log-tag', 'nbproc' ];

export function check_advanced_line(line, where) {
	for (let i = 0; i < length(line); i++) {
		let c = ord(line, i);

		if ((c < 32 && c != 9) || c == 127 || c == 96)
			return 'control characters and backticks are not allowed';
	}

	let words = split(line, /[ \t]+/);
	let kw = lc(words[0] ?? '');

	if (kw in SECTION_KEYWORDS)
		return `'${kw}' would start a new section`;

	if (kw == 'stats' && lc(words[1] ?? '') == 'socket')
		return 'the service owns the stats socket';

	if (where == 'global' && kw in OWNED_GLOBAL)
		return `the service sets '${kw}' itself`;

	if (where == 'service') {
		if (!(kw in [ 'http-request', 'http-response', 'http-after-response' ]))
			return 'service lines must be http-request, http-response or http-after-response rules';

		for (let w in words)
			if (w == 'if' || w == 'unless')
				return 'service lines may not have a condition; the service adds its own';
	}

	return null;
};

export function sort_by_order(items) {
	return sort(items, (a, b) => (a.order - b.order) || (a.index - b.index));
};

export function uniq(arr) {
	let seen = {}, out = [];

	for (let v in arr) {
		if (!seen[v]) {
			seen[v] = true;
			push(out, v);
		}
	}

	return out;
};
