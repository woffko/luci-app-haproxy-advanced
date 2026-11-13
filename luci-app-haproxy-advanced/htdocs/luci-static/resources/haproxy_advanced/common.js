'use strict';
'require baseclass';
'require rpc';
'require uci';
'require ui';

// Shared code of the HAProxy Advanced views: rpc calls, the apply-result
// watcher, validators matching the generator's, and small render helpers.

const CONFIG = 'haproxy-advanced';
const APPLY_KEY = 'haproxy-advanced.apply-pending';

const callStatus = rpc.declare({ object: 'luci.haproxy-advanced', method: 'status' });
const callPreview = rpc.declare({ object: 'luci.haproxy-advanced', method: 'preview', params: [ 'check' ] });
const callRuntime = rpc.declare({ object: 'luci.haproxy-advanced', method: 'runtime' });
const callSetServer = rpc.declare({ object: 'luci.haproxy-advanced', method: 'set_server', params: [ 'backend', 'server', 'state' ] });
const callCertificates = rpc.declare({ object: 'luci.haproxy-advanced', method: 'certificates' });
const callAcmeRenew = rpc.declare({ object: 'luci.haproxy-advanced', method: 'acme_renew' });
const callAcmeLog = rpc.declare({ object: 'luci.haproxy-advanced', method: 'acme_log' });
const callLogs = rpc.declare({ object: 'luci.haproxy-advanced', method: 'logs' });
const callReload = rpc.declare({ object: 'luci.haproxy-advanced', method: 'reload' });
const callStockDisable = rpc.declare({ object: 'luci.haproxy-advanced', method: 'stock_haproxy_disable' });
const callLegacyBackup = rpc.declare({ object: 'luci.haproxy-advanced', method: 'legacy_backup' });

const RE_NAME = /^[A-Za-z0-9_]{1,48}$/;
const RE_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const RE_PATH = /^\/[A-Za-z0-9._~!*+,;=:@\/-]*$/;
const RE_AMBIGUOUS = /\/\/|(^|\/)\.\.?(\/|$)/;
const RE_TIME = /^[0-9]{1,9}(us|ms|s|m|h|d)?$/;
const RE_FILE = /^\/[A-Za-z0-9._\/+@-]+$/;
const RE_QUOTED = /^[A-Za-z0-9 ._,;:=+*@!?()\/-]*$/;

function isHostname(v) {
	v = String(v).toLowerCase();

	if (v.length > 253)
		return false;

	return v.split('.').every((l) => RE_LABEL.test(l));
}

function isIPv4(v) {
	const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);

	return !!m && m.slice(1).every((x) => +x <= 255);
}

function isIPv6(v) {
	return /^[0-9A-Fa-f:.]+$/.test(v) && v.includes(':') && v.split('::').length <= 2;
}

function isNetwork(v) {
	const m = /^([0-9A-Fa-f:.]+)(\/(\d{1,3}))?$/.exec(v || '');

	if (!m)
		return false;

	if (isIPv4(m[1]))
		return m[3] == null || +m[3] <= 32;

	return isIPv6(m[1]) && (m[3] == null || +m[3] <= 128);
}

// Validators for form options; they return true or an error text.
const validators = {
	hostname(section_id, value) {
		return (!value || isHostname(value)) ? true : _('Expecting a host name such as nas.example.com (no wildcards)');
	},

	path(section_id, value) {
		if (!value)
			return true;

		if (!RE_PATH.test(value))
			return _('Expecting a path starting with / (write it decoded; no spaces, %, quotes, $, # or \\)');

		if (RE_AMBIGUOUS.test(value))
			return _('The path must not contain //, /./ or /../');

		return true;
	},

	network(section_id, value) {
		return (!value || isNetwork(value)) ? true : _('Expecting an IPv4 or IPv6 address or network');
	},

	time(section_id, value) {
		return (!value || RE_TIME.test(value)) ? true : _('Expecting a time such as 500ms, 10s, 5m or 1h');
	},

	file(section_id, value) {
		return (!value || (RE_FILE.test(value) && !RE_AMBIGUOUS.test(value)))
			? true : _('Expecting an absolute path of plain characters');
	},

	quoted(section_id, value) {
		return (!value || RE_QUOTED.test(value))
			? true : _('Only letters, digits, spaces and . _ , ; : = + * @ ! ? ( ) / - are allowed');
	},

	header(section_id, value) {
		if (!value)
			return true;

		const m = /^([A-Za-z0-9-]{1,64}):[ ]*(.*)$/.exec(value);

		return (m && RE_QUOTED.test(m[2])) ? true : _("Expecting 'Name: value' with a plain value");
	}
};

function formatTime(ts) {
	if (!ts)
		return '-';

	const d = new Date(ts * 1000);

	return '%04d-%02d-%02d %02d:%02d:%02d'.format(d.getFullYear(), d.getMonth() + 1, d.getDate(),
		d.getHours(), d.getMinutes(), d.getSeconds());
}

function problemList(title, items, cls) {
	if (!items || !items.length)
		return '';

	return E('div', { 'class': 'cbi-section' }, [
		E('strong', {}, title),
		E('ul', { 'class': cls || '' }, items.map((p) => E('li', {}, [
			E('code', {}, p.where), ': ', p.message
		])))
	]);
}

// The result of an apply (last-apply.json) as DOM nodes.
function renderApplyResult(la) {
	if (!la)
		return E('p', { 'class': 'cbi-value-description' }, _('No configuration has been applied yet.'));

	const labels = {
		applied: _('Applied'),
		disabled: _('Disabled (global setting)'),
		failed: _('Not applied: the running configuration was kept')
	};

	const nodes = [
		E('p', {}, [
			E('strong', {}, labels[la.state] || la.state), ' · ', formatTime(la.time)
		]),
		problemList(_('Errors'), la.errors, 'alert-message warning'),
		problemList(_('Left out for now'), la.skipped),
		problemList(_('Warnings'), la.warnings)
	];

	if (la.check && !la.check.ok)
		nodes.push(E('div', {}, [
			E('strong', {}, _('haproxy -c rejected the configuration:')),
			E('pre', { 'style': 'white-space:pre-wrap' }, la.check.output)
		]));

	if (la.runtime) {
		nodes.push(E('p', {}, [
			E('strong', {}, _('HAProxy:')), ' ',
			la.runtime.ok ? _('running the new configuration') : _('did not load the new configuration; the previous one keeps running'),
			' · ', formatTime(la.runtime.time)
		]));

		if (!la.runtime.ok)
			nodes.push(E('pre', { 'style': 'white-space:pre-wrap' }, la.runtime.output));
	}

	return E('div', {}, nodes);
}

function notifyApplyResult(la) {
	const ok = la && la.state != 'failed' && !(la.runtime && !la.runtime.ok);

	ui.addNotification(ok ? _('HAProxy Advanced: configuration applied') : _('HAProxy Advanced: configuration not applied'),
		renderApplyResult(la), ok ? 'info' : 'warning');
}

return baseclass.extend({
	CONFIG: CONFIG,
	callStatus: callStatus,
	callPreview: callPreview,
	callRuntime: callRuntime,
	callSetServer: callSetServer,
	callCertificates: callCertificates,
	callAcmeRenew: callAcmeRenew,
	callAcmeLog: callAcmeLog,
	callLogs: callLogs,
	callReload: callReload,
	callStockDisable: callStockDisable,
	callLegacyBackup: callLegacyBackup,
	validators: validators,
	isHostname: isHostname,
	isNetwork: isNetwork,
	isIPv4: isIPv4,
	isIPv6: isIPv6,
	RE_NAME: RE_NAME,
	formatTime: formatTime,
	renderApplyResult: renderApplyResult,

	// Section names of a type, for drop-downs.
	names: function(type) {
		return uci.sections(CONFIG, type).map((s) => s['.name']);
	},

	// A section name that no section of the configuration uses yet.
	uniqueName: function(base) {
		base = String(base || 'item').replace(/[^A-Za-z0-9_]/g, '_').replace(/^_+|_+$/g, '').substring(0, 40) || 'item';

		const used = {};

		uci.sections(CONFIG).forEach((s) => { used[s['.name']] = true; });

		if (!used[base])
			return base;

		for (let i = 2; ; i++)
			if (!used[base + '_' + i])
				return base + '_' + i;
	},

	// After Save & Apply LuCI reloads the page. Remember the previous apply
	// time when the apply starts, and on the next page load wait for a newer
	// last-apply.json and show it (task F5).
	watchApply: function(status) {
		const prev = (status && status.last_apply) ? status.last_apply.time || 0 : 0;

		document.addEventListener('uci-applied', () => {
			try { sessionStorage.setItem(APPLY_KEY, JSON.stringify({ prev: prev, at: Date.now() })); } catch (e) {}
		});

		let pending = null;

		try { pending = JSON.parse(sessionStorage.getItem(APPLY_KEY) || 'null'); } catch (e) {}

		if (!pending || Date.now() - pending.at > 120000)
			return;

		try { sessionStorage.removeItem(APPLY_KEY); } catch (e) {}

		let tries = 0;
		const poll = () => callStatus().then((st) => {
			const la = st.last_apply;

			if (la && (la.time || 0) > pending.prev && (la.state != 'applied' || la.runtime || tries > 5))
				return notifyApplyResult(la);

			if (++tries < 20)
				return new Promise((resolve) => window.setTimeout(resolve, 1500)).then(poll);
		});

		poll();
	},

	// Choices of listen addresses: '*' and the router's logical interfaces.
	addressChoices: function(networks) {
		const out = [ [ '*', _('Any address (*)') ] ];

		(networks || []).forEach((net) => {
			const name = net.getName();

			if (name == 'loopback')
				return;

			const addrs = (net.getIPAddrs() || []).concat(net.getIP6Addrs() || []);

			out.push([ name, addrs.length ? '%s (%s)'.format(name, addrs.join(', ')) : name ]);
		});

		return out;
	}
});
