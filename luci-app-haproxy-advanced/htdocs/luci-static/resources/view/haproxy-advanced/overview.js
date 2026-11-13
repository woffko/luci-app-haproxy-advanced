'use strict';
'require view';
'require poll';
'require uci';
'require ui';
'require haproxy_advanced.common as common';

const STATE_LABELS = {
	ready: _('Ready'),
	drain: _('Drain (no new clients)'),
	maint: _('Maintenance (no traffic)')
};

function proxyKind(name) {
	if (/^fe_/.test(name))
		return 'listener';

	if (/^be_/.test(name) && !/_loop$/.test(name) && name != 'be_ha_acme')
		return 'backend';

	return null;
}

function statusBadge(st) {
	const s = String(st || '').split(' ')[0];
	const color = { UP: '#2e7d32', OPEN: '#2e7d32', DOWN: '#c62828', MAINT: '#6d4c41', DRAIN: '#ef6c00', 'no': '#757575' }[s] || '#455a64';

	return E('span', { 'style': 'font-weight:bold; color:' + color }, st || '-');
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(common.callStatus(), {}),
			L.resolveDefault(common.callRuntime(), { running: false, rows: [] }),
			L.resolveDefault(common.callLogs(), { output: '' }),
			uci.load(common.CONFIG)
		]);
	},

	setServer: function(backend, server, state) {
		return common.callSetServer(backend, server, state).then((r) => {
			if (!r.ok)
				ui.addNotification(null, E('p', _('HAProxy answered: %s').format(r.output || _('error'))), 'warning');

			return this.refreshRuntime();
		});
	},

	// Disable a server in the configuration (it stays disabled after reloads).
	disablePermanently: function(backend, server) {
		const sec = uci.sections(common.CONFIG, 'server').find((s) => s.backend == backend && s.name == server);

		if (!sec)
			return;

		uci.set(common.CONFIG, sec['.name'], 'enabled', '0');

		return uci.save().then(() => {
			ui.changes.init();
			ui.addNotification(null, E('p', _('Server %s/%s is disabled in the configuration. Use Save & Apply to make it take effect.').format(backend, server)), 'info');
		});
	},

	renderRuntime: function(rt) {
		if (!rt || !rt.running)
			return E('em', {}, _('HAProxy is not running.'));

		const rows = [];
		const head = E('tr', { 'class': 'tr table-titles' }, [
			_('Name'), _('Status'), _('Last check'), _('Sessions now'), _('Sessions total'), _('Requests/s'), _('4xx'), _('5xx'), ''
		].map((t) => E('th', { 'class': 'th' }, t)));

		// "show stat" lists a proxy's servers before its BACKEND row. Show
		// listeners first, then each backend's summary followed by its servers.
		const ordered = [];
		const byProxy = {};

		rt.rows.forEach((r) => {
			const kind = proxyKind(r.proxy);

			if (!kind || (kind == 'listener' && r.name != 'FRONTEND'))
				return;

			if (!byProxy[r.proxy]) {
				byProxy[r.proxy] = { kind: kind, head: null, servers: [] };
				ordered.push(r.proxy);
			}

			if (r.name == 'FRONTEND' || r.name == 'BACKEND')
				byProxy[r.proxy].head = r;
			else
				byProxy[r.proxy].servers.push(r);
		});

		const flat = [];

		ordered.filter((p) => byProxy[p].kind == 'listener')
			.concat(ordered.filter((p) => byProxy[p].kind == 'backend'))
			.forEach((p) => {
				if (byProxy[p].head)
					flat.push(byProxy[p].head);

				flat.push(...byProxy[p].servers);
			});

		flat.forEach((r) => {
			const kind = proxyKind(r.proxy);
			const isServer = (r.name != 'FRONTEND' && r.name != 'BACKEND');

			let label, actions = '';

			if (kind == 'listener')
				label = E('strong', {}, _('Listener %s').format(r.proxy.replace(/^fe_/, '')));
			else if (!isServer)
				label = E('strong', {}, _('Backend %s').format(r.proxy.replace(/^be_/, '')));
			else
				label = E('span', { 'style': 'padding-left:1.5em' }, r.name);

			if (kind == 'backend' && isServer) {
				const b = r.proxy.replace(/^be_/, '');
				const sel = E('select', { 'class': 'cbi-input-select', 'style': 'width:auto' },
					Object.keys(STATE_LABELS).map((k) => E('option', { 'value': k }, STATE_LABELS[k])));

				sel.value = /MAINT/.test(r.status) ? 'maint' : (/DRAIN/.test(r.status) ? 'drain' : 'ready');

				actions = E('div', {}, [
					sel, ' ',
					E('button', { 'class': 'btn cbi-button-action', 'click': ui.createHandlerFn(this, () => this.setServer(b, r.name, sel.value)) }, _('Set')), ' ',
					E('button', { 'class': 'btn cbi-button-negative', 'click': ui.createHandlerFn(this, 'disablePermanently', b, r.name) }, _('Disable permanently'))
				]);
			}

			rows.push(E('tr', { 'class': 'tr' }, [
				label,
				statusBadge(r.status),
				isServer ? (r.check ? '%s %s'.format(r.check, r.check_desc || '') : '-') : '',
				String(r.scur), String(r.stot),
				String(r.req_rate || r.rate || 0),
				String(r.hrsp_4xx), String(r.hrsp_5xx),
				actions
			].map((c) => E('td', { 'class': 'td' }, c))));
		});

		return E('div', {}, [
			E('table', { 'class': 'table' }, [ head ].concat(rows)),
			E('p', { 'class': 'cbi-value-description' },
				_('Ready, drain and maintenance act on the running HAProxy only; the next reload resets them. "Disable permanently" changes the configuration instead.'))
		]);
	},

	refreshRuntime: function() {
		return L.resolveDefault(common.callRuntime(), { running: false, rows: [] }).then((rt) => {
			const box = document.getElementById('ha-runtime');

			if (box)
				box.replaceChildren(this.renderRuntime(rt));
		});
	},

	renderNotices: function(st) {
		const nodes = [];

		if (st.legacy_config)
			nodes.push(E('div', { 'class': 'alert-message warning' }, [
				E('p', {}, _('/etc/config/haproxy-advanced is a version 0.1 configuration. Version 0.2 uses a new format and does not convert it, so the service does not start.')),
				E('button', {
					'class': 'btn cbi-button-action',
					'click': ui.createHandlerFn(this, () => common.callLegacyBackup().then((r) => {
						ui.addNotification(null, E('p', r.output), r.ok ? 'info' : 'warning');

						if (r.ok)
							window.setTimeout(() => window.location.reload(), 1500);
					}))
				}, _('Move it to /etc/config/haproxy-advanced.v01 and start empty'))
			]));

		const stock = st.stock_haproxy || {};

		if (stock.installed && (stock.enabled || stock.running))
			nodes.push(E('div', { 'class': 'alert-message notice' }, [
				E('p', {}, _('The haproxy package\'s own service (/etc/init.d/haproxy) is %s. Its sample configuration listens on ports 81, 444 and 60000 as root, with a well-known stats password. HAProxy Advanced does not need it.')
					.format([ stock.running ? _('running') : null, stock.enabled ? _('enabled at boot') : null ].filter((x) => x).join(' ' + _('and') + ' '))),
				E('button', {
					'class': 'btn cbi-button-negative',
					'click': ui.createHandlerFn(this, () => ui.showModal(_('Stop the stock HAProxy service?'), [
						E('p', {}, _('This stops /etc/init.d/haproxy and disables it at boot. /etc/haproxy.cfg is not changed; "service haproxy enable" undoes it.')),
						E('div', { 'class': 'right' }, [
							E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
							E('button', {
								'class': 'btn cbi-button-negative',
								'click': ui.createHandlerFn(this, () => common.callStockDisable().then((r) => {
									ui.hideModal();
									ui.addNotification(null, E('p', r.output || ''), r.ok ? 'info' : 'warning');
									window.setTimeout(() => window.location.reload(), 1500);
								}))
							}, _('Stop and disable'))
						])
					]))
				}, _('Stop and disable it…'))
			]));

		const g = (st.last_apply || {}).skipped || [];

		if (g.some((s) => /already used by/.test(s.message)))
			nodes.push(E('div', { 'class': 'alert-message warning' },
				_('A port of a listener is used by another program. See "Left out for now" below.')));

		return nodes;
	},

	render: function(data) {
		const st = data[0] || {};
		const rt = data[1];
		const logs = data[2] || {};
		const logBox = E('pre', { 'style': 'white-space:pre-wrap; max-height:25em; overflow:auto' }, logs.output || _('No log lines.'));

		common.watchApply(st);

		poll.add(() => this.refreshRuntime(), 5);

		const info = E('table', { 'class': 'table' }, [
			[ _('Service'), st.enabled ? _('enabled') : _('disabled in Settings') ],
			[ _('HAProxy'), st.running ? _('running (PID %s)').format(st.pid || '?') : _('not running') ],
			[ _('Version'), st.version || '-' ]
		].map((r) => E('tr', { 'class': 'tr' }, [ E('td', { 'class': 'td left', 'style': 'width:33%' }, r[0]), E('td', { 'class': 'td left' }, r[1]) ])));

		return E('div', {}, [
			E('h2', {}, _('HAProxy Advanced')),
			E('p', { 'class': 'cbi-map-descr' }, _('Publishes internal web applications through HAProxy with TLS, host-based routing, access rules and logins.')),
			E('div', {}, this.renderNotices(st)),
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('Status')), info ]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Last apply')),
				common.renderApplyResult(st.last_apply),
				E('div', { 'class': 'cbi-page-actions' }, [
					E('button', {
						'class': 'btn cbi-button-apply',
						'click': ui.createHandlerFn(this, () => common.callReload().then((r) => {
							ui.addNotification(null, common.renderApplyResult(r.last_apply), r.ok ? 'info' : 'warning');
						}))
					}, _('Apply saved settings again'))
				])
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Runtime')),
				E('div', { 'id': 'ha-runtime' }, this.renderRuntime(rt))
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Log')),
				E('div', { 'class': 'cbi-page-actions' }, [
					E('button', {
						'class': 'btn cbi-button',
						'click': ui.createHandlerFn(this, () => common.callLogs().then((r) => { logBox.textContent = r.output || _('No log lines.'); }))
					}, _('Refresh'))
				]),
				logBox
			])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
