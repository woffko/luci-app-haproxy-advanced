'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require network';
'require haproxy_advanced.common as common';
'require haproxy_advanced.crypt as hacrypt';

// Requests per 10 seconds per client address offered when a preset turns the
// rate limit on. Measured on the test VM: see docs/goals/goal-a-status.md.
const RATE_DEFAULT = '300';

const PRESETS = {
	generic_https: {
		label: _('Generic HTTPS application'),
		mode: 'http', proto: 'https', port: '443', login: true, rate: true
	},
	nas_file: {
		label: _('NAS / file sharing'),
		mode: 'http', proto: 'https', port: '443', login: true, rate: true,
		public_path: [ '/share/', '/share.cgi' ],
		internal_path: [ '/admin/', '/cgi-bin/' ]
	},
	admin_panel: {
		label: _('Web admin panel (login outside trusted networks)'),
		mode: 'http', proto: 'https', port: '443', login: true, rate: true
	},
	home_assistant: {
		label: _('Home Assistant / WebSocket application'),
		mode: 'http', proto: 'http', port: '8123', login: false, rate: true, tunnel: '1h'
	},
	http_backend: {
		label: _('Plain HTTP application'),
		mode: 'http', proto: 'http', port: '80', login: true, rate: true
	},
	passthrough: {
		label: _('TLS passthrough (the server keeps its own certificate)'),
		mode: 'passthrough', proto: 'tls', port: '443', login: false, rate: false
	}
};

function splitList(v) {
	return String(v || '').split(/[\s,]+/).map((x) => x.trim()).filter((x) => x != '');
}

function field(label, widget, description) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, label),
		E('div', { 'class': 'cbi-value-field' }, [
			widget,
			description ? E('div', { 'class': 'cbi-value-description' }, description) : ''
		])
	]);
}

function select(options, selected) {
	return E('select', { 'class': 'cbi-input-select' }, options.map((o) =>
		E('option', { 'value': o[0], 'selected': (o[0] == selected) ? 'selected' : null }, o[1])));
}

function input(value, placeholder, type) {
	return E('input', { 'class': 'cbi-input-text', 'type': type || 'text', 'value': value || '', 'placeholder': placeholder || '' });
}

function checkbox(checked) {
	return E('input', { 'type': 'checkbox', 'checked': checked ? 'checked' : null });
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(common.callStatus(), {}),
			L.resolveDefault(network.getNetworks(), []),
			L.resolveDefault(common.callCertificates(), { files: [], acme: [] }),
			uci.load(common.CONFIG),
			L.resolveDefault(uci.load('acme'), null)
		]);
	},

	// The "Add service" dialog: creates the service and, when needed, its
	// listener, backend, server, login group and ACME certificate, with names no
	// other section uses (task F2, F4).
	addServiceDialog: function(section, prefillName) {
		const status = this.status, certs = this.certs, choices = this.choices;
		const listeners = common.names('listener');
		const groups = common.names('auth_group');
		const hasWan = choices.some((c) => c[0] == 'wan');

		const w = {
			preset: select(Object.keys(PRESETS).map((k) => [ k, PRESETS[k].label ]), 'generic_https'),
			name: input(prefillName || '', 'nas'),
			hosts: input('', 'nas.example.com'),
			listener: select(listeners.map((l) => [ l, l ]).concat([ [ '__new', _('New listener…') ] ]), listeners[0] || '__new'),
			l_addr: select(choices, hasWan ? 'wan' : '*'),
			l_port: input('443', '443'),
			l_redirect: input('80', _('none')),
			l_firewall: checkbox(true),
			b_proto: select([ [ 'https', 'HTTPS' ], [ 'http', 'HTTP' ] ], 'https'),
			b_addr: input('', '192.168.1.10'),
			b_port: input('443', '443'),
			b_verify: select([ [ 'none', _('Do not check the certificate (private network)') ], [ 'required', _('Check against the system CAs') ] ], 'none'),
			c_source: select((status.acme_installed ? [ [ 'acme', _('Issue with ACME (Let\'s Encrypt)') ] ] : [])
				.concat([ [ 'file', _('A file on the router') ], [ 'later', _('Choose later') ] ]), status.acme_installed ? 'acme' : 'file'),
			c_file: input('', '/etc/haproxy/certs/nas.pem'),
			c_email: input('', 'admin@example.com', 'email'),
			trusted: input('', '192.168.1.0/24'),
			login: select([ [ 'none', _('No login') ], [ '__new', _('New group with one user') ] ]
				.concat(groups.map((g) => [ g, _('Group %s').format(g) ])), '__new'),
			u_name: input('', 'alice'),
			u_pw1: input('', '', 'password'),
			u_pw2: input('', '', 'password'),
			rate: checkbox(true),
			error: E('div', { 'class': 'alert-message warning', 'style': 'display:none' }),
			hint: E('div', { 'class': 'cbi-value-description' })
		};

		const accountEmail = (uci.sections('acme', 'acme')[0] || {}).account_email;
		const listCerts = E('datalist', { 'id': 'ha-cert-files' }, (certs.files || []).map((c) => E('option', { 'value': c.path })));

		w.c_file.setAttribute('list', 'ha-cert-files');

		const block = {
			newListener: E('div', {}, [
				field(_('Listen on'), w.l_addr),
				field(_('Port'), w.l_port),
				field(_('HTTP companion port'), w.l_redirect, _('Redirects to HTTPS and answers ACME challenges. Empty for none.')),
				field(_('Open in firewall (wan)'), w.l_firewall),
				w.hint
			]),
			verify: field(_('Server certificate'), w.b_verify),
			cert: E('div', {}, [
				field(_('Certificate'), w.c_source),
				field(_('Certificate file'), w.c_file, _('PEM with the certificate chain and the private key.')),
				accountEmail ? '' : field(_('ACME account e-mail'), w.c_email, _('Let\'s Encrypt sends expiry notices here.'))
			]),
			user: E('div', {}, [
				field(_('Username'), w.u_name),
				field(_('Password'), w.u_pw1, _('Hashed in this browser; only the hash is saved.')),
				field(_('Repeat password'), w.u_pw2)
			]),
			login: null,
			proto: null
		};

		block.login = field(_('Login'), w.login);
		block.proto = field(_('Server protocol'), w.b_proto);

		const isNewListener = () => w.listener.value == '__new';
		const listenerTLS = () => isNewListener() || uci.get(common.CONFIG, w.listener.value, 'tls') != '0';
		const preset = () => PRESETS[w.preset.value];

		const update = () => {
			const p = preset();
			const pt = p.mode == 'passthrough';

			block.newListener.style.display = isNewListener() ? '' : 'none';
			block.proto.style.display = pt ? 'none' : '';
			block.verify.style.display = (!pt && w.b_proto.value == 'https') ? '' : 'none';
			block.cert.style.display = (!pt && listenerTLS()) ? '' : 'none';
			w.c_file.closest('.cbi-value').style.display = (w.c_source.value == 'file') ? '' : 'none';

			if (w.c_email.closest('.cbi-value'))
				w.c_email.closest('.cbi-value').style.display = (w.c_source.value == 'acme') ? '' : 'none';

			block.login.style.display = pt ? 'none' : '';
			block.user.style.display = (!pt && w.login.value == '__new') ? '' : 'none';

			const port = +w.l_port.value, rport = +w.l_redirect.value;
			const busy = (status.uhttpd_ports || []).filter((u) => u.port == port || u.port == rport);

			w.hint.textContent = (isNewListener() && busy.length)
				? _('LuCI (uhttpd) is configured for %s. Use other ports, or move LuCI first, or HAProxy cannot listen there.')
					.format(busy.map((u) => u.address + ':' + u.port).join(', '))
				: '';
		};

		const applyPreset = () => {
			const p = preset();

			w.b_proto.value = (p.proto == 'tls') ? 'https' : p.proto;
			w.b_port.value = p.port;
			w.login.value = p.login ? (w.login.value == 'none' ? '__new' : w.login.value) : 'none';
			w.rate.checked = !!p.rate;
			update();
		};

		[ w.preset ].forEach((el) => el.addEventListener('change', applyPreset));
		[ w.listener, w.b_proto, w.c_source, w.login, w.l_port, w.l_redirect ].forEach((el) => el.addEventListener('change', update));
		w.b_proto.addEventListener('change', () => { w.b_port.value = (w.b_proto.value == 'https') ? '443' : '80'; });

		const create = () => {
			const p = preset();
			const pt = p.mode == 'passthrough';
			const hosts = splitList(w.hosts.value).map((h) => h.toLowerCase());
			const trusted = splitList(w.trusted.value);
			const problems = [];

			if (!hosts.length || !hosts.every(common.isHostname))
				problems.push(_('Enter one or more host names such as nas.example.com.'));

			if (!trusted.every(common.isNetwork))
				problems.push(_('Trusted networks must be IP addresses or networks such as 192.168.1.0/24.'));

			if (!w.b_addr.value || !/^[A-Za-z0-9.:_-]+$/.test(w.b_addr.value))
				problems.push(_('Enter the server address.'));

			if (!/^\d{1,5}$/.test(w.b_port.value) || +w.b_port.value < 1 || +w.b_port.value > 65535)
				problems.push(_('Enter the server port.'));

			if (isNewListener()) {
				if (!/^\d{1,5}$/.test(w.l_port.value) || +w.l_port.value < 1 || +w.l_port.value > 65535)
					problems.push(_('Enter the listener port.'));

				if (w.l_redirect.value && (!/^\d{1,5}$/.test(w.l_redirect.value) || w.l_redirect.value == w.l_port.value))
					problems.push(_('The companion port must be a port other than the listener port.'));
			}

			const tls = !pt && listenerTLS();

			if (tls && w.c_source.value == 'file' && common.validators.file(null, w.c_file.value) !== true)
				problems.push(_('Enter the certificate file path.'));

			if (tls && w.c_source.value == 'acme' && !accountEmail && !/^[^\s@]+@[^\s@]+$/.test(w.c_email.value))
				problems.push(_('Enter the ACME account e-mail.'));

			if (tls && w.c_source.value == 'acme' && !isNewListener() && !uci.get(common.CONFIG, w.listener.value, 'redirect_port'))
				problems.push(_('ACME HTTP validation needs an HTTP companion port on the listener (usually 80). Set it on the Listeners tab first.'));

			if (tls && w.c_source.value == 'acme' && isNewListener() && !w.l_redirect.value)
				problems.push(_('ACME HTTP validation needs the HTTP companion port (usually 80).'));

			if (!pt && w.login.value == '__new') {
				if (!/^[A-Za-z0-9._@-]{1,64}$/.test(w.u_name.value))
					problems.push(_('Enter a username: letters, digits, ., _, @ or -.'));

				if (w.u_pw1.value.length < 8)
					problems.push(_('The password needs at least 8 characters.'));
				else if (w.u_pw1.value != w.u_pw2.value)
					problems.push(_('The passwords differ.'));
			}

			for (const h of hosts) {
				const owner = uci.sections(common.CONFIG, 'service').find((s) =>
					(s.listener == w.listener.value) && L.toArray(s.hostname).map((x) => x.toLowerCase()).includes(h));

				if (owner && !isNewListener())
					problems.push(_('%s is already published by service %s on this listener.').format(h, owner['.name']));
			}

			if (problems.length) {
				w.error.replaceChildren(E('ul', {}, problems.map((t) => E('li', {}, t))));
				w.error.style.display = '';
				return;
			}

			const svc = common.uniqueName(w.name.value || hosts[0].split('.')[0]);
			let listener = w.listener.value;

			if (isNewListener()) {
				listener = common.uniqueName(pt ? 'tls' : 'https');
				uci.add(common.CONFIG, 'listener', listener);
				uci.set(common.CONFIG, listener, 'address', [ w.l_addr.value ]);
				uci.set(common.CONFIG, listener, 'port', w.l_port.value);

				if (w.l_redirect.value)
					uci.set(common.CONFIG, listener, 'redirect_port', w.l_redirect.value);

				uci.set(common.CONFIG, listener, 'firewall', w.l_firewall.checked ? '1' : '0');
			}

			const backend = common.uniqueName(svc + '_backend');

			uci.add(common.CONFIG, 'backend', backend);

			if (p.tunnel)
				uci.set(common.CONFIG, backend, 'timeout_tunnel', p.tunnel);

			const srv = uci.add(common.CONFIG, 'server');

			uci.set(common.CONFIG, srv, 'backend', backend);
			uci.set(common.CONFIG, srv, 'name', 'server1');
			uci.set(common.CONFIG, srv, 'address', w.b_addr.value);
			uci.set(common.CONFIG, srv, 'port', w.b_port.value);

			if (!pt && w.b_proto.value == 'https') {
				uci.set(common.CONFIG, srv, 'tls', '1');
				uci.set(common.CONFIG, srv, 'verify', w.b_verify.value);

				if (w.b_verify.value == 'required') {
					uci.set(common.CONFIG, srv, 'ca_file', '@system-ca');
					uci.set(common.CONFIG, srv, 'sni', 'host');
				}
			}

			uci.add(common.CONFIG, 'service', svc);
			uci.set(common.CONFIG, svc, 'listener', listener);
			uci.set(common.CONFIG, svc, 'hostname', hosts);
			uci.set(common.CONFIG, svc, 'backend', backend);

			if (pt)
				uci.set(common.CONFIG, svc, 'mode', 'passthrough');

			if (trusted.length)
				uci.set(common.CONFIG, svc, 'trusted_network', trusted);

			[ 'public_path', 'internal_path', 'blocked_path' ].forEach((k) => {
				if (p[k] && p[k].length)
					uci.set(common.CONFIG, svc, k, p[k]);
			});

			if (w.rate.checked && !pt)
				uci.set(common.CONFIG, svc, 'rate_limit', RATE_DEFAULT);

			if (tls && w.c_source.value == 'file')
				uci.set(common.CONFIG, svc, 'certificate', w.c_file.value);

			if (tls && w.c_source.value == 'acme') {
				let cert = svc;

				for (let i = 2; uci.get('acme', cert); i++)
					cert = svc + '_' + i;

				if (!uci.sections('acme', 'acme').length)
					uci.add('acme', 'acme');

				if (!accountEmail)
					uci.set('acme', uci.sections('acme', 'acme')[0]['.name'], 'account_email', w.c_email.value);

				uci.add('acme', 'cert', cert);
				uci.set('acme', cert, 'enabled', '1');
				uci.set('acme', cert, 'domains', hosts);
				uci.set('acme', cert, 'validation_method', 'standalone');
				uci.set('acme', cert, 'listen_port', uci.get(common.CONFIG, 'global', 'acme_challenge_port') || '18402');
				uci.set('acme', cert, 'key_type', 'ec256');
				uci.set(common.CONFIG, svc, 'acme_cert', cert);
			}

			if (!pt && w.login.value == '__new') {
				const grp = common.uniqueName(svc + '_users');

				uci.add(common.CONFIG, 'auth_group', grp);
				uci.set(common.CONFIG, grp, 'realm', svc.replace(/_/g, ' '));

				const usr = uci.add(common.CONFIG, 'user');

				uci.set(common.CONFIG, usr, 'group', grp);
				uci.set(common.CONFIG, usr, 'username', w.u_name.value);
				uci.set(common.CONFIG, usr, 'password_hash', hacrypt.hash(w.u_pw1.value));
				uci.set(common.CONFIG, svc, 'auth_group', grp);
			}
			else if (!pt && w.login.value != 'none') {
				uci.set(common.CONFIG, svc, 'auth_group', w.login.value);
			}

			w.u_pw1.value = w.u_pw2.value = '';

			if (!uci.get(common.CONFIG, 'global', 'enabled') || uci.get(common.CONFIG, 'global', 'enabled') == '0')
				uci.set(common.CONFIG, 'global', 'enabled', '1');

			ui.hideModal();

			return section.map.save(null, true).then(() => {
				ui.addNotification(null, E('p', _('Service %s was added. Review it, then use Save & Apply; the Configuration tab shows what HAProxy will get.').format(svc)), 'info');
				return section.renderMoreOptionsModal(svc);
			});
		};

		ui.showModal(_('Add service'), [
			listCerts,
			E('p', _('Publish an internal web application under a host name. Presets fill the fields below; everything stays editable afterwards.')),
			field(_('Preset'), w.preset),
			field(_('Name'), w.name, _('Optional; letters, digits and _.')),
			field(_('Host names'), w.hosts, _('Names clients use, separated by spaces. DNS must point them at this router.')),
			field(_('Listener'), w.listener),
			block.newListener,
			E('h4', _('Server')),
			block.proto,
			field(_('Server address'), w.b_addr),
			field(_('Server port'), w.b_port),
			block.verify,
			block.cert,
			E('h4', _('Access')),
			field(_('Trusted networks'), w.trusted, _('Clients from these networks skip login and may use internal-only paths. Separate with spaces.')),
			block.login,
			block.user,
			field(_('Rate limit'), w.rate, _('At most %s requests per 10 seconds per client address.').format(RATE_DEFAULT)),
			w.error,
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
				E('button', { 'class': 'btn cbi-button-positive', 'click': ui.createHandlerFn(this, create) }, _('Create'))
			])
		]);

		applyPreset();
	},

	render: function(data) {
		const status = data[0] || {};
		const view = this;
		let m, s, o;

		this.status = status;
		this.choices = common.addressChoices(data[1]);
		this.certs = data[2] || { files: [], acme: [] };

		common.watchApply(status);

		const globalHardening = uci.get(common.CONFIG, 'global', 'hardening') != '0';

		m = new form.Map(common.CONFIG, _('HAProxy Advanced: services'),
			_('A service publishes one internal application under one or more host names. Requests are checked in this order: hardening, rate limits, blocked paths, custom rules, trusted networks, internal-only paths, public paths, login.'));

		s = m.section(form.GridSection, 'service', _('Services'));
		s.addremove = true;
		s.anonymous = false;
		s.nodescriptions = true;
		s.addbtntitle = _('Add service…');
		s.modaltitle = (sid) => _('Service') + ' » ' + sid;
		s.renderSectionPlaceholder = () => E('em', _('No service yet. "Add service…" publishes the first one.'));
		s.handleAdd = function(ev, name) {
			return view.addServiceDialog(this, name);
		};
		// LuCI keeps the add button of named sections disabled until a name is
		// typed next to it; the dialog asks for the name itself.
		s.renderSectionAdd = function(extra_class) {
			const el = E('div', { 'class': 'cbi-section-create' }, [
				E('button', {
					'class': 'cbi-button cbi-button-add',
					'title': _('Add service…'),
					'click': ui.createHandlerFn(this, (ev) => this.handleAdd(ev, ''))
				}, _('Add service…'))
			]);

			if (extra_class != null)
				el.classList.add(extra_class);

			return el;
		};

		s.tab('general', _('General'));
		s.tab('tls', _('TLS'));
		s.tab('access', _('Access'));
		s.tab('paths', _('Paths'));
		s.tab('auth', _('Login'));
		s.tab('headers', _('Headers & timeouts'));
		s.tab('advanced', _('Advanced'));

		o = s.taboption('general', form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.editable = true;

		o = s.taboption('general', form.DynamicList, 'hostname', _('Host names'),
			_('Exact names, case-insensitive. Each name may be used once per listener.'));
		o.rmempty = false;
		o.validate = common.validators.hostname;
		o.textvalue = (sid) => L.toArray(uci.get(common.CONFIG, sid, 'hostname')).join(', ');

		o = s.taboption('general', form.ListValue, 'listener', _('Listener'));
		common.names('listener').forEach((n) => o.value(n));
		o.rmempty = false;

		o = s.taboption('general', form.ListValue, 'mode', _('Mode'),
			_('Passthrough forwards the TLS connection by SNI without decrypting it; the server keeps its own certificate, and only trusted networks and the connection rate limit apply.'));
		o.value('http', _('HTTP reverse proxy'));
		o.value('passthrough', _('TLS passthrough'));
		o.default = 'http';

		o = s.taboption('general', form.ListValue, 'backend', _('Backend'));
		common.names('backend').forEach((n) => o.value(n));
		o.rmempty = false;

		o = s.taboption('tls', form.ListValue, 'acme_cert', _('ACME certificate'),
			_('A certificate of the acme package. It overrides the certificate file.'));
		o.value('', _('none'));
		(this.certs.acme || []).forEach((c) => o.value(c.name, '%s (%s)'.format(c.name, c.domains.join(', '))));
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.taboption('tls', form.Value, 'certificate', _('Certificate file'),
			_('PEM with the certificate chain and the private key.'));
		(this.certs.files || []).forEach((c) => o.value(c.path));
		o.validate = common.validators.file;
		o.depends({ mode: 'http', acme_cert: '' });
		o.modalonly = true;

		o = s.taboption('tls', form.Flag, 'hsts', _('HSTS'),
			_('Tell browsers to use HTTPS only for this host. Browsers remember it for the max-age, so enable it once HTTPS works.'));
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.taboption('tls', form.Value, 'hsts_max_age', _('HSTS max-age (seconds)'));
		o.placeholder = '31536000';
		o.datatype = 'uinteger';
		o.depends('hsts', '1');
		o.modalonly = true;

		o = s.taboption('tls', form.Flag, 'hsts_subdomains', _('Include subdomains'));
		o.depends('hsts', '1');
		o.modalonly = true;

		o = s.taboption('access', form.DynamicList, 'trusted_network', _('Trusted networks'),
			_('HTTP: these clients skip login and may use internal-only paths. Passthrough: only these clients may connect.'));
		o.validate = common.validators.network;
		o.modalonly = true;

		o = s.taboption('access', form.Value, 'rate_limit', _('Rate limit'),
			_('Requests per 10 seconds per client address; more get 429. Empty or 0: off.'));
		o.datatype = 'uinteger';
		o.placeholder = _('off');
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.taboption('access', form.Value, 'conn_rate_limit', _('Connection rate limit'),
			_('New connections per 10 seconds per client address. Empty or 0: off.'));
		o.datatype = 'uinteger';
		o.placeholder = _('off');
		o.depends('mode', 'passthrough');
		o.modalonly = true;

		o = s.taboption('access', form.ListValue, 'hardening', _('Hardening'),
			_('Deny ambiguous paths and replace forwarding headers sent by clients.'));
		o.value('', globalHardening ? _('As in Settings (on)') : _('As in Settings (off)'));
		o.value('1', _('On'));
		o.value('0', _('Off'));
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.taboption('paths', form.DynamicList, 'blocked_path', _('Blocked paths'),
			_('Denied for everyone, trusted networks included. Compared case-insensitively with the decoded path.'));
		o.validate = common.validators.path;
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.taboption('paths', form.DynamicList, 'internal_path', _('Internal-only paths'),
			_('Only trusted networks may use them; everyone else gets 403.'));
		o.validate = common.validators.path;
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.taboption('paths', form.DynamicList, 'public_path', _('Public paths (no login)'),
			_('Open without login. Compared exactly (case-sensitive) with the decoded path.'));
		o.validate = common.validators.path;
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.taboption('auth', form.ListValue, 'auth_group', _('Login group'),
			_('Ask for a login of a user of this group (Users tab).'));
		o.value('', _('No login'));
		common.names('auth_group').forEach((n) => o.value(n));
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.taboption('auth', form.Value, 'auth_fail_limit', _('Failed logins per minute'),
			_('From one client address; more get 429 until the rate drops. 0: off.'));
		o.datatype = 'uinteger';
		o.placeholder = '10';
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.taboption('headers', form.Flag, 'forward_headers', _('Forwarding headers'),
			_('Send X-Forwarded-For, X-Forwarded-Proto and X-Forwarded-Port to the server.'));
		o.default = '1';
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.taboption('headers', form.DynamicList, 'request_header', _('Extra request headers'),
			_('Headers set on requests to the server, as Name: value.'));
		o.validate = common.validators.header;
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.taboption('headers', form.Value, 'timeout_client', _('Idle client timeout'));
		o.placeholder = _('Listener or global setting');
		o.validate = common.validators.time;
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.taboption('advanced', form.TextValue, 'advanced', _('Extra rules'),
			_('http-request, http-response or http-after-response rules without a condition, one per line; they apply to this service only. They act with root rights.'));
		o.rows = 5;
		o.monospace = true;
		o.depends('mode', 'http');
		o.modalonly = true;

		o = s.option(form.DummyValue, '_summary', _('Access'));
		o.modalonly = false;
		o.textvalue = function(sid) {
			const g = (k) => uci.get(common.CONFIG, sid, k);
			const parts = [];

			if (g('mode') == 'passthrough')
				return _('passthrough');

			if (g('auth_group'))
				parts.push(_('login'));

			if (L.toArray(g('trusted_network')).length)
				parts.push(_('trusted networks'));

			if (L.toArray(g('public_path')).length || L.toArray(g('internal_path')).length || L.toArray(g('blocked_path')).length)
				parts.push(_('path rules'));

			if (+g('rate_limit') > 0)
				parts.push(_('rate limit'));

			return parts.length ? parts.join(', ') : _('open');
		};

		s = m.section(form.GridSection, 'rule', _('Custom rules'),
			_('Rules of one service, checked after blocked paths and before trusted networks, lowest order first. A rule matches when all of its criteria match.'));
		s.addremove = true;
		s.anonymous = true;
		s.nodescriptions = true;
		s.addbtntitle = _('Add rule');
		s.modaltitle = _('Rule');

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.editable = true;

		o = s.option(form.ListValue, 'service', _('Service'));
		common.names('service').forEach((n) => o.value(n));
		o.rmempty = false;

		o = s.option(form.Value, 'order', _('Order'));
		o.datatype = 'uinteger';
		o.placeholder = '100';

		o = s.option(form.ListValue, 'action', _('Action'));
		o.value('deny', _('Deny'));
		o.value('allow', _('Allow (skip the rest)'));
		o.value('auth', _('Ask for login'));
		o.rmempty = false;

		o = s.option(form.DynamicList, 'source', _('Client networks'));
		o.validate = common.validators.network;

		o = s.option(form.DynamicList, 'path', _('Path prefixes'));
		o.validate = common.validators.path;

		o = s.option(form.MultiValue, 'method', _('Methods'));
		[ 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'PROPFIND', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK' ].forEach((v) => o.value(v));
		o.modalonly = true;

		o = s.option(form.ListValue, 'deny_status', _('Answer'));
		[ '403', '404', '400', '401', '405', '429', '500', '503' ].forEach((v) => o.value(v));
		o.default = '403';
		o.depends('action', 'deny');
		o.modalonly = true;

		o = s.option(form.ListValue, 'auth_group', _('Login group'));
		o.value('', _('The service\'s group'));
		common.names('auth_group').forEach((n) => o.value(n));
		o.depends('action', 'auth');
		o.modalonly = true;

		return m.render();
	}
});
