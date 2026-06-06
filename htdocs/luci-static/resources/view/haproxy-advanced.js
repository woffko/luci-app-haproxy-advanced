'use strict';
'require view';
'require form';
'require fs';
'require network';
'require uci';
'require ui';

var CONFIG = 'haproxy-advanced';

function byId(id) {
	return document.getElementById(id);
}

function valueOf(id) {
	var node = byId(id);
	return node ? (node.value || '').trim() : '';
}

function valuesOf(id) {
	var node = byId(id);
	var values = [];

	if (!node)
		return values;

	if (node.multiple) {
		Array.prototype.forEach.call(node.options, function(option) {
			if (option.selected && option.value)
				values.push(option.value);
		});

		return values;
	}

	return splitList(node.value);
}

function checked(id) {
	var node = byId(id);
	return node ? node.checked : false;
}

function setValue(id, value) {
	var node = byId(id);

	if (node)
		node.value = value || '';
}

function setChecked(id, value) {
	var node = byId(id);

	if (node)
		node.checked = !!value;
}

function splitList(value) {
	return (value || '')
		.split(/[\n,]+/)
		.map(function(v) { return v.trim(); })
		.filter(function(v) { return v !== ''; });
}

function uniqueList(values) {
	var seen = {};

	return values.filter(function(value) {
		if (!value || seen[value])
			return false;

		seen[value] = true;
		return true;
	});
}

function sanitizeName(value, fallback) {
	value = (value || fallback || 'ServiceExample').replace(/[^A-Za-z0-9_.-]/g, '_');
	value = value.replace(/^_+/, '').replace(/_+$/, '');
	return value || fallback || 'ServiceExample';
}

function addSection(type, values) {
	var sid = uci.add(CONFIG, type);

	Object.keys(values).forEach(function(key) {
		if (values[key] != null && values[key] !== '')
			uci.set(CONFIG, sid, key, values[key]);
	});

	return sid;
}

function optionText(values) {
	return values.map(function(item) {
		return E('option', { 'value': item[0] }, item[1]);
	});
}

function inputRow(id, label, placeholder, value, type) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': id }, label),
		E('div', { 'class': 'cbi-value-field' }, [
			E('input', {
				'id': id,
				'class': 'cbi-input-text',
				'type': type || 'text',
				'placeholder': placeholder || '',
				'value': value || ''
			})
		])
	]);
}

function textareaRow(id, label, placeholder, value) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': id }, label),
		E('div', { 'class': 'cbi-value-field' }, [
			E('textarea', {
				'id': id,
				'class': 'cbi-input-textarea',
				'rows': 3,
				'placeholder': placeholder || ''
			}, value || '')
		])
	]);
}

function selectRow(id, label, values, selected, attrs) {
	var selectAttrs = {
		'id': id,
		'class': 'cbi-input-select'
	};

	Object.assign(selectAttrs, attrs || {});

	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': id }, label),
		E('div', { 'class': 'cbi-value-field' }, [
			E('select', selectAttrs, optionText(values).map(function(node) {
				if (node.getAttribute('value') === selected)
					node.setAttribute('selected', 'selected');
				return node;
			}))
		])
	]);
}

function multiSelectRow(id, label, values, selected) {
	selected = selected || [];

	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': id }, label),
		E('div', { 'class': 'cbi-value-field' }, [
			E('select', {
				'id': id,
				'class': 'cbi-input-select',
				'multiple': 'multiple',
				'size': Math.min(Math.max(values.length, 3), 8)
			}, optionText(values).map(function(node) {
				if (selected.indexOf(node.getAttribute('value')) !== -1)
					node.setAttribute('selected', 'selected');
				return node;
			}))
		])
	]);
}

function checkboxRow(id, label, checkedValue) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': id }, label),
		E('div', { 'class': 'cbi-value-field' }, [
			E('input', {
				'id': id,
				'type': 'checkbox',
				'checked': checkedValue ? 'checked' : null
			})
		])
	]);
}

function buildListenChoices(networks) {
	var choices = [];
	var seen = {};

	function add(value, label) {
		if (!value || seen[value])
			return;

		seen[value] = true;
		choices.push([ value, label ]);
	}

	(networks || []).forEach(function(net) {
		var name = net.getName();
		var addrs = net.getIPAddrs();
		var label = name;

		if (!addrs.length)
			return;

		if (addrs.length)
			label += ' (' + addrs.join(', ') + ')';

		add(name + '_ipv4', label);
	});

	add('*', _('All interfaces (*)'));

	return choices.length ? choices : [[ 'wan_ipv4', _('WAN IPv4 address') ], [ '*', _('All interfaces (*)') ]];
}

function defaultListenChoice(choices) {
	var i;

	for (i = 0; i < choices.length; i++)
		if (choices[i][0] === 'wan_ipv4')
			return 'wan_ipv4';

	return choices.length ? choices[0][0] : '*';
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(CONFIG),
			L.resolveDefault(network.getNetworks(), [])
		]);
	},

	applyPreset: function() {
		var preset = valueOf('ha_preset') || 'generic_https';

		if (preset === 'nas_file') {
			setValue('ha_backend_proto', 'https');
			setValue('ha_backend_port', '443');
			setValue('ha_backend_verify', 'none');
			setChecked('ha_basic_auth', true);
			setValue('ha_public_paths', '/share/\n/share.cgi');
			setValue('ha_protected_paths', '/admin/\n/cgi-bin/QTS.cgi\n/cgi-bin/apps/fileManager/');
			setValue('ha_blocked_paths', '/cgi-bin/');
			setChecked('ha_hardening', true);
			setChecked('ha_rate_limit', false);
		}
		else if (preset === 'admin_panel') {
			setValue('ha_backend_proto', 'https');
			setValue('ha_backend_port', '443');
			setValue('ha_backend_verify', 'none');
			setChecked('ha_basic_auth', true);
			setValue('ha_public_paths', '');
			setValue('ha_protected_paths', '/');
			setValue('ha_blocked_paths', '');
			setChecked('ha_hardening', true);
			setChecked('ha_rate_limit', false);
		}
		else if (preset === 'home_assistant') {
			setValue('ha_backend_proto', 'http');
			setValue('ha_backend_port', '8123');
			setValue('ha_backend_verify', 'none');
			setChecked('ha_basic_auth', false);
			setValue('ha_public_paths', '');
			setValue('ha_protected_paths', '');
			setValue('ha_blocked_paths', '');
			setChecked('ha_hardening', true);
			setChecked('ha_rate_limit', false);
		}
		else if (preset === 'http_backend') {
			setValue('ha_backend_proto', 'http');
			setValue('ha_backend_port', '80');
			setValue('ha_backend_verify', 'none');
			setChecked('ha_basic_auth', true);
			setValue('ha_public_paths', '');
			setValue('ha_protected_paths', '/admin/');
			setValue('ha_blocked_paths', '/cgi-bin/');
			setChecked('ha_hardening', true);
			setChecked('ha_rate_limit', false);
		}
		else {
			setValue('ha_backend_proto', 'https');
			setValue('ha_backend_port', '443');
			setValue('ha_backend_verify', 'none');
			setChecked('ha_basic_auth', true);
			setValue('ha_public_paths', '');
			setValue('ha_protected_paths', '/admin/');
			setValue('ha_blocked_paths', '/cgi-bin/');
			setChecked('ha_hardening', true);
			setChecked('ha_rate_limit', false);
		}
	},

	renderWizard: function() {
		var listenChoices = this.listenAddressChoices || buildListenChoices([]);
		var defaultListen = defaultListenChoice(listenChoices);

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', _('Publish internal service')),
			selectRow('ha_preset', _('Preset'), [
				[ 'generic_https', _('Generic HTTPS backend') ],
				[ 'nas_file', _('NAS / file-share example preset') ],
				[ 'admin_panel', _('Web admin panel') ],
				[ 'home_assistant', _('Home Assistant / WebSocket service') ],
				[ 'http_backend', _('Plain HTTP backend behind HTTPS frontend') ]
			], 'generic_https', { 'change': ui.createHandlerFn(this, this.applyPreset) }),
			inputRow('ha_service', _('Service name'), 'ServiceExample', 'ServiceExample'),
			inputRow('ha_hostname', _('Published hostname'), 'service.example.com', 'service.example.com'),
			multiSelectRow('ha_listen_addresses', _('Listen on'), listenChoices, [ defaultListen ]),
			textareaRow('ha_listen_custom_addresses', _('Custom listen addresses'), '203.0.113.10\nopt4_ipv4', ''),
			inputRow('ha_listen_port', _('Listen port'), '443', '443'),
			selectRow('ha_cert_mode', _('Certificate mode'), [
				[ 'pem', _('HAProxy PEM') ],
				[ 'acme_combined', _('OpenWrt ACME combined PEM') ],
				[ 'split', _('ACME fullchain + key') ]
			], 'pem'),
			inputRow('ha_certificate', _('Certificate path'), '/etc/haproxy/certs/service-example.pem', '/etc/haproxy/certs/service-example.pem'),
			inputRow('ha_fullchain', _('ACME fullchain path'), '/etc/acme/service.example.com/fullchain.cer', ''),
			inputRow('ha_key', _('ACME key path'), '/etc/acme/service.example.com/service.example.com.key', ''),
			selectRow('ha_backend_proto', _('Backend protocol'), [
				[ 'https', _('HTTPS') ],
				[ 'http', _('HTTP') ]
			], 'https'),
			inputRow('ha_backend_address', _('Backend address'), '192.168.10.2', '192.168.10.2'),
			inputRow('ha_backend_port', _('Backend port'), '443', '443'),
			selectRow('ha_backend_verify', _('Backend certificate verification'), [
				[ 'required', _('Verify required') ],
				[ 'none', _('Verify none') ]
			], 'none'),
			checkboxRow('ha_basic_auth', _('Require Basic Auth'), true),
			inputRow('ha_auth_user', _('Basic Auth username'), 'user1', 'user1'),
			inputRow('ha_auth_hash', _('Basic Auth password hash'), '$2y$10$REPLACE_ME', '$2y$10$REPLACE_ME', 'password'),
			textareaRow('ha_trusted_networks', _('Allowed internal networks'), '192.168.20.0/24', '192.168.20.0/24'),
			textareaRow('ha_public_paths', _('Public paths'), '/share/', ''),
			textareaRow('ha_protected_paths', _('Protected paths'), '/admin/', '/admin/'),
			textareaRow('ha_blocked_paths', _('Blocked paths'), '/cgi-bin/', '/cgi-bin/'),
			checkboxRow('ha_hardening', _('Enable basic hardening'), true),
			checkboxRow('ha_rate_limit', _('Enable rate limiting'), false),
			inputRow('ha_rate_limit_requests', _('Requests per 10 seconds'), '30', '30'),
			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', {
					'class': 'cbi-button cbi-button-add',
					'click': ui.createHandlerFn(this, this.createService)
				}, _('Create'))
			])
		]);
	},

	createService: function() {
		var preset = valueOf('ha_preset');
		var service = sanitizeName(valueOf('ha_service'), 'ServiceExample');
		var hostname = valueOf('ha_hostname');
		var listenAddresses = uniqueList(valuesOf('ha_listen_addresses').concat(splitList(valueOf('ha_listen_custom_addresses'))));
		var listenPort = valueOf('ha_listen_port') || '443';
		var certMode = valueOf('ha_cert_mode') || 'pem';
		var certificate = valueOf('ha_certificate');
		var fullchain = valueOf('ha_fullchain');
		var key = valueOf('ha_key');
		var backendProto = valueOf('ha_backend_proto') || 'https';
		var backendAddress = valueOf('ha_backend_address');
		var backendPort = valueOf('ha_backend_port') || (backendProto === 'https' ? '443' : '80');
		var backendVerify = valueOf('ha_backend_verify') || 'none';
		var requireAuth = checked('ha_basic_auth');
		var username = sanitizeName(valueOf('ha_auth_user'), 'user1');
		var passwordHash = valueOf('ha_auth_hash') || '$2y$10$REPLACE_ME';
		var trustedNetworks = splitList(valueOf('ha_trusted_networks'));
		var publicPaths = splitList(valueOf('ha_public_paths'));
		var protectedPaths = splitList(valueOf('ha_protected_paths'));
		var blockedPaths = splitList(valueOf('ha_blocked_paths'));
		var hardening = checked('ha_hardening') ? '1' : '0';
		var rateLimit = checked('ha_rate_limit') ? '1' : '0';
		var rateLimitRequests = valueOf('ha_rate_limit_requests') || '30';
		var backend = sanitizeName(service + '_' + backendProto + '_backend', 'service_backend');
		var userlist = sanitizeName(service + 'Users', 'ServiceUsers');
		var actionOrder = 10;
		var i;
		var advancedFrontend = '';
		var advancedBackend = '';

		if (!hostname || !backendAddress || listenAddresses.length === 0) {
			ui.addNotification(null, E('p', _('Service name, published hostname, listen address and backend address are required.')), 'danger');
			return Promise.resolve();
		}

		if (preset === 'home_assistant') {
			advancedFrontend = 'timeout client 1h\ntimeout tunnel 1h';
			advancedBackend = 'timeout server 1h';
		}

		uci.set(CONFIG, 'global', 'enabled', '1');

		addSection('frontend', {
			'name': service,
			'enabled': '1',
			'mode': 'http',
			'default_backend': backend,
			'http_connection_mode': 'http-keep-alive',
			'forwardfor': '1',
			'certificate_mode': certMode,
			'certificate': certificate,
			'certificate_fullchain': fullchain,
			'certificate_key': key,
			'hardening': hardening,
			'rate_limit_enabled': rateLimit,
			'rate_limit_requests': rateLimitRequests,
			'advanced_frontend': advancedFrontend
		});

		for (i = 0; i < listenAddresses.length; i++) {
			addSection('bind', {
				'frontend': service,
				'name': sanitizeName('bind_' + (i + 1), 'bind_1'),
				'address': listenAddresses[i],
				'port': listenPort,
				'ssl': '1'
			});
		}

		addSection('backend', {
			'name': backend,
			'mode': 'http',
			'balance': 'none',
			'check_type': 'none',
			'advanced_backend': advancedBackend
		});

		addSection('server', {
			'backend': backend,
			'name': 'backend1',
			'address': backendAddress,
			'port': backendPort,
			'ssl': backendProto === 'https' ? '1' : '0',
			'verify': backendProto === 'https' ? backendVerify : 'none',
			'enabled': '1'
		});

		addSection('acl', {
			'frontend': service,
			'name': 'published_host',
			'type': 'host_matches',
			'value': hostname
		});

		addSection('action', {
			'frontend': service,
			'order': String(actionOrder),
			'action': 'deny',
			'condition': '!published_host',
			'deny_status': '403'
		});
		actionOrder += 10;

		if (trustedNetworks.length > 0) {
			addSection('acl', {
				'frontend': service,
				'name': 'trusted_internal_net',
				'type': 'source_ip',
				'value': trustedNetworks.join(' ')
			});

			addSection('action', {
				'frontend': service,
				'order': String(actionOrder),
				'action': 'allow',
				'condition': 'trusted_internal_net'
			});
			actionOrder += 10;
		}

		if (protectedPaths.length > 0) {
			addSection('acl', {
				'frontend': service,
				'name': 'admin_path',
				'type': 'path_starts_with',
				'value': protectedPaths.join(' ')
			});

			addSection('action', {
				'frontend': service,
				'order': String(actionOrder),
				'action': 'deny',
				'condition': trustedNetworks.length > 0 ? '!trusted_internal_net admin_path' : 'admin_path',
				'deny_status': '403'
			});
			actionOrder += 10;
		}

		if (publicPaths.length > 0) {
			addSection('acl', {
				'frontend': service,
				'name': 'public_path',
				'type': 'path_starts_with',
				'value': publicPaths.join(' ')
			});

			addSection('action', {
				'frontend': service,
				'order': String(actionOrder),
				'action': 'allow',
				'condition': 'public_path'
			});
			actionOrder += 10;
		}

		if (requireAuth) {
			addSection('userlist', { 'name': userlist });
			addSection('user', {
				'userlist': userlist,
				'username': username,
				'password_hash': passwordHash,
				'enabled': '1'
			});
			addSection('acl', {
				'frontend': service,
				'name': 'auth_ok',
				'type': 'custom',
				'value': 'http_auth(' + userlist + ')'
			});
			addSection('action', {
				'frontend': service,
				'order': String(actionOrder),
				'action': 'auth',
				'realm': userlist,
				'unless': 'auth_ok'
			});
			actionOrder += 10;
		}

		if (blockedPaths.length > 0) {
			addSection('acl', {
				'frontend': service,
				'name': 'blocked_path',
				'type': 'path_starts_with',
				'value': blockedPaths.join(' ')
			});
			addSection('action', {
				'frontend': service,
				'order': String(actionOrder),
				'action': 'deny',
				'condition': 'blocked_path',
				'deny_status': '403'
			});
		}

		return uci.save().then(function() {
			ui.addNotification(null, E('p', _('Service has been created. Review generated sections, then validate and reload HAProxy Advanced.')), 'info');
			window.setTimeout(function() { window.location.reload(); }, 800);
		}).catch(function(e) {
			ui.addNotification(null, E('p', _('Unable to save generated service: %s').format(e.message)), 'danger');
		});
	},

	renderOperations: function() {
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', _('Status and generated config')),
			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', {
					'class': 'cbi-button cbi-button-neutral',
					'click': ui.createHandlerFn(this, this.runCommand, 'status')
				}, _('Status')),
				' ',
				E('button', {
					'class': 'cbi-button cbi-button-neutral',
					'click': ui.createHandlerFn(this, this.runCommand, 'preview')
				}, _('Preview config')),
				' ',
				E('button', {
					'class': 'cbi-button cbi-button-neutral',
					'click': ui.createHandlerFn(this, this.runCommand, 'validate')
				}, _('Validate config')),
				' ',
				E('button', {
					'class': 'cbi-button cbi-button-apply',
					'click': ui.createHandlerFn(this, this.runCommand, 'reload')
				}, _('Reload safely')),
				' ',
				E('button', {
					'class': 'cbi-button cbi-button-neutral',
					'click': ui.createHandlerFn(this, this.runCommand, 'logs')
				}, _('Logs'))
			]),
			E('pre', {
				'id': 'ha_output',
				'style': 'min-height:12em; overflow:auto; white-space:pre-wrap'
			}, '')
		]);
	},

	runCommand: function(command) {
		var output = byId('ha_output');

		if (output)
			output.textContent = _('Running %s...').format(command);

		return fs.exec('/etc/init.d/haproxy-advanced', [ command ]).then(function(res) {
			if (output)
				output.textContent = (res.stdout || '') + (res.stderr || '');
		}).catch(function(e) {
			if (output)
				output.textContent = e.message || String(e);
		});
	},

	addGlobalSection: function(m) {
		var s, o;

		s = m.section(form.NamedSection, 'global', 'global', _('Global settings'));
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('Enable HAProxy Advanced'));
		o.rmempty = false;

		o = s.option(form.Value, 'maxconn', _('Maximum connections'));
		o.datatype = 'uinteger';
		o.placeholder = '1000';

		o = s.option(form.Value, 'log_facility', _('Log facility'));
		o.placeholder = 'local0';

		o = s.option(form.Value, 'log_level', _('Log level'));
		o.placeholder = 'info';

		o = s.option(form.Flag, 'stats_enabled', _('Enable stats listener'));
		o.rmempty = false;

		o = s.option(form.Value, 'stats_bind', _('Stats bind'));
		o.placeholder = '127.0.0.1:2200';
		o.depends('stats_enabled', '1');

		o = s.option(form.Value, 'stats_uri', _('Stats URI'));
		o.placeholder = '/';
		o.depends('stats_enabled', '1');

		o = s.option(form.Value, 'ssl_default_dh_param', _('Default DH parameter size'));
		o.datatype = 'uinteger';
		o.placeholder = '2048';

		o = s.option(form.Flag, 'hardening', _('Enable basic hardening by default'));
		o.rmempty = false;

		o = s.option(form.Flag, 'dontlog_normal', _('Do not log normal requests'));
		o.rmempty = false;

		o = s.option(form.Flag, 'log_separate_errors', _('Log errors separately'));
		o.rmempty = false;

		o = s.option(form.Flag, 'log_detailed', _('Detailed HTTP logs'));
		o.rmempty = false;

		o = s.option(form.TextValue, 'advanced_global', _('Advanced global directives'));
		o.rows = 4;
	},

	addFrontendSections: function(m) {
		var s, o;

		s = m.section(form.GridSection, 'frontend', _('Frontends'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;

		o = s.option(form.Value, 'name', _('Frontend'));
		o.rmempty = false;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'mode', _('Mode'));
		o.value('http', _('HTTP'));
		o.default = 'http';
		o.rmempty = false;

		o = s.option(form.Value, 'default_backend', _('Default backend'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'http_connection_mode', _('HTTP connection mode'));
		o.value('', _('Default'));
		o.value('http-keep-alive', _('Keep alive'));
		o.value('httpclose', _('Close'));
		o.value('http-server-close', _('Server close'));

		o = s.option(form.Flag, 'forwardfor', _('X-Forwarded-For'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'certificate_mode', _('Certificate mode'));
		o.value('pem', _('HAProxy PEM'));
		o.value('acme_combined', _('OpenWrt ACME combined PEM'));
		o.value('split', _('ACME fullchain + key'));
		o.default = 'pem';
		o.rmempty = false;

		o = s.option(form.Value, 'certificate', _('Certificate path'));
		o.placeholder = '/etc/haproxy/certs/service.pem';

		o = s.option(form.Value, 'certificate_fullchain', _('ACME fullchain path'));
		o.depends('certificate_mode', 'split');

		o = s.option(form.Value, 'certificate_key', _('ACME key path'));
		o.depends('certificate_mode', 'split');
		o.password = true;

		o = s.option(form.Flag, 'hardening', _('Basic hardening'));
		o.rmempty = true;

		o = s.option(form.Flag, 'rate_limit_enabled', _('Rate limiting'));
		o.rmempty = false;

		o = s.option(form.Value, 'rate_limit_requests', _('Requests per 10 seconds'));
		o.datatype = 'uinteger';
		o.depends('rate_limit_enabled', '1');

		o = s.option(form.TextValue, 'advanced_frontend', _('Advanced frontend directives'));
		o.rows = 4;
	},

	addBindSections: function(m) {
		var s, o, i;
		var listenChoices = this.listenAddressChoices || buildListenChoices([]);

		s = m.section(form.GridSection, 'bind', _('Frontend binds'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;

		o = s.option(form.Value, 'frontend', _('Frontend'));
		o.rmempty = false;

		o = s.option(form.Value, 'name', _('Bind name'));
		o.rmempty = false;

		o = s.option(form.Value, 'address', _('Bind address/interface'));
		o.placeholder = 'wan_ipv4';
		o.rmempty = false;
		for (i = 0; i < listenChoices.length; i++)
			o.value(listenChoices[i][0], listenChoices[i][1]);

		o = s.option(form.Value, 'port', _('Port'));
		o.datatype = 'port';
		o.placeholder = '443';
		o.rmempty = false;

		o = s.option(form.Flag, 'ssl', _('TLS'));
		o.rmempty = false;

		o = s.option(form.Value, 'certificate', _('Certificate override'));
		o.depends('ssl', '1');
	},

	addBackendSections: function(m) {
		var s, o;

		s = m.section(form.GridSection, 'backend', _('Backends'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;

		o = s.option(form.Value, 'name', _('Backend'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'mode', _('Mode'));
		o.value('http', _('HTTP'));
		o.default = 'http';

		o = s.option(form.ListValue, 'balance', _('Balance'));
		o.value('none', _('None'));
		o.value('roundrobin', _('Round robin'));
		o.value('leastconn', _('Least connections'));
		o.value('source', _('Source'));
		o.value('first', _('First'));
		o.default = 'none';

		o = s.option(form.TextValue, 'advanced_backend', _('Advanced backend directives'));
		o.rows = 4;
	},

	addServerSections: function(m) {
		var s, o;

		s = m.section(form.GridSection, 'server', _('Backend servers'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;

		o = s.option(form.Value, 'backend', _('Backend'));
		o.rmempty = false;

		o = s.option(form.Value, 'name', _('Server'));
		o.rmempty = false;

		o = s.option(form.Value, 'address', _('Address'));
		o.rmempty = false;

		o = s.option(form.Value, 'port', _('Port'));
		o.datatype = 'port';
		o.rmempty = false;

		o = s.option(form.Flag, 'ssl', _('HTTPS backend'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'verify', _('Backend certificate verification'));
		o.value('required', _('Verify required'));
		o.value('none', _('Verify none'));
		o.default = 'none';
		o.depends('ssl', '1');

		o = s.option(form.Value, 'ca_file', _('CA file'));
		o.depends('verify', 'required');

		o = s.option(form.Flag, 'check', _('Health check'));
		o.rmempty = false;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.rmempty = false;
	},

	addAclSections: function(m) {
		var s, o;

		s = m.section(form.GridSection, 'acl', _('ACLs'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;

		o = s.option(form.Value, 'frontend', _('Frontend'));
		o.rmempty = false;

		o = s.option(form.Value, 'name', _('ACL name'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'type', _('Type'));
		o.value('host_matches', _('Published hostname'));
		o.value('source_ip', _('Source IP/network'));
		o.value('path_starts_with', _('Path starts with'));
		o.value('custom', _('Authentication group'));
		o.rmempty = false;

		o = s.option(form.Value, 'value', _('Value'));
		o.rmempty = false;
	},

	addActionSections: function(m) {
		var s, o;

		s = m.section(form.GridSection, 'action', _('Ordered actions'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;

		o = s.option(form.Value, 'frontend', _('Frontend'));
		o.rmempty = false;

		o = s.option(form.Value, 'order', _('Order'));
		o.datatype = 'uinteger';
		o.rmempty = false;

		o = s.option(form.ListValue, 'action', _('Action'));
		o.value('allow', _('Allow'));
		o.value('deny', _('Deny'));
		o.value('auth', _('Basic Auth'));
		o.rmempty = false;

		o = s.option(form.Value, 'condition', _('Condition'));

		o = s.option(form.Value, 'unless', _('Unless'));
		o.depends('action', 'auth');

		o = s.option(form.Value, 'realm', _('Authentication group'));
		o.depends('action', 'auth');

		o = s.option(form.Value, 'deny_status', _('Deny status'));
		o.datatype = 'uinteger';
		o.depends('action', 'deny');
	},

	addAuthSections: function(m) {
		var s, o;

		s = m.section(form.GridSection, 'userlist', _('Authentication groups'));
		s.addremove = true;
		s.anonymous = true;

		o = s.option(form.Value, 'name', _('Authentication group'));
		o.rmempty = false;

		s = m.section(form.GridSection, 'user', _('Basic Auth users'));
		s.addremove = true;
		s.anonymous = true;

		o = s.option(form.Value, 'userlist', _('Authentication group'));
		o.rmempty = false;

		o = s.option(form.Value, 'username', _('Username'));
		o.rmempty = false;

		o = s.option(form.Value, 'password_hash', _('Password hash'));
		o.password = true;
		o.modalonly = true;
		o.rmempty = false;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.rmempty = false;
	},

	render: function(data) {
		var m = new form.Map(CONFIG, _('HAProxy Advanced'), _('Generic HAProxy HTTP/HTTPS reverse proxy and security gateway.'));

		this.listenAddressChoices = buildListenChoices(data ? data[1] : []);

		this.addGlobalSection(m);
		this.addFrontendSections(m);
		this.addBindSections(m);
		this.addBackendSections(m);
		this.addServerSections(m);
		this.addAclSections(m);
		this.addActionSections(m);
		this.addAuthSections(m);

		return m.render().then(L.bind(function(mapNode) {
			return E([
				this.renderWizard(),
				this.renderOperations(),
				mapNode
			]);
		}, this));
	}
});
