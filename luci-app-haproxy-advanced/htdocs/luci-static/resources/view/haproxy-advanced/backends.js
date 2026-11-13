'use strict';
'require view';
'require form';
'require uci';
'require haproxy_advanced.common as common';

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(common.callStatus(), {}),
			uci.load(common.CONFIG)
		]);
	},

	render: function(data) {
		const status = data[0] || {};
		let m, s, o;

		common.watchApply(status);

		m = new form.Map(common.CONFIG, _('HAProxy Advanced: backends'),
			_('A backend is a pool of servers that receives a service\'s requests. A backend serves either HTTP services or passthrough services, not both.'));

		s = m.section(form.GridSection, 'backend', _('Backends'));
		s.addremove = true;
		s.anonymous = false;
		s.nodescriptions = true;
		s.addbtntitle = _('Add backend');
		s.modaltitle = (sid) => _('Backend') + ' » ' + sid;

		s.tab('general', _('General'));
		s.tab('check', _('Health check'));
		s.tab('timeouts', _('Timeouts'));
		s.tab('advanced', _('Advanced'));

		o = s.taboption('general', form.ListValue, 'balance', _('Balancing'));
		o.value('roundrobin', _('Round robin'));
		o.value('leastconn', _('Fewest connections'));
		o.value('source', _('By client address'));
		o.value('first', _('First available'));
		o.default = 'roundrobin';

		o = s.taboption('general', form.DummyValue, '_servers', _('Servers'));
		o.modalonly = false;
		o.textvalue = function(section_id) {
			const list = uci.sections(common.CONFIG, 'server')
				.filter((v) => v.backend == section_id && v.enabled != '0')
				.map((v) => '%s (%s:%s)'.format(v.name || '?', v.address || '?', v.port || '?'));

			return list.length ? list.join(', ') : _('none');
		};

		o = s.taboption('check', form.ListValue, 'health_check', _('Health check'));
		o.value('none', _('None'));
		o.value('tcp', _('TCP connect'));
		o.value('http', _('HTTP request'));
		o.default = 'none';

		o = s.taboption('check', form.ListValue, 'check_method', _('Method'));
		[ 'GET', 'HEAD', 'OPTIONS' ].forEach((v) => o.value(v));
		o.default = 'GET';
		o.depends('health_check', 'http');
		o.modalonly = true;

		o = s.taboption('check', form.Value, 'check_path', _('Path'));
		o.placeholder = '/';
		o.depends('health_check', 'http');
		o.modalonly = true;
		o.validate = function(section_id, value) {
			return (!value || /^\/[A-Za-z0-9._~!*+,;=:@\/?&-]*$/.test(value)) ? true : _('Expecting a path with an optional query');
		};

		o = s.taboption('check', form.Value, 'check_host', _('Host header'),
			_('Default: the first host name of a service that uses this backend.'));
		o.depends('health_check', 'http');
		o.modalonly = true;
		o.validate = common.validators.hostname;

		o = s.taboption('check', form.DynamicList, 'check_status', _('Accepted answers'),
			_('Status codes (200) or classes (2xx). Default: 2xx and 3xx.'));
		o.depends('health_check', 'http');
		o.modalonly = true;
		o.validate = function(section_id, value) {
			return (!value || /^[1-5]([0-9][0-9]|xx)$/.test(value)) ? true : _('Expecting a code like 200 or a class like 2xx');
		};

		o = s.taboption('check', form.Value, 'check_interval', _('Interval'));
		o.placeholder = '10s';
		o.validate = common.validators.time;
		o.depends('health_check', 'tcp');
		o.depends('health_check', 'http');
		o.modalonly = true;

		o = s.taboption('timeouts', form.Value, 'timeout_connect', _('Connect'));
		o.placeholder = _('Global setting');
		o.validate = common.validators.time;
		o.modalonly = true;

		o = s.taboption('timeouts', form.Value, 'timeout_server', _('Idle server'));
		o.placeholder = _('Global setting');
		o.validate = common.validators.time;
		o.modalonly = true;

		o = s.taboption('timeouts', form.Value, 'timeout_tunnel', _('WebSocket and passthrough idle'),
			_('Idle time of upgraded (WebSocket) and passthrough connections, for example 1h.'));
		o.validate = common.validators.time;
		o.modalonly = true;

		o = s.taboption('advanced', form.TextValue, 'advanced', _('Extra backend lines'),
			_('Lines added to the backend. They act with root rights.'));
		o.rows = 5;
		o.monospace = true;
		o.modalonly = true;

		s = m.section(form.GridSection, 'server', _('Servers'));
		s.addremove = true;
		s.anonymous = true;
		s.nodescriptions = true;
		s.addbtntitle = _('Add server');
		s.modaltitle = _('Server');

		s.tab('general', _('General'));
		s.tab('tls', _('TLS'));
		s.tab('more', _('More'));

		o = s.taboption('general', form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.editable = true;

		o = s.taboption('general', form.ListValue, 'backend', _('Backend'));
		common.names('backend').forEach((n) => o.value(n));
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'name', _('Name'));
		o.rmempty = false;
		o.validate = function(section_id, value) {
			return /^[A-Za-z0-9_.-]{1,48}$/.test(value || '') ? true : _('1-48 letters, digits, ., _ or -');
		};

		o = s.taboption('general', form.Value, 'address', _('Address'),
			_('IP address or host name (resolved when HAProxy starts).'));
		o.rmempty = false;
		o.datatype = 'host';

		o = s.taboption('general', form.Value, 'port', _('Port'));
		o.rmempty = false;
		o.datatype = 'port';

		o = s.taboption('tls', form.Flag, 'tls', _('TLS to the server'),
			_('Only for HTTP backends; passthrough backends receive the client\'s TLS as is.'));
		o.default = '0';

		o = s.taboption('tls', form.ListValue, 'verify', _('Certificate check'));
		o.value('none', _('None (private network)'));
		o.value('required', _('Required'));
		o.default = 'none';
		o.depends('tls', '1');

		o = s.taboption('tls', form.Value, 'ca_file', _('CA'),
			_('A CA file, or @system-ca for publicly trusted certificates.'));
		o.value('@system-ca', _('System CA bundle (@system-ca)'));
		o.depends({ tls: '1', verify: 'required' });
		o.rmempty = false;
		o.modalonly = true;
		o.validate = function(section_id, value) {
			return (value == '@system-ca') ? true : common.validators.file(section_id, value);
		};

		o = s.taboption('tls', form.Value, 'sni', _('SNI'),
			_('Name sent to the server: empty for none, "host" for the request\'s host name, or a fixed name.'));
		o.value('host', _('The request\'s host name'));
		o.depends('tls', '1');
		o.modalonly = true;
		o.validate = function(section_id, value) {
			return (!value || value == 'host') ? true : common.validators.hostname(section_id, value);
		};

		o = s.taboption('tls', form.Value, 'verifyhost', _('Expected certificate name'));
		o.depends({ tls: '1', verify: 'required' });
		o.modalonly = true;
		o.validate = common.validators.hostname;

		o = s.taboption('more', form.Value, 'weight', _('Weight'));
		o.datatype = 'range(0,256)';
		o.modalonly = true;

		o = s.taboption('more', form.Flag, 'backup', _('Backup'),
			_('Used only when all other servers are down.'));
		o.modalonly = true;

		o = s.taboption('more', form.Value, 'maxconn', _('Connection limit'));
		o.datatype = 'uinteger';
		o.modalonly = true;

		o = s.taboption('more', form.Flag, 'send_proxy', _('Send PROXY v2 header'),
			_('Only if the server expects it.'));
		o.modalonly = true;

		return m.render();
	}
});
