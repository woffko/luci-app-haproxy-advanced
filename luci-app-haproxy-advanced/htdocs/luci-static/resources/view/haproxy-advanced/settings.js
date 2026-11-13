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

		m = new form.Map(common.CONFIG, _('HAProxy Advanced: settings'),
			_('Settings that apply to the whole service. Every change is checked with <code>haproxy -c</code> before it is applied; a configuration that fails keeps the running one in place.'));

		s = m.section(form.NamedSection, 'global', 'global');
		s.addremove = false;
		s.tab('general', _('General'));
		s.tab('timeouts', _('Timeouts'));
		s.tab('logging', _('Logging'));
		s.tab('advanced', _('Advanced'));

		o = s.taboption('general', form.Flag, 'enabled', _('Enable HAProxy Advanced'));
		o.rmempty = false;

		o = s.taboption('general', form.Flag, 'hardening', _('Hardening by default'),
			_('Default of each service: deny ambiguous paths (<code>//</code>, <code>/../</code>, encoded dots and slashes) and replace forwarding headers sent by clients. A service can override it.'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'maxconn', _('Connection limit'),
			_('Connections HAProxy accepts at the same time.'));
		o.datatype = 'range(1,1000000)';
		o.placeholder = '2000';

		o = s.taboption('general', form.Value, 'acme_challenge_port', _('ACME challenge port'),
			_('Local port of acme.sh while it validates a certificate. HTTP companion listeners send <code>/.well-known/acme-challenge/</code> there.'));
		o.datatype = 'port';
		o.placeholder = '18402';

		o = s.taboption('timeouts', form.Value, 'timeout_connect', _('Connect to servers'));
		o.placeholder = '5s';
		o.validate = common.validators.time;

		o = s.taboption('timeouts', form.Value, 'timeout_client', _('Idle client'));
		o.placeholder = '60s';
		o.validate = common.validators.time;

		o = s.taboption('timeouts', form.Value, 'timeout_server', _('Idle server'));
		o.placeholder = '60s';
		o.validate = common.validators.time;

		o = s.taboption('timeouts', form.Value, 'timeout_http_request', _('Request headers'),
			_('Time a client has to send its complete request headers. Short values stop slow-header attacks.'));
		o.placeholder = '10s';
		o.validate = common.validators.time;

		o = s.taboption('timeouts', form.Value, 'timeout_http_keep_alive', _('Keep-alive'),
			_('Idle time between two requests on one connection.'));
		o.placeholder = '10s';
		o.validate = common.validators.time;

		o = s.taboption('logging', form.ListValue, 'log_requests', _('Log requests'));
		o.value('errors', _('Errors only'));
		o.value('all', _('All requests'));
		o.value('none', _('None'));
		o.default = 'errors';

		o = s.taboption('logging', form.ListValue, 'log_level', _('Log level'));
		[ 'emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug' ].forEach((l) => o.value(l));
		o.default = 'info';

		o = s.taboption('advanced', form.TextValue, 'advanced', _('Extra global lines'),
			_('Lines added to HAProxy\'s <code>global</code> section, one per line. They act with root rights: anyone who can edit them controls the router.'));
		o.rows = 6;
		o.monospace = true;

		return m.render();
	}
});
