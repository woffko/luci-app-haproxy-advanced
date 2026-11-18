'use strict';
'require view';
'require form';
'require uci';
'require network';
'require tools.widgets as widgets';
'require haproxy_advanced.common as common';

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(common.callStatus(), {}),
			L.resolveDefault(network.getNetworks(), []),
			L.resolveDefault(common.callCertificates(), { files: [] }),
			uci.load(common.CONFIG)
		]);
	},

	render: function(data) {
		const status = data[0] || {};
		const choices = common.addressChoices(data[1]);
		const certs = (data[2] && data[2].files) || [];
		let m, s, o;

		common.watchApply(status);

		m = new form.Map(common.CONFIG, _('HAProxy Advanced: listeners'),
			_('A listener is an entry point: addresses and a port. Several services share one listener and are told apart by host name (and by SNI for TLS). Two listeners cannot use the same address and port.'));

		s = m.section(form.GridSection, 'listener');
		s.addremove = true;
		s.anonymous = false;
		s.nodescriptions = true;
		s.addbtntitle = _('Add listener');
		s.modaltitle = (sid) => _('Listener') + ' » ' + sid;
		s.renderSectionPlaceholder = () => E('em', _('No listener yet. The "Add service" dialog on the Services tab can create one.'));

		s.tab('general', _('General'));
		s.tab('tls', _('TLS'));
		s.tab('firewall', _('Firewall'));
		s.tab('advanced', _('Advanced'));

		o = s.taboption('general', form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.editable = true;

		o = s.taboption('general', form.DynamicList, 'address', _('Addresses'),
			_('Interfaces (their current addresses, followed when they change), IP addresses, or * for any address.'));
		choices.forEach((c) => o.value(c[0], c[1]));
		o.default = '*';
		o.validate = function(section_id, value) {
			if (!value || value == '*' || common.isIPv4(value) || common.isIPv6(value) || /^[A-Za-z0-9_]{1,31}$/.test(value))
				return true;

			return _('Expecting an interface name, an IP address or *');
		};
		o.textvalue = function(section_id) {
			return (uci.get(common.CONFIG, section_id, 'address') || [ '*' ]).join(', ');
		};

		o = s.taboption('general', form.ListValue, 'family', _('Address family'),
			_('Which addresses of the interfaces (and of *) are used.'));
		o.value('ipv4', _('IPv4'));
		o.value('ipv6', _('IPv6'));
		o.value('any', _('IPv4 and IPv6'));
		o.default = 'ipv4';
		o.modalonly = true;

		o = s.taboption('general', form.ListValue, 'bind_mode', _('Bind'),
			_('"To the interfaces\' devices" listens on any address of their network devices, so a changing WAN address needs no reload.'));
		o.value('address', _('To the addresses'));
		o.value('device', _('To the interfaces\' devices'));
		o.default = 'address';
		o.modalonly = true;

		o = s.taboption('general', form.Value, 'port', _('Port'));
		o.datatype = 'port';
		o.rmempty = false;
		o.placeholder = '443';

		o = s.taboption('general', form.Value, 'timeout_client', _('Idle client timeout'));
		o.placeholder = _('Global setting');
		o.validate = common.validators.time;
		o.modalonly = true;

		o = s.taboption('tls', form.Flag, 'tls', _('TLS'),
			_('Terminate HTTPS here, or pass TLS through for passthrough services.'));
		o.default = '1';

		o = s.taboption('tls', form.Flag, 'http2', _('HTTP/2'));
		o.default = '1';
		o.depends('tls', '1');
		o.modalonly = true;

		o = s.taboption('tls', form.Value, 'redirect_port', _('HTTP companion port'),
			_('Plain HTTP port on the same addresses: answers ACME challenges and redirects to HTTPS. Usually 80; needed for ACME HTTP validation.'));
		o.datatype = 'port';
		o.depends('tls', '1');
		o.placeholder = _('none');

		o = s.taboption('tls', form.Value, 'default_certificate', _('Default certificate'),
			_('Sent to clients whose SNI matches no service. Default: the first service\'s certificate.'));
		certs.forEach((c) => o.value(c.path));
		o.validate = common.validators.file;
		o.depends('tls', '1');
		o.modalonly = true;

		o = s.taboption('firewall', form.Flag, 'firewall', _('Open in firewall'),
			_('Accept the listener\'s ports from the zone below while the service runs. The rule is not written into /etc/config/firewall.'));
		o.default = '0';

		o = s.taboption('firewall', widgets.ZoneSelect, 'firewall_zone', _('From zone'));
		o.default = 'wan';
		o.depends('firewall', '1');
		o.modalonly = true;

		o = s.taboption('advanced', form.TextValue, 'advanced', _('Extra frontend lines'),
			_('Lines added to the listener\'s frontend. They act with root rights.'));
		o.rows = 5;
		o.monospace = true;
		o.modalonly = true;

		o = s.option(form.DummyValue, '_services', _('Services'));
		o.modalonly = false;
		o.textvalue = function(section_id) {
			const names = uci.sections(common.CONFIG, 'service')
				.filter((sv) => sv.listener == section_id)
				.map((sv) => sv['.name']);

			return names.length ? names.join(', ') : _('none');
		};

		return m.render();
	}
});
