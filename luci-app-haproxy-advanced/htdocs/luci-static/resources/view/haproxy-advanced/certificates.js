'use strict';
'require view';
'require uci';
'require ui';
'require haproxy_advanced.common as common';

function table(headers, rows) {
	return E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr table-titles' }, headers.map((h) => E('th', { 'class': 'th' }, h)))
	].concat(rows.map((r) => E('tr', { 'class': 'tr' }, r.map((c) => E('td', { 'class': 'td' }, c))))));
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(common.callStatus(), {}),
			L.resolveDefault(common.callCertificates(), { files: [], acme: [] }),
			uci.load(common.CONFIG),
			L.resolveDefault(uci.load('acme'), null)
		]);
	},

	// Create an ACME certificate for a service's host names. Validation runs over
	// HTTP-01 through the listener's HTTP companion port, with acme.sh's
	// standalone server on the local ACME challenge port.
	issueDialog: function(status, certs) {
		const services = uci.sections(common.CONFIG, 'service').filter((s) => s.mode != 'passthrough');
		const accountEmail = certs.account_email;

		if (!services.length)
			return ui.addNotification(null, E('p', _('Add an HTTP service first.')), 'warning');

		const sel = E('select', { 'class': 'cbi-input-select' }, services.map((s) =>
			E('option', { 'value': s['.name'] }, '%s (%s)'.format(s['.name'], L.toArray(s.hostname).join(', ')))));
		const email = E('input', { 'class': 'cbi-input-text', 'type': 'email', 'value': accountEmail || '', 'placeholder': 'admin@example.com' });
		const staging = E('input', { 'type': 'checkbox' });
		const server = E('input', { 'class': 'cbi-input-text', 'placeholder': _('Let\'s Encrypt') });
		const err = E('div', { 'class': 'alert-message warning', 'style': 'display:none' });

		const row = (label, widget, desc) => E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, label),
			E('div', { 'class': 'cbi-value-field' }, [ widget, desc ? E('div', { 'class': 'cbi-value-description' }, desc) : '' ])
		]);

		const create = () => {
			const svc = sel.value;
			const hosts = L.toArray(uci.get(common.CONFIG, svc, 'hostname'));
			const listener = uci.get(common.CONFIG, svc, 'listener');
			const problems = [];

			if (!/^[^\s@]+@[^\s@]+$/.test(email.value))
				problems.push(_('Enter the account e-mail.'));

			if (server.value && !/^https:\/\/[A-Za-z0-9.:\/_-]+$/.test(server.value))
				problems.push(_('The ACME server must be an https:// URL.'));

			if (!listener || !uci.get(common.CONFIG, listener, 'redirect_port'))
				problems.push(_('Listener %s has no HTTP companion port. Let\'s Encrypt validates over HTTP on port 80: set the companion port on the Listeners tab first.').format(listener || '?'));

			if (problems.length) {
				err.replaceChildren(E('ul', {}, problems.map((p) => E('li', {}, p))));
				err.style.display = '';
				return;
			}

			let cert = svc;

			for (let i = 2; uci.get('acme', cert); i++)
				cert = svc + '_' + i;

			if (!uci.sections('acme', 'acme').length)
				uci.add('acme', 'acme');

			uci.set('acme', uci.sections('acme', 'acme')[0]['.name'], 'account_email', email.value);
			uci.add('acme', 'cert', cert);
			uci.set('acme', cert, 'enabled', '1');
			uci.set('acme', cert, 'domains', hosts);
			uci.set('acme', cert, 'validation_method', 'standalone');
			uci.set('acme', cert, 'listen_port', uci.get(common.CONFIG, 'global', 'acme_challenge_port') || '18402');
			uci.set('acme', cert, 'key_type', 'ec256');

			if (staging.checked)
				uci.set('acme', cert, 'staging', '1');

			if (server.value)
				uci.set('acme', cert, 'acme_server', server.value);

			uci.set(common.CONFIG, svc, 'acme_cert', cert);

			return uci.save().then(() => {
				ui.hideModal();
				ui.addNotification(null, E('p', _('Certificate %s is prepared. Save & Apply starts the issue; the service starts using the certificate as soon as it exists.').format(cert)), 'info');
				window.setTimeout(() => window.location.reload(), 1500);
			});
		};

		ui.showModal(_('Issue a certificate'), [
			E('p', _('The certificate covers all host names of the service. While it is issued, acme.sh answers the challenge on the local ACME port and the listener\'s HTTP companion forwards it there.')),
			row(_('Service'), sel),
			row(_('Account e-mail'), email, _('Let\'s Encrypt sends expiry notices here.')),
			row(_('Staging server'), staging, _('Test certificates that browsers do not trust; use this to try the setup.')),
			row(_('Other ACME server'), server, _('Empty for Let\'s Encrypt.')),
			err,
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
				E('button', { 'class': 'btn cbi-button-positive', 'click': ui.createHandlerFn(this, create) }, _('Prepare'))
			])
		]);
	},

	render: function(data) {
		const status = data[0] || {};
		const certs = data[1] || { files: [], acme: [] };
		const used = {};
		const logBox = E('pre', { 'style': 'white-space:pre-wrap; max-height:20em; overflow:auto; display:none' });

		common.watchApply(status);

		uci.sections(common.CONFIG, 'service').forEach((s) => {
			const key = s.acme_cert ? 'acme:' + s.acme_cert : s.certificate;

			if (key)
				(used[key] = used[key] || []).push(s['.name']);
		});

		const fileRows = (certs.files || []).map((c) => [
			E('code', {}, c.path),
			c.expires || E('em', {}, _('not loaded by HAProxy')),
			(used[c.path] || []).join(', ') || '-'
		]);

		const nodes = [
			E('h2', {}, _('HAProxy Advanced: certificates')),
			E('p', { 'class': 'cbi-map-descr' }, _('Certificates HAProxy can serve: PEM files that hold the chain and the private key, in /etc/haproxy/certs and /etc/ssl/acme. Key contents are never shown here.')),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Files')),
				fileRows.length ? table([ _('File'), _('Expires'), _('Used by') ], fileRows)
					: E('em', {}, _('No certificate file found.'))
			])
		];

		const acmeSection = E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('ACME (Let\'s Encrypt)')) ]);

		if (!status.acme_installed) {
			acmeSection.appendChild(E('p', {}, _('Install the acme-acmesh package (apk add acme-acmesh) to issue certificates from here. For DNS validation use the ACME page of luci-app-acme.')));
		}
		else {
			const rows = (certs.acme || []).map((c) => [
				c.name,
				c.domains.join(', '),
				(c.validation_method || '-') + (c.staging ? ' · ' + _('staging') : ''),
				c.issued ? _('issued') : E('em', {}, _('not issued yet')),
				(used['acme:' + c.name] || []).join(', ') || '-'
			]);

			acmeSection.appendChild(rows.length
				? table([ _('Name'), _('Domains'), _('Validation'), _('State'), _('Used by') ], rows)
				: E('em', {}, _('No ACME certificate yet.')));

			acmeSection.appendChild(E('div', { 'class': 'cbi-page-actions' }, [
				E('button', { 'class': 'btn cbi-button-add', 'click': ui.createHandlerFn(this, 'issueDialog', status, certs) }, _('Issue a certificate for a service…')), ' ',
				E('button', {
					'class': 'btn cbi-button-action',
					'click': ui.createHandlerFn(this, () => common.callAcmeRenew().then((r) => {
						ui.addNotification(null, E('p', r.output || ''), r.ok ? 'info' : 'warning');
					}))
				}, _('Renew now')), ' ',
				E('button', {
					'class': 'btn cbi-button',
					'click': ui.createHandlerFn(this, () => common.callAcmeLog().then((r) => {
						logBox.textContent = r.output || _('No log lines.');
						logBox.style.display = '';
					}))
				}, _('Show ACME log'))
			]));

			acmeSection.appendChild(E('p', { 'class': 'cbi-value-description' },
				_('DNS validation and wildcard certificates: use the ACME page of luci-app-acme; the certificates it issues appear in this list and can be chosen in a service.')));
		}

		acmeSection.appendChild(logBox);
		nodes.push(acmeSection);

		return E('div', {}, nodes);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
