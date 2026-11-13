'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require haproxy_advanced.common as common';
'require haproxy_advanced.crypt as hacrypt';

const HASH_RE = /^\$(1|5|6|2[aby])\$[A-Za-z0-9.\/$=]+$/;

// Ask for a password twice and store its SHA-512 crypt hash. The password stays
// in the browser.
function passwordDialog(section_id, onDone) {
	const p1 = E('input', { 'type': 'password', 'class': 'cbi-input-password', 'autocomplete': 'new-password' });
	const p2 = E('input', { 'type': 'password', 'class': 'cbi-input-password', 'autocomplete': 'new-password' });
	const err = E('p', { 'class': 'alert-message warning', 'style': 'display:none' });

	ui.showModal(_('Set password'), [
		E('p', _('The password is turned into a SHA-512 crypt hash in this browser; only the hash is saved on the router.')),
		E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('Password')), E('div', { 'class': 'cbi-value-field' }, p1) ]),
		E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('Repeat')), E('div', { 'class': 'cbi-value-field' }, p2) ]),
		err,
		E('div', { 'class': 'right' }, [
			E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
			E('button', {
				'class': 'btn cbi-button-positive',
				'click': function() {
					let problem = null;

					if (p1.value.length < 8)
						problem = _('Use at least 8 characters.');
					else if (p1.value != p2.value)
						problem = _('The passwords differ.');

					if (problem) {
						err.textContent = problem;
						err.style.display = '';
						return;
					}

					const hash = hacrypt.hash(p1.value);

					p1.value = p2.value = '';
					uci.set(common.CONFIG, section_id, 'password_hash', hash);
					ui.hideModal();
					onDone();
				}
			}, _('Set password'))
		])
	]);

	p1.focus();
}

function hashDialog(section_id, onDone) {
	const inp = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'style': 'width:100%', 'placeholder': '$6$…' });
	const err = E('p', { 'class': 'alert-message warning', 'style': 'display:none' });

	ui.showModal(_('Use an existing hash'), [
		E('p', _('A crypt hash made elsewhere: $6$ (SHA-512), $5$, $1$ or $2y$ (bcrypt). HAProxy checks the hash on every request that carries a login, so slow hashes such as bcrypt cost router CPU on every request.')),
		inp, err,
		E('div', { 'class': 'right' }, [
			E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
			E('button', {
				'class': 'btn cbi-button-positive',
				'click': function() {
					const v = inp.value.trim();

					if (!HASH_RE.test(v) || v.length > 200) {
						err.textContent = _('This is not a crypt hash.');
						err.style.display = '';
						return;
					}

					uci.set(common.CONFIG, section_id, 'password_hash', v);
					ui.hideModal();
					onDone();
				}
			}, _('Use hash'))
		])
	]);
}

function hashLabel(section_id) {
	const h = uci.get(common.CONFIG, section_id, 'password_hash');

	if (!h)
		return _('No password');

	const kind = { '6': 'SHA-512', '5': 'SHA-256', '1': 'MD5', '2a': 'bcrypt', '2b': 'bcrypt', '2y': 'bcrypt' }[(h.split('$')[1]) || ''];

	return _('Set (%s)').format(kind || _('unknown'));
}

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

		m = new form.Map(common.CONFIG, _('HAProxy Advanced: users'),
			_('Logins for services that require one (HTTP Basic authentication). A service names one group; any enabled user of that group may log in.'));

		s = m.section(form.GridSection, 'auth_group', _('Groups'));
		s.addremove = true;
		s.anonymous = false;
		s.nodescriptions = true;
		s.addbtntitle = _('Add group');

		o = s.option(form.Value, 'realm', _('Prompt text'),
			_('Shown in the browser\'s login window.'));
		o.placeholder = 'Restricted';
		o.validate = common.validators.quoted;

		o = s.option(form.DummyValue, '_users', _('Users'));
		o.textvalue = function(section_id) {
			const n = uci.sections(common.CONFIG, 'user').filter((u) => u.group == section_id && u.enabled != '0').length;

			return String(n);
		};

		s = m.section(form.GridSection, 'user', _('Users'));
		s.addremove = true;
		s.anonymous = true;
		s.nodescriptions = true;
		s.addbtntitle = _('Add user');
		s.modaltitle = _('User');

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.editable = true;

		o = s.option(form.ListValue, 'group', _('Group'));
		common.names('auth_group').forEach((n) => o.value(n));
		o.rmempty = false;

		o = s.option(form.Value, 'username', _('Username'));
		o.rmempty = false;
		o.validate = function(section_id, value) {
			return /^[A-Za-z0-9._@-]{1,64}$/.test(value || '') ? true : _('1-64 letters, digits, ., _, @ or -');
		};

		o = s.option(form.DummyValue, '_password', _('Password'));
		o.textvalue = hashLabel;
		o.modalonly = false;

		o = s.option(form.Button, '_setpw', _('Password'));
		o.modalonly = true;
		o.inputtitle = _('Set password…');
		o.inputstyle = 'action';
		o.onclick = function(ev, section_id) {
			const root = ev.target.closest('.cbi-value-field') || ev.target.parentNode;
			const label = root.querySelector('.ha-hash-label');

			passwordDialog(section_id, () => { if (label) label.textContent = hashLabel(section_id); });
		};
		o.renderWidget = function(section_id, option_index, cfgvalue) {
			const btn = form.Button.prototype.renderWidget.apply(this, [ section_id, option_index, cfgvalue ]);
			const paste = E('button', {
				'class': 'btn cbi-button',
				'click': (ev) => {
					ev.preventDefault();
					hashDialog(section_id, () => { label.textContent = hashLabel(section_id); });
				}
			}, _('Use an existing hash…'));
			const label = E('span', { 'class': 'ha-hash-label', 'style': 'margin-left:1em' }, hashLabel(section_id));

			return E('div', {}, [ btn, ' ', paste, label ]);
		};

		return m.render();
	}
});
