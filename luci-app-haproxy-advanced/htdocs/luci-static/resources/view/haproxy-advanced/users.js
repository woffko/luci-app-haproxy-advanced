'use strict';
'require view';
'require form';
'require uci';
'require haproxy_advanced.common as common';
'require haproxy_advanced.crypt as hacrypt';

const HASH_RE = /^\$(1|5|6|2[aby])\$[A-Za-z0-9.\/$=]+$/;

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
		common.liveChoices(o, 'auth_group');
		o.rmempty = false;

		o = s.option(form.Value, 'username', _('Username'));
		o.rmempty = false;
		o.validate = function(section_id, value) {
			return /^[A-Za-z0-9._@-]{1,64}$/.test(value || '') ? true : _('1-64 letters, digits, ., _, @ or -');
		};

		o = s.option(form.DummyValue, '_password', _('Password'));
		o.textvalue = hashLabel;
		o.modalonly = false;

		// Password fields inside the user editor. The hash is made in this browser
		// when the editor is saved (decision D6); the password itself is never
		// stored or sent. LuCI has one modal, so no nested dialog is used here.
		o = s.option(form.DummyValue, '_current', _('Password'));
		o.modalonly = true;
		o.textvalue = hashLabel;

		o = s.option(form.Value, '_newpw', _('New password'),
			_('Leave empty to keep the current password. Hashed (SHA-512 crypt) in this browser; only the hash is saved.'));
		o.modalonly = true;
		o.password = true;
		o.cfgvalue = () => '';
		o.remove = () => {};
		o.write = function(section_id, value) {
			if (value)
				uci.set(common.CONFIG, section_id, 'password_hash', hacrypt.hash(value));
		};
		o.validate = function(section_id, value) {
			const hash = this.section.formvalue(section_id, '_hash');

			if (value && value.length < 8)
				return _('Use at least 8 characters.');

			if (value && hash)
				return _('Give a new password or a hash, not both.');

			if (!value && !hash && !uci.get(common.CONFIG, section_id, 'password_hash'))
				return _('Set a password.');

			return true;
		};

		o = s.option(form.Value, '_newpw2', _('Repeat password'));
		o.modalonly = true;
		o.password = true;
		o.cfgvalue = () => '';
		o.remove = () => {};
		o.write = () => {};
		o.validate = function(section_id, value) {
			return ((value || '') == (this.section.formvalue(section_id, '_newpw') || '')) ? true : _('The passwords differ.');
		};

		o = s.option(form.Value, '_hash', _('Or an existing hash'),
			_('A crypt hash made elsewhere: $6$ (SHA-512), $5$, $1$ or $2y$ (bcrypt). HAProxy checks the hash on every request that carries a login, so slow hashes such as bcrypt cost router CPU on every request.'));
		o.modalonly = true;
		o.cfgvalue = () => '';
		o.remove = () => {};
		o.write = function(section_id, value) {
			if (value)
				uci.set(common.CONFIG, section_id, 'password_hash', value.trim());
		};
		o.validate = function(section_id, value) {
			return (!value || (HASH_RE.test(value.trim()) && value.length <= 200)) ? true : _('This is not a crypt hash.');
		};

		return m.render();
	}
});
