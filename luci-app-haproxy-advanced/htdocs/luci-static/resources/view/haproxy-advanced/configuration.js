'use strict';
'require view';
'require ui';
'require haproxy_advanced.common as common';

function problems(title, list) {
	if (!list || !list.length)
		return '';

	return E('div', {}, [
		E('strong', {}, title),
		E('ul', {}, list.map((p) => E('li', {}, [ E('code', {}, p.where), ': ', p.message ])))
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(common.callStatus(), {}),
			common.callPreview(true)
		]);
	},

	renderPreview: function(p) {
		const nodes = [];

		nodes.push(E('p', {}, p.staged
			? _('This is the configuration of the settings as they are now in LuCI, unsaved changes included.')
			: _('This is the configuration of the saved settings.')));

		if (!p.ok)
			nodes.push(E('div', { 'class': 'alert-message warning' }, [
				E('strong', {}, _('These settings cannot be applied:')),
				problems('', p.errors)
			]));
		else if (p.check && !p.check.ok)
			nodes.push(E('div', { 'class': 'alert-message warning' }, [
				E('strong', {}, _('haproxy -c rejects this configuration:')),
				E('pre', { 'style': 'white-space:pre-wrap' }, p.check.output)
			]));
		else if (p.check)
			nodes.push(E('div', { 'class': 'alert-message notice' }, _('haproxy -c accepts this configuration.')));

		if (p.ok && !p.enabled)
			nodes.push(E('p', {}, E('em', {}, _('The service is disabled in Settings, so nothing runs.'))));

		nodes.push(problems(_('Left out for now'), p.skipped));
		nodes.push(problems(_('Warnings'), p.warnings));

		if (p.config)
			nodes.push(E('pre', { 'style': 'white-space:pre; overflow:auto; max-height:60em; font-size:90%' }, p.config));

		return E('div', { 'id': 'ha-preview' }, nodes);
	},

	render: function(data) {
		const status = data[0] || {};
		const box = E('div', {}, this.renderPreview(data[1] || {}));

		common.watchApply(status);

		return E('div', {}, [
			E('h2', {}, _('HAProxy Advanced: configuration')),
			E('p', { 'class': 'cbi-map-descr' }, _('The HAProxy configuration generated from the settings, and the result of haproxy -c. Nothing is applied here; Save & Apply does that.')),
			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', {
					'class': 'btn cbi-button-action',
					'click': ui.createHandlerFn(this, () => common.callPreview(true).then((p) => {
						box.replaceChildren(this.renderPreview(p));
					}))
				}, _('Refresh'))
			]),
			box
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
