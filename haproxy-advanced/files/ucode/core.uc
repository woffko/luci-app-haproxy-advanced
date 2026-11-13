// SPDX-License-Identifier: MIT
// Pure entry point of the generator: UCI sections and an environment snapshot
// in, HAProxy configuration and report out. It touches no file, socket or
// process, so the host tests run it with fixtures.

'use strict';

import { build } from './model.uc';
import { render } from './render.uc';

export const VERSION = '0.2.0';

// sections: array of UCI sections in file order, each an object with '.type',
//           '.name' and the options (lists as arrays), as cursor.get_all() gives.
// env:      see system.uc's collect_env(); tests pass a plain object.
export function generate(sections, env) {
	let res = build(sections, env);
	let m = res.model;
	let rep = res.report;
	let ok = !length(rep.errors);

	return {
		version: VERSION,
		ok,
		enabled: m?.global?.enabled ?? false,
		config: ok ? render(m) : null,
		errors: rep.errors,
		warnings: rep.warnings,
		skipped: rep.skipped,
		firewall: ok ? m.firewall : [],
		interfaces: m?.interfaces ?? [],
		listeners: ok ? map(m.listeners, (l) => ({
			name: l.name,
			port: l.port,
			redirect_port: l.redirect_port,
			main_active: l.main_active,
			binds: l.binds,
			services: map(l.services, (s) => s.name)
		})) : []
	};
};
