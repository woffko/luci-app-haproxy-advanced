// SPDX-License-Identifier: MIT
// Golden tests of the generator.
//
// Each directory in tests/fixtures holds:
//   config         the UCI configuration (UCI file syntax);
//   env.json       the environment snapshot (interfaces, files, ACME certs,
//                  listening sockets); optional, defaults to {};
//   expected.cfg   the expected HAProxy configuration, when the case is valid;
//   expected.json  the expected report: ok, errors, warnings, skipped, firewall,
//                  interfaces.
//
// Usage: [UPDATE=1] ucode tests/run.uc [fixture-name ...]
// UPDATE=1 rewrites the expected files; review the diff before committing.

'use strict';

import * as fs from 'fs';
import { parse } from './lib/uci.uc';
import { generate } from '../haproxy-advanced/files/ucode/core.uc';

const root = fs.realpath(sourcepath(0, true) + '/fixtures');
let update = getenv('UPDATE') == '1', only = [ ...ARGV ];

function report_of(res) {
	return {
		ok: res.ok,
		errors: res.errors,
		warnings: res.warnings,
		skipped: res.skipped,
		firewall: res.firewall,
		interfaces: res.interfaces
	};
}

function pretty(v) {
	return sprintf('%.2J', v) + '\n';
}

let names = sort(filter(fs.lsdir(root), (n) => fs.stat(`${root}/${n}`)?.type == 'directory'));
let failed = 0, passed = 0;

for (let name in names) {
	if (length(only) && !(name in only))
		continue;

	let dir = `${root}/${name}`;
	let text = fs.readfile(`${dir}/config`);

	if (text == null) {
		warn(`${name}: no config file\n`);
		failed++;
		continue;
	}

	let envtext = fs.readfile(`${dir}/env.json`);
	let env = envtext ? json(envtext) : {};
	let res = generate(parse(text), env);
	let got_cfg = res.config;
	let got_rep = pretty(report_of(res));

	if (update) {
		fs.writefile(`${dir}/expected.json`, got_rep);

		if (got_cfg != null)
			fs.writefile(`${dir}/expected.cfg`, got_cfg);
		else
			fs.unlink(`${dir}/expected.cfg`);

		print(`updated ${name}\n`);
		continue;
	}

	let want_rep = fs.readfile(`${dir}/expected.json`);
	let want_cfg = fs.readfile(`${dir}/expected.cfg`);
	let problems = [];

	if (want_rep != got_rep)
		push(problems, 'report differs');

	if ((want_cfg ?? null) != (got_cfg ?? null))
		push(problems, 'config differs');

	if (length(problems)) {
		failed++;
		print(`FAIL ${name}: ${join(', ', problems)}\n`);

		let tmp = `/tmp/haproxy-advanced-test-${name}`;

		fs.mkdir(tmp);
		fs.writefile(`${tmp}/got.json`, got_rep);

		if (got_cfg != null)
			fs.writefile(`${tmp}/got.cfg`, got_cfg);

		print(`     diff -u ${dir}/expected.json ${tmp}/got.json\n`);

		if ((want_cfg ?? null) != (got_cfg ?? null))
			print(`     diff -u ${dir}/expected.cfg ${tmp}/got.cfg\n`);
	}
	else {
		passed++;
	}
}

if (!update)
	print(`${passed} passed, ${failed} failed\n`);

exit(failed ? 1 : 0);
