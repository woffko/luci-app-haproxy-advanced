// SPDX-License-Identifier: MIT
// Minimal UCI file reader for the host tests. The host ucode has no uci module
// (the OpenWrt tree builds it with UCI_SUPPORT=OFF), so fixtures are parsed
// here into the shape cursor.get_all() returns, in file order.
//
// Supports: config/option/list statements, bare words, single quotes, double
// quotes with backslash escapes, adjacent quoted parts, values spanning lines,
// and # comments.

'use strict';

function tokenize(text) {
	let toks = [], i = 0, n = length(text);
	let cur = null;

	function flush() {
		if (cur != null) {
			push(toks, cur);
			cur = null;
		}
	}

	while (i < n) {
		let c = substr(text, i, 1);

		if (c == '\n') {
			flush();
			push(toks, '\n');
			i++;
		}
		else if (c == ' ' || c == '\t' || c == '\r') {
			flush();
			i++;
		}
		else if (c == '#' && cur == null) {
			while (i < n && substr(text, i, 1) != '\n')
				i++;
		}
		else if (c == "'") {
			let j = index(substr(text, i + 1), "'");

			if (j < 0)
				die('unterminated single quote');

			cur = (cur ?? '') + substr(text, i + 1, j);
			i += j + 2;
		}
		else if (c == '"') {
			let s = '';

			i++;

			while (i < n && substr(text, i, 1) != '"') {
				let d = substr(text, i, 1);

				if (d == '\\' && i + 1 < n) {
					s += substr(text, i + 1, 1);
					i += 2;
				}
				else {
					s += d;
					i++;
				}
			}

			if (i >= n)
				die('unterminated double quote');

			cur = (cur ?? '') + s;
			i++;
		}
		else {
			cur = (cur ?? '') + c;
			i++;
		}
	}

	flush();

	return toks;
}

export function parse(text) {
	let toks = tokenize(text);
	let sections = [], cur = null, line = [], anon = 0;

	function statement(words) {
		if (!length(words))
			return;

		if (words[0] == 'config') {
			let name = words[2];
			let s = { '.type': words[1], '.anonymous': name == null, '.index': length(sections) };

			s['.name'] = name ?? sprintf('cfg%02x%04x', length(sections), ++anon);
			push(sections, s);
			cur = s;
		}
		else if (words[0] == 'option') {
			if (!cur)
				die('option outside a section');

			cur[words[1]] = words[2] ?? '';
		}
		else if (words[0] == 'list') {
			if (!cur)
				die('list outside a section');

			if (type(cur[words[1]]) != 'array')
				cur[words[1]] = [];

			push(cur[words[1]], words[2] ?? '');
		}
		else if (words[0] != 'package') {
			die(`unknown UCI statement '${words[0]}'`);
		}
	}

	for (let t in toks) {
		if (t == '\n') {
			statement(line);
			line = [];
		}
		else {
			push(line, t);
		}
	}

	statement(line);

	return sections;
};
