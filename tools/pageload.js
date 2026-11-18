'use strict';
// SPDX-License-Identifier: MIT
// How many requests a real web UI sends: LuCI of the OpenWrt test VM, served
// through HAProxy as luci.hatest.example:18443, logged in and moved through a
// few pages, once with a cold and once with a warm browser cache. The largest
// number of requests in any 10 s window sizes the default rate limit.
//
// Usage: printf '%s\n' "$PW" | node tools/pageload.js OUTDIR

const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('/home/w0w/.local/share/playwright/node_modules/playwright');

const outDir = process.argv[2];
const password = fs.readFileSync(0, 'utf8').replace(/[\r\n]+$/, '');
const BASE = 'https://luci.hatest.example:18443/cgi-bin/luci/';
const PAGES = [ 'admin/status/overview', 'admin/network/network', 'admin/services/haproxy-advanced/services',
	'admin/system/system', 'admin/status/overview' ];

fs.mkdirSync(outDir, { recursive: true });

function maxIn10s(times) {
	let best = 0;

	for (let i = 0, j = 0; i < times.length; i++) {
		while (times[i] - times[j] > 10000)
			j++;

		best = Math.max(best, i - j + 1);
	}

	return best;
}

async function run(context, label) {
	const page = await context.newPage();
	const times = [];
	const perPage = [];
	let count = 0;

	page.on('request', () => { times.push(Date.now()); count++; });

	const resp = await page.goto(BASE, { waitUntil: 'networkidle' });

	console.log(label, 'first load', resp && resp.status());
	// The warm run reuses the logged-in session, so the form may be absent.
	if (await page.locator('input[name=luci_username]').count()) {
		await page.fill('input[name=luci_username]', 'root');
		await page.fill('input[name=luci_password]', password);
		await Promise.all([ page.waitForLoadState('networkidle'), page.press('input[name=luci_password]', 'Enter') ]);
	}

	perPage.push([ 'login', count ]);

	for (const p of PAGES) {
		const before = count;

		await page.goto(BASE + p, { waitUntil: 'networkidle' });
		await page.waitForTimeout(1500);
		perPage.push([ p, count - before ]);
	}

	await page.close();

	return { label, total: count, max_in_10s: maxIn10s(times), per_page: perPage };
}

(async () => {
	const browser = await chromium.launch({ args: [ '--host-resolver-rules=MAP luci.hatest.example 192.168.189.130' ] });
	const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 } });
	const cold = await run(context, 'cold cache');
	const warm = await run(context, 'warm cache');
	const result = { cold, warm };

	fs.writeFileSync(path.join(outDir, 'pageload.json'), JSON.stringify(result, null, 2) + '\n');
	console.log(JSON.stringify({ cold: [ cold.total, cold.max_in_10s ], warm: [ warm.total, warm.max_in_10s ] }));
	await browser.close();
})().catch((e) => { console.error('FAILED', e.message); process.exit(1); });
