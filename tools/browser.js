'use strict';
// SPDX-License-Identifier: MIT
// Browser acceptance of goal A: drives LuCI on the OpenWrt test VM with
// Playwright. The root password is read from one stdin line.
//
// Usage: node tools/browser.js STEP OUTDIR
// Steps: add-service, staged, apply-error, password, certs, firewall-off,
//        firewall-on, runtime, stock, legacy, russian, phone, screens

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('/home/w0w/.local/share/playwright/node_modules/playwright');

const step = process.argv[2];
const outDir = process.argv[3];
const BASE = 'http://192.168.189.130/cgi-bin/luci/';
const APP = BASE + 'admin/services/haproxy-advanced/';
const password = fs.readFileSync(0, 'utf8').replace(/[\r\n]+$/, '');

fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

function log(...a) {
	console.log(...a);
}

async function login(page) {
	await page.goto(BASE, { waitUntil: 'domcontentloaded' });
	await page.fill('input[name=luci_username]', 'root');
	await page.fill('input[name=luci_password]', password);
	await Promise.all([ page.waitForLoadState('domcontentloaded'), page.press('input[name=luci_password]', 'Enter') ]);
	await page.waitForSelector('#maincontent', { timeout: 30000 });
}

async function open(page, tab) {
	await page.goto(APP + tab, { waitUntil: 'domcontentloaded' });
	await page.waitForSelector('#view .cbi-map, #view h2', { timeout: 30000 });
	await page.waitForTimeout(500);
}

function field(page, label) {
	return page.locator('.modal .cbi-value').filter({ has: page.locator('label.cbi-value-title', { hasText: new RegExp('^' + label + '$') }) });
}

async function modalSave(page) {
	await page.locator('.modal .cbi-button-positive', { hasText: /^Save$/ }).click();
	await page.waitForSelector('.modal', { state: 'hidden', timeout: 15000 });
}

// Save & Apply in the page footer, then wait for LuCI's reload and for the
// apply-result notification of common.watchApply().
async function saveApply(page) {
	await page.locator('.cbi-page-actions .cbi-button-apply').first().click();
	await page.waitForSelector('text=Configuration changes applied.', { timeout: 120000 }).catch(() => {});
	await page.waitForLoadState('domcontentloaded');
	const note = page.locator('.alert-message', { hasText: /HAProxy Advanced: configuration/ }).first();

	await note.waitFor({ timeout: 60000 });

	return (await note.innerText()).trim();
}

async function shot(page, name) {
	await page.screenshot({ path: path.join(outDir, name + '.png'), fullPage: true });
}

const steps = {
	async 'add-service'(page) {
		await open(page, 'services');
		await page.locator('.cbi-section-create .cbi-button-add').first().click();
		await page.waitForSelector('.modal');
		await field(page, 'Preset').locator('select').selectOption('generic_https');
		await field(page, 'Name').locator('input').fill('svcx');
		await field(page, 'Host names').locator('input').fill('svc-x.hatest.example');
		await field(page, 'Listener').locator('select').selectOption('pub');
		await field(page, 'Server protocol').locator('select').selectOption('http');
		await field(page, 'Server address').locator('input').fill('192.168.189.142');
		await field(page, 'Server port').locator('input').fill('19080');
		await field(page, 'Certificate').locator('select').selectOption('file');
		await field(page, 'Certificate file').locator('input').fill('/etc/haproxy/certs/svc-a.pem');
		await field(page, 'Login').locator('select').selectOption('__new');
		await field(page, 'Username').locator('input').fill('bob');
		await field(page, 'Password').locator('input').fill('browser-pass-1');
		await field(page, 'Repeat password').locator('input').fill('browser-pass-1');
		await shot(page, 'add-service-dialog');
		await page.locator('.modal .cbi-button-positive', { hasText: 'Create' }).click();
		// The service editor opens for the new service.
		await page.waitForSelector('.modal .cbi-section', { timeout: 20000 });
		await shot(page, 'add-service-editor');
		await modalSave(page);
		const note = await saveApply(page);

		log('NOTE', note);
		assert.match(note, /configuration applied/);
	},

	async staged(page) {
		await open(page, 'services');
		// Untick "Enabled" of svcx in the table and Save without applying.
		const row = page.locator('tr[data-sid="svcx"]');
		await row.locator('input[type=checkbox]').first().uncheck();
		await page.locator('.cbi-page-actions .cbi-button-save').first().click();
		await page.waitForTimeout(1500);
		await open(page, 'configuration');
		const text = await page.locator('#ha-preview').innerText();

		fs.writeFileSync(path.join(outDir, 'staged-preview.txt'), text);
		assert.match(text, /unsaved changes included/);
		assert.doesNotMatch(text, /svc-x\.hatest\.example/);
		await shot(page, 'configuration-staged');
		await open(page, 'services');
		await page.locator('tr[data-sid="svcx"] input[type=checkbox]').first().check();
		await page.locator('.cbi-page-actions .cbi-button-save').first().click();
		await page.waitForTimeout(1500);
		const note = await saveApply(page);

		assert.match(note, /configuration applied/);
	},

	async 'apply-error'(page) {
		await open(page, 'settings');
		await page.locator('a', { hasText: /^Advanced$/ }).first().click();
		await page.locator('textarea[id*="advanced"]').fill('stats socket /tmp/evil.sock');
		const note = await saveApply(page);

		log('NOTE', note);
		fs.writeFileSync(path.join(outDir, 'apply-error-note.txt'), note);
		assert.match(note, /configuration not applied/);
		assert.match(note, /the service owns the stats socket/);
		await shot(page, 'apply-error');
		await open(page, 'settings');
		await page.locator('a', { hasText: /^Advanced$/ }).first().click();
		await page.locator('textarea[id*="advanced"]').fill('');
		const ok = await saveApply(page);

		assert.match(ok, /configuration applied/);
	},

	async password(page) {
		await open(page, 'users');
		const row = page.locator('tr.cbi-section-table-row').filter({ hasText: 'bob' });
		await row.locator('.cbi-button-edit').click();
		await page.waitForSelector('.modal');
		await field(page, 'New password').locator('input').fill('browser-pass-2');
		await field(page, 'Repeat password').locator('input').fill('browser-pass-2');
		await shot(page, 'password-set');
		await modalSave(page);
		const note = await saveApply(page);

		assert.match(note, /configuration applied/);
	},

	async certs(page) {
		await open(page, 'certificates');
		const text = await page.locator('#view').innerText();

		fs.writeFileSync(path.join(outDir, 'certificates.txt'), text);
		assert.match(text, /\/etc\/haproxy\/certs\/svc-a\.pem/);
		assert.match(text, /GMT/);  // expiry read from HAProxy
		assert.doesNotMatch(text, /PRIVATE KEY/);
		await shot(page, 'certificates');
		await open(page, 'listeners');
		await page.locator('tr[data-sid="pub"] .cbi-button-edit').click();
		await page.waitForSelector('.modal');
		await page.locator('.modal a', { hasText: /^TLS$/ }).click();
		const html = await page.locator('.modal').innerHTML();

		assert.match(html, /svc-b\.pem/);
		await page.locator('.modal .btn', { hasText: /^Dismiss$/ }).click();
	},

	async 'firewall-off'(page) {
		await open(page, 'listeners');
		await page.locator('tr[data-sid="pub"] .cbi-button-edit').click();
		await page.waitForSelector('.modal');
		await page.locator('.modal a', { hasText: /^Firewall$/ }).click();
		await field(page, 'Open in firewall').locator('input[type=checkbox]').uncheck();
		await modalSave(page);
		const note = await saveApply(page);

		assert.match(note, /configuration applied/);
	},

	async 'firewall-on'(page) {
		await open(page, 'listeners');
		await page.locator('tr[data-sid="pub"] .cbi-button-edit').click();
		await page.waitForSelector('.modal');
		await page.locator('.modal a', { hasText: /^Firewall$/ }).click();
		await field(page, 'Open in firewall').locator('input[type=checkbox]').check();
		await modalSave(page);
		const note = await saveApply(page);

		assert.match(note, /configuration applied/);
	},

	async runtime(page) {
		await open(page, 'overview');
		await page.waitForSelector('#ha-runtime table');
		await shot(page, 'overview-runtime');
		const row = page.locator('#ha-runtime tr').filter({ hasText: 's1' }).filter({ has: page.locator('select') }).first();
		await row.locator('select').selectOption('maint');
		await row.locator('button', { hasText: /^Set$/ }).click();
		await page.waitForTimeout(1500);
		fs.writeFileSync(path.join(outDir, 'runtime-maint.txt'), await page.locator('#ha-runtime').innerText());
	},

	async 'runtime-ready'(page) {
		await open(page, 'overview');
		await page.waitForSelector('#ha-runtime table');
		const row = page.locator('#ha-runtime tr').filter({ hasText: 'MAINT' }).first();
		await row.locator('select').selectOption('ready');
		await row.locator('button', { hasText: /^Set$/ }).click();
		await page.waitForTimeout(1500);
	},

	async stock(page) {
		await open(page, 'overview');
		const notice = page.locator('.alert-message', { hasText: 'stock' }).or(page.locator('.alert-message', { hasText: '/etc/init.d/haproxy' }));
		await notice.first().waitFor({ timeout: 10000 });
		await shot(page, 'stock-notice');
		await page.locator('button', { hasText: 'Stop and disable it…' }).click();
		await page.locator('.modal button', { hasText: /^Stop and disable$/ }).click();
		await page.waitForTimeout(3000);
	},

	async legacy(page) {
		await open(page, 'overview');
		await page.locator('.alert-message', { hasText: 'version 0.1 configuration' }).first().waitFor({ timeout: 10000 });
		await shot(page, 'legacy-notice');
		await page.locator('button', { hasText: 'Move it to /etc/config/haproxy-advanced.v01' }).click();
		await page.waitForTimeout(3000);
	},

	async russian(page) {
		await open(page, 'overview');
		const text = await page.locator('body').innerText();

		fs.writeFileSync(path.join(outDir, 'russian.txt'), text);
		assert.match(text, /Обзор/);
		assert.match(text, /Службы|Сервисы/);
		assert.match(text, /Последнее применение/);
		assert.doesNotMatch(text, /запущенвключён/);
		await shot(page, 'russian-overview');
		await open(page, 'services');
		await shot(page, 'russian-services');
	},

	async phone(page) {
		for (const tab of [ 'overview', 'services', 'listeners', 'backends', 'users', 'certificates', 'settings', 'configuration' ]) {
			await open(page, tab);
			const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);

			log('PHONE', tab, over);
			await shot(page, 'phone-' + tab);
			fs.appendFileSync(path.join(outDir, 'phone.txt'), `${tab} ${over}\n`);
		}
	},

	async screens(page) {
		for (const tab of [ 'overview', 'services', 'listeners', 'backends', 'users', 'certificates', 'settings', 'configuration' ]) {
			await open(page, tab);
			await shot(page, 'tab-' + tab);
		}
	}
};

(async () => {
	assert(steps[step], 'unknown step');
	const browser = await chromium.launch();
	const phone = step == 'phone';
	const context = await browser.newContext(phone
		? { viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true }
		: { viewport: { width: 1400, height: 1000 } });
	const page = await context.newPage();
	const errors = [];

	page.on('pageerror', (e) => errors.push(String(e)));
	page.on('response', async (r) => {
		if (r.status() >= 400)
			errors.push(`HTTP ${r.status()} ${r.url()} ${(r.request().postData() || '').substring(0, 300)}`);
		else if (/\/ubus/.test(r.url())) {
			const body = await r.text().catch(() => '');

			if (/"error"\s*:/.test(body))
				errors.push(`RPC ${page.url()} ${(r.request().postData() || '').substring(0, 400)} -> ${body.substring(0, 300)}`);
		}
	});
	page.on('console', (m) => { if (m.type() == 'error') errors.push(m.text()); });

	try {
		await login(page);
		await steps[step](page);
		log('STEP_OK', step);
	}
	catch (e) {
		await shot(page, 'failure-' + step).catch(() => {});
		console.error('STEP_FAILED', step, e.message);
		process.exitCode = 1;
	}
	finally {
		fs.writeFileSync(path.join(outDir, 'console-' + step + '.txt'), errors.join('\n') + '\n');
		await browser.close();
	}
})();
