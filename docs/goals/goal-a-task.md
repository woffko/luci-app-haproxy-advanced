# Goal A task: fix the audit findings and finish the GUI (0.2.0)

Turn `luci-app-haproxy-advanced` 0.1.0 into a release-quality 0.2.0: fix every finding
of the 2026-11-12 audit below, split the project into a service package and a LuCI
package, replace the one-frontend-per-service model with shared listeners and
host-based routing, and finish the GUI with the features the owner chose. Work on a
branch `goal-a` and record progress in `docs/goals/goal-a-status.md`.

Read first:

- this repository at commit `3bc4ff6` (the audit's line numbers refer to it);
- `/home/w0w/HAPROXY_LUCI_CONTEXT.md`: how 0.1.0 was built and tested in June 2026. The
  build tree is still valid. The router `192.168.189.134` is not reachable, so this
  goal does not use it;
- `/home/w0w/AGENTS.md`: the language rules for GitHub, Gemini delegation and Longrun;
- the OpenWrt sources the package must follow, all in the dedicated build tree
  `/home/w0w/build/openwrt-25.12.4-clean-haproxy-luci` (tag `v25.12.4`):
  `feeds/luci/luci.mk`,
  `feeds/luci/modules/luci-base/htdocs/luci-static/resources/form.js`,
  `package/base-files/files/lib/functions.sh` (`default_postinst`),
  `feeds/packages/net/haproxy` (HAProxy 3.2.x and the stock init script),
  `feeds/packages/net/acme-common` and `acme-acmesh` (events `acme.issue` and
  `acme.renew`, files in `/etc/ssl/acme`, the `acme_server` option), and fw4's handling
  of firewall rules that services publish through procd.

## Owner decisions (2026-11-13)

- **O1. Test target:** the OpenWrt test VM `192.168.189.130`. It is shared with
  cake-autorate-rs (see "The shared VMs"). The Ubuntu VM `192.168.189.142` hosts the
  test backends and the ACME test server.
- **O2. Two packages in one repository:** `haproxy-advanced` (the service) and
  `luci-app-haproxy-advanced` (the GUI).
- **O3. New UCI schema, no migration:** 0.1.0 runs only on test equipment. When the
  service finds 0.1 sections (`frontend`, `bind`, `acl`, `action`), it refuses to start
  and says why. The GUI offers to move the old file to
  `/etc/config/haproxy-advanced.v01` and start from an empty configuration.
- **O4. GUI scope:** all four extras are in:
  - HTTPS conveniences: redirect from HTTP, HSTS, HTTP/2, IPv6, bind to a device;
  - ACME from the GUI;
  - a runtime panel;
  - TLS passthrough by SNI.

  Also always in scope: a certificate picker, a password-hash generator, opening the
  port in the firewall, and showing apply results and errors.

## Technical decisions

These come from the audit. Change one only with a recorded reason in the status file.

- **D1. The generator moves to ucode.** fw4 uses the same approach. ucode reads UCI
  natively. With a cursor on the rpcd session's save directory
  (`/var/run/rpcd/uci-<ubus_rpc_session>`), it can also render unsaved LuCI changes,
  which a shell script started by `fs.exec` cannot. The init script stays a small procd
  shell script that calls the generator.
- **D2. Shared listeners, routing by Host.**
  - A listener is one entry point (addresses + port + TLS settings), and services attach
    to it.
  - HTTP routing uses `use_backend` on `req.hdr(host),host_only,lower`.
  - SNI chooses the certificate (a `crt-list`) and, for passthrough, the backend.
  - The generator never emits two listeners on the same address and port.
- **D3. All-or-nothing for configuration errors, skip for runtime conditions.**
  - A configuration error keeps the running HAProxy on its last good config and is
    reported.
  - A runtime condition skips only what it affects, with a warning: an interface with no
    address yet, or a certificate file that ACME has not issued yet. The rest runs, and
    the skipped part comes back on the matching trigger.
- **D4. No experimental HAProxy directives** (`expose-experimental-directives`). That
  rules out `normalize-uri` and HAProxy's native ACME. Path safety comes from denying
  ambiguous paths and matching case-insensitively on the decoded path.
- **D5. Threat model:** a LuCI administrator is root. The advanced-directive fields stay
  available. They still refuse section escapes and control characters, but the README
  says plainly that they are root-equivalent, and nothing calls the denylist a security
  boundary (F22).
- **D6. Password hashes are made in the browser**, as SHA-512 crypt (`$6$`), so the
  password never reaches the router. Choose the default rounds from a measurement on
  the VM. HAProxy runs `crypt()` on every request that carries credentials, with no
  cache. Existing `$1$`, `$5$`, `$6$` and `$2y$`/`$2b$` hashes stay accepted.
- **D7. Firewall:** a listener with "open in firewall" publishes its rule through procd
  service data for fw4. Nothing writes `/etc/config/firewall`.
- **D8. The stock `haproxy` service is never changed silently.** Status reports when
  `/etc/init.d/haproxy` is enabled or running. The GUI offers to stop and disable it,
  after a confirmation.

## Audit findings to fix (commit `3bc4ff6`)

`INIT` = `root/etc/init.d/haproxy-advanced`,
`JS` = `htdocs/luci-static/resources/view/haproxy-advanced.js`,
`CFG` = `root/etc/config/haproxy-advanced`.

- **F1.** The hardening rule denies every HTTP/1 request that has `Content-Length: 0`.
  Browsers send this header with an empty POST. In HAProxy 3.2, `req.body_size` is 0
  for such a request and the header stays (INIT:702). Remove the rule: HAProxy 3.2 does
  not need it.
- **F2.** The wizard gives each service its own frontend on the same address and port.
  With `SO_REUSEPORT` the kernel splits connections between them at random, and nothing
  routes by host (JS:389-414).
- **F3.** Interface aliases resolve once, at start (INIT:213-241). There are no interface
  triggers (INIT:24-27). A start before WAN has an address fails with no retry, and an
  address change leaves HAProxy bound to the old address.
- **F4.** The wizard's default names collide with the example in CFG.
  - The backend name is duplicated, which is fatal in HAProxy.
  - The example's binds (`opt4_ipv4`), ACLs and actions attach to the new frontend by
    name (CFG:16-132, JS:304, JS:370).
- **F5.** Preview and Validate read the committed config, not the user's unsaved
  changes (JS:586-599). A failed reload after Save & Apply is invisible in LuCI
  (INIT:923-934).
- **F6.** `hdr(host) -i` fails when the Host header carries a port (INIT:475). SNI is
  never used, although the README claims SNI ACLs.
- **F7.** Path ACLs are case-sensitive and not normalized, so `/CGI-BIN/`, `//cgi-bin/`
  and `/%63gi-bin/` pass a `/cgi-bin/` block (INIT:483).
- **F8.** The frontend "Basic hardening" Flag has `rmempty`. Unchecking it removes the
  option, and the global value 1 applies again. The UI shows "off" while it is on
  (JS:699-700, INIT:633).
- **F9.** A client's own `X-Forwarded-For` reaches the backend. There is no
  `X-Forwarded-Proto` (INIT:680).
- **F10.** Basic Auth problems (INIT:351-381, JS:329):
  - `crypt()` runs per request, and there is no brute-force limit;
  - there is no way to make a hash in the GUI;
  - the placeholder hash is `REPLACE_ME`.
- **F11.** The Makefile's own postinst replaces luci.mk's. It loses `rpcd reload`, so the
  menu and ACL stay inactive until rpcd restarts, and it removes wrong cache names. The
  uci-defaults that only enables the service repeats `default_postinst`
  (Makefile:22-32).
- **F12.** Timeout problems:
  - the Home Assistant preset writes `timeout tunnel` into a frontend, where HAProxy
    ignores it (JS:383);
  - there is no `timeout http-request`;
  - all timeouts are fixed (INIT:331-333).
- **F13.** `verify required` without a CA fails validation, and the GUI neither requires
  a CA nor offers `@system-ca`. There is no `sni` or `verifyhost` (JS:797-804,
  INIT:757-775).
- **F14.** ACME problems (INIT:26, JS:315-316):
  - `acme.issue` triggers nothing;
  - the ACME placeholders point at acme.sh's private directory instead of
    `/etc/ssl/acme/<domain>.combined.crt`;
  - the split certificate mode is redundant.
- **F15.** Value checks accept spaces and `#`, which can inject bind options or cut a
  line short (INIT:60-72, 110-132, 156-163).
- **F16.** Dead options: `check_type` and `check_ssl` (CFG:45, CFG:54, JS:420).
- **F17.** The ACL grants `start`, `stop` and `restart`, which nothing uses
  (`acl.d`:22-25).
- **F18.** The rate limit has two problems (INIT:690-699):
  - the 30 requests per 10 s default is too low for a modern web UI;
  - the table type `ip` covers IPv4 only.
- **F19.** "Protected paths" actually means internal-only, and "Blocked paths" applies
  only after the allow and auth rules. The names mislead (JS:450-540).
- **F20.** The `haproxy` dependency installs and starts the stock demo config: uid 0,
  listening on :81, :444 and :60000, with stats login `username:password`. Nothing warns
  about it.
- **F21.** Packaging gaps (Makefile, layout):
  - the service lives inside the luci-app;
  - there are no translations;
  - `PKG_MAINTAINER` has no email;
  - the view is not in a per-app directory.
- **F22.** The advanced-directive denylist looks like a safety boundary, but it is not
  one (INIT:165-195). Handled by D5.
- **F23.** References between sections are free-text names: renaming a frontend
  silently detaches its ACLs and actions. Lists are stored as space-separated strings
  instead of UCI lists.
- **F24.** `logs` greps every haproxy line, including the stock instance's. The extra
  command `status` duplicates the built-in one (INIT:19-22, 986-988).

## Work, in order

Commit at the end of each stage, with the status file updated. If the goal must stop,
finish or revert the current stage first.

### 1. Layout and packaging

- Use this layout:
  - `haproxy-advanced/`: an OpenWrt package (`package.mk`). It holds the init script, an
    empty default config (global section only, disabled; F4), and the ucode generator
    under `/usr/share/haproxy-advanced/`. Dependencies: `+haproxy +ucode +ucode-mod-uci
    +ucode-mod-fs` and whatever else the generator really needs. List the config in
    `conffiles`.
  - `luci-app-haproxy-advanced/`: built with `luci.mk`. It holds the views under
    `htdocs/luci-static/resources/view/haproxy-advanced/`, `menu.d`, the rpcd ACL, an
    rpcd ucode plugin, and `po/templates` plus `po/ru`. No custom postinst and no
    uci-defaults that only enable a service (F11).
  - Top level: `tests/`, `tools/` (VM and browser drivers, no secrets), `docs/`.
- Version 0.2.0, release 1, for both packages. Maintainer:
  `woffko <2505149+woffko@users.noreply.github.com>`. License MIT, as now.
- Build in the dedicated tree through a `src-link` feed that points at this repository.
  - Its `package/luci-app-haproxy-advanced` is an untracked copy from 2026-06-06: check
    with `git status` in the tree, then remove it.
  - Leave `package/luci-app-haproxy-tcp` alone.
  - Packaging needs to run outside the sandbox (fakeroot).
  - List each APK's contents and modes, and record them in the status file.
- Add an `AGENTS.md` for this repository: build, tests, VM rules, English for GitHub,
  and the Longrun section from `/home/w0w/AGENTS.md`.

### 2. Schema and generator

- Write `docs/uci-schema.md` before the code. Must-haves:
  - **global:** enable, maxconn, logging, default timeouts, hardening default, stats
    socket (always local, for the runtime panel).
  - **listener:**
    - addresses as a UCI list of logical interfaces (IPv4, IPv6 or both), literal
      addresses or any;
    - an optional device to bind to instead of addresses (`bind ... interface <dev>`),
      for a WAN whose address changes;
    - port, TLS on or off, HTTP/2 (default on with TLS), and "open in firewall" with its
      zone (default `wan`).
  - **HTTP companion listener:** a plain-HTTP listener bound to a TLS listener. It
    redirects to HTTPS and keeps a non-443 port in `Location`. It answers ACME HTTP-01
    challenges, and answers 404 to everything else.
  - **service:**
    - enabled, listener, hostnames (list), mode `http` or `passthrough`;
    - certificate (a file, or an ACME certificate by name), backend;
    - access policy: trusted networks, blocked, internal-only and public path lists,
      auth group, rate limits, hardening (effective value inherited from global unless
      set);
    - HSTS, timeouts, extra request headers, ordered custom rules (allow/deny/auth with
      conditions), advanced lines.
  - **backend:**
    - balance, health check (none, TCP, or HTTP with method, path and expected status),
      advanced lines;
    - servers with address, port, TLS, verify, CA file or `@system-ca`, `sni` and
      `verifyhost`, weight, backup, maxconn, enabled.
  - **auth group and users:** a password hash, enabled.
  - References use section names. Multi-values are UCI lists (F23).
- The generator, in ucode (D1):
  - loads UCI (optionally with a session save directory), validates, renders, and
    returns a report (errors, warnings, skipped parts);
  - entry points `preview`, `validate` (runs `haproxy -c` on a temp file) and `render`;
  - accepts only values matching strict patterns, and rejects whitespace, `#`, quotes
    and control characters wherever HAProxy would split or comment (F15);
  - keeps the guard against section escapes in advanced lines (D5).
- Access policy order, fixed and documented:
  1. hardening denies;
  2. rate limits and the auth-failure limit;
  3. blocked paths, denied for everyone, trusted networks included;
  4. custom rules;
  5. trusted networks allowed;
  6. internal-only paths denied to everyone else;
  7. public paths allowed without login;
  8. auth when an auth group is set;
  9. the backend.

  The GUI uses these names: "Blocked paths", "Internal-only paths", "Public paths (no
  login)" (F19).
- Host matching: `req.hdr(host),host_only,lower` (F6).
- Paths (F7): deny ambiguous paths (`//`, `/./`, `/../`, encoded `.` `/` `\`, a
  backslash), then match the URL-decoded, lowercased path. No experimental directives
  (D4).

### 3. The service

- The init script is procd shell. It runs the generator and starts HAProxy in
  master-worker mode as now, as `nobody`. Reload is `USR2`, or a start when no instance
  runs. Apply rules follow D3.
- Write each apply's result to `/var/run/haproxy-advanced/last-apply.json`: time,
  result, errors, warnings and skipped parts. Log with the tag `haproxy-advanced`, and
  have `logs` read only that tag and HAProxy's own lines of this instance (F24). Drop
  the duplicate `status` extra command and keep `status_service`.
- Triggers: the config; `ifup`, `ifdown` and `ifupdate` of every interface a listener
  uses (F3); `acme.issue` and `acme.renew` (F14).
- Publish the firewall rules (D7). Starting, stopping or disabling a listener adds or
  removes them.
- A stats socket under `/var/run/haproxy-advanced/`, mode 0600, for the runtime panel.
  Advanced lines may not add another one.
- The generator refuses two listeners on the same address and port (F2). It warns when
  uhttpd (`/etc/config/uhttpd`) or another process already listens there.
- Stock haproxy: reported, never touched without the GUI's confirmation (D8, F20).

### 4. Safe defaults

- Remove the F1 rule. "Hardening" now means:
  - deny ambiguous paths (F7);
  - `timeout http-request 10s`;
  - delete the client's `X-Forwarded-For`, `Forwarded` and `X-Real-IP`, then add
    `X-Forwarded-For` and set `X-Forwarded-Proto` and `X-Forwarded-Port` (F9).

  Each part is tested on its own.
- Timeouts (F12):
  - `timeout tunnel` goes in backends;
  - connect, client, server, http-request, keep-alive and tunnel are configurable per
    service or backend, with documented defaults;
  - the WebSocket preset sets the tunnel timeout in the backend.
- Rate limits (F18): IPv6-capable tables, and a request-rate default measured against a
  real page load of a typical web UI, recorded in the status file.
- Auth (F10): limit failed logins per source (count 401 answers in a stick table, then
  answer 429 for a period). Defaults are documented and configurable. Measure the cost
  of one check on the VM for `$6$` at the chosen rounds and for `$2y$10$`, and record it.
- Backend TLS (F13): `verify required` needs a CA file or `@system-ca`. `sni` and
  `verifyhost` are offered, and the default for a private LAN address stays
  `verify none`, as now.

### 5. The GUI

- Menu `Services → HAProxy Advanced` with tabs:
  - **Overview:**
    - state, and the last apply result with errors, warnings, skipped parts and what to
      do;
    - port conflicts and the stock-haproxy notice (with its confirmed stop/disable);
    - the runtime panel and the instance's logs.
  - **Services:** a table, an "Add service" dialog, and an editor with tabs (General,
    Access, Paths, Authentication, TLS, Headers & timeouts, Advanced).
  - **Listeners, Backends, Users, Certificates, Settings.**
  - **Configuration:** the rendered config of the current unsaved changes, with
    `haproxy -c`'s result (F5).
- The "Add service" dialog replaces the wizard.
  - Presets fill visible, editable fields. The WebSocket preset sets the backend tunnel
    timeout.
  - It creates or reuses a listener and a backend.
  - It never duplicates or overwrites a name (F4, F2).
- References are drop-downs and lists are dynamic lists (F23). Inherited values show
  their effective state (F8).
- After Save & Apply, the page waits for the new `last-apply.json` and shows the result
  (F5).
- Certificate picker:
  - lists files in `/etc/ssl/acme` and `/etc/haproxy/certs`, and the ACME certificates;
  - never returns key contents;
  - shows the expiry date, from HAProxy's `show ssl cert` when running.
- Users: the hash generator from D6. Hashes are never shown in tables.
- Each listener has a firewall checkbox (D7).
- All server calls go through the rpcd ucode plugin, and the ACL lists exactly the
  methods and commands the GUI uses (F17). Show the methods and the ACL in the status
  file.
- Translations: `po/templates` and a complete `po/ru`.
- Works in the default theme, with no horizontal scroll at phone width.

### 6. The extras (O4)

- **HTTPS conveniences:**
  - the HTTP companion listener;
  - HSTS per service: off by default, with max-age and includeSubDomains, and no
    preload;
  - HTTP/2 through ALPN;
  - IPv6 listener addresses;
  - binding to a device.
- **ACME:**
  - the Certificates tab lists `/etc/config/acme` certificates and their files;
  - "Issue certificate" for a service's hostnames creates or updates an acme `cert`
    section that validates over HTTP-01 through the companion listener (standalone on a
    loopback port behind HAProxy, or the webroot `$CHALLENGE_DIR`; choose one and
    record why), then starts the issue and shows its progress from the log;
  - the service then uses `/etc/ssl/acme/<domain>.combined.crt`, and reloads on
    `acme.issue` and `acme.renew`;
  - DNS-01 is left to luci-app-acme, with a link;
  - `acme-acmesh` is optional: the tab explains when it is missing.
- **Runtime panel:**
  - from the stats socket: per listener, service, backend and server: status, last
    check, current and total sessions, request rate, 4xx and 5xx counts;
  - actions: server ready, drain or maintenance. These are runtime only, and the panel
    says a reload resets them. A separate "Disable permanently" action sets the UCI
    `enabled` option;
  - refresh without a page reload.
- **TLS passthrough:** a TLS listener with passthrough services becomes a TCP front.
  - It inspects the ClientHello.
  - Passthrough hostnames go to TCP backends.
  - Everything else goes over `abns@` or a unix socket with PROXY v2 to the internal
    HTTPS front, so source-based rules, logs and rate limits see the real client.
  - Passthrough services offer trusted networks and a connection rate limit. Path,
    auth, header and HSTS options are hidden for them.

### 7. Documentation

Rewrite README.md: features, install, the upgrade note from 0.1 (O3), limits, the threat
model (D5) and screenshots from the VM. Also write `docs/uci-schema.md`,
`docs/testing.md` and `CHANGELOG.md`. All in English.

## Tests

On the host, and in GitHub Actions:

- **Golden tests for the generator:** UCI fixtures go in, and the expected HAProxy
  config and report come out. Cover every option, every error, and every rejected
  value from F15.
- **A mutation pass on access-policy rendering:** at least 20 hand-made mutations
  (dropped deny, swapped order, lost `-i` or decoding, missing `host_only`, a
  passthrough route to the wrong backend, a lost XFF delete, …). Each must fail a test.
  List them in the status file.
- **Static checks:** `shellcheck` on shell scripts, `node --check` on views, and
  `ucode -c` on `.uc` files.
- **Host ucode:** build it from the tree (`make package/utils/ucode/host/compile`). CI
  builds ucode from the tree's pinned source (`85922056ef7abeace3cca3ab28bc1ac2d88e31b1`).
  If the host ucode lacks the uci module, test with a fixture loader and record that.
- **`haproxy -c`** of every golden config runs on the VM (no HAProxy on the host).

## VM acceptance

Use a `tools/accept.py` with named scenarios. SSH to the OpenWrt VM follows the pattern
of `/home/w0w/cake-autorate-rs/tools/vm_test_transport.py`:

- root, with the password as one stdin line, which the owner gives in chat when asked;
- strict host key from `/home/w0w/cake-autorate-rs/logs/vm-20260923-known_hosts`, copied
  into this project's git-ignored `logs/`.

The Ubuntu VM uses its key (see `/home/w0w/linuxreflect/AGENTS.md`).

- **Before the first run:** snapshot the VM's state:
  - `apk list -I`, `/etc/config/*` names and hashes, enabled init scripts;
  - `nft list ruleset` and listening ports;
  - `/etc/ssl/certs/ca-certificates.crt`'s hash.

  At the end, show that the VM is back to it. The exception is anything the owner asks
  to keep.
- **Ports:** LuCI holds :80 and :443 on the VM, so tests use free high ports (for
  example 18080 and 18443). Check that they are free first.
- **Install:**
  - build both APKs, then `apk add --allow-untrusted` (dependencies from the VM's
    feeds);
  - the menu works in LuCI with no manual rpcd restart (F11);
  - uninstall leaves nothing.
- **Backends on the Ubuntu VM, on high ports,** started for a run and stopped after:
  - an HTTP echo server (method, path, headers, client address);
  - a TLS server with its own test CA;
  - a WebSocket echo server.
- **Requests** go from WSL and from the Ubuntu VM with `curl` (`--resolve`, `--http2`)
  and `openssl s_client` (SNI, ALPN, certificate serial). One case per finding and
  feature:
  - **F1:** POST with `Content-Length: 0` and a POST whose body arrives late both pass.
  - **F2:** two services on one listener route by Host, to the right certificate by
    SNI. A wrong Host gets the documented answer. Two listeners on one address and port
    are refused.
  - **F3:** use a test interface `hatest` on an empty bridge (`bridge_empty`) or a dummy
    device. Never touch `wan`, `lan` or existing interfaces.
    - Restart with `hatest` down: the other listeners run and the warning shows.
    - `ifup`: its listener appears within 10 s.
    - Change its address: HAProxy follows.
    - Device binding works.
    - One VM reboot to check start at boot is allowed only after every other session
      agrees; otherwise record it as not done.
  - **F6:** `Host: name:18443` works. **F7:** every bypass from F7 and its variants is
    denied or routed as the policy says. **F9:** the echo shows only the real client
    address and `X-Forwarded-Proto`.
  - **F10:** the failed-login limit triggers and resets. A browser-made hash logs in.
  - **F12:** a WebSocket stays open past the client timeout. **F13:** `verify required`
    works with the test CA, and fails clearly without one.
  - **HTTPS conveniences:**
    - companion redirect with the port kept;
    - HSTS only when enabled;
    - `h2` negotiated;
    - IPv6 on `hatest` with a ULA address, tested from the VM itself.
  - **Firewall:** the rule appears in `nft list ruleset` and goes away with the listener.
  - **Passthrough:** the client sees the Ubuntu server's own certificate. HTTP services
    on the same port still terminate, and their echo shows the real client address.
    Trusted networks restrict passthrough.
  - **Runtime panel:** maintenance moves traffic or gives 503, ready restores it, and a
    reload resets it as documented.
  - **Stock haproxy:**
    - record its starting state;
    - check the warning, then the confirmed stop/disable;
    - restore it as found.
- **ACME with Pebble on the Ubuntu VM:**
  - get `pebble` and `pebble-challtestsrv` from Ubuntu's archive or the official
    `letsencrypt/pebble` release, checked against its published checksum;
  - challtestsrv resolves the test names to the OpenWrt VM, and Pebble's HTTP-01 port
    points at the companion listener's test port;
  - trust Pebble's root on the OpenWrt VM for the test only, and restore the CA bundle
    after;
  - issue from the GUI: HAProxy serves the new certificate (check the serial). A forced
    renew reloads it.
- **Browser runs with Playwright** (`/home/w0w/.local/share/playwright/node_modules/playwright`,
  password on stdin, as in cake-autorate-rs's `tools/*.browser.js`):
  - "Add service" with each preset, then editing;
  - the Configuration tab shows an unsaved change;
  - a deliberate error after Save & Apply shows in LuCI;
  - the hash generator, the certificate picker, the firewall checkbox and the runtime
    panel's actions;
  - Russian;
  - phone width.

  Screenshots stay in git-ignored `logs/`. Only README images of the test VM are
  committed.

## Done when

- F1–F24 are fixed, or the status file records the owner's decision for one.
- Everything in O1–O4 works on the VM, and every case above passes.
- Host tests and CI are green, and every mutation is caught.
- Both APKs build in the dedicated tree, and their contents are recorded.
- The OpenWrt VM matches its snapshot. Nothing of the goal is left running or installed
  on the Ubuntu VM, apart from cached downloads in `~/haproxy-advanced-test`.
- `docs/goals/goal-a-status.md` lists:
  - results and measurements: crypt cost, reload time, rate-limit default;
  - differences from this task, and open questions.
- Everything is committed on `goal-a` and pushed. No merge into `main`, no tag, no
  release.

## The shared VMs

Before each run on either VM, ask every other session in `ListAgents` and wait for every
answer: a question nobody has answered is not consent. Tell them when you finish.

- **OpenWrt VM `.130`:** cake-autorate-rs runs its acceptance there (SQM and
  cake-autorate on `eth1`, LuCI on :80 and :443). Its runs are timing-sensitive, so
  keep heavy builds off the host while one of them runs.
- **Ubuntu VM `.142`:** shared with linuxreflect, Linux_Storage_Spaces and NasMount.

## Do not

- Touch cake-autorate, SQM, network, firewall or uhttpd configuration on the OpenWrt VM.
  The exceptions are this goal's `hatest` interface and its procd firewall rules, all
  removed at the end.
- Reboot either VM, except the one consented reboot above. Never change routes,
  adapters or VMware settings.
- Use the physical routers 10.0.77.1, 10.0.77.2 or 10.0.100.1, or the router
  `192.168.189.134`.
- Use a public ACME server (Let's Encrypt production or staging), or expose anything to
  the internet.
- Put a password on a command line, in a file, in a log or in memory, or send it to
  Gemini. Gemini may give a second opinion on the schema or the policy order, with
  source only.
- Change `luci-app-haproxy-tcp`, its repository, or the build tree's copy of it.
- Merge into `main`, tag, release, change GitHub repository settings, or open a pull
  request to OpenWrt.

Stop on blockers, and when a decision belongs to the owner.
