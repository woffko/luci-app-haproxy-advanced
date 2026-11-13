# Goal A status

Task: `docs/goals/goal-a-task.md`. Branch `goal-a`.

## Progress

| Stage | State |
|---|---|
| 1. Layout and packaging | done: two packages build in the dedicated tree |
| 2. Schema and generator | written, host tests pass; VM check pending |
| 3. The service | written; VM check pending |
| 4. Safe defaults | written; VM check pending |
| 5. The GUI | written, Russian translation done; browser check pending |
| 6. The extras | written; VM check pending |
| 7. Documentation | README, schema, testing.md and CHANGELOG written; measurements pending |
| Tests | 25 golden fixtures pass, 34/34 mutations caught, crypt vectors pass, 21/21 golden configs pass `haproxy -c` 3.2.15 without warnings; CI green |
| VM acceptance | OpenWrt VM: install 8/8, golden 40/40, functional 58/58, interfaces 20/20, ACME 8/8, every browser step passes; final clean run and cleanup pending (both VMs were powered off by a VMware automation stop at 15:53Z) |

## Stage 1: layout and packaging

- The 0.1 files (`Makefile`, `root/`, `htdocs/`) are gone. The repository is a feed with
  `haproxy-advanced/` (package.mk) and `luci-app-haproxy-advanced/` (luci.mk).
- The build tree's untracked copy `package/luci-app-haproxy-advanced` (2026-06-06)
  was checked with `git status` and removed. The tree had been cleaned since June
  (no `dl/`, `staging_dir/`, `build_dir/`), so tools, the toolchain and the host
  ucode were rebuilt (`logs/build-toolchain-1.log`, exit 0).
- `feeds.conf` = `feeds.conf.default` + `src-link haproxyadv /home/w0w/luci-app-haproxy-advanced`.
- Built `haproxy-advanced-0.2.0-r1.apk` (22 829 bytes) and
  `luci-app-haproxy-advanced-0.2.0-r1.apk` (25 032 bytes), noarch.

APK contents and modes (from `build_dir/.../ipkg-all`):

```
haproxy-advanced 0.2.0-r1
  depends: haproxy libc ucode ucode-mod-fs ucode-mod-socket ucode-mod-ubus ucode-mod-uci
  600 /etc/config/haproxy-advanced            (conffile)
  755 /etc/init.d/haproxy-advanced
  755 /usr/libexec/haproxy-advanced/ctl
  644 /usr/share/haproxy-advanced/{core,model,render,system,util}.uc

luci-app-haproxy-advanced 0.2.0-r1
  depends: haproxy-advanced libc luci-base ucode-mod-socket
  644 /usr/share/luci/menu.d/luci-app-haproxy-advanced.json
  644 /usr/share/rpcd/acl.d/luci-app-haproxy-advanced.json
  644 /usr/share/rpcd/ucode/luci.haproxy-advanced
  644 /www/luci-static/resources/haproxy_advanced/{common,crypt}.js
  644 /www/luci-static/resources/view/haproxy-advanced/{overview,services,listeners,
      backends,users,certificates,settings,configuration}.js
```

- F11: the luci-app has no own postinst any more; luci.mk's post-install runs
  `default_postinst` (uci-defaults, init script enable/start) and then removes the
  LuCI caches and runs `/etc/init.d/rpcd reload`. There is no uci-defaults script.
- `AGENTS.md` added, with the Longrun section of `/home/w0w/AGENTS.md`.

## Host tests

- `tests/run.uc`: 25 fixtures, all pass with the tree's host ucode
  (`staging_dir/hostpkg/bin/ucode`, built with UCI_SUPPORT=OFF, so fixtures are read
  by `tests/lib/uci.uc`).
- `tests/mutations.py`: 32 mutations of the access policy and its checks, 32 caught.
  The first run caught 31; "ambiguous paths only with hardening" survived until the
  fixture `paths_without_hardening` was added.
- `tests/syntax.sh`: the ctl and the rpcd plugin (with every module they import)
  compile with stub `uci`, `ubus` and `socket` modules.
- `tests/js/crypt.test.js`: SHA-512 against Node for 13 lengths and the seven `$6$`
  vectors of Drepper's specification.
- shellcheck is not installed on the host; `sh -n` passes and CI runs shellcheck.

## Decisions taken during the goal

- Problems of backends and auth groups count only when a service uses them, and
  disabled sections are not validated, so an unused or disabled section with a typo
  cannot block an apply. Unused sections with problems get one warning each.
- Deny lists (blocked, internal-only, deny and auth rules) compare the decoded,
  lower-cased path without `;` parameters; allow lists (public paths, allow rules)
  compare the decoded path case-sensitively, so neither form can be bypassed by case
  or parameters. Ambiguous paths are denied for every service with path lists,
  hardening or not.
- The login check runs `http_auth` once per request and only when an
  `Authorization` header is present (result kept in a transaction variable); failed
  logins are counted before the check, so guessing costs at most the limit's number of
  hash checks per minute.
- A TLS listener whose services all wait for certificates keeps its HTTP companion
  running, so ACME HTTP-01 can issue the missing certificate.
- The Ubuntu VM's Pebble comes from Ubuntu's archive (`apt-get download pebble`,
  2.3.1+ds-1, SHA256 f1597a5a…0ba matches the signed index), unpacked under
  `~/haproxy-advanced-test`; nothing installed system-wide.

## haproxy -c before the OpenWrt VM (Ubuntu VM)

While the OpenWrt VM password was pending, OpenWrt's own HAProxy (feed package
haproxy-ssl 3.2.15-1 of the 25.12.4 tree, built in the dedicated tree) ran on the
Ubuntu VM through the musl loader, nothing installed (`tools/golden_ubuntu.sh`).
It checked every golden configuration with `haproxy -c`:

- run 1: 20 of 21 valid. Found three generator bugs the host tests could not see:
  an empty `request_header` value rendered as `set-header X ""` (an error); `option
  httplog`/`tcplog` with `log_requests none` (warning: no log address); stick-table
  backends without `from` mixed implicit and explicit defaults (warning).
- run 2: 21 of 21 valid; one more warning showed a real bug: a service's advanced
  `http-response` lines were conditioned on the request's Host, which a response rule
  cannot see, so they never applied. They are now conditioned on the transaction
  variable `txn.ha_svc`, like HSTS.
- run 3: 21 of 21 valid, no warning in any configuration.

Two mutations were added for these rules (34 in all, all caught).

Then the request checks of the functional scenario ran against the same HAProxy on the
Ubuntu VM (`tools/prerun_ubuntu.py`, configuration made by the generator from the
scenario's UCI config, run as the codex user with the user/group lines removed and
the sockets moved to its directory). Result, run 4: **43 of 43 pass**:

- F1: POST with `Content-Length: 0` and a POST whose body arrives 1.5 s late: 200;
- F2: two HTTPS services and a passthrough service on one port, routed by Host, each
  with its own certificate by SNI; an unknown host gets 404;
- F6: the Host header with `:18443` matches;
- F7: `/cgi-bin/x`, `/CGI-BIN/x`, `/%63gi-bin/x`, `/cgi-bin;x/y` → 403;
  `//cgi-bin/x`, `/x/../cgi-bin/`, `/x/%2e%2e/cgi-bin/`, `/a%00b`, `/share/../admin/`
  → 400; `/admin/`, `/ADMIN/`, `/admin;p/` → 403; `/share/f` → 200 without login,
  `/SHARE/f` and `/other` → 401;
- D6: the browser-made `$6$` hash logs in; F10: wrong passwords get 401, then 429;
- F9: the backend sees only `X-Forwarded-For: 192.168.189.1`, no `X-Real-IP` or
  `Forwarded`, `X-Forwarded-Proto: https`, `X-Forwarded-Port: 18443`;
- F12: a WebSocket stays open past 8 s idle with a 5 s client timeout;
- F13: `verify required` with the test CA and `verifyhost` works;
- HSTS only on the service that enables it; HTTP/2 negotiated; the companion port
  redirects with 308 to `https://…:18443/p?q=1` and answers 404 to unknown hosts;
- passthrough: the client sees the server's own certificate, and the HTTPS services
  behind the TCP front still see the real client address (PROXY v2);
- rate limit 20/10 s: 429 after 20; runtime `set server … state maint` gives 503,
  `ready` gives 200 again.

Run 1 found that the master CLI path given to `-S` must be absolute (the init script
already uses an absolute path; only the test harness was wrong). The OpenWrt VM run
still has to cover what depends on OpenWrt: procd, the firewall rule, ubus and LuCI,
interfaces, ACME, the staged preview and the failing apply.

## OpenWrt VM acceptance (192.168.189.130, OpenWrt 25.12.5 r33051, x86_64)

The root password came from the encrypted test-asset store of cake-autorate-rs, with the
owner's permission (2026-11-13), and reached ssh only through stdin.

- **probe**: `wan` (eth1) holds 192.168.189.130 and is in firewall zone `lan`; uhttpd
  listens on 0.0.0.0/[::]:80 and :443; no stock haproxy before the install.
- **snapshot** (`logs/accept-snapshot-1/snapshot.json`): 313 packages, 41 files in
  /etc/config, no crontab, LuCI language `auto`.
- **install**: 8/8. `apk add` of both APKs and acme-acmesh pulled haproxy 3.2.21-r1,
  ucode-mod-socket, socat, openssl-util; rpcd served `luci.haproxy-advanced` right
  after the install without a manual restart (F11); `default_postinst` enabled the
  init script; no uci-defaults left.
- **golden**: 40/40: the 20 golden configurations pass `haproxy -c` of the VM's
  HAProxy 3.2.21 without a warning (earlier notes said 21; there are 20 valid ones).
- **functional**: 58/58 on run 3. Runs 1-2 found:
  - an unparsable UCI file produced "disabled" instead of an error (fixed: reported
    as an error);
  - `rand()` is not a ucode builtin, so every apply died (fixed: `clock()`), and the
    ctl swallowed the exception (fixed: recorded as a failed apply);
  - test bugs: a service and a backend both named `pt`, a stale last-apply.json read.
- **interfaces** (F3): 20/20 on run 5. Run 1 found a real bug: a fresh IPv6 address is
  tentative during duplicate address detection, the reload failed with "cannot bind
  socket (Address not available)" (the old configuration kept running and the failure
  was reported). Interface addresses are now bound with `transparent`. The test
  interface needed a veth port so its IPv6 address leaves the tentative state. Times:
  listener back 7.5 s after `ifup`, HAProxy on the new address 4.6 s after the change.
- **acme**: 8/8 with Pebble 2.3.1 and challtestsrv on the Ubuntu VM: issued through
  the HTTP companion (port 18080) and acme.sh standalone on 18402; `acme.issue` and a
  forced `acme.renew` reloaded HAProxy with the new certificate; acme's temporary
  nft rule is gone afterwards.
- **browser**: every step passed after fixes: Add service dialog → editor → Save &
  Apply → "configuration applied" notice; unsaved change visible on the Configuration
  tab; failing apply shown in LuCI while the old configuration serves; password set in
  the user editor; certificate list with expiry; firewall checkbox (2 → 0 → 2 rules);
  runtime maintenance/ready from the GUI (503/200); stock haproxy stopped and
  disabled from the GUI and restored as found; 0.1 file refused and moved to `.v01`
  from the GUI; Russian; no horizontal scroll at 390 px on any tab. Bugs found and
  fixed: stale reference drop-downs (the editor would have saved another backend),
  the nested password dialog replaced the editor, HAProxy 3.2 prints `notAfter:`, a
  whitespace-only translation key.
- **reboot**: not done. All nine sessions said a reboot does not affect them, but most
  said the approval is the owner's; the task allows the reboot only when every session
  agrees, so it was recorded as not done. Start without an interface address is
  covered by the interfaces scenario instead.
- **measurements**: the first password-cost run over the network was dominated by
  latency; the CPU-time run was cut short when both VMs were powered off by a VMware
  automation stop (`Vix: VMAutomationPowerOff` at 15:53:52Z in the OpenWrt VM's
  vmware.log; not issued by this session).

## CI

- Run 43370201434 failed on shellcheck of `tests/syntax.sh`: the `-L` stub pattern
  was unquoted, so the shell globbed it and the stubs were never resolved as modules.
  Fixed in 3ffac02; run 43370407245 is green (ucode built at 85922056, golden tests,
  mutation pass, compile check, crypt vectors, JavaScript syntax, shellcheck, JSON).

## Open questions

- **Blocker: the OpenWrt test VM's root password.** The task says the owner gives it
  in chat. It was asked for on 2026-11-13 and has not arrived yet, so no VM
  acceptance has run: no `haproxy -c` of the golden configurations, no request
  through HAProxy, no browser step. The project-memory store of cake-autorate-rs holds
  12 encrypted test assets, possibly this password; they belong to another project and
  were not used without the owner's word.
- Consent for the shared VMs: all nine other sessions answered on 2026-11-13 that
  they do not use 192.168.189.130 or 192.168.189.142 (luci-app-kea: keep Kea
  disabled on .130; neuroguard: leave 192.168.189.146 alone). The one VM reboot the
  task allows needs a separate question when it comes.
