# Goal A status

Task: `docs/goals/goal-a-task.md`. Branch `goal-a` (pushed; not merged, no tag, no
release). Final state: **done**, including the one consented VM reboot.

## Result

| Part | Result |
|---|---|
| 1. Layout and packaging | two packages and a Russian translation package build in the dedicated 25.12.4 tree; the service package builds byte for byte reproducibly |
| 2. Schema and generator | `docs/uci-schema.md`; ucode generator (util, model, render, core, system) |
| 3. The service | procd init, ctl, apply results in `last-apply.json`, master-socket reloads, interface and ACME triggers, procd firewall data |
| 4. Safe defaults | hardening, path forms, forwarding headers, timeouts, rate and failed-login limits |
| 5. The GUI | eight tabs, "Add service" dialog, staged preview, apply results, runtime panel, password hashing in the browser, Russian |
| 6. The extras (O4) | HTTPS companion/HSTS/HTTP/2/IPv6/device binding, ACME from the GUI, runtime panel, TLS passthrough |
| 7. Documentation | README, `docs/uci-schema.md`, `docs/testing.md`, CHANGELOG |
| Host tests and CI | 26 golden fixtures, 35/35 mutations caught, crypt vectors, compile check, shellcheck; CI green |
| VM acceptance | every scenario passes on the OpenWrt VM, including start at boot after the one consented reboot; the VM matches its snapshot again |

Final APKs (`bin/packages/x86_64/haproxyadv/` of the dedicated tree, built from the
branch head before this file's last update):

```
2d88a9596edc5ba008afa8c28ea451e66cafb7ca29854d93933d00f9789219e9  haproxy-advanced-0.2.0-r1.apk
4627dc6f113fc8ff9f96e874fb7d9f1bbf138873ae3eb7e66916ea94c4f89a5c  luci-app-haproxy-advanced-0.2.0-r1.apk
daa55fc6a8fb9b29960ce4f3f8bafee9cb0b07aea2e319f1c804d754e4a3532d  luci-i18n-haproxy-advanced-ru-0.2.0-r1.apk
```

## Audit findings

| | Fix | Evidence |
|---|---|---|
| F1 | The CVE-2021-40346 rule is gone; hardening is now ambiguous-path denial and header cleanup | VM: POST with `Content-Length: 0` and a 1.5 s late body → 200 |
| F2 | Shared listeners, `use_backend` by `host_only` Host, certificates by SNI; two listeners on one address and port are refused | VM: two services and a passthrough service on :18443 routed correctly, unknown host 404, duplicate listener refused in the staged preview |
| F3 | Interface triggers; interface addresses bound with `transparent`; device binding | VM `interfaces`: ifdown/ifup/readdress/start-while-down, IPv6, device listener |
| F4 | Empty default config; the dialog generates names no section uses | browser: Add service; golden `duplicate_hostname` |
| F5 | rpcd preview with the session's save directory; `last-apply.json` shown after Save & Apply; failing apply keeps the running config | VM: staged preview, broken config refused while serving, LuCI notice |
| F6 | `req.hdr(host),host_only,lower` | VM: Host with `:18443` matches |
| F7 | Deny lists on the decoded, lower-cased path without `;` parameters; ambiguous paths denied | VM: 15 path forms |
| F8 | Tri-state hardening; the GUI shows the inherited value | golden `server_options`, `paths_without_hardening` |
| F9 | Client forwarding headers deleted, `X-Forwarded-For/-Proto/-Port` set | VM: spoofed headers removed |
| F10 | Failed-login limit; hash made in the browser; one `crypt()` per request with credentials | VM: 401 then 429; browser-made hashes log in |
| F11 | No own postinst or uci-defaults; luci.mk reloads rpcd | VM: rpcd serves the object right after install |
| F12 | `timeout tunnel` in backends; all timeouts configurable; `timeout http-request` | VM: WebSocket idle 8 s with client timeout 5 s |
| F13 | `verify required` needs `ca_file` or `@system-ca`; `sni`, `verifyhost` | VM: verified backend; refusal without CA |
| F14 | `acme.issue` and `acme.renew` triggers; `/etc/ssl/acme/<domain>.combined.crt`; no split mode | VM `acme`, `acme-gui` |
| F15 | Strict validators for every value | golden `invalid_values` |
| F16 | Dead options gone (new schema) | schema |
| F17 | ACL lists exactly the plugin's methods; no init exec rights | `acl.d` |
| F18 | Per-service rate limit, IPv6-capable tables, measured default | measurement below |
| F19 | Policy order fixed and named in the GUI (blocked, internal-only, public) | golden `basic`, VM F7 cases |
| F20 | Overview warns about the stock service and stops/disables it after confirmation | browser `stock` |
| F21 | Two packages, maintainer email, translations, per-app view directory | packaging |
| F22 | README: advanced lines are root-equivalent; the guard is not a boundary | README |
| F23 | Section-name references, drop-downs refreshed on every render, UCI lists | browser: the new backend kept |
| F24 | `logs` reads this service's tag; `status_service` only | init script |

## Owner decisions

- O1: tests ran on the OpenWrt VM 192.168.189.130 (OpenWrt 25.12.5 r33051, x86_64,
  HAProxy 3.2.21 from the feed); backends and Pebble on the Ubuntu VM .142.
- O2: two packages. O3: no migration; 0.1 files are refused and the GUI moves them to
  `.v01` (browser `legacy`). O4: all four extras, each with a VM check.
- 2026-11-13: the owner allowed taking the VM's root password from the encrypted
  test-asset store of cake-autorate-rs; it reached ssh only through stdin.
- 2026-11-17: the owner started the VM again after it had been suspended.

## Final VM acceptance

Fresh install of the final APKs on the VM, after a cleanup back to the snapshot of
2026-11-13 (`logs/accept-snapshot-1/snapshot.json`):

| Scenario | Checks | Failed |
|---|---|---|
| install (final-2, final APKs) | 8 | 0 |
| golden (HAProxy 3.2.21, 20 configurations, no warning) | 40 | 0 |
| functional | 58 | 0 |
| interfaces | 20 | 0 |
| acme (Pebble, issue and forced renew) | 8 | 0 |
| acme-gui (issue from the Certificates tab) | 7 | 0 |
| browser (final-2, final APKs) | 25 | 0 |
| measure | 4 | 0 |
| cleanup (final-2): packages, /etc/config, init scripts, CA bundle, crontab, sockets, nft | 8 | 0 |
| boot (one reboot, see below) | 13 | 0 after correcting one check's expectation (1 at run time) |
| cleanup after the reboot (boot-2) | 7 | 0 |

golden, functional, interfaces and acme ran on the first final build; the second one
changed only `certificates.js` of the luci-app (the service package is byte for byte
the same), and install, acme-gui and browser ran on it.

### Start at boot (the one reboot)

On 2026-11-17 all eight other sessions (w0w-61, neuroguard, rvp, nasmount-44,
bli-kvm, linuxreflect-a5, openwrt-ha-feed-1d, luci-app-kea-7c) explicitly agreed to
one reboot of .130. luci-app-kea asked to check afterwards that no Kea component runs.
Sequence: `baseline boot`, `install boot` (8/8), `boot 1`, `cleanup boot`, `cleanup
boot-2`.

- Before the reboot the scenario applied the functional configuration plus a LuCI
  service (uhttpd behind HAProxy) and checked that no other ssh session and no Kea
  process was on the VM.
- After the reboot (new boot id): `last-apply.json` says `applied` and HAProxy listens
  on 18443 at **48.5 s of uptime** (76 s from the `reboot` command to the check);
  procd runs the instance; the procd firewall rule is back in fw4; LuCI through
  HAProxy answers; the companion redirects with 308; a protected path needs a login
  and the login works; no Kea component runs.
- At run time one check failed: it expected the stock `haproxy` service to be
  stopped. That expectation was wrong: the feed's haproxy package enables its own
  service with a sample configuration (ports 81, 444, 60000) when it is installed,
  and by design (F20) the Overview only offers to stop it. The check now requires the
  stock service to be in the same state after the reboot as before it. Since the task
  allows one reboot, the corrected check was evaluated on the data the run recorded
  (`logs/accept-boot-1/recheck.json`): **PASS**. Before: enabled and running
  (`logs/accept-install-boot/stock-haproxy.json`, 7 s before the scenario). After:
  enabled and running, procd instance on `/etc/haproxy.cfg`, ports 81/444/60000, no
  overlap with 18443/18080 (`logs/accept-boot-1/stock-after-boot.txt`, read-only
  command at 04:32:11Z, before the cleanup). Four haproxy processes before and after
  (`proc-before.txt`, `proc-after.txt`). A fresh run of the corrected scenario
  needs a second reboot, which only the owner can allow.
- The first comparison with the snapshot after the reboot differed only in dnsmasq's
  link-local listener on SQM's `ifb4eth1`, which gets a random MAC each time it is
  created (`fe80::547a:7cff:fe98:e64c` → `fe80::6cb9:4dff:fe79:118e`). The cleanup
  now compares link-local listeners by count; `cleanup boot-2`: 7/7.

### Bugs the VM found (all fixed, with tests where the host can test them)

- haproxy -c 3.2.15/3.2.21: empty header value, `httplog` without logging, implicit
  defaults of stick-table backends, response rules conditioned on the request Host.
- An unparsable UCI file was reported as "disabled"; `rand()` is not a ucode builtin
  (every apply died); the ctl swallowed exceptions.
- A fresh IPv6 address is tentative during DAD and its bind failed (`transparent`).
- GUI: stale reference drop-downs (the editor would have saved another backend), the
  nested password dialog replaced the editor, `notAfter:` in HAProxy 3.2, a
  whitespace-only translation key, the Add button disabled until a name was typed, no
  Save & Apply on the Certificates tab ("Save and issue" now applies at once).

## Measurements

On the VM (2 vCPU of an AMD Ryzen Threadripper 3970X; slower router CPUs pay more):

- **Password check** (HAProxy worker CPU per request, best of 3): no login 1.4 ms,
  `$6$` 5000 rounds 3.7 ms, bcrypt cost 10 47.0 ms. One check costs **2.3 ms** for
  `$6$` and **45.6 ms** for bcrypt, about 20 times more. The GUI makes `$6$` with the
  default 5000 rounds; the README warns about slow hashes.
- **Rate limit default**: LuCI served through HAProxy and moved through five pages by
  a script (faster than a person): 211 requests cold, 227 warm, 29-55 per page, at most
  **136-152 in any 10 s window**. The default limit of 300 per 10 s keeps a margin of
  two over that.
- **Reload** (generate, `haproxy -c`, swap, master reload): 3.6-3.7 s per
  `/etc/init.d/haproxy-advanced reload`, of which 0.14 s is the ssh round trip.
- **Interfaces**: a listener comes back 4.7 s after `ifup`; after an address change
  HAProxy listens on the new address after 4.7 s.
- **ACME**: issue through the companion with Pebble took 15 s.

## Host tests and CI

- 26 golden fixtures (`uci_error` added for unreadable files), 35 mutations all caught,
  crypt vectors, compile check of the ctl and plugin, `sh -n`; CI (GitHub Actions)
  builds ucode at 85922056 and runs them with shellcheck: green on every push since
  3ffac02.
- Before the OpenWrt VM was available, OpenWrt's own HAProxy (3.2.15, built in the
  tree) ran on the Ubuntu VM through the musl loader (`tools/golden_ubuntu.sh`,
  `tools/prerun_ubuntu.py`): every golden configuration valid without a warning, and
  43/43 request checks.

## Decisions taken during the goal

- Problems of backends and auth groups count only when a service uses them; disabled
  sections are not validated.
- Deny lists compare the decoded, lower-cased path without `;` parameters; allow lists
  compare the decoded path case-sensitively; ambiguous paths are denied for every
  service with path lists, hardening or not.
- `http_auth` runs once per request and only with an `Authorization` header; failed
  logins are counted before the check.
- A TLS listener whose services wait for certificates keeps its HTTP companion running,
  so ACME HTTP-01 can issue them. ACME uses acme.sh standalone on a loopback port behind
  the companion (no web server changes); acme opens that port in nft only during the
  issue, as the acme package does by design.
- Interface-derived binds use `transparent`.
- Pebble from Ubuntu's archive (`apt-get download pebble` 2.3.1+ds-1, SHA256 matches
  the signed index), unpacked under `~/haproxy-advanced-test`.

## Notes on coverage

- The ACME scenario sets the acme configuration through uci; the GUI path is covered by
  the separate `acme-gui` scenario.

## Incidents

- 2026-11-13 15:53Z: both test VMs were stopped by a VMware automation command
  (`Vix: VMAutomationPowerOff` in the OpenWrt VM's vmware.log), not by this session. The
  owner resumed .130 on 2026-11-17.
- 2026-11-17: the first cleanup removed `/etc/config/*.apk-new` by a glob, deleting
  `kea.apk-new`, `sqm.apk-new`, `cake-autorate.apk-new` and `neuroguard.apk-new` of other
  projects, and `apk del socat openssl-util` removed pre-existing `/etc/config/socat`
  and `/etc/config/openssl`. All were restored from their packages with the snapshot's
  sha256 (only mtimes differ); the luci-app-kea and neuroguard sessions confirmed their
  files. The cleanup now removes only what this goal's own install logs name and
  restores the configuration files its packages touch (`baseline` scenario).

## Open questions

- Merge of `goal-a` into `main` and a 0.2.0 release are the owner's.
