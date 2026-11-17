# Testing

## On the host

The tests use the host ucode of an OpenWrt 25.12 build tree (or a ucode built from the
same commit, as CI does). That ucode has no `uci` module, so fixtures are read by
`tests/lib/uci.uc`.

```sh
UCODE=/path/to/staging_dir/hostpkg/bin/ucode
$UCODE tests/run.uc                          # golden tests
UPDATE=1 $UCODE tests/run.uc [fixture ...]   # rewrite expected files; review the diff
UCODE=$UCODE python3 -I tests/mutations.py   # every access-policy mutation must fail a test
UCODE=$UCODE tests/syntax.sh                 # compile the ctl and the rpcd plugin
node tests/js/crypt.test.js                  # browser-side SHA-512 crypt
shellcheck -s sh -e SC2034,SC3043 haproxy-advanced/files/haproxy-advanced.init
```

### Golden tests

Each directory in `tests/fixtures/` holds:

| File | Contents |
|---|---|
| `config` | the UCI configuration |
| `env.json` | the environment snapshot: interface states, existing files, ACME certificates, sockets other programs listen on, ports uhttpd is configured for |
| `expected.cfg` | the HAProxy configuration, for valid cases |
| `expected.json` | the report: `ok`, errors, warnings, skipped parts, firewall rules, interfaces to watch |

Together they cover every option of `docs/uci-schema.md`, every error message and
every rejected value (`invalid_values`), runtime conditions (`iface_down`,
`device_mode`, `acme_missing_cert`, `foreign_port`), passthrough (`passthrough_mixed`,
`passthrough_only`) and the policy forms (`basic`, `rules`,
`paths_without_hardening`).

### Mutation pass

`tests/mutations.py` applies 32 hand-made mutations to the generator, one at a time,
and runs the golden tests on each: the policy order, the deny and allow path forms,
host matching, forwarding headers, login counting, rate limits, passthrough routing,
HSTS, redirects, firewall rules, listener conflicts and foreign ports. Every mutation
must make at least one test fail.

## On the test VMs

`tools/accept.py` drives the OpenWrt test VM (root password on one stdin line) and the
Ubuntu VM that hosts the test backends (`tools/ubuntu_servers.py`) and the Pebble ACME
server. Output goes to `logs/accept-SCENARIO-ATTEMPT/`.

```sh
tools/testpki.sh                                # test-only CA and certificates
printf '%s\n' "$PW" | tools/accept.py probe 1
printf '%s\n' "$PW" | tools/accept.py snapshot 1
printf '%s\n' "$PW" | tools/accept.py baseline 1
printf '%s\n' "$PW" | tools/accept.py install 1
printf '%s\n' "$PW" | tools/accept.py backends 1        # 'backends 1 stop' stops them
printf '%s\n' "$PW" | tools/accept.py golden 1  # haproxy -c of every golden config
printf '%s\n' "$PW" | tools/accept.py functional 1
printf '%s\n' "$PW" | tools/accept.py interfaces 1
printf '%s\n' "$PW" | tools/accept.py acme 1
printf '%s\n' "$PW" | tools/accept.py acme-gui 1
printf '%s\n' "$PW" | tools/accept.py browser 1
printf '%s\n' "$PW" | tools/accept.py measure 1
printf '%s\n' "$PW" | tools/accept.py cleanup 1 logs/accept-snapshot-1/snapshot.json
```

| Scenario | What it checks |
|---|---|
| `install` | both APKs install with their dependencies; rpcd serves `luci.haproxy-advanced` without a manual restart |
| `golden` | every golden configuration passes `haproxy -c` without warnings |
| `functional` | requests through HAProxy: empty POST bodies, late bodies, routing by Host and SNI, host with a port, every path bypass form, forwarding headers, HTTP/2, the HTTP companion's redirect, passthrough beside HTTPS services, WebSocket idle, rate and failed-login limits, the runtime panel, the staged preview, a failing apply that keeps the running configuration, the firewall rule |
| `interfaces` | a listener on a test interface follows `ifdown`, `ifup` and address changes; device binding; IPv6 |
| `acme` | issue and forced renewal through the HTTP companion with Pebble; HAProxy serves the new certificate |
| `acme-gui` | the same issue started from the Certificates tab |
| `browser` | every LuCI step of `tools/browser.js`, with checks on the VM between steps |
| `measure` | CPU cost of one password check, requests of LuCI served through HAProxy, reload times |
| `baseline` | before an install: keeps the configuration files the packages touch |
| `cleanup` | removes only what this goal installed and compares the VM with the snapshot |

The VMs are shared with other projects: ask the other sessions before a run, and never
remove files by pattern there.

The measurements of the last acceptance run are in
[docs/goals/goal-a-status.md](goals/goal-a-status.md).
