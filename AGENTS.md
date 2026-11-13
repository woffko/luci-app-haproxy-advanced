# Agent instructions for luci-app-haproxy-advanced

This repository is an OpenWrt package feed with two packages:

- `haproxy-advanced/`: the service (procd init script, UCI config, ucode generator in
  `files/ucode/`, command line `files/haproxy-advanced-ctl`);
- `luci-app-haproxy-advanced/`: the LuCI views, menu, rpcd ACL and the rpcd ucode
  plugin `luci.haproxy-advanced`.

`docs/uci-schema.md` is the contract between them. Goals and their status live in
`docs/goals/`.

## Language

Everything committed here is in English: code comments, documentation, commit
messages, pull requests. Conversation with the owner may be in Russian.

## Build

The dedicated OpenWrt tree is `/home/w0w/build/openwrt-25.12.4-clean-haproxy-luci`
(tag v25.12.4, x86_64). It uses this checkout through a `src-link haproxyadv` feed:

```sh
cd /home/w0w/build/openwrt-25.12.4-clean-haproxy-luci
make package/feeds/haproxyadv/haproxy-advanced/compile \
     package/feeds/haproxyadv/luci-app-haproxy-advanced/compile V=s
ls bin/packages/x86_64/haproxyadv/
```

Packaging needs fakeroot and runs outside any sandbox. Do not touch the tree's
`package/luci-app-haproxy-tcp`, which belongs to the sibling project.

## Tests

```sh
UCODE=/home/w0w/build/openwrt-25.12.4-clean-haproxy-luci/staging_dir/hostpkg/bin/ucode
$UCODE tests/run.uc              # golden tests; UPDATE=1 rewrites expected files
UCODE=$UCODE tests/syntax.sh     # compile every ucode file
UCODE=$UCODE tests/mutations.sh  # access-policy mutations must all fail a test
node tests/js/crypt.test.js      # browser-side SHA-512 crypt
shellcheck -s sh haproxy-advanced/files/haproxy-advanced.init
```

The host ucode has no `uci` module, so the tests read fixtures with
`tests/lib/uci.uc`. `haproxy -c` of the golden configurations runs on the test VM
(`tools/accept.py golden`), never on the host.

## Test equipment

- OpenWrt test VM `192.168.189.130` (root). The owner gives the password in chat;
  pass it on one stdin line, never on a command line or in a file. It is shared with
  cake-autorate-rs: ask the other sessions before each run and leave its SQM,
  cake-autorate, network, firewall and uhttpd configuration alone.
- Ubuntu VM `192.168.189.142` (user `codex`, key login, see
  `/home/w0w/linuxreflect/AGENTS.md`): test backends and the Pebble ACME server.
- Never use the physical routers 10.0.77.1, 10.0.77.2, 10.0.100.1, or public ACME
  servers in tests.

## Long-running commands with Longrun MCP

- For a reviewed, trusted, non-interactive command expected to run longer than about 30 seconds, use `longrun.start_job` exactly once when it is available and the exact project root is enrolled.
- After a bridge-enabled `start_job` returns, never call `longrun.get_job`, `collaboration.wait_agent`, a generic wait tool, `write_stdin`, log-tail tools, or any polling loop in that turn. In the automatically resumed turn, call `longrun.get_job` exactly once and continue from the terminal result.
- Use `wake_policy="none"` only with ordinary `codex` or an explicitly requested manual fallback. In that mode automatic wakeup is unavailable: end the turn without waiting, and use one `longrun.get_job` only in a later user-resumed turn. If it is still running, end that turn without polling again.
- Treat `longrun.run_and_wait` as legacy compatibility mode because current Codex runtimes may convert a pending blocking call into model-driven wait cycles. Progress heartbeats are disabled by default and do not fix that outer wait loop.
- Never put secret values in command arguments, MCP fields, prompts, or environment. For one reviewed non-interactive command that accepts one finite secret stdin payload, prefer `project_memory_stage_test_asset_for_longrun` when a suitable encrypted test-only asset exists, then pass only its one-time `stdin_secret_id` to Longrun; do not ask the user to re-enter that stored credential. Use `codex-longrun-secret` only when no suitable asset is enrolled. Output is suppressed for secret-stdin jobs. TTY-dependent or repeated password prompts remain unsupported. Do not use longrun for interactive programs, daemons, or unreviewed commands.
- Keep project roots narrowly enrolled. Never broaden `LONGRUN_ALLOWED_ROOTS` to `/home/w0w`; add each trusted project root explicitly.
- The global MCP configuration is loaded by new Codex processes. After installing, upgrading, or changing longrun configuration, start a new process or resume the session from a new process.
- Whenever creating a project-level `AGENTS.md`, include this section unless that project explicitly opts out or already has stricter equivalent guidance.
