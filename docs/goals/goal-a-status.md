# Goal A status

Task: `docs/goals/goal-a-task.md`. Branch `goal-a`.

## Progress

| Stage | State |
|---|---|
| 1. Layout and packaging | done: two packages build in the dedicated tree |
| 2. Schema and generator | in progress |
| 3. The service | in progress |
| 4. Safe defaults | in progress |
| 5. The GUI | in progress |
| 6. The extras | in progress |
| 7. Documentation | not started |
| Tests | in progress |
| VM acceptance | not started |

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

## Decisions taken during the goal

(none yet)

## Open questions

(none yet)
