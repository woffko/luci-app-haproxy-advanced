#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM acceptance of goal A.

Usage: printf '%s\\n' "$PASSWORD" | tools/accept.py SCENARIO [ATTEMPT]

The OpenWrt VM's root password is read from one stdin line (see vmlib.py).
Every scenario writes its output to logs/accept-SCENARIO-ATTEMPT/.
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import vmlib  # noqa: E402

import shlex
import subprocess

import vmcases as vc  # noqa: E402

TEST_PASSWORD = "test-password-1"
PKI = vmlib.ROOT / "logs" / "testpki"
APK_DIR = Path("/home/w0w/build/openwrt-25.12.4-clean-haproxy-luci/bin/packages/x86_64/haproxyadv")


class Checks:
    def __init__(self, out):
        self.out = out
        self.items = []

    def check(self, name, ok, detail=""):
        self.items.append({"name": name, "ok": bool(ok), "detail": detail})
        print("%s %s%s" % ("PASS" if ok else "FAIL", name, ("  -- " + str(detail)[:300]) if detail and not ok else ""))
        return ok

    def finish(self):
        failed = [i for i in self.items if not i["ok"]]
        save(self.out, "results.json", self.items)
        print("%d checks, %d failed" % (len(self.items), len(failed)))
        return 1 if failed else 0


def crypt_hash(password):
    js = ("const fs=require('fs');const c=require('crypto');"
          "const src=fs.readFileSync(process.argv[1],'utf8').replace(/^'require [^']+';$/mg,'');"
          "global.window={crypto:{getRandomValues:(a)=>c.randomFillSync(a)}};"
          "const m=new Function('baseclass',src)({extend:(o)=>o});process.stdout.write(m.hash(process.argv[2]));")
    path = ROOT / "luci-app-haproxy-advanced/htdocs/luci-static/resources/haproxy_advanced/crypt.js"
    return subprocess.run(["node", "-e", js, str(path), password], capture_output=True, check=True).stdout.decode()


def iface_of(vm, ip):
    dump = json.loads(vm.out("ubus call network.interface dump"))

    for i in dump["interface"]:
        for a in i.get("ipv4-address", []):
            if a["address"] == ip:
                return i["interface"]

    raise RuntimeError("no interface holds %s" % ip)


def zone_of(vm, iface):
    for line in vm.out("uci -q show firewall").splitlines():
        if ".network=" in line and ("'%s'" % iface) in line:
            sec = line.split(".")[1]
            name = vm.out("uci -q get firewall.%s.name" % sec).strip()

            if name:
                return name

    raise RuntimeError("no firewall zone has %s" % iface)


def ubus(vm, obj, method, args=None):
    r = vm.run("ubus call %s %s %s" % (obj, method, shlex.quote(json.dumps(args or {}))), check=False, timeout=90)
    text = r.stdout.decode(errors="replace")

    try:
        return json.loads(text)
    except ValueError:
        return {"_error": r.stderr.decode(errors="replace") + text}


def last_apply(vm):
    try:
        return json.loads(vm.out("cat /var/run/haproxy-advanced/last-apply.json"))
    except (ValueError, RuntimeError):
        return None


def apply_config(vm, text, wait_runtime=True):
    """Install a UCI configuration and reload; return last-apply.json."""
    vm.upload(text, "/etc/config/haproxy-advanced", mode="600")
    before = (last_apply(vm) or {}).get("time", 0)
    vm.run("/etc/init.d/haproxy-advanced reload", check=False, timeout=120)

    for _ in range(40):
        la = last_apply(vm)

        if la and la.get("time", 0) >= before and (not wait_runtime or la.get("state") != "applied" or la.get("runtime")):
            return la

        time.sleep(0.5)

    return last_apply(vm)


def stage_pki(vm):
    for name in ("svc-a.pem", "svc-b.pem", "svc-c.pem", "ca.crt"):
        vm.upload((PKI / name).read_bytes(), "%s/pki/%s" % (vmlib.STAGE, name))

    vm.run("mkdir -p /etc/haproxy/certs && cp %s/pki/svc-*.pem /etc/haproxy/certs/ && "
           "cp %s/pki/ca.crt /etc/haproxy/certs/test-ca.crt && chmod 600 /etc/haproxy/certs/*" % (vmlib.STAGE, vmlib.STAGE))

ROOT = vmlib.ROOT
SCENARIOS = {}


def scenario(fn):
    SCENARIOS[fn.__name__.replace("_", "-")] = fn
    return fn


def save(out, name, data):
    out.mkdir(parents=True, exist_ok=True)
    p = out / name

    if isinstance(data, (dict, list)):
        p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    else:
        p.write_text(data)

    return p


@scenario
def probe(vm, out, args):
    """Read-only facts about the VM that the other scenarios depend on."""
    cmds = {
        "release": "cat /etc/openwrt_release",
        "interfaces": "ubus call network.interface dump",
        "listening": "netstat -ltnp 2>/dev/null || ss -ltnp",
        "apk": "apk list -I 2>/dev/null | sort",
        "uhttpd": "uci show uhttpd",
        "zones": "uci show firewall | grep -E '=zone|\\.name=|\\.network='",
        "feeds": "cat /etc/apk/repositories.d/*.list 2>/dev/null; cat /etc/apk/repositories 2>/dev/null",
        "space": "df -h / /tmp; free",
        "stock": "ls -la /etc/init.d/haproxy /etc/rc.d/*haproxy* 2>&1",
        "routes": "ip -4 addr; ip -6 addr | grep inet6",
    }

    for name, cmd in cmds.items():
        save(out, name + ".txt", vm.out(cmd, check=False))
        print("saved", name)


@scenario
def snapshot(vm, out, args):
    """The VM's state before the goal touches it; cleanup compares against it."""
    state = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "apk": vm.out("apk list -I 2>/dev/null | sort").splitlines(),
        "config_hashes": vm.out("cd /etc/config && sha256sum * | sort -k2").splitlines(),
        "enabled_init": vm.out("ls /etc/rc.d | sort").splitlines(),
        "nft": vm.out("nft list ruleset"),
        "listening": vm.out("netstat -ltn 2>/dev/null | sort").splitlines(),
        "ca_bundle": vm.out("sha256sum /etc/ssl/certs/ca-certificates.crt 2>/dev/null").strip(),
        "crontab": vm.out("cat /etc/crontabs/root 2>/dev/null"),
        "dirs": vm.out("ls -d /etc/acme /etc/ssl/acme /etc/haproxy /etc/haproxy.cfg 2>/dev/null", check=False).splitlines(),
        "luci_lang": vm.out("uci -q get luci.main.lang", check=False).strip(),
    }
    p = save(out, "snapshot.json", state)
    print("snapshot written to", p)


@scenario
def install(vm, out, args):
    """Install both APKs (dependencies from the VM's feeds) and check that LuCI's
    menu and rpcd object work without a manual rpcd restart (F11)."""
    c = Checks(out)
    apks = sorted(APK_DIR.glob("*.apk"))
    names = []

    for a in apks:
        vm.upload(a.read_bytes(), "%s/%s" % (vmlib.STAGE, a.name))
        names.append("%s/%s" % (vmlib.STAGE, a.name))

    save(out, "apk-update.txt", vm.out("apk update 2>&1", check=False, timeout=300))
    r = vm.run("apk add --allow-untrusted %s 2>&1" % " ".join(names), check=False, timeout=600)
    save(out, "apk-add.txt", r.stdout.decode(errors="replace"))
    c.check("apk add exits 0", r.returncode == 0, r.stdout.decode(errors="replace")[-500:])
    listed = vm.out("apk list -I 2>/dev/null | grep -E '^(haproxy|haproxy-advanced|luci-app-haproxy-advanced)-[0-9]'", check=False)
    save(out, "installed.txt", listed)
    c.check("haproxy-advanced 0.2.0-r1 installed", "haproxy-advanced-0.2.0-r1" in listed, listed)
    c.check("luci-app-haproxy-advanced 0.2.0-r1 installed", "luci-app-haproxy-advanced-0.2.0-r1" in listed, listed)
    objs = vm.out("ubus list luci.haproxy-advanced", check=False)
    c.check("rpcd serves luci.haproxy-advanced right after install (F11)", "luci.haproxy-advanced" in objs, objs)
    st = ubus(vm, "luci.haproxy-advanced", "status")
    save(out, "status.json", st)
    c.check("status method answers", "version" in st, st)
    c.check("init script enabled by default_postinst", vm.run("/etc/init.d/haproxy-advanced enabled", check=False).returncode == 0)
    acl = vm.out("ls /usr/share/rpcd/acl.d/luci-app-haproxy-advanced.json /usr/share/luci/menu.d/luci-app-haproxy-advanced.json", check=False)
    c.check("menu and ACL installed", acl.count("luci-app-haproxy-advanced") == 2, acl)
    c.check("no uci-defaults left behind", vm.out("ls /etc/uci-defaults/ 2>/dev/null | grep -c haproxy || true").strip() in ("0", ""))
    save(out, "stock-haproxy.json", st.get("stock_haproxy", {}))
    return c.finish()


def golden_text(cfg):
    """Point a golden configuration's file references at test files on the VM."""
    out = []

    for line in cfg.splitlines():
        words = line.split(" ")

        for i, w in enumerate(words[:-1]):
            if w in ("crt", "ca-file") and words[i + 1] != "@system-ca":
                words[i + 1] = "%s/pki/%s" % (vmlib.STAGE, "ca.crt" if w == "ca-file" else "svc-a.pem")

        out.append(" ".join(words))

    return "\n".join(out) + "\n"


@scenario
def golden(vm, out, args):
    """haproxy -c of every golden configuration (certificate paths replaced by
    test files)."""
    c = Checks(out)
    stage_pki(vm)
    fixtures = ROOT / "tests" / "fixtures"

    for d in sorted(fixtures.iterdir()):
        cfg = d / "expected.cfg"

        if not cfg.exists():
            continue

        dest = "%s/golden/%s.cfg" % (vmlib.STAGE, d.name)
        vm.upload(golden_text(cfg.read_text()), dest)
        r = vm.run("haproxy -c -f %s 2>&1" % dest, check=False)
        text = r.stdout.decode(errors="replace")
        save(out, d.name + ".txt", text)
        warnings = [l for l in text.splitlines() if "WARNING" in l or "ALERT" in l]
        c.check("haproxy -c %s" % d.name, r.returncode == 0, text[-800:])
        c.check("no warnings %s" % d.name, not warnings, "\n".join(warnings)[:800])

    return c.finish()


def functional_config(iface, zone, hash_, extra=""):
    return """
config global 'global'
	option enabled '1'
	option timeout_client '5s'

config listener 'pub'
	list address '%(iface)s'
	option port '18443'
	option redirect_port '18080'
	option firewall '1'
	option firewall_zone '%(zone)s'

config service 'svca'
	option listener 'pub'
	list hostname 'svc-a.hatest.example'
	option backend 'echo_http'
	option certificate '/etc/haproxy/certs/svc-a.pem'
	list trusted_network '10.99.0.0/16'
	list blocked_path '/cgi-bin/'
	list internal_path '/admin/'
	list public_path '/share/'
	option auth_group 'family'
	option auth_fail_limit '5'
	option hsts '1'

config service 'svcb'
	option listener 'pub'
	list hostname 'svc-b.hatest.example'
	option backend 'echo_https'
	option certificate '/etc/haproxy/certs/svc-b.pem'
	option rate_limit '20'

config service 'svcc'
	option listener 'pub'
	list hostname 'svc-c.hatest.example'
	option backend 'ws'
	option certificate '/etc/haproxy/certs/svc-c.pem'

config service 'pt'
	option listener 'pub'
	list hostname 'pt.hatest.example'
	option mode 'passthrough'
	option backend 'pt'

config backend 'echo_http'

config server
	option backend 'echo_http'
	option name 's1'
	option address '192.168.189.142'
	option port '19080'

config backend 'echo_https'

config server
	option backend 'echo_https'
	option name 's1'
	option address '192.168.189.142'
	option port '19443'
	option tls '1'
	option verify 'required'
	option ca_file '/etc/haproxy/certs/test-ca.crt'
	option verifyhost 'backend.hatest.example'

config backend 'ws'
	option timeout_tunnel '1h'

config server
	option backend 'ws'
	option name 's1'
	option address '192.168.189.142'
	option port '19081'

config backend 'pt'

config server
	option backend 'pt'
	option name 's1'
	option address '192.168.189.142'
	option port '19444'

config auth_group 'family'
	option realm 'Family'

config user
	option group 'family'
	option username 'alice'
	option password_hash '%(hash)s'
%(extra)s""" % {"iface": iface, "zone": zone, "hash": hash_, "extra": extra}


@scenario
def functional(vm, out, args):
    """Requests through HAProxy, one case per finding and feature."""
    c = Checks(out)
    stage_pki(vm)
    iface = iface_of(vm, vc.VM)
    zone = zone_of(vm, iface)
    hash_ = crypt_hash(TEST_PASSWORD)
    good = functional_config(iface, zone, hash_)
    la = apply_config(vm, good)
    save(out, "last-apply-1.json", la)
    c.check("apply succeeds", la and la["state"] == "applied" and (la.get("runtime") or {}).get("ok"), la)
    save(out, "haproxy.cfg", vm.out("cat /var/etc/haproxy-advanced.cfg"))
    time.sleep(2)

    A, B, C, PT = "svc-a.hatest.example", "svc-b.hatest.example", "svc-c.hatest.example", "pt.hatest.example"
    auth = "alice:" + TEST_PASSWORD

    # Firewall (D7): the listener's ports are open while the service runs.
    nft = vm.out("nft list ruleset")
    save(out, "nft-1.txt", nft)
    c.check("firewall accepts 18443 from the zone", "18443" in nft and "haproxy-advanced" in nft, "")
    c.check("firewall accepts 18080 from the zone", "18080" in nft, "")

    # F1: Content-Length: 0 and a late body pass.
    r = vc.curl(B, "/post", method="POST", headers=["Content-Length: 0"])
    c.check("F1 POST with Content-Length: 0 passes", r["status"] == 200, r)
    r = vc.raw_tls(B, [("POST /late HTTP/1.1\r\nHost: %s:18443\r\nContent-Length: 10\r\n\r\n" % B).encode(), b"0123456789"], pause=1.5)
    c.check("F1 POST whose body arrives 1.5 s late passes", " 200 " in r["status_line"] + " " and (r.get("json") or {}).get("body_length") == 10, r)

    # F2: host routing on one listener, certificate by SNI, unknown host.
    ra, rb = vc.curl(A, "/share/x"), vc.curl(B, "/x")
    c.check("F2 svc-a routed to the HTTP echo", ra["status"] == 200 and ra.get("json", {}).get("server") == "http", ra)
    c.check("F2 svc-b routed to the HTTPS echo (verify required with the test CA, F13)",
            rb["status"] == 200 and rb.get("json", {}).get("server") == "https", rb)
    pa, pb = vc.tls_peer(A), vc.tls_peer(B)
    c.check("F2 SNI svc-a gets the svc-a certificate", pa["subject"] == A, pa)
    c.check("F2 SNI svc-b gets the svc-b certificate", pb["subject"] == B, pb)
    r = vc.curl("unknown.hatest.example", "/")
    c.check("F2 unknown host gets 404", r["status"] == 404, r)

    # F6: Host with a port (curl sends svc-a.hatest.example:18443).
    c.check("F6 Host header with a port matches", ra["status"] == 200 and any(
        v.endswith(":18443") for v in vc.echo_headers(ra).get("host", [])), vc.echo_headers(ra).get("host"))

    # F7: path forms.
    cases = [("/cgi-bin/x", 403), ("/CGI-BIN/x", 403), ("/%63gi-bin/x", 403), ("/cgi-bin;x/y", 403),
             ("//cgi-bin/x", 400), ("/x/../cgi-bin/", 400), ("/x/%2e%2e/cgi-bin/", 400), ("/a%00b", 400),
             ("/admin/", 403), ("/ADMIN/", 403), ("/admin;p/", 403), ("/share/f", 200), ("/SHARE/f", 401),
             ("/share/../admin/", 400), ("/other", 401)]

    for path, want in cases:
        r = vc.curl(A, path)
        c.check("F7 %s -> %d" % (path, want), r["status"] == want, r.get("status") or r.get("error"))

    r = vc.curl(A, "/other", user=auth)
    c.check("login with the browser-made $6$ hash works (D6)", r["status"] == 200, r)
    c.check("HSTS on svc-a", "strict-transport-security" in r["headers"], r["headers"])
    r2 = vc.curl(B, "/x")
    c.check("no HSTS on svc-b", "strict-transport-security" not in r2["headers"], r2["headers"])

    # F9: forwarding headers.
    r = vc.curl(A, "/share/h", headers=["X-Forwarded-For: 6.6.6.6", "X-Real-IP: 6.6.6.6", "Forwarded: for=6.6.6.6",
                                         "X-Forwarded-Proto: http"])
    h = vc.echo_headers(r)
    c.check("F9 X-Forwarded-For is only the client address", h.get("x-forwarded-for") == ["192.168.189.1"], h)
    c.check("F9 X-Real-IP and Forwarded removed", "x-real-ip" not in h and "forwarded" not in h, h)
    c.check("F9 X-Forwarded-Proto https", h.get("x-forwarded-proto") == ["https"], h)
    c.check("F9 X-Forwarded-Port 18443", h.get("x-forwarded-port") == ["18443"], h)

    # HTTP/2.
    r = vc.curl(B, "/h2", http2=True)
    c.check("HTTP/2 negotiated", r["status"] == 200 and r.get("version") == "2", r.get("version"))

    # Companion: redirect with the port kept, 404 for unknown hosts.
    r = vc.curl(A, "/p?q=1", port=18080, scheme="http")
    c.check("redirect 308 to https with port 18443", r["status"] == 308 and
            r["headers"].get("location") == "https://svc-a.hatest.example:18443/p?q=1", r)
    r = vc.curl("unknown.hatest.example", "/", port=18080, scheme="http")
    c.check("companion: unknown host 404", r["status"] == 404, r)

    # Passthrough on the same port.
    pp = vc.tls_peer(PT)
    c.check("passthrough: client sees the server's own certificate", pp["issuer"] == "haproxy-advanced passthrough CA", pp)
    r = vc.curl(PT, "/pt")
    c.check("passthrough: request reaches the passthrough server", r.get("json", {}).get("server") == "passthrough", r)
    c.check("passthrough: HTTPS services behind it see the real client (PROXY v2)",
            vc.echo_headers(ra).get("x-forwarded-for") == ["192.168.189.1"], vc.echo_headers(ra))

    # F12: WebSocket idle past the 5 s client timeout.
    st, echoed = vc.websocket_idle(C, 8)
    c.check("F12 WebSocket upgrade", " 101 " in st + " ", st)
    c.check("F12 WebSocket survives 8 s idle (client timeout 5 s, tunnel 1h)", echoed == "ping-after-idle", echoed)

    # Rate limit on svc-b: 20 per 10 s.
    statuses = [vc.curl(B, "/r%d" % i, timeout=5)["status"] for i in range(30)]
    c.check("rate limit answers 429 beyond 20 requests per 10 s", 429 in statuses and statuses[:15].count(200) == 15, statuses)

    # Runtime panel.
    rt = ubus(vm, "luci.haproxy-advanced", "runtime")
    save(out, "runtime.json", rt)
    names = {(r["proxy"], r["name"]) for r in rt.get("rows", [])}
    c.check("runtime lists be_echo_http/s1", ("be_echo_http", "s1") in names, sorted(names)[:20])
    r = ubus(vm, "luci.haproxy-advanced", "set_server", {"backend": "echo_http", "server": "s1", "state": "maint"})
    c.check("set_server maint answers ok", r.get("ok"), r)
    r = vc.curl(A, "/share/m")
    c.check("maintenance: svc-a answers 503", r["status"] == 503, r.get("status"))
    ubus(vm, "luci.haproxy-advanced", "set_server", {"backend": "echo_http", "server": "s1", "state": "ready"})
    r = vc.curl(A, "/share/m")
    c.check("ready again: svc-a answers 200", r["status"] == 200, r.get("status"))
    ubus(vm, "luci.haproxy-advanced", "set_server", {"backend": "echo_http", "server": "s1", "state": "maint"})
    vm.run("/etc/init.d/haproxy-advanced reload", check=False, timeout=120)
    time.sleep(2)
    r = vc.curl(A, "/share/m")
    c.check("a reload resets runtime maintenance", r["status"] == 200, r.get("status"))

    # F5: staged preview through a session save directory, and a failing apply.
    sid = "0123456789abcdef0123456789abcdef"
    sd = "/var/run/rpcd/uci-" + sid
    vm.run("rm -rf %s && mkdir -p %s && uci -t %s set haproxy-advanced.svcb.hostname=svc-b2.hatest.example" % (sd, sd, sd))
    pv = ubus(vm, "luci.haproxy-advanced", "preview", {"ubus_rpc_session": sid, "check": True})
    save(out, "preview-staged.json", pv)
    c.check("F5 preview shows an unsaved change", pv.get("staged") and "svc-b2.hatest.example" in (pv.get("config") or ""), pv.get("errors"))
    c.check("F5 preview runs haproxy -c", (pv.get("check") or {}).get("ok"), pv.get("check"))
    vm.run("uci -t %s set haproxy-advanced.svcb.listener=pub && uci -t %s add haproxy-advanced listener >/dev/null && "
           "uci -t %s rename haproxy-advanced.@listener[-1]=dup && uci -t %s set haproxy-advanced.dup.port=18443 && "
           "uci -t %s set haproxy-advanced.svcc.listener=dup" % (sd, sd, sd, sd, sd))
    pv = ubus(vm, "luci.haproxy-advanced", "preview", {"ubus_rpc_session": sid})
    save(out, "preview-dup.json", pv)
    c.check("F2 two listeners on one address and port are refused", not pv.get("ok") and any(
        "shares port 18443" in e["message"] for e in pv.get("errors", [])), pv.get("errors"))
    vm.run("rm -rf %s" % sd)
    c.check("F5 committed configuration untouched by the preview",
            "svc-b2" not in vm.out("uci -q get haproxy-advanced.svcb.hostname", check=False))

    broken = good.replace("option backend 'echo_https'\n\toption certificate", "option backend 'missing'\n\toption certificate")
    la = apply_config(vm, broken, wait_runtime=False)
    save(out, "last-apply-broken.json", la)
    c.check("F5 a broken configuration is reported as failed", la and la["state"] == "failed" and la["errors"], la)
    r = vc.curl(B, "/still")
    c.check("F5 the running configuration keeps serving", r["status"] == 200, r.get("status"))

    # verify required without a CA is refused with a clear message (F13).
    noca = good.replace("\toption ca_file '/etc/haproxy/certs/test-ca.crt'\n", "")
    la = apply_config(vm, noca, wait_runtime=False)
    c.check("F13 verify required without ca_file is refused", la and la["state"] == "failed" and any(
        "needs ca_file" in e["message"] for e in la.get("errors", [])), la and la.get("errors"))

    # Passthrough restricted to trusted networks.
    trusted = good.replace("\toption mode 'passthrough'\n", "\toption mode 'passthrough'\n\tlist trusted_network '10.99.0.0/16'\n")
    la = apply_config(vm, trusted)
    r = vc.curl(PT, "/pt", timeout=5)
    c.check("passthrough with trusted networks rejects other clients", r["status"] is None, r)
    r = vc.curl(B, "/x")
    c.check("other services still answer", r["status"] == 200, r.get("status"))

    # F10: failed-login limit (5 per minute). Last, because it blocks svc-a for a minute.
    statuses = [vc.curl(A, "/other", user="alice:wrong%d" % i, timeout=5)["status"] for i in range(8)]
    c.check("F10 failed logins: 401 first, then 429", statuses[0] == 401 and 429 in statuses, statuses)

    la = apply_config(vm, good)
    c.check("good configuration applies again", la and la["state"] == "applied", la and la.get("state"))
    return c.finish()


def wait_for(fn, timeout=20, step=0.5):
    end = time.time() + timeout
    t0 = time.time()

    while time.time() < end:
        v = fn()

        if v:
            return time.time() - t0

        time.sleep(step)

    return None


def listening(vm, needle):
    return needle in vm.out("netstat -ltn 2>/dev/null", check=False)


HATEST_NETWORK = """
config device 'hatest_dev'
	option name 'br-hatest'
	option type 'bridge'
	option bridge_empty '1'

config interface 'hatest'
	option proto 'static'
	option device 'br-hatest'
	option ipaddr '10.99.99.1/24'
	option ip6addr 'fd99::1/64'
"""


@scenario
def interfaces(vm, out, args):
    """F3: listeners follow their interfaces (test interface hatest on an empty
    bridge), device binding, IPv6."""
    c = Checks(out)
    stage_pki(vm)
    iface = iface_of(vm, vc.VM)
    zone = zone_of(vm, iface)
    orig = vm.run("cat /etc/config/network").stdout
    save(out, "network.orig.sha256", vm.out("sha256sum /etc/config/network"))
    vm.upload(orig, vmlib.STAGE + "/network.orig")

    extra = """
config listener 'test'
	list address 'hatest'
	option family 'any'
	option port '18444'

config service 'svct'
	option listener 'test'
	list hostname 'svc-c.hatest.example'
	option backend 'echo_http'
	option certificate '/etc/haproxy/certs/svc-c.pem'

config listener 'dev'
	list address '%s'
	option bind_mode 'device'
	option port '18445'
	option firewall '1'
	option firewall_zone '%s'

config service 'svcd'
	option listener 'dev'
	list hostname 'svc-b.hatest.example'
	option backend 'echo_http'
	option certificate '/etc/haproxy/certs/svc-b.pem'
""" % (iface, zone)

    try:
        vm.run("cat %s/network.orig > /tmp/network.new && cat >> /tmp/network.new && "
               "cp /tmp/network.new /etc/config/network && rm /tmp/network.new && "
               "/etc/init.d/network reload" % vmlib.STAGE, data=HATEST_NETWORK.encode(), timeout=60)
        c.check("hatest comes up", wait_for(lambda: "10.99.99.1" in vm.out("ip -4 addr show br-hatest", check=False), 30) is not None)

        cfg = functional_config(iface, zone, crypt_hash(TEST_PASSWORD), extra)
        la = apply_config(vm, cfg)
        save(out, "last-apply-1.json", la)
        c.check("apply with hatest up", la and la["state"] == "applied" and not la["skipped"], la)
        c.check("listens on 10.99.99.1:18444", listening(vm, "10.99.99.1:18444"))
        c.check("listens on fd99::1 port 18444 (IPv6)", listening(vm, "fd99::1:18444"))
        c.check("device listener on :::18445", listening(vm, ":::18445"))

        r = vc.curl("svc-b.hatest.example", "/dev", port=18445)
        c.check("device listener answers through %s" % iface, r["status"] == 200, r.get("status") or r.get("error"))

        v6 = vm.run("printf 'GET /v6 HTTP/1.1\\r\\nHost: svc-c.hatest.example:18444\\r\\nConnection: close\\r\\n\\r\\n' | "
                    "openssl s_client -connect '[fd99::1]:18444' -servername svc-c.hatest.example -quiet 2>/dev/null",
                    check=False, timeout=20).stdout.decode(errors="replace")
        save(out, "ipv6.txt", v6)
        c.check("IPv6 request on fd99::1 answers 200", "HTTP/1.1 200" in v6, v6[:300])

        vm.run("ifdown hatest")
        t = wait_for(lambda: not listening(vm, "10.99.99.1:18444"), 20)
        c.check("ifdown: the hatest listener goes away", t is not None, t)
        la = last_apply(vm)
        save(out, "last-apply-down.json", la)
        c.check("ifdown: last apply names hatest as skipped", la and any("hatest" in s["message"] for s in la.get("skipped", [])), la)
        r = vc.curl("svc-a.hatest.example", "/share/x")
        c.check("ifdown: other listeners keep serving", r["status"] == 200, r.get("status"))

        vm.run("ifup hatest")
        t = wait_for(lambda: listening(vm, "10.99.99.1:18444"), 20)
        c.check("ifup: the listener is back within 10 s", t is not None and t <= 10, t)
        save(out, "ifup-seconds.txt", str(t))

        vm.run("uci set network.hatest.ipaddr=10.99.98.1/24 && uci commit network && /etc/init.d/network reload")
        t = wait_for(lambda: listening(vm, "10.99.98.1:18444"), 25)
        c.check("address change: HAProxy follows to 10.99.98.1", t is not None, t)
        c.check("address change: old address released", not listening(vm, "10.99.99.1:18444"))
        save(out, "readdress-seconds.txt", str(t))

        vm.run("ifdown hatest")
        wait_for(lambda: not listening(vm, "10.99.98.1:18444"), 20)
        vm.run("/etc/init.d/haproxy-advanced restart", check=False, timeout=120)
        t = wait_for(lambda: vc.curl("svc-a.hatest.example", "/share/r", timeout=3)["status"] == 200, 20)
        c.check("start with hatest down: other listeners run", t is not None, t)
        la = last_apply(vm)
        c.check("start with hatest down: skipped part reported", la and any("hatest" in s["message"] for s in la.get("skipped", [])), la)
        vm.run("ifup hatest")
        t = wait_for(lambda: listening(vm, "10.99.98.1:18444"), 20)
        c.check("start with hatest down: listener appears after ifup", t is not None, t)
    finally:
        vm.run("ifdown hatest 2>/dev/null; cp %s/network.orig /etc/config/network && /etc/init.d/network reload" % vmlib.STAGE,
               check=False, timeout=60)
        time.sleep(3)
        after = vm.out("sha256sum /etc/config/network")
        c.check("network configuration restored byte for byte", after.split()[0] == (out / "network.orig.sha256").read_text().split()[0], after)
        c.check("br-hatest removed", wait_for(lambda: vm.run("ip link show br-hatest", check=False).returncode != 0, 15) is not None)

    la = apply_config(vm, functional_config(iface, zone, crypt_hash(TEST_PASSWORD)))
    c.check("back to the functional configuration", la and la["state"] == "applied", la and la.get("state"))
    return c.finish()


@scenario
def cleanup(vm, out, args):
    """Remove everything of goal A and compare with a snapshot (args[0]: path of
    snapshot.json)."""
    c = Checks(out)
    snap = json.loads(Path(args[0]).read_text()) if args else None
    vm.run("/etc/init.d/haproxy-advanced stop 2>/dev/null; /etc/init.d/haproxy-advanced disable 2>/dev/null", check=False)
    before = set((snap or {}).get("apk", []))
    now = vm.out("apk list -I 2>/dev/null | sort").splitlines()
    added = [l.split(" ")[0] for l in now if l not in before]
    save(out, "added-packages.txt", "\n".join(added) + "\n")

    if added:
        # apk del by name: strip the version from "name-1.2.3-r4".
        names = sorted({a.rsplit("-", 2)[0] for a in added})
        r = vm.run("apk del %s 2>&1" % " ".join(names), check=False, timeout=300)
        save(out, "apk-del.txt", r.stdout.decode(errors="replace"))

    vm.run("rm -rf /etc/haproxy/certs /var/etc/haproxy-advanced.cfg* /var/run/haproxy-advanced %s "
           "/etc/config/haproxy-advanced /etc/config/haproxy-advanced.v01 /etc/config/haproxy-advanced-opkg "
           "/etc/config/*.apk-new" % vmlib.STAGE, check=False)

    if snap:
        # Files and directories the packages left behind (modified conffiles,
        # acme's state, the cron line acme adds when it starts).
        known = {l.split()[-1] for l in snap["config_hashes"]}

        for f in vm.out("ls /etc/config").split():
            if f not in known:
                vm.run("rm -f /etc/config/%s" % f, check=False)

        for d in ("/etc/acme", "/etc/ssl/acme", "/etc/haproxy", "/etc/haproxy.cfg"):
            if d not in snap["dirs"]:
                vm.run("rm -rf %s" % d, check=False)

        if vm.out("cat /etc/crontabs/root 2>/dev/null") != snap["crontab"]:
            vm.upload(snap["crontab"], vmlib.STAGE + "/crontab")
            vm.run("cp %s/crontab /etc/crontabs/root && /etc/init.d/cron restart; rm -rf %s" % (vmlib.STAGE, vmlib.STAGE),
                   check=False)

    if snap:
        now = vm.out("apk list -I 2>/dev/null | sort").splitlines()
        c.check("package set as in the snapshot", now == snap["apk"], sorted(set(now) ^ set(snap["apk"])))
        hashes = vm.out("cd /etc/config && sha256sum * | sort -k2").splitlines()
        c.check("/etc/config as in the snapshot", hashes == snap["config_hashes"], sorted(set(hashes) ^ set(snap["config_hashes"])))
        init = vm.out("ls /etc/rc.d | sort").splitlines()
        c.check("enabled init scripts as in the snapshot", init == snap["enabled_init"], sorted(set(init) ^ set(snap["enabled_init"])))
        ca = vm.out("sha256sum /etc/ssl/certs/ca-certificates.crt 2>/dev/null").strip()
        c.check("CA bundle as in the snapshot", ca == snap["ca_bundle"], ca)
        cron = vm.out("cat /etc/crontabs/root 2>/dev/null")
        c.check("root crontab as in the snapshot", cron == snap["crontab"], cron)
        lst = vm.out("netstat -ltn 2>/dev/null | sort").splitlines()
        c.check("listening sockets as in the snapshot", lst == snap["listening"], sorted(set(lst) ^ set(snap["listening"])))
        nft = vm.out("nft list ruleset")
        c.check("no haproxy-advanced firewall rule left", "haproxy-advanced" not in nft and "ACME" not in nft)

    return c.finish()


PEBBLE_CONFIG = """{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "127.0.0.1:15000",
    "certificate": "pki/pebble.crt",
    "privateKey": "pki/pebble.key",
    "httpPort": 18080,
    "tlsPort": 18443,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}
"""


def ubuntu_start(ub, name, command):
    """Start a background process on the Ubuntu VM in its own session."""
    ub.run("cd %s && setsid nohup %s > %s.log 2>&1 < /dev/null & echo $! > %s/%s.pid" % (
        vmlib.UBUNTU_DIR, command, name, vmlib.UBUNTU_DIR, name), timeout=20)


def ubuntu_stop(ub, name):
    ub.run("f=%s/%s.pid; [ -f $f ] && kill -- -$(cat $f) 2>/dev/null; kill $(cat $f) 2>/dev/null; rm -f $f; true" % (
        vmlib.UBUNTU_DIR, name), check=False, timeout=20)


def served_cert(vm_host, port=vc.TLS_PORT):
    p = subprocess.run("openssl s_client -connect %s:%d -servername %s </dev/null 2>/dev/null | "
                       "openssl x509 -noout -issuer -serial" % (vc.VM, port, vm_host),
                       shell=True, capture_output=True, timeout=20)
    return p.stdout.decode(errors="replace").strip()


def acme_setup(vm, ub, out):
    ub.upload(PEBBLE_CONFIG, vmlib.UBUNTU_DIR + "/pebble-config.json")
    ubuntu_stop(ub, "challtestsrv")
    ubuntu_stop(ub, "pebble")
    ubuntu_start(ub, "challtestsrv", "./pebble-root/usr/bin/pebble-challtestsrv -defaultIPv4 192.168.189.130 "
                 "-defaultIPv6 '' -dns01 127.0.0.1:8053 -http01 '' -https01 '' -tlsalpn01 '' -management 127.0.0.1:8055")
    ubuntu_start(ub, "pebble", "env PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 ./pebble-root/usr/bin/pebble "
                 "-config pebble-config.json -dnsserver 127.0.0.1:8053")
    time.sleep(2)
    save(out, "pebble-start.log", ub.out("cat %s/pebble.log %s/challtestsrv.log" % (vmlib.UBUNTU_DIR, vmlib.UBUNTU_DIR), check=False))

    # Trust the test CA (which signed Pebble's listener certificate) for the test only.
    vm.run("cp /etc/ssl/certs/ca-certificates.crt %s/ca-bundle.orig && cat %s/pki/ca.crt >> /etc/ssl/certs/ca-certificates.crt"
           % (vmlib.STAGE, vmlib.STAGE))


def acme_teardown(vm, ub):
    vm.run("[ -f %s/ca-bundle.orig ] && cp %s/ca-bundle.orig /etc/ssl/certs/ca-certificates.crt" % (vmlib.STAGE, vmlib.STAGE), check=False)
    ubuntu_stop(ub, "pebble")
    ubuntu_stop(ub, "challtestsrv")


@scenario
def acme(vm, out, args):
    """ACME through the HTTP companion with Pebble on the Ubuntu VM."""
    c = Checks(out)
    ub = vmlib.Ubuntu()
    stage_pki(vm)
    iface = iface_of(vm, vc.VM)
    zone = zone_of(vm, iface)
    host = "acme.hatest.example"
    acme_orig = vm.run("cat /etc/config/acme", check=False).stdout
    vm.upload(acme_orig, vmlib.STAGE + "/acme.orig")
    acme_setup(vm, ub, out)

    try:
        d = vm.run("wget -qO- https://192.168.189.142:14000/dir", check=False, timeout=20)
        c.check("the VM reaches Pebble over TLS", b"newAccount" in d.stdout, d.stderr.decode(errors="replace"))

        vm.run("uci -q delete acme.hatest_acme; uci set acme.hatest_acme=cert && "
               "uci set acme.hatest_acme.enabled=1 && uci add_list acme.hatest_acme.domains=%s && "
               "uci set acme.hatest_acme.validation_method=standalone && uci set acme.hatest_acme.listen_port=18402 && "
               "uci set acme.hatest_acme.key_type=ec256 && "
               "uci set acme.hatest_acme.acme_server=https://192.168.189.142:14000/dir && "
               "uci set acme.@acme[0].account_email=hostmaster@hatest.example && uci commit acme" % host)

        extra = """
config service 'svcacme'
	option listener 'pub'
	list hostname '%s'
	option backend 'echo_http'
	option acme_cert 'hatest_acme'
""" % host
        la = apply_config(vm, functional_config(iface, zone, crypt_hash(TEST_PASSWORD), extra))
        save(out, "last-apply-before.json", la)
        c.check("before the issue: the service is left out, the rest runs", la and la["state"] == "applied" and any(
            "does not exist yet" in s["message"] for s in la["skipped"]), la)

        t0 = time.time()
        vm.run("/etc/init.d/acme renew", check=False, timeout=60)
        path = "/etc/ssl/acme/%s.combined.crt" % host
        t = wait_for(lambda: vm.run("test -s %s" % path, check=False).returncode == 0, 180, 2)
        save(out, "acme-issue.log", vm.out("logread -e acme | tail -n 80", check=False))
        c.check("certificate issued through the companion port", t is not None, t)
        t2 = wait_for(lambda: "Pebble" in served_cert(host), 60, 2)
        first = served_cert(host)
        save(out, "served-1.txt", first)
        c.check("acme.issue reloads HAProxy and the service serves the new certificate", t2 is not None, first)
        save(out, "issue-seconds.txt", "%.1f" % (time.time() - t0))
        r = vc.curl(host, "/hello")
        c.check("the ACME service answers", r["status"] == 200, r.get("status"))

        conf = "/etc/acme/%s_ecc/%s.conf" % (host, host)
        vm.run("sed -i \"s/^Le_NextRenewTime=.*/Le_NextRenewTime='0'/\" %s" % conf)
        vm.run("/etc/init.d/acme renew", check=False, timeout=60)
        t = wait_for(lambda: served_cert(host) not in ("", first) and "Pebble" in served_cert(host), 180, 2)
        second = served_cert(host)
        save(out, "served-2.txt", second)
        save(out, "acme-renew.log", vm.out("logread -e acme | tail -n 60", check=False))
        c.check("a forced renewal reloads HAProxy with the new certificate (acme.renew)", t is not None, second)
        nft = vm.out("nft list ruleset")
        c.check("acme's temporary port rule is gone after the issue", "ACME" not in nft)
    finally:
        vm.run("cp %s/acme.orig /etc/config/acme && rm -rf /etc/acme/%s_ecc /etc/ssl/acme/%s.*" % (vmlib.STAGE, host, host),
               check=False)
        acme_teardown(vm, ub)
        la = apply_config(vm, functional_config(iface, zone, crypt_hash(TEST_PASSWORD)))
        c.check("back to the functional configuration", la and la["state"] == "applied", la and la.get("state"))

    return c.finish()


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in SCENARIOS:
        print(__doc__)
        print("scenarios:", ", ".join(sorted(SCENARIOS)))
        return 2

    name = sys.argv[1]
    attempt = sys.argv[2] if len(sys.argv) > 2 else time.strftime("%Y%m%d-%H%M%S")
    out = ROOT / "logs" / ("accept-%s-%s" % (name, attempt))
    vm = vmlib.OpenWrt()
    SCENARIOS[name](vm, out, sys.argv[3:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
