#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM acceptance of goal A.

Usage: printf '%s\\n' "$PASSWORD" | tools/accept.py SCENARIO [ATTEMPT]

The OpenWrt VM's root password is read from one stdin line (see vmlib.py).
Every scenario writes its output to logs/accept-SCENARIO-ATTEMPT/.
"""

import hashlib
import json
import re
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
    vm.run("rm -f /var/run/haproxy-advanced/last-apply.json")
    vm.run("/etc/init.d/haproxy-advanced reload", check=False, timeout=120)

    for _ in range(40):
        la = last_apply(vm)

        if la and (not wait_runtime or la.get("state") != "applied" or la.get("runtime")):
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
        "ca_bundle": vm.out("sha256sum /etc/ssl/certs/ca-certificates.crt 2>/dev/null", check=False).strip(),
        "crontab": vm.out("cat /etc/crontabs/root 2>/dev/null", check=False),
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
    names = [n for n in names if "luci-i18n" not in n]
    r = vm.run("apk add --allow-untrusted %s acme-acmesh 2>&1" % " ".join(names), check=False, timeout=600)
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


HOSTS = ("svc-a.hatest.example", "svc-b.hatest.example", "svc-c.hatest.example", "pt.hatest.example")
A, B, C, PT = HOSTS
AUTH = "alice:" + TEST_PASSWORD


def request_checks(c):
    """Requests through HAProxy that do not depend on OpenWrt; run against the
    OpenWrt VM by functional, and against the Ubuntu VM by tools/prerun_ubuntu.py."""
    auth = AUTH

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
    c.check("F2 SNI svc-a gets the svc-a certificate", pa["subject"] == "svc-a", pa)
    c.check("F2 SNI svc-b gets the svc-b certificate", pb["subject"] == "svc-b", pb)
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

    # Rate limit on svc-b: 20 per 10 s. Let the earlier requests' window pass.
    time.sleep(11)
    statuses = [vc.curl(B, "/r%d" % i, timeout=5)["status"] for i in range(30)]
    c.check("rate limit answers 429 beyond 20 requests per 10 s", 429 in statuses and statuses[:15].count(200) == 15, statuses)
    return ra


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
	option backend 'pt_backend'

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

config backend 'pt_backend'

config server
	option backend 'pt_backend'
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

    A, B, C, PT = HOSTS
    auth = AUTH
    ra = request_checks(c)

    # Firewall (D7): the listener's ports are open while the service runs.
    nft = vm.out("nft list ruleset")
    save(out, "nft-1.txt", nft)
    c.check("firewall accepts 18443 from the zone", "18443" in nft and "haproxy-advanced" in nft, "")
    c.check("firewall accepts 18080 from the zone", "18080" in nft, "")

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
config device 'hatest_veth'
	option type 'veth'
	option name 'hatest-a'
	option peer_name 'hatest-b'

config device 'hatest_dev'
	option name 'br-hatest'
	option type 'bridge'
	list ports 'hatest-a'

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
        # The veth peer gives the bridge a carrier, so IPv6 duplicate address
        # detection can finish as on a real interface.
        vm.run("ip link set hatest-b up", check=False)
        c.check("fd99::1 leaves the tentative state", wait_for(lambda: "tentative" not in vm.out(
            "ip -6 addr show br-hatest", check=False) and "fd99::1" in vm.out("ip -6 addr show br-hatest", check=False), 20) is not None)

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
                    "openssl s_client -connect '[fd99::1]:18444' -servername svc-c.hatest.example -quiet -ign_eof 2>/dev/null",
                    check=False, timeout=20).stdout.decode(errors="replace")
        save(out, "ipv6.txt", v6 + "\n--- ip -6 addr show br-hatest\n" + vm.out("ip -6 addr show br-hatest", check=False))
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
        c.check("br-hatest and the veth pair removed", wait_for(lambda: all(vm.run("ip link show %s" % d, check=False).returncode != 0
                                                                   for d in ("br-hatest", "hatest-a", "hatest-b")), 15) is not None)

    la = apply_config(vm, functional_config(iface, zone, crypt_hash(TEST_PASSWORD)))
    c.check("back to the functional configuration", la and la["state"] == "applied", la and la.get("state"))
    return c.finish()


@scenario
def cleanup(vm, out, args):
    """Remove what this goal installed and compare the VM with a snapshot
    (args[0]: path of snapshot.json). Only touches what the goal itself added:
    packages named in this goal's own `apk add` logs and the configuration files
    of haproxy-advanced and acme when the snapshot did not have them. Other
    sessions share the VM, so nothing is removed by pattern."""
    c = Checks(out)
    snap = json.loads(Path(args[0]).read_text()) if args else None
    vm.run("/etc/init.d/haproxy-advanced stop 2>/dev/null; /etc/init.d/haproxy-advanced disable 2>/dev/null", check=False)

    def names(lines):
        out = set()

        for l in lines:
            m = re.match(r"^(.*)-(\d[\w.~+]*(?:-r\d+)?) ", l)

            if m:
                out.add(m.group(1))

        return out

    ours = set()

    for log in list((ROOT / "logs").glob("accept-install-*/apk-add.txt")) + list((ROOT / "logs").glob("accept-browser-*/step-*.txt")):
        ours |= set(re.findall(r"Installing (\S+) \(", log.read_text(errors="replace")))

    ours |= {"luci-i18n-base-ru", "luci-i18n-haproxy-advanced-ru"}
    before = names(snap["apk"]) if snap else set()
    now = names(vm.out("apk list -I 2>/dev/null | sort").splitlines())
    remove = sorted((now - before) & ours)
    save(out, "removed-packages.txt", "\n".join(remove) + "\n")

    if remove:
        r = vm.run("apk del %s 2>&1" % " ".join(remove), check=False, timeout=300)
        save(out, "apk-del.txt", r.stdout.decode(errors="replace"))
        c.check("apk del of this goal's packages", r.returncode == 0, r.stdout.decode(errors="replace")[-500:])

    # Put back the files the packages changed or removed, from the baseline
    # copy, when that copy has the snapshot's hash.
    snap_hash = {l.split()[1]: l.split()[0] for l in (snap or {}).get("config_hashes", [])}

    for f in TOUCHED_CONFIGS:
        want = snap_hash.get(f)
        b = BASELINE / f

        if not want or not b.exists() or hashlib.sha256(b.read_bytes()).hexdigest() != want:
            continue

        cur = vm.run("sha256sum /etc/config/%s 2>/dev/null" % f, check=False).stdout.decode().split()

        if not cur or cur[0] != want:
            mode = {"luci": "644", "openssl": "644"}.get(f, "600")
            vm.run("cat > /etc/config/%s && chmod %s /etc/config/%s" % (f, mode, f), data=b.read_bytes())
            print("restored /etc/config/%s from the baseline" % f)

    left = sorted((now - before) - ours)

    if left:
        print("packages added since the snapshot by someone else, left alone:", left)

    known = {l.split()[-1] for l in (snap or {}).get("config_hashes", [])}

    for f in vm.out("ls /etc/config").split():
        if f in known:
            continue

        if re.match(r"^(haproxy-advanced(\.v01|\.apk-new|-opkg)?|acme(\.apk-new)?)$", f):
            vm.run("rm -f /etc/config/%s" % f, check=False)

    vm.run("rm -rf /etc/haproxy/certs /var/etc/haproxy-advanced.cfg* /var/run/haproxy-advanced %s" % vmlib.STAGE, check=False)

    for d in ("/etc/acme", "/etc/ssl/acme", "/etc/haproxy", "/etc/haproxy.cfg"):
        if snap and d not in snap["dirs"]:
            vm.run("rm -rf %s" % d, check=False)

    if snap:
        tokens = lambda lines: sorted(l.split(" ")[0] for l in lines)
        now_apk = vm.out("apk list -I 2>/dev/null | sort").splitlines()
        c.check("package set as in the snapshot (name-version)", tokens(now_apk) == tokens(snap["apk"]),
                sorted(set(tokens(now_apk)) ^ set(tokens(snap["apk"]))))
        hashes = vm.out("cd /etc/config && sha256sum * | sort -k2").splitlines()
        c.check("/etc/config as in the snapshot", hashes == snap["config_hashes"],
                sorted(set(hashes) ^ set(snap["config_hashes"])))
        init = vm.out("ls /etc/rc.d | sort").splitlines()
        c.check("enabled init scripts as in the snapshot", init == snap["enabled_init"], sorted(set(init) ^ set(snap["enabled_init"])))
        ca = vm.out("sha256sum /etc/ssl/certs/ca-certificates.crt 2>/dev/null", check=False).strip()
        c.check("CA bundle as in the snapshot", ca == snap["ca_bundle"], ca)
        cron = vm.out("cat /etc/crontabs/root 2>/dev/null", check=False)
        c.check("root crontab as in the snapshot", cron == snap["crontab"], cron)
        # A reboot gives devices with random MACs (SQM's ifb4eth1) new link-local
        # addresses, so link-local listeners are compared by count only.
        def norm(lines):
            return sorted(re.sub(r"fe80::[0-9a-f:]+:(\d+) ", r"fe80::LL:\1 ", l) for l in lines)

        lst = vm.out("netstat -ltn 2>/dev/null | sort").splitlines()
        c.check("listening sockets as in the snapshot (link-local by count)", norm(lst) == norm(snap["listening"]),
                sorted(set(lst) ^ set(snap["listening"])))
        nft = vm.out("nft list ruleset")
        c.check("no haproxy-advanced or ACME firewall rule left", "haproxy-advanced" not in nft and "ACME" not in nft)

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
    # setsid -f returns at once; the child writes its own pid before exec, so
    # the ssh session does not wait for it.
    ub.run("cd %s && setsid -f sh -c 'echo $$ > %s/%s.pid; exec %s > %s.log 2>&1 < /dev/null'" % (
        vmlib.UBUNTU_DIR, vmlib.UBUNTU_DIR, name, command.replace("'", "'\\''"), name), timeout=20)


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


@scenario
def sync(vm, out, args):
    """Development only: copy the checkout's service and LuCI files over the
    installed ones. The final acceptance installs the built APKs instead."""
    files = {
        "haproxy-advanced/files/haproxy-advanced.init": ("/etc/init.d/haproxy-advanced", "755"),
        "haproxy-advanced/files/haproxy-advanced-ctl": ("/usr/libexec/haproxy-advanced/ctl", "755"),
        "luci-app-haproxy-advanced/root/usr/share/rpcd/ucode/luci.haproxy-advanced": ("/usr/share/rpcd/ucode/luci.haproxy-advanced", "644"),
        "luci-app-haproxy-advanced/root/usr/share/rpcd/acl.d/luci-app-haproxy-advanced.json": ("/usr/share/rpcd/acl.d/luci-app-haproxy-advanced.json", "644"),
        "luci-app-haproxy-advanced/root/usr/share/luci/menu.d/luci-app-haproxy-advanced.json": ("/usr/share/luci/menu.d/luci-app-haproxy-advanced.json", "644"),
    }

    for f in (ROOT / "haproxy-advanced/files/ucode").glob("*.uc"):
        files[str(f.relative_to(ROOT))] = ("/usr/share/haproxy-advanced/" + f.name, "644")

    for f in (ROOT / "luci-app-haproxy-advanced/htdocs/luci-static/resources").rglob("*.js"):
        files[str(f.relative_to(ROOT))] = ("/www/luci-static/resources/" + str(f.relative_to(
            ROOT / "luci-app-haproxy-advanced/htdocs/luci-static/resources")), "644")

    for src, (dest, mode) in sorted(files.items()):
        tmp = "%s/sync/%s" % (vmlib.STAGE, dest.replace("/", "_"))
        vm.upload((ROOT / src).read_bytes(), tmp)
        vm.run("cp %s %s && chmod %s %s" % (tmp, dest, mode, dest))

    vm.run("rm -rf /tmp/luci-indexcache.* /tmp/luci-modulecache; /etc/init.d/rpcd reload", check=False)
    print("synced %d files" % len(files))


def node_step(vm, step, out):
    p = subprocess.run(["node", str(ROOT / "tools/browser.js"), step, str(out)],
                       input=vm.password + b"\n", capture_output=True, timeout=600)
    text = p.stdout.decode(errors="replace") + p.stderr.decode(errors="replace")
    save(out, "step-%s.txt" % step, text)
    return "STEP_OK " + step in text, text[-600:]


def curl_status(host, path="/x", user=None):
    return vc.curl(host, path, user=user).get("status")


def nft_rules(vm):
    return int(vm.out("nft list ruleset | grep -c 'ubus:haproxy-advanced' || true").strip() or 0)


@scenario
def browser(vm, out, args):
    """The LuCI steps of tools/browser.js, with checks on the VM between them.
    Starts from the functional configuration."""
    c = Checks(out)
    stage_pki(vm)
    iface = iface_of(vm, vc.VM)
    zone = zone_of(vm, iface)
    la = apply_config(vm, functional_config(iface, zone, crypt_hash(TEST_PASSWORD)))
    c.check("start from the functional configuration", la and la["state"] == "applied", la and la.get("state"))
    X = "svc-x.hatest.example"

    ok, t = node_step(vm, "screens", out)
    c.check("every tab renders", ok, t)

    ok, t = node_step(vm, "add-service", out)
    c.check("Add service dialog, editor, Save & Apply, applied notice", ok, t)
    c.check("the new service's login works (hash made in the browser)", curl_status(X, user="bob:browser-pass-1") == 200)
    c.check("the new service refuses a wrong password", curl_status(X, user="bob:wrong") == 401)
    c.check("the new service keeps its own backend",
            vm.out("uci -q get haproxy-advanced.svcx.backend", check=False).strip() == "svcx_backend")

    ok, t = node_step(vm, "staged", out)
    c.check("Configuration tab shows unsaved changes (F5)", ok, t)

    ok, t = node_step(vm, "apply-error", out)
    c.check("a failing apply is shown in LuCI (F5)", ok, t)
    c.check("the running configuration keeps serving", curl_status(B) == 200)

    ok, t = node_step(vm, "password", out)
    c.check("password set in the user editor", ok, t)
    c.check("new password works", curl_status(X, user="bob:browser-pass-2") == 200)
    c.check("old password refused", curl_status(X, user="bob:browser-pass-1") == 401)

    ok, t = node_step(vm, "certs", out)
    c.check("certificate list with expiry, picker values, no key contents", ok, t)

    before = nft_rules(vm)
    ok, t = node_step(vm, "firewall-off", out)
    time.sleep(3)
    off = nft_rules(vm)
    ok2, t2 = node_step(vm, "firewall-on", out)
    time.sleep(3)
    on = nft_rules(vm)
    c.check("firewall checkbox removes and restores the rules", ok and ok2 and before == 2 and off == 0 and on == 2,
            (before, off, on, t, t2))

    ok, t = node_step(vm, "runtime", out)
    c.check("runtime panel: maintenance from the GUI", ok and curl_status(A, "/share/m") == 503, t)
    ok, t = node_step(vm, "runtime-ready", out)
    c.check("runtime panel: ready again from the GUI", ok and curl_status(A, "/share/m") == 200, t)

    stock = lambda: (vm.out("ls /etc/rc.d | grep -c 'haproxy$' || true").strip(),
                     vm.out("pgrep -f /etc/haproxy.cfg | wc -l").strip())
    found = stock()
    ok, t = node_step(vm, "stock", out)
    after = stock()
    c.check("stock haproxy stopped and disabled from the GUI", ok and after[0] == "0", (found, after, t))

    if found[0] != "0":
        vm.run("/etc/init.d/haproxy enable; /etc/init.d/haproxy start", check=False)

    c.check("stock haproxy restored as found", stock()[0] == found[0])

    vm.run("cp /etc/config/haproxy-advanced %s/current.config" % vmlib.STAGE)
    vm.upload(subprocess.run(["git", "show", "3bc4ff6:root/etc/config/haproxy-advanced"], cwd=ROOT,
                             capture_output=True, check=True).stdout, "/etc/config/haproxy-advanced")
    vm.run("/etc/init.d/haproxy-advanced reload", check=False, timeout=120)
    la = last_apply(vm)
    c.check("a 0.1 configuration is refused with a reason", la and la["state"] == "failed" and "version 0.1" in la["errors"][0]["message"])
    c.check("the running configuration keeps serving under a 0.1 file", curl_status(B) == 200)
    ok, t = node_step(vm, "legacy", out)
    moved = vm.out("grep -c 'config frontend' /etc/config/haproxy-advanced.v01 2>/dev/null || true").strip()
    c.check("the GUI moves the 0.1 file aside (O3)", ok and moved == "1", t)
    vm.run("cp %s/current.config /etc/config/haproxy-advanced && rm -f /etc/config/haproxy-advanced.v01 && "
           "/etc/init.d/haproxy-advanced reload" % vmlib.STAGE, check=False, timeout=120)

    ru = sorted(APK_DIR.glob("luci-i18n-haproxy-advanced-ru-*.apk"))[-1]
    vm.upload(ru.read_bytes(), "%s/%s" % (vmlib.STAGE, ru.name))
    r = vm.run("apk add --allow-untrusted %s/%s luci-i18n-base-ru 2>&1" % (vmlib.STAGE, ru.name), check=False, timeout=300)
    c.check("Russian packages install", r.returncode == 0, r.stdout.decode(errors="replace")[-300:])
    vm.run("cp /etc/config/luci %s/luci.orig && uci set luci.main.lang=ru && uci commit luci && "
           "rm -f /tmp/luci-indexcache.*; rm -rf /tmp/luci-modulecache" % vmlib.STAGE)

    try:
        ok, t = node_step(vm, "russian", out)
        c.check("Russian translation", ok, t)
    finally:
        vm.run("cp %s/luci.orig /etc/config/luci" % vmlib.STAGE)

    ok, t = node_step(vm, "phone", out)
    widths = (out / "phone.txt").read_text() if (out / "phone.txt").exists() else ""
    c.check("no horizontal scroll at 390 px on any tab", ok and widths and all(
        int(l.split()[1]) <= 0 for l in widths.splitlines()), widths)

    la = apply_config(vm, functional_config(iface, zone, crypt_hash(TEST_PASSWORD)))
    c.check("back to the functional configuration", la and la["state"] == "applied")
    return c.finish()


@scenario
def backends(vm, out, args):
    """Start (or with 'stop', stop) the test backends on the Ubuntu VM."""
    ub = vmlib.Ubuntu()
    ub.upload((ROOT / "tools/ubuntu_servers.py").read_bytes(), vmlib.UBUNTU_DIR + "/servers.py")

    for name in ("backend.pem", "passthrough.pem", "pebble.crt", "pebble.key", "ca.crt"):
        ub.upload((PKI / name).read_bytes(), "%s/pki/%s" % (vmlib.UBUNTU_DIR, name), mode="600")

    ubuntu_stop(ub, "servers")

    if args and args[0] == "stop":
        print("backends stopped")
        return 0

    ubuntu_start(ub, "servers", "python3 -I servers.py pki")
    time.sleep(2)
    up = ub.out("ss -ltn | grep -cE ':(19080|19081|19443|19444) '", check=False).strip()
    print("backends listening on %s of 4 ports" % up)
    return 0 if up == "4" else 1


MEASURE_H6 = "$6$lhB0kwyr7FuLqRj8$9mT69LBIlGbpVp6aFA9DJMZbhpP2WsdsHHob2sah6bXpu2emKUTLmUU68n5honAYlXAtuYGQEzEEz58xRJ7kF0"
MEASURE_HB = "$2b$10$DHFc/s5cOncHd8qFesatOOooBivXW74AmmDcSkZJegINSfnII2GgO"
MEASURE_PW = "measure-pass-1"


def worker_cpu_ms(vm):
    """utime + stime of this service's HAProxy processes, in ms."""
    txt = vm.out("for p in $(pgrep -f haproxy-advanced.cfg); do cat /proc/$p/stat; done", check=False)
    tick = 100
    total = 0

    for line in txt.splitlines():
        f = line.rsplit(")", 1)[1].split()
        total += int(f[11]) + int(f[12])

    return total * 1000.0 / tick


def auth_batch(vm, path, user, n):
    url = "https://svc-a.hatest.example:18443" + path
    argv = ["curl", "-sk", "--http1.1", "-m", "120", "--resolve", "svc-a.hatest.example:18443:192.168.189.130",
            "-w", "%{http_code}\n"]

    if user:
        argv += ["-u", user]

    for _ in range(n):
        argv += ["-o", "/dev/null", url]

    c0 = worker_cpu_ms(vm)
    t0 = time.time()
    p = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    wall = time.time() - t0
    cpu = worker_cpu_ms(vm) - c0
    return {"requests": n, "wall_s": round(wall, 2), "cpu_ms": round(cpu, 1),
            "cpu_ms_per_request": round(cpu / n, 2), "statuses": sorted(set(p.stdout.split()))}


@scenario
def measure(vm, out, args):
    """Numbers for the status file: the CPU cost of one password check, the
    requests a real web UI (LuCI through HAProxy) sends, and reload times."""
    c = Checks(out)
    stage_pki(vm)
    iface = iface_of(vm, vc.VM)
    zone = zone_of(vm, iface)
    extra = """
config user
	option group 'family'
	option username 'm6'
	option password_hash '%s'

config user
	option group 'family'
	option username 'mbc'
	option password_hash '%s'

config service 'luci'
	option listener 'pub'
	list hostname 'luci.hatest.example'
	option backend 'luci_backend'
	option certificate '/etc/haproxy/certs/svc-c.pem'

config backend 'luci_backend'

config server
	option backend 'luci_backend'
	option name 'uhttpd'
	option address '127.0.0.1'
	option port '80'
""" % (MEASURE_H6, MEASURE_HB)
    la = apply_config(vm, functional_config(iface, zone, crypt_hash(TEST_PASSWORD), extra))
    c.check("measurement configuration applies", la and la["state"] == "applied", la and la.get("errors"))
    time.sleep(2)
    res = {"cpu": vm.out("grep -m1 'model name' /proc/cpuinfo").strip(),
           "cores": vm.out("grep -c ^processor /proc/cpuinfo").strip()}

    # Password checks: compare the worker CPU of logged-in requests with
    # requests that need no login.
    runs = {"no_login": [], "sha512_5000": [], "bcrypt_10": []}

    for _ in range(3):
        runs["no_login"].append(auth_batch(vm, "/share/x", None, 100))
        runs["sha512_5000"].append(auth_batch(vm, "/x", "m6:" + MEASURE_PW, 100))
        runs["bcrypt_10"].append(auth_batch(vm, "/x", "mbc:" + MEASURE_PW, 20))

    best = {k: min(r["cpu_ms_per_request"] for r in v) for k, v in runs.items()}
    res["auth_runs"] = runs
    res["auth_cpu_ms_per_request"] = best
    res["sha512_5000_check_ms"] = round(best["sha512_5000"] - best["no_login"], 2)
    res["bcrypt_10_check_ms"] = round(best["bcrypt_10"] - best["no_login"], 2)
    c.check("logins with both hashes succeed", all(r["statuses"] == ["200"] for k in ("sha512_5000", "bcrypt_10")
                                                     for r in runs[k]), runs)

    # A real web UI through HAProxy.
    p = subprocess.run(["node", str(ROOT / "tools/pageload.js"), str(out)], input=vm.password + b"\n",
                       capture_output=True, timeout=600)
    save(out, "pageload.txt", p.stdout.decode() + p.stderr.decode())
    pl = json.loads((out / "pageload.json").read_text()) if (out / "pageload.json").exists() else None
    res["pageload"] = pl
    c.check("LuCI through HAProxy loads", p.returncode == 0 and pl, p.stderr.decode()[-300:])

    # Reload times.
    times = []

    for _ in range(5):
        t0 = time.time()
        vm.run("/etc/init.d/haproxy-advanced reload", check=False, timeout=120)
        times.append(round(time.time() - t0, 2))

    base = []

    for _ in range(5):
        t0 = time.time()
        vm.run("true")
        base.append(time.time() - t0)

    res["reload_seconds"] = times
    res["ssh_round_trip_seconds"] = round(min(base), 2)
    save(out, "measurements.json", res)
    print(json.dumps({k: v for k, v in res.items() if k not in ("auth_runs", "pageload")}, indent=1))

    if pl:
        print("pageload cold total/max10s:", pl["cold"]["total"], pl["cold"]["max_in_10s"],
              "warm:", pl["warm"]["total"], pl["warm"]["max_in_10s"])

    la = apply_config(vm, functional_config(iface, zone, crypt_hash(TEST_PASSWORD)))
    c.check("back to the functional configuration", la and la["state"] == "applied")
    return c.finish()


TOUCHED_CONFIGS = ("acme", "socat", "openssl", "luci")
BASELINE = ROOT / "logs" / "config-baseline"


@scenario
def baseline(vm, out, args):
    """Before an install: keep the bytes of the /etc/config files that this
    goal's packages change or remove (acme-common takes over acme, socat and
    openssl-util remove theirs, luci-i18n-base-ru adds a language to luci).
    cleanup restores them when their hash differs from the snapshot."""
    BASELINE.mkdir(parents=True, exist_ok=True)

    for f in TOUCHED_CONFIGS:
        r = vm.run("cat /etc/config/%s" % f, check=False)
        p = BASELINE / f

        if r.returncode == 0:
            p.write_bytes(r.stdout)
            print("kept /etc/config/%s (%s)" % (f, hashlib.sha256(r.stdout).hexdigest()[:16]))
        elif p.exists():
            p.unlink()

    return 0


@scenario
def acme_gui(vm, out, args):
    """ACME issue started from the Certificates tab (tools/browser.js
    acme-issue) for svca, validated by Pebble through the HTTP companion."""
    c = Checks(out)
    ub = vmlib.Ubuntu()
    stage_pki(vm)
    iface = iface_of(vm, vc.VM)
    zone = zone_of(vm, iface)
    host = "svc-a.hatest.example"
    la = apply_config(vm, functional_config(iface, zone, crypt_hash(TEST_PASSWORD)))
    c.check("functional configuration applies", la and la["state"] == "applied")
    before = served_cert(host)
    c.check("before: svc-a serves the test-CA certificate", "haproxy-advanced test CA" in before, before)
    acme_setup(vm, ub, out)

    try:
        ok, t = node_step(vm, "acme-issue", out)
        c.check("Issue dialog: Save and issue applies the change", ok, t)
        save(out, "acme-uci.txt", vm.out("uci show acme; uci -q get haproxy-advanced.svca.acme_cert", check=False))
        path = "/etc/ssl/acme/%s.combined.crt" % host
        t = wait_for(lambda: vm.run("test -s %s" % path, check=False).returncode == 0, 240, 3)
        save(out, "acme.log", vm.out("logread -e acme | tail -n 60", check=False))
        c.check("the acme package issued the certificate (config trigger)", t is not None, t)
        t2 = wait_for(lambda: "Pebble" in served_cert(host), 90, 3)
        after = served_cert(host)
        save(out, "served.txt", after)
        c.check("svc-a now serves the Pebble certificate", t2 is not None, after)
        r = vc.curl(A, "/share/acme")
        c.check("svc-a answers with the new certificate", r["status"] == 200, r.get("status"))
    finally:
        acme_teardown(vm, ub)

    la = apply_config(vm, functional_config(iface, zone, crypt_hash(TEST_PASSWORD)))
    c.check("back to the functional configuration", la and la["state"] == "applied")
    return c.finish()


LUCI_EXTRA = """
config service 'luci'
	option listener 'pub'
	list hostname 'luci.hatest.example'
	option backend 'luci_backend'
	option certificate '/etc/haproxy/certs/svc-c.pem'

config backend 'luci_backend'

config server
	option backend 'luci_backend'
	option name 'uhttpd'
	option address '127.0.0.1'
	option port '80'
"""


def stock_state(vm):
    return tuple(vm.run("/etc/init.d/haproxy %s" % a, check=False).returncode == 0 for a in ("enabled", "running"))


def proc_names(vm):
    return sorted(vm.out("for d in /proc/[0-9]*; do cat $d/comm 2>/dev/null; done").split())


def boot_id(vm):
    try:
        r = vm.run("cat /proc/sys/kernel/random/boot_id", check=False, timeout=20)
    except subprocess.TimeoutExpired:
        return None

    return r.stdout.decode().strip() if r.returncode == 0 else None


@scenario
def boot(vm, out, args):
    """Reboots the shared VM, so run it only after every other session
    agrees (the task allows one reboot; the owner allowed a second one on
    2026-11-17): haproxy-advanced starts at boot with the applied
    configuration, its firewall rule, and serves without a manual step."""
    c = Checks(out)
    stage_pki(vm)
    iface = iface_of(vm, vc.VM)
    zone = zone_of(vm, iface)
    la = apply_config(vm, functional_config(iface, zone, crypt_hash(TEST_PASSWORD), LUCI_EXTRA))
    c.check("configuration applies before the reboot", la and la["state"] == "applied")
    c.check("init script enabled", vm.run("/etc/init.d/haproxy-advanced enabled", check=False).returncode == 0)

    # Guard: nobody else may be working on the shared VM right now. Busybox-less
    # ps lists only terminal processes, so read /proc: one dropbear per pid
    # file (the listeners) plus this session's own.
    comms = proc_names(vm)
    save(out, "proc-before.txt", "\n".join(comms))
    listeners = int(vm.out("ls /var/run/dropbear.*.pid 2>/dev/null | wc -l").strip() or 0)
    sessions = comms.count("dropbear") - listeners - 1
    kea = [n for n in comms if n.startswith("kea-")]
    if not c.check("no other ssh session and no Kea process before the reboot",
                   sessions == 0 and not kea, "%d other sessions, %s" % (sessions, kea)):
        return c.finish()

    stock_before = stock_state(vm)
    old = boot_id(vm)
    t0 = time.time()
    try:
        vm.run("(sleep 1; reboot) >/dev/null 2>&1 &", check=False, timeout=20)
    except subprocess.TimeoutExpired:
        pass

    def booted():
        b = boot_id(vm)
        return b and b != old

    t = wait_for(booted, 420, 5)
    c.check("the VM came back with a new boot id", t is not None, t)
    if t is None:
        return c.finish()

    t = wait_for(lambda: (last_apply(vm) or {}).get("state") == "applied" and listening(vm, ":18443"), 180, 2)
    up = vm.out("cat /proc/uptime").split()[0]
    save(out, "timing.txt", "reboot to ssh+service: %.1f s; uptime when serving: %s s\n" % (time.time() - t0, up))
    la = last_apply(vm)
    save(out, "last-apply.json", la)
    c.check("started at boot: last apply 'applied', HTTPS listener up", t is not None, la)
    svc = ubus(vm, "service", "list", {"name": "haproxy-advanced"})
    inst = (svc.get("haproxy-advanced") or {}).get("instances") or {}
    c.check("procd runs the instance", any(i.get("running") for i in inst.values()), svc)
    c.check("the firewall rule is back (procd data, fw4)", nft_rules(vm) >= 1, nft_rules(vm))
    # The feed's haproxy package enables its own service with a sample config
    # (ports 81, 444, 60000); the Overview offers to stop it (F20). It must be
    # in the same state as before the reboot and must not take our ports.
    c.check("the stock haproxy service is as before the reboot",
            stock_state(vm) == stock_before, (stock_before, stock_state(vm)))

    st = curl_status("luci.hatest.example", "/cgi-bin/luci/")
    c.check("LuCI through HAProxy answers after the boot", st in (200, 403), st)
    r = vc.curl(A, "/p?q=1", port=vc.HTTP_PORT, scheme="http")
    c.check("the HTTP companion redirects after the boot", r.get("status") == 308, r.get("status"))
    c.check("a protected path still needs a login", curl_status(A, "/other") == 401)
    c.check("the login works", curl_status(A, "/other", user=AUTH) in (200, 502, 503))

    comms = proc_names(vm)
    save(out, "proc-after.txt", "\n".join(comms))
    kea = [n for n in comms if n.startswith("kea-")]
    c.check("no Kea component runs after the boot (asked by luci-app-kea)", not kea, "\n".join(kea))
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
