#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the request checks of the functional scenario against OpenWrt's HAProxy
build on the Ubuntu VM (through the musl loader, no install), with the
configuration the generator makes from the functional scenario's UCI config.
This exercises the generated rules before the OpenWrt VM is available; the
OpenWrt-side parts (procd, firewall, LuCI, ubus) stay with tools/accept.py.

Usage: tools/prerun_ubuntu.py OUTDIR   (after tools/golden_ubuntu.sh staged hx/)
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

os.environ["HA_TEST_TARGET"] = "192.168.189.142"
sys.path.insert(0, str(Path(__file__).resolve().parent))

import accept  # noqa: E402
import vmlib  # noqa: E402
import vmcases as vc  # noqa: E402

ROOT = vmlib.ROOT
UCODE = "/home/w0w/build/openwrt-25.12.4-clean-haproxy-luci/staging_dir/hostpkg/bin/ucode"
HX = vmlib.UBUNTU_DIR + "/hx"


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    ub = vmlib.Ubuntu()
    c = accept.Checks(out)
    cfg = accept.functional_config("ens37", "wan", accept.crypt_hash(accept.TEST_PASSWORD))
    env = {
        "interfaces": {"ens37": {"up": True, "device": "ens37", "ipv4": ["192.168.189.142"], "ipv6": []}},
        "files": ["/etc/haproxy/certs/svc-a.pem", "/etc/haproxy/certs/svc-b.pem", "/etc/haproxy/certs/svc-c.pem"],
    }
    (out / "config").write_text(cfg)
    (out / "env.json").write_text(json.dumps(env))
    res = json.loads(subprocess.run([UCODE, str(ROOT / "tools/gen_host.uc"), str(out / "config"), str(out / "env.json")],
                                    capture_output=True, check=True, cwd=ROOT).stdout)
    c.check("generator accepts the functional configuration", res["ok"], res["errors"])
    text = res["config"]
    text = text.replace("/etc/haproxy/certs/test-ca.crt", HX + "/pki/ca.crt")
    text = text.replace("/etc/haproxy/certs/", HX + "/pki/")
    text = text.replace("/var/run/haproxy-advanced/", HX + "/run/")
    text = "\n".join(l for l in text.splitlines() if l.strip() not in ("user nobody", "group nogroup")) + "\n"
    (out / "haproxy.cfg").write_text(text)

    for name in ("svc-a.pem", "svc-b.pem", "svc-c.pem", "ca.crt"):
        ub.upload((ROOT / "logs/testpki" / name).read_bytes(), "%s/pki/%s" % (HX, name))

    ub.upload(text, HX + "/prerun.cfg")
    ub.run("[ -f %s/haproxy.pid ] && kill $(cat %s/haproxy.pid) 2>/dev/null; true" % (HX, HX), check=False)
    ub.run("mkdir -p %s/run" % HX)
    ub.run("cd %s && setsid -f sh -c 'exec ./lib/ld-musl-x86_64.so.1 --library-path ./lib ./haproxy -W -db -f prerun.cfg "
           "-S %s/run/master.sock -p %s/haproxy.pid > haproxy.log 2>&1 < /dev/null'" % (HX, HX, HX), timeout=20)
    time.sleep(2)
    (out / "haproxy.log").write_text(ub.out("cat %s/haproxy.log" % HX, check=False))

    try:
        ra = accept.request_checks(c)

        def stats(cmd):
            return ub.out("python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(\"%s/run/admin.sock\"); "
                          "s.sendall(sys.argv[1].encode()+b\"\\n\"); print(s.recv(65536).decode())' %s"
                          % (HX, json.dumps(cmd)), check=False)

        stats("set server be_echo_http/s1 state maint")
        r = vc.curl(accept.A, "/share/m")
        c.check("maintenance: svc-a answers 503", r["status"] == 503, r.get("status"))
        stats("set server be_echo_http/s1 state ready")
        r = vc.curl(accept.A, "/share/m")
        c.check("ready again: svc-a answers 200", r["status"] == 200, r.get("status"))
        statuses = [vc.curl(accept.A, "/other", user="alice:wrong%d" % i, timeout=5)["status"] for i in range(8)]
        c.check("F10 failed logins: 401 first, then 429", statuses[0] == 401 and 429 in statuses, statuses)
    finally:
        (out / "haproxy.log").write_text(ub.out("cat %s/haproxy.log" % HX, check=False))
        ub.run("kill $(cat %s/haproxy.pid) 2>/dev/null; sleep 1; true" % HX, check=False)

    return c.finish()


if __name__ == "__main__":
    sys.exit(main())
