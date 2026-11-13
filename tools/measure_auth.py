#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Measure what one password check costs HAProxy on the OpenWrt VM: 200
requests on one kept-alive TLS connection, without login and with a login
whose hash is $6$ (5000 rounds) or $2b$ (bcrypt cost 10). Password on stdin."""
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import accept  # noqa: E402
import vmlib  # noqa: E402

H6 = sys.argv[1]
HB = sys.argv[2]
out = Path(sys.argv[3])
out.mkdir(parents=True, exist_ok=True)
vm = vmlib.OpenWrt()
iface = accept.iface_of(vm, "192.168.189.130")
zone = accept.zone_of(vm, iface)
extra = """
config user
	option group 'family'
	option username 'm6'
	option password_hash '%s'

config user
	option group 'family'
	option username 'mbc'
	option password_hash '%s'
""" % (H6, HB)
la = accept.apply_config(vm, accept.functional_config(iface, zone, accept.crypt_hash(accept.TEST_PASSWORD), extra))
assert la["state"] == "applied", la
time.sleep(2)


def worker_cpu():
    # utime + stime (clock ticks) of HAProxy's worker processes of this service.
    txt = vm.out("for p in $(pgrep -f haproxy-advanced.cfg); do cat /proc/$p/stat; done", check=False)
    total = 0

    for line in txt.splitlines():
        f = line.rsplit(")", 1)[1].split()
        total += int(f[11]) + int(f[12])

    return total


TICK = int(vm.out("getconf CLK_TCK 2>/dev/null || echo 100").strip() or 100)


def run(path, user=None, n=200):
    url = "https://svc-a.hatest.example:18443" + path
    argv = ["curl", "-sk", "--http1.1", "--resolve", "svc-a.hatest.example:18443:192.168.189.130",
            "-w", "%{http_code}\n"]

    if user:
        argv += ["-u", user]

    for _ in range(n):
        argv += ["-o", "/dev/null", url]

    c0 = worker_cpu()
    t0 = time.time()
    p = subprocess.run(argv, capture_output=True, text=True)
    total = time.time() - t0
    cpu = (worker_cpu() - c0) * 1000.0 / TICK
    return {"requests": n, "seconds": round(total, 3), "cpu_ms": round(cpu, 1),
            "cpu_ms_per_request": round(cpu / n, 3), "statuses": sorted(set(p.stdout.split()))}


res = {}

for rnd in range(3):
    res.setdefault("no_login", []).append(run("/share/x"))
    res.setdefault("sha512_5000", []).append(run("/x", "m6:measure-pass-1"))
    res.setdefault("bcrypt_10", []).append(run("/x", "mbc:measure-pass-1", n=50))

summary = {k: min(r["cpu_ms_per_request"] for r in v) for k, v in res.items()}
summary["sha512_check_ms"] = round(summary["sha512_5000"] - summary["no_login"], 3)
summary["bcrypt_check_ms"] = round(summary["bcrypt_10"] - summary["no_login"], 3)
summary["cpu"] = vm.out("grep -m1 'model name' /proc/cpuinfo").strip()
(out / "auth-cost.json").write_text(json.dumps({"runs": res, "summary": summary}, indent=2) + "\n")
print(json.dumps(summary, indent=1))
la = accept.apply_config(vm, accept.functional_config(iface, zone, accept.crypt_hash(accept.TEST_PASSWORD)))
print("restored:", la["state"])
