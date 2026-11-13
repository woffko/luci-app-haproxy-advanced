#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation pass over the access-policy part of the generator.

Each mutation breaks one rule of the policy (order, matching form, a missing
condition, ...). The golden tests must fail for every one of them; a mutation
that passes means the tests do not cover that rule.

Usage: UCODE=/path/to/ucode tests/mutations.py
"""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UCODE = os.environ.get("UCODE", "ucode")
R = "haproxy-advanced/files/ucode/render.uc"
M = "haproxy-advanced/files/ucode/model.uc"
U = "haproxy-advanced/files/ucode/util.uc"

MUTATIONS = [
    ("blocked paths not denied",
     R, "\t\tif (length(svc.blocked))\n\t\t\tpush(out, `    http-request deny deny_status 403 if ${h} blocked_${n}`);\n", ""),
    ("trusted networks allowed before blocked paths",
     R, "\t\tif (length(svc.trusted))\n\t\t\tpush(out, `    http-request allow if ${h} trusted_${n}`);\n",
     "\t\tif (false)\n\t\t\tpush(out, '');\n"),
    ("deny paths compared without lower-casing",
     R, "const DENY_PATH = 'path,url_dec,lower,regsub(;[^/]*,,g)';", "const DENY_PATH = 'path,url_dec,regsub(;[^/]*,,g)';"),
    ("deny paths compared without URL decoding",
     R, "const DENY_PATH = 'path,url_dec,lower,regsub(;[^/]*,,g)';", "const DENY_PATH = 'path,lower,regsub(;[^/]*,,g)';"),
    ("deny paths keep ;parameters",
     R, "const DENY_PATH = 'path,url_dec,lower,regsub(;[^/]*,,g)';", "const DENY_PATH = 'path,url_dec,lower';"),
    ("deny patterns not lower-cased",
     R, "return map(items, (p) => lc(p));", "return items;"),
    ("host matched without host_only",
     R, "acl host_${n} req.hdr(host),host_only,lower", "acl host_${n} req.hdr(host),lower"),
    ("host matched case-sensitively",
     R, "acl host_${n} req.hdr(host),host_only,lower", "acl host_${n} req.hdr(host),host_only"),
    ("passthrough routed to the wrong backend",
     R, "\t\t\tpush(out, `    use_backend be_${svc.backend} if sni_${svc.name}`);",
     "\t\t\tpush(out, `    use_backend be_${l.pt_services[0].backend}_x if sni_${svc.name}`);"),
    ("client forwarding headers not removed",
     R, "\t\tif (svc.hardening)\n\t\t\tfor (let hd in", "\t\tif (false)\n\t\t\tfor (let hd in"),
    ("X-Forwarded-For appended under hardening",
     R, "http-request ${svc.hardening ? 'set' : 'add'}-header X-Forwarded-For", "http-request add-header X-Forwarded-For"),
    ("ambiguous paths not denied",
     R, "\t\tif (svc.hardening || uses_path_lists(svc))\n", "\t\tif (false)\n"),
    ("ambiguous paths only with hardening",
     R, "\t\tif (svc.hardening || uses_path_lists(svc))\n", "\t\tif (svc.hardening)\n"),
    ("// no longer ambiguous",
     R, "(/|$)|//|\\\\\\\\'\"", "(/|$)|\\\\\\\\'\""),
    ("internal-only paths not denied",
     R, "\t\tif (length(svc.internal))\n\t\t\tpush(out, `    http-request deny deny_status 403 if ${h} internal_${n}`);\n", ""),
    ("public paths compared case-insensitively",
     R, "acl public_${n} ${ALLOW_PATH} -m beg ${join(' ', svc.public)}", "acl public_${n} ${DENY_PATH} -m beg ${join(' ', svc.public)}"),
    ("successful logins counted as failures",
     R, "{ req.hdr(authorization) -m found } !{ var(${v}) -m bool }`);", "{ req.hdr(authorization) -m found }`);"),
    ("login asked even after success",
     R, "auth realm \"${realm}\" if ${cond} !{ var(${v}) -m bool }", "auth realm \"${realm}\" if ${cond}"),
    ("rate limit compared the wrong way",
     R, "{ sc_http_req_rate(0) gt ${svc.rate_limit} }", "{ sc_http_req_rate(0) lt ${svc.rate_limit} }"),
    ("unknown hosts not denied",
     R, "\tpush(out, `    http-request deny deny_status 404 if ${join(' ', map(svcs, (s) => '!host_' + s.name))}`);\n", ""),
    ("trusted allow without the host condition",
     R, "http-request allow if ${h} trusted_${n}", "http-request allow if trusted_${n}"),
    ("custom rules not sorted by order",
     R, "for (let r in u.sort_by_order(svc.rules))", "for (let r in svc.rules)"),
    ("allow rules compared case-insensitively",
     R, "push(out, `    http-request allow if ${h}${rule_criteria(r, false)}`);", "push(out, `    http-request allow if ${h}${rule_criteria(r, true)}`);"),
    ("passthrough trusted networks not enforced",
     R, "\t\t\tif (length(svc.trusted))\n\t\t\t\tpush(out, `    tcp-request content reject if ${s} !{ src", "\t\t\tif (false)\n\t\t\t\tpush(out, `    tcp-request content reject if ${s} !{ src"),
    ("host names not lower-cased",
     M, "\t\tlet lh = lc(h);", "\t\tlet lh = h;"),
    ("ambiguous path prefixes accepted",
     U, "\treturn !is_ambiguous_path(v);", "\treturn true;"),
    ("HSTS sent for every service",
     R, "if { var(txn.ha_svc) -m str ${svc.name} }", "if { var(txn.ha_svc) -m found }"),
    ("redirect drops a non-443 port",
     R, "let port = (l.port == 443) ? '' : `:${l.port}`;", "let port = '';"),
    ("firewall rule without the firewall option",
     M, "\t\tif (l.firewall) {\n\t\t\tif (l.main_active)", "\t\tif (true) {\n\t\t\tif (l.main_active)"),
    ("listeners on one address and port allowed",
     M, "\t\t\tif (a.any || b.any || a.key == b.key)\n\t\t\t\treturn true;", "\t\t\tif (false)\n\t\t\t\treturn true;"),
    ("ports held by other programs ignored",
     M, "\t\tlet foreign = foreign_owner(env, l, l.binds);", "\t\tlet foreign = null;"),
    ("blocked paths skipped for trusted networks",
     R, "\t\tif (length(svc.blocked))\n\t\t\tpush(out, `    http-request deny deny_status 403 if ${h} blocked_${n}`);\n",
     "\t\tif (length(svc.blocked))\n\t\t\tpush(out, `    http-request deny deny_status 403 if ${h} blocked_${n}${length(svc.trusted) ? ' !trusted_' + n : ''}`);\n"),
    ("response rules conditioned on the request host",
     R, "push(out, `    ${line} if { var(txn.ha_svc) -m str ${n} }`);", "push(out, `    ${line} if ${h}`);"),
    ("empty request header written as an empty value",
     R, "push(out, `    http-request del-header ${hd.name} if ${h}`);", "push(out, `    http-request set-header ${hd.name} \"\" if ${h}`);"),
]


def run_tests(root):
    p = subprocess.run([UCODE, os.path.join(root, "tests/run.uc")], cwd=root,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout


def main():
    rc, out = run_tests(ROOT)

    if rc != 0:
        print("the unmutated tests fail; fix them first:\n" + out)
        return 2

    survived = []

    for i, (name, path, old, new) in enumerate(MUTATIONS, 1):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(os.path.join(ROOT, "tests"), os.path.join(tmp, "tests"))
            shutil.copytree(os.path.join(ROOT, "haproxy-advanced"), os.path.join(tmp, "haproxy-advanced"))
            f = os.path.join(tmp, path)
            text = open(f).read()

            if text.count(old) < 1:
                print(f"M{i:02d} BROKEN  {name}: pattern not found in {path}")
                survived.append(name)
                continue

            open(f, "w").write(text.replace(old, new, 1))
            rc, out = run_tests(tmp)
            failing = [l.split()[1].rstrip(":") for l in out.splitlines() if l.startswith("FAIL ")]

            if rc == 0:
                print(f"M{i:02d} SURVIVED {name}")
                survived.append(name)
            else:
                print(f"M{i:02d} caught   {name}  ({', '.join(failing) or 'error'})")

    print(f"{len(MUTATIONS) - len(survived)} of {len(MUTATIONS)} mutations caught")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
