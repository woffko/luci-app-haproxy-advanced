#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regenerate po/templates/haproxy-advanced.pot with LuCI's i18n-scan.pl and
write po/ru/haproxy-advanced.po from tools/ru_translations.py. Fails when a
msgid has no translation."""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "luci-app-haproxy-advanced"
SCAN = Path("/home/w0w/build/openwrt-25.12.4-clean-haproxy-luci/feeds/luci/build/i18n-scan.pl")
sys.path.insert(0, str(ROOT / "tools"))

from ru_translations import RU  # noqa: E402


def unquote(block):
    return "".join(bytes(s, "utf-8").decode("unicode_escape").encode("latin-1").decode("utf-8")
                   for s in re.findall(r'"((?:[^"\\]|\\.)*)"', block))


def quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


pot = subprocess.run(["perl", str(SCAN), "."], cwd=APP, capture_output=True, check=True, text=True).stdout
(APP / "po/templates/haproxy-advanced.pot").write_text(pot)

out = ['msgid ""', 'msgstr ""', '"Project-Id-Version: luci-app-haproxy-advanced\\n"', '"MIME-Version: 1.0\\n"',
       '"Content-Type: text/plain; charset=UTF-8\\n"', '"Content-Transfer-Encoding: 8bit\\n"', '"Language: ru\\n"',
       '"Plural-Forms: nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);\\n"', '']
missing = []

for entry in pot.split("\n\n"):
    m = re.search(r'^msgid ((?:"(?:[^"\\]|\\.)*"\n?)+)', entry, re.M)

    if not m:
        continue

    msgid = unquote(m.group(1))

    if not msgid:
        continue

    refs = [l for l in entry.splitlines() if l.startswith("#:")]
    tr = RU.get(msgid)

    if tr is None:
        missing.append(msgid)
        continue

    out += refs + ["msgid " + quote(msgid), "msgstr " + quote(tr), ""]

(APP / "po/ru").mkdir(parents=True, exist_ok=True)
(APP / "po/ru/haproxy-advanced.po").write_text("\n".join(out))

if missing:
    print("missing translations:\n  " + "\n  ".join(missing))
    sys.exit(1)

subprocess.run(["msgfmt", "--check", "-o", "/dev/null", str(APP / "po/ru/haproxy-advanced.po")], check=True)
print("po/ru/haproxy-advanced.po: %d messages" % (len([l for l in out if l.startswith("msgid ")]) - 1))
