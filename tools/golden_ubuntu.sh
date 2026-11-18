#!/bin/sh
# Pre-check of the golden configurations with OpenWrt's own HAProxy build,
# run on the Ubuntu test VM before the OpenWrt VM is available. The haproxy
# binary and the musl libraries it needs come from the dedicated build tree;
# the binary runs through the musl loader, so nothing is installed.
#
# Usage: tools/golden_ubuntu.sh OUTDIR
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
T=/home/w0w/build/openwrt-25.12.4-clean-haproxy-luci
OUT=${1:?outdir}
UB="ssh -o BatchMode=yes -o HostKeyAlias=192.168.189.144 -o ConnectTimeout=10 -i /home/w0w/.ssh/rustadmin_vm_ed25519 codex@192.168.189.142"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

BIN=$(find "$T/build_dir/target-x86_64_musl" -maxdepth 3 -path '*haproxy-ssl/haproxy-*/haproxy' -type f | head -n1)
TC=$(ls -d "$T"/staging_dir/toolchain-x86_64_*_musl | head -n1)
STG="$T/staging_dir/target-x86_64_musl"
[ -x "$BIN" ] || { echo "haproxy not built"; exit 1; }

mkdir -p "$TMP/hx/lib" "$TMP/hx/golden" "$TMP/hx/pki"
cp "$BIN" "$TMP/hx/haproxy"
cp "$TC/lib/libc.so" "$TMP/hx/lib/ld-musl-x86_64.so.1"

# Copy every NEEDED library, recursively.
need() {
	"$TC"/bin/x86_64-openwrt-linux-musl-readelf -d "$1" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'
}
todo="$TMP/hx/haproxy"
while [ -n "$todo" ]; do
	next=""
	for f in $todo; do
		for lib in $(need "$f"); do
			[ "$lib" = "libc.so" ] && continue
			[ -e "$TMP/hx/lib/$lib" ] && continue
			src=$(find "$STG/usr/lib" "$STG/lib" "$TC/lib" -name "$lib" 2>/dev/null | head -n1)
			[ -n "$src" ] || { echo "missing $lib"; exit 1; }
			cp -L "$src" "$TMP/hx/lib/$lib"
			next="$next $TMP/hx/lib/$lib"
		done
	done
	todo=$next
done

cp "$ROOT/logs/testpki/svc-a.pem" "$ROOT/logs/testpki/ca.crt" "$TMP/hx/pki/"

for d in "$ROOT"/tests/fixtures/*/; do
	n=$(basename "$d")
	[ -f "$d/expected.cfg" ] || continue
	# Same path rewrite as tools/accept.py golden: certificates -> test files.
	awk -v pki=/home/codex/haproxy-advanced-test/hx/pki '{
		for (i = 1; i < NF; i++) {
			if ($i == "crt") $(i+1) = pki "/svc-a.pem";
			else if ($i == "ca-file" && $(i+1) != "@system-ca") $(i+1) = pki "/ca.crt";
		}
		print
	}' "$d/expected.cfg" > "$TMP/hx/golden/$n.cfg"
done

tar -C "$TMP" -cf - hx | $UB 'rm -rf ~/haproxy-advanced-test/hx && tar -C ~/haproxy-advanced-test -xf - 2>/dev/null'
mkdir -p "$OUT"
$UB 'cd ~/haproxy-advanced-test/hx && ./lib/ld-musl-x86_64.so.1 --library-path ./lib ./haproxy -v | head -n1;
	for f in golden/*.cfg; do
		n=$(basename "$f" .cfg)
		./lib/ld-musl-x86_64.so.1 --library-path ./lib ./haproxy -c -f "$f" > "out-$n.txt" 2>&1
		echo "$? $n"
	done' > "$OUT/summary.txt"
$UB 'cd ~/haproxy-advanced-test/hx && tar -cf - out-*.txt' | tar -C "$OUT" -xf -
cat "$OUT/summary.txt"
