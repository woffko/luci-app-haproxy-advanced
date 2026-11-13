#!/bin/sh
# Compile every ucode file of both packages with the host ucode. Target-only
# modules (uci, ubus, socket) are replaced by stubs, and the absolute
# /usr/share/haproxy-advanced imports are pointed at this checkout.
set -eu
UCODE=${UCODE:-ucode}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
LIB="$ROOT/haproxy-advanced/files/ucode"
# Stubs of the target-only modules, so imports resolve at compile time.
mkdir -p "$TMP/stubs"
echo 'return { cursor: () => null };' > "$TMP/stubs/uci.uc"
echo 'return { connect: () => null };' > "$TMP/stubs/ubus.uc"
echo 'return { connect: () => null, SOL_SOCKET: 1, SO_RCVTIMEO: 20 };' > "$TMP/stubs/socket.uc"
FLAGS="-c -L $TMP/stubs/*.uc"
rc=0
for f in "$ROOT/haproxy-advanced/files/haproxy-advanced-ctl" \
         "$ROOT/luci-app-haproxy-advanced/root/usr/share/rpcd/ucode/luci.haproxy-advanced"; do
	sed "s#/usr/share/haproxy-advanced/#$LIB/#g" "$f" > "$TMP/check.uc"
	if "$UCODE" $FLAGS -o "$TMP/out" "$TMP/check.uc"; then
		echo "ok   ${f#$ROOT/}"
	else
		echo "FAIL ${f#$ROOT/}"
		rc=1
	fi
done
exit $rc
