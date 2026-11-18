#!/bin/sh
# Test-only PKI for the VM acceptance of goal A, written to logs/testpki.
# Nothing here is a real secret: the keys exist only for the test VMs.
set -eu
D=$(cd "$(dirname "$0")/.." && pwd)/logs/testpki
mkdir -p "$D" && cd "$D"
[ -f ca.crt ] && { echo "exists: $D"; exit 0; }

ca() { # name subject
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
		-subj "/CN=$2" -keyout "$1.key" -out "$1.crt" 2>/dev/null
}

leaf() { # name ca subject-alt-names
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
		-keyout "$1.key" -out "$1.csr" 2>/dev/null
	printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$3" > "$1.ext"
	openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial -days 30 \
		-extfile "$1.ext" -out "$1.crt" 2>/dev/null
	cat "$1.crt" "$1.key" > "$1.pem"
	rm -f "$1.csr" "$1.ext"
}

ca ca "haproxy-advanced test CA"
ca ptca "haproxy-advanced passthrough CA"
leaf svc-a ca "DNS:svc-a.hatest.example"
leaf svc-b ca "DNS:svc-b.hatest.example"
leaf svc-c ca "DNS:svc-c.hatest.example"
leaf backend ca "DNS:backend.hatest.example,IP:192.168.189.142"
leaf passthrough ptca "DNS:pt.hatest.example"
leaf pebble ca "DNS:pebble,IP:192.168.189.142"
echo "written: $D"
