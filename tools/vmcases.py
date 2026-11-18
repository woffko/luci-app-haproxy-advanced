# SPDX-License-Identifier: MIT
"""Client-side checks of the goal A acceptance, run from the WSL host against
HAProxy on the OpenWrt VM. Each helper returns plain data; accept.py decides
what passes."""

import json
import os
import socket
import ssl
import subprocess
import time

VM = os.environ.get("HA_TEST_TARGET", "192.168.189.130")
TLS_PORT = 18443
HTTP_PORT = 18080


def curl(host, path="/", port=TLS_PORT, scheme="https", method=None, headers=(), user=None,
         data=None, http2=False, path_as_is=True, timeout=10, extra=()):
    """Run curl with --resolve so the VM answers for the test host name.
    Returns {status, headers, body, json, version}."""
    url = "%s://%s:%d%s" % (scheme, host, port, path)
    argv = ["curl", "-sS", "-k", "-m", str(timeout), "--resolve", "%s:%d:%s" % (host, port, VM),
            "-D", "-", "-o", "-", "-w", "\n__HTTP_VERSION__%{http_version}"]

    if path_as_is:
        argv.append("--path-as-is")

    argv.append("--http2" if http2 else "--http1.1")

    if method:
        argv += ["-X", method]

    for h in headers:
        argv += ["-H", h]

    if user:
        argv += ["-u", user]

    if data is not None:
        argv += ["--data-binary", data]

    argv += list(extra) + [url]
    p = subprocess.run(argv, capture_output=True, timeout=timeout + 5)
    text = p.stdout.decode(errors="replace")

    if p.returncode != 0 or "__HTTP_VERSION__" not in text:
        return {"status": None, "error": p.stderr.decode(errors="replace").strip(), "headers": {}, "body": ""}

    text, ver = text.rsplit("\n__HTTP_VERSION__", 1)
    head, _, body = text.partition("\r\n\r\n")

    # Skip 1xx/redirect-less extra header blocks.
    while body.startswith("HTTP/"):
        head, _, body = body.partition("\r\n\r\n")

    lines = head.split("\r\n")
    status = int(lines[0].split()[1])
    hdrs = {}

    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()

    res = {"status": status, "headers": hdrs, "body": body, "version": ver}

    try:
        res["json"] = json.loads(body)
    except ValueError:
        pass

    return res


def echo_headers(res):
    """The request headers the echo backend received, as {lower name: [values]}."""
    out = {}

    for k, v in (res.get("json") or {}).get("headers", []):
        out.setdefault(k.lower(), []).append(v)

    return out


def tls_peer(host, port=TLS_PORT, timeout=10):
    """Subject and issuer CN of the certificate the VM sends for SNI host."""
    p = subprocess.run(["openssl", "s_client", "-connect", "%s:%d" % (VM, port), "-servername", host,
                        "-alpn", "h2,http/1.1"],
                       input=b"", capture_output=True, timeout=timeout)
    text = p.stdout.decode(errors="replace")
    subject = issuer = alpn = None

    for line in text.splitlines():
        line = line.strip()

        if line.startswith("subject=") and subject is None:
            subject = line.split("CN", 1)[-1].lstrip(" =")
        elif line.startswith("issuer=") and issuer is None:
            issuer = line.split("CN", 1)[-1].lstrip(" =")
        elif line.startswith("ALPN protocol:"):
            alpn = line.split(":", 1)[1].strip()

    return {"subject": subject, "issuer": issuer, "alpn": alpn, "rc": p.returncode}


def raw_tls(host, request_parts, port=TLS_PORT, pause=0.0, timeout=10):
    """Send an HTTP/1.1 request in parts over TLS, sleeping between parts, and
    return the status line and body."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((VM, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            for i, part in enumerate(request_parts):
                if i and pause:
                    time.sleep(pause)

                s.sendall(part)

            data = b""

            while b"\r\n\r\n" not in data:
                chunk = s.recv(65536)

                if not chunk:
                    break

                data += chunk

            head, _, body = data.partition(b"\r\n\r\n")
            length = 0

            for line in head.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1])

            while len(body) < length:
                chunk = s.recv(65536)

                if not chunk:
                    break

                body += chunk

    status = head.split(b"\r\n", 1)[0].decode(errors="replace")

    try:
        return {"status_line": status, "json": json.loads(body)}
    except ValueError:
        return {"status_line": status, "body": body.decode(errors="replace")}


def websocket_idle(host, idle, port=TLS_PORT, timeout=None):
    """Open a WebSocket through HAProxy, stay idle for `idle` seconds, then send
    bytes. Returns (status line, echoed bytes or error)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((VM, port), timeout=idle + 15) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.sendall(("GET /ws HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
                       % (host, port)).encode())
            data = b""

            while b"\r\n\r\n" not in data:
                chunk = s.recv(4096)

                if not chunk:
                    break

                data += chunk

            status = data.split(b"\r\n", 1)[0].decode(errors="replace")
            time.sleep(idle)

            try:
                s.sendall(b"ping-after-idle")
                echoed = s.recv(4096)
            except OSError as e:
                return status, "error: %s" % e

            return status, echoed.decode(errors="replace")
