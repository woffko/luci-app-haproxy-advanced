#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test backends of the goal A acceptance, run on the Ubuntu VM.

  19080  HTTP echo: answers JSON with the method, path, headers, body length and
         the client's address and port
  19443  the same echo over TLS (certificate backend.pem, test CA)
  19444  the same echo over TLS with the passthrough certificate (pt.hatest.example)
  19081  WebSocket echo: answers 101 to an Upgrade, then echoes every byte

Started and stopped by tools/accept.py; runs in the foreground of a nohup.
"""

import base64
import hashlib
import json
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DIR = sys.argv[1] if len(sys.argv) > 1 else "."


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        out = json.dumps({
            "server": self.server.label,
            "method": self.command,
            "path": self.path,
            "headers": [[k, v] for k, v in self.headers.items()],
            "body_length": len(body),
            "client": list(self.client_address)
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = handle_any


def serve_http(port, label, cert=None):
    srv = ThreadingHTTPServer(("0.0.0.0", port), Echo)
    srv.label = label

    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain("%s/%s.pem" % (DIR, cert))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)

    threading.Thread(target=srv.serve_forever, daemon=True).start()


GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_client(conn):
    try:
        data = b""

        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)

            if not chunk:
                return

            data += chunk

        head, rest = data.split(b"\r\n\r\n", 1)
        key = ""

        for line in head.decode(errors="replace").split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()

        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                      "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n" % accept).encode())

        if rest:
            conn.sendall(rest)

        while True:
            chunk = conn.recv(4096)

            if not chunk:
                return

            conn.sendall(chunk)
    except OSError:
        pass
    finally:
        conn.close()


def serve_ws(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(16)

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=ws_client, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


serve_http(19080, "http")
serve_http(19443, "https", "backend")
serve_http(19444, "passthrough", "passthrough")
serve_ws(19081)
print("ready", flush=True)
threading.Event().wait()
