# HAProxy Advanced for OpenWrt

Publish internal web applications (a NAS, an admin panel, Home Assistant, a camera
recorder, …) to the internet through HAProxy on an OpenWrt router: HTTPS with
your certificates or Let's Encrypt, one port for many host names, access rules,
logins, rate limits, and a web interface in LuCI.

Two packages, built from this repository as an OpenWrt feed:

| Package | Contents |
|---|---|
| `haproxy-advanced` | The service: init script, UCI configuration `/etc/config/haproxy-advanced`, and the generator that turns it into an HAProxy configuration. Works without LuCI. |
| `luci-app-haproxy-advanced` | The web interface under **Services → HAProxy Advanced**. |

Target: OpenWrt 25.12 with HAProxy 3.2 (the `haproxy` package with OpenSSL).

## How it fits together

```text
client ── listener (addresses + port, TLS) ──┬─ service nas.example.com ── backend ── servers
                                             ├─ service ha.example.com  ── backend ── servers
                                             └─ service vault.example.com (TLS passthrough)
```

- A **listener** is an entry point: interfaces or addresses and a port. Several
  services share it; HAProxy tells them apart by host name (the `Host` header, and
  SNI for the certificate). Two listeners never share an address and port.
- A **service** publishes one application under one or more host names, with its
  certificate, access rules and login.
- A **backend** is the pool of internal servers behind a service.
- An optional **HTTP companion port** (usually 80) on a TLS listener redirects to
  HTTPS and answers Let's Encrypt's HTTP challenges.

## Features

- HTTPS termination with HTTP/2, one certificate per service, chosen by SNI.
- **TLS passthrough** by SNI on the same port as HTTPS services: the internal server
  keeps its own certificate. HTTPS services behind the same port still see the real
  client address (PROXY protocol on an internal hop).
- **Access policy** per service, in a fixed order:
  1. hardening: ambiguous paths (`//`, `/../`, encoded dots and slashes) are denied;
  2. rate limit and failed-login limit (429);
  3. blocked paths, denied for everyone;
  4. custom rules (allow, deny or login by client network, path and method);
  5. trusted networks: no login, internal-only paths allowed;
  6. internal-only paths, denied for everyone else;
  7. public paths, open without login;
  8. HTTP Basic login of a user group.

  Deny lists compare the URL-decoded, lower-cased path without `;` parameters, so
  `/CGI-BIN/`, `/%63gi-bin/` and `/cgi-bin;x/` are all caught by `/cgi-bin/`.
- Forwarding headers: the client's own `X-Forwarded-*`, `X-Real-IP` and
  `Forwarded` are removed, then `X-Forwarded-For`, `-Proto` and `-Port` are set.
- **ACME**: issue Let's Encrypt certificates for a service from the GUI (HTTP-01
  through the companion port, with the `acme-acmesh` package); HAProxy reloads when
  a certificate is issued or renewed. DNS validation stays in luci-app-acme; its
  certificates can be chosen here.
- **Firewall**: a listener can open its ports in a zone through procd; nothing is
  written to `/etc/config/firewall`, and the rule goes away with the listener.
- **Interfaces that change**: listeners follow their interfaces' addresses (reload
  on `ifup`, `ifdown`, address change) or bind to the interfaces' devices.
- **Safe apply**: every change is generated and checked with `haproxy -c` first. A
  broken configuration never replaces a working one; HAProxy reloads through its
  master socket, which reports whether the new configuration loaded. LuCI shows the
  result of every apply, and a Configuration tab shows the generated file of the
  settings as they are in LuCI, unsaved changes included, with `haproxy -c`'s verdict.
- **Runtime panel**: state, health checks, sessions, request rates and error counts
  per listener, backend and server; put a server in drain or maintenance without a
  reload.
- Passwords are hashed in the browser (SHA-512 crypt); only the hash reaches the
  router.

## Install

Build the packages in an OpenWrt 25.12 buildroot or SDK with this repository as a
feed:

```sh
echo "src-git haproxyadv https://github.com/woffko/luci-app-haproxy-advanced.git" >> feeds.conf
./scripts/feeds update haproxyadv && ./scripts/feeds install -a -p haproxyadv
make package/feeds/haproxyadv/haproxy-advanced/compile \
     package/feeds/haproxyadv/luci-app-haproxy-advanced/compile
```

Or download them from the
[GitHub releases](https://github.com/woffko/luci-app-haproxy-advanced/releases): the
packages are architecture-independent and work on any OpenWrt 25.12 target. They are
not signed with an OpenWrt key, so `apk` needs `--allow-untrusted`.

Copy the two `.apk` files to the router and install them, and the Russian translation
if you want it:

```sh
apk add --allow-untrusted haproxy-advanced-*.apk luci-app-haproxy-advanced-*.apk
apk add --allow-untrusted luci-i18n-haproxy-advanced-ru-*.apk   # optional
```

Then open **Services → HAProxy Advanced → Services → Add service…**.

The `haproxy` package brings its own service, `/etc/init.d/haproxy`, with a sample
configuration that listens on ports 81, 444 and 60000 as root. HAProxy Advanced does
not use it; the Overview tab offers to stop and disable it.

LuCI itself (uhttpd) usually listens on ports 80 and 443 of all addresses. Either
give HAProxy other ports, or move LuCI first (for example to the LAN address only),
or HAProxy cannot listen there; the Overview tab says so when it happens.

### Upgrading from 0.1

Version 0.2 uses a new configuration format and does not convert 0.1
configurations. The service refuses to start on a 0.1 file, and the Overview tab
offers to move it to `/etc/config/haproxy-advanced.v01` and start empty.

## Command line

```sh
/etc/init.d/haproxy-advanced preview   # the configuration that would be generated
/etc/init.d/haproxy-advanced check     # generate and run haproxy -c
/etc/init.d/haproxy-advanced reload    # apply; a failing configuration is not applied
/etc/init.d/haproxy-advanced status    # state and the last apply result (JSON)
/etc/init.d/haproxy-advanced logs      # recent log lines
```

The configuration format is documented in [docs/uci-schema.md](docs/uci-schema.md).

## Security model

- The service's HAProxy workers run as `nobody`; the master process stays root to
  read certificates and reload.
- Anyone who can change this configuration in LuCI is an administrator of the
  router. In particular the "extra lines" fields pass HAProxy directives through
  as they are: they can read any file the master can read. The generator refuses
  lines that would break the file's structure, but that is not a security
  boundary.
- HAProxy checks a login's password hash on every request that carries one. Cheap
  hashes cost little CPU per request; slow ones such as bcrypt cost much more, see
  the measurements in [docs/testing.md](docs/testing.md). The failed-login limit
  (default 10 per minute per client address) keeps guessing from turning that into
  a CPU load.

## Development

Tests, the mutation pass and the VM acceptance are described in
[docs/testing.md](docs/testing.md). Contributions and commit messages are in
English.

## License

MIT, see [LICENSE](LICENSE).
