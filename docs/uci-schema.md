# UCI schema of `/etc/config/haproxy-advanced` (0.2)

This file describes every section type and option the generator reads. The generator
lives in `haproxy-advanced/files/ucode/` and turns this configuration into
`/var/etc/haproxy-advanced.cfg`.

Conventions:

- Sections that other sections refer to (`listener`, `backend`, `service`,
  `auth_group`) are **named** sections; the section name is the reference. UCI names
  allow `A-Z a-z 0-9 _`.
- `server`, `user` and `rule` are anonymous sections that point at their owner with
  an option.
- Multi-values are UCI `list` options. A plain `option` with one value is accepted
  where a list is expected.
- *time* is a number with an optional unit: `ms`, `s`, `m`, `h` or `d` (`10s`, `1h`).
- Options left empty take the documented default. "Inherit" means the value of the
  `global` section applies.

0.1 sections (`frontend`, `bind`, `acl`, `action`, `userlist`) are not read. When
the generator finds one, it refuses to start the service and says why; the GUI
offers to move the old file to `/etc/config/haproxy-advanced.v01`.

## `config global 'global'`

| Option | Values | Default | Meaning |
|---|---|---|---|
| `enabled` | 0/1 | 0 | Run the service. |
| `maxconn` | integer | 2000 | Process-wide connection limit. |
| `log_level` | `emerg` … `debug` | `info` | Syslog level of HAProxy's messages. |
| `log_requests` | `all`, `errors`, `none` | `errors` | Which requests are logged. |
| `hardening` | 0/1 | 1 | Default of each service's `hardening`. |
| `timeout_connect` | time | `5s` | Connect timeout to servers. |
| `timeout_client` | time | `60s` | Client inactivity timeout. |
| `timeout_server` | time | `60s` | Server inactivity timeout. |
| `timeout_http_request` | time | `10s` | Time a client has to send complete request headers. |
| `timeout_http_keep_alive` | time | `10s` | Idle time between two requests on a kept-alive connection. |
| `acme_challenge_port` | port | 18402 | Local port of acme.sh's standalone HTTP-01 server; companion listeners route `/.well-known/acme-challenge/` there. |
| `advanced` | text | | Extra lines for HAProxy's `global` section (root-equivalent, see README). |

## `config listener '<name>'`

A listener is one entry point: a set of addresses and a port. Services attach to it.
Two listeners never share an address and port.

| Option | Values | Default | Meaning |
|---|---|---|---|
| `enabled` | 0/1 | 1 | |
| `address` | list of interface names, IPv4 or IPv6 addresses, or `*` | `*` | Where to listen. An interface name means its current addresses of the chosen `family`; the service reloads when the interface changes. |
| `family` | `ipv4`, `ipv6`, `any` | `ipv4` | Address family used for interface names and `*`. |
| `bind_mode` | `address`, `device` | `address` | `device` listens on any address but only on the interfaces' network devices (`bind … interface <dev>`), so an address change needs no reload. Needs interface names in `address`. |
| `port` | port | — | Required. |
| `tls` | 0/1 | 1 | Terminate TLS (or pass it through, see `service.mode`). |
| `http2` | 0/1 | 1 | Offer HTTP/2 through ALPN (TLS only). |
| `default_certificate` | path | | Certificate for clients without a matching SNI. Default: the first service's certificate. |
| `redirect_port` | port | | Plain-HTTP companion on the same addresses: answers ACME HTTP-01 challenges, redirects known hosts to HTTPS (308), and answers 404 to everything else. |
| `firewall` | 0/1 | 0 | Accept the listener's ports (and `redirect_port`) from `firewall_zone`, through procd service data for fw4. |
| `firewall_zone` | fw4 zone | `wan` | |
| `timeout_client` | time | inherit | |
| `advanced` | text | | Extra lines for the listener's frontend. |

## `config service '<name>'`

| Option | Values | Default | Meaning |
|---|---|---|---|
| `enabled` | 0/1 | 1 | |
| `listener` | listener name | — | Required. |
| `hostname` | list of host names | — | Required. Exact, case-insensitive names; unique per listener. |
| `mode` | `http`, `passthrough` | `http` | `passthrough` forwards the TLS connection to the backend by SNI without decrypting it. |
| `backend` | backend name | — | Required. |
| `certificate` | path | | PEM with chain and key (HTTP mode on TLS listeners). If `<path>.key` exists HAProxy also loads it. |
| `acme_cert` | name of a `cert` section of `/etc/config/acme` | | Use `/etc/ssl/acme/<first domain>.combined.crt`; overrides `certificate`. |
| `trusted_network` | list of IPv4/IPv6 networks | | Clients that bypass path rules and login. For passthrough: the only allowed clients. |
| `blocked_path` | list of path prefixes | | Denied (403) for everyone, trusted networks included. |
| `internal_path` | list of path prefixes | | Denied (403) except for trusted networks. |
| `public_path` | list of path prefixes | | Allowed without login. |
| `auth_group` | auth_group name | | Require HTTP Basic login of a user of this group. |
| `rate_limit` | integer | 0 | Requests per 10 s per client address; 0 = off. Over the limit: 429. |
| `auth_fail_limit` | integer | 10 | Failed logins per minute per client address before 429; 0 = off. |
| `conn_rate_limit` | integer | 0 | Passthrough: new connections per 10 s per client address; 0 = off. |
| `hardening` | empty, 0, 1 | inherit | See "Hardening" below. |
| `forward_headers` | 0/1 | 1 | Send `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Port`. |
| `hsts` | 0/1 | 0 | Send `Strict-Transport-Security` (TLS listeners). |
| `hsts_max_age` | integer | 31536000 | |
| `hsts_subdomains` | 0/1 | 0 | Add `includeSubDomains`. |
| `timeout_client` | time | inherit | |
| `request_header` | list of `Name: value` | | Headers set on requests to the backend; an empty value (`Name:`) removes the header. |
| `advanced` | text | | Extra `http-request` or `http-response` rules without a condition; the generator limits them to this service. |

Path prefixes are decoded paths (`/my files/` is written as it reads, not
`%20`-encoded), start with `/`, and may not contain `//`, `/./` or `/../`.

### Access policy order

For a request whose `Host` matches the service:

1. hardening: ambiguous paths are denied (400);
2. `rate_limit` and `auth_fail_limit` (429);
3. `blocked_path` (403), for everyone;
4. the service's `rule` sections, by `order`;
5. `trusted_network`: allowed;
6. `internal_path` (403) for everyone else;
7. `public_path`: allowed without login;
8. login, when `auth_group` is set;
9. the backend.

Blocked and internal-only prefixes are compared case-insensitively against the
URL-decoded path with `;` path parameters removed, so `/CGI-BIN/`, `/%63gi-bin/` and
`/cgi-bin;x/` all match `/cgi-bin/`. Public prefixes are compared case-sensitively
against the decoded path. Ambiguous paths (`//`, `/./`, `/../`, a trailing `/.` or
`/..`, a backslash or `%00`, also when encoded) are always denied for services that
have path lists, and for every service with hardening on.

### Hardening

On by default (`global.hardening`). For the service it:

- denies ambiguous paths (see above);
- removes the client's own `X-Forwarded-For`, `X-Forwarded-Host`,
  `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Real-IP` and `Forwarded` headers
  before `forward_headers` adds its own; without hardening, `X-Forwarded-For` is
  appended to what the client sent.

`timeout http-request` (`global.timeout_http_request`) applies to every service.

## `config rule`

Custom rules of one service, evaluated after blocked paths and before trusted
networks. A rule matches when all of its non-empty criteria match.

| Option | Values | Default | Meaning |
|---|---|---|---|
| `service` | service name | — | Required. |
| `enabled` | 0/1 | 1 | |
| `order` | integer | 100 | Lower runs first; ties keep file order. |
| `action` | `allow`, `deny`, `auth` | — | `allow` ends the policy and goes to the backend; `auth` asks for a login. |
| `source` | list of networks | | |
| `path` | list of path prefixes | | Compared like `blocked_path` for `deny` and `auth`, like `public_path` for `allow`. |
| `method` | list of HTTP methods | | |
| `deny_status` | 400, 401, 403, 404, 405, 429, 500, 503 | 403 | |
| `auth_group` | auth_group name | the service's | For `auth`. |

## `config backend '<name>'`

| Option | Values | Default | Meaning |
|---|---|---|---|
| `balance` | `roundrobin`, `leastconn`, `source`, `first` | `roundrobin` | |
| `health_check` | `none`, `tcp`, `http` | `none` | |
| `check_method` | `GET`, `HEAD`, `OPTIONS` | `GET` | HTTP checks. |
| `check_path` | path with optional query | `/` | |
| `check_host` | host name | | `Host` header of HTTP checks. |
| `check_status` | list of codes (`200`) or classes (`2xx`) | `2xx`, `3xx` | Accepted answers. |
| `check_interval` | time | `10s` | |
| `timeout_connect` | time | inherit | |
| `timeout_server` | time | inherit | |
| `timeout_tunnel` | time | | Idle timeout of WebSocket and passthrough connections. |
| `advanced` | text | | Extra lines for the backend. |

A backend is used either by HTTP services or by passthrough services, not both.

## `config server`

| Option | Values | Default | Meaning |
|---|---|---|---|
| `backend` | backend name | — | Required. |
| `name` | name | — | Required, unique within the backend. |
| `enabled` | 0/1 | 1 | |
| `address` | IPv4, IPv6 or host name | — | A host name is resolved when HAProxy starts. |
| `port` | port | — | |
| `tls` | 0/1 | 0 | Connect with TLS (HTTP backends). |
| `verify` | `none`, `required` | `none` | Certificate verification. |
| `ca_file` | path or `@system-ca` | | Required with `verify required`. |
| `sni` | empty, `host`, or a host name | | SNI to send: `host` sends the request's host. |
| `verifyhost` | host name | | Name the certificate must carry. |
| `weight` | 0–256 | | |
| `backup` | 0/1 | 0 | Used only when all others are down. |
| `maxconn` | integer | | |
| `send_proxy` | 0/1 | 0 | Send a PROXY v2 header (the server must expect it). |

## `config auth_group '<name>'` and `config user`

| Option | Section | Values | Default | Meaning |
|---|---|---|---|---|
| `realm` | auth_group | text | `Restricted` | Shown in the browser's login prompt. |
| `group` | user | auth_group name | — | Required. |
| `username` | user | name | — | Unique within the group. |
| `password_hash` | user | crypt hash | — | `$6$` (SHA-512, made by the GUI), `$5$`, `$1$`, `$2a$`/`$2b$`/`$2y$`. |
| `enabled` | user | 0/1 | 1 | |

HAProxy checks the hash on every request that carries a login, so the hash's cost is
paid per request; see the README for measured numbers.
