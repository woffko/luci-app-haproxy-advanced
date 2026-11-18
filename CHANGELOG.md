# Changelog

## 0.2.0 (2026-11-18)

A rewrite. 0.1 configurations are not converted: the service refuses to start on
one, and the GUI offers to move it to `/etc/config/haproxy-advanced.v01`.

### Changed

- Two packages: `haproxy-advanced` (the service) and `luci-app-haproxy-advanced`
  (the GUI), plus `luci-i18n-haproxy-advanced-ru`.
- New configuration model: listeners shared by services, routed by host name
  (`docs/uci-schema.md`). The generator is written in ucode.
- Every apply is checked with `haproxy -c`; a failing configuration keeps the running
  one. HAProxy reloads through its master socket, and the result of every apply is
  shown in LuCI.
- The GUI has tabs for services, listeners, backends, users, certificates, settings,
  the generated configuration and an overview with a runtime panel. "Add service"
  replaces the wizard.

### Added

- TLS passthrough by SNI beside HTTPS services on the same port.
- HTTP companion port: redirect to HTTPS, ACME HTTP-01 challenges.
- ACME certificates issued from the GUI through the acme package; reload on
  `acme.issue` and `acme.renew`.
- HTTP/2, IPv6 listeners, binding to interface devices, reload on interface changes.
- Firewall rules published through procd.
- Custom rules (allow, deny, login by network, path and method), HSTS, extra request
  headers, per-service and per-backend timeouts, HTTP health checks, server weights,
  backups, connection limits and PROXY v2.
- Failed-login limit; passwords hashed (SHA-512 crypt) in the browser.
- Runtime panel: server state, sessions, rates and errors; drain and maintenance.
- Preview of the configuration of unsaved LuCI changes, with `haproxy -c`.
- Russian translation.

### Fixed

- The hardening rule denied every HTTP/1 request with `Content-Length: 0`.
- Two services on one port bound twice and split connections at random.
- Listeners did not follow interface address changes and did not start when an
  interface had no address yet.
- The wizard's default names collided with the example configuration.
- Host matching failed when the Host header carried a port.
- Blocked and protected paths could be bypassed with case, `//`, `/../`, `;` or
  percent-encoding.
- A service could not turn hardening off when the global default was on.
- Clients could spoof `X-Forwarded-For`.
- The luci-app's postinst did not reload rpcd, so the menu stayed hidden until a
  restart.
- `timeout tunnel` was written into frontends, where HAProxy ignores it.
- `verify required` without a CA failed with HAProxy's message only.
- Value checks let spaces and `#` through.

## 0.1.0

First version (2026-06-06).
