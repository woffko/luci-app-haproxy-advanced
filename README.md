# LuCI HAProxy Advanced

Generic LuCI application for publishing internal HTTP and HTTPS services through
HAProxy on OpenWrt 25.12.4.

The model is intentionally service-oriented:

```text
Published Service
  -> Frontend binds
  -> Host ACL
  -> Optional authentication
  -> Path ACLs
  -> Ordered actions
  -> Backend pool
  -> Backend servers
```

It is not tied to any NAS vendor. NAS and file sharing rules are available only
as editable presets.

## Features

- Multiple HTTP/HTTPS frontends
- Multiple bind addresses or OpenWrt interface IPv4 aliases such as `wan_ipv4`
- TLS offload with direct HAProxy PEM certificates
- Optional ACME split certificate assembly from `fullchain + key`
- SNI/Host based publishing ACLs
- HTTP and HTTPS backend servers
- Basic Auth userlists
- Ordered allow, deny and auth actions
- Public, protected and blocked path rules
- Source network restrictions
- X-Forwarded-For
- Optional HTTP request rate limiting
- Optional baseline hardening rules
- Generated config preview
- `haproxy -c` validation before apply
- Rollback-safe reload
- Status and logs page

## ACME certificates

HAProxy normally expects a single PEM containing both the certificate chain and
the private key.

Supported patterns:

- Use an existing HAProxy PEM directly in `certificate`.
- Point `certificate` to an OpenWrt `acme-acmesh` `combined.cer`.
- Set `certificate_mode` to `split` and provide `certificate_fullchain` plus
  `certificate_key`; the init script assembles `/var/etc/haproxy-advanced-certs`
  before validation and reload.

For renewals, call:

```sh
/etc/init.d/haproxy-advanced reload
```

## Generic UCI example

The installed default config contains the same generic `ServiceExample` model
with the service disabled by default. Enable the global section and frontend
after setting a valid certificate path and backend address.

