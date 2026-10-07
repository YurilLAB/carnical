# Put Carnical in front of a website

Carnical is a reverse proxy for one origin per process. Start with a reviewed site
file, test through the edge before changing DNS, and then hand the client the
edge addresses. The client does not need to install Coraza or change application
code. Separate sites with different origins need separate instances; the CLI
does not provide a hosted multi-tenant control plane.

## Operator: prepare one site file

Build the binary from `carnical/`:

```sh
CGO_ENABLED=0 go build -trimpath -o carnical ./cmd/carnical
cp docs/examples/site-local.json site.json
./carnical -config site.json -check
./carnical -config site.json -check -check-origin
./carnical -config site.json
```

The local example protects an application on `127.0.0.1:8081`, listens on
`127.0.0.1:8080`, and starts with CRS detection and format monitoring. Proxy
safety checks and flood mitigation still enforce. Visit the edge's port, exercise
normal application flows and read the structured logs. After tuning, enable both
content blocking layers:

```sh
./carnical -config site.json -mode block -formats-mode block
```

For a public site, copy [site-edge.json](examples/site-edge.json) and replace
the example hostnames and certificate paths. Keep the origin address separate
from the visitor hostname: pointing the upstream at `example.com` after its DNS
moves to the edge can create a proxy loop. Use `https://origin.example.com`
with a certificate valid for that name, or a private origin address explicitly
approved by the operator. `upstream-host` controls the HTTP Host header; it does
not change the upstream TLS certificate name. TLS verification stays enabled.

The file has an exact `version: 1` and a `flags` object using the names from
`-h` without dashes. Strings and durations are JSON strings, booleans are JSON
booleans, and numeric flags are JSON numbers. Integers must fit the flag's type.
Unknown fields, duplicate names (including escaped aliases), nulls, wrong types,
trailing documents and files over 64 KiB are refused. Only regular files are
accepted; the configuration path itself must not be a symlink.

Explicit command-line flags override file values, including `-flag=false`.
Omitted settings retain the CLI defaults. `config`, `check`, `check-origin`,
`check-origin-http` and `version` are command-line actions and cannot appear inside `flags`.
Existing direct flag invocations remain supported.

Site files are **operator-owned configuration**. They can grant access to private
origins, trust proxy identities and relax inspection. Do not accept a client's
raw JSON as a deployment policy. Review requested changes and use the authenticated
[policy/control libraries](config-and-policy.md) when building a customer portal.
Keep the file and its parent directory unwritable by the service user or clients.
Use absolute paths for production files; relative paths are resolved from the
process working directory, not the JSON directory.

## Operator: authenticate the WAF to the origin

Use HTTPS with mutual TLS for a remote origin. The edge verifies the origin's
server certificate; the origin requires and authorizes the edge's client
certificate. This authenticates the proxy connection. Website users still use
the application's login and authorization.

Provision these files through the deployment's certificate authority:

- An origin server certificate valid for `origin.example.com`.
- A dedicated **per-site client CA**, with its signing key kept offline.
- A currently valid edge certificate with `clientAuth` extended key usage and
  its matching private key. Give each edge its own certificate.

Install the client pair on the edge and add these site-file flags:

```json
"origin-client-cert": "/etc/carnical/origin/edge.crt",
"origin-client-key": "/etc/carnical/origin/edge.key"
```

If the origin uses a private server CA, also set `origin-ca-file` to that CA's
PEM trust bundle. This replaces the system trust store for this origin; it does
not disable certificate or hostname verification. Without the flag, system
roots are used. All three settings require an HTTPS upstream. Client cert/key
must be provided together; invalid, expired, future-dated, mismatched and
non-client-authentication identities fail startup. Certificate/CA files are
bounded to 1 MiB and the key to 64 KiB. Files must be regular files, with no
symlink at the supplied path.

On Unix, use key permissions `0600`, or `0640` with a dedicated read-only edge
group. World access and group write access are refused. On Windows, restrict the
key's ACL to the service account and administrators; the CLI's Unix mode check
does not validate Windows ACLs. Keep the files and parent directories under
operator control.

For an NGINX origin, adapt [origin-mtls.conf](../deploy/nginx/origin-mtls.conf)
in its `http` context. Replace the names, paths and
`REPLACE_WITH_APPROVED_CERTIFICATE_SERIAL` with the serial from:

```sh
openssl x509 -in edge.crt -noout -serial
```

Use the value after `serial=`. The template requires a verified certificate
from the site's CA **and** an approved serial, the expected TLS SNI and an
approved HTTP Host. Add an allowlist entry for each authorized edge certificate.
For this NGINX template, set `upstream-host` to `origin.example.com` so HTTP
Host matches TLS SNI. NGINX can refuse mismatched names when client verification
is enabled. The template sets the application's HTTP Host to `example.com`
after authenticating ingress; adapt that fixed value to the application.
The placeholder denies access until replaced. Authorization uses TLS variables,
so visitor headers cannot supply an identity. The application behind NGINX must
listen only on loopback or a private network restricted to this ingress.

Run `nginx -t` and reload the reviewed configuration. Close every alternate
public HTTP/HTTPS port, virtual host and direct application route; also restrict
origin network access to approved ingress peers. Confirm directly that no
certificate, another site's certificate, and an unapproved certificate from
the same CA cannot reach the application. Then check the edge:

```sh
./carnical -config /etc/carnical/site.json -check -check-origin -check-origin-http
```

This explicit probe sends `HEAD /` with the configured HTTP Host and edge TLS
identity. It accepts 2xx/3xx responses, follows no redirects, uses no visitor
cookies or credentials, and bounds response headers to 32 KiB within the
ten-second origin-check budget. A 401/403 fails the check. Select an origin where
`HEAD /` is allowed. A successful probe shows that this identity was accepted;
the direct negative checks above establish that other identities are refused.

Certificates are loaded on startup. Monitor expiry, issue replacements, update
the origin's approved serials, validate the new files and restart the edge.
Remove retired identities at the origin and drain/restart its existing workers
and connections when revocation must take effect. The template disables TLS
session resumption and early data and bounds connection reuse, but replacing
a certificate does not revoke an already established connection instantly.

The CLI does not expose a customer provisioning or management-login endpoint.
Integrators building one must use the [control API's authentication and tenant
authorization](control-api.md), including verified client certificates, signed
requests and replay protection, and validate domain ownership before accepting
an origin. Do not replace those checks with public request headers.

## Operator: check, install and test

`-check` loads the selected settings, compiles the rules, validates inspectors
and reads local certificates and other configured files. It exits with a nonzero
status on an error. It neither binds a port, consumes a systemd listening
descriptor nor applies process confinement. It checks confinement port syntax and
CrowdSec configuration, but does not authenticate with CrowdSec or prove kernel
sandbox support. Normal startup still performs those checks.

`-check -check-origin` additionally checks all resolved origin addresses against
the origin policy, connects with the serving dial-time address check, and verifies
the TLS handshake for HTTPS. The DNS/connect/handshake budget is ten seconds.
It sends no HTTP request or application credentials and follows no redirect.
When configured, it presents the edge client certificate during TLS. TLS 1.3
client-authentication refusal may appear only on a later read; use the explicit
HTTP probe above to check application acceptance.
This proves connection reachability and certificate trust, **not** application
routing, website health, available capacity or protection against every attack.
The probe runs before confinement; actual confined forwarding must also be tested.

For the hardened Linux service, follow the [host installation order](../deploy/README.md).
Install the reviewed file as `/etc/carnical/site.json`, readable by the edge group,
and use this `/etc/carnical/edge.env` value:

```text
CARNICAL_ARGS="-config /etc/carnical/site.json"
```

The shipped service checks the same settings in `ExecStartPre` before serving.
It preserves the existing unprivileged socket activation, upload directory and
confinement. The socket template uses one IPv6 listener with
`BindIPv6Only=both`, allowing IPv4 and IPv6 while passing the single descriptor
the CLI requires. On an IPv4-only host, use a socket drop-in:

```ini
[Socket]
ListenStream=
ListenStream=0.0.0.0:443
```

Match origin ports and addresses in **all** enforcement layers: the site
`origin-allow`, `confine-connect` and the host network policy. Public HTTPS
origins fit the default port policy; private origins require deliberate changes
to the host policy too. Configure `trusted-proxies` only for the actual CDN or
load-balancer peers. With direct visitors, leave it empty. The CLI reads TLS
certificates at startup: arrange renewal with the existing certificate provider,
check the new pair and restart the service to load it.

Before DNS cutover, test the real hostname and certificate against each edge IP:

```sh
curl --resolve example.com:443:EDGE_IPV4 https://example.com/
curl --resolve www.example.com:443:EDGE_IPV4 https://www.example.com/
```

Replace `EDGE_IPV4` with the assigned address. Keep certificate verification
enabled. Test the IPv6 route separately if it will be advertised. Exercise login,
cookies, redirects, uploads, checkout and supported APIs through the edge, then
a controlled blocked request in staging with both content layers enabled. Verify
that refused traffic did not reach the origin. Review format and rule logs for
legitimate requests before enforcing the production site. A successful `-check`
does not replace these live tests.

## Client: DNS cutover and handover

The operator should provide this short handover:

| Item | Client/operator agreement |
| --- | --- |
| Protected names | Exact apex, www and other hostnames included in the site's host allowlist and certificate. |
| DNS records | Assigned edge IPv4 addresses for A records and tested IPv6 addresses for AAAA records, or the operator's supported DNS target. |
| Origin | Stable origin address and expected HTTP Host, retained separately from public website DNS. |
| TLS | Who renews the edge and origin certificates and how renewal is monitored. |
| Cutover | Time window, observed DNS TTL, live application checks and who monitors errors. |
| Rollback | Recorded previous ingress/DNS settings and an approved origin access policy for that path. |
| Support | Operator contact and where to report blocked legitimate requests. |

Lower the affected records' TTL in advance and wait out their previous TTL.
Change **every** advertised A and AAAA route for the protected names; a leftover
direct-origin record provides a route around the WAF. Check authoritative DNS
and representative clients after the change. Monitor application errors, blocked
legitimate requests and the running service while caches drain.

Restrict the origin to approved ingress peers, or bind a local origin to loopback.
DNS alone does not stop someone connecting directly to a public origin IP.
Include the previous approved ingress in the planned rollback policy where
appropriate. For rollback, restore the recorded ingress/DNS configuration and
verify it serves the site; do not disable WAF checks or origin restrictions as a
routine shortcut.

After acceptance, save the reviewed site file and effective command-line
overrides, record a baseline traffic rate for flood tuning, and document
certificate renewal and the rollback procedure. Configuration changes take
effect on restart; live configuration reload is not provided by this CLI.

References: the Go [flag package](https://pkg.go.dev/flag) defines the registered
flag types and boolean override syntax; systemd's
[socket reference source](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
defines `BindIPv6Only=both` and descriptor activation.
