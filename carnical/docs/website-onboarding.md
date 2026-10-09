# Put Carnical in front of a website

Prepare the site, authenticate its origin, test through the edge, then change DNS. Clients do not
install the WAF or change application code. Each process forwards to one origin; sites with
different origins need separate instances.

Operator: [site file](#operator-prepare-one-site-file), [origin
authentication](#operator-authenticate-the-waf-to-the-origin), [live
checks](#operator-check-install-and-test). Client: [DNS handover](#client-dns-cutover-and-handover).
Source: [site configuration](../cmd/carnical/siteconfig.go), [origin TLS](../proxy/origin_tls.go).

## Operator: prepare one site file

With an installed binary, run `carnical setup` on Windows or Linux and answer its prompts.
It validates the settings before asking to save, encrypts private origin details and credential
paths, and prints the check/start commands. Follow the [setup guide](setup.md) when running
under another account or transferring the configuration. Existing JSON site files still work.


From `carnical/`, build and try the local example:

```sh
CGO_ENABLED=0 go build -trimpath -o carnical ./cmd/carnical
cp docs/examples/site-local.json site.json
./carnical -config site.json -check
./carnical -config site.json -check -check-origin
./carnical -config site.json
```

It protects `127.0.0.1:8081` on `127.0.0.1:8080`, with CRS detection and format monitoring. Proxy
safety checks and flood limits still enforce. Exercise normal application flows and review the logs
before enabling both content-blocking layers:

```sh
./carnical -config site.json -mode block -formats-mode block
```

For a public site, copy [site-edge.json](examples/site-edge.json) and replace its names and file
paths. Keep the origin DNS/address separate from the visitor hostname to avoid a proxy loop after
cutover. An HTTPS origin needs a certificate valid for its upstream name. `upstream-host` sets HTTP
Host; it does not change the TLS certificate name.

| Site-file rule | Requirement |
| --- | --- |
| Structure | Exact `version: 1` and a `flags` object, with an optional encrypted `private` section; names match `-h` without leading dashes. |
| Values | Strings/durations are strings, booleans are booleans, numbers must fit their flag type. |
| Parsing | Unknown/duplicate names, escaped aliases, nulls, wrong types and trailing documents are refused. |
| File | Regular file, at most 64 KiB; the supplied path must not be a symlink. |
| Precedence | Explicit CLI flags override file values, including `-flag=false`; omissions keep defaults. |
| CLI-only actions | `config`, `config-key-file`, `check`, `check-origin`, `check-origin-http`, `probe` and `version` cannot appear in `flags`. |

Site files are operator-owned policy: they can relax inspection or grant private-origin/proxy trust.
Review client requests instead of accepting raw client JSON as deployment configuration. Keep files
and parent directories unwritable by clients/service users. Use absolute production paths; relative
paths resolve from the process working directory. Customer portals need the [authenticated
policy/control integration](control-api.md).

## Operator: authenticate the WAF to the origin

Use mutual TLS for a remote HTTPS origin. The edge verifies the origin server certificate; the
origin verifies and authorizes the edge client identity. Application users still need their normal
login and authorization.

1. Issue an origin certificate for its upstream hostname.
2. Use a dedicated per-site client CA with its signing key offline.
3. Give each edge a valid `clientAuth` certificate and matching private key.
4. Install the client pair and configure:

```json
"origin-client-cert": "/etc/carnical/origin/edge.crt",
"origin-client-key": "/etc/carnical/origin/edge.key"
```

Set `origin-ca-file` for a private server issuer. It replaces the origin's system root store without
disabling hostname/certificate checks. All three options require HTTPS; cert/key must be supplied
together. Invalid, expired, future-dated, mismatched or unsuitable identities fail startup.

Certificates/CA bundles are capped at 1 MiB and keys at 64 KiB. Files must be regular with no
symlink at the supplied path. Unix keys may use 0600, or 0640 with a dedicated read-only group;
world access and group write are refused. On Windows, enforce service/admin access with ACLs; the
Unix mode check does not validate them. Keep parent directories under operator control.

For NGINX, adapt [origin-mtls.conf](../deploy/nginx/origin-mtls.conf) in the `http` context. Replace
names, paths and the approved certificate serial using:

```sh
openssl x509 -in edge.crt -noout -serial
```

Use the value after `serial=` and authorize each edge separately. The template requires a verified
site-CA certificate, approved serial, expected SNI and approved HTTP Host. Set `upstream-host` to
`origin.example.com` for that template. It then sets the application's Host to `example.com`; adapt
that fixed value to the application. The placeholder denies access. TLS variables establish
identity, so visitor headers cannot supply it.

Run `nginx -t` and reload. Restrict origin access to approved ingress peers and close alternate
public ports, virtual hosts and direct application routes. Keep the application behind NGINX on
loopback or a restricted private network.

Test both outcomes:

- No certificate, another site's certificate and an unapproved same-CA certificate must not reach the application.
- The configured edge identity must pass this explicit acceptance check:

```sh
./carnical -config /etc/carnical/site.json -check -check-origin -check-origin-http
```

The HTTP probe sends `HEAD /` with configured Host and TLS identity. It accepts 2xx/3xx without
following redirects, sends no visitor credentials, and limits response headers to 32 KiB within the
ten-second check budget. A 401/403 fails. Choose an origin that permits `HEAD /`.

Certificates load at startup. Monitor expiry, approve replacement serials, validate files and
restart the edge. Remove retired identities and drain/restart origin workers/connections when
revocation must take effect. The template disables TLS resumption/early data and bounds reuse;
certificate replacement does not instantly revoke an established connection.

The CLI has no provisioning/login endpoint. A hosted management service needs [control
authentication](control-api.md), replay/tenant checks and verified domain ownership.

## Operator: check, install and test

| Check | What it establishes |
| --- | --- |
| `-check` | Load effective settings, compile rules/inspectors and validate configured local files. No bind, socket consumption or confinement is performed. |
| `-check -check-origin` | Check resolved addresses against origin policy, connect using the dial-time guard, and verify HTTPS trust within ten seconds. No HTTP request or redirects. |
| `-check -check-origin -check-origin-http` | Also test `HEAD /` acceptance with configured origin identity. |

`-check` validates confinement port syntax and CrowdSec settings, but does not authenticate to
CrowdSec or prove kernel support. Normal startup performs those checks. TLS 1.3 client-auth refusal
may appear only on a later read, so use the HTTP probe to check acceptance. These checks run before
confinement; test real confined forwarding separately.

For Linux installation, follow the [deployment order](../deploy/README.md). Install the reviewed
site file at `/etc/carnical/site.json`, root-owned and readable by the edge group, and set:

```text
CARNICAL_ARGS="-config /etc/carnical/site.json"
```

The service validates the same settings in `ExecStartPre` and retains unprivileged socket
activation, private uploads and confinement. The socket's IPv6 listener uses `BindIPv6Only=both`. On
a host without IPv6, use this drop-in and rerun the zone/listener checks:

```ini
[Socket]
ListenStream=
ListenStream=0.0.0.0:443
```

Match origin addresses/ports across `origin-allow`, `confine-connect` and the host policy. Private
origins need explicit host-policy changes too. Leave `trusted-proxies` empty for direct visitors;
otherwise name only real CDN/load-balancer peers. Renew visitor certificates through the certificate
provider, validate the new pair and restart to load it.

Before cutover, test the real hostname/certificate against every edge IP:

```sh
curl --resolve example.com:443:EDGE_IPV4 https://example.com/
curl --resolve www.example.com:443:EDGE_IPV4 https://www.example.com/
```

Replace `EDGE_IPV4` and keep certificate verification enabled. Test IPv6 separately before
advertising it. Exercise login, cookies, redirects, uploads, checkout and APIs, then a controlled
staging refusal with both content layers enabled. Confirm refused requests never reached the origin.
Review legitimate-traffic logs before enforcing production policy.

## Client: DNS cutover and handover

The operator should provide:

| Item | Agreement |
| --- | --- |
| Names | Exact apex, www and other names covered by the host allowlist/certificate. |
| DNS | Edge IPv4 A records and tested IPv6 AAAA records, or the supported DNS target. |
| Origin | Separate stable origin address and expected HTTP Host. |
| TLS | Renewal owner and expiry monitoring for edge/origin certificates. |
| Cutover | Time window, DNS TTL, application checks and error monitoring owner. |
| Rollback | Previous ingress/DNS settings and an approved access policy for that route. |
| Support | Contact for blocked legitimate requests. |

Lower TTL in advance and wait out the previous TTL. Update every advertised A/AAAA route; a leftover
direct-origin record provides a route around the WAF. Check authoritative DNS and representative
clients, then monitor errors and legitimate refusals while caches drain.

Restrict the origin to approved ingress or loopback. DNS alone does not prevent direct-origin
access. For rollback, restore the recorded ingress/DNS path and verify it serves the site with its
approved access policy.

After acceptance, save the site file/CLI overrides, normal traffic baseline, renewal procedure and
rollback plan. Configuration changes require restart; the CLI does not provide live reload.

References: [Go flag syntax](https://pkg.go.dev/flag), [systemd socket
activation](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml).
