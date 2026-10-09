<img src="../docs/assets/carnival-logo.png" align="left" height="46px" alt="Carnical logo"/>

# Carnical operator guide

Carnical is a Go reverse proxy built on Coraza and OWASP CRS. It checks requests before forwarding
them to one origin per process. This guide covers the standalone proxy; the
[documentation index](docs/README.md) also covers integration libraries and validation records.

## Run it

Once the binary is installed on Windows or Linux, `carnical setup` collects and validates the
site settings. It asks before saving, encrypts private origin details and credential paths,
and prints the commands to check and start the WAF. See [setup](docs/setup.md) for the key
file, service accounts and backups. The wizard uses existing certificates; it does not change DNS.


From this directory, with an application on `127.0.0.1:8081`:

```sh
cp docs/examples/site-local.json site.json
go run ./cmd/carnical -config site.json -check
go run ./cmd/carnical -config site.json -check -check-origin
go run ./cmd/carnical -config site.json
```

Use patched Go 1.26.9 or later on that release branch, or Go 1.27.2 or later on the 1.27 branch.
The workspace selects Go 1.26.9. The example listens on `127.0.0.1:8080` with CRS detection,
format monitoring and flood protection enabled. Review the logs and tune legitimate traffic,
then enable both content-blocking layers:

```sh
go run ./cmd/carnical -config site.json -mode block -formats-mode block
go run ./cmd/carnical -h
go run ./cmd/carnical -version
```

For a public site, follow [website setup](docs/website-onboarding.md) before changing DNS.
It covers the site file, certificates, origin authentication, live checks and rollback.
[Availability and deployment](docs/availability-and-deployment.md) covers replicas, private probes,
shutdown, containers and platform support.

## Choose protections

| Setting | Default | What to review |
| --- | --- | --- |
| `-mode` | `detect` | CRS and supplemental rule findings. Use `block` after tuning exclusions. |
| `-formats-mode` | `monitor` | Strict JSON, XML/SOAP, GraphQL, form, multipart, NDJSON and text checks. Use `block` to enforce. |
| `-formats-policy` | No file | Per-site format limits and rule actions; the CLI mode overrides the policy's monitor setting. |
| `-allow-request-encoding` | Disabled | Opt into one bounded gzip/deflate layer; the origin receives the decoded bytes. |
| `-api-spec` | No file | Supported OpenAPI contracts. Blocking requires `-formats-mode block`. |
| `-api-per-minute` | Disabled | One sliding-minute budget per verified client across the selected API routes. |
| `-ddos` | `on` | Flood detection, connection/request budgets and bounded IDS signals. |
| `-crowdsec-api` | Disabled | Optional CrowdSec IP/CIDR bans, enforced independently of inspection modes. |
| `-trusted-proxies` | Empty | Only actual CDN/load-balancer peers may supply client identity headers. |
| `-origin-allow` | No private-range exception | Explicitly permit only required private origin ranges. |

Proxy safety checks and baseline flood limits still apply in detection/monitor modes.
Format inspection cannot be disabled while a format policy or request decoding is configured.
See [request formats](docs/formats.md), [API contracts](docs/input-hardening.md),
[flood protection](docs/ddos.md) and [CrowdSec](docs/crowdsec.md) for exact limits and outcomes.

## What the proxy adds around Coraza

The proxy checks that inspected traffic and forwarded traffic agree. It validates request targets,
framing, client identity and origin addresses; removes unsafe forwarding/framework headers;
checks uploads; and bounds body size, rule evaluation and upstream concurrency.
Default finding logs omit request content. Detailed logging is an explicit opt-in.

The [proxy reference](docs/proxy-reference.md) lists these checks, rule identities and operational
limits. [Host hardening](docs/hardening.md) and [network protection](docs/network-protection.md)
describe the optional Linux layers. Signed policy, control and virtual-patch services require
[library integration](docs/README.md#build-an-integration).

## Known limits

- Request inspection does not establish application authorization or safe use of data at an application sink.
- Upload checks detect executable names and script markers; they are not a general malware scanner.
- WebSocket inspection and schema-aware gRPC/Protobuf inspection are not provided.
- Linux packet guards need a separate deployment. Provider-side protection is needed when a flood saturates the network link.
- Quotas, flood state and caches are per process. Plan [replica state and capacity](docs/availability-and-deployment.md#state-and-replica-contracts).
- Keep body and evaluation limits appropriate to the site; hostile large bodies can consume substantial CPU.

For measured admissions, false positives and test boundaries, use the
[validation index](docs/README.md#review-the-evidence) and [security review](../docs/security-findings.md).
Historical load-test rates describe those runs, not the current build's overall protection rate.

## Versions

The engine baseline is Coraza v3.8.1 (`foundation`); Carnical development uses `edge-crs`.
The embedded CRS is 4.30.0. Its release signing key is
`3600 6F0E 0BA1 6783 2158 8211 38EE ACA1 AB8A 6E72`.
`crs/provenance.json` records the archive, signature and embedded-file hashes; tests check the files.

## Updating the CRS

```sh
GPG=$(command -v gpg) go run ./tools/update-crs -version 4.31.0
go test ./crs
```

The updater accepts GitHub HTTPS downloads signed by the pinned key, uses a temporary keyring,
and extracts only expected regular files. Failed validation leaves the embedded copy unchanged.

## Changes to upstream files

The workspace uses the local engine and a separate Carnical module. The module keeps its existing
`github.com/YurilLAB/coraza/carnical` import path for compatibility with the repository rename.
See [engine changes](../docs/engine-integration.md#changes-in-this-fork) and
[reviewed fixes](../docs/security-findings.md) for context, sources and validation.

## Licence

Coraza and CRS use Apache-2.0; the CRS licence is retained in `crs/owasp_crs/LICENSE`.
The licence for additions in `carnical/` has not yet been decided.
