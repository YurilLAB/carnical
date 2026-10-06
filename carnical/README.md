<img src="../docs/assets/carnival-logo.png" align="left" height="46px" alt="Carnical logo"/>

# Carnical: a Web Application Firewall built on Coraza

Carnical is an independent web application firewall written in Go, built on [OWASP Coraza](https://github.com/corazawaf/coraza)
and the OWASP Core Rule Set (CRS). It runs as a reverse proxy between clients and protected applications, inspecting
HTTP traffic before forwarding it. Its protections include API and body validation, flood mitigation, virtual patches,
configurable policies and monitoring, alongside targeted hardening fixes to the Coraza engine.

Transport protections reserve connection capacity before TLS or HTTP processing, keep live subnet counts through address
churn, and enforce a global cap across listeners and trusted proxies. See [flood protection](docs/ddos.md) for tuning and limits.
The optional [Linux deployment policy](docs/network-protection.md) adds SYN budgets before connection tracking, malformed-packet
filtering, bounded flood counters and echo limits that preserve IPv6 discovery. Small and large deployment profiles provide
finite budgets for ordinary sources and configured high-volume proxy peers; connection caps also respect small hosts' file limits.

`carnical/` is its own Go module (`github.com/YurilLAB/coraza/carnical`), keeping the application additions separate
from the Coraza engine. See the [repository overview](../README.md) and [current security findings](../docs/security-findings.md).

| Folder | What it is |
|---|---|
| `crs/` | The CRS embedded in the binary, with proof of where it came from, and typed settings (mode, paranoia level, thresholds, body limit, allowed methods, exclusions) turned into the directives that configure it. |
| `proxy/` | A reverse proxy: every request goes through Coraza and the CRS, clean ones are forwarded to one upstream. |
| `cmd/carnical/` | The program: `carnical -upstream http://127.0.0.1:8081 -mode block`. |
| `tools/update-crs/` | Fetches a CRS release, checks its GPG signature against the CRS project's pinned key, and replaces the embedded copy. |
| `audit/`, `cmd/carnical-audit/` | The segmentation checks: the walls between zones and between customers, run a few times a day. `carnical-audit -zones zones.json`. |
| `docs/backend-integration.md` | Backend and web UI integration requirements. |
| `docs/segmentation.md` | Zones, who may talk to whom, how customers are kept apart, and the checks and their schedule. Read this next. |
| `sandbox/`, `cmd/carnical-confine/` | The proxy confining itself from the inside (Landlock, seccomp, no new privileges), and a probe that tries 34 forbidden actions from inside it. |
| `audit/host/` | Checks of the machine itself: kernel settings, mounts, services' sandboxes, network and audit rules, listeners, processes, integrity, setuid files, whether the running edge is confined. |
| `deploy/` | systemd units, nftables policy by user, sysctls, module blacklist, audit rules, users and directories, honeytokens, and the order to install them in. |
| `docs/hardening.md` | What stops an attacker who is already on the machine as a service user, what would show it, what was verified and what was not. |
| `docs/attacks.md` | Modern web attacks researched, what Carnical does about each, what the rule set already covers, and what no proxy can stop. |
| `docs/backend-compat.md` | The contracts the existing backend expects (feed, events, policy, updates, advice) and the defects in it that matter for hosting. |
| `apiguard/` | Per-site API schema enforcement, discovery, learning and rate-limit integration; see [API protection](docs/apiguard.md). |
| `config/`, `policy/`, `control/` | Signed configuration, validated customer policy, authenticated control API and compatible feed; see [configuration and policy](docs/config-and-policy.md) and [control API](docs/control-api.md). |
| `shield/` | Flood protection, on by default: connection admission, per-address and per-network limits, detection of attacks spread over many addresses and countries, and mitigation that keeps regular visitors working; see [flood protection](docs/ddos.md). |
| `vpatch/`, `cmd/carnical-sigs/`, `cmd/carnical-vpatch/` | Bounded virtual-patch matching, rule importers and offline pack/corpus tools; see [virtual patches](docs/vpatch.md). External rule libraries are supplied separately. |

## Versions

- Coraza: v3.8.1 (branch `foundation` is the pinned upstream tag; Carnical development uses `edge-crs`).
- OWASP CRS: 4.30.0, release signed by key `3600 6F0E 0BA1 6783 2158 8211 38EE ACA1 AB8A 6E72`. `crs/provenance.json` holds the
  archive hash, the signature hash and the hash of every embedded file; a test fails if any file differs.

## Run it

```
go run ./cmd/carnical -upstream http://127.0.0.1:8081 -listen :8080            # detect: log what the rules find, block nothing
go run ./cmd/carnical -upstream http://127.0.0.1:8081 -mode block              # block at the anomaly threshold
go run ./cmd/carnical -version                                                  # which CRS is embedded
```

Start every new site in `detect`, read the log for a few days, add exclusions for what is wrongly flagged, then switch to `block`.
Options: `-paranoia 1..4`, `-inbound-threshold`, `-max-body`, `-allowed-methods`, `-inspect-responses`, `-trusted-proxies`,
`-tls-cert`/`-tls-key`, `-upstream-host`, `-max-upstream`, `-log-details`. Run `-h` for all of them.

Local injection rules also run at PL1 with the selected CRS mode and threshold. Use `-local-rules=false` to omit them.
`-api-spec site-api.json` optionally installs an explicit OpenAPI input contract; enforcement requires
`-formats-mode block`. See [input hardening](docs/input-hardening.md) for rule IDs, supported contracts and destination restrictions.

The executable enables request-format findings in monitor mode by default. Use `-formats-mode block` to enforce strict JSON, XML/SOAP, GraphQL, forms, multipart, NDJSON and text checks independently of CRS mode. `-formats-policy formats.json` loads validated per-site limits and rule actions before listening; the file must be regular and at most 1 MiB. The CLI mode overrides the policy's `monitor` field. `-allow-request-encoding` enables one bounded gzip or deflate layer; the origin and CRS receive the decompressed bytes with corrected framing. `-formats-mode off` cannot be combined with a policy file or compression opt-in. See [format policy](docs/formats.md) and [validation evidence](docs/enterprise-validation.md).

```
go run ./cmd/carnical -upstream http://127.0.0.1:8081 -mode block -formats-mode block -allow-request-encoding
```

API rate limits are opt-in: `-api-per-minute 120` gives each verified client address one shared sliding-minute budget across `/api` and `/graphql`. `-api-rate-paths /api,/internal/orders` changes the path prefixes; `/` covers every route. Prefixes match whole path segments and conservatively include case, slash and matrix-parameter variants, while the forwarded target stays unchanged. Every method counts, before body reading and rule evaluation. An exceeded quota returns 429, rule 5000042, `Retry-After: 60` and `Cache-Control: no-store`; exhausted state returns 503 and rule 5000041. Login and API budgets are separate. State is local to one process, capped at 50,000 active identities and 200,000 admitted events across both protections, and expires after one minute. Restarting resets it; a deployment with several edges needs shared enforcement upstream for a fleet-wide quota. Configure `-trusted-proxies` only for the actual proxy peers; visitor-supplied identity headers cannot rotate a direct client's budget.

Paranoia levels on the 715-request corpus from the earlier research (468 deliberately tricky benign requests, 247 attacks):

| Level | Benign requests wrongly blocked | Attacks detected |
|---|---|---|
| 1 (default) | 2.4% | 82.6% |
| 2 | 8.3% | 86.2% |
| 3 | 13.7% | 83.8% (measured before upload bodies were replayed correctly, so a little low) |
| 4 | 35.3% | 85.0% (same) |

Level 1 is right for a new site; level 2 only after the site's exclusions are tuned. Levels 3 and 4 block too much ordinary traffic
to use without heavy tuning.

## What the proxy adds around Coraza

The proxy addresses cases where the traffic inspected by the firewall could differ from what the application receives.

- The request target is forwarded exactly as it was inspected; one Go would re-encode (such as `/a%2fb|`) is refused.
- Proxy and identity headers are removed with `_` and `-` treated alike (`X_Original_URL` is `X-Original-URL` to PHP, CGI and IIS), and rebuilt from the verified client address.
- Trailers are not forwarded, protocol upgrades (WebSocket, h2c) are refused, and `CONNECT` is refused.
- A request takes an upstream place only after its body has been read, so a stalled upload cannot use them up.
- The visitor's address comes from `X-Forwarded-For` only when the connection is from a trusted proxy, read from the right; a `/0` trusted range is refused.
- A customer's origin is not trusted: connections to loopback, private, link-local and cloud-metadata addresses, and to this machine's own addresses, are refused at the moment they are made, on the address actually used (`-origin-allow` names ranges an operator permits).
- Rule evaluation is bounded. The rules cost about 6 ms of CPU per KiB of request body (measured: 300 KiB of plain text takes 1.8 s on one core, almost all of it in Go's regular-expression matcher), so a few large requests could use every core. Each phase of evaluation has a budget (`-eval-budget`, 2 s; over it the request is refused with 503, measured at 48 ms against 1.8 s for a 5 ms budget), no more than `-max-evaluations` run at once, and a body that is not a file upload may be at most `-max-form-body` (128 KiB; the engine does not enforce its own no-files limit). Reading a slow client's body does not count against the budget.
- When the engine returns without answering (a malformed chunk, a body that ended early), the visitor gets 400 or 413 and not the empty 200 that net/http would send.
- Rules that run programs or change the process environment (`@inspectFile`, `exec`, `setenv`, `@rbl`, `@geoLookup`) are replaced with versions that refuse to compile (`crs/refuse.go`).
- Protections that do not depend on the rule set, so they hold in detection mode and with the rules off (details, evidence and what a proxy cannot stop are in `docs/attacks.md`): a request path that needs interpreting is refused (encoded slashes, dot segments, `;`, unnecessary escapes); mixed/lowercase method tokens and method-override headers are refused; other framework control headers (`x-middleware-*`, `x-invoke-*`) are removed; `-hosts` limits the names a site answers to; compressed request bodies are refused unless explicitly enabled for bounded format inspection; a request with a body never shares its connection to the application with the next request; interim `1xx` responses are dropped so response inspection sees the real response; file uploads are refused if a name has a script extension anywhere in it or the content holds a PHP, ASP or JSP opening tag; `-wordpress` stops scripts being run from upload and cache directories, switches `xmlrpc.php` off and limits login attempts; responses get `nosniff`, lose software banners, and are not cacheable if they set a cookie or are HTML at a stylesheet's address; connections per address are capped and HTTP/2 is limited to 100 streams.
- Rule matches are logged with the rule's ID, severity and fixed summary. The JSON event uses `msg` and rule text uses `rule_msg`, avoiding duplicate keys. CRS macro-expanded messages and inspector panic details may contain credentials; they appear only as `expanded_msg` with `-log-details`, alongside client address, URI and matched data. Default CRS summaries use the rule ID for lookup rather than an expanded description.

Format bypass findings have process-local per-rule blocked/monitored totals. `-formats-stats-interval 1m` is the default; `0` disables summary logging. Only changed snapshots are logged, with a final snapshot during graceful shutdown. `Inspector.Stats()` provides the same bounded counters for integrations. These count emitted findings and reset with a new inspector. See [format monitoring](docs/formats.md#monitoring-and-logs). API quota findings use 5000042; inspector failures retain 5000040.

## Known limits

The [2026-10-06 live load report](docs/loadtest-2026-10-06.md) records 500,000 mixed requests through the standalone executable,
including per-case origin admissions, detection gaps and false positives. Its harness is `tools/loadtest/`.

The [750,000-request extended run](docs/loadtest-750k-2026-10-06.md) retains that workload and adds LDAP, XPath, NoSQL,
SSI, parameter pollution and prototype pollution. Its [admitted-attack inventory](docs/loadtest-750k-admitted-2026-10-06.md)
groups all 67 admitted templates by category. Use the harness's `-extended` flag to reproduce this suite.

The [750,000-request variant run](docs/loadtest-750k-variants-2026-10-06.md) adds syntax and encoding variants across all
22 attack categories, exercising 3,849 distinct attack requests and 1,778 distinct benign requests. Its
[admitted-variant inventory](docs/loadtest-750k-variants-admitted-2026-10-06.md) groups every admission by category and
variation. Use `-variants` for this suite and its even attack/benign request split.

- The CRS has no rule for XML external entities, and Coraza's XML processor hands rules the text pieces of an element separately, so a keyword split by an empty CDATA section is not seen whole.
- Uploaded file contents, trailers (dropped, so never forwarded) and SQL in a URL path segment are not inspected; CRS is generic and does not carry CVE-specific virtual patches for WordPress plugins.
- A body of hostile input costs CPU in proportion to its size (several seconds for 1 MiB of adversarial text). Keep `-max-body` as small as the site allows.
- Developing on Windows: run the tests under WSL or Linux. Coraza's own suite has Windows-only failures, and one of them (`normalisePath`, fixed in this fork) silently disabled the CRS's OS-file rule on Windows.

## Updating the CRS

```
GPG=$(command -v gpg) go run ./tools/update-crs -version 4.31.0
go test ./crs
```

The tool downloads over https from github.com only, refuses anything whose signature is not from the pinned key (checked with a
throwaway keyring, not yours), extracts only expected regular files, and writes nothing if any check fails.

## Changes to upstream files

- `go.work`: one line adding `./carnical`, and a `toolchain` line so the workspace builds with a Go release that has the standard-library fixes (go1.26.4 had seven that affect a proxy: HTTP/2 cleartext check, quadratic URL path resolution, XML recursion; `govulncheck ./...` reports none on go1.26.6).
- `internal/corazawaf/rulegroup.go`, `rule.go`, `transaction.go`: rule evaluation stops when the transaction's context is done, and a blocking engine refuses the transaction (503). Nothing in the engine looked at the context before, so a request that was expensive to inspect could not be cut short. The proxy gives each evaluation phase a budget through it (`proxy/deadline.go`). A test in `rulegroup_test.go` covers the three cases.
- `internal/transformations/normalise_path.go`: `path.Clean` instead of `filepath.Clean`, so the transformation gives the same result on every OS.

## Licence

Coraza and the CRS are Apache-2.0 (the CRS licence is kept in `crs/owasp_crs/LICENSE`). The licence for additions in `carnical/` is not
decided yet.
