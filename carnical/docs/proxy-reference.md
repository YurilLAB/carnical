# Proxy behavior and limits

The proxy checks that inspected traffic agrees with what it forwards to the origin. These checks
cover forwarding, identity, uploads and resource use. CRS and format enforcement have separate
modes; see the [operator guide](../README.md#choose-protections).

Source: [proxy](../proxy/proxy.go), [request deadlines](../proxy/deadline.go), [origin
guard](../proxy/origin.go), [CLI](../cmd/carnical/main.go).

## Forwarding and identity

| Check | Behavior |
| --- | --- |
| Request target | Forward the inspected target unchanged; refuse targets Go would re-encode. |
| Paths | Refuse ambiguous encoded separators, dot segments, semicolons and unnecessary escapes. |
| Identity headers | Remove proxy/identity headers, treating underscore and hyphen aliases alike, then rebuild from the verified address. |
| Trusted proxies | Read X-Forwarded-For from the right only for configured peer ranges; a `/0` trust range is refused. |
| Methods | Refuse CONNECT, mixed/lowercase method tokens and method-override headers. |
| Framework controls | Remove `x-middleware-*` and `x-invoke-*` headers. |
| Hostnames | `-hosts` restricts the names a site serves. |
| Origin addresses | Check the actual address at dial time; private, loopback, link-local, metadata (including Azure's 168.63.129.16) and local-host destinations need an explicit operator allowance where supported. |
| Trailers/upgrades | Drop trailers; refuse protocol upgrades by default. Explicitly allowed upgrades are uninspected. |
| Origin framing | Body-bearing requests use separate origin connections; interim 1xx responses are dropped before final response inspection. |

## Bodies and evaluation

A request takes an upstream slot after its body has been read, so a stalled upload cannot occupy
that pool. A prematurely ended or malformed body returns 400/413 rather than an empty 200.

| Setting | Default/behavior |
| --- | --- |
| `-eval-budget` | 2s per evaluation phase; exceeding it refuses with 503. Slow body reads do not consume this budget. Negative values are refused. |
| `-max-evaluations` | Bounds simultaneous evaluations, including response body rules run when an inspected response reaches its body limit. |
| `-max-form-body` | 128 KiB for non-upload bodies; the proxy enforces this independently of the engine. |
| Request compression | Refused unless bounded format decoding is explicitly enabled, and refused if no inspector decoded it. Final decoded bytes and uploads are checked again. |
| Uploads | Refuse script extensions anywhere in filenames and PHP/ASP/JSP markers. This is not a malware scanner. |
| Dangerous rule features | `@inspectFile`, `exec`, `setenv`, `@rbl` and `@geoLookup` are replaced by compile-time refusals in `crs/refuse.go`. |

Keep limits suited to the application. Historical evaluation measurements found about 6ms CPU per
KiB for one plain-text workload, with 300 KiB taking 1.8s on one core. A 5ms evaluation budget
reduced that measured request to 48ms. These are workload-specific measurements, not latency
guarantees.

`-wordpress` adds upload/cache script restrictions, disables XML-RPC and limits login attempts. Its paths
are matched as PHP routes them, ignoring empty segments, a trailing slash, path info and path parameters.
Login attempts, `-api-per-minute` and `-max-conns-per-ip` count an IPv6 /64 as one address, as the flood
protection does.
Responses get `nosniff`, lose software banners and prevent caching when they set cookies or serve
HTML from a stylesheet address. Connection limits and a 100-stream HTTP/2 cap bound transport work.

## Monitoring

Default match events contain the rule ID, severity, transaction ID and a fixed summary. The event
uses `msg`; rule text uses `rule_msg`. `-log-details` may include client address, URI, matched data,
expanded CRS text and inspector panic details. Treat it as sensitive logging.

Format totals are process-local blocked/monitored findings. The default `-formats-stats-interval 1m`
logs changed snapshots; `0` disables reporting, and graceful shutdown flushes a final changed
snapshot. See [format monitoring](formats.md#monitoring-and-logs). API quotas use 5000042,
rate-state exhaustion 5000041 and inspector failures 5000040.

See [attack coverage](attacks.md) and [security findings](../../docs/security-findings.md) for
application-dependent limits and verified fixes.

Supplemental injection rules inspect arguments, XML text/attributes and cookies. SQL appearing
only in URL path segments is outside those argument-focused checks; use application-specific
path/input constraints where needed.

## Historical paranoia-level comparison

Historical paranoia-level comparison on the initial 715-request corpus (468 deliberately tricky
benign requests, 247 attacks), measured before the later format and supplemental-rule improvements.
These are reference results, not current protection rates:

| Level | Benign requests wrongly blocked | Attacks detected |
|---|---|---|
| 1 (default) | 2.4% | 82.6% |
| 2 | 8.3% | 86.2% |
| 3 | 13.7% | 83.8% (measured before upload bodies were replayed correctly, so a little low) |
| 4 | 35.3% | 85.0% (same) |

Level 1 is right for a new site; level 2 only after the site's exclusions are tuned. Levels 3 and 4
block too much ordinary traffic to use without heavy tuning.
