# Proxy behavior and limits

The proxy checks that inspected traffic agrees with what it forwards to the origin. These checks
cover forwarding, identity, uploads and resource use. CRS and format enforcement have separate
modes; see the [operator guide](../README.md#choose-protections).

Source: [proxy](../proxy/proxy.go), [request deadlines](../proxy/deadline.go), [origin
guard](../proxy/origin.go), [CLI](../cmd/carnical/main.go).

## Forwarding and identity

| Check | Behavior |
| --- | --- |
| Request target | Forward the inspected target unchanged; refuse targets Go would re-encode and a raw `#` anywhere in the target. |
| Paths | Refuse ambiguous encoded separators, dot segments, semicolons and unnecessary escapes. A dot segment is judged on the path an application resolves, so `..;` and `..%2F` are refused when path parameters or encoded slashes are allowed. |
| Identity headers | Remove proxy/identity headers, treating underscore and hyphen aliases alike, then rebuild from the verified address. |
| Trusted proxies | Read X-Forwarded-For from the right only for configured peer ranges; a `/0` trust range is refused. |
| Methods | Refuse CONNECT, mixed/lowercase method tokens and method-override headers. |
| Framework controls | Remove `x-middleware-*` and `x-invoke-*` headers. |
| Hostnames | `-hosts` restricts the names a site serves. They are also the only hosts the local rules count as this site's when a parameter holds an address ([input hardening](input-hardening.md)); the rule set takes at most 4,096 of them, and the proxy does not start with more. |
| Origin addresses | Check the actual address at dial time; private, loopback, link-local, metadata (including Azure's 168.63.129.16) and local-host destinations need an explicit operator allowance where supported. |
| Trailers/upgrades | Drop trailers; refuse protocol upgrades by default. Explicitly allowed upgrades (`-allow-upgrade`) are uninspected; each tunnel holds an upstream place and counts against its address's connection limit until it closes. |
| Origin framing | Body-bearing requests use separate origin connections; interim 1xx responses are dropped before final response inspection. |

## Bodies and evaluation

A request takes an upstream slot after its body has been read, so a stalled upload cannot occupy
that pool. A prematurely ended or malformed body returns 400/413 rather than an empty 200.

| Setting | Default/behavior |
| --- | --- |
| `-eval-budget` | 2s per evaluation phase. Exceeding it refuses with 503 in block mode; in detect mode the request goes on with that phase's remaining rules unread. Either is logged as rule 5000045, at most once a second. Slow body reads do not consume this budget. Negative values are refused. |
| `-max-evaluations` | Bounds simultaneous evaluations, including response body rules run when an inspected response reaches its body limit. A phase that finds no slot within the budget is refused with 503 and logged as rule 5000046, at most once a second. |
| `-max-form-body` | 128 KiB for non-upload bodies; the proxy enforces this independently of the engine. Negative values are refused. |
| `-join-repeated-params` | On. A name given more than once in the URL or in a form or multipart body is also read by the rules as one value joined with commas, the cookies of that name last, so an injection split over the values is seen whole ([input hardening](input-hardening.md#repeated-parameters)). |
| Request compression | Refused unless bounded format decoding is explicitly enabled, and refused if no inspector decoded it. Final decoded bytes and uploads are checked again. |
| Response compression | With `-inspect-responses` the visitor's `Accept-Encoding` is not forwarded: the proxy asks the origin for gzip and decompresses it, so the response rules read plain text and visitors receive uncompressed responses. A response the origin compresses in any other coding is refused with 502. `Range` and `If-Range` are not forwarded either: a range is a slice no rule sees whole, and several are `multipart/byteranges`, which the rules do not read, so the origin sends the whole response and a visitor that asked for a range gets it all (`200`), as HTTP allows. |
| Uploads | Refuse script extensions anywhere in filenames and PHP/ASP/JSP markers. This is not a malware scanner. A body the rules read as multipart is refused with 400 (rule 5000005) unless its `Content-Type` follows the grammar and PHP finds the same boundary in it. |
| Dangerous rule features | `@inspectFile`, `exec`, `setenv`, `@rbl` and `@geoLookup` are replaced by compile-time refusals in `crs/refuse.go`. |

Keep limits suited to the application. Historical evaluation measurements found about 6ms CPU per
KiB for one plain-text workload, with 300 KiB taking 1.8s on one core. A 5ms evaluation budget
reduced that measured request to 48ms. These are workload-specific measurements, not latency
guarantees.

`-wordpress` adds upload/cache script restrictions, disables XML-RPC and limits login attempts. Its paths
are matched as PHP routes them, ignoring empty segments, a trailing slash, path info and path parameters.
Login attempts, `-api-per-minute` and `-max-conns-per-ip` count an IPv6 /64 as one address, as the flood
protection does.

The login limit and `-api-per-minute` are rate rules with a table of clients each, so one cannot use up
the other's room. Each client has a sliding window of ten slots of six seconds: while the table holds a
client, no minute holds more requests from it than its limit, and a client is held back at most one slot
(six seconds) longer than an exact log of its requests would hold it. A request that matches both rules
goes on only if both have room, and a refused request is counted by neither. A refusal is `429` with
`Cache-Control: no-store` and a `Retry-After` that is the exact number of seconds, rounded up, until the
request would be admitted.
A table holds at most 50,000 clients. When it is full, the client admitted least recently makes room for
a new one, so whoever fills a table locks no other network out; an idle client goes first, and when a
client still inside its window has to go, rule 5000041 says so, at most once every ten seconds with how
many such evictions were not logged. A dropped client comes back with a fresh window, and no client is
ever refused for what its neighbours sent: a source able to fill a table already has more addresses than
the table holds (one IPv6 /48 is 65,536 clients), each with a budget of its own, so the per-client limits
do not bound what a whole network sends; the network budgets of `-ddos` do. Refusals (5000022 for
logins, 5000042 for API quotas) are logged at most once a second per rule, and the next line logged says
how many refusals were not.

A program that embeds the proxy can add its own rate rules in `proxy.Config.Limits`, read from text by
`proxy.ParseRateRules`. A rule is `[METHODS] PATHS COUNT/WINDOW [monitor]`, and rules are separated by
`;`, as in `POST /login,/register 10/m; /api 600/m; GET /search 30/10s monitor`:

- METHODS is `*` or methods separated by commas, in any case. GET also counts HEAD; with no methods or
  `*` every method counts. A method is letters only, at most 16 of them, so a hyphenated method such as
  VERSION-CONTROL cannot be named (leave the methods out to count it). A method that is not GET, HEAD,
  POST, PUT, PATCH, DELETE or OPTIONS but is one or two edits from one of them is refused as a
  misspelling; other names, such as WebDAV's MKCOL, are accepted.
- PATHS are plain path prefixes separated by commas, matched as the `-api-per-minute` paths are: by
  path segment, without ASCII case, after removing empty segments, a trailing slash and `;`
  parameters. `/api` counts `/api` and `/api/orders` but not `/apiary`; `/` counts every path. A path
  also counts itself with a format suffix of letters and digits, which Rails routes to the same action:
  `/login` counts `/login.json` and `/login.xml`, but not a script such as `/login.php`. It also
  counts itself as the path info after a PHP script in the first segment, which a front controller
  routes the same way: `/login` counts `/index.php/login` (Laravel, Symfony, Drupal, WordPress) and
  `/app.php/login` (older Symfony), but not `/index.php` or `/login.php`, for `-api-rate-paths` too.
  A script deeper in the path, as in `/blog/index.php/login`, is not looked through. Routing that the
  query chooses, such as WordPress's `?rest_route=/wp/v2/users`, is not seen; a rule for `/` or for
  the script (`/index.php`) counts it.
- COUNT is 1 to 1,000,000, optionally with `k` for thousands (`3k`). WINDOW is `s`, `m` or `h` with an
  optional whole multiplier (`10s`, `5m`), from 1s to 1h.
- `monitor` makes a rule report, as rule 5000048 ("rate limit would be exceeded: ..."), a request it
  would refuse, and let it through. It counts the requests that the enforcing rules let through,
  exactly as it would if it enforced. It goes after the rate: `monitor` anywhere before it is refused
  rather than taken as a method name.

There are at most 32 rules, 16 paths in a rule and 100 in all, the text is at most 4 KiB, also when
written out in full (`1k/h` is written `1000/1h`), and a rule written twice is refused. An error names
the rule by its number and text and says what is wrong, with a suggestion for a likely misspelling, as
in `-limit rule 1 ("PSOT /login 5/m"): "PSOT" is not an HTTP method (did you mean POST?)`. `proxy.New` checks rules built without `ParseRateRules` the same way and
keeps its own copy.

Each rule has its own table of clients and its own budget, counted after the login and API limits, with
the same window, eviction and `Retry-After` as they have. A request goes on only if every enforcing rule
it matches has room, and is then counted by all of them; one that a rule refuses is counted by none.
A refusal is logged as rule 5000047 with the rule's text ("rate limit exceeded: POST /login 5/1m"),
which comes from the configuration and never from the request. The rules apply whatever the `-ddos`
mode, and with the flood protection off.

Responses get `nosniff`, lose software banners and prevent caching when they set cookies or serve
HTML from a stylesheet address. Connection limits and a 100-stream HTTP/2 cap bound transport work.

## Monitoring

Default match events contain the rule ID, severity, transaction ID and a fixed summary. The event
uses `msg`; rule text uses `rule_msg`. `-log-details` may include client address, URI, matched data,
expanded CRS text and inspector panic details. Treat it as sensitive logging.

Format totals are process-local blocked/monitored findings. The default `-formats-stats-interval 1m`
logs changed snapshots; `0` disables reporting, and graceful shutdown flushes a final changed
snapshot. See [format monitoring](formats.md#monitoring-and-logs). Login limits use 5000022, API quotas
5000042, other rate rules 5000047 (5000048 for a monitor rule), a full rate-limit table 5000041 and
inspector failures 5000040.

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
