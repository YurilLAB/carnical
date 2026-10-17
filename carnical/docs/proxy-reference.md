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
that pool. A body over its limit is refused with 413 (rule 5000074), and one that cannot be read
(a malformed chunk, a body that ends early) with 400 (rule 5000075). Should the rule engine still
leave a request unanswered, it is refused with 400 (rule 5000077) rather than given an empty 200.

A client has 30 seconds to send a whole request (10 for its headers), and a response must be
finished 120 seconds after the end of the request's headers. A body still arriving at 30 seconds is
answered with 408 Request Timeout, which the flood protection does not count as a security
rejection and which is counted (`Edge.SlowBodies`, rule 5000076) but not logged; a longer response
is cut. `-read-timeout` and `-write-timeout` set them (in a program
that embeds the proxy, `proxy.Config.ReadTimeout` and `WriteTimeout`), the read timeout up to 23
hours and the write timeout up to 24, so that a write timeout longer than the read timeout can
always be given; 0 is the default and a negative value is refused, and the flags also refuse a
value under a second, which would cut off nearly every client: raise them for large uploads over slow connections,
Server-Sent Events or large downloads, as in `-read-timeout 5m` or `-write-timeout 1h`. The write
timeout also runs while the body is arriving, so it must be longer than the read timeout, and one
that is not is refused (`-write-timeout (1m0s) must be longer than -read-timeout (2m0s), ...`):
otherwise an upload could reach the application and its client get no answer. Left at zero, the
write timeout is the read timeout plus 90 seconds, so raising only the read timeout is enough for
slow uploads.

The application has 30 seconds to start its response, its status and headers; one that takes longer
is answered with 502 and logged as rule 5000050 (`upstream request timed out`). `-upstream-timeout`
sets it (`proxy.Config.ResponseHeaderTimeout`), from a second (on the flag) up to 24 hours, with 0 for the default. Long polling,
where the application holds a request until it has something to say, needs it raised along with the
write timeout, as in `-upstream-timeout 5m -write-timeout 6m`: one that is not shorter than the write
timeout is refused (`-upstream-timeout (5m0s) must be shorter than -write-timeout (2m0s), ...`), as
an answer that comes later could no longer reach the client. The default of 30 seconds counts too: a
`-write-timeout` of 30 seconds or less needs a shorter `-upstream-timeout` given with it, or it is
refused (`-write-timeout (20s) must be longer than -upstream-timeout (30s, its default), ...`).

| Setting | Default/behavior |
| --- | --- |
| `-eval-budget` | 2s per evaluation phase. Exceeding it refuses with 503 in block mode; in detect mode the request goes on with that phase's remaining rules unread. Either is logged as rule 5000045, at most once a second. Slow body reads do not consume this budget. Negative values are refused. |
| `-max-evaluations` | Bounds simultaneous evaluations, including response body rules run when an inspected response reaches its body limit. A phase that finds no slot within the budget is refused with 503 and logged as rule 5000046, at most once a second. |
| `-max-form-body` | 128 KiB for non-upload bodies; the proxy enforces this independently of the engine. A multipart body may be as large as `-max-body`, but everything in it other than the content of its files (fields, part headers, names, file names and boundaries) is held to this limit, as ModSecurity's `SecRequestBodyNoFilesLimit` holds it, and refused with 413 as rule 5000012 when over it; so is a multipart body over it that cannot be read to its end as parts. Negative values are refused. |
| `-join-repeated-params` | On. A name given more than once in the URL or in a form or multipart body is also read by the rules as one value joined with commas, the cookies of that name last, so an injection split over the values is seen whole ([input hardening](input-hardening.md#repeated-parameters)). |
| Request compression | Refused unless bounded format decoding is explicitly enabled, and refused if no inspector decoded it. Final decoded bytes and uploads are checked again. |
| Response compression | With `-inspect-responses` the visitor's `Accept-Encoding` is not forwarded: the proxy asks the origin for gzip and decompresses it, so the response rules read plain text and visitors receive uncompressed responses. A response the origin compresses in any other coding is refused with 502. `Range` and `If-Range` are not forwarded either: a range is a slice no rule sees whole, and several are `multipart/byteranges`, which the rules do not read, so the origin sends the whole response and a visitor that asked for a range gets it all (`200`), as HTTP allows. |
| Uploads | Refuse script extensions anywhere in filenames and PHP/ASP/JSP markers. This is not a malware scanner. A body the rules read as multipart is refused with 400 (rule 5000005) unless its `Content-Type` follows the grammar and PHP finds the same boundary in it, and so is one with a part that Go and the rules take for a file and PHP for a field, or the other way round: one named as a file only by `filename*` (which RFC 7578 forbids in form data and PHP ignores), one whose `filename` PHP does not read, such as `filename ="a.txt"`, or one whose `Content-Disposition` only PHP reads, such as one with a repeated parameter. An empty file input (`filename=""`) is a field to Go and the rules and an empty upload to PHP, which discards its content; it passes, and its content counts toward the form limit. |
| Dangerous rule features | `@inspectFile`, `exec`, `setenv`, `@rbl` and `@geoLookup` are replaced by compile-time refusals in `crs/refuse.go`, and so are the `drop` and `redirect` actions, which the HTTP middleware would answer with an empty 200. Any interruption that still reaches the middleware as something other than a deny with an error status is answered with 403. |

Keep limits suited to the application. Historical evaluation measurements found about 6ms CPU per
KiB for one plain-text workload, with 300 KiB taking 1.8s on one core. A 5ms evaluation budget
reduced that measured request to 48ms. These are workload-specific measurements, not latency
guarantees.

`-wordpress` adds upload/cache script restrictions, disables XML-RPC and limits login attempts. Its paths
are matched as PHP routes them, ignoring empty segments, a trailing slash, path info and path parameters.
`wp-login.php` and `xmlrpc.php` are matched in any directory, so a site installed under `/blog/` is covered
as well; the upload/cache restrictions cover `/wp-content/` at the root only.
Login attempts, `-api-per-minute` and `-max-conns-per-ip` count an IPv6 /64 as one address, as the flood
protection does. A connection `-max-conns-per-ip` refuses is closed at once and logged as rule 5000030, at
most once a second with how many refusals were not logged; the address is in the line only with
`-log-details`.

Responses get `nosniff`, lose software banners and prevent caching when they set cookies or serve
HTML from a stylesheet address. Connection limits and a 100-stream HTTP/2 cap bound transport work.

## Rate rules

`-limit` limits how often one client may make the requests a rule matches. Each client is an IPv4
address or an IPv6 /64, the verified one behind `-trusted-proxies`. A rule is
`[METHODS] PATHS COUNT/WINDOW [monitor]`; give several separated by `;` or as repeated flags:

```sh
carnical -upstream http://127.0.0.1:8081 -limit 'POST /login 5/m'
carnical -upstream http://127.0.0.1:8081 -limit 'POST /login,/register 10/m; /api 600/m'
carnical -upstream http://127.0.0.1:8081 -limit 'GET /search 30/10s monitor' -limit '* / 3k/m'
```

In a site file it is one JSON string, `"limit": "POST /login 5/m; /api 600/m"`. `-limit` on the
command line replaces the site file's rules as a whole, as every flag replaces its site value, and the
start-up log says `site configuration limit replaced by the command line`. The start-up log, and
`-check`, list every rate rule that applies, normalized and in the order they are applied, with where
it comes from, as in `"rate_limits":["POST */wp-login.php 10/1m (-wordpress)","POST /login 5/1m (flag)","GET /search 30/10s monitor (flag)"]`;
the `-limit` rules all come from the command line (`flag`) or all from the site file (`site configuration`).
`-api-per-minute` and the login limit of `-wordpress` are rate rules too, listed as `(-api-per-minute)`
and `(-wordpress)`, or `(-policy)` when a local policy switches the WordPress protections on. Their
flags are checked at start-up: `-login-per-minute` is 1 to 100,000 (default 10), `-api-per-minute` 0 (off)
or 1 to 100,000, and `-api-rate-paths` (default `/api,/graphql`) up to 100 plain path prefixes, an
error naming the one at fault, as in `-api-rate-paths: "/v1/" has a trailing slash; write /v1`. The log
warns when `-login-per-minute` is given without `-wordpress`, or `-api-rate-paths` with
`-api-per-minute 0`, as neither then changes anything. A program that embeds the proxy sets the rules in `proxy.Config.Limits`, read from
text by `proxy.ParseRateRules`; a signed or local policy cannot add or remove them.

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
written out in full (`1k/h` is written `1000/1h`), and a rule written twice is refused. The proxy does
not start with a rule it cannot read: the error names the rule by its number among all the `-limit`
values and its text, and says what is wrong, with a suggestion for a likely misspelling, as in
`-limit rule 1 ("PSOT /login 5/m"): "PSOT" is not an HTTP method (did you mean POST?)`. `proxy.New`
checks rules built without `ParseRateRules` the same way and keeps its own copy.

Each rule, the login limit and `-api-per-minute` included, has its own table of clients and its own
budget, so one cannot use up another's room. A client has a sliding window of ten slots, each a tenth
of the rule's window: while the table holds a client, it is never admitted more than COUNT requests in
any span of the window, and it is held back at most a tenth of the window (six seconds for a minute)
longer than an exact log of its requests would hold it. A request goes on only if every enforcing rule
it matches has room, and is then counted by all of them; one that a rule refuses is counted by none. A
refusal is `429` with `Cache-Control: no-store` and a `Retry-After` that is the exact number of
seconds, rounded up, until the request would be admitted; the request never reaches the application.
A refusal is logged as rule 5000022 for logins, 5000042 for API quotas and 5000047 for a `-limit` rule,
with the rule's text ("rate limit exceeded: POST /login 5/1m"), which comes from the configuration and
never from the request. Each rule logs at most one refusal a second; how many it did not log follows
in a line of its own ("... (37 more refusals not logged)") within about a second, before the rule's
next refusal is logged, and when the proxy stops. That line names no client, even with `-log-details`,
as the refusals it counts may be from many. `Edge.RateTotals` gives the running totals of refusals and
of clients evicted while still counting. The rules apply whatever the `-ddos` mode, and with the flood
protection off.

A table holds at most 50,000 clients, and the tables of all the rate rules together at most 200,000:
with more than four rules, each holds 200,000 divided by their number, so 25,000 with eight and 5,882
with the most there can be (the login limit, `-api-per-minute` and 32 `-limit` rules). When a table is
full, the client admitted least recently makes room for a new one, so whoever fills a table locks no
other network out; an idle client goes first, and when a client still inside its window has to go, rule
5000041 says so, at most once every ten seconds with how many such evictions were not logged. A dropped
client comes back with a fresh window, and no client is ever refused for what its neighbours sent: a
source able to fill a table already has more addresses than the table holds (one IPv6 /48 is 65,536
clients, a /51 is 8,192), each with a budget of its own, so the per-client limits do not bound what a
whole network sends; the network budgets of `-ddos` do. Refusals, and the reports of
monitor rules, are logged at most once a second per rule, and the next line logged says how many were
not.

## Monitoring

Default match events contain the rule ID, severity, the request's id and a fixed summary. The event
uses `msg`; rule text uses `rule_msg`. The id, `tx`, is 16 hexadecimal digits made when the request
arrives; the rule set's transaction is given the same one, so the lines of the rule set, the proxy's
own checks, the inspectors and the rate rules about one request all carry it and can be read
together. It joins lines; it is not a secret. `-log-details` may include the client address (the
visitor's, never with a port), URI, matched data, expanded CRS text and inspector panic details.
Treat it as sensitive logging.

Format totals are process-local blocked/monitored findings. The default `-formats-stats-interval 1m`
logs changed snapshots; `0` disables reporting, and graceful shutdown flushes a final changed
snapshot. See [format monitoring](formats.md#monitoring-and-logs). Login limits use 5000022, API quotas
5000042, other rate rules 5000047 (5000048 for a monitor rule), a full rate-limit table 5000041 and
inspector failures 5000040.

The proxy's own refusals before the flood protection sees a request are logged too: CONNECT 5000070
(405), a protocol upgrade or h2c 5000071 (501), a target that cannot be forwarded unchanged (absolute
form, `*`, a raw `#`, `//` or a byte Go would re-encode) 5000072 (400), and a client address or
forwarding chain that cannot be read 5000073 (400, naming the connection's address with
`-log-details`). Nothing has limited such a request yet, so each of the four is logged at most once
a second; how many were not follows in a line of its own ("a CONNECT request (37 more refusals not
logged)") within about a second, before that kind's next line, and when the proxy stops, naming no
client or request. They do not count toward an address's standing with the flood protection.

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
