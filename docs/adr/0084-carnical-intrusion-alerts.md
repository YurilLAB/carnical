# ADR-0084: Carnical intrusion alerts

- **Status:** proposed
- **Date:** 2026-10-16 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Carnical reported what it found one rule at a time. A refused SQL injection wrote seven
`rule matched` lines that looked the same in detect and block mode; none said whether the request
was refused, what its score was, or which rules made up the verdict. On CRS lines `disruptive`
meant "the engine is on", so clean requests answered 200 logged `disruptive:true`. Lines from the
proxy, formats, vpatch, apiguard and the rate rules carried no transaction id and could not be
joined to the CRS lines of the same request. Several refusals (CONNECT, Upgrade, targets that
cannot be forwarded, oversized bodies) and every shield refusal wrote nothing at all. Nothing was
deduplicated or bounded: 3,000 requests from 60 addresses wrote 96,032 lines (18.7 MB), enough to
bury the one line that mattered and to fill a disk. There were no exact totals, no view of which
sources were attacking, no way to silence a known false positive without changing what is
blocked, and no way to be told about an intrusion without reading the log.

An operator running Carnical as an IDS needs to see every intrusion and suspected intrusion once,
with who did it, without alert fatigue. Running it as an IPS, the same record must say what was
refused, and nothing that was refused may go unreported.

## Decision Drivers

- One record per request and signature that states the final verdict (blocked, would block,
  detected, not inspected, rate limited, source blocked, client closed), as Suricata's `verdict`
  and UniFi's IDS/IPS alerts do, with the same request id on every layer.
- The source is shown by default; what the visitor sent (query, body, headers, cookies, matched
  data, expanded messages) never is.
- A flood must not blind the IDS: repeats are deduplicated and the log is rate limited, but exact
  totals are never sampled and no count is lost on eviction or shutdown.
- Every table and queue is bounded; memory stays constant under attack and a clean request does
  not allocate an alert.
- Alert delivery never blocks request handling, the shield lock or shutdown beyond a fixed bound.
- Silencing an alert never changes what is blocked.
- Standard library only, no new dependency, nothing in the Coraza core.

## Considered Options

Record:

- Per-rule logs only (today). Every layer already logs; nothing to build. It is the problem
  described above: no verdict, no join across layers, unbounded volume.
- Logging the source and the payload together, so an alert can be triaged from the log alone.
  Rejected: matched data and query strings carry personal data and credentials, and a log line
  that copies attacker input is an amplification and re-injection vector. `-log-details` keeps
  that opt-in for the per-rule lines only.
- One deduplicated alert record per request and signature, built from the final verdict (chosen).

Notification sinks:

- A syslog sink. Left to journald: under systemd stderr already reaches the journal, which
  forwards to syslog and remote collectors with its own rate limits; a second path would duplicate
  every line and add a socket to the confined process.
- A webhook that is always on, or on by default. Rejected: it adds an outbound connection, a
  secret and a server-side request forgery surface to every deployment, including those that never
  asked to be called.
- An opt-in webhook sink (chosen, at the owner's request, on top of the log sink; not built yet).
  An operator without a log pipeline otherwise has no way to be told of an intrusion. It is bound
  by these safety rules:
  - Off unless the operator configures a destination; the destination is fixed at start-up and is
    never built from request data.
  - `https` only, the certificate verified, no redirects followed, no user information in the URL,
    and the query of the URL never logged.
  - The destination must not resolve to a loopback, private, link-local, multicast or unspecified
    address unless the operator allows private destinations explicitly, and the address is checked
    again when the connection is made, so DNS rebinding cannot turn it toward an internal service.
  - A signing secret, when used, is read from a file, never from a flag or the site file, is never
    logged, and signs each body with HMAC-SHA256 over a timestamp so the receiver can refuse a
    replay.
  - It carries only what the alert log line carries, after deduplication, suppression and the
    limiter, never per-rule lines and never what the visitor sent; bodies and batches are capped.
  - It runs behind its own bounded queue on one goroutine with a short per-request timeout and
    bounded retries; a full queue or a failed delivery drops and counts, is reported in the
    `alerts dropped` and totals lines and in a rate-limited warning, and never blocks a request or
    holds shutdown past the alert bound.
  - The start-up posture line names it, and `-check` validates it without sending anything.
- The library's `control/feed` event source as a sink, through an adapter (chosen, alongside the
  log): integrators that already run the signed pull feed get alerts in the vocabulary the owner's
  console reads, with no new outbound connection.

Aggregation:

- A global token bucket only. A single noisy rule would use up the budget and hide a rarer, more
  serious one.
- Dedupe per (source key, signature, action) with a window, a two-tier limiter that serves high
  and medium risk before low and informational, exact totals, and a per-source correlation table
  (chosen).

## Decision Outcome

Chosen: **one alert record per request and signature, built from the final verdict, deduplicated per
source and signature, delivered through a bounded asynchronous queue to the JSON log, the library
feed adapter and, once built, an opt-in webhook, with exact totals, a per-source suspected-intrusion
signal and suppression that only silences**, because it shows every intrusion once with who did it,
keeps volume and memory bounded under attack, and never weakens blocking.

Implementation status. This change adds the `alert` package (record, catalog, sanitizer,
aggregation, suppression, log sink, bounded queue and feed adapter), the `rule matched` changes
(`tx` on every layer, `category`, `risk`, a per-request cap, and `disruptive` only on the refusing
check) and the proxy's wiring: each request's verdict feeds the aggregator, and the command line
has the flags named below, `-alerts`, `-alert-path`, `-alert-rate`, `-alert-table`, the intervals and
`-log-rule-matches`, lists suppressions at start-up and waits for the queue at shutdown. The
webhook sink is not built yet.

The record. Each alert has an `alert_id` (the request id, equal to the Coraza transaction id and to
`tx` on `rule matched` lines), `layer`, a stable `sig` (`crs-942100`, `carnical-5000010`,
`formats-5002103`, `apiguard-5003113`, `shield-5004001`, `policy-1030000`, `vpatch-<ID>`), a static
`sig_name` from a catalog compiled from the CRS file families, the rules of Coraza's recommended
configuration (`crs-200002` and the other 2000xx ids that refuse a body, multipart part, argument
count or URI the engine could not take apart) and carnical's own rule ids (never a macro-expanded
message), up to eight contributing `rules`, up to four `category` values from a closed vocabulary,
one `risk` scale for every layer (`high`, `medium`, `low`, `info`, as UniFi uses), the raw severity,
the `action`, the layer's `mode`, the status sent, the CRS score and threshold, the verified source
(`-alert-source full`, its /24 or /48 with `prefix`, or nothing with `off`), with `full` the /32 or
/64 `src_key` it is counted under (left out with `prefix`, where it would name the address the
operator chose to hide), the method, a bounded host, the path as a template unless the operator asks
for the raw path without its query, and `count`, `first` and `last`. Every attacker-derived string
goes through one sanitizer that replaces invalid UTF-8, escapes control, line-separator and
bidirectional characters and the backslash, and cuts on a rune boundary with a marker only when the
whole result does not fit.

Aggregation. The first alert for a (source key, signature, action) is written at once; repeats in
the window (one minute by default) are counted and written as one `alert repeated` line when the
window closes or the entry is evicted from the bounded, sharded table (16,384 entries by default).
That line names only what its repeats share: the source key, signature, action, layer and mode, with
the categories and highest risk of the repeats; it carries no request id, status, score, method,
host or path, which belong to single requests, and no incident id in the feed. An `alert repeated`
line the limiter or the queue does not let through still has its count added, by signature and
action, to `alerts dropped` and to the totals, so no count is lost. Lines pass a global limiter (20
a second by default) split 80/20 between high/medium and low/info, and high/medium may use the low
tier's tokens but not the reverse; `suspected intrusion` lines first take a reserved bucket of one a
second (burst ten); what it drops is counted and reported at most once a second in `alerts dropped`.
`intrusion totals` holds exact counters by layer, action and risk, the suppressed, below-minimum and
dropped counts and per-rule counts, every minute when something changed and always at shutdown. A
second bounded table keyed by source writes one `suspected intrusion` (risk high, at most once per
source per hour) when a source shows three distinct attack categories, a scanner finding together
with an attack, ten refused or would-be-refused findings, or a decoy hit within ten minutes, in
detect mode as in block mode; one the limiter or the queue does not let through leaves the source
unreported, so the next finding that meets a condition writes it. An IPv6 source is also correlated
by its /48, and the network is reported when its findings came from more than one /64: a host or
home connection holds a /56 or a /48 and can rotate through its /64s, which would keep each /64
under every threshold. Correlation only writes an alert, so the wider key costs no false ban;
auto-block keeps the /64. `intrusion summary` lists the ten sources (and such networks) with the
most refused or would-be-refused findings every five minutes; it lists addresses, so it is not
written with `-alert-source off`. `-alert-min-risk` (default `low`) keeps findings below it out of
the log but in the totals.

Suppression. `-alert-suppress` takes `SIG [PATH-PREFIX] [until=YYYY-MM-DD] [note=TEXT]` and
`-alert-exclude-sources` takes CIDRs no wider than /16 (IPv4) or /32 (IPv6), at most 256 of each. A
path prefix covers only a path in plain form: one with a `.` or `..` segment, `//`, `%`, a backslash
or `;` could resolve elsewhere, so it is never under a prefix and stays visible. Both only silence
alerts: blocking, rate limits and points toward a ban are unchanged, matches are counted as
suppressed, every entry is listed at start-up with its note and expiry, and an expired entry warns
and stops applying, which is the periodic review NIST SP 800-94 asks for.

Delivery. Alerts are queued on a bounded channel (1,024 by default) drained by one goroutine;
sending never blocks and a full queue counts a drop. The `alerts dropped`, `intrusion totals` and
`intrusion summary` records have a small lane of their own that is drained first, the drops and
totals are offered again on the next tick when refused, so a flood of alerts, or the repeats of
every open window flushed at shutdown, cannot crowd out the lines that count them. At shutdown the
process waits at most two seconds for the queue and writes the final totals.

`rule matched` lines stay for compatibility, gain `tx` on every layer, `category` and `risk`, are
capped per request, and mark `disruptive` only for the rule that refused the request.
`proxy.Config.NoRuleMatches`, `-log-rule-matches false` on the command line, keeps alerts only.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:** every refusal and every finding reaches one deduplicated record with a verdict and a
  source; a flood costs one line per source and signature per window plus totals, at constant memory
  (under 10 MB at the defaults); exact totals survive any rate limit; slow single-source scans are
  reported in detect mode; known false positives can be silenced without weakening the IPS;
  operators without a log pipeline can be notified once the webhook is built.
- **Negative / follow-up:** the limiter can drop alert lines (counted, and the totals stay exact);
  an entry evicted from the correlation table forgets that it already alerted, so a source can be
  reported again within the hour; users who share an IPv6 /48 can together be reported as one
  suspected network; the webhook, when built, is a new outbound connection and secret that the
  operator must protect and monitor.

## References

- NIST SP 800-94, sections 3.2.3, 4.3.2 and 4.3.3
- UniFi IDS/IPS: https://help.ui.com/hc/en-us/articles/360006893234
- Suricata exception policies and verdicts: https://docs.suricata.io/en/latest/configuration/exception-policies.html
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- Related ADRs: ADR-0080 (bounded IDS signals), ADR-0083 (rate rules, whose sampled refusal lines
  this record replaces with counted repeats)
