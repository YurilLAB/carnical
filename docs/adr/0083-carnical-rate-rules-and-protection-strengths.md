# ADR-0083: Carnical per-client rate rules and protection strengths

- **Status:** proposed
- **Date:** 2026-10-16 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

The proxy's only request-rate controls were the WordPress login limit and `-api-per-minute`
(ADR-0065). Both kept every admitted request in one site-wide ring of 200,000 events and refused
with 503 (rule 5000041) once it was full. Clients within their own limits could fill it: two
clients at `-api-per-minute 100000`, or about 334 clients at 600 a minute, locked every other
client out of the API and of `wp-login.php`, a site-wide ceiling of about 3,333 limited requests a
second. Its `Retry-After` was a fixed 60 whatever the real wait. Operators also had no way to limit
other routes, such as an application's own login or search, or to choose a method.

The flood protection (ADR-0071) had one set of settings. A small or often attacked site wanted it
tighter, and an API or a site behind carrier NAT wanted it looser, which took up to a dozen
`-ddos-*` flags and knowledge of how they interact. Its 429 for an address's or a network's own
limit always said `Retry-After: 1`, wrong for any limit below one request a second, and a ban sent
no `Retry-After` at all.

## Decision Drivers

- A client within its limits must never cause another client's refusal.
- Bounded memory per rule and in total, with no state allocated before traffic arrives.
- No more than COUNT admitted requests in any span of one window, for any arrival pattern.
- An exact `Retry-After`, so a client that honours it is admitted.
- One short flag, with the same text accepted in the site file (ADR-0077) and errors that name the
  rule and say what is wrong.
- No allocation on the request path for the client key.
- Rate rules are an operator decision; a signed or local policy (ADR-0082) must not add or drop
  them.
- A strength is a starting point: every existing `-ddos-*` flag keeps working and overrides it.

## Considered Options

Counting algorithm:

- An exact event log per client and rule. Exact, but its memory grows with COUNT per client, so a
  1,000,000/h rule needs megabytes per client or a shared ring, which is what failed.
- GCRA (a token bucket). One timestamp per client, but it admits up to 2·COUNT−1 requests in a
  span of one window, which breaks the window guarantee a login limit is written for.
- A sliding window of ten counter slots per client and rule (chosen). Fixed memory per client
  (about 150 bytes), never more than COUNT in any span of the window, stricter than an exact log by
  at most one slot (a tenth of the window, six seconds for a minute), and an exact `Retry-After`
  computed from the slots.

A full table:

- Refuse new clients while the table is full (fail-closed, ADR-0065's choice). A source that fills
  the table locks every new visitor out, the bug being fixed: two IPv6 /48s inside the shield's
  per-network budget fill a 50,000-client table in under a minute.
- Evict the client admitted least recently (chosen). One IPv6 /48 already holds 65,536 /64 clients,
  each with its own budget, so a source able to fill a table has more independent budgets than the
  table holds, and a dropped client returning with a fresh window gives it nothing it lacked. What a
  whole network sends is bounded by the shield's per-network budgets, not by the rate rules.

Choosing a strength:

- A separate `-ddos-preset` flag. Longer commands, and a second flag to keep consistent with
  `-ddos off`.
- Strength words on `-ddos` (chosen): `-ddos strict`, `-ddos monitor,strict`. A strength alone
  implies `on`, a mode alone implies `normal`, and `off` with a strength is refused.

## Decision Outcome

Chosen: **per-client ten-slot sliding windows with one table per rule and least-recently-admitted
eviction, configured by `-limit`, and `relaxed`, `normal` and `strict` strength words on
`-ddos`**, because together they remove the shared ceiling, keep each rule's window guarantee,
bound memory, and keep commands short.

Rate rules. `-limit` takes `[METHODS] PATHS COUNT/WINDOW [monitor]`, separated by `;` or repeated,
as in `-limit 'POST /login 5/m; /api 600/m'`; the site file takes the same text as one `"limit"`
string, and a command-line `-limit` replaces it as a whole with a start-up notice.
`proxy.ParseRateRules` reads the text into `Config.Limits`, which `proxy.New` checks again and
copies. Methods are matched with GET covering HEAD; paths by segment and without ASCII case, with
the normalization of `-api-rate-paths`. Windows run from 1s to 1h, counts from 1 to 1,000,000,
with at most 32 rules, 16 paths in a rule, 100 in all and 4 KiB of text. A misspelled method,
window unit or `monitor` is refused with a suggestion.

Per-rule tables. The login limit (rule 5000022), `-api-per-minute` (5000042) and each `-limit`
rule (5000047) are rules of one set, each with its own table and budget, keyed by the verified
client's IPv4 address or IPv6 /64 as a `netip.Addr`. A table holds at most
min(50,000, 200,000 / number of rules) clients and grows only as clients arrive. A request goes on
only if every enforcing rule it matches has room, and is then counted by all of them; a refused
request is counted by none and does not refresh its client. Tables are locked in rule order. A
`monitor` rule counts what enforcement would count and reports a would-be refusal as rule 5000048.
The rules apply under every `-ddos` mode, with the flood protection off too. Refusal logs are
sampled to one line a second per rule with a count of those not logged, and the eviction of a
client still inside its window is logged as rule 5000041 at most once every ten seconds.

Retry-After. A rate-rule refusal is 429 with `Cache-Control: no-store` and `Retry-After` set to the
exact seconds, rounded up, until the request would be admitted by every refusing rule. In the
shield, a 429 for an address's or a network's own limit carries the seconds until its next token at
the rate it is held to (1 to 3600), and a ban's 403 the seconds the ban has left. The 503 of an
attack's shared budget and the challenge keep 5, an estimate.

Strengths and precedence. `shield.Preset` returns the configuration of a strength; `normal` is
exactly `DefaultConfig`. `strict` lowers the per-address rate and burst, the highest raise of a
limit, the budget of strangers during an attack, the connection rate, and the ban threshold, and
lengthens bans and declares attacks sooner; `relaxed` does the opposite. Capacity and user
experience settings (connection counts, address tables, challenge difficulty) are the same at every
strength. A setting comes from, first to last, the flag on the command line, the same flag in the
site file, the strength, and the built-in default; an explicit 0 where 0 meant "default" now means
the strength's value. The start-up log and `-check` name the mode, the strength, the `-ddos-*`
flags that override it, and every rate rule with where it comes from. Each strength ships only with
simulation cases that pass for it; `relaxed` keeps the normal budget for known clients during an
attack because the doubled budget first proposed let a botnet that had earned standing through
(recorded in `carnical/docs/flood-validation.md`).

This record reverses ADR-0065's choice that capacity exhaustion refuses, for rate limits only.
ADR-0065 is not rewritten: its sliding-minute budgets, verified-client identity and headers are kept,
and its event ring and fail-closed saturation are replaced as described here.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:** clients within their limits can no longer lock others out of login or the API; each
  rule has its own budget and bounded memory (about 30 MB at most, none before traffic); operators
  limit any route and method with one flag; `Retry-After` is exact; one word picks a tested set of
  flood settings, and every existing flag still applies on top of it.
- **Negative / follow-up:** a client evicted from a full table starts a fresh window, so per-client
  limits do not bound what a whole network sends; the shield's network budgets do. A window is
  stricter than an exact log by up to a tenth of its length. Limits stay per process, as in
  ADR-0065. A command-line `-ddos` replaces the site file's whole value, so `-ddos monitor` over a
  site's `strict` runs `normal`. Under `strict`, an address many people share can be banned for 30
  minutes when their crowd is taken for an attack.

## References

- [Rate rules](../../carnical/docs/proxy-reference.md#rate-rules)
- [Flood protection strengths](../../carnical/docs/ddos.md#strengths)
- [Site file rate rules and strength](../../carnical/docs/config-and-policy.md#rate-rules-and-flood-strength-in-the-site-file)
- [Strength simulations](../../carnical/docs/flood-validation.md#2026-10-16-three-strengths-of-protection)
- Related ADRs: ADR-0065 (API rate limits, whose fail-closed saturation this reverses for rate
  limits), ADR-0071 (flood protection), ADR-0077 (site configuration), ADR-0081 (interactive site
  setup), ADR-0082 (local policy loading)
