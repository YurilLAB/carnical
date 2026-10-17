# ADR-0085: Carnical repeat-offender blocking

- **Status:** proposed
- **Date:** 2026-10-17 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

A source that kept sending attacks was refused request by request and never more. The shield
(ADR-0071) bans an address only for refusals during a declared flood; outside one, a scanner that
sent 5,400 cross-site scripting probes over 30 minutes from one address, each refused by the rule
set, was never banned, and nothing said it was still there. An intrusion prevention system is
expected to stop a source that keeps attacking for a while, and to say so, while an address that
many people share (carrier NAT, an office, the owner's own scanner) must not be locked out by a
scoring rule that was never tuned on the site.

## Decision Drivers

- Ban only on enforced, high-confidence findings, by points, and never on one false positive.
- Bans are temporary, escalate for a source that comes back, decay, and are never persisted, so a
  restart is the fail-safe direction.
- Memory is bounded under a spray of addresses, and a new ban never pushes out another one.
- Reuse the enforcement that already refuses a banned source at accept and at `Admit`, its
  per-source key (an IPv4 address or an IPv6 /64, never wider) and its protection of bans from
  eviction.
- Every ban, would-be ban, end of a ban and refused ban is reported, or counted in a report when the
  event queue has no room for it; none is silent.
- Trusted proxies, operator exemptions, loopback, link-local and unspecified addresses are never
  banned.

## Considered Options

- A separate ban table in the proxy. A second per-source table with its own key, eviction and
  enforcement point, and connections from a banned source would still reach the proxy.
- Pushing decisions to CrowdSec. It needs machine credentials in the proxy and a running LAPI, and
  the ban would hold only once the bouncer polled it.
- Adding sources to a kernel set by running `nft`. The confined process may not run programs
  (ADR-0073), and a set of its own would need its own cleanup.
- Points in the shield's source table (chosen). The table is already bounded, keyed per source,
  forgets bans last when it is full, refuses at accept and at `Admit`, exempts trusted proxies and
  tells the `Banner` hook.

## Decision Outcome

Chosen: **points in the shield's source table, scored through `Shield.Offend`, with temporary
escalating bans capped in number**, because it reuses enforcement that is already tested and bounded
and adds no new place where a source can be refused.

`shield.Config.AutoBlock` holds `Mode` (`off`, the zero value; `monitor`; `on`), `Points` (default
12, 4 to 1,000), `Window` (10 minutes, one minute to 24 hours), `For` (10 minutes, one minute to 24
hours), `MaxFor` (24 hours, 10 minutes to 7 days, at least `For`), `Max` (10,000 or an eighth of
`MaxSources` if fewer, 100 to 262,144, at most an eighth of `MaxSources`) and `Exempt` (at most 256
ranges, none of them /0); `Validate` names the field and its range. `Shield.Offend(client, points,
sig)` adds the points to the client's source. Its score is the points of its current window plus a
share of the previous window's that falls linearly to nothing as the current one goes on (a sliding
window of two slots). A source whose score reaches `Points`, or twice that for a source with
standing (known to the shield), is banned for `For` times two to the number of bans before it in a
row, at most `MaxFor`; a source not banned for `MaxFor` after its last ban ended starts again at
`For`. The ban sets the source's existing `bannedUntil`, so `Admit` refuses it with 403 and rule
5004008 (with `Connection: close` and a `Retry-After` of the time left) and the listener resets its
connections. It takes the source's standing, as an attack's ban does, and is sent to the `Banner`
unless its range holds a trusted address. In `monitor` the same scoring runs, nothing is banned, and
the source is treated as banned for the would-be ban's length, so what is reported is what `on`
would have done.

An index of the bans `Offend` made, ordered by their end, holds at most `Max`, and at most a
sixteenth of `Max` from one network (an IPv4 /24 or an IPv6 /48, counted beside the index), so that
one cheap IPv6 /48, which holds 65,536 sources, cannot take every ban and leave none for other
sources; the ban itself still covers only the source. When the index or the source's network share
is full a source that reaches its threshold is not banned, keeps its points, and the refusal is
counted and reported; no ban is pushed out. Ended bans are taken off on the shield's one-second tick, 512 at
most, and when the index is full. The bans live in the source table, whose 64 shards each hold a
64th of `MaxSources`, so `Max` is at most an eighth of `MaxSources` to leave the table room for its
other entries. A full table forgets a repeat offender's ban after any other entry (a stranger's,
then a known client's or an attack's ban), and only when every entry in its sample of 32 is such a
ban; the ban is then taken off the index and reported as ended at once, never lifted unseen.
Signatures are cleaned to 64 bytes of letters, digits and `._:/-`, interned (at most 1,024 names,
later ones reported as `other`) and kept as eight numbers per source. A source's offence record is
allocated only when it first offends, so the table grows by one pointer per remembered address.
Nothing is persisted.

Events: `source_blocked` and `source_would_block` (the source range, the client, the score, up to
eight signatures, the ban's length, end and level), `source_block_ended`, `auto_block_full` (the
bans not made since the last one) and `auto_block_unreported` (the events above that the queue had
no room for since the last one), each of the last two at most once every 30 seconds. They are
queued under the detector's lock and delivered by the tick outside it, like the shield's other
events. A source's events may use three quarters of the event queue, so that a spray of offenders
cannot crowd out an attack's events; the two counts may use all of it, and a count that finds no
room is kept for the next tick.
`Snapshot` counts offences, bans, would-be bans, bans refused for room, and the bans in force.

The intended scale of points, for the proxy's wiring: only enforced, high-confidence refusals score
(a CRS anomaly block with two or more categories or a scanner 4, with one category 3; a stable
virtual patch, an upload or WordPress policy block, or the block list 4; a decoy path 10; a
high-risk format or API contract block 2; a CONNECT, h2c or proxy-form target 1), and low-risk
findings, rate limits, the shield's own refusals, CrowdSec bans and anything only detected score
nothing. The proxy does not call `Offend` yet and has no `-auto-block` flag. When it is wired,
separately from this library change, its command line is to default `-auto-block` to `monitor`, so
an upgrade bans nothing until the owner chooses `on`, and the alert lines of ADR-0084 are to report
these events.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:** once the proxy reports offences, a source that keeps attacking is stopped at accept
  for a while, longer each time it returns; the owner sees every ban, would-be ban and refused ban,
  or how many went unreported when a spray filled the event queue; an attacker cannot evict bans or
  grow memory by spraying addresses; `monitor` shows what `on` would do before it is chosen.
- **Negative / follow-up:** an address many people share can still be banned once the owner turns
  `on`, which is why the planned command-line default is `monitor` and why `Exempt` exists. A ban
  holds per process and ends with it; kernel bans need a `Banner` or the CrowdSec bouncer. A source
  evicted from a full source table under pressure loses its escalation. An attacker with sixteen
  networks (an IPv6 /44, or sixteen /24s) can still fill the index and keep refilling it as bans
  end, which turns auto-block off for every other source until it does not; each request is still
  refused by its own check and every ban not made is counted in `auto_block_full`. A network shared
  by more attackers than its share is banned only up to that share. An address that offends holds
  about 80 more bytes until its points and escalation have decayed.

## References

- [Flood protection and IDS](../../carnical/docs/ddos.md#repeat-offenders)
- Related ADRs: ADR-0071 (flood protection), ADR-0073 (kernel packet guards), ADR-0080 (bounded IDS
  signals), ADR-0083 (rate rules and protection strengths), ADR-0084 (intrusion alerts)
