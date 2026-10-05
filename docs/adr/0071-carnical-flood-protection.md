# ADR-0071: Carnical flood protection

- **Status:** proposed
- **Date:** 2026-10-06 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Coraza evaluates each transaction in isolation. The owner asked for protection against denial-of-service floods, including
attacks spread over many devices and countries, which no per-request rule and no per-address limit can see.

## Decision Drivers

- Act before the costly stages (TLS handshake, body reading, rule evaluation) and keep per-request cost to a few lookups.
- Detect distributed attacks by what their traffic has in common, not by address.
- Keep regular visitors working during an attack, and never log one line per refused request.
- Bounded memory whatever the attacker sends; no change to the upstream engine.

## Considered Options

- Per-address limits only (already partly present): blind to distributed floods.
- An external scrubbing service: required for floods bigger than the link, but outside this repository.
- An in-process shield with connection admission, aggregate detection and graded mitigation.

## Decision Outcome

Chosen: a new `carnical/shield` package used by the proxy before every other check and by the listener. Detection compares
ten-second aggregates (rate, fingerprint and target concentration, new-address share, engagement, application health)
with a baseline learnt only during ordinary traffic. During an attack, known clients and browsers that pass a stateless
proof-of-work check go on; requests resembling the attack and unknown clients share small budgets; repeat offenders are
banned. Sketches (HyperLogLog, space-saving, rotating Bloom filters) and sharded bounded tables keep memory fixed.
Evidence and limits are in `carnical/docs/ddos.md`.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change.

## References

- [Flood protection](../../carnical/docs/ddos.md)
- ADR-0065: API rate limits
