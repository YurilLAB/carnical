# ADR-0065: Bound API request rates and limiter state

- **Status:** proposed
- **Date:** 2026-10-05 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (local private Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Enterprise WAFs provide configurable request-rate protections. Carnical only limits WordPress login attempts. Its existing limiter also admits previously unseen clients when its 50,000-key table fills, and per-key timestamp slices do not provide a single bound on event storage. API requests need a verified client identity and predictable state costs.

## Decision Drivers

- Limit API attempts before body reading, inspection and origin forwarding.
- Use the existing trusted-proxy boundary, never arbitrary visitor identity headers.
- Prevent route variants and separate paths from multiplying a shared budget.
- Cap identities and timestamp storage without permitting unrecorded requests.
- Keep defaults compatible until an operator selects a traffic budget.

## Considered Options

- Integrate a distributed external rate-limit service now.
- Use token buckets with bursts and continuous refill.
- Retain exact sliding-minute counting, using a shared bounded event ring and per-identity counts.

## Decision Outcome

Chosen: **a bounded sliding-minute counter**. `Config.APIRate` and the executable's `-api-per-minute`/`-api-rate-paths` enable a shared client budget across selected path prefixes and all methods. Zero disables it. Prefixes are validated and copied. Matching uses conservative case/slash/matrix normalization for quota selection, without changing the forwarded request target. The verified address comes from the existing peer/forwarding-chain validation; trusted ranges are copied during construction.

API and login identities have separate key namespaces. One mutex protects the per-edge counter map and an event ring, capped at 50,000 active identities and 200,000 admitted events. The clock is read under that lock, so expiration order follows admission order. Each expired event is visited once and releases its count and identity storage. Rejected attempts do not extend their window. Quota exhaustion returns 429; inability to record an attempt returns 503. Both carry fixed findings, `Retry-After: 60` and `Cache-Control: no-store`.

The implementation preserves an exact minute rather than changing login semantics to a refilling burst budget. Initial event-ring allocation is bounded and occurs on first use. Limits are local to one Edge; restarts clear them and multiple instances do not share state.

## Technical Discussion

No substantive technical discussion recorded in a PR; this ADR accompanies local private development requested by the project owner.

## Participants

- Codex — implementation and local executable validation assistance; maintainer review pending.

## Consequences

- **Positive:** API volume has an explicit early bound; saturated limiter state cannot disable protection; event expiration has amortized constant work rather than repeated full-table scans.
- **Negative / follow-up:** state exhaustion can refuse legitimate new clients until events expire. NAT clients share an address budget. Distributed enforcement, authenticated principal quotas and weighted operation costs require distinct trusted-state integrations.

## References

- [Fastly request and rate-limit rules](https://www.fastly.com/documentation/reference/api/ngwaf/rules/)
- [RFC 6585: 429 and cache behavior](https://www.rfc-editor.org/rfc/rfc6585)
- [Carnical executable usage](../../carnical/README.md)
