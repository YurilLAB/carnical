# ADR-0074: Carnical CrowdSec IP decisions

- **Status:** proposed
- **Date:** 2026-10-07 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

The owner requested CrowdSec IP tables in the Go WAF, with connectivity, security
and bug validation. The existing CrowdSec importer converts AppSec signatures;
it has no runtime IP decision feed. Kernel table scraping also cannot reliably
recover decision IDs, expiry, IPv6 ranges or verified clients behind a proxy.

## Decision Drivers

- Low request latency and bounded memory/work during floods.
- Correct overlap, deletion, expiry and recovery after lost stream updates.
- Verified client identity, protected credentials and deployment confinement.
- No new production dependencies or kernel privileges.

## Considered Options

- Query LAPI for every visitor: adds network latency and an outage dependency.
- Scrape iptables/nftables: OS-specific privileges and incomplete decision semantics.
- Fetch complete snapshots on every poll: simpler but expensive for large lists.
- Consume LAPI v1 deltas into immutable prefix snapshots, with full resync on failure.

## Decision Outcome

Chosen: **bounded LAPI streaming and immutable prefix snapshots**. A dedicated
bouncer key owns each process's cursor. Startup authenticates and fetches a full
snapshot; subsequent polls use deltas. Failed responses leave the cache intact
and force a full resync. Decision IDs own bans; a prefix index uses their maximum
expiry so overlapping decisions survive individual deletion.

The proxy checks the verified visitor on every request, before body/CRS/flood
evaluation. Active bans return 403. A stale cache returns 503 by default; explicit
fail-open permits unlisted visitors while retaining active bans. IPv4 and IPv6
prefix probes have constant upper bounds, and ranges are not expanded.

## Technical Discussion

No substantive technical discussion recorded on a repository PR thread; this
record accompanies the owner's request and local development. Implementation
references CrowdSec's current LAPI documentation and v1.8.1 controller source.

## Participants

- Repository owner — requested CrowdSec integration and live validation.
- Coding agent — implementation and validation; maintainer review pending.

## Consequences

- **Positive:** no remote calls on the request path; bounded cache, response,
  timeout and logging costs; atomic reloads and privacy-safe counters.
- **Negative / follow-up:** ban decisions only, without captcha, AppSec forwarding
  or metrics submission. Polling delays changes; default fail-closed can interrupt
  traffic during long LAPI outages. Every replica needs a distinct key. Unix
  sockets or narrow network exceptions are needed with the host policy.

## References

- Related: ADR-0070, ADR-0071, ADR-0073.
- [Integration guide](../../carnical/docs/crowdsec.md).
- [CrowdSec bouncer protocol](https://docs.crowdsec.net/docs/contributing/specs/bouncer_appsec_specs/).
- [CrowdSec v1.8.1 decisions controller](https://github.com/crowdsecurity/crowdsec/blob/v1.8.1/pkg/apiserver/controllers/v1/decisions.go).
