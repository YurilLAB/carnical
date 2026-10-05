# ADR-0066: Validate URL parameters with bounded parsing

- **Status:** proposed
- **Date:** 2026-10-05 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (local private Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Format inspection previously checked URL parameters only when identifying GraphQL. Generic API queries with malformed escapes, raw semicolons, invalid UTF-8, NULs and prototype parameter names reached the origin. A parser may ignore invalid parameters while another application parser reads them, undermining agreement about the request.

## Decision Drivers

- Validate every URL query regardless of HTTP method or endpoint.
- Reuse the existing strict parameter grammar and preserve forwarded bytes.
- Keep query tuning independent of URL-encoded body policy.
- Bound raw bytes, decoded names/values, parameter count and bracket depth.
- Preserve legitimate repeated parameters with explicit monitoring defaults.

## Considered Options

- Decode with `url.ParseQuery` and ignore partial results or errors.
- Add another URL-specific parameter parser.
- Reuse the form scanner with separate limits and rule identities.

## Decision Outcome

Chosen: **reuse the bounded parameter scanner**. `Policy.Query` has the existing form-limit fields, and `MaxQueryBytes` caps raw query scanning at 64 KiB by default. The scanner reports separate query rules for grammar, controls, UTF-8, count/length, bracket depth, prototypes, semicolons and duplicate names. Duplicates default to monitoring; explicit array names ending in `[]` retain their existing support. GraphQL captures the four protocol parameters during the same pass and retains stricter repetition/operation checks.

No query rewriting occurs. A blocked query stops forwarding. A monitored or disabled query budget stops query analysis to retain the work bound, while body inspection continues. Such a request does not receive complete query analysis; operators requiring full inspection should retain budget enforcement. Generic query validation requires format inspection to be enabled.

## Technical Discussion

No substantive technical discussion recorded in a PR; this ADR accompanies local private development requested by the project owner.

## Participants

- Codex — implementation and local executable validation assistance; maintainer review pending.

## Consequences

- **Positive:** API URL inputs receive explicit bounded validation; a scanner differential is removed; request bytes and valid clients remain unchanged.
- **Negative / follow-up:** legacy non-UTF-8 or raw-semicolon queries require policy tuning. Application-specific parameter schemas and collisions between query/body parameters remain separate integrations.

## References

- [Go URL parameter parsing and partial results](https://pkg.go.dev/net/url#ParseQuery)
- [Carnical format policy](../../carnical/docs/formats.md)
