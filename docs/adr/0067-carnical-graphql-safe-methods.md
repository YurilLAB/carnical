# ADR-0067: Protect GraphQL mutations on all safe HTTP methods

- **Status:** proposed
- **Date:** 2026-10-05 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (local private Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

GraphQL mutation protection originally covered GET only. Live executable tests showed HEAD mutations reaching the origin, both on a configured GraphQL path and on a discovered endpoint. Frameworks can dispatch HEAD through a GET handler, and HTTP safe-method semantics also cover OPTIONS and TRACE.

## Decision Drivers

- Refuse selected mutations carried by standard safe HTTP methods.
- Preserve the existing GET rule and operator overrides.
- Check every inspected envelope without rewriting the request.
- Keep legitimate queries and ordinary preflights working.

## Considered Options

- Rely on the origin to reject HEAD and other safe-method mutations.
- Reject every GraphQL request using methods other than GET and POST.
- Extend selected-mutation enforcement while preserving origin method negotiation.

## Decision Outcome

Chosen: **extend selected-mutation enforcement**. GET retains rule 5002310. HEAD, OPTIONS and TRACE use rule 5002314, defaulting to block with 403. Safe-method query strings are inspected for discovered GraphQL endpoints. Method safety also applies to body envelopes, including a HEAD body allowed by an explicit body-rule override. Method tokens follow HTTP's case-sensitive semantics.

The rule has ordinary block/monitor/off controls. An unselected mutation beside a selected query does not trigger it. Ordinary OPTIONS preflights pass. These safeguards do not declare additional GraphQL protocol methods supported; the origin still negotiates allowed methods. Persisted queries without a document require origin enforcement because the proxy lacks the registry.

## Technical Discussion

No substantive technical discussion recorded in a PR; this ADR accompanies local private development requested by the project owner.

## Participants

- Codex — implementation and local executable validation assistance; maintainer review pending.

## Consequences

- **Positive:** HEAD-to-GET routing no longer bypasses mutation protection; safe-method semantics are consistent across inspected envelopes.
- **Negative / follow-up:** nonstandard origin method aliases and persisted-query operation resolution require application-specific integration.

## References

- [HTTP safe methods](https://httpwg.org/specs/rfc9110.html#safe.methods)
- [Express automatic HEAD dispatch](https://expressjs.com/en/4x/api/router/#router-method)
- [Carnical format policy](../../carnical/docs/formats.md)
