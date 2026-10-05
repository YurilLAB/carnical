# ADR-0062: Configure Carnical format enforcement independently of CRS

- **Status:** proposed
- **Date:** 2026-10-05 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (local private Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Carnical's format inspector is available to Go integrations but the executable does not install it. Operators need per-site format validation and bounded decompression through the executable used for deployment.

## Decision Drivers

- Make existing format protections deployable and observable.
- Keep CRS mode and format policy independently tunable.
- Refuse invalid configuration before accepting traffic.
- Open and finish reading configuration before Linux confinement.

## Considered Options

- Enforce the built-in strict policy immediately on every site. This can interrupt legitimate clients before exceptions are tuned.
- Expose an independent monitor/block/off mode, validated policy file and explicit compression option.

## Decision Outcome

Chosen: **independent mode with monitor as the executable default**. CLI mode overrides the policy's monitor flag; individual rule actions remain configurable. A regular policy file is read through a 1 MiB bound and validated before opening the listener. Compression is off by default and requires formats enabled. Off combined with a policy or encoding opt-in is a startup error, preventing a silently ignored operator setting. Both the proxy's body limits and the inspector's body/decompression limits apply.

The proxy applies its body limit and upload filename/content policy to the final body after inspectors have transformed it, using the final Content-Type and boundary. Before this change, compressed bytes were checked instead, leaving decompressed size and upload contents unchecked by those guards. CLI regressions reproduce the old 200 responses and assert the corrected 413/403 responses with zero origin requests.

## Technical Discussion

No substantive technical discussion recorded in a PR; this ADR accompanies local private development requested by the project owner.

## Participants

- Codex — implementation and local executable validation assistance; maintainer review pending.

## Consequences

- **Positive:** the deployed executable can enforce structured API bodies; invalid settings fail startup; operators can stage rules through monitoring.
- **Negative / follow-up:** default monitoring produces additional findings. Independent modes must be communicated clearly. This does not integrate the unfinished API-policy/control packages.

## References

- Related decision: ADR-0061.
- [Carnical format policy](../../carnical/docs/formats.md)
- [Vendor research](../../carnical/docs/enterprise-waf-research.md)
