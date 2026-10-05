# ADR-0070: Publish Carnical enterprise integration packages

- **Status:** proposed
- **Date:** 2026-10-06 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

The owner requested publication of the existing local firewall work. API protection, signed configuration, validated policy,
authenticated control/feed APIs and virtual-patch import/matching implementations were present locally but absent from Git.
Publishing only the standalone executable would omit those integration APIs and their tests.

## Decision Drivers

- Keep Carnical in its separate module without altering the upstream engine.
- Validate package behavior and state concurrency before publication.
- Document the boundary between available APIs and active standalone protections.
- Keep external signature libraries and private keys outside the source repository.

## Considered Options

- Publish only the already committed standalone proxy protections.
- Publish the existing packages with their tests and explicit integration contracts.

## Decision Outcome

Chosen: publish the integration packages. `apiguard` supplies per-site API models, bounded validation, rate state and learning;
`config` supplies signed envelopes and replay state; `policy` validates and compiles customer settings; `control` supplies
authenticated tenant operations and feed delivery; `vpatch` supplies bounded matching and rule importers with offline commands.
Their documented interfaces leave production storage, guarded discovery transport, key provisioning and deployment wiring to
the integrator. The standalone command continues to activate CRS and its explicitly configured format inspector; these new
APIs are not implicitly installed in its request pipeline.

Publication testing found Windows append-handle truncation failures in the control audit writer. Repair now uses a checked
second handle on Windows, and failed rollback closes the writer. Tests cover recovery, partial writes, failed rollback and
refusal to repair a different file. Policy integration assertions now expect the proxy's fixed privacy-safe rule summary.
The offline replay command also accepts software scope and refuses empty active signature sets, avoiding a successful
index comparison that evaluated no loaded rules.

Normal package checks, scoped short race checks, vet, a dependency vulnerability scan and Linux/amd64 compilation are recorded
in the publication validation report. External dataset tests can skip when their inputs are absent, and the short virtual-patch
index comparison uses its existing reduced workload. These checks do not assert a full Linux runtime or production rollout.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized publication.

## References

- [API protection](../../carnical/docs/apiguard.md)
- [Configuration and policy](../../carnical/docs/config-and-policy.md)
- [Control API](../../carnical/docs/control-api.md)
- [Publication validation](../../carnical/docs/enterprise-validation.md)
- ADR-0068: bypass monitoring and privacy-safe rule summaries
- ADR-0069: independent GraphQL transport layers
