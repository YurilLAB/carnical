# ADR-0082: Carnical local policy and virtual-patch loading

- **Status:** proposed
- **Date:** 2026-10-11
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Policy compilation and virtual-patch matching exist as libraries but the standalone proxy does
not connect them. Operators need to load reviewed local files without building a control service.
An earlier prototype also bundled automatic profiling, discovery and traffic-derived state, which
needs separate storage, trust and deployment validation.

## Decision Drivers

Preserve current origin authentication, flood controls and strict explicit OpenAPI imports. Reject
invalid requested protections before listening. Keep machine body ceilings independent of site
policy, and avoid automatic changes based on origin fingerprints or observed traffic.

## Considered Options

Importing the prototype as a whole would include unvalidated persistence and change startup defaults.
A smaller static-file integration uses maintained library interfaces and keeps those boundaries
separate. Requiring a control service would add deployment requirements for local users.

## Decision Outcome

Load operator-managed policy and signature files before listener creation. Pin each parent directory,
reject symlinks and nonregular files, use nonblocking opens, verify opened identity and bound reads.
Policy settings apply first; explicit CLI and site-config settings override matching fields. Body
limits always remain at or below operator ceilings, while denied-header lists combine.

Install format checks before virtual patches so matching sees decoded bodies. Load a static pack
with explicit tier/scope choices; no signatures are silently excluded by default. Rejected or empty
selections stop startup. Keep strict local OpenAPI configuration separate. Optional generic API
checks use the existing guard without learning, discovery, promotion or state persistence.

Startup does not fetch profiles, descriptions or signatures. Files are not reloaded; deployment
requires a restart. Counter summaries contain counts, not visitor content. This change adds no
network helper, signing service or kernel-policy replacement.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change.

## References

- [Local policies](../../carnical/docs/config-and-policy.md#load-a-local-policy)
- [Virtual-patch CLI](../../carnical/docs/vpatch.md#run-a-pack-in-the-proxy)
- [API checks](../../carnical/docs/apiguard.md)
