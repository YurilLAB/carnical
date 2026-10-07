# ADR-0076: Carnical result-cache capacity limit

- **Status:** proposed
- **Date:** 2026-10-07 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Perf

## Context and Problem

The virtual-patch Go constructor rounds a caller-supplied result-cache capacity
up by shifting a signed integer. Extremely large positive capacities overflow
and cannot terminate; other large capacities can cause excessive allocation.
The option is not supplied by an in-tree HTTP, policy or control entry point.
The current constructor returns an engine without an error value.

## Decision Drivers

- Bound constructor work and the result table's per-engine allocation.
- Preserve the constructor signature, default capacity and negative/off option.
- Make oversized configuration visible through the existing load report.

## Considered Options

- Guard only integer overflow: leaves excessive allocation possible.
- Return an error for oversized capacity: changes the public constructor API.
- Cap the optional table before rounding and report the reduction on load.

## Decision Outcome

Cap positive capacities at 1,048,576 entries before rounding up. Each atomic
64-bit slot costs eight bytes, so the table has an 8 MiB ceiling. This gives
32 times the default capacity while keeping a finite, architecture-independent
budget. The value is a new capacity policy, not a pre-existing resource standard.
Zero still selects 32,768 entries and negative values disable the table.
Load reports a warning whenever the requested capacity exceeded the ceiling.
Build the unsigned index mask alongside the bounded integer table size.

## Technical Discussion

No substantive technical discussion recorded on a repository PR thread;
maintainer review of the capacity policy is pending.

## Participants

- Repository owner — requested CI fixes and security validation.
- Coding agent — implementation and validation; maintainer review pending.

## Consequences

- **Positive:** finite constructor work and a bounded result-table allocation
  on both 32-bit and 64-bit architectures, without a constructor API change.
- **Negative / follow-up:** callers previously requesting larger tables now
  receive a warning and a smaller cache. More evictions can mean repeated regex
  work and earlier exhaustion of per-request work budgets. Matching decisions
  remain subject to the configured work-limit policy. The ceiling does not
  bound loaded signatures or aggregate allocations across multiple engines.

## References

- [Virtual-patch integration guide](../../carnical/docs/vpatch.md).
- [Engine options](../../carnical/vpatch/engine.go).
