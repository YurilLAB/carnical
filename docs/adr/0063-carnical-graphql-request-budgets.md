# ADR-0063: Bound total selected GraphQL work across each HTTP request

- **Status:** proposed
- **Date:** 2026-10-05 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (local private Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

GraphQL's JSON batching extension can combine several permitted operations in one HTTP request. Individual document limits and a batch count bound the maximum, but still allow that batch count to multiply permitted field, alias and directive work. Existing per-operation limits remain necessary.

## Decision Drivers

- Prevent batch multiplication of the individual work budget.
- Count selected operations, with fragments expanded by bounded arithmetic.
- Keep state within one request, avoiding shared counters or locks.
- Expose tunable limits, monitor/off behavior and fixed-content findings.

## Considered Options

- Disable JSON batches. This interrupts legitimate clients and loses an existing supported format.
- Add separate aggregate budgets using selected-operation statistics already produced by the analyzer.

## Decision Outcome

Chosen: **aggregate budgets using existing statistics**. Add request-level field, alias and directive limits with defaults 1000, 40 and 100. The request's finder accumulates each selected operation with the existing saturating arithmetic. Selection returns the operation index among operation definitions, so interleaved fragment definitions cannot misalign the statistics. Every operation still undergoes its per-operation checks. Requests over a total produce distinct configurable rules with 400 responses in enforcement mode.

These remain conservative syntax counts: duplicated fields may merge at the application, while list-valued resolvers may generate work invisible without a schema and argument policy. No resolver cost or response-size guarantee is claimed. Persisted requests without text remain outside this analysis.

## Technical Discussion

No substantive technical discussion recorded in a PR; this ADR accompanies local private development requested by the project owner.

## Participants

- Codex — implementation and local executable validation assistance; maintainer review pending.

## Consequences

- **Positive:** per-request work has an explicit policy independent of batch length; state is isolated; fragments are counted without expansion allocations.
- **Negative / follow-up:** legitimate large batches may need tuned totals or monitor mode. Schema-aware resolver weights and persisted-query registries remain future integrations.

## References

- Related decision: ADR-0061.
- [F5 GraphQL protection](https://docs.nginx.com/waf/policies/graphql-protection/)
- [Carnical format policy](../../carnical/docs/formats.md)
