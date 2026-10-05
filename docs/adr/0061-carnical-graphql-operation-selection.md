# ADR-0061: Select GraphQL operations before enforcing HTTP method safety

- **Status:** proposed
- **Date:** 2026-10-05 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (local private Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Carnical's format inspector bounds GraphQL query complexity and checks envelope types, but discarded operation names and kinds while parsing. Method safety needs the operation actually selected by the client, rather than a keyword search or a prohibition on any document containing a mutation. Commercial WAFs provide GraphQL-specific controls; this change strengthens Carnical's existing inspector using the GraphQL specifications as the behavioral contract.

## Decision Drivers

- Refuse a mutation selected using GET before it reaches the application.
- Allow GET queries that select a query beside an unselected mutation.
- Keep parsing bounded and avoid executing or schema-validating client documents.
- Preserve monitor/off policy behavior and avoid logging input or operation names.

## Considered Options

- Reject any GET document containing a mutation. This rejects valid mixed documents selecting a query.
- Retain operation metadata in the existing bounded parser and apply GraphQL operation selection. This uses the parser's interpretation consistently across JSON, form and query-string envelopes.

## Decision Outcome

Chosen: **retain metadata and select the operation**. Reject duplicate operation names, a non-lone anonymous operation, missing selection among multiple operations, and an unknown selection. Refuse selected GET mutations with 403, a permitted 4xx response that does not require a method advertisement. Decode and check all four protocol parameters; reject repeated parameters and check JSON types of URL/form variables and extensions. Existing per-document complexity limits continue to inspect every operation conservatively.

Persisted requests without query text remain supported. Their operation type cannot be established without the origin's registry; origins must enforce GET safety for them. Field authorization and schema validation remain application responsibilities.

## Technical Discussion

No substantive technical discussion recorded in a PR; this ADR accompanies local private development requested by the project owner.

## Participants

- Codex — implementation and local validation assistance; maintainer review pending.

## Consequences

- **Positive:** HTTP method policy uses parsed operation semantics; JSON member order cannot affect selection; ambiguous protocol parameters are refused.
- **Negative / follow-up:** Previously accepted invalid selections now receive a request-shape finding. Monitor mode allows rollout observation. Persisted-query method validation needs a registry integration.

## References

- [GraphQL operation selection](https://spec.graphql.org/September2025/#GetOperation())
- [GraphQL over HTTP: GET](https://http-spec.graphql.org/draft/#sec-GET)
- [F5 GraphQL protection](https://docs.nginx.com/waf/policies/graphql-protection/)
- [Fastly GraphQL inspection](https://www.fastly.com/blog/introducing-graphql-inspection-for-the-fastly-next-gen-waf)
