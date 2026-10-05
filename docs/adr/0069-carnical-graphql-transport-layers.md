# ADR-0069: Layer GraphQL transport and method-override protection

- **Status:** proposed
- **Date:** 2026-10-05 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (local private Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

The owner requested independent layers against the GraphQL method bypass and related envelopes. Live executable tests reproduced a HEAD mutation with its mutation rule disabled, GraphQL in a PUT form, URL/body operation selection conflicts, noncanonical method tokens, and method-override fields in URLs, forms and JSON. Discovered endpoints also accepted URL documents with body-only operation selection or variables. Middleware can change the method from headers/query/body after inspection, while origins may merge envelope channels differently.

## Decision Drivers

- Preserve multiple independent detections without matching one attack string.
- Inspect related URL/body envelopes on every method, including discovered endpoints.
- Stop ambiguity before origin forwarding, with fixed messages and distinct identities.
- Preserve ordinary GET/POST operations, preflights and application fields inside variables.

## Considered Options

- Extend only the mutation-specific rule.
- Rewrite incoming methods and merge protocol parameters at the proxy.
- Reject ambiguous transports and reserve separate enforcement rules.

## Decision Outcome

Chosen: **independent rejection layers**. Rule 5002315 allows inspected GraphQL operations/protocol parameters over GET or POST. Rule 5002316 rejects GraphQL protocol parameters split between URL and body. Rule 5002317 rejects top-level method-override metadata, including decoded/case/bracket aliases of `_method`, but leaves variables alone. Rules use the existing block/monitor/off policy and fixed per-rule counters. Monitor mode continues gathering independent findings; blocking stops at the first refusal.

The GET/POST restriction is a local hardening policy, not a GraphQL standard requirement. Operators can explicitly disable it for legacy transports; safe-method mutation protection remains separate. Preflights without GraphQL parameters pass. All-method URL and form discovery handles parsed GraphQL and propagates URL identification to the body envelope, without rewriting requests.

Protocol-name case aliases are captured for inspection and rejected with the existing request-shape rule, including JSON batch discovery. This avoids origin folding or envelope merging hiding an operation from mutation/transport guards. Monitor mode records the independent findings while retaining the original forwarding bytes.

The bounded JSON scanner observes query candidates in every root-array object, including beyond retained elements. Batch discovery therefore cannot be hidden by an empty prefix or an operation placed past the retention cap; the existing batch-size rule then refuses excessive batches. Monitor/off modes retain the original bounded analysis limit.

The proxy rejects noncanonical mixed/lowercase method tokens (5000043) and the three common method-override headers, including underscore spellings (5000044), regardless of rule modes. This deliberately changes header tunneling from stripping to refusal. No upstream Coraza engine or unrelated API-policy files are changed.

## Technical Discussion

No substantive technical discussion recorded in a PR; this ADR accompanies local private development requested by the project owner.

## Participants

- Codex — implementation and local executable validation assistance; maintainer review pending.

## Consequences

- **Positive:** independent transport, selection, envelope and override enforcement; distinct every-attempt findings and bounded monitoring; refusal before the application sees tested variants.
- **Negative / follow-up:** legacy HEAD/PUT GraphQL and header tunneling require integration changes or explicit format-rule exceptions. Custom override names/getters and persisted-query operation types remain origin responsibilities. Enforcement requires format block mode; monitored/disabled layers intentionally admit requests.

## References

- [GraphQL-over-HTTP method extensibility and GET safety](https://http-spec.graphql.org/draft/)
- [Express method-override middleware](https://expressjs.com/en/resources/middleware/method-override/)
- [Carnical format policy and rule identities](../../carnical/docs/formats.md)
- [Local validation evidence](../../carnical/docs/enterprise-validation.md)
