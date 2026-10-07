# ADR-0075: Carnical YAML parser work budget

- **Status:** proposed
- **Date:** 2026-10-07 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Perf

## Context and Problem

A hosted Ubuntu runtime check measured a 4,999-pair YAML block mapping at
250.968 ms. The document fits the existing 32 KiB and 10,000-node defaults.
The upstream parser recursively builds sibling mappings and appends each child
suffix, so unique and duplicate block keys both cause quadratic pointer copying.

## Decision Drivers

- Bound parser work before building an AST, including monitor-mode inspection.
- Keep duplicate-key reporting, policy actions and all existing format limits.
- Report an accurate, configurable lower work budget without permitting unsafe
  increases in the supported parser's worst-case work.

## Considered Options

- Increase the timing assertion: leaves the demonstrated parser cost unchanged.
- Reject duplicates in the parser: changes policy semantics and leaves unique
  block mappings expensive.
- Replace or fork the parser: requires broader grammar compatibility validation.
- Bound collection structural work before parsing: a small, conservative work bound.

## Decision Outcome

Add YAML `max_collection_work`, default and hard ceiling 1024. A site may lower
it. Count lexer tokens for colons, explicit keys, opening flow maps, commas and
block sequence entries and stop before parser.Parse
when the work-unit budget is exceeded. Retain the separate byte/node/depth checks.
The shared yaml-limit rule records the work-unit limit with a fixed message detail.

The supported parser can copy about n(n-1)/2 mapping pointers on this path.
A 1024-work-unit ceiling bounds block-map entries at 1024 and reduces that
bound from 12,492,501 at 4,999 pairs to 523,776. This
source-derived comparison describes copying work, not a latency guarantee.

## Technical Discussion

No substantive technical discussion recorded on a repository PR thread; this
record accompanies source review and local/hosted regression evidence.

## Participants

- Repository owner — requested CI fixes and security validation.
- Coding agent — implementation and validation; maintainer review pending.

## Consequences

- **Positive:** bounded block-mapping work with accurate reporting; tests retain
  the 250 ms assertion and exercise parsing at the new budget.
- **Negative / follow-up:** previously permitted wide documents may be refused.
  The counter conservatively includes flow sequences, valued explicit entries
  and many small collections. It also covers implicit-null insertion costs in
  shorthand flow maps and block sequences.
  Monitor mode forwards with a limit finding; disabling yaml-limit forwards
  silently after YAML inspection stops, so later findings are not assessed.
  A future parser replacement requires renewed grammar and cost validation.

## References

- [Upstream v1.19.2 parser source](https://github.com/goccy/go-yaml/blob/v1.19.2/parser/parser.go#L442).
- [Format protection guide](../../carnical/docs/formats.md).
- [Security findings and measurements](../security-findings.md).
