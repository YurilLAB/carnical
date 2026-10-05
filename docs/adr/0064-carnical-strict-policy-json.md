# ADR-0064: Reject ambiguous format policy JSON before startup

- **Status:** proposed
- **Date:** 2026-10-05 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (local private Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Refactor

## Context and Problem

The executable now loads format policy JSON before serving requests. `encoding/json` accepts duplicate members and case aliases, and silently ignores `null` for some scalar values. Contradictory settings such as two `max_depth` members can therefore discard an operator's intended limit. `DisallowUnknownFields` alone does not detect these ambiguities.

## Decision Drivers

- Fail before opening a listener when a policy has contradictory settings.
- Keep JSON tags authoritative, without a second manually maintained list of fields.
- Bound parsing by the finite policy schema and a shared file-size cap.
- Preserve omitted fields, empty collections, numeric zero defaults and canonical serialization.

## Considered Options

- Continue using the decoder's compatibility behavior and rely on operator linting.
- Adopt an alternative JSON package or require experimental toolchain behavior.
- Validate tokens against the existing Go policy types before the ordinary typed decode.

## Decision Outcome

Chosen: **a schema-directed token validation pass**. `ParsePolicy` rejects duplicate decoded names in every object, field names that do not match JSON tags exactly, `null`, invalid UTF-8 bytes, wrong shapes and trailing data. It then uses the existing typed decoder for integer conversion and `Validate` for supported settings and numeric ceilings. `MaxPolicyBytes` gives the library and executable the same 1 MiB cap.

The validator follows the acyclic policy type schema. Input cannot create arbitrary recursion: a nested value where a boolean, integer or string is expected is refused immediately. Reflection happens only during configuration loading, with no change to request inspection. Unsupported future schema types fail closed until explicitly supported.

This tightens configuration compatibility: previously accepted duplicate, case-aliased or nullable settings now fail. Operators should omit defaulted settings or use their documented zero/empty values.

## Technical Discussion

No substantive technical discussion recorded in a PR; this ADR accompanies local private development requested by the project owner.

## Participants

- Codex — implementation and local executable validation assistance; maintainer review pending.

## Consequences

- **Positive:** contradictory settings cannot silently select a weaker policy; decoding follows the documented field names; loading has a shared resource bound.
- **Negative / follow-up:** configuration loads perform a second pass and use reflection. Future schema changes must preserve the finite type graph and add validator support when introducing new kinds.

## References

- Related decision: ADR-0062.
- [Go JSON decoder compatibility and security considerations](https://pkg.go.dev/encoding/json@go1.26.6)
- [Carnical format policy](../../carnical/docs/formats.md)
