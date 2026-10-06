# ADR-0072: Layer local injection rules and explicit API input contracts

- **Status:** proposed
- **Date:** 2026-10-06 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

The variant load test admitted XPath, command, template, serialized Java, encoded traversal and URL indicators.
It also showed ambiguous parameter names. A URL or diagnostic path can be legitimate, so refusing every admitted
fixture would confuse corpus admission with an application exploit. The API guard previously existed only as an
integration package, leaving the standalone binary unable to enforce an operator's declared API contract.

## Decision Drivers

- Keep the signed CRS release and upstream engine unchanged.
- Detect syntactic families across decoded request fields without rewriting the application input.
- Give resource destinations and scalar/array semantics an explicit application contract.
- Refuse unsupported enforcement contracts rather than silently weakening them.
- Keep request content out of default logs and preserve the existing flood-protection work.
- Distinguish operational upstream failure telemetry from payload detections.

## Considered Options

- Raise the whole CRS paranoia level, increasing unrelated false positives.
- Deny all corpus URLs and probe paths irrespective of the application's behavior.
- Supplement CRS and structural parsing, and optionally install an explicitly supplied OpenAPI contract.

## Decision Outcome

Chosen: separate embedded local rules (5006001–5006010), structural parameter-shape checks, and optional local
OpenAPI validation after the format inspector. Local rules add five PL1 inbound anomaly points and share the
configured CRS mode and threshold. They can be disabled independently and excluded with existing SecLang settings.
The optional API contract uses the existing bounded guard with format and specification enforcement; it does not
enable rate learning, automatic discovery or promotion. Enforcement refuses import warnings, object parameters,
unbounded body media declarations, multiple body media types and non-JSON body contracts. Monitor mode remains available.
Upstream failures use a fixed operational label and numeric OS code in the existing match callback; raw error
strings require the existing sensitive-detail option.
Live Windows load probing also exposed transient address-in-use failures. The proxy permits three total TCP dial
attempts only for that pre-connection error, reapplying the origin policy on every attempt and respecting cancellation.
It does not retry established-connection failures or change the body-connection isolation policy. Retry telemetry
has a separate operational ID and is never credited as an attack detection.

## Technical Discussion

No substantive technical discussion recorded on a PR thread; this decision follows the owner's request and local
variant/adversarial evidence. No public vulnerability issue or PR was opened.

## Participants

- Project owner — requested the hardening, live validation and publication.
- Codex — implementation and local review; maintainer review remains pending.

## Consequences

- **Positive:** broader syntax detection, deterministic parameter interpretations, safe rule labels,
  and executable API contracts with typed inputs and explicit destination patterns.
- **Negative / follow-up:** local rules may reject intentional code examples and require site tuning. Ordinary
  remote URLs require a real site contract. Authorization, query binding, guarded outbound fetching,
  DNS/redirect controls and plugin patching remain application/deployment responsibilities. No finite corpus
  establishes universal bypass resistance. Flood refusal is measured separately from payload detection.

## References

- Related ADRs: ADR-0066, ADR-0070, ADR-0071.
- [Input hardening configuration](../../carnical/docs/input-hardening.md).
- [Variant evidence](../../carnical/docs/loadtest-750k-variants-2026-10-06.md).
