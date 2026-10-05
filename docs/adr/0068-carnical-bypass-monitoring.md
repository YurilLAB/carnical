# ADR-0068: Monitor bypass findings without exposing request data

- **Status:** proposed
- **Date:** 2026-10-05 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (local private Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

The owner requested detection of related bypass forms and more logging/monitoring. A live Coraza rule with a request macro reproduced request data in the default log's message. Inspector panic text could also include request content. The executable used the logger's message key for rule text, producing duplicate JSON keys, and new API quotas shared an ID with existing inspector failures.

## Decision Drivers

- Make repeated, structurally equivalent bypass attempts observable in block and monitor modes.
- Keep monitoring storage bounded independently of visitor-controlled labels.
- Keep credentials out of default logs and aggregates.
- Preserve graceful shutdown and avoid another exposed HTTP listener.

## Considered Options

- Depend on downstream log aggregation alone.
- Add client/route counters and a public metrics endpoint.
- Add fixed per-rule counters with changed local summaries and repair log boundaries.

## Decision Outcome

Chosen: **fixed per-rule counters and privacy-safe logging**. Each format inspector allocates atomic blocked/monitored counters sized by its static rule registry. Snapshots contain only stable rule IDs/names and totals. Counters measure emitted findings, once per rule per request, subject to the existing stop/reporting limits. They reset with a new inspector and are not transactional across all rules.

The executable logs changed snapshots once a minute by default, with a configurable interval of zero (off) or 100ms through 24h. A joined reporter flushes a final changed snapshot after graceful server shutdown. It opens no listener and retains no visitor labels. Forced termination cannot flush. Individual findings remain logged for every attempt.

Default CRS messages become fixed summaries because Coraza's public metadata exposes no unexpanded message. Expanded messages and inspector panic text require detailed logging. The event message retains the logger's message key; rule summaries use a separate rule-message key. API quota identity changes to 5000042, preserving existing inspector-failure identity 5000040 and state-saturation identity 5000041.

## Technical Discussion

No substantive technical discussion recorded in a PR; this ADR accompanies local private development requested by the project owner.

## Participants

- Codex — implementation and local executable validation assistance; maintainer review pending.

## Consequences

- **Positive:** bounded, concurrent bypass telemetry; reliable event parsing; default request-data redaction; distinct admission/failure signals.
- **Negative / follow-up:** default CRS descriptions require lookup by ID; detailed logs can expose credentials; totals are local and do not count unseen findings or unique attacks. Log consumers must update the rule-message key and API-quota ID.

## References

- [Go structured logging keys](https://pkg.go.dev/log/slog@go1.26.6#MessageKey)
- [Go atomic counters](https://pkg.go.dev/sync/atomic@go1.26.6#Uint64)
- [Carnical monitoring](../../carnical/docs/formats.md#monitoring-and-logs)
