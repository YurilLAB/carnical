# ADR-0080: Carnical bounded IDS signals

- **Status:** proposed
- **Date:** 2026-10-09 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Connection floods and rejected HTTP probes need visibility even when the aggregate flood detector has not declared an attack. Operators of small sites and busy services need signals without automatically banning legitimate shared addresses or treating application errors as intrusions.

## Decision Drivers

- Reuse verified peer addresses, existing network admission and the proxy's response provenance.
- Keep counters and detection windows bounded, without request bodies, credentials or raw paths in alerts.
- Preserve existing attack classification and mitigation behaviour.
- Work on Windows and Linux without a new packet-capture dependency.

## Considered Options

- Infer scans from all 4xx responses: application errors and missing resources would create misleading signals.
- Automatically ban on connection closes or rejection ratios: configuration failures and shared clients can produce those observations.
- Add observation-only signals to the existing shield and retain its existing mitigations.

## Decision Outcome

Chosen: ten-second aggregate IDS signals for IP/network connection admission pressure, nontrusted connections ending before HTTP activity, and 4xx rejections after shield admission but before the origin. Each needs the configured detector MinAttackRate (default 20 observations/second) and a majority ratio: 50% of incoming connections refused, 75% of closed connections ending before HTTP StateActive, or 50% of admitted requests rejected by later checks. Alerts carry Kind=ids_signal and are globally limited to one every 30 seconds per Shield. Snapshot exposes current reasons, rates and cumulative early-close/rejection counters. These observations never change attack state or create a ban.

Connections are released and counted once; TLS wrappers use the existing unwrapping path. Trusted proxy peers are excluded from early-close measurements. Origin responses and gateway 5xx failures are excluded from security-rejection counts. This does not count every pre-parser HTTP failure: Go can enter StateActive for malformed input, and checks preceding Shield.Admit are outside its completion accounting.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change.

## References

- ADR-0071: Carnical flood protection
- ADR-0073: Carnical kernel packet guards
- [Go connection states](https://pkg.go.dev/net/http#ConnState)
- [Suricata thresholding](https://docs.suricata.io/en/suricata-8.0.4/rules/thresholding.html)
- [CrowdSec HTTP probing scenario](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/http-probing.yaml): response provenance and context matter; this change does not implement its distinct-path scanner scenario.
- [Flood protection guide](../../carnical/docs/ddos.md)
