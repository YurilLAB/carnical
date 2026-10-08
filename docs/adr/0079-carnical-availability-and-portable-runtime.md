# ADR-0079: Carnical readiness, bounded draining and portable runtime

- **Status:** proposed
- **Date:** 2026-10-08 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

The standalone edge has no deployment readiness interface, and its shutdown
budget is a fixed ten seconds. Operators need checked rolling changes without
exposing a visitor route that bypasses inspection or treating a stale security
dependency as an unrecoverable process failure. The deployment artifacts
previously target one Linux/systemd machine.

## Decision Drivers

- Separate process liveness, security readiness and origin application health.
- Preserve complete inspection and decision refresh during routing propagation.
- Bound the entire stop operation and report unfinished shutdowns.
- Keep Linux-only confinement distinct from portable HTTP protections.
- Avoid dependencies and misleading fleet-wide state guarantees.

## Considered Options

- Add visitor-listener health exclusions and origin checks in every probe.
- Offer only supervisor-specific deployment checks without readiness.
- Use a separate optional numeric-loopback HTTP listener and executable probes.

## Decision Outcome

Choose the private listener. Exact GET/HEAD health targets have no control or
forwarding operation; host/target/body checks and finite I/O budgets apply.
The executable probe connects only to numeric loopback, refuses redirects and
environment proxies, and exits without compiling CRS or requiring an origin.

Publish readiness only after the visitor Serve loop reaches Accept. Required
stale CrowdSec state withdraws readiness; explicitly configured fail-open
retains that operator policy. Liveness remains independent of shared dependency
availability. Neither probe performs origin network I/O.

On a stop signal, mark draining before an optional propagation delay. Keep
CrowdSec refresh alive during that delay and active-request shutdown. A single
deadline covers delay and HTTP draining; on expiry close ordinary connections
and report failure. The CLI's optional upgrades retain their existing
uninspected behavior and terminate on process exit without WebSocket close
guarantees.

Ship a digest-pinned builder and non-root scratch runtime containing system
trust roots, with a read-only/capability-free Compose example. Exercise the actual
container and native processes in CI. Document Linux/Windows/macOS support,
cross-build limits, per-replica bouncer credentials, process-local quotas and
challenge state, and regular-file provisioning for Kubernetes projections.

## Technical Discussion

No substantive technical discussion recorded on a repository PR thread;
maintainer review of lifecycle and deployment choices is pending.

## Participants

- Repository owner — requested availability hardening and broader deployment.
- Coding agent — implementation and validation; maintainer review pending.

## Consequences

- **Positive:** consistent private probes, bounded rolling-stop behavior,
  dependency recovery without restart loops, portable service packaging and
  explicit operational contracts without new Go dependencies.
- **Negative / follow-up:** readiness is not an application health or capacity
  guarantee. The CLI still has one origin and process-local state. Global quotas,
  distributed control replay/rollback stores, production failover/capacity,
  native macOS and arm64 execution, and a live Kubernetes cluster remain
  deployment validation work. Certificates/configuration load on restart.

## References

- [ADR-0074: CrowdSec](0074-carnical-crowdsec-ip-decisions.md).
- [ADR-0077: Site configuration](0077-carnical-site-configuration.md).
- [ADR-0078: Origin authentication](0078-carnical-origin-authentication.md).
- [Availability and deployment guide](../../carnical/docs/availability-and-deployment.md).
- [Go Server.Shutdown](https://pkg.go.dev/net/http#Server.Shutdown).
- [Kubernetes probes](https://kubernetes.io/docs/concepts/workloads/pods/probes/).
