# ADR-0077: Reusable Carnical site configuration and deployment preflight

- **Status:** proposed
- **Date:** 2026-10-08 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Operators currently repeat a long flag list to put the standalone reverse proxy
in front of a website. Settings must be checked consistently before traffic is
cut over, without binding a listener or requiring a systemd inherited descriptor.

## Decision Drivers

- Keep one set of flag types, defaults and runtime policy validators.
- Provide a small, reviewable file usable locally and by the hardened service.
- Preserve explicit operator overrides and origin/TLS safety checks.
- Distinguish local configuration validation from live deployment validation.

## Considered Options

- Add a second typed runtime configuration with independent defaults.
- Continue documenting only long command-line invocations.
- Load a bounded typed flag document into the existing registered flags.

## Decision Outcome

Use an operator-owned version-1 JSON object with exact flag names and JSON
scalar types. Refuse duplicate and unknown fields, nulls, nested flag values,
invalid numeric/duration representations and files over 64 KiB. Explicit CLI
flags win, including false boolean values. Management actions stay on the CLI.
Paths retain existing working-directory semantics; production examples use
absolute paths. No shell interpolation or execution is introduced.

Run local checks through the actual startup configuration and rule compilation
path, returning before listener acquisition and sandbox application. Skip the
CrowdSec network snapshot in check mode; serving still requires it. An explicit
origin probe adds a ten-second DNS/TCP/TLS check with the existing origin policy
at resolution and dial time, system roots, and no HTTP request.

The hardened service runs the local check with its serving arguments before
starting. Its socket passes one dual-stack descriptor, matching the CLI contract.
Client cutover remains an administrator-coordinated DNS/TLS/origin-access operation.

## Technical Discussion

No substantive technical discussion recorded on a repository PR thread;
maintainer review of the configuration surface is pending.

## Participants

- Repository owner — requested easier operator and client deployment.
- Coding agent — implementation and validation; maintainer review pending.

## Consequences

- **Positive:** repeatable site settings, early failures and a documented handover
  without a second runtime policy schema or a new dependency.
- **Negative / follow-up:** configuration is still operator authority, not a
  customer policy API. One process protects one upstream. A passing check does
  not prove port ownership, kernel confinement, CrowdSec authentication, origin
  application health or attack coverage. Certificates need external renewal;
  settings and certificates are loaded on restart.

## References

- [Website onboarding](../../carnical/docs/website-onboarding.md).
- [Go flag types and syntax](https://pkg.go.dev/flag).
- [systemd socket semantics](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml).
