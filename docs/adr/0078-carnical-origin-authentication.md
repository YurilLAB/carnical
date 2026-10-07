# ADR-0078: Authenticated Carnical origin connections

- **Status:** proposed
- **Date:** 2026-10-08 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Website onboarding needs an authenticated path from the edge to the application.
A DNS cutover and a trusted HTTPS server certificate alone do not authenticate
the edge to a public origin. Operators also need to distinguish connection
checks from actual HTTP acceptance of a client certificate.

## Decision Drivers

- Keep server certificate and configured-origin hostname verification mandatory.
- Let origins authorize a specific edge identity without trusting visitor headers.
- Reuse the existing origin address policy at resolution and dial time.
- Test the shipped origin configuration against a running WAF and actual NGINX.

## Considered Options

- Use an HTTP secret header for origin access.
- Rely on origin IP restrictions alone.
- Combine per-site origin mutual TLS and identity authorization with network restrictions.

## Decision Outcome

Support structured origin trust roots and a fixed client certificate in the
proxy configuration, with bounded regular-file loading in the CLI. Require
HTTPS, a currently valid client-authentication certificate and matching key.
Snapshot certificates and trust roots at construction; the private signer remains
caller-owned and must be immutable and safe for concurrent TLS handshakes.
The origin URL selects the server identity independently of the HTTP Host.

Ship an origin-side NGINX example requiring a verified per-site certificate,
approved serial, expected SNI and allowed HTTP Host. Origin enforcement remains
the operator's responsibility, including closing alternate ingress paths.
Existing HTTPS origins without a client identity remain compatible.

Keep the existing TCP/TLS probe. Add an explicit HEAD probe that never follows
redirects, bounds headers and uses the existing ten-second context. TLS 1.3
client-authentication refusal can surface on a read after the client's handshake
returns. HTTP acceptance therefore needs its own probe. Success does not prove
that the origin requires authentication: live negative controls must establish
that missing and unauthorized identities cannot reach the application.

## Technical Discussion

No substantive technical discussion recorded on a repository PR thread;
maintainer review of the authentication surface is pending.

## Participants

- Repository owner — requested authenticated and validated website onboarding.
- Coding agent — implementation and validation; maintainer review pending.

## Consequences

- **Positive:** visitor headers cannot select the edge's TLS identity; origin
  authorization can distinguish approved edges from other clients of a CA.
  Certificate errors and HTTP refusal fail deployment checks.
- **Negative / follow-up:** PKI, domain ownership, Windows key ACLs, renewal and
  closing alternate origin routes remain deployment responsibilities. Restart
  loads new identity material; existing origin connections must be drained when
  retiring a certificate. This does not add a client login portal or automatic
  domain provisioning.

## References

- Related: [ADR-0077](0077-carnical-site-configuration.md).
- [Website onboarding](../../carnical/docs/website-onboarding.md).
- [NGINX client certificate verification and TLS variables](https://nginx.org/en/docs/http/ngx_http_ssl_module.html).
- [NGINX compound maps](https://nginx.org/en/docs/http/ngx_http_map_module.html).
- [Go TLS configuration](https://pkg.go.dev/crypto/tls).
- [TLS 1.3 certificate authentication](https://www.rfc-editor.org/rfc/rfc8446).
