# Carnical documentation

Start with the guide for the task at hand. Setup guides explain what to do; references give the
exact contracts, limits and integration points. Dated reports preserve the evidence from their
recorded build and configuration.

## Deploy a website

| Task | Guide |
| --- | --- |
| Try the proxy locally | [Operator guide](../README.md#run-it) |
| Configure a site, authenticate its origin and change DNS | [Website setup](website-onboarding.md) |
| Run replicas, health probes, shutdown or containers | [Availability and deployment](availability-and-deployment.md) |
| Install the Linux service and host controls | [Deployment files](../deploy/README.md) |

## Tune protections

| Task | Guide |
| --- | --- |
| Understand what the proxy enforces | [Proxy reference](proxy-reference.md) |
| Tune parsing and body/query limits | [Request formats](formats.md) |
| Enforce an OpenAPI contract | [Input hardening](input-hardening.md) |
| Tune floods and inspect IDS alerts | [Flood protection and IDS](ddos.md) |
| Add Linux packet filtering | [Network protection](network-protection.md) |
| Connect CrowdSec IP bans | [CrowdSec](crowdsec.md) |
| Review host confinement and zone boundaries | [Host hardening](hardening.md), [segmentation](segmentation.md) |

## Build an integration

These packages need an application to wire them into the proxy and supply storage, credentials and
management endpoints. They are not services automatically started by `cmd/carnical`.

| Integration | Reference |
| --- | --- |
| API schemas, discovery, learning and quotas | [API guard](apiguard.md) |
| Signed configuration and customer policy | [Configuration and policy](config-and-policy.md) |
| Authenticated management and event feed | [Control API](control-api.md) |
| Virtual-patch matching and rule conversion | [Virtual patches](vpatch.md) |
| Backend and UI contracts | [Backend integration](backend-integration.md), [backend compatibility](backend-compat.md) |
| Coraza library and development tools | [Engine integration](../../docs/engine-integration.md) |

## Review the evidence

| Record | What to look for |
| --- | --- |
| [Security findings](../../docs/security-findings.md) | Confirmed fixes, remaining concerns and validation boundaries. |
| [Security tooling](../../docs/security-tooling.md) | CI categories, scanner scope, exceptions and local commands. |
| [Protection validation](enterprise-validation.md) | Dated regression/live results and the conditions used. |
| [Network validation](network-validation.md) | Kernel, small/large deployment and flood-latency measurements. |
| [Attack coverage](attacks.md) | The responsible protection layer and application-dependent limits. |
| [WAF research](enterprise-waf-research.md) | Vendor/standards references that informed the design. |
| [Architecture decisions](../../docs/adr/README.md) | Why a design was chosen and which alternatives were considered. |

Historical load runs:

- [500,000 requests](loadtest-2026-10-06.md).
- [750,000 requests with six additional categories](loadtest-750k-2026-10-06.md), with [admitted templates](loadtest-750k-admitted-2026-10-06.md).
- [750,000 requests with variants](loadtest-750k-variants-2026-10-06.md), with [admitted variants](loadtest-750k-variants-admitted-2026-10-06.md).
- [Post-hardening run](loadtest-hardening-2026-10-06.md), with [admissions](loadtest-hardening-admitted-2026-10-06.md).

For a technical review, follow a guide's configuration names to the linked source, then check the
matching tests and CI evidence. A refusal count measures request admission; it does not prove that
every admitted input can exploit an application.
