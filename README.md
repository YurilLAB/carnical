<h1>
  <img src="docs/assets/carnival-logo.png" align="left" height="46px" alt="Carnical logo"/>&nbsp;
  <span>Carnical - Web Application Firewall</span>
</h1>

[![Regression Tests](https://github.com/YurilLAB/carnical/actions/workflows/regression.yml/badge.svg?branch=edge-crs)](https://github.com/YurilLAB/carnical/actions/workflows/regression.yml)
[![Security Review](https://github.com/YurilLAB/carnical/actions/workflows/security.yml/badge.svg?branch=edge-crs)](https://github.com/YurilLAB/carnical/actions/workflows/security.yml)
[![OWASP Core Rule Set v4](https://img.shields.io/badge/OWASP%20CRS-v4-brightgreen)](carnical/README.md)

Carnical is a web application firewall written in Go, built on [OWASP Coraza](https://github.com/corazawaf/coraza)
and the OWASP Core Rule Set (CRS). It sits between visitors and a website's origin server,
checks HTTP traffic, and forwards accepted requests to the application.

It adds a standalone reverse proxy, API validation, flood protection, CrowdSec bans,
monitoring, and deployment tools around the Coraza engine. Carnical is an independent project.

## What it protects

| Protection | What Carnical adds | Guide |
| --- | --- | --- |
| Web requests | CRS rules, supplemental injection rules, strict body/query parsing and upload checks | [Request validation](carnical/docs/formats.md) |
| APIs | Supported OpenAPI contracts, GraphQL checks and optional per-client quotas | [API contracts](carnical/docs/input-hardening.md) |
| Floods and network abuse | Connection and request budgets, distributed-flood detection and bounded IDS alerts | [Flood protection and IDS](carnical/docs/ddos.md) |
| IP bans | Optional CrowdSec Local API decisions, checked on every HTTP request | [CrowdSec](carnical/docs/crowdsec.md) |
| Linux hosts | Optional nftables packet guards and Landlock/seccomp process restrictions | [Network protection](carnical/docs/network-protection.md), [host hardening](carnical/docs/hardening.md) |
| Deployment | Site files, origin mutual TLS, startup checks, private health probes and graceful shutdown | [Website setup](carnical/docs/website-onboarding.md), [availability](carnical/docs/availability-and-deployment.md) |

Signed configuration, customer policies, the authenticated control API and virtual patches
are also available as [integration libraries](carnical/docs/README.md#build-an-integration).
The standalone proxy does not start those services automatically.

## Run locally

Use Go 1.26.9 or later with the security fixes for your release branch; Go 1.27 requires
1.27.2 or later. The workspace and CI use Go 1.26.9.
The proxy runs on Linux, Windows and macOS. Kernel filtering and process confinement require Linux.

With a test application already listening on `127.0.0.1:8081`:

```sh
git clone https://github.com/YurilLAB/carnical.git
cd carnical/carnical
go run ./cmd/carnical -upstream http://127.0.0.1:8081 -origin-allow 127.0.0.1/32
```

Visit `http://127.0.0.1:8080`. By default, CRS uses `detect`, format checks use `monitor`,
and flood protection is `on`. Review legitimate traffic and tune exclusions before enabling
content blocking with `-mode block -formats-mode block`.

Proxy safety checks, flood limits and configured CrowdSec bans enforce independently of
content-detection mode. The loopback allowance above is for this local example.
See the [operator guide](carnical/README.md) for site files and configuration.

## Protect a website

1. Give the operator the website names and current origin address, and complete the domain-ownership check.
2. Once the operator has tested certificates, origin authentication and forwarding, point every advertised A and AAAA record at the supplied Carnical addresses or supported DNS target. Save the previous records for rollback.
3. Check pages, login, forms, uploads and APIs through the protected domain. Report blocked legitimate requests to the operator.

Clients do not need to install the WAF or change application code. The operator keeps a separate
origin address and restricts it to approved WAF identities and ingress paths. DNS changes alone
cannot prevent direct access to a public origin.
The [website setup guide](carnical/docs/website-onboarding.md) covers both sides of the handover.

## Limits and validation

Tests cover varied attacks, legitimate traffic, Linux/Windows behavior and live deployments.
The [security review](docs/security-findings.md) and [validation records](carnical/docs/README.md#review-the-evidence)
describe the tested configurations and remaining limits.

The proxy cannot replace application authorization, patch application bugs, or recover a saturated
network link. Upload checks are not a general malware scanner. WebSocket inspection and schema-aware
gRPC/Protobuf inspection are not provided. Quotas, flood state and caches are local to each process;
replicas need an explicit [state and capacity plan](carnical/docs/availability-and-deployment.md#state-and-replica-contracts).

## Coraza core usage

The engine keeps the `github.com/corazawaf/coraza/v3` import path. The workspace builds Carnical
against the local engine. See [engine integration](docs/engine-integration.md) for a Go example,
HTTP integration tests and development commands.

### Build tags

These engine options are intended for advanced integrations. Compatibility across minor versions is not guaranteed.

| Tag | Effect |
| --- | --- |
| `coraza.disabled_operators.*` | Exclude a named operator, for example when registering a replacement. |
| `coraza.rule.multiphase_evaluation` | Evaluate variables in the phases when they become available. |
| `coraza.no_memoize` | Disable the shared regex/Aho-Corasick compilation cache. |
| `no_fs_access` | Disable filesystem-dependent features, including file body buffers. |
| `coraza.rule.case_sensitive_args_keys` | Match ARGS keys with case sensitivity. |
| `coraza.rule.no_regex_multiline` | Disable implicit multiline matching for `@rx`. |
| `coraza.rule.mandatory_rule_id_check` | Require an `id` action on every SecRule/SecAction. |
| `coraza.rule.rx_prefilter` | Default `SecRxPreFilter` to `On` for testing; use the directive for runtime configuration. |

Memoization is enabled by default. Integrations that reload rules should release old WAF instances
through `experimental.WAFCloser`, or disable memoization with the build tag.

### FIPS mode

Go's FIPS mode is detected at runtime. `t:md5` and `t:sha1` remain registered, but evaluation
returns an error and retains the original input when FIPS mode is enabled. The rule still runs,
so its result may change. Review affected rules before deployment; see the
[full FIPS behavior](docs/engine-integration.md#fips-mode).

## Development

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) before changing the engine.
Run `go run mage.go -l` for development commands and `go run mage.go check` for engine tests and lint.
The [security tooling guide](docs/security-tooling.md) explains automated checks and their reports.

## Security

Report vulnerabilities privately. See [SECURITY.md](SECURITY.md) for reporting instructions and
[current findings](docs/security-findings.md) for reviewed issues and validation limits.

## Contributors and attribution

Carnical builds on Coraza and the CRS. Thanks to Juan Pablo Tosso and the Coraza contributors,
the OWASP Core Rule Set team, and Ivan Ristić for ModSecurity.

<a href="https://github.com/corazawaf/coraza/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=corazawaf/coraza" alt="Coraza contributors" />
</a>

Contributor image supplied by [contrib.rocks](https://contrib.rocks).
