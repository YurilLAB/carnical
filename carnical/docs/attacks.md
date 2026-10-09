# Attack coverage and boundaries

Carnical combines protocol checks, CRS rules, format/API validation, flood protection and optional
host controls. The table identifies the layer to review for each attack class. A labelled attack
reaching an inert test origin is an admission result; exploitation still depends on the application.

## Protection layers

| Attack class | Relevant protection | Review boundary |
| --- | --- | --- |
| SQLi, XSS, command/template injection, traversal | CRS plus [supplemental rules](input-hardening.md) | Signatures and parsing do not replace safe application sinks. |
| Request smuggling/desynchronization | Framing checks, target preservation, separate origin connections for body-bearing requests | Validate the actual origin/proxy chain. |
| Ambiguous paths, Host and forwarding headers | [Proxy checks](proxy-reference.md#forwarding-and-identity), hostname allowlist and verified client identity | Trust only actual forwarding peers. |
| Malformed/ambiguous JSON, XML, multipart and forms | [Format policy](formats.md) | Defaults monitor; use `-formats-mode block` to enforce. |
| Compressed-body ambiguity/exhaustion | Refuse encoding by default; optional bounded decoding followed by final body/upload checks | Independent proxy and decompression limits all apply. |
| GraphQL method/envelope/cost abuse | Selected-operation, transport, fragment and syntax-budget checks in [formats](formats.md#verdicts) | No schema-weighted resolver cost or authorization. Persisted queries need origin method checks. |
| Undeclared API input | Supported explicit [OpenAPI contracts](input-hardening.md#executable-api-contracts) | CLI enforcement rejects unsupported contracts; full discovery/learning is a library integration. |
| API/login volume | Optional verified-client quotas and [API guard](apiguard.md) budgets | Local state; review saturation/outage behavior and replicas. |
| Script uploads | Filename and PHP/ASP/JSP marker checks | Not a malware/archive scanner; the origin must not execute untrusted uploads. |
| WordPress upload/cache scripts and XML-RPC | `-wordpress` restrictions and login limits | Application/plugin patches and scoped virtual patches remain necessary. |
| Cache deception/content sniffing | Response cache checks, `nosniff` and banner removal | Review the downstream cache and application headers. |
| Origin-address abuse | Dial-time address restrictions | Does not constrain the application's own outbound requests. |
| Floods and early TCP abuse | [Shield](ddos.md), connection budgets and IDS signals | Alerts are observations; packet/link protection needs separate layers. |
| SYN, malformed TCP, UDP/443 and echo floods | Optional [Linux packet policy](network-protection.md) | Host deployment and measured budgets required; no upstream bandwidth guarantee. |
| Known malicious IP/CIDR sources | Optional [CrowdSec bans](crowdsec.md) | LAPI outage/expiry rules apply; HTTP bans do not replace packet filtering. |
| Expensive WAF evaluation | Body, concurrency and phase-time limits | Keep limits suitable for legitimate uploads and origin capacity. |
| Post-compromise host activity | [Confinement and host controls](hardening.md) | Kernel/runtime validation and patching remain necessary. |

Response inspection is optional. Interim 1xx responses are removed so enabled inspection sees the
final response. Dangerous engine program/network operators are refused by the standalone proxy's CRS
builder. See [proxy behavior](proxy-reference.md) for details and defaults.

## Application responsibilities

The application must enforce object/function authorization, credential validity, safe field binding,
atomic business operations and guarded outbound fetches. Schema-valid input can still violate those
rules. Uploaded content must not become executable, and diagnostic/admin routes need their own
authentication and access policy.

Application-specific vulnerabilities require application patches or reviewed, scoped virtual
patches. Carnical's [virtual-patch library](vpatch.md) needs a separately supplied rule pack and
integration; the CLI does not install a universal plugin/CVE deny-list.

## Evidence

Use the [validation index](README.md#review-the-evidence) for fixed-corpus results, admitted attack
inventories and false-positive observations. The [historical
research](attack-research-2026-10-05.md) preserves the original sources and backlog without treating
its old missing-feature notes as current.
