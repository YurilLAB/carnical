# Enterprise WAF capabilities and implementation priorities

Research date: 2026-10-05. Sources below are vendor documentation or standards. Descriptions indicate capabilities, not measured comparative effectiveness. All validation here uses the local private Carnical build, not vendor services or production customer traffic.

| Vendor capability | Primary source | Carnical implication |
|---|---|---|
| Wallarm enforces uploaded API specifications as a positive security policy, including request schema validation. | [API specification enforcement](https://docs.wallarm.com/api-specification-enforcement/overview/) | Treat explicit schemas as authoritative; refuse unsupported constructs instead of quietly allowing them. The existing untracked `apiguard` work needs its own review and deployment integration. |
| F5 supports GraphQL syntax, introspection and size/structure/cost/batch controls, with per-profile enforcement. | [GraphQL protection](https://docs.nginx.com/waf/policies/graphql-protection/) | Preserve existing bounded parsing and fragment arithmetic; enforce operation selection and GET safety; add a total budget across a batch as well as individual document limits. |
| Fastly provides GraphQL inspection signals and request/rate-limit rules with configurable client identification. | [GraphQL inspection](https://www.fastly.com/blog/introducing-graphql-inspection-for-the-fastly-next-gen-waf), [rules API](https://www.fastly.com/documentation/reference/api/ngwaf/rules/) | Use verified proxy client identity for abuse controls; avoid trusting arbitrary visitor-supplied forwarding or identity headers. Existing WordPress login limits do not cover every API endpoint. |
| F5 protects gRPC using an attached interface definition, parsed messages and size/unknown-field restrictions. | [Policy configuration](https://docs.nginx.com/waf/policies/configuration/) | Binary support must be explicit and schema-aware. Carnical's opaque-type allowance only provides a byte limit; it does not constitute gRPC or Protobuf inspection. |

## Delivered and next work

1. GraphQL operation/protocol checks: retain operation metadata, reject ambiguous selection and repeated protocol parameters, block selected mutations over GET, HEAD, OPTIONS and TRACE. Keep legitimate mixed-operation queries, ordinary preflights and POST mutations working.
2. Executable integration: expose format monitoring/enforcement and validated per-site policy loading; bounded request decompression is explicit. Load policy before listening or confinement. Existing parsing supports JSON, XML/SOAP, GraphQL, URL-encoded forms, multipart, NDJSON, text and optional YAML.
3. Aggregate GraphQL budgets: total selected-operation fields, aliases and directives across the request have explicit ceilings, preventing a permitted batch from multiplying the individual budget. Defaults are 1000 fields, 40 aliases and 100 directives; each can be configured with a bounded positive limit. These syntax counts do not substitute for schema-weighted resolver cost.
4. API abuse limits: configurable route prefixes share a verified-client sliding-minute budget before body processing, with separate login quotas, bounded event/identity state, fail-closed saturation and retry/cache headers. This is single-process enforcement; distributed state remains a separate integration.
5. Strict policy loading: duplicate/nullable settings and case aliases fail before startup, with exact JSON tags and a shared size bound.
6. URL query validation: all endpoints and methods use bounded parameter parsing with independent query limits and rules, preserving valid forwarded bytes. Malformed escapes, raw semicolons, invalid UTF-8, NULs and prototype names are refused in enforcement mode; ordinary duplicates remain monitored unless the operator selects blocking.
7. Complete and review the pre-existing API-policy/control work independently: OpenAPI import fidelity, strict authorization/credential validation, signed updates, origin-observed learning and policy rollback. These untracked files were preserved and are not included in these commits.

The proxy cannot enforce object-level application authorization or deduce a persisted GraphQL query's operation without the origin's registry. Schema-aware gRPC, streaming WebSockets, distributed rate-limit state and TLS client authentication on application routes remain distinct projects. Listing them as gaps avoids silently representing opaque passthrough as inspected traffic.

## Standards used

- [GraphQL September 2025: operation selection and validation](https://spec.graphql.org/September2025/)
- [GraphQL over HTTP: GET method safety and parameter encoding](https://http-spec.graphql.org/draft/#sec-GET)
- [HTTP safe methods](https://httpwg.org/specs/rfc9110.html#safe.methods)
- [Express automatic HEAD dispatch to GET handlers](https://expressjs.com/en/4x/api/router/#router-method)

See [validation](enterprise-validation.md) for observed behavior and environment limitations.
