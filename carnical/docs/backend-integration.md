# Integrate a backend or customer UI

Carnical supplies libraries for customer policy, signed configuration, management and monitoring. An
integration service must provide storage, credentials, deployment coordination and UI behavior. The
standalone CLI forwards to one origin; it does not provide a hosted multi-tenant control plane.

## Package boundaries

| Need | Package and reference |
| --- | --- |
| Validate customer settings and compile rules | [`policy`](../policy/); [policy reference](config-and-policy.md#part-2-the-customer-policy-policy) |
| Verify signed tenant/edge configuration | [`config`](../config/); [configuration reference](config-and-policy.md#part-1-the-configuration-channel-config) |
| Authenticate and authorize management requests | [`control`](../control/); [control API](control-api.md) |
| Publish a signed monitoring feed | [`control/feed`](../control/feed/); [feed contract](control-api.md#11-the-feed) |
| Check API descriptions, discovery and learning | [`apiguard`](../apiguard/); [API guard](apiguard.md) |
| Load virtual patches | [`vpatch`](../vpatch/); [virtual patches](vpatch.md) |
| Audit zone/tenant boundaries | [`audit`](../audit/); [segmentation](segmentation.md) |

## Policy flow

1. Authenticate the customer in the UI and derive the tenant from the session.
2. Submit through the authenticated control API. Validate roles, locks, tenant access and weakening changes.
3. Store an atomic revision and publish the JSON policy in a signed envelope.
4. At the edge, verify the key, tenant, audience, time and persistent sequence before decoding/compiling.
5. Publish the complete replacement WAF only after validation. Keep the last valid configuration if compilation fails.
6. Close the old WAF after its active requests finish.

The control [interfaces](control-api.md#what-the-owner-has-to-connect) define required store,
validator, publisher, event and hostname behavior. In a replicated service, coordinate durable
rollback floors and idempotency; local locks/caches do not provide distributed guarantees.

## Events and compatibility

Collect final request outcomes, rule IDs, timing and policy revision per tenant. Keep monitored
events distinct from blocked events. Define retention, privacy and paging before wiring a feed.
Default WAF logs omit request content; detailed logs require an explicit privacy decision.

For an existing PHP/Python console, use the [compatibility reference](backend-compat.md). Its field
contracts and external-backend findings come from a dated survey. Verify the actual consumer before
treating a compatibility claim as current.

## Hosted deployment requirements

- Verify hostname ownership before routing or issuing a certificate.
- Keep every store, event stream and policy scoped to an immutable tenant identity.
- Authenticate the origin and close alternate ingress paths; [website setup](website-onboarding.md) covers one site.
- Review [replica state](availability-and-deployment.md#state-and-replica-contracts), key rotation and rollout/rollback.
- Test [tenant boundaries](segmentation.md) against the actual hosted implementation, with positive controls.

External signature packs need their own conversion review. PCRE features such as lookarounds, atomic
groups and possessive quantifiers are not Go/RE2 equivalents. Inspect importer warnings and test
retained/lost constraints before allowing a converted rule to block.

The [original proposal](backend-integration-proposal-2026-10-05.md) records the earlier design
discussion. It is historical context, not a list of current CLI features.
