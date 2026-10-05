# Connecting Carnical to our backend and web UI

Status: proposal for decision, 5 October 2026. Nothing here changes Coraza or the CRS. It lists what is left to build around them.

## The idea

We already have a complete customer control model. It lives in the PHP site console and is described in `firewall/CONSOLE.md`
(section 13): one settings table (`firewall/engine/src/Settings.php`) that gives every setting a type, a range, a group, the roles
that may change it, whether weakening it asks for the password, and whether the host has locked it. Around it sit the policy history
and restore, export and import, the audit trail, the events and traffic pages, the advice table, and the signed feed that Harbourline
reads (feed version 1, HMAC-signed; `docs/firewall-monitoring-plan.md`).

So the work is not to design a new control model. It is to make Carnical **another engine behind that model**: it reads the same
site policy, writes the same events, answers the same feed. Then the owner console, the fleet reader, the monthly reports and the advice
table keep working, and customers see the same settings whichever engine protects their site.

## What exists today (built, tested)

| Layer | State |
|---|---|
| Engine and rules | Coraza v3.8.1 with OWASP CRS 4.30.0, checked against the CRS signing key. |
| Rule set settings | `crs.Settings`: mode, paranoia level, thresholds, body limit, allowed methods, response inspection, raw before/after directives. |
| Reverse proxy | One site, one upstream, hardened so the application receives what the WAF inspected. |
| Update tool | Fetches and verifies a new CRS release. |

## What is missing

| Layer | Needed for |
|---|---|
| Site policy compiler | Turning the customer's settings into Coraza directives. |
| Site registry and hot reload | Many sites on one edge, changed without a restart. |
| Events, traffic and the feed | The events page, traffic charts, reports, and Harbourline's monitoring. |
| Address lists, bans and IDS/IPS | The lists, bans and behaviour detections the console already promises. |
| Config delivery | Signed per-site configuration from the backend to each edge. |
| Hub and web UI for hosted sites | Where customers sign in, if hosted sites are not to use the PHP console. |

## How each customer control maps onto Coraza

"Native" means Coraza or the CRS already does it. "Adapter" means a small amount of code that turns our setting into directives.

| Our setting | Coraza mechanism | Status |
|---|---|---|
| `mode` block / monitor / off | `SecRuleEngine On / DetectionOnly / Off` | Native (done in `crs.Settings`). |
| `threshold` | `tx.inbound_anomaly_score_threshold` | Native (done). |
| `sensitivity` relaxed / standard / strict | Paranoia level plus threshold. Ours is about signature confidence, the CRS's is about paranoia level, so they are not the same thing. Proposed presets: relaxed = level 1 with threshold 8, standard = level 1 with threshold 5, strict = level 2 with threshold 5. | Decide, then adapter. |
| `block_oversize` | `SecRequestBodyLimitAction Reject` | Native (always on). |
| Rule groups (16 categories) set to off | `SecRuleRemoveByTag attack-sqli` and the other CRS tags | Adapter: a table from our categories to CRS tags. |
| Rule groups set to log only | None directly. The category's score has to be taken off the request's total before the blocking rule 949110 reads it. | Adapter, a little involved. |
| `disabled_signatures` | `SecRuleRemoveById` | Adapter. |
| `overrides` (score 0 to 10, or log only) | CRS rules carry their score in their own actions, so a per-rule score cannot be set from outside. "Off" works; a custom score would need the rule rewritten. | Decide: offer off and log only, and drop per-rule scores for CRS rules. |
| `exclusions` (path, categories, parts) | `ctl:ruleRemoveTargetByTag` and `ctl:ruleRemoveById` under a path condition, which is the CRS's own exclusion model (already tested in `crs_test.go`) | Adapter: build directives from validated fields, never from text typed by a customer. |
| `allow_ips`, `block_ips`, `allow_paths` | `@ipMatch` and `@beginsWith` rules, or better a step before the WAF so the order (allow, ban, block list, then inspection) matches the PHP firewall exactly | Adapter in the proxy. |
| `reputation` lists | `@ipMatchFromFile` | Adapter; the Python pipeline already fetches and releases the lists. |
| Custom rules (up to 200) | A generated `SecRule` with an id in a reserved range, a score added to the anomaly total, and a Go regular expression | Adapter plus validation. "Try a request" is a made-up request run through the same engine, which Coraza's transaction API supports. |
| `outbound.inspect`, `outbound.max_kb` | `SecResponseBodyAccess`, `SecResponseBodyLimit`, the CRS response rules | Native (done as `InspectResponses`). |
| IDS/IPS (`ips.*`: floods, scans, enumeration, spraying, bans) | Nothing: Coraza has no ban store or behaviour detection. It can supply the signals (each rule match) | Build (port the PHP points and ban model to the proxy). |
| `log.*`, `stats.*`, `timezone`, `log.truncate_ip` | Our own event and traffic records; Coraza only reports rule matches | Build. |
| `portal.locked`, roles, "asks for the password", history, audit | Entirely backend and UI; the edge only enforces the signed policy it is given | Not the edge's job. |

Two cautions about rules from outside the CRS:

- Our verified signature library (about 1,500 rules, many of them CVE-specific virtual patches that the CRS does not carry) is written
  for PCRE. Coraza uses Go's regular expressions, which reject possessive quantifiers (`\s*+`), atomic groups and lookarounds, and
  several of our patterns use them. Converting means rewriting those patterns and checking each rule, which is doable but is its own
  piece of work. Decision for later: convert, or leave the CVE rules to a second path.
- The CRS's scores are fixed by severity (critical 5, error 4, warning 3, notice 2). Our per-signature scores of 0 to 10 do not carry over.

## Data flows

**Policy in.** The backend holds each site's policy in the form the console already exports and imports (`site_firewall_policy`). It
signs it as an envelope (Ed25519, role `config`, a rising sequence number), and the edge fetches it, verifies it, compiles a new WAF
for that site off the request path, and swaps it in whole. The old WAF is closed once its requests finish. Compiling the whole rule set
takes about 40 ms (compiled patterns are shared between WAFs), so a change is in force within seconds. A bad policy is refused whole
and the last good one stays, as the console already refuses a bad change whole.

**Events out.** Today the proxy sees each rule match but not the outcome of the request. To produce the events the console shows (what
happened, to whom, which page, which signatures, blocked or only noted, how the score added up) the proxy should drive Coraza's
transaction API directly instead of the packaged middleware, so it can record the final decision, the anomaly score (`tx.*` variables),
the matches and the timings, and then emit one record per request that matters in the existing log format. CRS tags map onto our
categories, so `advice.yaml` and the reports work unchanged.

**Traffic and the feed.** Per-site, per-minute sums (requests, outcomes, status classes, latency histogram, top pages) as the PHP
firewall writes them, and the feed endpoint as specified for version 1, so the fleet reader and the monthly report read an edge exactly
as they read a PHP site.

**Hosted specifics** (certificates for each customer hostname, origin lockdown, two edges and failover, tenant isolation, honest
claims about denial-of-service) are unchanged from the hosted-edge design written on 4 October (archived in
`D:\Dev\_removed-firewall-go-2026-10-05\main-checkout-go-and-docs.zip` as `docs/hosted-edge-design.md`). Its parts about our own Go
engine are obsolete; its proxy, hub, certificate and origin parts still describe what has to be built.

## Suggested order

Each step is small, ships on its own, and leaves Coraza and the CRS alone.

1. **Site policy compiler** (`carnical/policy`): the site's policy in, a `crs.Settings` and directives out, with the checks the PHP schema
   makes. Covers mode, sensitivity presets, rule groups, exclusions, lists, disabled ids and custom rules, and the "try a request" check.
2. **Site registry** (`carnical/site`): sites chosen by hostname, atomic swap, a local signed file as the first config source.
3. **Events, traffic and the feed**: the proxy driving the transaction API, the event and minute records, the version 1 feed. After this
   the existing owner console reads the edge.
4. **Lists, bans and IDS/IPS**: the points and ban model, with Coraza's matches as the signals.
5. **Hub and web UI for hosted sites**, if hosted sites are not to use the PHP console.
6. **Signature library**: conversion of our CVE rules to something the engine accepts.

## Decisions needed

1. **Which backend does the edge talk to first?** My recommendation is the existing one: read the console's policy format and write its
   events and feed, so the owner console and fleet reader work immediately, and build a hosted hub later. The alternative is the new
   hub from the hosted-edge design first. Your last message points at the first; please confirm.
2. **Sensitivity.** Keep our three levels as presets over paranoia level and threshold (proposed above), or show customers the CRS's
   paranoia level directly?
3. **Per-rule scores.** Drop them for CRS rules (offer on, log only, off), or rewrite rules to carry a customer's score?
4. **Our CVE signature library.** Convert it, or keep it out of the edge for now?
5. **Licence** for the code we add in `carnical/`.

## Not now

More security work, as agreed. Two items from earlier reviews are launch blockers for hosted customers and are listed so they are not
forgotten: an origin address check at connection time (customers type their own origin addresses, so the edge must refuse loopback,
private and cloud-metadata destinations), and tenant isolation of events and policy.
