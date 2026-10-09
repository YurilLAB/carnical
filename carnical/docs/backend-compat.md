# External backend compatibility reference

This records the PHP/Python backend contracts surveyed on 5 October 2026. That backend is separate
from Carnical and is not included in this repository. Its current behavior and the status of its
reported defects have not been revalidated here. **Checked** marks source verification in that
survey; other entries were not executed.

Use [backend integration](backend-integration.md) for current Carnical package boundaries and the
[control/feed reference](control-api.md#11-the-feed) for the implemented feed.

## 1. The cheapest thing that works: a feed

A signed `/feed` that returns empty `events`, `traffic`, `ips` and `marks` lists and a `health`
block already passes the existing reader. Everything else is filling those lists in.

| Item | Contract |
|---|---|
| Request | `GET https://<host>/feed?since=<cursor>&days=1..90`. The path must end in `/feed` and use only `A-Za-z0-9._~/-`. TLS 1.2+ with a public CA, no redirects, 20 s per read, 60 s total, 8 MB cap, `Content-Type: application/json`. |
| Signature | `Authorization: SFW1 key=<16 hex>, ts=<unix>, nonce=<32 hex>, sig=<64 hex>`. `sig` = HMAC-SHA256(32-byte secret, `"SFW1\nGET\n" + raw request target + "\n" + ts + "\n" + nonce`). **Checked** against `PortalFeed.php`. A test vector is in `newsletter/tests/test_waf_fleet.py` (secret bytes 1..32, `/feed?since=abc&days=7`, ts 1791014400, nonce `0123456789abcdef0123456789abcdef`). |
| Errors | 401 for a bad header, unknown or revoked key, clock skew over 300 s, a reused nonce (600 s), or a bad signature. 403 for a scope not allowed. 429 with `Retry-After` past 60 per hour per key. 404 when off. 405 for non-GET. Only correctly signed requests count toward the nonce and rate limits. |
| Frame | `feed: 1`, `generated` (`YYYY-MM-DDTHH:MM:SSZ` only), `site{id: 32 lower-case hex, name, host, engine, bundle, mode, policy_rev, timezone}`, `scopes[]`, `addresses: "cut"|"whole"`, **`cursor` and `more`, always** (see below), then one section per advertised scope. |
| events | at most 2000, newest first. Required `t`, `ev` (`[a-z][a-z0-9_]{0,31}`), `sev` (info, low, medium, high, critical). Optional `id` (an incident number), `ip` (omit rather than `""`), `method`, `path`, `score`, `thr`, `sigs[]{id,s,a,t,n}`, `code`, `why`, `n`, `until`, `user`, `what`, `ua`. At most 60 fields. Events are de-duplicated by a hash of the canonical JSON, so a re-sent event must be byte-identical. |
| traffic | one row per day: `day`, `requests`, `pages`, `visitors`, `attacks`, optional `outcomes`, `status`, `hours[24]`, `ms{p50,p95,max}`, `top_*`. Empty maps must be `{}` or null, never `[]`. Rows are upserted by (site, day). |
| ips | `bans[]` and `offenders[]`, both lists required when advertised; snapshots replaced on every read. |
| health | `updates{...}`, `errors[]` and `notes[]`, all required. **Every entry in `errors[]` is a red standing alert on the owner's Desk**, which is how a failing segmentation check reaches the owner (`segmentation.md`). |
| privacy | `addresses: "cut"` turns IPv4 into `a.b.c.0` and IPv6 into a /48, for events, bans, offenders and marks. |

**A mismatch that exists today (checked).** The PHP feed leaves out `cursor` and `more` when a key
lacks the `events` scope, but the Python reader requires both unconditionally (`feed.py`: `_cursor`
and `_flag`), so such a key reads as "not a feed". Carnical always sends both; the reader or the PHP
should be fixed too.

**One site, one feed, one key.** The register holds one feed URL and one key id per site, they must
be unique across sites, and the first `site.id` seen is pinned (a different one later is reported as
"changed"). A hosted Carnical therefore serves **one feed path and one key per protected site**,
which is also what the tenant rules need (`segmentation.md` T6).

**Unknown fields are dropped silently** by the reader. A Carnical-only field needs a matching change
in `feed.py` before it reaches anything.

## 2. Events, in the vocabulary the reports use

The monthly report and the Desk read event kinds and letters, not free text, so Carnical emits the
same ones.

- **Kinds and severities** (`Log.php`): `block` and `would_block` are high at twice the threshold, otherwise medium. `match`, `budget`, `listed`, `reputation` are low. `error`, `log_full`, `ip_ban`, `campaign`, `leak`, `health`, `flood`, `spraying` are high. `scan`, `enumeration`, `would_ban`, `sig_error` are medium. `ip_unban`, `policy`, `update_ok` are info. `update_failed` is critical for a tamper-class code.
- **Per-request outcome letters** feed the report: `b B L w` count as stopped or would-stop. Monitor mode must emit `would_block`, not `block`.
- **Incident ids** are 12 upper-case hex characters and also appear on the block page.
- **Policy changes** are `policy` events with `user`, `what` and a revision `n`; the monthly "tuned" list reads them.

## 3. Policy: what maps cleanly and what does not

The customer-facing settings model (`firewall/engine/src/Settings.php`, `CONSOLE.md` section 13,
export format `{"site_firewall_policy":1,...}`) is kept as the language customers use. The compiler
turns it into CRS settings.

| Setting | Carnical |
|---|---|
| `mode` block / monitor / off | `SecRuleEngine On / DetectionOnly / Off`. Exact. |
| `threshold` | the CRS inbound anomaly threshold. Exact: CRS scores of 5/4/3/2 match our severities. |
| `sensitivity` (relaxed, normal, strict) | presets over blocking paranoia level and threshold, with a higher detection level used to log what stricter would have found. Approximate; the `stops_at` figure in the console must be computed the same way (`Engine::sensitiveThreshold`). |
| `rule_groups` (17 categories) | filter by CRS tag or rule-id range. Several groups (upload, cve, wordpress, probe) have no CRS tag and need explicit id lists. |
| per-signature `overrides` (score 0 to 10, or log) | **cannot be exact.** CRS has only 5/4/3/2. Either quantise and handle 0, 1 and "log" outside the engine, or drop per-rule scores for CRS rules. See the [historical proposal](backend-integration-proposal-2026-10-05.md#decisions-needed). |
| `exclusions` (path, categories, targets) | `ctl:ruleRemoveTargetByTag` and friends, keyed on the URI. |
| custom `rules` | structured form compiled to SecLang by us, in a reserved id range (`segmentation.md` T7). Raw SecLang is never accepted. The existing console validates with PHP's PCRE; Carnical must validate with RE2. |
| `block_oversize` | `SecRequestBodyLimitAction Reject` or `ProcessPartial`; emit the oversize event with no `sigs`. |
| bans, reputation, allow and block lists, `contact`, `timezone`, stats, log settings | no Coraza counterpart: our own code on top. |

## 4. Signed updates

The existing envelope (`{"role","keyid","payload","sig"}`, Ed25519 over `"sfw-v1\n" + role + "\n" +
payload`, roles `keys`, `engine`, `manifest`) is verifiable from Go's standard library. For
Carnical, ship **a pinned CRS** (already embedded and verified) and take from the owner a **signed
overlay**: per-tenant defaults, reputation lists, retired ids and attribution, on a separate
sequence stream. The configuration channel to the edge is a different signed object
(`segmentation.md` T5) with a different key; it must not be confusable with a release.

The existing bundle path carries CRS only as translated signatures (`CRS-<rid>`) and skips the
libinjection-based rules such as 942100, so it is not a substitute for running CRS itself.

## 5. The advice table

Advice for a block is chosen from the highest-scoring signature's category, which comes from the
library or from the second dash-part of the id (`FW-SQLI-0001` is sqli). `CRS-942100` therefore
resolves to "other". Two ways to fix it:

- emit `CRS-SQLI-942100`-style ids (no owner change; the library match for `CRS-<rid>` is lost), or
- **recommended:** keep `CRS-<rid>` and add a rule-id range table to `advice.yaml`: 941 xss, 942 sqli, 930 lfi, 931 rfi, 932 rce, 933 php, 934 ssrf/other, 944 java, 913 scanner, 920 to 922 protocol; then regenerate `Advice.php` with `python -m brief.waf.advice`.

## 6. Order of work, cheapest first

1. A persisted 32-hex site id and a feed key store (16-hex id, 32-byte secret, scopes, cut or whole, revoke).
2. `/feed` with verification, the limits above and an empty frame including `health`. Use the test vector and the existing `FakeSite` double as the conformance harness.
3. The event writer with severities, incident ids and `policy` events; cursor and paging.
4. Traffic roll-up with the outcome letters.
5. The rule-id category table in `advice.yaml`.
6. Bans and offenders (own code; send empty lists until built).
7. The policy compiler and export/import in the existing format.
8. The signed overlay consumer and the shared update-event codes.

## 7. Defects in the existing backend that matter for hosting

These are historical findings in the external backend. Their current fix status is unknown; verify
them before exposing the affected integration to customers.

| Defect | Where | Fix |
|---|---|---|
| `Brand.slug` is taken from `brand.yaml` unchecked and becomes a folder name that is `rmtree`d. **Checked.** | `pack.py:59-63`, `model.py:533` | validate against `clients.SLUG` when loading, and refuse a name that resolves outside `out/` |
| `clients.SLUG` uses `^...$`, which also matches a trailing newline; `fleet.SLUG` uses `\A...\Z`. | `clients.py:31` | use `\A...\Z` |
| `remove_site` keeps reports and a later site can take the same slug and inherit them. **Checked** (docstring, `write_due`). | `fleet.py` (`remove_site`), `report.py` (`write_due`) | never reissue a slug, or move the reports with the removal |
| `write_due` stops at the first site that fails. | `report.py:340-345` | catch per site and carry on |
| Fleet readers with no site parameter. | `fleet.py` (`open_marks`, `bans`, `offenders`, `shared_addresses`) | make the site argument required |
| A feed's `t` and `day` are not bounded, so a future-dated event is never pruned and sorts first. No per-site row quota; up to 10 pages of 20,000 events per site under one global lock. | `feed.py:360`, `fleet.py:690, 945, 1083` | bound the timestamps; add a per-site quota and a read-time cap |
| PHP leaves out `cursor` and `more`; the reader requires them. **Checked.** | `PortalFeed.php:321-333`, `feed.py:644-646` | always send them |
| The console is unauthenticated, holds the key passphrases, and `sending.smtp_host` is editable from it. **Checked.** | `web/app.py`, `web/yamledit.py:50` | before any hosted key exists: a local credential for the console, `sending.*` added to the integrity register, and the mailbox password never in a process the console starts |
| Fleet-repeat publishes one customer's visitor addresses to all, on a consent flag the site sets itself. | `reputation.py:711-789` | central consent and weighting (`segmentation.md` T8) |

Not in the survey and so unexamined: the owner's host, DNS and GitHub credentials, which live
outside the repository.
