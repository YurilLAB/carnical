# Validation record: 18 October 2026

This record measures revision `deb80b41` of `edge-crs`, after the bot policy, intrusion alerts
and auto-block work; the sections on varied agents and on application traffic name their own. The local runs
used a cloud container (Ubuntu 24.04.5, Linux 6.18.44, Go 1.26.9, running as root, no IPv6). The CI runs used GitHub's Ubuntu 24.04 runners. The counts
belong to these runs. Attacks targeted isolated local origins.

Use the [documentation index](README.md#review-the-evidence) for the current guides and older
records.

## Security CI

[Run 39091203301](https://github.com/YurilLAB/carnical/actions/runs/39091203301): all 12 security
jobs passed at `deb80b41`.

- **Network protection (L3/L4)**, as root with nftables:
  - Every case in `test_network_policy.py` passed: malformed TCP, UDP/443, fragments, IPv6 /64
    rotation, bucket-sharing, egress and reload.
  - A varied flood of 6,000 packets (small profile) and one of 100,000 packets (large profile) was
    accounted for packet by packet. In the large profile, 33,334 bad TCP and 33,333 UDP packets
    were dropped, and of the SYNs, 9,957 were admitted and 23,376 refused by their source's
    budget. SQL injection was blocked 50 of 50 times through each.
  - Ordinary traffic during the packet flood was all served:
    - 10,000 of 10,000 IPv4/IPv6 requests under the large profile, p99 84 ms;
    - 4,000 of 4,000 over verified TLS, p99 6.3 ms.
- **Flood latency.** With a listen queue of 5, p99 was 1,045 ms, with 419 listen overflows. With
  a queue of 256 and persistent origin connections, p99 was 50 ms without a flood and
  55 ms with one.
- **CrowdSec**, against a live CrowdSec 1.8.1 (still the latest release on 18 October):
  - 10,000 of 10,000 benign requests were allowed;
  - 10,000 of 10,000 requests from banned addresses were blocked;
  - 200 of 200 varied SQL injections were blocked;
  - the TCP, Unix socket, IPv6, deletion, overlap, expiry, outage-recovery and confinement cases
    passed.
- **Origin mTLS**: every case passed with 0 redirects.
  - XSS and SQL injection stayed inspected: 403, with no request reaching the origin.
  - A WAF with no client certificate, a wrong certificate from the same CA or a foreign one was
    refused by the origin.

## Local tests

- `go test ./...` in `carnical/` passed, apart from three subtests that this container cannot run:
  - `TestTheConfinedProxyStillDoesItsJob/confined` fails because the container runs as root and
    holds capabilities, which the confined proxy refuses;
  - `TestRequestFormatsAtCLI/expanded_IPv6_health_address_works` and
    `TestTheProxyServesOnASocketSystemdHandsOver/IPv6` fail because the container has no IPv6.
  - All three run in CI.
- The documentation consistency tests (API guard, control, formats, config, virtual patches and
  backend compatibility) passed.
- Confinement and the systemd unit scores are in [hardening](hardening.md#what-was-verified-and-how), under the
  same date.

## Detection compared with upstream Coraza

The configurations compared:

- **Upstream**: Coraza v3.8.1 behind a minimal reverse proxy, with the same CRS 4.30.0 at
  paranoia 1 and threshold 5.
- **Carnical**: `-mode block -ddos off -formats-mode block`, with otherwise default settings.
- **None**: a control with no WAF.

The GoTestWAF test-case tree hash was `cf3fb65be07e` (verified). The control's origin received
every request, and each WAF's origin received exactly the requests it passed.

| Corpus | Configuration | Attacks blocked | Benign passed |
| --- | --- | --- | --- |
| GoTestWAF | none | 0 / 675 | 141 / 141 |
| GoTestWAF | upstream | 331 / 675 (49.0%) | 128 / 141 (90.8%) |
| GoTestWAF | Carnical | 347 / 675 (51.4%) | 128 / 141 (90.8%) |
| Carnical corpus (hardening-v1) | upstream | 2,538 / 3,414 (74.3%) | 403 / 410 (98.3%) |
| Carnical corpus (hardening-v1) | Carnical | 3,355 / 3,414 (98.3%) | 387 / 410 (94.4%) |

The Carnical corpus was developed alongside Carnical. It is not a blind test, and its higher
figure is not evidence of general detection.

On GoTestWAF:

- 16 attacks were blocked only by Carnical: XML injection and XXE, RCE in JSON and multipart,
  SSTI and an XSS path. None were blocked only by upstream.
- 46 attacks that both blocked got a different status (400, 413 or 415 instead of 403).
- The 13 benign requests refused are the same for both configurations.

On the Carnical corpus, Carnical passed 16 fewer benign requests. All 16 are
prototype-pollution-shaped JSON keys (`__proto__`, `constructor`), which the format policy refuses on
purpose.

The detection results at this revision are identical to the previous revision measured
(`13ecc1fc`). The bot, alert and auto-block work changed no detection result.

## Bot policy: people misread and real browsers

The classifier was run over the 6,936 browser user agents of `fake-useragent` 2.2.0, each sent with
a browser's `Accept`, `Accept-Language` and `Accept-Encoding`:

- 6,456 were read as `person`, 479 as `disguised` and 1 as `bot`. All 480 name Chrome before 70.
- 477 of the 480 carry a build number that version of Chrome never had, so they were made up by
  the dataset's generator. 119 of them are the DevTools Galaxy S5 emulation string. The other 3
  are genuine Chrome 63 and 66 builds from 2018.
- The `bot` one is a user agent wrapped in quotation marks.
- The default policy (`scanner`) refuses none of them. Only the opt-in `disguised` and `bot` kinds
  do.

Real browsers over TLS, with every kind refused (`-bots fake,scanner,ai,seo,tool,headless,disguised,bot`):

- Chromium 141 and Firefox each loaded a page with styles, scripts, a font, fetch, XHR, POST,
  server-sent events, two WebSockets, images and a frame. 13 of 14 requests reached the origin.
  The bot policy refused none of the browsers' requests.
- The 14th was `navigator.sendBeacon('/beacon', 'x')`, which sends `text/plain`. CRS rule 920420
  refused it, in both browsers. This is the CRS's default list of request types, and upstream
  Coraza with the same CRS refuses it too. See
  [formats](formats.md#what-is-not-done-and-what-to-watch).
- Requests that look like a browser but are not one were refused as `disguised` (5) or
  `headless` (2):
  - python-requests with Chrome's full DevTools headers or only its user agent;
  - curl with Chrome's headers;
  - Python posing as Firefox;
  - default headless Chromium.

  In that run the bot policy refused 0 requests from people. Chromium's new headless mode, which
  is the full browser, was served.

The published crawler range files parsed as expected:

| File | Ranges |
| --- | --- |
| Google, common crawlers | 317 |
| Google, special crawlers | 272 |
| Bing | 28 |
| Apple | 24 |
| Amazon | 1,292 |

## Bot policy: varied agents, apps and proxies

Measured on `fcdf06a9`, then again with the fixes below. Each user agent was classified in four
settings:

- **HTTP:** a browser's `Accept`, `Accept-Language` and `Accept-Encoding`, no TLS.
- **HTTPS:** also the `Sec-Fetch-*` headers and client hints the browser named sends, and its TLS
  handshake: GREASE from Chrome 55 and later and from Safari, `record_size_limit` from Firefox 65
  and later.
- **Inspected:** the same headers, through a proxy that reads HTTPS and offers neither in its own
  handshake.
- **Forwarded:** the same headers from a `-trusted-proxies` load balancer, over HTTP/1.0.

| Set | Agents | HTTP and HTTPS | Inspected |
| --- | --- | --- | --- |
| [intoli/user-agents](https://github.com/intoli/user-agents), weighted by use | 10,000 | 94.7% `person`, 5.3% `disguised` | 38.2% `person`, 61.8% `disguised` |
| Apps, devices and enterprise clients, written by hand | 55 | 44 `person`, 1 `disguised` | 29 `person`, 16 `disguised` |
| [uap-core](https://github.com/ua-parser/uap-core) test agents | 14,548 | see below | |
| [crawler-user-agents](https://github.com/monperrus/crawler-user-agents) | 2,120 | 3.96% read as `person` | |

Forwarded gave the same reads as HTTP. Nothing that a person uses was read as `scanner` in any
set, so the default policy (`-bots scanner`) refused no person.

intoli:

- Every `disguised` read names Chrome 39 to 50 with a build number Chrome never had. These are
  generated user agents, so they come from programs, not people.
- The one `bot` read is a user agent marked `compatible;` with no browser in it.
- Inspected, all 6,173 agents naming Chrome (Edge and other Chromium browsers included) or Firefox
  90 and later read as `disguised`.

Apps and devices, after the fixes:

- 44 were read as `person`. They include okhttp, Dalvik, CFNetwork, AppleCoreMedia, ExoPlayer,
  in-app browsers, Electron and Teams, Opera, Vivaldi, Samsung Internet, Firefox ESR, Tor Browser,
  Internet Explorer 11, Edge in IE mode, a Chromebook, the PlayStation 5, the Switch, a Tesla, and
  televisions from LG and Samsung.
- `tool`: curl, python-requests, a Flutter app (`Dart/3.5 (dart:io)`) and a Unity game
  (`UnityPlayer`, which names libcurl).
- `bot`: no user agent, and Windows fetching a revocation list (`Microsoft-CryptoAPI/10.0`).
- `monitor`: Zabbix and the Prometheus blackbox exporter. `preview`: Slack and WhatsApp.
- `disguised`: an Android 4.4 web view, which names Chrome 30.

uap-core's agents are mostly historical. Every `disguised` read among them comes from the version
rule: Firefox before 60 (2,162), Chrome before 70 (95) and Internet Explorer before 11 (47). The
only `scanner` reads were OpenVAS (3), WhatWeb and masscan.

Live, through [mitmproxy](https://mitmproxy.org) 12.2.3 (OpenSSL 4.0.1) in front of Carnical with
`-bots disguised`:

| Browser | Direct | Through mitmproxy |
| --- | --- | --- |
| Chromium 141 | served | 403, `disguised` |
| Firefox | served | 403, `disguised` |

Fixed in the classifier:

- **ExoPlayer and Media3** (`ExoPlayerLib/2.19.1`, `AndroidXMedia3/1.4.1`), the video players of
  Android apps, were `bot`. They are now apps (`person`).
- **Televisions** were `disguised`: LG's of 2016 to 2020 name Chrome 38 to 68, and the older ones
  offer no GREASE. A television's user agent (`SmartTV`, `SMART-TV`, `Web0S`, `Tizen`, `HbbTV`) is
  now excused from both checks, below Chrome 70 only. This opens no new way past the policy: a
  program can already claim Safari 16, whose handshake is not checked and which sends no
  `Sec-Fetch-*`.
- **Apps built on Chromium**, such as WeChat on Windows (`XWEB`), CEF apps and in-app browsers,
  were held to Chrome's client hints. Only Electron, Android web views and four named forks were
  excused. Now only a user agent that is Chrome's, Edge's or Opera's and names nothing else is
  held to them. In intoli, that leaves 0.08% of the weight no longer checked, all of it forks.

Not fixed. A browser behind a proxy that reads HTTPS cannot be told apart, by its handshake, from a
program that copies a browser's headers. [Bots](bots.md#disguised-programs) now says to keep
`disguised` in `-bots-monitor` for such visitors.

## Legitimate application traffic

Measured on `e15fa899`, then again with the fix below. 64 requests were sent the way the named
software sends them, with Chrome's headers and a session cookie: beacons and reports, API calls,
CMS edits, search boxes, sign-in and single sign-on, webhooks, uploads and ordinary pages. They
use realistic hosts in their URLs, not `localhost`, which the CRS's SSRF rules (934110, 934190)
score. Each went through upstream Coraza v3.8.1 with CRS 4.30.0 at paranoia level 1, and
through Carnical with `-mode block -formats-mode block`. With no WAF, all 64 reached the origin.

| Configuration | Reached the origin |
| --- | --- |
| Upstream Coraza and the CRS | 41 of 64 |
| Carnical | 41 of 64, the same 41 |
| Carnical with `-allowed-methods GET,HEAD,POST,OPTIONS,PUT,PATCH,DELETE` | 45 of 64 |
| Carnical before the fix | 39 of 64 |

What was refused, in Carnical (the rules that matched are in brackets):

- **The request's type, 12.** CRS rule 920420 or Carnical's content-type check (5002001,
  5002002, 5002040) refused:
  - `text/plain`: a `sendBeacon` string, a Google Analytics 4 hit, a Sentry envelope and a Next.js
    server action;
  - `application/csp-report`, gRPC-Web, NDJSON, CSV and protobuf bodies;
  - an image, a tus chunk and a file sent as the body.

  [Formats](formats.md#what-is-not-done-and-what-to-watch) lists these. No flag widens the CRS's
  list.
- **The method, 4.** PUT, PATCH and DELETE (911100), until `-allowed-methods` lists them.
- **What the request said, 7.** These are the CRS's own rules, and upstream refused the same
  requests:
  - an OData `$filter` (942290);
  - a GraphQL query with `__typename` and fragments (932235, 942290);
  - a WordPress block post with an image and an embed (941160, 941180);
  - a blog post with a shell snippet (930120, 932235);
  - a comment with quotes, semicolons and `--` (942190);
  - the searches `javascript: the good parts` (941210) and `cat /etc/hosts tutorial` (930120).

  A site that needs these takes the paths out with [exclusions](config-and-policy.md#exclusions).

Passed in both: JSON, JSON:API and PostgREST queries, a GraphQL persisted query, rich text in a
GraphQL mutation, multipart photos, PDFs, Word documents, SAML and OIDC posts, Stripe and GitHub
webhooks, a password with quotes and `--`, a CORS preflight, server-sent events, a range request,
SOAP and long tracking parameters.

Fixed. Carnical's rule 5006003 took a line break before `id`, `cat`, `sleep` and other command names
as shell chaining. It refused a GraphQL query with a field on each line and a review whose lines
began "Cat toys" and "ID check", which upstream let through. After a line break, the word must now
stand alone or come with an option, a path, a URL, an address or a shell operator. The fix changed
nothing else that was measured:

- Carnical's attack and benign corpus: 3,355 of 3,414 attacks blocked and 387 of 410 benign
  requests passed, before and after, with no case changed;
- GoTestWAF: no request had a different outcome.

## Alerts and auto-block under sustained hostile traffic

`-auto-block on -auto-block-for 1m -bots scanner,ai,tool`, behind a trusted proxy that sets
`X-Forwarded-For`. The test sent traffic from:

- 3,000 attacker addresses. During the four-minute attack phase, three requests in four were
  attacks (SQL injection, XSS, traversal, command injection, Log4Shell, and one in five from
  sqlmap's user agent); the fourth was ordinary;
- AI crawlers and tools;
- people.

After the attack phase, two minutes of ordinary traffic followed.

- 947,281 requests were sent at 2,631 a second, with 0 connection errors.
- 0 of 802,984 requests from people were refused.
- 2,998 of the 3,000 attackers were banned (`source blocked`), 5,361 bans in all, and every ban
  ended (`source block ended`).
  - 5,270 bans came at 12 to 15 points;
  - 91 came at 24 to 27 points, for sources with standing.
- Every attacker the probe saw banned (2,880) was let through again once the attack phase was
  over. No `auto-block table full` event occurred.
- The test's own probe saw 2,880 attackers banned. It notices a ban only when an attacker's
  ordinary request lands inside a one-minute ban, so the other 118 were banned without the probe
  seeing it.
- The 2 attackers never banned had sent only 5 and 6 attacks and had earned
  [standing](ddos.md#who-still-gets-through-during-an-attack) with their ordinary requests, so they
  needed 24 points. This was reproduced:
  - a new address was banned at 12 points after 3 to 4 attacks of each kind;
  - an address with standing was not banned after five single-category attacks (15 points), and
    was banned at 24.
- The `intrusion totals` counted:
  - 33,205 requests refused from bots, and 64,676 from attackers whose user agent was a browser's
    (`person`);
  - for the bot kinds, `ai` 12,103, `tool` 11,998 and `scanner` 9,104.

  The alert line limit held back 58,267 lines and reported each hold-back as `alerts dropped`.
- The process grew from 67 MB to a steady 135 to 140 MB, with 104 descriptors and 11 threads,
  and did not grow further.

## Flood simulations

The shield simulations and the live proxy flood tests were re-run. The results are in the
[flood validation record](flood-validation.md):

- every simulated figure was reproduced, apart from the attack record's address estimate;
- the live test detected the flood after 2.2 s, and 22 of 23,662 flood requests reached the
  application.
