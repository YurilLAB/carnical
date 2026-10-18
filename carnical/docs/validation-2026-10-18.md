# Validation record: 18 October 2026

This record measures revision `deb80b41` of `edge-crs`, after the bot policy, intrusion alerts
and auto-block work; the sections on varied agents, application traffic, independent corpora, the crawler list updater, the real applications and the tuning name their own. The local runs
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

## Independent corpora

These corpora were written by others, not for Carnical. They were measured on `98834421`, and
again on the final revision with the fixes below. The comparison uses the same harness as
[Detection compared with upstream Coraza](#detection-compared-with-upstream-coraza): upstream
Coraza v3.8.1 with CRS 4.30.0 at paranoia level 1, against Carnical in `-mode block`. A control
run with no WAF passed every request to the origin.

[nemesida-waf/waf-bypass](https://github.com/nemesida-waf/waf-bypass) at `887f2f9` (July 2026)
sends each payload in the zones it names (URL, query, form body, cookie, user agent, referer and
another header), as written and encoded in Base64 and UTF-16. The tool counted a status of 403,
400, 413 or 415 as a block.

| | Upstream | Carnical, formats blocking |
| --- | --- | --- |
| Attacks as written (2,992) | 2,398 (80.1%) | 2,471 (82.6%) |
| Attacks encoded (3,818) | 2,643 (69.2%) | 2,660 (69.7%) |
| Its false-positive probes refused (19) | 9 | 9 |

All 90 requests that had a different outcome were blocked by Carnical and passed by upstream.
Carnical's rules blocked 24 of them. Its query and path checks (status 400) blocked the other 66.
Both refused the same false-positive probes, which the tool sends as a body with no Content-Type.

The [open-appsec WAF comparison project](https://github.com/openappsec/waf-comparison-project)
publishes 73,924 attacks and 1,040,242 requests that real browsers sent to 185 sites. The
legitimate set was sampled: every 12th of its 692 files in name order, 58 sites, 78,208
requests. A request with no Host header was sent with `Host: localhost`.

| Requests refused | Upstream | Carnical | Carnical, formats blocking |
| --- | --- | --- | --- |
| Attacks (73,924) | 66,132 (89.5%) | 66,186 (89.5%) | 73,614 (99.6%) |
| Legitimate, all (78,208) | 18,706 (23.9%) | 19,576 (25.0%) | 19,903 (25.4%) |
| Legitimate, first-party (33,987) | 8,583 (25.3%) | 8,641 (25.4%) | 8,839 (26.0%) |

"Carnical" is the build as it ships, with format checks in monitor. First-party requests are the
ones the browser marked `Sec-Fetch-Site: same-origin` or `none`. The rest went to other hosts,
mostly analytics and advertising, which a site's own edge never sees. Upstream's figures include
16 requests that timed out. No request was passed by Carnical and refused by upstream.

As shipped, Carnical adds 54 command executions. With formats blocking it also adds 7,424 path
traversals (by its path and query checks) and 4 SQL injections.

Most refusals of legitimate traffic come from the CRS itself. In a random sample of 600
first-party requests that upstream refused:

- 312 matched rule 932270, a shell expression. 239 of them carried Akamai Bot Manager's `_abck`
  cookie, whose value holds `||~-1`. That cookie is on every visit to a site behind Akamai. The
  [policy guide](config-and-policy.md#exclusions) shows the exclusion that takes it out of the
  command-injection rules. With it, the shipped build refused 13.9% of
  first-party requests instead of 25.4% (6,231 fewer refusals in the whole sample, none added), and
  refused the same 66,186 attacks.
- 201 matched 920420, the request type: mostly `text/plain` beacons, as in
  [Legitimate application traffic](#legitimate-application-traffic).

Carnical's own refusals of legitimate traffic, before the fixes (898 requests):

- 549 had a `;` in the path, on 21 sites. Most went to advertising hosts such as `doubleclick.net`.
  `-allow-path-params` lets them through.
- 197 began with `//` (`//i/aurora/...`), 183 of them on one site.
- 50 had an encoded slash (`-allow-encoded-slash`).
- 15 named a product with a percent sign (`100%25-WHEY`).
- 86 were refused by Carnical's URL rules:
  - 5006021: a `.php` page in Google Analytics' and Facebook's `dl` and `rl` parameters;
  - 5006016: a URL with no scheme (`//cdn.example/`) in a parameter;
  - 5006015: a URL in `layout=`;
  - 5006008: schema.org markup.
- 1 was refused by 5006003, for an advertising code list `|NC|NC|` (netcat between pipes).

Fixed:

- **A percent sign in a path** is refused only when it starts another escape (`%252e`), not in
  `100%25-WHEY`.
- **Rule 5006008** ends a URL's userinfo at a double quote. `"https://schema.org","@type"` is
  JSON, not a URL with userinfo.
- **Exclusions can name cookies and arguments that start with `_`**: `_abck`, `_ga`,
  `__cf_bm`, `_token`. Before, the `_abck` exclusion could not be written.

With the fixes, the shipped build refuses 58 first-party requests that upstream lets through
(0.17%), down from 72. None of the corpora lost a detection: Carnical's own 3,824 cases,
waf-bypass and GoTestWAF had no request with a different outcome, and open-appsec's attacks were
refused as before.

## Crawler list updater on five distributions

`carnical-ranges.service`, its timer, `refresh.sh` and the tmpfiles entry from `f887b767` were
installed by the [deployment steps](../deploy/README.md#order) in containers booted with systemd as
PID 1, one per distribution. The edge itself was not installed. A test-only drop-in gave the unit
the sandbox's HTTPS proxy; the proxy's CA was in the system trust store, and TLS was verified.

| | Ubuntu 22.04.5 | Debian 12 | Ubuntu 24.04.5 | Debian 13 | Ubuntu 26.04.1 |
| --- | --- | --- | --- | --- | --- |
| systemd | 249 | 252 | 255 | 257 | 259 |
| `systemd-analyze verify` | clean | clean | clean | clean | clean |
| Four lists fetched and checked, exit 0 | yes | yes | yes | yes | yes |
| `systemd-analyze security` exposure | 1.7 | 1.7 | 1.7 | 1.7 | 1.7 |

On every one:

- `systemd-tmpfiles --create` made `/var/lib/carnical/ranges` mode 0755, owned by root;
- `carnical -check` read the four installed lists with the paths step 10 gives the edge;
- the timer was listed with its next run within the 4-hour random delay;
- the service could write the lists' directory and nothing else (`/etc` was read-only to it).

Both failure paths were tested:

- with downloads failing, the unit exited 1 and showed as failed;
- with the check failing (`CARNICAL=/bin/false`), it also exited 1.

In both, the lists in place were byte-identical afterwards, and no temporary file was left.

A unit denying `127.0.0.1` could not reach the proxy on loopback, and the same unit without it
could, on both cgroup layouts used here. So `IPAddressDeny` is enforced, not just accepted.

Found and fixed in the steps:

- neither `/etc/sysusers.d` nor `/usr/local/lib/carnical` exists on a fresh Ubuntu or Debian, so
  steps 3 and 10 failed as written; they now use `install -D`.

Limits of the test:

- the host had cgroup v1, which systemd 259 does not boot on, so Ubuntu 26.04 ran on a separate
  cgroup2 mount with no controllers;
- journald could not start there, so its log lines were not seen; the exit codes and files were
  checked as on the others.

## Real applications in a browser

Four applications ran in containers behind each configuration, and real use of each was replayed:

- **WordPress 6.8.3** (PHP 8.3, MariaDB 11.4): an author writing in the block editor, uploading an
  image, changing settings and a profile, a visitor reading, commenting and searching, a REST client
  and XML-RPC;
- **Keycloak 26.4**: a web app's OpenID Connect sign-in with PKCE, its back channel (code
  exchange, userinfo, introspection, refresh), single sign-on, the account console, sign-out,
  self-registration, and an administrator in the admin console and the admin API;
- **Gitea 1.24**: a developer creating a repository, an issue with code blocks, a previewed and
  posted comment, a file in the web editor, a wiki page, a search, the REST API, and git cloning,
  pushing and pulling over HTTP;
- **Matomo 5.14**: the JavaScript tracker on a shop's pages (a campaign visit, events, outlinks,
  site searches, an order), the dashboard and reports, segments and goals, and a server-side SDK
  sending bulk tracking.

Browser steps used real Chromium 141 with a desktop Chrome user agent; API clients and git sent
their own. Each step ran on a page of its own. When a WAF refused a step that made something later
steps need (a post, a repository, a token), that thing was made inside the application instead, so
every step was measured on its own. The sites had names (`wp.example.test` and so on): a first run
on `localhost` was refused everywhere, because CRS rule 934110 reads `http://localhost` in a
parameter as SSRF, and real sites do not send that. The configurations were upstream Coraza v3.8.1
with CRS 4.30.0 at paranoia level 1, and Carnical in `-mode block` with and without `-formats-mode
block`. Revision `612790ac`.

| Steps passed | No WAF | Upstream | Carnical | Carnical, formats blocking |
| --- | --- | --- | --- | --- |
| WordPress (19) | 19 | 12 | 12 | 12 |
| Keycloak (18) | 18 | 15 | 15 | 15 |
| Gitea (17) | 17 | 3 | 3 | 3 |
| Matomo (16) | 16 | 16 | 16 | 16 |
| All (70) | 70 | 46 | 46 | 46 |

All three refused the same 24 steps, and no request reached the application through one of them
that the others refused. Carnical's own rules matched only requests the CRS refused anyway. Its
one refusal of its own is 5000044, on the block editor's saves: the editor sends PUT as POST with
`X-HTTP-Method-Override`, and the CRS refuses the same requests with rule 920450 (a restricted
header). Matomo was never refused. What was:

- **WordPress:**
  - updating a post or the user's preferences in the block editor (the method override);
  - post content with code, an `<iframe>` or a block comment `<!--`, sent by the editor or a REST
    client (930, 932 and 941 rules);
  - a comment quoting `rm -rf node_modules` and `DATE_SUB(`;
  - a search for `/etc/nginx/sites-enabled`;
  - REST deletes (DELETE is not an allowed method by default);
  - every XML-RPC call (a defect, below).
- **Keycloak:**
  - the admin console, because its `/admin/master/console/whoami` path holds the command `whoami`
    (932260);
  - a client whose redirect URIs include `http://localhost:3000`;
  - a password policy `length(12) and notUsername(undefined)`, which libinjection reads as SQL;
  - PUT on the admin API.
- **Gitea:**
  - a repository described as "bash, SQL & PowerShell snippets";
  - issues, comments, previews, API issues and markdown with shell or SQL in code blocks;
  - a script in the web editor;
  - a wiki page showing `<script>` example code;
  - a search for `../config`;
  - a `.sql` file through the contents API, and the page of any `.sh` file (920440, restricted
    extensions);
  - `git clone` (930130 reads `.git/` in the path as a request for a repository's files).

Found and fixed:

- **XML-RPC and RSS bodies.** The engine's XML reader closed HTML's empty elements (`param`,
  `link`, `meta` and others) as soon as they opened, so a `</param>` was a syntax error and rule
  200002 refused the body. Every XML-RPC call (the WordPress apps, Jetpack, pingbacks) and every RSS
  document was refused, by upstream Coraza too. Since the fix, a `wp.getUsersBlogs` call passes and
  SQL, script and shell values inside `<param>` are refused by the rules. Neither GoTestWAF's XML
  cases nor waf-bypass changed.

## Tuning a site, and keeping formats blocking

Could these sites run with `-formats-mode block` once tuned? A policy for each was written from the
refusals above alone. The steps were then run again with the same operations and different words
(other commands, other SQL, other paths), which the policies had not seen.

The policies:

- **WordPress:** `allowed_methods` with PUT, PATCH and DELETE; `wordpress.enabled` with
  `allow_xmlrpc`. Exclusions:
  - `lfi`, `rce` and `xss` from `arg:json.content` under `/wp-json/wp/v2/posts`;
  - `protocol` from `header:x-http-method-override` under `/wp-json/wp/v2/`;
  - `rce` and `sqli` from `arg:comment` on `/wp-comments-post.php`;
  - `lfi` from `arg:s` everywhere.
- **Keycloak:** `rce` from the path `/admin/master/console/whoami`; `ssrf` and `sqli` from the
  arguments under `/admin/realms/`; PUT and DELETE allowed.
- **Gitea:**
  - the four injection groups from `arg:content` and `arg:text` under the owner's path, and from
    the JSON bodies under `/api/v1/`;
  - `rce` from the repository description;
  - `lfi` from `arg:q` and the path under the owner's path;
  - git's two request types added to `body_formats.allowed_types`.
- **Matomo:** none.

| Steps passed | Formats blocking | Tuned |
| --- | --- | --- |
| Words the policies were written from (70) | 46 | 62 |
| New words (70) | 46 | 57 |

What tuning could not fix:

- **The block editor.** 5000044 has no setting, so editing a post fails even with 920450 excluded.
- **Git over HTTP.** CRS rule 920420 refuses git's request types, and no setting reaches the CRS's
  list of request types.
- **Gitea file pages.** The page of a `.sh` file and a `.sql` file through the API are refused by
  920440, which reads the file name (`REQUEST_BASENAME`). That is not a target an exclusion can name.

New words found what the policies left out: a search for "union select", a redirect URI to
`http://127.0.0.1:8080` (an `rfi` rule; the policy had excluded `ssrf`), and `system("rm -f
/tmp/lock")` in a Python traceback (a `php` rule). The remaining Keycloak failure, the admin
console's user list, also failed once with no WAF, and no WAF refused it.

The formats checks added no refusal of their own except git's request types, which the policy
then accepted: for these four sites, `-formats-mode block` costs one setting.

An exclusion is not free. Each plain payload of waf-bypass's SQLi, XSS, RCE and LFI sets was sent
as the value of an excluded field, and of one the policy does not name. Counts are payloads that
reached the application, untuned then tuned:

| Field | SQLi (20) | XSS (230) | RCE (16) | LFI (4) |
| --- | --- | --- | --- | --- |
| WordPress post content (`lfi`, `rce`, `xss` excluded) | 4, 4 | 10, 164 | 1, 8 | 0, 4 |
| WordPress comment (`rce`, `sqli` excluded) | 4, 20 | 10, 13 | 1, 8 | 0, 0 |
| Gitea issue content (four groups excluded) | 4, 20 | 10, 185 | 1, 9 | 0, 4 |
| A field the policy does not name, on the same pages | 4, 4 | 10, 10 | 1, 1 | 0, 0 |

So exclude a field only where the application already treats it as code or markup it trusts: an
editor's content, an issue tracker's text. Keep the exclusion's path as narrow as the
application's.

Found and fixed: an exclusion removed only the CRS rules of its groups. A field excluded from `rce`
or `lfi` was still refused by Carnical's local shell and traversal rules (5006003, 5006006). In
the first tuned run, that left every Gitea issue and comment refused. Each group now names its
local rules too ([rule groups](config-and-policy.md#rule-groups)).

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
