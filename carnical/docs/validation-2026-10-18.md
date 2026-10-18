# Validation record: 18 October 2026

This record measures revision `deb80b41` of `edge-crs`, after the bot policy, intrusion alerts
and auto-block work. The local runs used a cloud container (Ubuntu 24.04.5, Linux 6.18.44,
Go 1.26.9, running as root, no IPv6). The CI runs used GitHub's Ubuntu 24.04 runners. The counts
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
