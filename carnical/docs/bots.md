# Bots

Carnical reads what kind of client sent each request, names it in every alert, and counts blocked
requests by it, so the log says how many bots and how many people were blocked. With `-bots` it
also blocks the kinds of bot a site does not want. Nothing is blocked for being a bot unless
`-bots` lists it. [ADR-0087](../../docs/adr/0087-carnical-bot-policy-and-counts.md) records the
design.

## What each layer does about bots

| Bot | What stops it |
| --- | --- |
| Vulnerability scanners (sqlmap, Nikto, Nuclei, dirsearch, ...) | The rule set by their user agent (CRS 913100, local 5006014) and by what they send; `-bots scanner` refuses them by name even in detect mode. |
| Bots that pretend to be Google, Bing, ... | `-bots fake`: the address must belong to the engine, checked by DNS. |
| AI crawlers and fetchers | `-bots ai`. |
| SEO, marketing, archive and data-mining crawlers | `-bots seo`. |
| HTTP libraries, scripts and scraping frameworks that keep their own user agent | `-bots tool`. |
| Headless and automated browsers that say so | `-bots headless`. |
| Other bots: no user agent, a contact URL, an unknown program, a browser's user agent without the headers browsers send | `-bots bot`. |
| Floods and fast scrapers, whatever they claim | The [flood protection](ddos.md) and its browser challenge, [rate rules](proxy-reference.md#rate-rules), and [auto-block](ddos.md#repeat-offenders). |
| Known bad addresses | [CrowdSec](crowdsec.md) and the policy block list. |

A user agent is the client's own claim. Declared bots are named by it. A bot that copies a real
browser's headers exactly is counted as a person; the flood protection and the rate rules still
limit how fast it can go. Only a search engine's claim can be checked, against its DNS.

## Kinds of client

| Kind | Examples | Can be blocked |
| --- | --- | --- |
| `person` | Chrome, Safari, Firefox, Edge; apps on phones (okhttp, CFNetwork) | no |
| `search` | Googlebot, Bingbot, Applebot, YandexBot, Baiduspider, DuckDuckBot | no, when real |
| `fake` | A search engine's user agent from an address its DNS does not confirm | `fake` |
| `ai` | GPTBot, ChatGPT-User, OAI-SearchBot, ClaudeBot, Claude-User, CCBot, Bytespider, PerplexityBot, Amazonbot, meta-externalagent, Google-CloudVertexBot, Diffbot, ... | `ai` |
| `seo` | AhrefsBot, SemrushBot, MJ12bot, DotBot, BLEXBot, DataForSeoBot, Barkrowler, ia_archiver, ... | `seo` |
| `tool` | curl, Wget, python-requests, aiohttp, Go-http-client, Java, Apache HttpClient, node-fetch, axios, Scrapy, Colly, HTTrack, ... | `tool` |
| `headless` | HeadlessChrome (also by its client hints), PhantomJS, Lightpanda, ... | `headless` |
| `scanner` | sqlmap, Nikto, Nmap, Nuclei, WPScan, ffuf, Acunetix, Nessus, Censys, ... | `scanner` |
| `preview` | Slack, WhatsApp, Discord, Telegram, Facebook, X, LinkedIn link previews | no |
| `monitor` | UptimeRobot, Pingdom, StatusCake, Datadog, kube-probe, load balancer health checks | no |
| `bot` | No user agent; a contact URL; an unknown program; "compatible" with a crawler word; a browser's user agent over HTTP/1.0 or without Accept or Accept-Language | `bot` |

Previews and uptime checks cannot be blocked by kind: they fetch what people share or what the
operator set up. A site that wants none of them says so in robots.txt or a [custom
rule](config-and-policy.md).

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-bots` | none | Kinds to block, separated by commas: `fake`, `ai`, `seo`, `tool`, `headless`, `scanner`, `bot`. |
| `-bots-mode` | `block` | `monitor` lets them through and writes `intrusion detected` with `would_block`. |

Setup asks "Bots to block" and writes these flags; in detect mode it writes `-bots-mode monitor`.

| Setup answer | `-bots` |
| --- | --- |
| `none` | nothing |
| `fake` (recommended) | `fake` |
| `ai` | `fake,ai,seo` |
| `strict` | `fake,ai,seo,tool,headless,scanner,bot` |

Use `strict` only for a site that browsers alone use: mobile apps and API clients that set their
own user agent are `tool` or `bot`. Run `-bots-mode monitor` for a few days first and read which
clients would be blocked.

A blocked request is answered 403 and reported under its own id: 5005003 `ai`, 5005004 `seo`,
5005005 `tool`, 5005006 `headless`, 5005007 `scanner`, 5005010 `bot` and 5005011 `fake`. The
alerts are layer `bots`, category `bot`, signature `bots-<id>`. All are low risk except `fake`,
which is medium. A bot refused for its kind adds nothing toward auto-block; the flood protection
counts its refusals among the site's refusals, and a refused request earns its address no standing.

## Search engine checks

For `fake`, a request that claims to be Googlebot, Bingbot, Applebot, YandexBot, Baiduspider,
PetalBot, SeznamBot or Naver's Yeti is checked as each engine asks sites to. The address's DNS name
must be in the engine's domains, and that name must resolve back to the address.

| Engine | Domains |
| --- | --- |
| Google | `googlebot.com`, `google.com` |
| Bing | `search.msn.com` |
| Apple | `applebot.apple.com` |
| Yandex | `yandex.ru`, `yandex.net`, `yandex.com` |
| Baidu | `baidu.com`, `baidu.jp` |
| Petal | `petalsearch.com` |
| Seznam | `seznam.cz` |
| Naver | `naver.com` |

Google's `googleusercontent.com` is not accepted: every Google Cloud machine has a name there.
DuckDuckGo, Qwant, Mojeek and Sogou publish no DNS names, so their crawlers stay `search`.

How the check behaves:

- Answers are cached: 24 hours for a crawler, 1 hour for an impostor, 1 minute for a lookup that
  failed.
- A failed lookup counts as not verified. The reverse zone belongs to the address's owner, so an
  impostor could otherwise fail it on purpose.
- At most 8 checks run at once, each for at most 2 seconds. With none free, the answer is no: real
  crawlers come from addresses already cached.
- Carnical needs outbound DNS for this. `-confine` allows port 53 by default.

## Counting

Every alert has `client`, the kind of client that sent the request. The `intrusion totals` line
counts requests that were refused (blocked, rate limited, or from a banned source):

| Field | Meaning |
| --- | --- |
| `blocked_bots` | Requests from bots refused, for any reason: a bot kind, an attack, a rate limit or a ban. |
| `blocked_people` | Requests from people refused. Most are attacks sent with a browser's user agent; the rest may be false positives worth a look. |
| `blocked_bot_sources`, `blocked_people_sources` | About how many different addresses (IPv6 /64s) those came from; close to exact below a few hundred, within about 2% above. |
| `blocked_by_client` | The refused requests by kind, for example `{"ai": 120, "fake": 3, "person": 9, "tool": 41}`. |

```json
{"msg":"intrusion totals","blocked_bots":7,"blocked_people":2,"blocked_bot_sources":1,
 "blocked_people_sources":1,"blocked_by_client":{"ai":2,"fake":1,"headless":1,"person":2,"seo":1,"tool":2}, ...}
```

Requests the flood protection refuses on the connection, before any request is read, carry no
user agent and are not in these counts.
