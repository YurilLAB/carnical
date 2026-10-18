# Bots

Carnical reads what kind of client sent each request, names it in every alert, and counts blocked
requests by it, so the log says how many bots and how many people were blocked. With `-bots` it
also refuses the kinds of bot a site does not want. By default it refuses scanners and attack
tools, which nothing but an attack sends; nothing else is refused for being a bot unless `-bots`
lists it. [ADR-0087](../../docs/adr/0087-carnical-bot-policy-and-counts.md) records the design.

## What each layer does about bots

| Bot | What stops it |
| --- | --- |
| Vulnerability scanners, attack and brute-force tools, botnets (sqlmap, Nuclei, Hydra, OpenBullet, zgrab, ZmEu, ...) | `-bots scanner`, the default, refuses them by name in every mode; the rule set also stops them by user agent (CRS 913100, local 5006014) and by what they send. |
| Bots that pretend to be Google, Bing, ... | `-bots fake`: the address must belong to the engine, checked by DNS. |
| AI crawlers and fetchers | `-bots ai`. |
| SEO, marketing, archive and data-mining crawlers, address harvesters, site copiers | `-bots seo`. |
| HTTP libraries, scripts and scraping frameworks that keep their own user agent | `-bots tool`. |
| Headless and automated browsers that say so | `-bots headless`. |
| Programs that send a browser's user agent | `-bots disguised`: their headers, client hints or TLS handshake do not match the browser named. |
| Other bots: no user agent, a contact URL, an unknown program | `-bots bot`. |
| Floods and fast scrapers, whatever they claim | The [flood protection](ddos.md) and its browser challenge, [rate rules](proxy-reference.md#rate-rules), and [auto-block](ddos.md#repeat-offenders). |
| Known bad addresses | [CrowdSec](crowdsec.md) and the policy block list. |

A user agent is the client's own claim. Declared bots are named by it; a program that claims to be
a browser is caught when what it sends does not match that browser (see [Disguised
programs](#disguised-programs)). A real browser driven by a program, with its own consistent
headers and handshake, is counted as a person; the flood protection and the rate rules still limit
how fast it can go. Only a search engine's claim can be checked, against its DNS.

## Kinds of client

| Kind | Examples | Can be refused |
| --- | --- | --- |
| `person` | Chrome, Safari, Firefox, Edge; apps on phones (okhttp, CFNetwork, Dalvik); Microsoft Office opening a link; Roku players | no |
| `search` | Googlebot, Bingbot, Applebot, YandexBot, Baiduspider, DuckDuckBot, Qwant, Mojeek | no, when real |
| `fake` | A search engine's user agent from an address its DNS does not confirm | `fake` |
| `ai` | GPTBot, ChatGPT-User, OAI-SearchBot, ClaudeBot, Claude-User, CCBot, Bytespider, PerplexityBot, Amazonbot, meta-externalagent, GoogleOther, Google-CloudVertexBot, Diffbot, a `Signature-Agent` header (ChatGPT agent), ... | `ai` |
| `seo` | AhrefsBot, SemrushBot, MJ12bot, DotBot, BLEXBot, DataForSeoBot, Barkrowler, ia_archiver, AmazonAdBot, EmailCollector, HTTrack, WebZIP, Teleport Pro, ... | `seo` |
| `tool` | curl, Wget, python-requests, urllib3, PycURL, aiohttp, Go-http-client, Java, Apache HttpClient, node-fetch, axios, Scrapy, Colly, ... | `tool` |
| `headless` | HeadlessChrome (also by its client hints), PhantomJS, Lightpanda, ... | `headless` |
| `scanner` | sqlmap, Nikto, Nmap, Nuclei, WPScan, ffuf, Acunetix, Nessus, Ghauri, Dalfox; Hydra, Medusa, OpenBullet; zgrab, Censys, Shodan, Expanse; botnet and malformed user agents (ZmEu, Mozlila, libredtail, "Hello, world") | `scanner` |
| `disguised` | A browser's user agent with headers, client hints or a TLS handshake that browser does not send | `disguised` |
| `preview` | Slack, WhatsApp, Discord, Telegram, Facebook, X, LinkedIn link previews; feed readers; Gmail's and Yahoo Mail's image proxies; Google Read Aloud | no |
| `monitor` | UptimeRobot, Pingdom, StatusCake, Datadog, Nagios, Gatus, kube-probe, load balancer health checks, Let's Encrypt domain validation | no |
| `bot` | No user agent; a contact URL; a user agent too long for a browser; an unknown program; "compatible" with a crawler word | `bot` |

Previews and uptime checks cannot be refused by kind: they fetch what people share or what the
operator set up. A site that wants none of them says so in robots.txt or a [custom
rule](config-and-policy.md). Their names cannot be checked, so a scraper can claim one; the flood
protection and the rate rules still limit how fast it can go.

## Disguised programs

A request whose user agent names Chrome, Firefox, Safari, Edge or Internet Explorer is `disguised`
when any of these holds:

- it came over HTTP/1.0, or has no `Accept` or `Accept-Language` header (OPTIONS aside, and a
  WebSocket handshake needs no `Accept`);
- it names a browser no one still runs: Internet Explorer before 11, Chrome before 70, Firefox
  before 60 (the old Edge, which named an old Chrome, is left alone);
- it carries Chrome's client hints (`Sec-Ch-Ua`) while naming Firefox or Safari, or Chrome's hints
  do not name the version or the platform its user agent gives;
- it names two user agents.

Over HTTPS, when Carnical holds the certificate (`-tls-cert`), it is also `disguised` when:

- Chrome 80 or later, Firefox 90 or later or Safari 17 or later sends no `Sec-Fetch-*` header;
- Chrome 90 or later sends no client hints (Chrome's forks that do not send them, such as
  Samsung Internet, Yandex Browser, Android web views and Electron, are left alone);
- Chrome opens a WebSocket with neither (it sends none on a handshake), so a handshake, with its
  `Upgrade`, key, version and `Origin` headers, is excused from those two checks and from `Accept`,
  never from the TLS one;
- its TLS handshake is not that browser's: Chrome always offers GREASE values (RFC 8701), and
  Firefox always offers `record_size_limit` (RFC 8449). Python, Go, curl and most HTTP libraries
  offer neither.

A handshake is all those excuses buy: an answer to a WebSocket handshake that neither switches
protocols nor is an error (a page, a redirect) is withheld and answered 502 (rule 5000079), so a
program that copies a handshake's headers cannot fetch a page with them. Upgrades are refused anyway
unless `-allow-upgrade` is set.

A browser that passes these checks and sends a `Signature-Agent` header (an agent such as ChatGPT's
signing its requests) is `ai`, and one whose client hints say HeadlessChrome is `headless`. A
program cannot use those headers to get past the checks: it is still `disguised`. A long user agent
is searched whole, so padding cannot push a scanner's name out of sight.

Behind a load balancer or CDN, only the header checks apply. That holds whether it ends TLS or
opens a TLS connection of its own to Carnical. For a request from a `-trusted-proxies` peer,
Carnical does not use the connection's HTTP version, its TLS handshake, or the HTTPS-only checks of
`Sec-Fetch-*` and client hints. Those are the proxy's (nginx forwards over HTTP/1.0 by default),
and the visitor may have reached the proxy without HTTPS, when a browser sends neither header.
Tools that copy a
browser's handshake as well as its headers (curl-impersonate, curl_cffi, a real browser driven by
Playwright or Selenium with its user agent changed) pass as people. A browser behind antivirus or a
company proxy that reads HTTPS shows the proxy's handshake, so it can be read as `disguised`: run
`-bots-monitor disguised` first and read the alerts.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-bots` | `scanner` | Kinds to refuse, separated by commas: `fake`, `scanner`, `ai`, `seo`, `tool`, `headless`, `disguised`, `bot`; or `none`. |
| `-bots-monitor` | none | Kinds only logged: `intrusion detected` with `would_block`. A kind in both lists is refused. |
| `-bots-mode` | `block` | `monitor` only logs every kind `-bots` lists, as if they were in `-bots-monitor`. |
| `-bots-trust-networks` | off | When every DNS check is busy, let a crawler claim pass if the engine was verified in the address's /24 or /48 (see [Search engine checks](#search-engine-checks)). |
| `-bots-ranges` | none | `ENGINE=FILE` pairs separated by commas: the address ranges an engine publishes for its crawlers, verified without DNS (see [Search engine checks](#search-engine-checks)). |
| `-bots-exempt` | none | Addresses or ranges never refused by `-bots`, such as your own scanners; a range is no wider than a /16 (IPv4) or a /32 (IPv6). |

Setup asks "Bots to block" and writes these flags. In detect mode it keeps `-bots scanner` and puts
the answer's kinds in `-bots-monitor`.

| Setup answer | `-bots` |
| --- | --- |
| `none` | `none` |
| `fake` (recommended) | `fake,scanner` |
| `ai` | `fake,scanner,ai,seo` |
| `strict` | `fake,scanner,ai,seo,tool,headless,disguised,bot` |

Use `strict` only for a site that browsers alone use: mobile apps and API clients that set their
own user agent are `tool` or `bot`. Watch the kinds with `-bots-monitor` for a few days first and
read which clients would be refused.

A refused request is answered 403 and reported under its own id: 5005003 `ai`, 5005004 `seo`,
5005005 `tool`, 5005006 `headless`, 5005007 `scanner`, 5005010 `bot`, 5005011 `fake` and 5005012
`disguised`. The alerts are layer `bots`, category `bot` (and `scanner` for 5005007), signature
`bots-<id>`. `scanner` and `fake` are medium risk, the rest low. A refused scanner earns its address
4 points toward [auto-block](ddos.md#repeat-offenders) and a fake search engine 3, as attacks do; a
crawler or tool refused for its kind adds nothing. The flood protection counts all of them among
the site's refusals, and a refused request earns its address no standing.

## Search engine checks

For `fake`, a request that claims to be Googlebot (or GoogleOther, Google-CloudVertexBot), AdsBot,
Mediapartners-Google, Bingbot, Applebot, YandexBot, Baiduspider, PetalBot, SeznamBot, Naver's Yeti,
Amazonbot or AmazonAdBot is checked as each engine asks sites to. The address's DNS name must be in
the engine's domains, and that name must resolve back to the address.

| Engine | Domains |
| --- | --- |
| Google's common crawlers (Googlebot, GoogleOther, Google-InspectionTool, Storebot, Google-CloudVertexBot) | `googlebot.com` |
| Google's special-case crawlers (AdsBot, Mediapartners-Google, APIs-Google) | `rate-limited-proxy-*.google.com` |
| Bing | `search.msn.com` |
| Apple | `applebot.apple.com` |
| Yandex | `yandex.ru`, `yandex.net`, `yandex.com` |
| Baidu | `baidu.com`, `baidu.jp` |
| Petal | `petalsearch.com` |
| Seznam | `seznam.cz` |
| Naver | `naver.com` |
| Amazon | `crawl.amazonbot.amazon`, `amazonadbot.com` |

Google's user-triggered fetchers (`google-proxy-*.google.com`, `gae.googleusercontent.com`) are not
accepted for any crawler: they fetch whatever a user asks Google to, so a request through one could
otherwise claim to be Googlebot and pass. Nor is the rest of `googleusercontent.com`, where every
Google Cloud machine has a name.

Some engines publish their crawlers' addresses instead, or as well: Amazon publishes only addresses
for Amazonbot now, so without them a real Amazonbot from an address with no
`crawl.amazonbot.amazon` name is read as `fake`. `-bots-ranges` takes those lists, by engine
(`google`, `google-special`, `bing`, `apple`, `yandex`, `baidu`, `petal`, `seznam`, `naver`,
`amazon`), each a file in the JSON form the engines publish or one range or address a line, with
`#` comments. An address in its engine's list is verified without DNS; any other is still checked
by DNS. Name an engine twice to join two of its lists:

```sh
carnical start -bots fake,scanner \
  -bots-ranges amazon=/var/lib/carnical/ranges/amazonbot.json,google=/var/lib/carnical/ranges/common-crawlers.json,google-special=/var/lib/carnical/ranges/special-crawlers.json
```

| Engine | List |
| --- | --- |
| Amazon | the JSON under "Copy code" at `developer.amazon.com/amazonbot/ip-addresses/` |
| Google | `developers.google.com/static/crawling/ipranges/common-crawlers.json` (`google`), `special-crawlers.json` (`google-special`) |
| Bing | `www.bing.com/toolbox/bingbot.json` |
| Apple | `search.developer.apple.com/applebot.json` |

Do not give Google's `user-triggered-fetchers*.json`: those fetchers would pass as crawlers, which
DNS refuses. A file must be a regular file (no symlinks) of at most 4 MiB, and a range no wider than
a /16 (IPv4) or a /32 (IPv6), so a mistake cannot verify the whole Internet as an engine's. Finding
an address in the lists takes a binary search, however long they are
([ADR-0088](../../docs/adr/0088-carnical-indexed-crawler-ranges.md)).
DuckDuckGo, Qwant, Mojeek, Sogou and the other engines that publish no DNS names stay `search`.

How the check behaves:

- Answers are cached: 24 hours for a crawler, 1 hour for an impostor, 1 minute for a lookup that
  failed.
- A failed lookup counts as not verified. The reverse zone belongs to the address's owner, so an
  impostor could otherwise fail it on purpose.
- At most 8 checks run at once, each for at most 2 seconds, and at most 2 for one network (an IPv4
  /24 or IPv6 /48). With none free, the answer is no: real crawlers come from addresses already
  cached. A real crawler from a new address can therefore be refused as `fake` while impostors keep
  every check busy; it is let in once its own check runs.
- `-bots-trust-networks` lets such an address pass unchecked when a crawler of the same engine was
  verified in its /24 or /48 in the last day. That keeps crawlers passing under a flood, but trusts
  every address of those networks as the engine's. It is off by default: leave it off where a
  network's addresses need not belong to one owner, as in a cloud's shared ranges (Amazonbot crawls
  from AWS).
- An impostor sending from many addresses cannot push verified crawlers out of the cache: when it
  fills, expired answers go first, then impostors', and verified ones last.
- Carnical needs outbound DNS for this. `-confine` allows port 53 by default.

### Keeping the lists current

Engines move their crawlers, so a list goes out of date. Carnical keeps the lists current while it
runs ([ADR-0089](../../docs/adr/0089-carnical-crawler-lists-kept-current.md)):

- At start it logs `crawler ranges` for each file:
  - the engine, the file and how many ranges it holds;
  - `fetched`, the file's modification time, and `age_days`;
  - `published`, the engine's own `creationTime`, when the JSON has one. This is when the engine
    last rewrote the list: Bing's says 2024, because its list has not changed.
- Every minute it looks at the files. When one has been replaced or changed, it reads them all
  again and logs `crawler ranges reloaded`. Write a new copy beside the old one and move it into
  place (`mv`), so that a half-written file is never read.
- A file that cannot be used leaves the lists as they were. That includes a missing file, a
  symbolic link, a range that is too wide, or a file that does not parse. Carnical logs
  `crawler ranges not reloaded` with the reason, once, and keeps checking.
- A file last written more than 7 days ago is reported as `crawler ranges not refreshed`: at start,
  then at most once a day. The age is counted from the file's modification time, so it measures
  when the list was last fetched, not when the engine last changed it.
- Under `-confine`, Carnical can read a replaced file only from a directory listed in
  `-confine-read`. Keep the lists in a directory of their own, such as `/var/lib/carnical/ranges`,
  and list that directory. Without it, the lists read at start stay in use and each attempt is
  reported once.

Changing the lists needs no restart, so the flood shield's learnt baseline, its bans and its known
clients are kept.

[`deploy/ranges/refresh.sh`](../deploy/ranges/refresh.sh) fetches Google's, Bing's and Apple's lists
over HTTPS. It checks each with `carnical -check` and moves each one that passes into place. A list
that fails to download or to check is kept as it was, and the script exits 1.
`deploy/systemd/carnical-ranges.timer` runs it once a day; see the
[deployment recipe](../deploy/README.md). Amazon publishes Amazonbot's addresses only on a web page,
so copy them into `amazonbot.json` by hand.

Whoever can write the lists decides which addresses pass as a search engine. Keep the directory
writable by root only, as the recipe's `tmpfiles.d` line does; the host audit checks this.

## Counting

Every alert has `client`, the kind of client that sent the request. The `intrusion totals` line
counts requests that were refused (blocked, rate limited, or from a banned source), each once,
however many of its alerts refused it:

| Field | Meaning |
| --- | --- |
| `blocked_bots` | Requests from bots refused, for any reason: a bot kind, an attack, a rate limit or a ban. |
| `blocked_people` | Requests from people refused. Most are attacks sent with a browser's user agent; the rest may be false positives worth a look. |
| `blocked_bot_sources`, `blocked_people_sources` | About how many different addresses (IPv6 /64s) those came from; close to exact below a few hundred, above that typically within 2% (a standard error of about 1.6%) and rarely more than 5%. |
| `blocked_by_client` | The refused requests by kind, for example `{"ai": 120, "fake": 3, "person": 9, "tool": 41}`. |

```json
{"msg":"intrusion totals","blocked_bots":7,"blocked_people":2,"blocked_bot_sources":1,
 "blocked_people_sources":1,"blocked_by_client":{"ai":2,"fake":1,"headless":1,"person":2,"seo":1,"tool":2}, ...}
```

Requests the flood protection refuses on the connection, before any request is read, carry no
user agent and are not in these counts.
