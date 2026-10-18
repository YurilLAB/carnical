# ADR-0087: Carnical bot policy and bot and people counts

- **Status:** proposed
- **Date:** 2026-10-17 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Carnical's only bot defences were CRS 913100 and local rule 5006014, which score the default user
agents of vulnerability scanners, plus the flood shield and rate limits, which see how fast a client
is, not what it is. CRS v4 dropped its lists of HTTP libraries and crawlers. Nothing named AI
crawlers, SEO and data-mining crawlers, scraping libraries or headless browsers. Nothing caught a
scraper that claims to be Googlebot to get past robots.txt and rate limits. The owner asked for a
review of the protection against common and less common bots, scrapers and data miners. The owner
also asked that Carnical keep track of how many bots and how many people it blocked. The alert
totals (ADR-0084) counted findings by layer, action, risk and rule, not by who sent them. A second
review asked for the malicious bots of 2026 too: brute-force kits, botnets, internet-wide scanners,
address harvesters, and scripts that send a browser's user agent to pass as people.

## Decision Drivers

- Blocking bots is the site's policy, not a safe default. A shop wants search engines and may want
  AI crawlers; an API is used by tools. Nothing is blocked for being a bot unless the operator says
  so, with one exception: scanners and attack tools, whose user agents nothing but an attack sends.
- A user agent is the client's claim. Use it to name declared bots, and verify the one claim that
  can be verified: a search engine's, by the DNS check the engines document.
- Classifying must stay in the low microseconds, since the default policy runs on every request.
- No request content in alerts or totals (ADR-0084): the kind of client is a word from a closed
  vocabulary.

## Considered Options

- Local CRS rules listing bot user agents. These are only scored and reach the anomaly verdict, so a
  crawler adds 5 and is refused with every other finding, never on its own terms. They also cannot
  check DNS, and give no kind for the counts.
- Verify search engines against their published IP-range files. The files must be fetched and
  refreshed. Several engines publish only DNS names.
- A `bots` package that classifies requests into a closed set of client kinds, refuses the kinds
  `-bots` lists, verifies search engine claims by forward-confirmed reverse DNS, and stamps the
  kind on every alert so the totals count refusals by it.
- For programs posing as browsers, match TLS fingerprints (JA3, JA4) against a list of known
  browsers' or known tools'. The lists change with every browser release, and JA3 changes with
  Chrome's extension order on every connection. Two properties are stable instead: Chrome has sent
  GREASE values (RFC 8701) since 2016, and Firefox's NSS sends `record_size_limit` (RFC 8449);
  most HTTP libraries send neither.

## Decision Outcome

Chosen: **a `bots` package with a closed set of client kinds, a refuse list that defaults to
scanners, DNS verification of search engine claims, and header and TLS consistency checks for
programs that claim to be browsers**.

`bots.Classify` reads the User-Agent with one case-insensitive Aho-Corasick pass, the dependency
Coraza's `@pm` already uses. It also checks whether the Accept and Accept-Language headers every
browser sends are present, and the protocol. The kinds are:

- `person`: a browser, or a phone app's networking library.
- `search`, `ai`, `seo`, `tool`, `headless`, `scanner`, `preview` and `monitor`.
- `scanner` also covers brute-force kits (Hydra, Medusa, OpenBullet), internet-wide scanners
  (zgrab, Shodan, Censys, Expanse) and the misspelled or bare user agents botnets send (ZmEu,
  Mozlila, libredtail, "Hello, world").
- `bot`: no user agent, a contact URL, a user agent over 512 bytes, an unknown program, or a crawler
  word in a "compatible" agent.
- `fake`: a claimed Googlebot, GoogleOther, Bingbot, Applebot, YandexBot, Baiduspider, PetalBot,
  SeznamBot, Naver Yeti, Amazonbot or AmazonAdBot whose address fails the check.
- `disguised`: a browser's user agent that the request contradicts. Without TLS: HTTP/1.0, no Accept
  or Accept-Language, IE before 11, Chrome before 70 or Firefox before 60, Chrome's client hints on
  Firefox or Safari, hints that do not name the agent's version or platform, or two user agents.
  When Carnical ends TLS: no `Sec-Fetch-*` from Chrome 80, Firefox 90 or Safari 17 and later, no
  hints from Chrome 90 and later (forks that send none are left out), or a ClientHello without
  Chrome's GREASE or Firefox's `record_size_limit`. `Hellos` keeps each connection's ClientHello,
  read through `tls.Config.GetConfigForClient`, until `http.Server.ConnState` reports it closed.
- A browser's agent that passes those checks is `ai` with a `Signature-Agent` header (Web Bot Auth,
  sent by ChatGPT's agent) and `headless` with HeadlessChrome client hints. These checks come last,
  so a program cannot add the headers to move from `disguised` to a kind the site allows.

Where several words match, a fixed rank decides: scanner, ai, search, seo, headless, preview,
monitor, tool, then the app libraries. A named kind wins over the header checks, so a crawler is
never read as disguised. The whole user agent is searched, so that padding cannot push a scanner's
name past a cut; the server bounds headers to 32 KiB, which takes about 170 µs. The AI list follows the ai.robots.txt project.

`-bots` lists the kinds to refuse: `fake`, `scanner`, `ai`, `seo`, `tool`, `headless`, `disguised`
and `bot`. People, real search engines, link previews and uptime checks cannot be listed. The
default is `scanner`, in every mode: CRS 913100 only scores a scanner's agent, so in detect mode
nothing refused it. `-bots-monitor` lists kinds only reported (`would_block`); `-bots-mode monitor`
moves all of `-bots` there; `-bots-exempt` names sources never refused, under auto-block's
exclusion grammar and floor. Each kind refused has the id 5005000 plus its number, in a new `bots`
layer and `bot` category, with `scanner` also in the `scanner` category. `scanner` and `fake` are
medium risk, the rest low. A refused scanner earns 4 auto-block points, as the rule set's scanner
verdict does, and a fake search engine 3; a crawler or tool refused for its kind earns none. The
check runs after the flood shield and the proxy's own request checks, before rate limits and the
body. Setup's answers are none, fake (`fake,scanner`), ai (adds `ai,seo`) and strict (every kind);
in detect mode setup keeps `-bots scanner` and puts the answer's kinds in `-bots-monitor`.

Verification follows the engines' own instructions. The address's PTR name must be in the engine's
domains, on a label boundary, and resolve back to the address. Google's `googleusercontent.com` is
left out, because every Google Cloud VM has a name there. Answers are cached: 24 h verified, 1 h
refuted, and 1 min for a failed lookup, which still counts as not verified. The reverse zone
belongs to the address's owner, so failing open would let an impostor bypass the check by breaking
its own PTR. At most 8 checks run at once, each limited to 2 s. A request waits for its check, and
requests from the same address share one check. One network (IPv4 /24, IPv6 /48) holds at most 2
of the slots, so an impostor in one range cannot take them all. With no free slot the answer is
no, unless an address of the same network was verified for the same engine within the day: a
flood of impostors cannot force lookups, and real crawlers come from cached addresses or known
networks. When the cache fills, eviction drops expired answers first, then refuted ones, and
verified ones last, so impostors from many addresses cannot push real crawlers out. Engines that
publish no DNS names (DuckDuckGo, Qwant, Mojeek, Sogou, ...) stay `search`.

Every alert of a request carries its kind (`client` in the alert line). It comes from the policy
when it ran, otherwise from `Classify` when the request is finished, only for requests that have
alerts. The aggregator counts refused requests (blocked, rate limited, source blocked) by kind. It
also estimates how many distinct sources the refused bots and people came from, with one 4096-
register HyperLogLog each: 16 KiB, lock-free, near exact below a few hundred, and about 1.6% error
above. "Intrusion totals" gains `blocked_bots`, `blocked_people`, `blocked_bot_sources`,
`blocked_people_sources` and `blocked_by_client`.

Measured on the development machine, `Classify` takes about 1.9 µs and 7 allocations for a Chrome
request over TLS, and 0.8 µs for Googlebot. With the default policy this runs on every request,
small beside the rule set's evaluation.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:**
  - Scanners, attack tools and botnets are refused out of the box, in every mode, and their
    sources move toward an auto-block ban.
  - AI, SEO and data-mining crawlers, scraping tools, headless browsers, disguised programs and
    fake search engines can be refused by kind, or only reported first.
  - Real search engines are verified, not trusted by name.
  - Operators see how many bots and how many people were blocked, and from how many addresses.
- **Negative / follow-up:**
  - Kinds come from the client's own claim. A tool that copies a browser's handshake as well as its
    headers (curl-impersonate, curl_cffi) or a real browser driven by a program with its agent
    changed is counted as a person; telling it apart needs behaviour (the shield already
    fingerprints floods). The TLS checks apply only where Carnical ends TLS.
  - Antivirus and company proxies that read HTTPS present their own handshake, so a browser behind
    one can be read as `disguised`; the guide says to monitor the kind first.
  - Scanners are refused by default, so a site's own scans need `-bots-exempt` or `-bots none`.
  - Link previews and uptime checks cannot be verified or refused, so a scraper can claim one.
  - `tool` and `bot` also cover API clients and apps with custom user agents, so they are meant for
    sites that only browsers use.
  - Refusals the shield makes on a connection, before any request is read, have no user agent and
    are not counted by kind.
  - The word lists need updates as new crawlers appear.
  - Verification needs outbound DNS; `-confine` already allows port 53.

## References

- ADR-0084: Carnical intrusion alerts
- ADR-0085: Carnical repeat-offender blocking
- ADR-0086: Carnical short commands and setup profiles
- [Verifying Googlebot and other Google crawlers](https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot)
- [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt)
- [RFC 8701: GREASE for TLS](https://www.rfc-editor.org/rfc/rfc8701)
- [RFC 8449: Record Size Limit Extension for TLS](https://www.rfc-editor.org/rfc/rfc8449)
- [Bot policy guide](../../carnical/docs/bots.md)
