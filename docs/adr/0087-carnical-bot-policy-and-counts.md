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
totals (ADR-0084) counted findings by layer, action, risk and rule, not by who sent them.

## Decision Drivers

- Blocking bots is the site's policy, not a safe default. A shop wants search engines and may want
  AI crawlers; an API is used by tools. Nothing is blocked for being a bot unless the operator says
  so.
- A user agent is the client's claim. Use it to name declared bots, and verify the one claim that
  can be verified: a search engine's, by the DNS check the engines document.
- Counting must not add work to clean requests: classify only when a policy runs or a request
  already has an alert.
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

## Decision Outcome

Chosen: **a `bots` package with a closed set of client kinds, an opt-in refuse list and DNS
verification of search engine claims**.

`bots.Classify` reads the User-Agent with one case-insensitive Aho-Corasick pass, the dependency
Coraza's `@pm` already uses. It also checks whether the Accept and Accept-Language headers every
browser sends are present, and the protocol. The kinds are:

- `person`: a browser, or a phone app's networking library.
- `search`, `ai`, `seo`, `tool`, `headless`, `scanner`, `preview` and `monitor`.
- `bot`: no user agent, a contact URL, an unknown program, a crawler word in a "compatible"
  agent, or a browser's agent over HTTP/1.0 or without those headers.
- `fake`: a claimed Googlebot, Bingbot, Applebot, YandexBot, Baiduspider, PetalBot, SeznamBot or
  Naver Yeti whose address fails the check.

Where several words match, a fixed rank decides: scanner, ai, search, seo, headless, preview,
monitor, tool, then the app libraries. The AI list follows the ai.robots.txt project.

`-bots` lists the kinds to refuse: `fake`, `ai`, `seo`, `tool`, `headless`, `scanner` and `bot`.
People, real search engines, link previews and uptime checks cannot be listed. The default is none.
Each kind refused has the id 5005000 plus its number, in a new `bots` layer and `bot` category. All
are low risk, except `fake` at medium, because the client lies about itself. None counts toward
auto-block. The check runs after the flood shield and the proxy's own request checks, before rate
limits and the body. `-bots-mode monitor` reports `would_block` instead.

Verification follows the engines' own instructions. The address's PTR name must be in the engine's
domains, on a label boundary, and resolve back to the address. Google's `googleusercontent.com` is
left out, because every Google Cloud VM has a name there. Answers are cached: 24 h verified, 1 h
refuted, and 1 min for a failed lookup, which still counts as not verified. The reverse zone
belongs to the address's owner, so failing open would let an impostor bypass the check by breaking
its own PTR. At most 8 checks run at once, each limited to 2 s. A request waits for its check, and
requests from the same address share one check. With no free slot the answer is no: a flood of
impostors from many addresses cannot force lookups, and real crawlers' addresses are already
cached. DuckDuckGo, Qwant, Mojeek and Sogou publish no DNS names, so their claims stay `search`.

Every alert of a request carries its kind (`client` in the alert line). It comes from the policy
when it ran, otherwise from `Classify` when the request is finished, only for requests that have
alerts. The aggregator counts refused requests (blocked, rate limited, source blocked) by kind. It
also estimates how many distinct sources the refused bots and people came from, with one 4096-
register HyperLogLog each: 16 KiB, lock-free, near exact below a few hundred, and about 1.6% error
above. "Intrusion totals" gains `blocked_bots`, `blocked_people`, `blocked_bot_sources`,
`blocked_people_sources` and `blocked_by_client`.

Measured on the development machine, `Classify` takes about 1.5 µs and 6 allocations for a Chrome
request, and 0.8 µs for Googlebot.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:**
  - AI, SEO and data-mining crawlers, scraping tools, headless browsers and fake search engines can
    be refused by kind, or only reported first.
  - Real search engines are verified, not trusted by name.
  - Operators see how many bots and how many people were blocked, and from how many addresses.
- **Negative / follow-up:**
  - Kinds come from the client's own claim. A bot that copies a real browser's headers exactly is
    counted as a person; telling it apart needs behaviour or TLS fingerprints (the shield already
    fingerprints floods).
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
- [Bot policy guide](../../carnical/docs/bots.md)
