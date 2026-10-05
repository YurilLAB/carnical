# Flood protection (`shield`)

Coraza and the Core Rule Set judge one request at a time, so they cannot see a flood. The shield (`carnical/shield`) sees the
traffic as a whole. It is on by default in `cmd/carnical` (`-ddos on`); `-ddos monitor` detects and logs without acting, and
`-ddos off` removes it.

## Where it acts

| Point | What it does | Rule IDs |
|---|---|---|
| Connection accepted (`Shield.Listener`) | Per-address connection rate (20/s, bursts of 60; a quarter of that for strangers during an attack). At most 1,024 connections per /24 (IPv4) or /48 (IPv6). At most 20,000 connections, with a fifth kept back for known clients. When connections run short, idle keep-alive connections of unknown clients are closed first. Banned addresses are reset at once. A refused connection is reset (RST), so it leaves no TIME_WAIT. | connection refusals are counted, not logged one by one |
| Socket (Linux) | `TCP_DEFER_ACCEPT` (10 s): a connection that sends nothing is never handed to the proxy. `TCP_USER_TIMEOUT` (30 s): a client that stops acknowledging data (slow read, zero window) is dropped by the kernel. | |
| Request, before any other check (`Shield.Admit`) | 50 requests a second per address (bursts of 200) and 500 per /24 or /48, at all times. During an attack: requests that look like the attack share 5 a second in total; clients the shield does not know share the site's usual rate; known clients and browsers that passed the check go on as normal. Addresses refused 30 times during an attack are banned for 10 minutes. | 5004001 address rate, 5004002 network rate, 5004003 attack cluster, 5004004 unknown-client budget, 5004005 check shown, 5004006/5004007 check failed/passed, 5004008 banned |
| Response (`Shield.Done`) | Status and time from the application: how clients become known, and how the detector sees the application struggling. | |

A refusal is 429 (rate) or 503 with `Retry-After`, `Cache-Control: no-store` and `Connection: close`. The shield never writes
a log line per refused request (in a flood that is a second flood, into the log); it writes a few lines per attack.

## Detecting an attack from many addresses and countries

A botnet of home routers, cameras and phones sends from tens of thousands of addresses, each slower than any per-address
limit. Per-address limits do not see it. The detector looks, every second, at the last ten seconds against a baseline (a
moving average with a 10-minute time constant, learnt only while traffic is ordinary):

| Signal | Attack looks like | People look like |
|---|---|---|
| Volume | several times the usual rate (4x by default, and at least 50 requests a second) | same, during a newsletter or a shared post |
| Fingerprint concentration (client program, header set, TLS settings) | one fingerprint is suddenly most of the traffic, from many addresses | the usual mix of browsers |
| Target concentration (path with numbers, IDs and query values removed) | one target, often with random query strings to get past caches | spread over pages and assets |
| New addresses | most requests from addresses never seen before | some |
| Engagement | a new address asks for one thing and nothing else | a page, then its CSS, scripts and images |
| Application health | errors or slow answers | — |

Volume alone is "elevated" (logged, nothing done). Volume with a concentrated fingerprint from at least 20 addresses, or a
concentrated target from new addresses that do not behave like browsers, or an application in trouble with traffic from new
places, held for 3 seconds, is an attack. An attack lasts at least a minute and ends after 30 quiet seconds.

## Who still gets through during an attack

- **Known clients:** 5 successful requests spread over at least a minute, while traffic was ordinary. A standing earned in the
  minute before the attack began does not count, so bots cannot earn it in the seconds before detection.
- **Browsers that pass a check:** an unknown browser that falls outside the budget gets a small page that finds a SHA-256
  answer in JavaScript (17 leading zero bits, about a second on a phone) and earns a cookie bound to its address and browser for
  30 minutes. Nothing is stored on the server. The page's JavaScript is tested against Go's SHA-256.
- **Everyone else** shares a budget equal to the site's usual rate. API clients are never shown the page; they get 503 with
  `Retry-After`.

## Measured

Simulation (`shield/sim_test.go`, simulated clock, the real `Admit`/`Done`, an application that can serve 200 requests a
second, 32 requests a second of ordinary traffic from 400 returning and many new visitors with six browsers):

| Scenario | Detected after | Attack admitted after detection | Returning visitors served | New visitors served |
|---|---|---|---|---|
| 20,000 addresses in 30 countries, 5,000 req/s, cache-busting `/` | 4 s | 0.10% | 100% | 100% |
| Same, `-ddos monitor` (control) | 4 s | — (not mitigated) | 3.1% | 3.1% |
| 30,000 addresses copying a real Chrome browser exactly, 3,000 req/s to `/search` | 4 s | 0.17% | 100% | 100% |
| Low and slow: 10,000 addresses, one request each every 20 s | 5 s | 1.0% | 100% | 100% |
| Flash crowd of real people, 10x the visits (negative control) | never (stays "elevated") | — | — | 100% |
| A crowd to one article whose assets are on another host | treated as an attack | — | 100% | 100% (through the check) |

The attack record estimated the first botnet at 20,421 addresses (true 20,000) in 106 country/network labels.

Live (`proxy/shield_linux_test.go`, Linux): the real proxy and listener, 1,000 bot addresses (127.1.x.y; Linux routes all of
127/8 to loopback) sending about 500 requests a second, 20 regular visitors. Detected 2.9 s after the flood began; after
detection 182 of 182 visitor requests were served and 18 of 21,977 flood requests reached the application (0.08%). With
`-ddos monitor` (control) all 22,597 flood requests reached it.

The first live run found a hole the simulation did not: with a one-second reputation age, bots earned "known" standing in the
2.5 seconds before detection, and 85% of the flood got through. Standing is now learnt only while traffic is ordinary, and
during an attack only standing earned at least `KnownMinAge` before the attack began counts.

## What it cannot do

- **Floods bigger than the network link** fill the link before they reach this machine. Only the hosting provider's network
  (its DDoS protection) or an upstream scrubbing service can stop those. Ask the provider what volumetric protection the
  server's network has.
- **Packet floods below TCP** (SYN floods, spoofed sources, UDP and reflection floods) are the kernel's work. SYN cookies are on
  (`deploy/sysctl/90-carnical.conf`); kernel firewall rate limits for the public port are not part of this change.
- **A patient botnet** that uses the site normally for minutes before attacking can earn known standing. Per-address limits
  still apply to it, and 30 refusals during an attack remove the standing.
- **A restart during an attack** relearns the baseline from the attack. Give `-ddos-baseline-rate` (the site's usual
  requests a second) to start from a known value.
- **Assets on another host:** a crowd to one page is then indistinguishable from a single-target flood and is treated as an
  attack; people get through by the check (measured above), at the cost of a one-second page.
- State is per process: several edges each keep their own.

## Flags

| Flag | Default | |
|---|---|---|
| `-ddos` | `on` | `on`, `monitor` or `off` |
| `-ddos-rate`, `-ddos-burst` | 50, 200 | requests per address |
| `-ddos-max-conns` | 20000 | connections at once (a fifth reserved for known clients) |
| `-ddos-challenge` | true | the browser check during an attack |
| `-ddos-baseline-rate` | 0 (learn) | the usual requests a second |
| `-ddos-ranges` | none | an ip2asn-style table (from iptoasn.com, public domain) so attack logs name countries and networks |

Load tests from one address (such as `tools/loadtest`) need `-ddos off` or a higher `-ddos-rate`.
