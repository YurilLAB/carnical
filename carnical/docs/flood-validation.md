# Flood validation record

These results use the recorded simulation/live fixtures. They explain the detector's tested
behavior and previous fixes; they are not production capacity guarantees.
For current settings, see [flood protection and IDS](ddos.md).

Measured (`TestASiteWithMuchTrafficIsNotLimitedAsIfItWereSmall`): a site serving 1,200 requests a second, half of its returning
visitors behind four shared addresses of about 120 requests a second each. After 25 minutes of ordinary traffic from a start (the
time the shared addresses need to earn their limits, since a second counts for at most twice an address's average from the first
second on) the per-address limit had risen 5.7x and the per-network limit 3.1x, and in the following minute 100% of returning
visitors were served (86% over the 25 minutes). With the limits fixed (control) 71% were. An attack of 8,000 requests a second
from 25,000 addresses on that site was detected after 8 s, 0.31% of it reached the application, and 100% of returning and new
visitors were served. A sudden tripling of real traffic was not flagged.

The adjustment is bounded: one address that sends a lot for a long time raises the per-address limit by at most 20x, a rise is
learnt at most twice per step, and nothing is learnt during an attack. The raised limit applies to every address, not only to
the busy one (see 2026-10-11 below).

The 80% file-descriptor ceiling applies to the initial connection floor as well as later growth. A small process with a soft
limit of 1,024 therefore admits at most 819 shield connections before the reserved share, even with the default 20,000 floor.
This ceiling leaves some descriptor headroom; it is not a memory or CPU budget. Set `-ddos-max-conns` lower when necessary,
and measure origin sockets, TLS handshakes, rule evaluation and memory use before raising it on a large edge. Kernel packet
budgets are configured separately; see [deployment profiles and live scaling tests](network-protection.md#choosing-a-budget).

## Measured

Simulation (`shield/sim_test.go`, simulated clock, the real `Admit`/`Done`, an application that can serve 200 requests a
second, 32 requests a second of ordinary traffic from 400 returning and many new visitors with six browsers):

| Scenario | Detected after | Attack admitted after detection | Returning visitors served | New visitors served |
|---|---|---|---|---|
| 20,000 addresses in 30 countries, 5,000 req/s, cache-busting `/` | 4 s | 0.10% | 100% | 100% |
| Same, `-ddos monitor` (control) | 4 s | — (not mitigated) | 3.1% | 3.1% |
| 30,000 addresses copying a real Chrome browser exactly, 3,000 req/s to `/search` | 4 s | 0.17% | 100% | 100% |
| Low and slow: 10,000 addresses, one request each every 20 s | 5 s | 1.0% | 100% | 100% |
| Busy site (1,200 req/s, half its returning visitors behind 4 shared addresses): 8,000 req/s from 25,000 addresses | 8 s | 0.31% | 100% | 100% |
| Busy site, real traffic suddenly 3x (negative control), 8 minutes after a start | never flagged | — | 59% (the shared addresses have not yet earned their limits) | 100% |
| Flash crowd of real people, 10x the visits (negative control) | never (stays "elevated") | — | — | 100% |
| A crowd to one article whose assets are on another host | treated as an attack | — | 100% | 100% (through the check) |

The attack record estimated the first botnet at 20,421 addresses (true 20,000) in 106 country/network labels.

Live (`proxy/shield_linux_test.go`, Linux): the real proxy and listener, 1,000 bot addresses (127.1.x.y; Linux routes all of
127/8 to loopback) sending about 500 requests a second, 20 regular visitors. Detected 3.0 s after the flood began; after
detection 180 of 180 visitor requests were served and 17 of 21,751 flood requests reached the application (0.08%). With
`-ddos monitor` (control) all 22,767 flood requests reached it.

Two flaws were found later, by testing a busy site and a site whose traffic is one app calling one endpoint, and are fixed. The
detector had a fixed floor of 50 requests a second and a baseline that started at zero, so a bursty busy site was declared under
attack in its first seconds, the baseline froze, and the attack could not end because the traffic never fell (reproduced:
1,197 of 1,200 seconds "in attack", baseline stuck at 7 requests a second). Now there is a learning period, an evidence-based way
out (an attack that shows none of the evidence that declared it for 5 minutes ends even if traffic has not fallen), and the
limits above. The test removes all four safeguards at once and fails; with them it passes.

The first live run found a hole the simulation did not: with a one-second reputation age, bots earned "known" standing in the
2.5 seconds before detection, and 85% of the flood got through. Standing is now learnt only while traffic is ordinary, and
during an attack only standing earned at least `KnownMinAge` before the attack began counts.


## 2026-10-10: Reproducible cardinality checks

`TestHLLEstimatesWithinAFewPercent` now uses deterministic SHA-256 hash fixtures for 50, 5,000 and 200,000 distinct inputs, retaining the 8% error limit. Production address hashing still uses its random process seed. HyperLogLog has [statistical estimation error](https://algo.inria.fr/flajolet/Publications/FlFuGaMe07.pdf), so a fresh random seed cannot guarantee the same error on every test run. A 100-seed diagnostic produced three estimates outside 8%.

The same test also checks register-index and rank boundaries, duplicate address hashing, merge preservation, reset and finite estimates. Manual negative controls disabled register updates, removed the rank sentinel, or returned NaN; each was rejected. The live flood and detector tests continue to exercise production address hashing.

## 2026-10-11: Known clients have a budget during an attack

A review found that known standing let a client past every attack budget, limited only by its own per-address rate. Standing
costs five ordinary requests over a minute and lasts seven days, so a botnet could earn it a day ahead and flood with it.
Reproduced: a client with standing that sent the attack's exact fingerprint at 45 requests a second had 13,500 of 13,500
requests admitted during an attack, and a stranger 1. Known clients now share a budget of twice the usual rate (at least 50
a second, `KnownFactor` and `MinKnownRate`); beyond it they are treated like strangers, so they are challenged or refused,
struck, and banned, and a ban removes their standing. Browsers that answered the challenge are not held to it.

| Scenario (simulation, as above) | Detected after | Attack admitted after detection | Returning visitors served | New visitors served |
|---|---|---|---|---|
| 2,000 addresses that each loaded `/` every 100 s for ten minutes, then 3,000 req/s to `/search` as Chrome | 4 s | 3.2% | 98.8% | 98.8% |
| Same, with the known budget unbounded (control: the behaviour before) | 4 s | 6.6% (the application was saturated) | 6.1% | 7.8% |

`TestStandingDoesNotCarryAFlood`: 200 addresses with standing, each sending 10 requests a second with the attack's fingerprint
for a minute, had 2,630 of 120,000 admitted, against 120,000 before; 196 were banned and lost their standing, a known client was
served again once they were gone, and a browser that answered the challenge was served while the budget was spent. The other
simulations above gave the same results.

A client that stops reading held the application's places. Research on HTTP/2 flood techniques found that Go's own fixes (Rapid
Reset, CONTINUATION, MadeYouReset and the 2026 header and settings fixes) are in the Go 1.26.9 this edge builds with, but that a
response stuck on a client that is not reading keeps one of the `-max-upstream` places until the write timeout. Reproduced with
an HTTP/2 client that set its stream window to zero and opened eight requests for a 1 MiB response against eight places: another
client got 503 at 1, 10 and 30 seconds, and would until the 120 second write timeout. With the hand-over (rule 5000052) the same
client is served at once; the test covers HTTP/2 streams and HTTP/1.1 over TLS, runs under the race detector, and a unit test
checks which response is ended, the limit on how many may be finishing, and that a place is given back once.

Cost, measured with the real binary and a micro-benchmark on a Ryzen 5 5600X (12 logical CPUs): the place accounting is a mutex and a map
insert where there was a channel send, about 35 ns more a request on one core and 86 ns more with 12 cores hammering it, and the
wrapper about 30 to 65 ns and two small allocations (80 bytes); a request through the rules takes about 3 ms. Three runs each of
10,000 requests through the committed binary and the new one, alternating, gave medians of 5,296 and 5,216 requests a second (-1.5%,
within the 4.7% spread between runs of one binary) and a p99 of 8.6 and 9.2 ms.

The same review showed that the per-address limit follows the busiest address. In a simulation one address sending 600
requests a second against the 50 a second limit, for 45 minutes on a site of 30 a second, raised the per-address limit for
every address to 20x (control without it: 1x). This is the adjustment working as designed for shared addresses, and it is now
listed under what the protection cannot do.

## 2026-10-11: A connection that is not read is dropped, not waited for

When a response over HTTP/1 with TLS was ended to free its place (rule 5000052), the place was free at once but the
connection was not: closing it first writes a TLS `close_notify` to the same client that is not reading, which Go waits
on for five seconds, and after the close the kernel kept the unsent part of the response and went on offering it. A
client could so hold a socket, and the memory of what was queued for it, well past the hand-over. The connection is now
closed underneath TLS and set to reset. The test, which goes through the shield's listener as a deployment does, finds
the server done with the connection within two seconds of the hand-over (before: five or more), the client told of a
reset and not of an orderly close, and the other connection untouched. An HTTP/2 stream is reset as before, since its
connection carries the client's other requests. The test runs on Windows and Linux and under the race detector. Of
eleven deliberate breaks of the change ten fail it; the eleventh (not cancelling the request to the application when the
connection is dropped) makes no difference, because dropping the connection cancels the request as well.

## 2026-10-11: Each address earns its own limit

The per-address and per-network limits followed the busiest address of the site, so one heavy address raised the limit
of every address (see above). Each address and each network now has its own moving average of the requests a second
that the application answered well for it, and only its own limits are raised by it: to four times that average, at
most 20 times what is configured. On the simulated site of about 1,200 requests a second with visitors behind shared
addresses, 99.4% of returning visitors are served (71.0% with the limits fixed), with the busiest address's limit at 9.4
times and the busiest network's at 3.7 times the configured ones. An address that had sent nothing, and then sent 600
requests a second for five seconds on that site, was served no more than the 450 its configured limit allows, of 3,000.
In an attack of 8,000 requests a second from 25,000 addresses on the same site, detected after 8 seconds, 0.3% of the
attack was admitted and returning and new visitors were served in full; what a shared address had earned was the same
after the minute of the attack as before it (within 5%).

The tests also cover answers that earn nothing (a 404, a 500, and an answer from the proxy itself), trusted addresses,
one second's burst while the detector warms up, a sudden rise after it, fading within an hour of the last request, an
average kept when a flood of new addresses fills the tables, a ban taking it away, connection limits rising with the
request limit, and the two figures on the dashboard. Each of 35 deliberate breaks of the change fails a test.

Two limits are stated in [ddos.md](ddos.md) and not changed. An address that is answered well for tens of minutes earns
a higher limit for itself, whoever is behind it, and an address that asks for a few pages over a minute is still known:
nothing an address tells can separate a patient bot from a visitor. Both are bounded by the ceiling and the known-client
budget and are lost with a ban. IPv6 networks stay grouped by /48, the block one site is given.

Because an address raises its own limit by using it, how fast and how far was measured and the ceiling made a setting
(`-ddos-max-raise`, 20 by default, 1 for fixed limits). One address that asks for a quarter more than it was last given,
on a site of 60 requests a second that the detector knows, is served its configured limit after 5 minutes, 1.4 times it
after 10, 2.2 after 15, 3.8 after 20, 10 after 30 and the ceiling of 20 after 40, and no more after an hour; with a
ceiling of 4 it stops at 4 and with 1 it never moves. The site stays in its normal state throughout: an address that
asked for 300 requests a second instead made the detector report a rise within ten seconds. Eleven deliberate breaks of the
ceiling, of the limit on a sudden rise and of the flag each fail a test.

## 2026-10-16: Showing the challenge counts for a tenth of a refusal

Each challenge page shown during an attack counted toward the address's ban, as a refusal does. At an address many people
share (a carrier's NAT, an office), 30 people each shown the challenge once got the address banned for ten minutes, the
browsers that had answered it with the rest. Reproduced: a browser that answered and was served was refused (rule 5004008)
after 30 others at its address were shown the challenge. Now ten pages shown count as one refusal, so it takes some 300
people. Not counting them at all was tried first: a bot that sent page loads under its own limit was then never banned, and
was shown the challenge for ever, each page costing about two and a half times what a refusal does, on a connection left open.
Reproduced: one address loading `/` 20 times a second was shown it on 1,999 of 2,000 requests and never banned. Now it is
banned after 300, in 15 seconds. Counted at a tenth, the people who answer still added up: with a ban after 3 refusals, 30
people behind one address who were each shown the challenge and answered it got the address banned, so a right answer now
takes back one challenge shown. A browser shown a page that names no icon also asks for `/favicon.ico`, which the attack's
budget refused as a full refusal, so 30 people who answered still got the address banned: the page now names an empty icon,
which its Content-Security-Policy allows. A client can send one answer as often as it likes, so answers take back no more than the
address was shown, and never a refusal or a wrong answer. In the simulation of 2,000 addresses with standing that copy
Chrome (above), 3.6% of the attack was admitted after detection, against 3.2%, with 98.8% of returning and new visitors
served as before: those bots send about one request a second each, and are no longer banned for the challenge they are
shown. The other simulations gave the same results.

## 2026-10-16: What the baseline learns, and when an attack ends

A review of the detector found four ways its baseline learnt the wrong thing, or stopped protecting while a flood went on.
Each is now a case in `TestSimulatedAttacks` that fails without its fix.

- **New fingerprints and targets were never learnt after warm-up.** A second weighs a six-hundredth once warmed up, so a key
  new to the baseline entered below the fifth of a percent at which it is forgotten and was dropped at once: a browser
  released after the start stayed "usually 0%" for good. Reproduced: half the visitors moved to Chrome 142 after the
  warm-up, and a tenfold crowd of people half an hour later was declared an attack. Now a key is never forgotten in a
  second it was seen in; the new browser's assets were learnt at 35.9% of requests (about their real share) and the crowd
  stayed "elevated".
- **`-ddos-baseline-rate` skipped the warm-up of every measure, not only the rate.** An app's own users surging fivefold
  five minutes after a restart were declared an attack, its fingerprint and endpoint "usually 40.3%". The rest of the
  baseline now has its own five-minute warm-up and learns, during it, only from seconds under the threshold; the surge
  stays "elevated". Learning from every second instead was tried and fails another case: after a restart into a flood of
  2,000 requests a second at one target from 64 programs, with the usual rate given, on an application that keeps up,
  the target and the new addresses were learnt as usual in the first second and the flood stayed "elevated". With the
  threshold rule it is declared after 4 s. (A flood that also hurts the application is declared either way, since a
  failing application stops the learning, below.)
- **A flood that ramped up slowly was never declared.** The baseline followed it, at up to twice its rate a second's
  weight at a time, and learnt the application's errors as usual. Reproduced: a botnet of 20,000 addresses growing from
  10 requests a second by 0.3% a second (doubling every four minutes), on an application that serves 200, was at most
  "elevated" for 40 minutes, with 3,000 requests a second at the end; at 0.15% a second, as found, it stayed "normal".
  The application's error ratio is now also averaged six times more slowly (about an hour), and in a second where the
  application is failing against that average the usual error ratio and latency can only fall, the traffic's look is not
  learnt, and the usual rate can rise only as far as the requests the application answers well rise from when it began
  to fail. Holding the rate still outright was tried first and fails another case: traffic growing sixfold over twenty
  minutes while a broken dependency fails three requests in ten, whatever the load, was declared an attack at 193
  requests a second against a usual frozen at 32, and 43% of new visitors were not served; the application answers more
  of it as it grows, as it cannot a flood's, and it now stays "normal". The 0.3%
  flood is declared after 1,218 s at 386 requests a second (the usual frozen at 102), with returning and new visitors
  served in full in the minute after. The 0.15% flood is declared after 2,686 s at 562 requests a second but held off
  only in part: the application kept up with it to about 170 a second, so the usual it froze at, 146, was mostly the
  flood's; the attack's budgets, sized from it, let in 30.5% of the flood, and returning and new visitors were served
  64.8% and 64.4% in the minute after. Ordinary traffic growing as fast, tenfold, on an application that keeps up, is
  not flagged. Latency was first part of the test of a failing application, as an average against its own hour-long
  average, and was taken out: it is measured until the response has been sent, so four addresses downloading slowly (one
  request in twenty, half a minute each) held it high, the baseline stayed at 50 requests a second while the site's own
  traffic grew tenfold, and that growth was declared an attack at about 340 a second, 18% of new visitors not served.
  An application that queues what it cannot serve, instead of failing it, showed no failure at all: its clients hang up
  long before it would, and a request the client hung up on was left out of its health, so that clients that hang up at
  once could not make a healthy application look as if it failed. The 0.3% flood against it, with every client hanging
  up after five seconds, was never declared and was learnt as the usual. A hang-up after at least a second and four
  times the usual latency now counts as the application's failure, and that flood is declared as the one above is.
- **An attack declared from harm alone ended after the evidence time-out while the flood went on.** Once mitigated, the
  application is well again and a flood that rotates its look shows nothing else, so the attack ended and the flood was
  let back in. Reproduced with 2,000 requests a second from 200,000 addresses and a two-minute time-out: the attack
  ended twice in five minutes. The mitigation now counts as evidence while the rate is over the threshold of the
  baseline from before the attack and at least half of the requests are refused or shown the challenge; the attack is
  held for the five minutes and 1.6% of the flood is admitted. At first that counted every refusal, and one address that
  went on at 400 requests a second after the flood, refused by its own limit and then banned, held the attack for over
  an hour, with the baseline frozen and new visitors on the attack's budgets. What an address's or a network's own
  limit refuses is now left out of both the rate and the refusals, since it is held whether there is an attack or not,
  and so are the refusals of banned addresses unless they come from at least 20 addresses in ten seconds; with that
  address going on the attack ends 129 s after the flood stops, at the time-out. Leaving out every ban's refusals was
  tried first and fails another case: the same flood from 2,000 addresses, one request a second each, had them banned
  within a minute, the bans' refusals were then most of it and did not count, and the attack ended at the time-out;
  the baseline learnt the banned flood's addresses, and when the bans ran out the flood was not declared again and,
  over forty minutes, visitors were served about 10% (the case in the simulation uses 1,000 addresses and shorter bans). Counting every refusal by the attack's budgets had a fault of its own: a flood
  declared on an app's API, then stopped, followed by the app's own users at eight times their usual rate, held the
  attack for as long as they kept it up (the twenty minutes measured), with returning users served 53% and new 21%,
  since the budgets, sized from the usual before the flood, refused most of them. The mitigation now counts only while
  the share of requests whose fingerprint the baseline knew is under half what it was before the attack; the users,
  who look as they did, let the attack end at the time-out, and the floods above, from programs the site did not see
  before, are held. Two floods still ended at the time-out. One from eight programs that ran for fifteen seconds at 150
  requests a second, over the threshold but not yet hurting, before going to 2,000 a second: its programs were learnt at
  a sliver each in those seconds, and a fingerprint the baseline held at all counted as the site's own. Now the usual
  fingerprints and targets are learnt only from seconds under the threshold, and a fingerprint counts only when it was at
  least 0.2% of the usual requests, the share below which the baseline forgets it. The other came after a restart into
  the flood with `-ddos-baseline-rate`: the baseline had learnt no fingerprint, so the flood could never be unlike it.
  Then the fingerprints are now left out of the test. Both are held for the five minutes.

Three consequences are stated in [ddos.md](ddos.md). Real visitors that grow past four times the usual rate while the
application cannot keep up are treated as an attack, as a flood would be (known visitors and browsers that answer the
challenge are still served); before, the baseline learnt the failure. A flood slow enough to be learnt in part while the
application keeps up is declared but held off only in part, as above. And the mitigation holds an attack for as long as
traffic over the threshold that it mostly refuses is unlike the site's own clients by fingerprint, not for five minutes at
most; the site's own clients, however much of their traffic the attack's budgets refuse, let it end after the five minutes.
The other simulations gave the same results as before, within 0.1 point.
