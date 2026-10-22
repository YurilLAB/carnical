# ADR-0097: Carnical's stricter local rules detect until they are switched on

- **Status:** proposed
- **Date:** 2026-10-21 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Three local rules (5006101 to 5006103) find what some sites receive in ordinary use: a page called `/console`, a
visitor's own `.php` address in a form field, a forwarded host a load balancer sets. They were removed from the rule set
unless `-local-rules-on` named them, so on a site with the defaults what they would have found left no trace. In the
live suite the default setup let 59 attack templates through to the origin: 32 repeated parameters, which the format
checks already report in monitor mode, and 27 addresses of a script on another host in a form or JSON field, which
rule 5006102 would have found and which raised no alert at all. The owner asked for the attacks the default setup lets
through to raise alerts instead of being blocked.

## Decision Drivers

- Refuse nothing that is forwarded today: the rules are off by default because they refuse ordinary requests.
- Every attack the default setup forwards should leave an alert an operator can act on.
- An alert should say that the rule only detected, so it is not read as a refused request or as part of a score.
- Keep `-local-rules-on` and `-local-rules-off` as they are, and keep the rule file one file.

## Considered Options

- **Leave them out (as before).** Nothing to tune, and nothing seen.
- **A second, scoreless copy of each rule under another id.** Two ids for one finding, and the copy has to be kept the
  same as the rule by hand.
- **The rule always loaded, its score a variable set by the switch (chosen).**

## Decision Outcome

Chosen: **the rule always loaded, its score a variable set by the switch**, because one rule then serves both states and
nothing is forwarded or refused differently from before.

- Each stricter rule adds `%{tx.carnical_points_<id>}` to the inbound score. `crs.Settings.Directives` sets that to 5
  for a rule `LocalRulesOn` names and 0 for the others, in one `SecAction` (5006099) before the local rules load. A rule
  `LocalRulesOff` names is removed as before, so it neither scores nor reports.
- A rule that is neither on nor off still matches and logs, so the proxy writes its finding as an alert:
  `intrusion detected`, action `detected`, mode `detect`. `crs.Settings.OnlyDetects` tells the proxy which rules these
  are; their findings are alerts of their own and never part of the anomaly verdict's rules, since they added nothing
  to its score.
- The live WAF gate re-sends every attack that reaches the origin from a loopback address of its own
  (`tools/loadtest -alert-probe`), reads the alerts written for that address, and fails when one raised none.

## Technical Discussion

No substantive technical discussion recorded: the change was made for the owner, without a pull request.

## Consequences

- **Positive:** in the live suite all 59 attacks the default setup forwards now raise an alert, as do all of those the
  format-monitor setup forwards; none of the 390 benign controls forwarded raises one from these rules.
- **Positive:** an operator sees what a stricter rule would refuse before switching it on.
- **Negative:** a site whose ordinary traffic matches one of the rules (a shop's `/console` page, a form that asks for
  a web address) now gets `intrusion detected` lines for it, deduplicated per source; it silences them with
  `-local-rules-off` or `-alert-suppress`. Rule 5006103 leaves the case this was first feared for alone: a forwarded
  host that is one of the site's own names, and any forwarded host a proxy in `-trusted-proxies` sends, are not another
  host, so a load balancer that sends the public name raises no alert.
- **Negative:** each stricter rule is evaluated on every request, where it was removed before; they are three anchored
  expressions over the path, the body arguments and three headers.

## References

- Related ADRs: ADR-0072 (local rules), ADR-0084 (alerts)
- Code: `carnical/crs/crs.go`, `carnical/crs/local/REQUEST-499-CARNICAL.conf`, `carnical/proxy/verdict.go`,
  `carnical/proxy/deadline.go`, `carnical/tools/loadtest/main.go`, `.github/security/check_live_report.py`
- Documentation: `carnical/docs/input-hardening.md#stricter-rules`
