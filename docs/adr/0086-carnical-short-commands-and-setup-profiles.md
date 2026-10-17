# ADR-0086: Carnical short commands and setup profiles

- **Status:** proposed
- **Date:** 2026-10-17 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

`carnical setup` (ADR-0081) asked about connections and two protection choices, then printed
commands such as `carnical -config '/path/site.json' -config-key-file '/path/key' -check`.
Everything else (detection level, flood strength, auto-block, a login limit, alerts) needed one of
about 120 flags, and `-h` listed all of them. The owner asked for a setup that is straightforward,
short commands, a help command, setup of the basic security settings and protection profiles, and
the recommended answer shown next to each question.

## Decision Drivers

- Commands short enough to type and remember, with every existing flag form still working.
- Setup chooses only flags that start-up already validates, and checks them the same way.
- Every question has a recommended answer that is the safe start, or none when there is no safe
  default (allowing a private origin must be answered).
- Nothing new is stored outside the existing site file and key file.

## Considered Options

- Keep the wizard and document more flags. The operator still assembles the security settings.
- A preset file format of its own for profiles. A second format to validate and keep in step.
- Short commands over the existing flags, with setup questions that each set named flags.

## Decision Outcome

Chosen: **short commands over the existing flags, with setup questions that each set named flags**,
because the saved site stays an ordinary flags object that `-config` already reads, and every
answer can be checked by the start-up validation.

`carnical setup`, `check [FILE]`, `start [FILE]`, `help [TOPIC]` and `version` are added; any
other first argument that starts with `-` runs the proxy with flags as before, and no argument
prints the short guide. `check` and `start` add `-config` for the site setup saved in the
account's configuration directory (`os.UserConfigDir()/carnical/site.json`, next to the key
store), and `check` adds `-check -check-origin`; flags after the command are passed through.

Setup asks in five sections: the website, visitors, a protection profile (site type `general`,
`wordpress`, `api` or `java`, and detection level `relaxed`, `normal` or `strict`, which set
`-wordpress`, `-api-guard monitor`, `-allow-path-params`, `-inbound-threshold`/`-outbound-threshold
8` or `-paranoia 2`), security settings (`-mode`, `-ddos`, `-auto-block`, a `-limit 'POST PATH
10/m'` login limit and `-alerts`), then check and save. Only the flags that differ from the
defaults are written for a type or level. The recommended answer is shown in brackets and taken on
Enter; `?` shows help on the question. The recommendations are `detect`, `normal`, flood `normal`
(`relaxed` for an API), auto-block `monitor` and alerts `on`. Setup prints a summary after the
check and, when the site is saved in its default place, the next commands are `carnical check`
and `carnical start`. An existing file is still never replaced.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:** a site is set up, checked and started with three short commands; the basic
  security settings and profiles are chosen with a recommended answer each; the saved file stays
  readable and editable as flags.
- **Negative / follow-up:** a second site for the same account goes in a file of its own, named on
  the command line; the site type is chosen by the operator, not detected from the origin (the
  `profile` package could suggest it, at the cost of HTTP requests to the origin during setup).

## References

- ADR-0081: Carnical interactive site setup
- ADR-0084: Carnical intrusion alerts
- ADR-0085: Carnical repeat-offender blocking
- [Setup guide](../../carnical/docs/setup.md)
