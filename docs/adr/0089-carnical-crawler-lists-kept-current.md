# ADR-0089: Crawler address lists kept current while the edge runs

- **Status:** proposed
- **Date:** 2026-10-18 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

`-bots-ranges` verifies search engine crawlers by the address lists the engines publish
([ADR-0087](0087-carnical-bot-policy-and-counts.md)). The files were read once, at start, and
nothing said how old they were. Engines move their crawlers, so the lists go out of date. A stale
list refuses a real crawler that has moved to new addresses as `fake`, and keeps verifying addresses
an engine has given up.

The only way to load a refreshed list was to restart the edge. A restart drops what the edge has
learnt:

- the flood shield's baseline (a restarted shield learns again, or needs `-ddos-baseline-rate`);
- its bans and its known clients;
- the cache of DNS answers.

A daily refresh would reset all of it every day.

## Decision Drivers

- A refreshed list must take effect without a restart.
- A mistaken or half-written list must never replace a good one.
- An operator must be told when the lists are not being refreshed.
- `-confine` must not be weakened to make this possible.
- Whoever can write the lists decides who passes as a search engine, so the lists need an owner no
  service user can impersonate.

## Considered Options

- **Restart after each refresh.** This is simple, and `ExecStartPre` checks the new files. But it
  loses the state above every time, and a bad list stops the edge from starting.
- **Reload on SIGHUP.** A hang-up already stops the edge the way SIGTERM does (there was no
  configuration to reload). Changing what a signal does changes the behaviour of existing service
  managers and scripts.
- **Look at the files every minute and read them again when one changes.** A new copy must be read
  in whole and parse before it replaces anything. Otherwise the lists in use are kept and the
  failure is reported once.
- **Fetch the lists from inside the edge.** This puts an HTTP client and the engines' URLs in the
  process that faces the internet, and lets anyone who controls those responses change who passes
  as a crawler. The edge would also need outbound HTTPS to more than the origins.

## Decision Outcome

Chosen: **look at the files every minute**, with fetching done outside the edge.

The edge:

- At start, logs `crawler ranges` for each file: the engine, the file, the number of ranges, its
  modification time (`fetched`), `age_days`, and `published` (the JSON's `creationTime`, when the
  engine gives one).
- Every minute, compares each file with the copy it read (same file, size and modification time).
  When any differs, it reads them all again. The lists are replaced only when every file reads,
  stays the same while it is read, and parses. Lookups run on without a lock: `Verifier.SetRanges`
  swaps one pointer.
- Logs `crawler ranges reloaded` on success. On failure it logs `crawler ranges not reloaded` with
  the reason, once per reason, and keeps the lists it had.
- Warns `crawler ranges not refreshed` at start, then at most once a day, for any file last written
  more than 7 days ago. The age comes from the file's modification time, so it measures when the
  operator last fetched the list. The engine's `creationTime` cannot measure that: Bing's list was
  last rewritten in January 2024 and is still current.

Under `-confine`, a file is read again only from a directory the operator lists in `-confine-read`.
No directory is added to the confinement on the operator's behalf. Without one, the lists read at
start stay in use and the refusal is reported once.

Outside the edge, `deploy/ranges/refresh.sh` runs from `carnical-ranges.timer` once a day:

- It fetches Google's, Bing's and Apple's lists over HTTPS only.
- It checks each with `carnical -check`, the same parser and limits the edge uses, and moves each
  one that passes into place.
- It keeps a list that fails to download or to check, and exits 1.

The unit runs as its own user, `carnical-ranges`, with no capabilities, and the machine is
read-only to it except `/var/lib/carnical/ranges`. That directory belongs to that user and is
readable by all. `sysusers.d` makes the user and `tmpfiles.d` the directory, and the host audit's
ownership check requires it to be that user's and no more than 0755. Root with no capabilities was
tried first, but it does not contain a compromised download: root still reads root's files that
are read-only to it, can ask systemd over its private socket to start any unit, can signal root's
daemons, and passes the nftables rule that keeps every other user from the cloud metadata service.
The nftables policy limits outbound traffic only for the edge and the internal services, so the
updater's user needs no rule of its own.

Verified:

- **`TestCrawlerListsStayCurrent`** in `cmd/carnical`. It covers:
  - an unchanged list is not read again;
  - a new copy replaces the old one;
  - a copy that does not parse, a removed file and a symbolic link each leave the list as it was,
    and are reported once;
  - a week-old list is reported at start, then once a day;
  - the start-up line's fields.

  Five deliberate faults each made it fail:
  - always reloading;
  - reporting a failure every minute;
  - no daily limit on the staleness warning;
  - a wrong age threshold;
  - not installing the new lists.
- **`TestVerify`** runs a replacement while requests are checked, under the race detector.
- **Live, with the binary.** A list was moved into place while Carnical ran. Within a minute,
  Googlebot from the old list's address got 403 and from the new list's address 200.
- **Live, confined** (Landlock ABI 7, seccomp, every capability dropped). Without `-confine-read`,
  the reload was refused with `permission denied`, reported, and the old list kept. With the list
  directory in `-confine-read`, the new list was read.
- **`refresh.sh` against the real lists:**
  - Google common 317 ranges, special 272, Bing 28, Apple 24;
  - a list with a /8 and a failed download each kept the list in place and exited 1;
  - it passes shellcheck.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:** lists stay current without a restart. A bad list cannot replace a good one or stop
  the edge. An operator who never set up the refresh is told within a week.
- **Negative / follow-up:**
  - A list written in place, rather than moved into place, can be read half-written if it still
    parses. The guide says to move a new copy into place, as `refresh.sh` does.
  - Amazon publishes Amazonbot's addresses only on a web page, so `refresh.sh` does not fetch them.
  - A confined edge needs `-confine-read` for the lists' directory.

## References

- Related ADRs: ADR-0087, ADR-0088
- Code: `carnical/cmd/carnical/bots.go` (`crawlerLists`), `carnical/bots/verify.go`
  (`SetRanges`, `ParseRanges`), `carnical/deploy/ranges/refresh.sh`,
  `carnical/deploy/systemd/carnical-ranges.service`, `carnical/deploy/systemd/carnical-ranges.timer`
- Guide: `carnical/docs/bots.md#keeping-the-lists-current`
