# ADR-0098: Carnical sends its intrusion alerts to the alert endpoint

- **Status:** proposed
- **Date:** 2026-10-22 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

The alert endpoint (`-alert-endpoint`) was told only of the attacks flood protection finds and of the network floods
`carnical-netwatch` reports: an attack's start, at most one update a minute, and its end. The intrusion alerts of
ADR-0084 (`intrusion blocked`, `intrusion detected`, `alert repeated`, `suspected intrusion` and the repeat-offender
lines) went to the log only, so an operator who relies on the endpoint learned of none of them, including the
`intrusion detected` alerts that ADR-0097 added for the attacks the default setup forwards. The owner asked for every
intrusion alert written to the log to reach the alert endpoint as well.

## Decision Drivers

- The endpoint is told what the log is told, in the same fields under the same names, so a receiver reads one schema.
- A request never waits on the endpoint, and a slow or dead endpoint costs bounded memory.
- Requests cannot make the edge post more than a fixed number of messages a second.
- An attack's start and end are never displaced by alert messages, which are in the log either way.
- A message stays within the endpoint's 16 KiB.

## Considered Options

- **One message per alert line.** Simple, but the log may be written up to `-alert-rate` lines a second (20 by default,
  up to 10,000) against the sender's one post every half second, so most would be dropped in a queue of 32.
- **A count of the alerts at an interval.** Small, but it loses who and what, which is what the lines are for.
- **A second endpoint for the alerts.** Another URL, secret and allowance to set up, where the owner asked for the one
  endpoint.
- **The log's lines, many to a message, at most two messages a second (chosen).**

## Decision Outcome

Chosen: **the log's lines, many to a message, at most two messages a second**, because the endpoint then holds every
alert the log does while it keeps up, and is told how many it missed when it does not.

- `alert.NewLine` gives a record as `LogSink` writes it, without the time and the level. `TestSinks` compares the two,
  field for field, for every kind of record; the totals and the summary are reports and have no line.
- `notify.AlertSink` is an `alert.Sink` that never blocks. At most 256 alerts wait; when that many do, a medium or high
  risk alert, an `alerts dropped` line or a ban takes the place of the oldest line that is none of these, and any other
  is counted as not sent. Once a second it sends a
  message of event `intrusions` (a second one in the same second when more wait than one holds), each of at most 50
  alerts and 14 KiB of them, with a severity, a line of text and `intrusions_dropped`, the alerts before it that were
  not sent.
- In the sender's full queue a message of intrusion alerts gives its place to any other, as an attack's update does.
  The sender counts the alerts of a message it drops, or cannot deliver, and the next message of intrusion alerts
  reports them in `intrusions_dropped`.
- In `carnical`, the alert queue's goroutine writes each line and then hands the record to the endpoint's sink, so the
  endpoint gets exactly the lines the log is written, after `-alert-min-risk`, `-alert-suppress`,
  `-alert-exclude-sources`, the deduplication and `-alert-rate`. Each line shows the source as `-alert-source` says.
  The repeat-offender lines are not records: the shield's event handler builds each as `alert.Line`'s `BanLine`,
  writes the log line from it and hands it to the sink.
  The endpoint closes the alerts before its own queue, so that the repeats written at shutdown are sent too. With
  `-alerts off` nothing is handed over.

## Technical Discussion

No substantive technical discussion recorded: the change was made for the owner, without a pull request.

## Consequences

- **Positive:** an operator is told of every intrusion alert without reading the log, in the schema the log already
  documents, and a would-be refusal or a detection the default setup forwards reaches whoever watches the endpoint.
- **Positive:** the cost is bounded: 256 alerts waiting, two posts a second, and nothing on the request's path but a
  lock and an append.
- **Negative:** the endpoint now receives visitors' addresses, in full by default, as the log does; an operator who
  does not want that sets `-alert-source prefix` or `off`, which changes the log too.
- **Negative:** under a heavy attack with a high `-alert-rate`, the endpoint is sent fewer alerts than the log is
  written; `intrusions_dropped` and `intrusions_not_sent` in `alert endpoint closed` say how many.
- **Negative:** a receiver gets a new event, `intrusions`; one written for the attack events only must ignore an event
  it does not know.

## References

- Related ADRs: ADR-0084 (intrusion alerts), ADR-0097 (stricter rules detect by default)
- Code: `carnical/alert/line.go`, `carnical/notify/intrusions.go`, `carnical/notify/message.go`,
  `carnical/notify/notify.go`, `carnical/cmd/carnical/alerts.go`, `carnical/cmd/carnical/endpoint.go`
- Documentation: `carnical/docs/alert-endpoint.md#intrusion-alerts`
