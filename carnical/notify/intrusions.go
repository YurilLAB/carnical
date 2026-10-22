// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/YurilLAB/coraza/carnical/alert"
)

// Intrusions is the event of a message that carries intrusion alerts: the lines the log writes as "intrusion
// blocked", "intrusion detected", "alert repeated", "suspected intrusion", "alerts dropped" and the repeat-offender
// lines, each as its log line has it (alert.Line), many to a message.
const Intrusions Event = "intrusions"

// The batching of intrusion alerts. An attack can produce many alerts a second, of which the endpoint is sent one message
// a second, or two when more wait than one holds (the Sender posts no more often): what waits past intrusionPending is
// counted and said in the next message.
const (
	intrusionEvery   = time.Second
	intrusionBurst   = 2              // messages a second, at most
	intrusionPending = 256            // alerts waiting, at most
	intrusionLines   = 50             // alerts in one message, at most
	intrusionRoom    = MaxBody - 2048 // bytes the alerts of one message may take; the rest is the message's own
)

// AlertSink is an alert.Sink that sends intrusion alerts to the endpoint through a Sender. Send never blocks: the alerts
// wait, at most intrusionPending of them, and are sent many to a message. When too many wait, a medium or high risk
// alert takes the place of the oldest lower one; any other is dropped, and the drops are in the next message. The
// totals and the summary are not sent: they are reports, and stay in the log.
type AlertSink struct {
	s      *Sender
	site   string
	source alert.SourceMode
	every  time.Duration

	mu       sync.Mutex
	pending  []alert.Line
	dropped  uint64 // alerts not sent since the last message
	lost     uint64 // alerts not sent, in all
	messages uint64 // messages handed to the Sender
	closed   bool
	stop     chan struct{}
	done     chan struct{}
}

// NewAlertSink starts sending the alerts it is given through s, naming site and showing the source as mode says (as the
// log does, -alert-source). Close it before s.
func NewAlertSink(s *Sender, site string, mode alert.SourceMode) *AlertSink {
	return newAlertSink(s, site, mode, intrusionEvery)
}

func newAlertSink(s *Sender, site string, mode alert.SourceMode, every time.Duration) *AlertSink {
	a := &AlertSink{s: s, site: site, source: mode, every: every, stop: make(chan struct{}), done: make(chan struct{})}
	go a.run()
	return a
}

// Send queues r's line, or counts it as dropped. It never blocks.
func (a *AlertSink) Send(r alert.Record) {
	l, ok := alert.NewLine(r, a.source)
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		a.drop(1)
		return
	}
	if len(a.pending) >= intrusionPending {
		victim := -1
		if l.RiskOf() >= alert.RiskMedium {
			for i := range a.pending {
				if a.pending[i].RiskOf() < alert.RiskMedium {
					victim = i
					break
				}
			}
		}
		a.drop(1)
		if victim < 0 {
			return
		}
		a.pending = append(a.pending[:victim], a.pending[victim+1:]...)
	}
	a.pending = append(a.pending, l)
}

// drop counts n alerts as not sent. a.mu is held.
func (a *AlertSink) drop(n uint64) {
	a.dropped += n
	a.lost += n
}

// Stats are the messages handed to the Sender and the alerts that were not sent.
func (a *AlertSink) Stats() (messages, lost uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.messages, a.lost
}

// Close sends what waits, in as many messages as it takes, and stops. The Sender's own Close then delivers them.
func (a *AlertSink) Close() {
	a.mu.Lock()
	already := a.closed
	a.closed = true
	a.mu.Unlock()
	if !already {
		close(a.stop)
	}
	<-a.done
}

func (a *AlertSink) run() {
	defer close(a.done)
	t := time.NewTicker(a.every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			for i := 0; i < intrusionBurst && a.flush(); i++ {
			}
		case <-a.stop:
			for a.flush() {
			}
			return
		}
	}
}

// flush sends one message of what waits, and reports whether more waits.
func (a *AlertSink) flush() bool {
	a.mu.Lock()
	n, room := 0, intrusionRoom
	for n < len(a.pending) && n < intrusionLines {
		data, err := json.Marshal(a.pending[n])
		if err != nil || len(data)+1 > room {
			if n == 0 { // a line that does not fit a message of its own is never sent
				a.pending = a.pending[1:]
				a.drop(1)
				continue
			}
			break
		}
		room -= len(data) + 1
		n++
	}
	lines := append([]alert.Line(nil), a.pending[:n]...)
	a.pending = append(a.pending[:0], a.pending[n:]...)
	dropped := a.dropped
	a.dropped = 0
	more := len(a.pending) > 0
	if len(lines) == 0 && dropped == 0 {
		a.mu.Unlock()
		return false
	}
	a.messages++
	a.mu.Unlock()
	m := Message{Event: Intrusions, At: time.Now().UTC(), Site: a.site, Severity: intrusionSeverity(lines, dropped),
		Text: intrusionText(lines, dropped, a.site), Intrusions: lines, IntrusionsDropped: dropped}
	if !a.s.Send(m) {
		a.mu.Lock()
		a.drop(uint64(len(lines))) // the Sender counts the message; these are the alerts it held
		a.mu.Unlock()
	}
	return more
}

// intrusionSeverity is critical when a line is high risk, a suspected intrusion or a blocked source, warning when one is
// medium risk or alerts were dropped (from the log or from the messages), and info otherwise.
func intrusionSeverity(lines []alert.Line, dropped uint64) string {
	sev := "info"
	if dropped > 0 {
		sev = "warning"
	}
	for i := range lines {
		l := &lines[i]
		switch {
		case l.RiskOf() == alert.RiskHigh, l.Msg == "suspected intrusion", l.Msg == "source blocked":
			return "critical"
		case l.RiskOf() == alert.RiskMedium, l.Msg == "alerts dropped":
			sev = "warning"
		}
	}
	return sev
}

// intrusionWords says what each kind of alert is in a message's text, in the order they are told.
var intrusionWords = []struct{ msg, words string }{
	{"intrusion blocked", "blocked"},
	{"intrusion detected", "detected"},
	{"inspection incomplete", "not inspected"},
	{"alert repeated", "repeated"},
	{"suspected intrusion", "suspected intrusion"},
	{"source blocked", "source blocked"},
	{"source would be blocked", "source would be blocked"},
	{"source block ended", "source block ended"},
	{"auto-block table full", "auto-block table full"},
}

// intrusionText is the message's line for a person: "3 intrusion alerts on example.com: 2 blocked, 1 detected", then
// the alerts the log dropped and those not sent to the endpoint, if any.
func intrusionText(lines []alert.Line, dropped uint64, site string) string {
	counts := map[string]uint64{}
	var shown, unwritten uint64
	for i := range lines {
		if lines[i].Msg == "alerts dropped" {
			unwritten += lines[i].Count
			continue
		}
		counts[lines[i].Msg]++
		shown++
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d intrusion alert", shown)
	if shown != 1 {
		b.WriteString("s")
	}
	if site != "" {
		b.WriteString(" on " + site)
	}
	sep := ": "
	for _, w := range intrusionWords {
		if n := counts[w.msg]; n > 0 {
			fmt.Fprintf(&b, "%s%d %s", sep, n, w.words)
			sep = ", "
		}
	}
	if unwritten > 0 {
		fmt.Fprintf(&b, "; %d not written to the log (too many)", unwritten)
	}
	if dropped > 0 {
		fmt.Fprintf(&b, "; %d not sent here (too many waited)", dropped)
	}
	return b.String()
}
