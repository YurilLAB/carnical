// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/YurilLAB/coraza/carnical/alert"
)

const (
	// maxRequestLines is how many lines one request is reported in. One request can match dozens of rules, and each
	// line could carry its matched data: past the cap the lines are counted, and one line says how many were held back.
	// The line of a check that refused the request, or in detection or monitor mode would have, is never held back (see
	// Match.verdict).
	maxRequestLines = 32
	// maxDetail is how much of the matched data and the expanded message a line keeps, with LogDetails; maxURI is how
	// much of the target. Both come from the visitor.
	maxDetail, maxURI = 512, 2048
)

// record is what the proxy holds about one request while it runs. It is made at the top of guard and kept in the
// request's context, so every layer that reports on the request reaches the same one.
type record struct {
	// id names the request on every line about it. The rule engine's transaction is given it too (see budgetWAF), so
	// the rule set's lines and the proxy's, the inspectors' and the rate rules' carry the same id.
	id string
	// client is the visitor's address once it is known (see clientAddr), without a port. conn is the connection's
	// address, set only when the visitor's cannot be read: it may be a trusted proxy's, which carries other visitors'
	// requests too, so it names the line and is never counted against as a visitor.
	client, conn netip.Addr
	// lines is how many lines the request has been reported in, and held how many of them went over maxRequestLines.
	lines, held atomic.Int32
	// alerts says the edge gives alerts (Config.OnAlert), without which nothing below is kept. via says the visitor's
	// address came through a trusted proxy.
	alerts, via bool
	// mu guards what follows, which the request's own goroutine fills and finish reads once the request is done: a line
	// about the request can still come from elsewhere, and is then no longer noted.
	mu   sync.Mutex
	done bool
	// found holds the request's findings, taken from a pool at the first one, so that a request with none costs nothing.
	found *findings
	// engine is how the rule engine's evaluation of the request ended (see budgetTx.Close).
	engine engineEnd
	// kind is the kind of client the bot policy read the request as (see checkBots); 0 when it did not run. The
	// request's own goroutine writes and reads it.
	kind alert.Client
	// override is the method WordPress's REST API is asked to run instead of POST, when checkRequest allowed it (see
	// wordPressOverride); the forwarded request carries it as the only override header. Written and read like kind.
	override string
}

// admit counts a line about the request and reports whether it may be logged: a verdict always may.
func (rec *record) admit(verdict bool) bool {
	if rec.lines.Add(1) <= maxRequestLines || verdict {
		return true
	}
	rec.held.Add(1)
	return false
}

type recordKey struct{}

// newRecord starts the record of a request, with a fresh id: 16 hexadecimal digits from math/rand/v2, whose generator
// is seeded by the runtime. The id is there to join lines, not to be a secret, and two requests that share one would
// only have their lines read together.
func newRecord() *record {
	const digits = "0123456789abcdef"
	var b [16]byte
	x := rand.Uint64() // #nosec G404 -- a correlation id, not a secret: nothing is decided by guessing it
	for i := len(b) - 1; i >= 0; i, x = i-1, x>>4 {
		b[i] = digits[x&0xf]
	}
	return &record{id: string(b[:])}
}

// recordOf returns the record of the request a context belongs to, or nil outside a request.
func recordOf(ctx context.Context) *record {
	if ctx == nil {
		return nil
	}
	rec, _ := ctx.Value(recordKey{}).(*record)
	return rec
}

// finding notes what a request matched or why it was refused for the request's verdict (see note), and reports it in a
// line, which Config.NoRuleMatches leaves out.
func (e *Edge) finding(m Match, rec *record, r *http.Request) {
	if rec == nil && r != nil {
		rec = recordOf(r.Context())
	}
	e.note(m, rec)
	if !e.cfg.NoRuleMatches {
		e.report(m, rec, r)
	}
}

// report hands one line about a request to OnMatch, with the request's id, and with the visitor's address and the
// target only if details are on. r may be nil for a line about a request that is no longer at hand; rec may be nil for
// one that is about no request.
func (e *Edge) report(m Match, rec *record, r *http.Request) {
	if e.cfg.OnMatch == nil {
		return
	}
	if rec == nil && r != nil {
		rec = recordOf(r.Context())
	}
	if rec != nil {
		if !rec.admit(m.Disruptive || m.verdict) {
			return
		}
		if m.TransactionID == "" {
			m.TransactionID = rec.id
		}
	}
	if e.cfg.LogDetails {
		if rec != nil && rec.client.IsValid() {
			m.ClientIP = rec.client.String()
		} else if rec != nil && rec.conn.IsValid() {
			m.ClientIP = rec.conn.String()
		}
		if r != nil && m.URI == "" {
			m.URI = r.RequestURI
		}
		m.URI, m.Data, m.ExpandedMessage = alert.Clean(m.URI, maxURI), alert.Clean(m.Data, maxDetail), alert.Clean(m.ExpandedMessage, maxDetail)
	}
	e.deliver(m)
}

// deliver hands a line to OnMatch, which must be set, with the rule's category and risk from the alert catalog where the
// line does not give its own. Every line goes through it, so that none is without a risk. A rule the catalog does not
// know, such as one written into crs.Settings.Before or After, has no category; it is rated as a rule set rule that
// scores, by its severity, or as medium when it refused the request or would have.
func (e *Edge) deliver(m Match) {
	risk, cats := rating(m)
	if m.Category == "" {
		m.Category = categoryText(cats)
	}
	if m.Risk == "" {
		m.Risk = risk.String()
	}
	e.cfg.OnMatch(m)
}

// rating is the risk and categories of a line: its own where it gives them, otherwise the catalog's (see deliver).
func rating(m Match) (alert.Risk, alert.Categories) {
	entry, known := alert.Lookup(m.RuleID)
	cats := entry.Categories
	if m.cats != 0 {
		cats = m.cats
	}
	if r, ok := alert.ParseRisk(m.Risk); ok {
		return r, cats
	}
	switch {
	case known:
		return entry.Risk, cats
	case m.Disruptive || m.verdict:
		return alert.RiskMedium, cats
	}
	return alert.CRSRisk(m.Severity), cats
}

// categoryText is a set of categories as a line gives them: their names joined with commas. One name, the usual case, is
// the catalog's own string.
func categoryText(c alert.Categories) string {
	switch c.Len() {
	case 0:
		return ""
	case 1:
		return c.Names(1)[0]
	}
	return strings.Join(c.Names(alert.MaxCategories), ",")
}

// reportHeld says, once a request is done, how many of its lines went over maxRequestLines.
func (e *Edge) reportHeld(rec *record) {
	if n := rec.held.Load(); n > 0 && e.cfg.OnMatch != nil {
		e.deliver(Match{RuleID: idLinesHeld, Severity: "WARNING", TransactionID: rec.id,
			Message: strconv.FormatInt(int64(n), 10) + " more rule matches not logged"})
	}
}
