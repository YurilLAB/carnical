// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"strconv"
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
	e.cfg.OnMatch(m)
}

// reportHeld says, once a request is done, how many of its lines went over maxRequestLines.
func (e *Edge) reportHeld(rec *record) {
	if n := rec.held.Load(); n > 0 && e.cfg.OnMatch != nil {
		e.cfg.OnMatch(Match{RuleID: idLinesHeld, Severity: "WARNING", TransactionID: rec.id,
			Message: strconv.FormatInt(int64(n), 10) + " more rule matches not logged"})
	}
}
