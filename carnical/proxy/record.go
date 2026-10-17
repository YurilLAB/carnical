// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"math/rand/v2"
	"net/http"
	"net/netip"
)

// record is what the proxy holds about one request while it runs. It is made at the top of guard and kept in the
// request's context, so every layer that reports on the request reaches the same one.
type record struct {
	// id names the request on every line about it. The rule engine's transaction is given it too (see budgetWAF), so
	// the rule set's lines and the proxy's, the inspectors' and the rate rules' carry the same id.
	id string
	// client is the visitor's address once it is known (see clientAddr), without a port.
	client netip.Addr
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
	if rec != nil && m.TransactionID == "" {
		m.TransactionID = rec.id
	}
	if e.cfg.LogDetails {
		if rec != nil && rec.client.IsValid() {
			m.ClientIP = rec.client.String()
		}
		if r != nil && m.URI == "" {
			m.URI = r.RequestURI
		}
	}
	e.cfg.OnMatch(m)
}
