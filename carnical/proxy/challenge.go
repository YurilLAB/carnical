// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/YurilLAB/coraza/carnical/bots"
	"github.com/YurilLAB/coraza/carnical/challenge"
	"github.com/YurilLAB/coraza/carnical/shield"
)

// idGateRefused is a visitor the person check refused (Config.Challenge), in the range kept for it (5007000 to 5007999).
const idGateRefused = 5007001

// maxGateReason is how much of a person check's reason an alert keeps.
const maxGateReason = 64

// inboundKey keeps, in the context of a request forwarded to the application, the request as the visitor sent it, for
// a person check that sees the responses (challenge.Responder).
type inboundKey struct{}

// serveGate offers r to the person check at point p (see package challenge), with what the edge knows about its
// visitor, and reports whether the check answered it. d is the shield's decision at admission (zero at the request
// point). The check sees the body held to the site's limit, and what it writes is never cached; at admission, an
// answer in place of a refusal closes the connection as the shield's would have. A check that writes anything has
// answered, whatever it returns.
func (e *Edge) serveGate(w http.ResponseWriter, r *http.Request, rec *record, p challenge.Point, d shield.Decision) bool {
	if rec.kind == 0 { // no bot policy ran: what the request says it is, as its alerts name it
		rec.kind, _ = bots.Classify(r, e.helloOf(r))
	}
	sig := challenge.Signals{Point: p, Client: rec.client, Kind: rec.kind, Watched: rec.watched, Relayed: rec.via}
	sh := e.cfg.Shield
	if sh != nil {
		st := sh.Standing(rec.client)
		sig.Attack, sig.Known, sig.Strikes = st.Attack, st.Known, st.Strikes
	}
	gw := &gateWriter{ResponseWriter: w}
	gw.closeConn = p == challenge.Admission && d.Action == shield.Refuse && (!rec.via || r.ProtoMajor == 1 && r.ContentLength != 0)
	gr := r
	if r.Body != nil && r.Body != http.NoBody {
		gr = r.WithContext(r.Context())
		gr.Body = http.MaxBytesReader(gw, r.Body, e.bodyLimit(r))
	}
	// A report made on another goroutine while Serve returns ends before the request goes on, as it may set headers on w.
	var mu sync.Mutex
	done, reported := false, false
	report := func(o challenge.Outcome) {
		mu.Lock()
		defer mu.Unlock()
		if done || reported {
			return
		}
		reported = true
		switch o.Verdict {
		case challenge.Passed:
			if sh != nil {
				sh.Vouch(gw, r, rec.client, d)
			}
		case challenge.Refused:
			msg := "the person check refused the visitor, score " + strconv.Itoa(min(max(o.Score, 0), 100))
			if reason := gateReason(o.Reason); reason != "" {
				msg += ": " + reason
			}
			m := Match{RuleID: idGateRefused, Severity: "WARNING", Message: msg, Disruptive: true, status: http.StatusForbidden}
			if p == challenge.Admission {
				// What reaches the check at admission is held only to the address's and the network's rates, so a flood
				// of refusals has its alert but no line each. The shield has counted what it would have done.
				e.note(m, rec)
			} else {
				e.finding(m, rec, r)
			}
		}
	}
	handled := e.cfg.Challenge.Serve(gw, gr, sig, report)
	mu.Lock()
	done = true // a report after Serve returned is not the request's
	mu.Unlock()
	return handled || gw.wrote
}

// gateWriter is what the person check writes through.
type gateWriter struct {
	http.ResponseWriter
	closeConn bool
	wrote     bool
}

func (g *gateWriter) prepare() {
	if g.wrote {
		return
	}
	g.wrote = true
	h := g.Header()
	h.Set("Cache-Control", "no-store") // an answer about one visitor
	h.Set("X-Content-Type-Options", "nosniff")
	if g.closeConn {
		h.Set("Connection", "close")
	}
}

func (g *gateWriter) WriteHeader(code int) { g.prepare(); g.ResponseWriter.WriteHeader(code) }

func (g *gateWriter) Write(b []byte) (int, error) {
	g.prepare()
	return g.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the connection's writer.
func (g *gateWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// gateReason is what of a person check's reason goes into an alert: letters, digits, spaces and "-+:,.", at most
// maxGateReason bytes. The reason is the check's own text, but it is kept to a plain form all the same.
func gateReason(s string) string {
	b := make([]byte, 0, min(len(s), maxGateReason))
	for i := 0; i < len(s) && len(b) < maxGateReason; i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ' || c == '-' || c == '+' || c == ':' || c == ',' || c == '.' {
			b = append(b, c)
		}
	}
	return string(b)
}
