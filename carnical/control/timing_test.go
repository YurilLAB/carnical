// SPDX-License-Identifier: Apache-2.0

package control

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

// median returns the middle of the durations.
func median(d []time.Duration) time.Duration {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func percentile(d []time.Duration, p int) time.Duration {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)*p/100]
}

// TestFailurePathsTakeTheSameTime measures how long the server takes to refuse a request for each of the reasons an
// authentication can fail, 2,000 times each, and compares the medians. They have to be close: a server that answered an
// unknown credential faster than a bad signature would let a caller find out which credentials exist.
//
// What is timed is ServeHTTP on a prepared request with a prepared recorder, so building the requests (which signs them)
// is not part of it. The audit log is in memory; with the real file each refusal adds a flush to disk, the same for every
// reason. The tolerance is generous (a ratio between 0.6 and 1.6) because the machine is shared and a few microseconds
// either way are noise; the work that matters is one Ed25519 verification, about 50 microseconds, in every case.
func TestFailurePathsTakeTheSameTime(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	const attempts = 2000
	h := newHarness(t, func(c *Config) { c.Limits.FailureThreshold = 1 << 30 })
	h.addIdentity("revoked-id", []string{tenantA}, false, ScopeRead)
	h.setCred("revoked-id", func(c *Credential) { c.Revoked = true })
	h.addIdentity("expired-id", []string{tenantA}, false, ScopeRead)
	h.setCred("expired-id", func(c *Credential) { c.NotAfter = epoch.Add(-time.Hour) })
	h.addIdentity("pinned-id", []string{tenantA}, false, ScopeRead)
	h.setCred("pinned-id", func(c *Credential) { c.Sources = []netipPrefix{mustPrefix("203.0.113.0/24")} })
	status := "/v1/tenants/" + tenantA + "/status"
	flipSig := func(r *http.Request) {
		a := r.Header.Get("Authorization")
		i := len(a) - 3
		c := byte('B')
		if a[i] == 'B' {
			c = 'C'
		}
		r.Header.Set("Authorization", a[:i]+string(c)+a[i+1:])
	}

	classes := []struct {
		name string
		mk   func(i int) *http.Request
		want int
	}{
		{"unknown credential", func(i int) *http.Request { return h.build(reqOpts{as: "nobody-here", target: status}) }, 401},
		{"bad signature (another key)", func(i int) *http.Request { return h.build(reqOpts{keyAs: "ui-b", target: status}) }, 401},
		{"bad signature (one character changed)", func(i int) *http.Request { return h.build(reqOpts{target: status, after: flipSig}) }, 401},
		{"wrong certificate", func(i int) *http.Request { return h.build(reqOpts{certAs: "ui-b", target: status}) }, 401},
		{"no certificate", func(i int) *http.Request { return h.build(reqOpts{noTLS: true, target: status}) }, 401},
		{"revoked credential", func(i int) *http.Request { return h.build(reqOpts{as: "revoked-id", target: status}) }, 401},
		{"expired credential", func(i int) *http.Request { return h.build(reqOpts{as: "expired-id", target: status}) }, 401},
		{"source not allowed", func(i int) *http.Request { return h.build(reqOpts{as: "pinned-id", target: status}) }, 401},
		{"time too far off", func(i int) *http.Request { return h.build(reqOpts{target: status, ts: epoch.Unix() - 1000}) }, 401},
		{"malformed Authorization header", func(i int) *http.Request {
			return h.build(reqOpts{target: status, after: func(r *http.Request) { r.Header.Set("Authorization", "Carnical-Sig nonsense") }})
		}, 401},
		{"no Authorization header", func(i int) *http.Request {
			return h.build(reqOpts{target: status, after: func(r *http.Request) { r.Header.Del("Authorization") }})
		}, 401},
		{"missing acting user", func(i int) *http.Request {
			return h.build(reqOpts{target: status, after: func(r *http.Request) { r.Header.Del(HeaderActingUser) }})
		}, 401},
		{"replayed request", func(i int) *http.Request {
			r := h.build(reqOpts{target: status})
			if w := h.serve(r); w.Code != 200 {
				t.Fatalf("priming the replay: %d", w.Code)
			}
			return h.build(reqOpts{target: status, nonce: nonceOf(r), ts: tsOf(r)})
		}, 401},
	}

	type result struct {
		name string
		d    []time.Duration
	}
	// Every request is prepared first. They are then sent round-robin, one of each kind in turn, so that whatever the
	// machine is doing (other processes, the garbage collector) is spread evenly over all the kinds.
	all := make([][]*http.Request, len(classes))
	recs := make([][]*httptest.ResponseRecorder, len(classes))
	for ci, c := range classes {
		all[ci] = make([]*http.Request, attempts+200)
		recs[ci] = make([]*httptest.ResponseRecorder, attempts+200)
		for i := range all[ci] {
			all[ci][i] = c.mk(i)
			recs[ci][i] = httptest.NewRecorder()
		}
	}
	results := make([]result, len(classes))
	for ci, c := range classes {
		results[ci] = result{c.name, make([]time.Duration, 0, attempts)}
	}
	for i := 0; i < attempts+200; i++ {
		for ci, c := range classes {
			start := time.Now()
			h.srv.ServeHTTP(recs[ci][i], all[ci][i])
			el := time.Since(start)
			if recs[ci][i].Code != c.want {
				t.Fatalf("%s: attempt %d got %d, want %d: %s", c.name, i, recs[ci][i].Code, c.want, recs[ci][i].Body.String())
			}
			if i >= 200 { // the first 200 warm the caches and the scheduler
				results[ci].d = append(results[ci].d, el)
			}
		}
	}

	ref := median(results[1].d) // a bad signature from a real credential: the reference path
	t.Logf("%-40s %10s %10s %10s %8s", "failure", "median", "p10", "p90", "vs ref")
	var lo, hi = ref, ref
	for _, r := range results {
		m := median(r.d)
		t.Logf("%-40s %10v %10v %10v %7.2fx", r.name, m, percentile(r.d, 10), percentile(r.d, 90), float64(m)/float64(ref))
		if m < lo {
			lo = m
		}
		if m > hi {
			hi = m
		}
		if ratio := float64(m) / float64(ref); ratio < 0.6 || ratio > 1.6 {
			t.Errorf("%s: median %v against the reference %v (%.2fx): the failure paths differ in time", r.name, m, ref, ratio)
		}
	}
	t.Logf("fastest median %v, slowest %v, spread %v over %d attempts each", lo, hi, hi-lo, attempts)

	// The negative control: a request refused before authentication (no signature is checked) is clearly faster, and this
	// comparison does see it. If this passed with the check above too, the check would be measuring nothing.
	t.Run("the comparison can tell a path that skips the signature check", func(t *testing.T) {
		reqs := make([]*http.Request, attempts+200)
		recs := make([]*httptest.ResponseRecorder, attempts+200)
		for i := range reqs {
			reqs[i] = h.build(reqOpts{target: status, extra: http.Header{"X-Forwarded-For": {"203.0.113.9"}}}) // refused for a header, before any signature work
			recs[i] = httptest.NewRecorder()
		}
		var d []time.Duration
		for i := range reqs {
			start := time.Now()
			h.srv.ServeHTTP(recs[i], reqs[i])
			if i >= 200 {
				d = append(d, time.Since(start))
			}
		}
		m := median(d)
		t.Logf("a request refused before authentication: median %v (%.2fx the reference)", m, float64(m)/float64(ref))
		if ratio := float64(m) / float64(ref); ratio >= 0.6 {
			t.Fatalf("a path that skips the signature check took %.2fx the reference: the timing comparison cannot see a difference", ratio)
		}
	})
}
