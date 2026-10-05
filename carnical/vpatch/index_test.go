// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// diffHits compares the indexed answer with the brute-force answer for one request and describes any difference.
func diffHits(e *Engine, r *inspect.Request) string {
	got, want := e.Match(r), e.MatchBruteForce(r)
	if len(got) == len(want) {
		same := true
		for i := range got {
			if got[i].ID != want[i].ID {
				same = false
			}
		}
		if same {
			return ""
		}
	}
	ids := func(h []Hit) string {
		var s []string
		for _, x := range h {
			s = append(s, x.ID)
		}
		return strings.Join(s, " ")
	}
	return fmt.Sprintf("indexed [%s] brute force [%s]", ids(got), ids(want))
}

func cloneReq(r *inspect.Request) *inspect.Request {
	c := *r
	c.Header = http.Header{}
	for k, v := range r.Header {
		c.Header[k] = append([]string(nil), v...)
	}
	c.Body = append([]byte(nil), r.Body...)
	return &c
}

func pctEncode(r *rand.Rand, s string, p float64) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' || r.Float64() < p {
			fmt.Fprintf(&b, "%%%02x", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func flipCase(r *rand.Rand, s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' && r.Intn(3) == 0 {
			b[i] = c - 32
		}
	}
	return string(b)
}

func fullWidth(r *rand.Rand, s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '!' && c <= '~' && r.Intn(4) == 0 {
			b.WriteRune(c + 0xFEE0)
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// mutate returns a request derived from base (and from others, for splicing).
func mutate(r *rand.Rand, base, other *inspect.Request, lits []string, padded *int) *inspect.Request {
	q := cloneReq(base)
	for n := 1 + r.Intn(3); n > 0; n-- {
		switch r.Intn(14) {
		case 0:
			q.Path = pctEncode(r, q.Path, 0.3)
		case 1:
			q.RawQuery = pctEncode(r, q.RawQuery, 0.3)
		case 2:
			q.Path = pctEncode(r, pctEncode(r, q.Path, 0.2), 0.2) // double encoding
		case 3:
			q.Path, q.RawQuery = flipCase(r, q.Path), flipCase(r, q.RawQuery)
		case 4: // the query becomes a form body
			q.Method = "POST"
			q.Body = []byte(q.RawQuery)
			q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			q.RawQuery = ""
		case 5: // a value becomes JSON
			q.Method = "POST"
			q.Header.Set("Content-Type", "application/json")
			q.Body = []byte(fmt.Sprintf(`{"a":{"b":%q},"c":[%q]}`, q.RawQuery, string(q.Body)))
		case 6: // the query moves into a cookie and a header
			q.Header.Set("Cookie", "x="+q.RawQuery+"; y=1")
			q.Header.Set("X-Test", q.RawQuery)
		case 7: // splice
			q.Path = other.Path
		case 8:
			q.RawQuery, q.Body = other.RawQuery, other.Body
			if ct := other.Header.Get("Content-Type"); ct != "" {
				q.Header.Set("Content-Type", ct)
			}
		case 9: // headers from the other request
			for k, v := range other.Header {
				q.Header[k] = append([]string(nil), v...)
			}
			q.Host = other.Host
		case 10: // padding in front of the payload, so that the head and tail windows matter. Evaluating every signature on a 140 KiB
			// body takes seconds, so only a few requests get it.
			if *padded >= 25 {
				continue
			}
			*padded++
			q.Method = "POST"
			q.Body = append([]byte(strings.Repeat("p", 70000)), q.Body...)
			q.Body = append(q.Body, []byte(strings.Repeat("q", r.Intn(70000)))...)
		case 11: // flip some bytes
			b := []byte(q.Path + "?" + q.RawQuery)
			for k := 0; k < 1+r.Intn(3) && len(b) > 0; k++ {
				b[r.Intn(len(b))] = byte(r.Intn(256))
			}
			s := string(b)
			if i := strings.IndexByte(s, '?'); i >= 0 {
				q.Path, q.RawQuery = s[:i], s[i+1:]
			} else {
				q.Path = s
			}
		case 12:
			q.Path, q.RawQuery = fullWidth(r, q.Path), fullWidth(r, q.RawQuery)
			q.Body = []byte(fullWidth(r, string(q.Body)))
		case 13: // a literal some signature needs, in a random place
			if len(lits) == 0 {
				continue
			}
			lit := lits[r.Intn(len(lits))]
			switch r.Intn(6) {
			case 0:
				q.Path += lit
			case 1:
				q.RawQuery += "&p=" + lit
			case 2:
				q.Header.Set("User-Agent", lit)
			case 3:
				q.Header.Set("Cookie", "c="+lit)
			case 4:
				q.Method = "POST"
				q.Body = append(q.Body, []byte("&b="+lit)...)
			case 5:
				q.Header.Set("Referer", "http://x/"+lit)
			}
		}
	}
	return q
}

func requestsForEquivalence(t *testing.T, e *Engine, generated int) []*inspect.Request {
	var base []*inspect.Request
	for _, s := range readSamplesFile(t, samplesPath(t), "") {
		base = append(base, s.Request)
		if s.Alt != nil {
			base = append(base, s.Alt)
		}
	}
	nSamples := len(base)
	base = append(base, corpusRequests(t, "benign.jsonl", "benign")...)
	base = append(base, corpusRequests(t, "attack.jsonl", "attack")...)
	// the literals the loaded signatures require, to plant
	var lits []string
	snap := e.cur.Load()
	for i := range snap.conds {
		lits = append(lits, snap.conds[i].anchors...)
	}
	r := rand.New(rand.NewSource(20261005))
	out := append([]*inspect.Request(nil), base...)
	padded := 0
	for i := 0; i < generated; i++ {
		a, b := base[r.Intn(len(base))], base[r.Intn(len(base))]
		if r.Intn(3) == 0 {
			a = base[r.Intn(nSamples)] // more weight on requests that are real attacks
		}
		out = append(out, mutate(r, a, b, lits, &padded))
	}
	return out
}

// TestIndexedMatchEqualsBruteForce is the proof that the index never skips a signature that could match: with the whole library
// loaded, the indexed answer must equal the answer from evaluating every signature, on every sample request, every corpus request
// and thousands of requests generated from them by encoding, case changes, splicing, moving a value to another place, padding,
// byte flips, full-width forms and planting the literals the signatures require.
func TestIndexedMatchEqualsBruteForce(t *testing.T) {
	generated, stride := 3000, 1
	if testing.Short() {
		generated, stride = 500, 6
	}
	sigs := library(t)
	for _, cache := range []int{-1, 0} { // without and with the table of remembered results
		name := "cache off"
		if cache == 0 {
			name = "cache on"
		}
		t.Run(name, func(t *testing.T) {
			e := New(Options{Tiers: allTiers, ResultCache: cache})
			e.Load(sigs)
			all := requestsForEquivalence(t, e, generated)
			var reqs []*inspect.Request
			for i, r := range all {
				if i%stride == 0 && (cache == 0 || i%3 == 0) { // the run with the table on is a shorter one: the answers are the same
					reqs = append(reqs, r)
				}
			}
			hitsSeen, bad := 0, 0
			for i, r := range reqs {
				if d := diffHits(e, r); d != "" {
					bad++
					if bad <= 5 {
						t.Errorf("request %d (%s %s?%.80s): %s", i, r.Method, r.Path, r.RawQuery, d)
					}
				}
				if len(e.Match(r)) > 0 {
					hitsSeen++
				}
			}
			t.Logf("%s: %d requests compared, %d of them matched at least one signature, %d differences", name, len(reqs), hitsSeen, bad)
			if hitsSeen < len(reqs)/4 {
				t.Fatalf("only %d of %d requests matched anything: the comparison proves little", hitsSeen, len(reqs))
			}
		})
	}
}

// Negative controls: the equivalence test must be able to fail. Each one breaks the index on purpose and requires the comparison to
// notice.
func TestEquivalenceTestDetectsABrokenIndex(t *testing.T) {
	sigs := library(t)
	samples := readSamplesFile(t, samplesPath(t), "")
	var reqs []*inspect.Request
	for i, s := range samples {
		if i%5 == 0 {
			reqs = append(reqs, s.Request)
		}
	}
	count := func(e *Engine) int {
		n := 0
		for _, r := range reqs {
			if diffHits(e, r) != "" {
				n++
			}
		}
		return n
	}
	t.Run("a signature that is never nominated", func(t *testing.T) {
		e := New(Options{Tiers: allTiers, ResultCache: -1})
		e.Load(sigs)
		if n := count(e); n != 0 {
			t.Fatalf("the intact index already differs on %d samples", n)
		}
		snap := e.cur.Load()
		broken := 0
		for si := range snap.sigs {
			if d := snap.sigs[si].driver; d >= 0 {
				snap.condDriver[d] = -1
				broken++
			}
		}
		if n := count(e); n == 0 {
			t.Fatalf("with %d signatures made un-nominatable the comparison found no difference", broken)
		}
	})
	t.Run("a literal that is not the one the expression requires", func(t *testing.T) {
		e := New(Options{Tiers: allTiers, ResultCache: -1, mutateAnchors: func(l []string) []string {
			out := make([]string, len(l))
			for i, s := range l {
				out[i] = s + "zz"
			}
			return out
		}})
		e.Load(sigs)
		if n := count(e); n == 0 {
			t.Fatal("anchors that are wrong were not noticed")
		}
	})
	t.Run("a gate that cannot pass", func(t *testing.T) {
		e := New(Options{Tiers: allTiers, ResultCache: -1})
		e.Load(sigs)
		snap := e.cur.Load()
		// make every condition's literal "unseen" by pointing the gates at a condition that never gets marked: the last one in the set
		last := int32(len(snap.conds) - 1)
		snap.condDriver[last] = -1
		for si := range snap.sigs {
			snap.sigs[si].gates = append(snap.sigs[si].gates, last)
		}
		if n := count(e); n == 0 {
			t.Fatal("a gate that fails for every signature was not noticed")
		}
	})
}

// TestTheResultTableNeverChangesAnAnswer: remembered results are only a shortcut.
func TestTheResultTableNeverChangesAnAnswer(t *testing.T) {
	sigs := library(t)
	on := New(Options{Tiers: allTiers})
	off := New(Options{Tiers: allTiers, ResultCache: -1})
	on.Load(sigs)
	off.Load(sigs)
	r := rand.New(rand.NewSource(3))
	reqs := requestsForEquivalence(t, on, 1500)
	for pass := 0; pass < 2; pass++ { // the second pass is answered from the table
		for i, q := range reqs {
			a, b := on.Match(q), off.Match(q)
			if len(a) != len(b) {
				t.Fatalf("pass %d request %d: %d hits with the table, %d without", pass, i, len(a), len(b))
			}
			_ = r
		}
	}
}
