// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// fakeSite is the Go equivalent of FakeSite in newsletter/tests/test_waf_fleet.py: a stand-in site console that checks
// each request the way a real one does, with its own independent code (its own pattern for the header, its own HMAC),
// and answers 401 to anything it cannot verify. The Python double is used to test the reader (the client); here it is
// the oracle the handler (the server) is compared with. If the two ever disagree about a request, one of them has
// read the contract differently.
type fakeSite struct {
	secret []byte
	keyID  string
	nonces map[string]bool
}

var fakeAuth = regexp.MustCompile(`^SFW1 key=([0-9a-f]{16}), ts=(\d+), nonce=([0-9a-f]{32}), sig=([0-9a-f]{64})$`)

func newFakeSite() *fakeSite {
	return &fakeSite{secret: vectorSecret(), keyID: testKeyID, nonces: map[string]bool{}}
}

// accepts reports whether the fake site would answer 200 to a request for target with this Authorization header.
func (f *fakeSite) accepts(target, header string) bool {
	m := fakeAuth.FindStringSubmatch(header)
	if m == nil {
		return false
	}
	mac := hmac.New(sha256.New, f.secret)
	mac.Write([]byte("SFW1\nGET\n" + target + "\n" + m[2] + "\n" + m[3]))
	if m[1] != f.keyID || f.nonces[m[3]] || !hmac.Equal([]byte(m[4]), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return false
	}
	f.nonces[m[3]] = true
	return true
}

// TestHandlerAndFakeSiteAgree runs a few hundred requests, valid and damaged in every part the signature covers, past
// both and requires the same verdict from each. The requests are made with a fixed seed so a disagreement can be
// reproduced.
func TestHandlerAndFakeSiteAgree(t *testing.T) {
	rng := rand.New(rand.NewSource(20261005))
	targets := []string{"/feed", "/feed?days=7", vectorTarget, "/feed?since=a%20b%2Fc&days=30", "/feed?scopes=events,traffic&days=1"}
	mutations := []struct {
		name string
		do   func(target, header string) (string, string)
	}{
		{"none", func(a, h string) (string, string) { return a, h }},
		{"sig digit", func(a, h string) (string, string) { return a, flip(h, strings.Index(h, "sig=")+4+rng.Intn(64)) }},
		{"nonce digit", func(a, h string) (string, string) { return a, flip(h, strings.Index(h, "nonce=")+6+rng.Intn(32)) }},
		{"key digit", func(a, h string) (string, string) { return a, flip(h, strings.Index(h, "key=")+4+rng.Intn(16)) }},
		{"ts digit", func(a, h string) (string, string) { return a, flip(h, strings.Index(h, "ts=")+3+rng.Intn(10)) }},
		{"target char", func(a, h string) (string, string) { return flip(a, 1+rng.Intn(len(a)-1)), h }},
		{"target appended", func(a, h string) (string, string) { return a + "&x=1", h }},
		// The PHP console (and so this handler) also accepts a comma with no space after it; the Python double does not, so that
		// spelling is covered by TestParseAuthorization and is left out of this comparison.
		{"two spaces after a comma", func(a, h string) (string, string) { return a, strings.Replace(h, ", ", ",  ", 1) }},
		{"lower-case scheme", func(a, h string) (string, string) { return a, "sfw1" + h[4:] }},
		{"trailing space", func(a, h string) (string, string) { return a, h + " " }},
		{"upper-case sig", func(a, h string) (string, string) {
			return a, strings.Replace(h, "sig=", "sig=", 1)[:strings.Index(h, "sig=")+4] + strings.ToUpper(h[strings.Index(h, "sig=")+4:])
		}},
	}
	handlerYes, siteYes := 0, 0
	var r *rig
	var site *fakeSite
	for n := 0; n < 400; n++ {
		if n%50 == 0 { // a fresh handler and site: the hour's limit is 60
			r = newRig(t)
			site = newFakeSite()
		}
		target := targets[rng.Intn(len(targets))]
		req := r.signed(target)
		hdr := req.Header.Get("Authorization")
		mut := mutations[rng.Intn(len(mutations))]
		target2, hdr2 := mut.do(target, hdr)
		// sometimes replay an earlier nonce exactly
		if rng.Intn(10) == 0 && n%50 != 0 {
			target2, hdr2 = target, hdr
			r.do(r.signed(target)) // use another request first so there is something to compare to
		}
		want := site.accepts(target2, hdr2)
		req2 := httpRequest(target2, hdr2)
		got := r.do(req2).Code == 200
		if got != want {
			t.Fatalf("request %d (mutation %q): handler says %v, fake site says %v\ntarget %q\nheader %q", n, mut.name, got, want, target2, hdr2)
		}
		if got {
			handlerYes++
		}
		if want {
			siteYes++
		}
	}
	if handlerYes < 50 || handlerYes == 400 {
		t.Fatalf("the corpus is not mixed: %d of 400 accepted", handlerYes)
	}
	t.Logf("%d of 400 requests accepted by both", handlerYes)
}

func flip(s string, i int) string {
	if i < 0 || i >= len(s) {
		return s
	}
	c := s[i]
	repl := byte('0')
	if c == '0' {
		repl = '1'
	}
	return s[:i] + string(repl) + s[i+1:]
}

func httpRequest(target, header string) *http.Request {
	req, _ := http.NewRequest("GET", "http://x"+target, nil)
	req.RequestURI = target
	req.Header.Set("Authorization", header)
	return req
}

// TestFakeSiteIsItselfSensitive is the negative control for the one above: the oracle refuses what it should, so
// agreement is not agreement on "everything passes".
func TestFakeSiteIsItselfSensitive(t *testing.T) {
	good := "SFW1 key=" + testKeyID + ", ts=" + strconv.FormatInt(vectorTS, 10) + ", nonce=" + vectorNonce + ", sig=" + vectorSig
	f := newFakeSite()
	if f.accepts(vectorTarget, flip(good, strings.Index(good, "sig=")+5)) {
		t.Fatal("accepted a damaged signature")
	}
	if f.accepts(vectorTarget+"x", good) {
		t.Fatal("accepted a damaged target")
	}
	if !f.accepts(vectorTarget, good) {
		t.Fatal("refused the shared vector")
	}
	if f.accepts(vectorTarget, good) {
		t.Fatal("accepted a replay")
	}
}
