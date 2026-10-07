// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHLLEstimatesWithinAFewPercent(t *testing.T) {
	for _, n := range []int{50, 5_000, 200_000} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			h := newHLL(10)
			for i := 0; i < n; i++ {
				h.add(hashAddr(netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})))
			}
			if e := h.estimate(); math.Abs(e-float64(n))/float64(n) > 0.08 {
				t.Fatalf("estimate %.0f for %d", e, n)
			}
		})
	}
}

func TestTopKKeepsTheHeavyHittersAmongNoise(t *testing.T) {
	t.Run("incident labels retain unsigned counter ordering", func(t *testing.T) {
		d := &detector{incident: &incidentAcc{}}
		d.incident.labels = newTopK(2)
		d.incident.labels.e = []topEntry{{label: "small", count: 1}, {label: "large", count: math.MaxUint32}}
		event := d.incidentEvent("attack_update", 0)
		if event.Incident.Labels[0].Label != "large" {
			t.Fatalf("incorrect incident ordering: %+v", event.Incident.Labels)
		}
	})
	k := newTopK(16)
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 100_000; i++ {
		switch x := r.IntN(100); {
		case x < 30:
			k.add(1, "a", uint64(i), 1)
		case x < 45:
			k.add(2, "b", uint64(i), 1)
		default:
			k.add(uint64(1000+r.IntN(50_000)), "noise", uint64(i), 1)
		}
	}
	got := map[uint64]uint32{}
	for _, e := range k.e {
		got[e.key] = e.count
	}
	if got[1] < 29_000 || got[2] < 14_000 {
		t.Fatalf("heavy hitters lost or undercounted: %v", got)
	}
}

func TestSeenFilterRemembersForOneToTwoPeriods(t *testing.T) {
	f := newSeenFilter()
	for i := 0; i < 100_000; i++ {
		f.add(hashString("seen" + strconv.Itoa(i)))
	}
	for i := 0; i < 100_000; i += 997 {
		if !f.has(hashString("seen" + strconv.Itoa(i))) {
			t.Fatal("an added key is missing")
		}
	}
	fp := 0
	for i := 0; i < 20_000; i++ {
		if f.has(hashString("never" + strconv.Itoa(i))) {
			fp++
		}
	}
	if fp > 200 {
		t.Fatalf("%d false positives in 20,000", fp)
	}
	f.rotate()
	if !f.has(hashString("seen5")) {
		t.Fatal("forgotten after one rotation")
	}
	f.rotate()
	if f.has(hashString("seen5")) {
		t.Fatal("still remembered after two rotations")
	}
}

func TestBucketHoldsTheRateAndRefusedTakesNothing(t *testing.T) {
	var b bucket
	ns := int64(1e18)
	ok := 0
	for i := 0; i < 100; i++ { // 100 at once: the burst
		if b.take(ns, 10, 20) {
			ok++
		}
	}
	if ok != 20 {
		t.Fatalf("burst let %d through", ok)
	}
	ok = 0
	for i := 0; i < 1000; i++ { // ten seconds at 100 a second: the rate
		if b.take(ns+int64(i)*1e7, 10, 20) {
			ok++
		}
	}
	if ok < 95 || ok > 105 {
		t.Fatalf("rate let %d through in ten seconds at 10/s", ok)
	}
}

func req(method, target string, headers ...string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Header = http.Header{}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Add(headers[i], headers[i+1])
	}
	return r
}

func TestPathTemplatesTakeOutTheVariableParts(t *testing.T) {
	tests := []struct{ target, want string }{
		{"/", "/"},
		{"/product/1234/reviews?page=2", "/product/9/reviews?"},
		{"/product/98/reviews?page=7", "/product/9/reviews?"},
		{"/?r=8f7d6a5c", "/?"},
		{"/u/0f8e9a7b6c5d4e3f2a1b/avatar.png", "/u/x/avatar.png"},
		{"/a/b/c/d/e/f/g/h", "/a/b/c/d/e/f/*"},
		{"/about", "/about"},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			if _, got := pathTemplate(req("GET", tt.target)); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
	a, _ := pathTemplate(req("GET", "/search?q=one"))
	b, _ := pathTemplate(req("GET", "/search?q=two&x=1"))
	c, _ := pathTemplate(req("GET", "/search"))
	if a != b || a == c {
		t.Fatal("query values or keys changed the template, or its presence did not")
	}
}

func TestFingerprintsSeparateProgramsNotRequests(t *testing.T) {
	chrome := []string{"User-Agent", "Mozilla/5.0 Chrome/141", "Accept", "text/html", "Accept-Language", "en-AU,en;q=0.9", "Sec-Fetch-Mode", "navigate"}
	a, _ := fingerprint(req("GET", "/one", chrome...))
	b, _ := fingerprint(req("GET", "/two?x=1", append(chrome, "Cookie", "a=1")[:8]...))
	c, _ := fingerprint(req("GET", "/one", "User-Agent", "python-requests/2.32", "Accept", "*/*"))
	d, _ := fingerprint(req("GET", "/one", append(append([]string{}, chrome...), "Cookie", "a=1")...))
	if a != b {
		t.Fatal("the same program on different pages has different fingerprints")
	}
	if a == c || a == d {
		t.Fatal("different programs, or a program with and without a cookie, share a fingerprint")
	}
	many := []string{}
	for i := 0; i < 60; i++ {
		many = append(many, "X-H"+strconv.Itoa(i), "v")
	}
	x, _ := fingerprint(req("GET", "/", many...))
	for i := 0; i < 20; i++ {
		if y, _ := fingerprint(req("GET", "/", many...)); y != x {
			t.Fatal("a request with many headers has an unstable fingerprint")
		}
	}
}

func TestNavigationIsOnlyABrowserLoadingAPage(t *testing.T) {
	tests := []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"fetch metadata says navigate", req("GET", "/", "Sec-Fetch-Mode", "navigate"), true},
		{"fetch metadata says cors", req("GET", "/", "Sec-Fetch-Mode", "cors", "Accept", "text/html"), false},
		{"old browser asks for html", req("GET", "/", "Accept", "text/html,application/xhtml+xml"), true},
		{"API client", req("GET", "/api/x", "Accept", "application/json"), false},
		{"a POST is never shown a page", req("POST", "/", "Sec-Fetch-Mode", "navigate"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNavigation(tt.r); got != tt.want {
				t.Fatalf("got %v", got)
			}
		})
	}
}

func newTestShield(t *testing.T, clock *time.Time, mod func(*Config)) *Shield {
	t.Helper()
	cfg := Config{Now: func() time.Time { return *clock }, ChallengeBits: 8}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// solve finds the answer to a token by brute force.
func solve(token string, bits int) string {
	for n := 0; ; n++ {
		ns := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(token + "." + ns))
		if binary.BigEndian.Uint32(sum[:4]) < 1<<(32-bits) {
			return ns
		}
	}
}

func TestChallengeTokensAndClearance(t *testing.T) {
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	s := newTestShield(t, &now, nil)
	me, other := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("198.51.100.8")
	tok := s.token(me, now)
	n := solve(tok, 8)
	tests := []struct {
		name  string
		tok   string
		n     string
		key   netip.Addr
		at    time.Time
		valid bool
	}{
		{"the answer, from the address it was issued to", tok, n, me, now, true},
		{"the answer from another address", tok, n, other, now, false},
		{"a wrong answer", tok, solveWrong(tok, 8), me, now, false},
		{"after the token expired", tok, n, me, now.Add(tokenTTL + time.Second), false},
		{"a token with its difficulty lowered", tamper(tok, 16), n, me, now, false},
		{"not a number", tok, n + "x", me, now, false},
		{"garbage", "AAAA", "1", me, now, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.solved(tt.tok, tt.n, tt.key, tt.at); got != tt.valid {
				t.Fatalf("solved = %v", got)
			}
		})
	}

	d := s.verify(req("GET", VerifyPath+"?t="+tok+"&n="+n+"&to=/basket%3Fx%3D1", "User-Agent", "UA"), me, now)
	if d.Action != Respond || d.Status != http.StatusSeeOther || d.resp.cookie == nil || d.resp.location != "/basket?x=1" {
		t.Fatalf("verify: %+v %+v", d, d.resp)
	}
	withCookie := func(ua string) *http.Request {
		r := req("GET", "/", "User-Agent", ua)
		r.AddCookie(d.resp.cookie)
		return r
	}
	if !s.cleared(withCookie("UA"), me, now.Add(time.Minute)) {
		t.Fatal("the cookie does not admit the browser that earned it")
	}
	if s.cleared(withCookie("UA"), other, now) || s.cleared(withCookie("other UA"), me, now) || s.cleared(withCookie("UA"), me, now.Add(s.cfg.ClearanceFor+time.Second)) {
		t.Fatal("the cookie admits another address, another browser, or after it expired")
	}
	for _, tc := range []struct {
		name      string
		tls       bool
		forwarded string
	}{
		{"plain HTTP", false, ""},
		{"direct TLS", true, ""},
		{"untrusted forwarded scheme", false, "https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := req("GET", VerifyPath+"?t="+tok+"&n="+n, "X-Forwarded-Proto", tc.forwarded)
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			got := s.verify(r, me, now)
			if got.Status != http.StatusSeeOther || got.resp.cookie == nil || got.resp.cookie.Secure != tc.tls || !got.resp.cookie.HttpOnly {
				t.Fatalf("cookie transport flags: %+v", got.resp)
			}
		})
	}
	bad := s.verify(req("GET", VerifyPath+"?t="+tok+"&n="+solveWrong(tok, 8)), me, now)
	if bad.Status != http.StatusForbidden || bad.resp.cookie != nil {
		t.Fatal("a wrong answer earned a cookie")
	}
}

func solveWrong(token string, bits int) string {
	for n := 0; ; n++ {
		ns := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(token + "." + ns))
		if binary.BigEndian.Uint32(sum[:4]) >= 1<<(32-bits) {
			return ns
		}
	}
}

func tamper(tok string, bits byte) string {
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	raw[16] = bits
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestTheReturnAddressStaysOnTheSite(t *testing.T) {
	for in, want := range map[string]string{
		"/basket?x=1":                   "/basket?x=1",
		"//evil.example/":               "/",
		"/\\evil.example":               "/",
		"https://evil.example/":         "/",
		"/a\r\nSet-Cookie: x=1":         "/",
		"":                              "/",
		"/" + strings.Repeat("a", 3000): "/",
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q", in, got)
		}
	}
}

// The challenge page's JavaScript must compute the same SHA-256 as Go, or no browser could ever pass. This runs it in
// Node when Node is installed (it is skipped otherwise, and says so).
func TestTheChallengeScriptComputesSHA256(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; the challenge script was not run")
	}
	inputs := []string{"", "abc", strings.Repeat("a", 55), strings.Repeat("b", 56), strings.Repeat("c", 64), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.123456"}
	var js strings.Builder
	js.WriteString(solverJS + ";console.log([")
	for i, in := range inputs {
		if i > 0 {
			js.WriteString(",")
		}
		js.WriteString(strconv.Quote(in))
	}
	js.WriteString("].map(function(s){return (h(s)>>>0).toString()}).join(','))")
	file := filepath.Join(t.TempDir(), "h.js")
	if err := os.WriteFile(file, []byte(js.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, file).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(out)), ",")
	for i, in := range inputs {
		sum := sha256.Sum256([]byte(in))
		if want := strconv.FormatUint(uint64(binary.BigEndian.Uint32(sum[:4])), 10); got[i] != want {
			t.Errorf("input %d (%d bytes): script %s, Go %s", i, len(in), got[i], want)
		}
	}
}

func TestTheChallengePageEscapesTheReturnAddress(t *testing.T) {
	now := time.Now()
	s := newTestShield(t, &now, nil)
	body, nonce := s.challengePage(req("GET", `/x?a="</script><script>alert(1)</script>`), netip.MustParseAddr("192.0.2.1"), now)
	if strings.Count(body, "<script") != 1 || strings.Contains(body, "alert(1)</script>") || !strings.Contains(body, `nonce="`+nonce+`"`) {
		t.Fatalf("page: %s", body)
	}
}

func TestRangesLabelAddresses(t *testing.T) {
	table := "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
		"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
		"1.0.4.0\t1.0.7.255\t38803\tAU\tExample\n" +
		"2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t64500\tBR\tDoc\n"
	r, err := LoadRanges(strings.NewReader(table))
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]string{"1.0.0.7": "US AS13335", "1.0.2.1": "", "1.0.5.5": "AU AS38803", "1.0.8.0": "", "2001:db8::1": "BR AS64500", "::ffff:1.0.4.1": "AU AS38803"} {
		if got := r.Label(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %q, want %q", addr, got, want)
		}
	}
	if _, err := LoadRanges(strings.NewReader("1.0.4.0\t1.0.7.255\t1\tAU\tx\n1.0.0.0\t1.0.0.255\t2\tUS\ty\n")); err == nil {
		t.Fatal("an unsorted table was accepted")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*Config)
		ok   bool
	}{
		{"defaults", func(*Config) {}, true},
		{"negative rate", func(c *Config) { c.RequestRate = -1 }, false},
		{"NaN connection rate", func(c *Config) { c.ConnRate = math.NaN() }, false},
		{"NaN reserved share", func(c *Config) { c.ReservedShare = math.NaN() }, false},
		{"infinite network scale", func(c *Config) { c.Detector.MaxScale = math.Inf(1) }, false},
		{"infinite burst", func(c *Config) { c.ConnBurst = math.Inf(-1) }, false},
		{"scaled rate overflow", func(c *Config) { c.ConnRate, c.ConnBurst = math.MaxFloat64, math.MaxFloat64 }, false},
		{"network slower than an address", func(c *Config) { c.RequestRate, c.SubnetRate = 100, 50 }, false},
		{"too few connections", func(c *Config) { c.MaxConns = 4 }, false},
		{"challenge too hard", func(c *Config) { c.ChallengeBits = 30 }, false},
		{"trusted /0", func(c *Config) { c.Trusted = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} }, false},
		{"exit above entry", func(c *Config) { c.Detector.ExitFactor = 10 }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{}
			tt.mod(&c)
			if err := c.Validate(); (err == nil) != tt.ok {
				t.Fatalf("Validate() = %v", err)
			}
		})
	}
}

func TestPerAddressAndPerNetworkLimitsApplyOutsideAnAttack(t *testing.T) {
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	s := newTestShield(t, &now, func(c *Config) { c.RequestRate, c.RequestBurst, c.SubnetRate, c.SubnetBurst = 5, 10, 20, 30 })
	allowed := func(a string, n int) int {
		ok := 0
		for i := 0; i < n; i++ {
			if d := s.Admit(req("GET", "/"), netip.MustParseAddr(a)); d.Action == Allow {
				ok++
			} else if d.Status != http.StatusTooManyRequests {
				t.Fatalf("refused with %d", d.Status)
			}
		}
		return ok
	}
	if got := allowed("203.0.113.1", 50); got != 10 {
		t.Fatalf("one address got %d of 50 at once, want the burst of 10", got)
	}
	total := 0
	for i := 2; i < 12; i++ {
		total += allowed("203.0.113."+strconv.Itoa(i), 10)
	}
	t.Run("response write failures remain refusals and are counted", func(t *testing.T) {
		d := s.Admit(req("GET", "/"), netip.MustParseAddr("203.0.113.1"))
		for _, decision := range []Decision{d, s.verify(req("GET", VerifyPath), netip.MustParseAddr("203.0.113.1"), now), {Action: Challenge, Status: http.StatusServiceUnavailable, key: netip.MustParseAddr("203.0.113.1")}} {
			before := s.Snapshot().WriteErrors
			writer := failedResponseWriter{httptest.NewRecorder()}
			s.Write(writer, req("GET", "/"), decision)
			if writer.Code != decision.Status || s.Snapshot().WriteErrors != before+1 {
				t.Fatalf("failed write: status=%d errors=%d", writer.Code, s.Snapshot().WriteErrors)
			}
			control := httptest.NewRecorder()
			s.Write(control, req("GET", "/"), decision)
			s.Write(writer, req("HEAD", "/"), decision)
			if control.Code != decision.Status || control.Body.Len() == 0 || s.Snapshot().WriteErrors != before+1 {
				t.Fatal("successful response or HEAD counted as a failed write")
			}
		}
	})
	if total != 20 { // the /24's burst of 30, less the 10 the first address used
		t.Fatalf("the network let %d through, want 20", total)
	}
	if got := allowed("198.51.100.1", 5); got != 5 {
		t.Fatal("another network was limited too")
	}
	s2 := newTestShield(t, &now, func(c *Config) {
		c.RequestRate, c.RequestBurst = 5, 10
		c.Trusted = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	})
	for i := 0; i < 50; i++ {
		if d := s2.Admit(req("GET", "/"), netip.MustParseAddr("203.0.113.1")); d.Action != Allow {
			t.Fatal("a trusted address was limited")
		}
	}
}

// failedResponseWriter models a disconnected client after the response status was committed.
type failedResponseWriter struct{ *httptest.ResponseRecorder }

func (failedResponseWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
