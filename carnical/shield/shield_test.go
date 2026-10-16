// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
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
				// Accuracy needs reproducible, well-distributed hashes. The process-random
				// production seed gives different statistical errors on every run.
				var input [8]byte
				binary.BigEndian.PutUint64(input[:], uint64(i))
				digest := sha256.Sum256(input[:])
				h.add(binary.BigEndian.Uint64(digest[:8]))
			}
			if e := h.estimate(); math.IsNaN(e) || math.IsInf(e, 0) || math.Abs(e-float64(n))/float64(n) > 0.08 {
				t.Fatalf("estimate %.0f for %d", e, n)
			}
		})
	}
	for _, tc := range []struct {
		name string
		x    uint64
		idx  int
		rank uint8
	}{
		{"first remainder bit", uint64(17)<<54 | 1<<53, 17, 1},
		{"second remainder bit", uint64(17)<<54 | 1<<52, 17, 2},
		{"last remainder bit", 1, 0, 54},
		{"zero remainder", uint64(17) << 54, 17, 55},
		{"last register", math.MaxUint64, 1023, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHLL(10)
			h.add(tc.x)
			h.add(tc.x)
			if h.reg[tc.idx] != tc.rank {
				t.Fatalf("register %d: got %d, want %d", tc.idx, h.reg[tc.idx], tc.rank)
			}
			for i, rank := range h.reg {
				if i != tc.idx && rank != 0 {
					t.Fatalf("unrelated register %d changed to %d", i, rank)
				}
			}
		})
	}
	t.Run("merge and reset", func(t *testing.T) {
		left, right := newHLL(10), newHLL(10)
		left.add(1 << 53)                // register 0, rank 1
		left.add(uint64(1)<<54 | 1<<52)  // register 1, rank 2
		right.add(0)                     // register 0, maximum rank
		right.add(uint64(2)<<54 | 1<<51) // register 2, rank 3
		left.merge(&right)
		if left.reg[0] != 55 || left.reg[1] != 2 || left.reg[2] != 3 || right.reg[1] != 0 {
			t.Fatal("merge lost a rank or modified its source")
		}
		left.reset()
		for i, rank := range left.reg {
			if rank != 0 {
				t.Fatalf("reset retained register %d", i)
			}
		}
		if e := left.estimate(); e != 0 {
			t.Fatalf("empty counter estimated %.3f", e)
		}
	})
	t.Run("duplicate address hashing", func(t *testing.T) {
		h := newHLL(10)
		addr := netip.MustParseAddr("192.0.2.1")
		for i := 0; i < 100; i++ {
			h.add(hashAddr(addr))
		}
		if e := h.estimate(); math.IsNaN(e) || math.IsInf(e, 0) || math.Abs(e-1) > 0.08 {
			t.Fatalf("duplicate source counted as %.3f", e)
		}
	})
}

func TestTopKKeepsTheHeavyHittersAmongNoise(t *testing.T) {
	t.Run("incident labels retain unsigned counter ordering", func(t *testing.T) {
		d := &detector{incident: &incidentAcc{}}
		d.incident.labels = newTopK(2)
		d.incident.labels.add(1, "small", 0, 1)
		d.incident.labels.add(2, "large", 0, 1)
		d.incident.labels.e[1].count = math.MaxUint32
		d.incident.labels.add(2, "large", 0, 1) // a long attack counts past 32 bits
		event := d.incidentEvent("attack_update", 0)
		if got := event.Incident.Labels[0]; got.Label != "large" || got.Requests != math.MaxUint32+1 {
			t.Fatalf("incorrect incident ordering or count: %+v", event.Incident.Labels)
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
	got := map[uint64]uint64{}
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
	// Through the detector: an address that comes back every hour stays seen, and one that stops is forgotten.
	d := newDetector(DetectorConfig{})
	poller, other := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("198.51.100.8")
	start := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC).UnixNano()
	var newAt []int
	for h := 0; h <= 60; h++ {
		ns := start + int64(h)*int64(time.Hour)
		d.observe(ns, other, 1, "fp", 2, "/") // keeps the filter rotating
		if (h <= 30 || h == 60) && d.observe(ns, poller, 1, "fp", 2, "/") {
			newAt = append(newAt, h)
		}
	}
	if !slices.Equal(newAt, []int{0, 60}) {
		t.Fatalf("an address seen every hour until hour 30 was new at hours %v, want [0 60]", newAt)
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
		{"a ban count the strike counter cannot reach", func(c *Config) { c.BanAfter = 70000 }, false},
		{"negative known budget", func(c *Config) { c.MinKnownRate = -1 }, false},
		{"infinite known factor", func(c *Config) { c.KnownFactor = math.Inf(1) }, false},
		{"a larger known budget", func(c *Config) { c.KnownFactor, c.MinKnownRate = 4, 500 }, true},
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

// The strengths' names, and that each is a configuration New accepts; what each does to a flood and to a crowd is in
// sim_test.go.
func TestPreset(t *testing.T) {
	tests := []struct {
		name, err string // err is "" when the name is known
	}{
		{"normal", ""},
		{"strict", ""},
		{"relaxed", ""},
		{"stict", `unknown strength "stict": want relaxed, normal or strict (did you mean strict?)`},
		{"Relaxed", "(did you mean relaxed?)"},
		{"norm", "(did you mean normal?)"},
		{"", `unknown strength "": want relaxed, normal or strict`},
		{"aggressive", `unknown strength "aggressive": want relaxed, normal or strict`},
		{"strict,relaxed", `unknown strength "strict,relaxed": want relaxed, normal or strict`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Preset(tt.name)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("Preset(%q) = %v, want an error with %q", tt.name, err, tt.err)
				}
				if !strings.Contains(tt.err, "did you mean") && strings.Contains(err.Error(), "did you mean") {
					t.Fatalf("Preset(%q) = %v: suggests a name that is not close", tt.name, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			c.defaults()
			if tt.name == "normal" && !reflect.DeepEqual(c, DefaultConfig()) {
				t.Fatalf("normal is %+v, want DefaultConfig %+v", c, DefaultConfig())
			}
			if tt.name != "normal" && reflect.DeepEqual(c, DefaultConfig()) {
				t.Fatalf("%s is the default configuration", tt.name)
			}
		})
	}
}

// An address that keeps attacking after its ban expires is banned again within the same attack.
func TestABanIsRenewedWithinOneAttack(t *testing.T) {
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	s := newTestShield(t, &now, func(c *Config) { c.BanAfter, c.BanFor = 5, time.Minute })
	key, info := netip.MustParseAddr("203.0.113.9"), &attackInfo{epoch: 1}
	banned := func() (b bool) {
		s.sources.peek(key, func(src *source) { b = src.bannedUntil > now.UnixNano() })
		return b
	}
	for round := 1; round <= 2; round++ {
		for i := 0; i < 5; i++ {
			s.strike(now.UnixNano(), key, info)
		}
		if !banned() {
			t.Fatalf("round %d: not banned after BanAfter refusals", round)
		}
		now = now.Add(2 * time.Minute) // the ban runs out while the attack goes on
		if banned() {
			t.Fatalf("round %d: the ban did not expire", round)
		}
	}
	if got := s.counters.banned.Load(); got != 2 {
		t.Fatalf("%d bans, want 2", got)
	}
	// Monitor mode only reports an attack: an address over its own limit during one is refused as at any other time, and
	// never banned for it.
	t.Run("monitor mode never bans", func(t *testing.T) {
		now := now
		s := newTestShield(t, &now, func(c *Config) { c.BanAfter, c.BanFor, c.MonitorOnly = 5, time.Minute, true })
		s.det.info.Store(&attackInfo{epoch: 1, since: now.UnixNano(), fps: map[uint64]bool{}, paths: map[uint64]bool{}})
		ids := map[int]int{}
		for i := 0; i < 260; i++ { // all at once: its burst of 200 and then sixty refusals
			ids[s.Admit(req("GET", "/"), key).ID]++
		}
		now = now.Add(10 * time.Second)
		if d := s.Admit(req("GET", "/"), key); d.Action != Allow || ids[idRate] != 60 || ids[idBanned] != 0 || s.Snapshot().Banned != 0 {
			t.Fatalf("decisions %v, then %+v; %d bans", ids, d, s.Snapshot().Banned)
		}
	})
	// An IPv6 ban covers the /64. A trusted proxy that shares it with the address that earned the ban is still served, and
	// the ban is not sent to the kernel, which would drop the proxy's packets with the rest of the range. Nor do the proxy's
	// own requests, answered before the attack, give the range standing: its neighbour is a stranger like any other.
	t.Run("a trusted proxy in a banned /64", func(t *testing.T) {
		lb, neighbour := netip.MustParseAddr("2001:db8:1::10"), netip.MustParseAddr("2001:db8:1::99")
		for _, tc := range []struct {
			name     string
			trusted  netip.Prefix
			answered bool // the proxy's health checks were answered before the attack
			want     Action
			bans     uint64
			kernel   int
		}{
			{"is served and keeps its packets", netip.PrefixFrom(lb, 128), false, Allow, 1, 0},
			{"control: an untrusted one is banned with its range", netip.MustParsePrefix("2001:db8:9::1/128"), false, Refuse, 1, 1},
			{"its answered requests give its range no standing", netip.PrefixFrom(lb, 128), true, Allow, 1, 0},
			{"control: an untrusted one's answered requests make its range known", netip.MustParsePrefix("2001:db8:9::1/128"), true, Allow, 0, 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				now := now
				s := newTestShield(t, &now, func(c *Config) {
					c.BanAfter, c.Banner, c.Trusted = 3, nopBanner{}, []netip.Prefix{tc.trusted}
				})
				s.Close() // nothing takes a ban off the queue: what was sent to the kernel stays there
				if tc.answered {
					s.det.learning.Store(true)
					for i := 0; i < 10; i++ {
						now = now.Add(20 * time.Second)
						s.Done(s.Admit(req("GET", "/healthz"), lb), 200, true)
					}
					now = now.Add(5 * time.Minute)
					s.det.learning.Store(false)
				}
				s.det.info.Store(&attackInfo{epoch: 1, since: now.UnixNano(), fps: map[uint64]bool{}, paths: map[uint64]bool{}})
				for i := 0; i < 5; i++ { // one request in the budget, then three refusals and a ban
					s.Admit(req("GET", "/api", "Accept", "application/json"), neighbour)
				}
				if d := s.Admit(req("GET", "/healthz"), lb); d.Action != tc.want || s.Snapshot().Banned != tc.bans || len(s.bans) != tc.kernel {
					t.Fatalf("the proxy got %+v; %d bans, %d sent to the kernel", d, s.Snapshot().Banned, len(s.bans))
				}
			})
		}
	})
	// What counts toward a ban (BanAfter 3) from one address, while a browser there holds the answer to a challenge: a
	// refusal (r) and a wrong answer (f) do, and showing the challenge to someone (c) counts as a tenth of one. A right
	// answer (s), which can be sent again, takes back one challenge shown, never more than were shown, and never a refusal
	// or a wrong answer. At the end, the browser that answered is served unless the address was banned.
	t.Run("what counts toward a ban", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			steps   string
			monitor bool
			want    Action
		}{
			{"the challenge shown 29 times", strings.Repeat("c", 29), false, Allow},
			{"the challenge shown 30 times, ten for each refusal", strings.Repeat("c", 30), false, Refuse},
			{"the challenge shown 30 times, each answered", strings.Repeat("cs", 30), false, Allow},
			{"the challenge page loaded by 30 browsers, each answered", strings.Repeat("bs", 30), false, Allow},
			{"the challenge shown 29 times, answered 29 times, shown 29 times", strings.Repeat("c", 29) + strings.Repeat("s", 29) + strings.Repeat("c", 29), false, Allow},
			{"the answer sent ten times after one challenge shown, then 30 shown", "c" + strings.Repeat("s", 10) + strings.Repeat("c", 30), false, Refuse},
			{"a refusal and the challenge shown 20 times", "r" + strings.Repeat("c", 20), false, Refuse},
			{"refusals", "rrr", false, Refuse},
			{"the same answer sent again between refusals", "rsrsr", false, Refuse},
			{"wrong answers", "fff", false, Refuse},
			{"wrong answers and refusals", "frf", false, Refuse},
			{"wrong answers in monitor mode", "fff", true, Allow},
		} {
			t.Run(tc.name, func(t *testing.T) {
				now := now
				s := newTestShield(t, &now, func(c *Config) { c.BanAfter, c.MonitorOnly = 3, tc.monitor })
				s.det.info.Store(&attackInfo{epoch: 1, since: now.UnixNano(), fps: map[uint64]bool{}, paths: map[uint64]bool{}})
				s.Admit(req("GET", "/api", "Accept", "application/json"), netip.MustParseAddr("192.0.2.1")) // the budget's one request
				tok := s.token(key, now)
				answer := req("GET", VerifyPath+"?t="+tok+"&n="+solve(tok, 8), "User-Agent", "browser A")
				cookie := s.Admit(answer, key).resp.cookie
				for i, step := range tc.steps {
					r, want := req("GET", "/api", "Accept", "application/json"), idUnknown
					switch step {
					case 'b': // a browser shown the page asks for /favicon.ico unless the page names an icon its policy allows
						w := httptest.NewRecorder()
						page := req("GET", "/", "User-Agent", "visitor "+strconv.Itoa(i), "Accept", "text/html", "Sec-Fetch-Mode", "navigate")
						s.Write(w, page, s.Admit(page, key))
						if strings.Contains(w.Body.String(), `<link rel="icon" href="data:,">`) && strings.Contains(w.Header().Get("Content-Security-Policy"), "img-src data:") {
							continue
						}
						r = req("GET", "/favicon.ico", "Accept", "image/*", "Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Dest", "image")
					case 'c':
						r, want = req("GET", "/", "User-Agent", "visitor "+strconv.Itoa(i), "Accept", "text/html"), idChallenge
					case 's':
						r, want = answer, idChallengeSolved
					case 'f':
						r, want = req("GET", VerifyPath+"?t="+tok+"&n="+solveWrong(tok, 8)), idChallengeFailed
					}
					if d := s.Admit(r, key); d.ID != want {
						t.Fatalf("step %d (%c): rule %d, want %d", i, step, d.ID, want)
					}
				}
				r := req("GET", "/", "User-Agent", "browser A", "Accept", "text/html")
				r.AddCookie(cookie)
				if d := s.Admit(r, key); d.Action != tc.want {
					t.Fatalf("the browser that answered got %+v", d)
				}
			})
		}
	})
	// A banned address is told when the ban runs out; a refusal for the attack's shared budget gives an estimate.
	t.Run("Retry-After", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			refusals int           // before the request looked at; three get the address banned
			after    time.Duration // between them and it
			status   int
			want     string
		}{
			{"a ban", 3, 0, http.StatusForbidden, "600"},
			{"a ban a second later", 3, time.Second, http.StatusForbidden, "599"},
			{"the last moment of a ban", 3, 10*time.Minute - time.Millisecond, http.StatusForbidden, "1"},
			{"the attack's budget", 0, 0, http.StatusServiceUnavailable, "5"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				now := now
				s := newTestShield(t, &now, func(c *Config) { c.BanAfter = 3 })
				s.det.info.Store(&attackInfo{epoch: 1, since: now.UnixNano(), fps: map[uint64]bool{}, paths: map[uint64]bool{}})
				api := func() *http.Request { return req("GET", "/api", "Accept", "application/json") }
				s.Admit(api(), netip.MustParseAddr("192.0.2.1")) // the budget's one request
				for i := 0; i < tc.refusals; i++ {
					s.Admit(api(), key)
				}
				now = now.Add(tc.after)
				w := httptest.NewRecorder()
				s.Write(w, api(), s.Admit(api(), key))
				if w.Code != tc.status || w.Header().Get("Retry-After") != tc.want {
					t.Fatalf("status %d, Retry-After %q, want %d and %q", w.Code, w.Header().Get("Retry-After"), tc.status, tc.want)
				}
			})
		}
	})
	// Nor does a client that became known shortly before the attack lose its standing for its connections (the reserved
	// share, and keeping an idle connection), which mitigation takes from it.
	t.Run("monitor mode keeps a recent client known", func(t *testing.T) {
		for _, monitor := range []bool{true, false} {
			now := now
			s := newTestShield(t, &now, func(c *Config) { c.MonitorOnly = monitor })
			s.sources.do(key, now.UnixNano(), func(src *source) {
				src.knownAt, src.knownUntil = now.Add(-10*time.Second).UnixNano(), now.Add(time.Hour).UnixNano()
			})
			s.det.info.Store(&attackInfo{epoch: 1, since: now.UnixNano(), fps: map[uint64]bool{}, paths: map[uint64]bool{}})
			mine, theirs := net.Pipe()
			defer theirs.Close()
			c := s.admitConn(addrConn{mine, net.TCPAddrFromAddrPort(netip.AddrPortFrom(key, 40000))})
			if c == nil {
				t.Fatalf("monitor %v: the connection was refused", monitor)
			}
			if known := c.(*conn).known; known != monitor {
				t.Fatalf("monitor %v: the client is known: %v", monitor, known)
			}
			c.Close()
		}
	})
}

// A known client gets past the attack's budgets only within a budget of its own. A botnet that earned standing before it
// attacks, each address well under its own limit and sending exactly what the attack sends, is held to that budget, struck
// and banned like strangers, and loses its standing; a known client comes through again once they are gone. A browser that
// answered the challenge is not held to the budget.
func TestStandingDoesNotCarryAFlood(t *testing.T) {
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	s := newTestShield(t, &now, nil)
	hdr := []string{"User-Agent", "probe-client/1.0", "Accept", "*/*"}
	bots := make([]netip.Addr, 200)
	for i := range bots {
		bots[i] = netip.AddrFrom4([4]byte{byte(20 + i%100), byte(i / 100), 7, 1}) // each in a network of its own
	}
	person := netip.MustParseAddr("198.51.100.9")
	// Ordinary traffic for two minutes; every bot and the person earn standing with a request every 20 seconds.
	for sec := 0; sec < 120; sec++ {
		start := now
		for i := 0; i < 20; i++ {
			now = start.Add(time.Duration(i+1) * 40 * time.Millisecond)
			s.Done(s.Admit(req("GET", "/", "User-Agent", "Mozilla/5.0", "Accept", "text/html"), netip.AddrFrom4([4]byte{10, 1, byte(i), 1})), 200, true)
		}
		if sec%20 == 0 {
			for _, a := range append([]netip.Addr{person}, bots...) {
				now = now.Add(time.Microsecond)
				s.Done(s.Admit(req("GET", "/", hdr...), a), 200, true)
			}
		}
		now = start.Add(time.Second)
		s.Tick()
	}
	for _, a := range append([]netip.Addr{person}, bots...) {
		if !s.sources.peek(SourceKey(a), func(src *source) {
			if src.knownUntil <= now.UnixNano() {
				t.Fatalf("%s did not earn standing", a)
			}
		}) {
			t.Fatalf("%s is not remembered", a)
		}
	}
	fp, _ := fingerprint(req("GET", "/", hdr...))
	now = now.Add(10 * time.Minute)
	s.det.info.Store(&attackInfo{epoch: 1, since: now.UnixNano(), fps: map[uint64]bool{fp: true}, paths: map[uint64]bool{}, knownRate: 50})
	admitted, sent := 0, 0
	for sec := 0; sec < 60; sec++ {
		start := now
		for i := 0; i < 10; i++ { // ten a second from each bot: 2,000 a second, a fifth of each address's own limit
			for j, a := range bots {
				now = start.Add(time.Duration(i*len(bots)+j+1) * 400 * time.Microsecond)
				sent++
				if s.Admit(req("GET", "/", hdr...), a).Action == Allow {
					admitted++
				}
			}
		}
		now = start.Add(time.Second)
	}
	if limit := 50*60 + 200; admitted > limit {
		t.Fatalf("the bots with standing got %d of %d requests through, more than the known budget of %d", admitted, sent, limit)
	}
	banned := 0
	for _, a := range bots {
		s.sources.peek(SourceKey(a), func(src *source) {
			if src.bannedUntil > now.UnixNano() && src.knownUntil <= now.UnixNano() {
				banned++
			}
		})
	}
	t.Logf("bots with standing: %d of %d requests admitted, %d of %d banned", admitted, sent, banned, len(bots))
	if banned < len(bots)*9/10 {
		t.Fatalf("only %d of %d bots were banned and lost their standing", banned, len(bots))
	}
	for i := 0; i < 10; i++ {
		now = now.Add(100 * time.Millisecond)
		if d := s.Admit(req("GET", "/", hdr...), person); d.Action != Allow {
			t.Fatalf("request %d of a known client was refused once the bots were banned: %+v", i, d)
		}
	}
	// A browser that answered the challenge, from an address the shield never saw, while the known budget is spent.
	browser := netip.MustParseAddr("192.0.2.77")
	tok := s.token(browser, now)
	v := s.verify(req("GET", VerifyPath+"?t="+tok+"&n="+solve(tok, 8), "User-Agent", "probe-client/1.0"), browser, now)
	if v.resp.cookie == nil {
		t.Fatalf("verify: %+v", v)
	}
	s.knownBudget = bucket{tokens: 0, last: now.UnixNano()}
	for i := 0; i < 100; i++ {
		now = now.Add(20 * time.Millisecond)
		r := req("GET", "/", hdr...)
		r.AddCookie(v.resp.cookie)
		if d := s.Admit(r, browser); d.Action != Allow {
			t.Fatalf("request %d of a browser that answered the challenge was refused: %+v", i, d)
		}
	}
	// A page load is a burst of requests at once: a new attack's known budget starts with a burst, not with one request.
	s.det.info.Store(&attackInfo{epoch: 2, since: now.UnixNano(), fps: map[uint64]bool{fp: true}, paths: map[uint64]bool{}, knownRate: 50})
	for i := 0; i < 100; i++ {
		if d := s.Admit(req("GET", "/", hdr...), person); d.Action != Allow {
			t.Fatalf("request %d of 100 at once from a known client at the start of an attack was refused: %+v", i, d)
		}
	}
}

// The known clients' budget is set when an attack is declared, from the baseline then: KnownFactor times the usual rate, and
// at least MinKnownRate (defaults 2 and 50).
func TestTheKnownBudgetFollowsTheBaselineWhenAnAttackStarts(t *testing.T) {
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		mod      func(*Config)
		baseline float64
		want     float64
	}{
		{"default factor on a busy site", nil, 100, 200},
		{"default minimum on a quiet site", nil, 10, 50},
		{"set factor", func(c *Config) { c.KnownFactor, c.MinKnownRate = 3, 40 }, 100, 300},
		{"set minimum", func(c *Config) { c.KnownFactor, c.MinKnownRate = 3, 40 }, 5, 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestShield(t, &now, tc.mod)
			s.det.mu.Lock()
			s.det.base.rate = tc.baseline
			s.det.startAttack(now.UnixNano(), aggregate{}, nil, false, false)
			s.det.mu.Unlock()
			if got := s.det.info.Load().knownRate; got != tc.want {
				t.Fatalf("known budget %v, want %v", got, tc.want)
			}
		})
	}
}

// A flood of new addresses fills the table; it must push out its own entries before a ban or a known client's standing.
func TestAFloodDoesNotEvictBansOrKnownClients(t *testing.T) {
	tab := newTable[netip.Addr, source](1024, sourceIdle, sourceLast, sourceKeep)
	const now = int64(1e12)
	banned, known := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
	tab.do(banned, 0, func(src *source) { src.bannedUntil = 2 * now })
	tab.do(known, 0, func(src *source) { src.knownUntil = 2 * now })
	for i := 0; i < 1<<16; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		tab.do(a, now, func(src *source) { src.last = now })
	}
	for _, a := range []netip.Addr{banned, known} {
		if !tab.peek(a, func(*source) {}) {
			t.Fatalf("%s was evicted by the flood", a)
		}
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
	t.Run("IDS lifecycle and response provenance", func(t *testing.T) {
		for _, tc := range []struct {
			name            string
			active, trusted bool
			want            uint64
		}{
			{"early close", false, false, 1}, {"HTTP activity", true, false, 0}, {"trusted peer", false, true, 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				sh := newTestShield(t, &now, func(c *Config) { c.MonitorOnly = true })
				socket, peer := net.Pipe()
				defer peer.Close()
				sc := &conn{Conn: socket, s: sh, key: netip.MustParseAddr("192.0.2.1"), subnet: netip.MustParsePrefix("192.0.2.0/24"), trusted: tc.trusted}
				if admitted, _ := sh.reserveConn(sc, 1); !admitted {
					t.Fatal("control connection refused")
				}
				if tc.active {
					sh.ConnState(tls.Server(sc, &tls.Config{MinVersion: tls.VersionTLS12}), http.StateActive)
				}
				if err := sc.Close(); err != nil {
					t.Fatal(err)
				}
				if err := sc.Close(); err != nil {
					t.Fatal(err)
				}
				snap := sh.Snapshot()
				if snap.EarlyCloses != tc.want || snap.Connections != 0 {
					t.Fatalf("close accounting: %+v", snap)
				}
			})
		}
		for _, tc := range []struct {
			name   string
			status int
			origin bool
			want   uint64
		}{
			{"WAF forbidden", 403, false, 1}, {"invalid request", 400, false, 1}, {"origin not found", 404, true, 0},
			{"origin forbidden", 403, true, 0}, {"gateway failure", 503, false, 0}, {"successful request", 200, true, 0},
			{"a client too slow to send its request", 408, false, 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				sh := newTestShield(t, &now, func(c *Config) { c.MonitorOnly = true })
				d := sh.Admit(req("GET", "/"), netip.MustParseAddr("192.0.2.1"))
				if d.Action != Allow {
					t.Fatal("control request refused")
				}
				sh.Done(d, tc.status, tc.origin)
				sh.Done(Decision{Action: Refuse}, 403, false)
				if got := sh.Snapshot().SecurityRejections; got != tc.want {
					t.Fatalf("security rejections=%d want=%d", got, tc.want)
				}
			})
		}
	})
	t.Run("IDS thresholds and alert pacing", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			a       aggregate
			signals int
		}{
			{"network admission pressure", aggregate{connRate: 40, connRefused: 25}, 1},
			{"early TCP closes", aggregate{closed: 40, earlyCloses: 35}, 1},
			{"WAF rejection burst", aggregate{rate: 40, securityRejects: 25}, 1},
			{"all three signals", aggregate{connRate: 40, connRefused: 25, closed: 40, earlyCloses: 35, rate: 40, securityRejects: 25}, 3},
			{"low volume", aggregate{connRate: 10, connRefused: 9, closed: 10, earlyCloses: 9, rate: 10, securityRejects: 9}, 0},
			{"busy site low ratios", aggregate{connRate: 1000, connRefused: 25, closed: 1000, earlyCloses: 35, rate: 1000, securityRejects: 25}, 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				det := newDetector(DetectorConfig{})
				var events []Event
				det.onEvent = func(e Event) { events = append(events, e) }
				ns := now.UnixNano()
				det.detectIDS(ns, tc.a)
				if len(det.idsReasons) != tc.signals {
					t.Fatalf("signals=%v", det.idsReasons)
				}
				if tc.signals == 0 {
					if len(events) != 0 {
						t.Fatal("unexpected signal")
					}
					return
				}
				events[0].Reasons[0] = "modified"
				if det.idsReasons[0] == "modified" {
					t.Fatal("event owns detector reasons")
				}
				det.detectIDS(ns+int64(time.Second), tc.a)
				if len(events) != 1 || events[0].Kind != "ids_signal" || det.state != Normal || det.info.Load() != nil {
					t.Fatal("alert pacing or mitigation changed")
				}
				det.detectIDS(ns+int64(30*time.Second), tc.a)
				if len(events) != 2 {
					t.Fatal("persistent signal was not reported")
				}
				det.detectIDS(ns+int64(31*time.Second), aggregate{})
				if len(det.idsReasons) != 0 {
					t.Fatal("cleared signal remained")
				}
			})
		}
	})
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
	// A refusal for an address's or a network's own limit says when its next token comes, at the rate it is held to.
	t.Run("Retry-After is the wait for the next token", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			mod    func(*Config)
			second string        // where the second request comes from, the first being from 203.0.113.1
			after  time.Duration // between the two
			want   string
		}{
			{"one a second", func(c *Config) { c.RequestRate, c.RequestBurst = 1, 1 }, "203.0.113.1", 0, "1"},
			{"one every five seconds", func(c *Config) { c.RequestRate, c.RequestBurst = 0.2, 1 }, "203.0.113.1", 0, "5"},
			{"two of the five seconds gone", func(c *Config) { c.RequestRate, c.RequestBurst = 0.2, 1 }, "203.0.113.1", 2 * time.Second, "3"},
			{"the network's limit", func(c *Config) { c.RequestRate, c.RequestBurst, c.SubnetRate, c.SubnetBurst = 0.2, 1, 0.5, 1 }, "203.0.113.2", 0, "2"},
			{"at most an hour", func(c *Config) { c.RequestRate, c.RequestBurst = 0.0001, 1 }, "203.0.113.1", 0, "3600"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				now := now
				s := newTestShield(t, &now, tc.mod)
				if d := s.Admit(req("GET", "/"), netip.MustParseAddr("203.0.113.1")); d.Action != Allow {
					t.Fatalf("the first request was refused: %+v", d)
				}
				now = now.Add(tc.after)
				d := s.Admit(req("GET", "/"), netip.MustParseAddr(tc.second))
				w := httptest.NewRecorder()
				s.Write(w, req("GET", "/"), d)
				if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != tc.want {
					t.Fatalf("status %d, Retry-After %q, want %q", w.Code, w.Header().Get("Retry-After"), tc.want)
				}
			})
		}
	})
	// The shield's own clock (no Config.Now) is not the wall clock: when that is set back an hour (an NTP correction, a
	// virtual machine restored), an address that has spent its burst gets its limit back as time passes, not an hour later.
	t.Run("a step back of the wall clock does not stop the limits", func(t *testing.T) {
		sh := newTestShield(t, &now, func(c *Config) { c.Now, c.RequestRate, c.RequestBurst = nil, 100, 10 })
		sh.Close() // no ticker alongside the test
		a := netip.MustParseAddr("203.0.113.50")
		for i := 0; i < 10; i++ {
			sh.Admit(req("GET", "/"), a)
		}
		sh.wall = func() time.Time { return time.Now().Add(-time.Hour) }
		time.Sleep(50 * time.Millisecond) // five requests at 100 a second
		if d := sh.Admit(req("GET", "/"), a); d.Action != Allow {
			t.Fatalf("after the wall clock was set back the address was refused (%d): its limit stopped refilling", d.ID)
		}
	})
}

// failedResponseWriter models a disconnected client after the response status was committed.
type failedResponseWriter struct{ *httptest.ResponseRecorder }

func (failedResponseWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// addrConn is a connection that says it comes from the address given.
type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

// nopBanner accepts every ban and does nothing with it.
type nopBanner struct{}

func (nopBanner) Ban(context.Context, netip.Prefix, time.Duration, string) error { return nil }

// An address's limits are raised by what that address itself has had answered well by the application in seconds that
// were not an attack's. What one address earns no other address has, and a request that was answered with an error, or
// by the proxy itself, earns nothing: the limit of an address that only probes stays where the operator put it.
func TestEachAddressEarnsItsOwnLimits(t *testing.T) {
	const burst, connBurst, netConns = 10, 2, 4
	busy, other := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.7")
	late, trusted := netip.MustParseAddr("198.18.0.7"), netip.MustParseAddr("192.0.2.7")
	html := []string{"User-Agent", "Mozilla/5.0", "Accept", "text/html"}
	for _, tc := range []struct {
		name       string
		status     int
		fromOrigin bool
		earns      bool
	}{
		{"answered well by the application", 200, true, true},
		{"redirected by the application", 302, true, true},
		{"not found", 404, true, false},
		{"an error from the application", 500, true, false},
		{"answered by the proxy itself", 200, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
			s := newTestShield(t, &now, func(c *Config) {
				c.RequestRate, c.RequestBurst, c.SubnetRate, c.SubnetBurst = 5, burst, 10, 2*burst
				c.ConnRate, c.ConnBurst, c.SubnetConns = 1, connBurst, netConns
				c.MaxSources = 1024
				c.Trusted = []netip.Prefix{netip.PrefixFrom(trusted, 24)}
			})
			// ordinary runs seconds of ordinary traffic: twenty people a second, and four requests a second from each of
			// the addresses given, which is within the limit of five.
			ordinary := func(seconds int, from ...netip.Addr) {
				t.Helper()
				for sec := 0; sec < seconds; sec++ {
					start := now
					for i := 0; i < 20; i++ {
						now = start.Add(time.Duration(i+1) * 20 * time.Millisecond)
						s.Done(s.Admit(req("GET", "/", html...), netip.AddrFrom4([4]byte{10, 1, byte(i), 1})), 200, true)
					}
					for i := 0; i < 4*len(from); i++ {
						now = start.Add(500*time.Millisecond + time.Duration(i+1)*5*time.Millisecond)
						d := s.Admit(req("GET", "/feed", html...), from[i%len(from)])
						if d.Action != Allow {
							t.Fatalf("a request within the limit was refused (%d)", d.ID)
						}
						s.Done(d, tc.status, tc.fromOrigin)
					}
					now = start.Add(time.Second)
					s.Tick()
				}
				if st := s.State(); st != Normal {
					t.Fatalf("the state is %v: %q", st, s.Snapshot().Reasons)
				}
			}
			// atOnce is how many requests, and then how many connections, an address gets at one moment, after ten quiet
			// seconds in which every bucket has filled.
			atOnce := func(a netip.Addr) (requests, conns int) {
				for i := 0; i < 10; i++ {
					now = now.Add(time.Second)
					s.Tick()
				}
				for i := 0; i < 40*burst; i++ {
					if s.Admit(req("GET", "/"), a).Action == Allow {
						requests++
					}
				}
				for i := 0; i < 40*connBurst; i++ {
					mine, theirs := net.Pipe()
					defer theirs.Close()
					defer mine.Close()
					if c := s.admitConn(addrConn{mine, net.TCPAddrFromAddrPort(netip.AddrPortFrom(a, 40000))}); c != nil {
						conns++
						defer c.Close() // gives its place back
					}
				}
				return requests, conns
			}
			if snap := s.Snapshot(); snap.RequestScale != 1 || snap.NetworkScale != 1 {
				t.Fatalf("before anything was earned the limits are raised %vx and %vx", snap.RequestScale, snap.NetworkScale)
			}
			// Forty minutes: a second weighs a six-hundredth and counts for at most twice the average, so that is how long
			// an average takes to settle.
			ordinary(40*60, busy, trusted)
			// The dashboard shows how far each limit was raised, the address's and the network's apart. Four requests a
			// second earn a limit of four times that: 3.2 times an address's 5 a second, 1.6 times a network's 10.
			wantSrc, wantNet := 1.0, 1.0
			if tc.earns {
				wantSrc, wantNet = 3.2, 1.6
			}
			if snap := s.Snapshot(); math.Abs(snap.RequestScale-wantSrc) > 0.1*wantSrc || math.Abs(snap.NetworkScale-wantNet) > 0.1*wantNet {
				t.Errorf("the dashboard says the limits were raised %.2fx and %.2fx, want about %.1fx and %.1fx", snap.RequestScale, snap.NetworkScale, wantSrc, wantNet)
			}
			if requests, conns := atOnce(other); requests != burst || conns != connBurst {
				t.Errorf("an address that had sent nothing got %d requests and %d connections at once, want its own limits of %d and %d", requests, conns, burst, connBurst)
			}
			requests, conns := atOnce(busy)
			if !tc.earns {
				if requests != burst || conns != connBurst {
					t.Errorf("the address got %d requests and %d connections at once, want the limits of %d and %d: it earned by answers that were not good ones", requests, conns, burst, connBurst)
				}
				return
			}
			// More than the address's own limits, and more connections than its network's: both were raised.
			if requests <= 2*burst || conns <= netConns {
				t.Errorf("the address got %d requests and %d connections at once: it has not earned more than the limits of %d and %d", requests, conns, burst, netConns)
			}
			if requests > 20*burst || conns > 20*connBurst {
				t.Errorf("the address got %d requests and %d connections at once: more than 20 times the limits", requests, conns)
			}
			// An address the limits do not apply to earns nothing and is not remembered as a network.
			if s.subnets.peek(netOf(trusted), func(*subnet) {}) {
				t.Error("a trusted address's network is remembered")
			}
			// A sudden rise counts for little at first: an address that arrives now and sends as much has earned nothing
			// five minutes later.
			ordinary(5*60, busy, late)
			if requests, conns := atOnce(late); requests != burst || conns != connBurst {
				t.Errorf("an address that arrived five minutes ago got %d requests and %d connections at once, want %d and %d", requests, conns, burst, connBurst)
			}
			// And what was earned fades when the address stops sending.
			ordinary(60 * 60)
			if requests, conns := atOnce(busy); requests != burst || conns != connBurst {
				t.Errorf("an hour after its last request the address got %d requests and %d connections at once, want %d and %d", requests, conns, burst, connBurst)
			}
		})
	}
}

// What an address and its network have earned is standing, like being known: a flood of new addresses that fills the
// tables does not push it out, and a ban takes it away.
func TestWhatAnAddressEarnedIsStanding(t *testing.T) {
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	s := newTestShield(t, &now, func(c *Config) {
		c.RequestRate, c.RequestBurst, c.SubnetRate, c.SubnetBurst, c.MaxSources = 5, 10, 5, 10, 1024
		c.KnownAfter = 60000 // nobody becomes known here: only what was earned can keep an entry
	})
	busy := netip.MustParseAddr("198.51.100.7")
	hdr := []string{"User-Agent", "probe-client/1.0", "Accept", "*/*"}
	for sec := 0; sec < 40*60; sec++ {
		start := now
		for i := 0; i < 20; i++ {
			now = start.Add(time.Duration(i+1) * 20 * time.Millisecond)
			s.Done(s.Admit(req("GET", "/", "User-Agent", "Mozilla/5.0", "Accept", "text/html"), netip.AddrFrom4([4]byte{10, 1, byte(i), 1})), 200, true)
		}
		for i := 0; i < 4; i++ {
			now = start.Add(500*time.Millisecond + time.Duration(i+1)*5*time.Millisecond)
			s.Done(s.Admit(req("GET", "/feed", hdr...), busy), 200, true)
		}
		now = start.Add(time.Second)
		s.Tick()
	}
	earned := func() (address, network float32) {
		s.sources.peek(SourceKey(busy), func(src *source) { address = src.earned.avg })
		s.subnets.peek(netOf(busy), func(n *subnet) { network = n.earned.avg })
		return address, network
	}
	if a, n := earned(); a < 3 || n < 3 {
		t.Fatalf("after forty minutes at four requests a second the address has earned %.1f and its network %.1f", a, n)
	}
	// Two quiet minutes, then more new addresses, each in a network of its own, than the tables hold.
	for i := 0; i < 120; i++ {
		now = now.Add(time.Second)
		s.Tick()
	}
	for i := 0; i < 20000; i++ {
		now = now.Add(time.Microsecond)
		s.Admit(req("GET", "/"), netip.AddrFrom4([4]byte{byte(11 + i>>16), byte(i >> 8), byte(i), 1}))
	}
	if n := s.sources.len(); n > 1100 {
		t.Fatalf("%d addresses are remembered: the flood did not fill the table, so this proves nothing", n)
	}
	if a, n := earned(); a < 3 || n < 3 {
		t.Fatalf("after a flood of new addresses the address has %.1f and its network %.1f left of what they earned", a, n)
	}
	// The address then takes part in an attack and is banned for it.
	fp, _ := fingerprint(req("GET", "/feed", hdr...))
	s.det.info.Store(&attackInfo{epoch: 1, since: now.UnixNano(), fps: map[uint64]bool{fp: true}, paths: map[uint64]bool{}})
	for i := 0; i < 200; i++ {
		now = now.Add(time.Millisecond)
		s.Admit(req("GET", "/feed", hdr...), busy)
	}
	banned := false
	s.sources.peek(SourceKey(busy), func(src *source) { banned = src.bannedUntil > now.UnixNano() })
	if a, _ := earned(); !banned || a != 0 {
		t.Fatalf("banned: %v; the address still has %.1f of what it earned", banned, a)
	}
}

// An attack neither adds to what an address has earned nor wears it down: the average's clock stops while it lasts. The
// attack here comes two minutes after the start; its fifty seconds would wear an average down by 8%, or add a fifth of a
// request a second to one, if they counted.
func TestNothingIsEarnedOrLostDuringAnAttack(t *testing.T) {
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	// Monitoring only, so that the attack is declared and nothing is refused or banned for it.
	s := newTestShield(t, &now, func(c *Config) { c.RequestRate, c.RequestBurst, c.MonitorOnly = 5, 10, true })
	before, during := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.7")
	second := func(from ...netip.Addr) {
		start := now
		for i := 0; i < 20; i++ {
			now = start.Add(time.Duration(i+1) * 20 * time.Millisecond)
			s.Done(s.Admit(req("GET", "/", "User-Agent", "Mozilla/5.0", "Accept", "text/html"), netip.AddrFrom4([4]byte{10, 1, byte(i), 1})), 200, true)
		}
		for i := 0; i < 4*len(from); i++ {
			now = start.Add(500*time.Millisecond + time.Duration(i+1)*5*time.Millisecond)
			d := s.Admit(req("GET", "/feed", "User-Agent", "Mozilla/5.0", "Accept", "text/html"), from[i%len(from)])
			if d.Action != Allow {
				t.Fatalf("a request was refused (%d)", d.ID)
			}
			s.Done(d, 200, true)
		}
		now = start.Add(time.Second)
		s.Tick()
	}
	earned := func(a netip.Addr) (avg float64) {
		s.sources.peek(SourceKey(a), func(src *source) { avg = src.earned.at(s.det.earn.Load(), 5) })
		return avg
	}
	for i := 0; i < 120; i++ {
		second(before)
	}
	had := earned(before)
	if had < 0.4 {
		t.Fatalf("after two minutes at four requests a second the address has earned %.2f", had)
	}
	s.det.mu.Lock()
	s.det.startAttack(now.UnixNano(), aggregate{}, nil, false, false)
	s.det.mu.Unlock()
	for i := 0; i < 50; i++ {
		second(during)
		if st := s.State(); st != Attack {
			t.Fatalf("second %d of the attack: the state is %v", i, st)
		}
	}
	if got := earned(before); got < 0.99*had || got > 1.01*had {
		t.Errorf("an address that had earned %.2f has %.2f after 50 seconds of an attack it took no part in", had, got)
	}
	// The attack ends; what the other address sent while it lasted counts for nothing.
	for i := 0; i < 180 && s.State() != Normal; i++ {
		second()
	}
	if st := s.State(); st != Normal {
		t.Fatalf("three minutes later the state is %v", st)
	}
	for i := 0; i < 5; i++ {
		second()
	}
	if got := earned(during); got > 0.05 {
		t.Errorf("an address that sent only during the attack has earned %.2f requests a second", got)
	}
}

// While the detector warms up a second weighs as much as every second before it in its baseline, and in its first seconds
// that would be most of an address's average: an address that used its whole burst then would have a limit several times
// its own a second later. A second weighs what it weighs in the warmed-up baseline, and counts for at most twice the
// average, from the first second.
func TestOneSecondsBurstIsNotAnAverage(t *testing.T) {
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	s := newTestShield(t, &now, func(c *Config) {
		c.RequestRate, c.RequestBurst, c.SubnetRate, c.SubnetBurst = 5, 30, 50, 300
	})
	a := netip.MustParseAddr("198.51.100.7")
	atOnce := func() (allowed int) {
		for i := 0; i < 40; i++ {
			if d := s.Admit(req("GET", "/"), a); d.Action == Allow {
				allowed++
				s.Done(d, 200, true)
			}
		}
		return allowed
	}
	second := func() {
		now = now.Add(time.Second)
		s.Tick()
	}
	for i := 0; i < 3; i++ { // the detector's clock is running: what is answered well from here on is earned
		second()
	}
	if got := atOnce(); got != 30 {
		t.Fatalf("the address got %d requests at once, want its burst of 30", got)
	}
	second()
	if got := atOnce(); got != 5 {
		t.Fatalf("a second after its burst the address got %d requests, want the 5 its limit gives back in a second", got)
	}
}

// An address raises its own limit by using it, so how fast, and how far, is what an address that takes everything it is
// given can do. Five minutes of that earn nothing, on a site the detector knows and right after a start without a
// baseline alike; the limit then doubles about every seven minutes, and stops at the ceiling the operator set. With a
// ceiling of 1 the limit never moves.
func TestALimitIsEarnedSlowlyAndStopsAtTheCeiling(t *testing.T) {
	const rate, burst = 5, 10
	for _, tc := range []struct {
		name     string
		ceiling  float64 // 0: the default of 20
		most     float64 // times the configured limit
		baseline float64 // the site's usual rate as the detector knows it at the start; 0: learnt from nothing
	}{
		{"the default ceiling", 0, 20, 60},
		{"a ceiling of four", 4, 4, 60},
		{"limits kept fixed", 1, 1, 60},
		{"the default ceiling, right after a start without a baseline", 0, 20, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
			s := newTestShield(t, &now, func(c *Config) {
				c.RequestRate, c.RequestBurst, c.SubnetRate, c.SubnetBurst = rate, burst, 500, 1000
				c.Detector.InitialRate = tc.baseline
				c.Detector.MaxScale = tc.ceiling
			})
			greedy := netip.MustParseAddr("198.51.100.7")
			html := []string{"User-Agent", "Mozilla/5.0", "Accept", "text/html"}
			// second is a second of the site's usual traffic in which the greedy address asks for a quarter more than it
			// was last given (so that it finds its limit without making the site look attacked) and is answered well each
			// time it is let through; it returns how often that was.
			last := rate
			second := func() (allowed int) {
				start := now
				for i := 0; i < 60; i++ {
					now = start.Add(time.Duration(i+1) * 5 * time.Millisecond)
					s.Done(s.Admit(req("GET", "/", html...), netip.AddrFrom4([4]byte{10, 1, byte(i), 1})), 200, true)
				}
				now = start.Add(500 * time.Millisecond)
				for i := 0; i < last+last/4+2; i++ {
					if d := s.Admit(req("GET", "/feed", html...), greedy); d.Action == Allow {
						allowed++
						s.Done(d, 200, true)
					}
				}
				now = start.Add(time.Second)
				s.Tick()
				if st := s.State(); st != Normal {
					t.Fatalf("the state is %v: %q", st, s.Snapshot().Reasons)
				}
				last = allowed
				return allowed
			}
			after := func(minutes int, seconds *int) (allowed int) {
				for ; *seconds < 60*minutes; *seconds++ {
					if allowed = second(); float64(allowed) > tc.most*burst {
						t.Fatalf("second %d: the address was served %d requests, more than %.0f times its burst", *seconds, allowed, tc.most)
					}
				}
				return allowed
			}
			seconds := 0
			if got := after(5, &seconds); got != rate {
				t.Errorf("after 5 minutes the address is served %d requests a second, want its configured %d", got, rate)
			}
			lo, hi := 2.0, 6.0 // about 3.7 times by then
			if tc.most < lo {
				lo, hi = 1, 1
			} else if tc.most < hi {
				hi = tc.most
			}
			if got := float64(after(20, &seconds)) / rate; got < lo || got > hi+0.21 {
				t.Errorf("after 20 minutes the address is served %.1f times its configured limit, want %.0f to %.0f times", got, lo, hi)
			}
			if got := float64(after(60, &seconds)) / rate; math.Abs(got-tc.most) > 0.21 {
				t.Errorf("after an hour the address is served %.1f times its configured limit, want the ceiling of %.0f", got, tc.most)
			}
		})
	}
}
