// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("answer is not JSON: %v\n%s", err, w.Body.String())
	}
	return m
}

func errText(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	s, _ := decode(t, w)["error"].(string)
	return s
}

func TestTheSharedVector(t *testing.T) {
	secret := vectorSecret()
	if got := SecretText(secret); got != vectorSecretText {
		t.Fatalf("secret text %q", got)
	}
	back, err := SecretFromText(vectorSecretText)
	if err != nil || string(back) != string(secret) {
		t.Fatalf("secret from text: %v", err)
	}
	if got := SignedText(vectorTarget, vectorTS, vectorNonce); got != vectorSigned {
		t.Fatalf("signed text %q", got)
	}
	if got := Sign(secret, vectorTarget, vectorTS, vectorNonce); got != vectorSig {
		t.Fatalf("signature %s, want %s", got, vectorSig)
	}
	hdr, err := Authorization(testKeyID, secret, vectorTarget, vectorTS, vectorNonce)
	if err != nil {
		t.Fatal(err)
	}
	if want := "SFW1 key=" + testKeyID + ", ts=1791014400, nonce=" + vectorNonce + ", sig=" + vectorSig; hdr != want {
		t.Fatalf("header %q", hdr)
	}
	// and the handler accepts the request the vector describes
	r := newRig(t)
	req := signedAt(vectorTarget, secret, testKeyID, vectorTS, vectorNonce)
	if w := r.do(req); w.Code != 200 {
		t.Fatalf("the vector's own request was refused: %d %s", w.Code, w.Body.String())
	}
}

func TestEveryPartOfTheRequestIsCovered(t *testing.T) {
	secret := vectorSecret()
	base := Sign(secret, vectorTarget, vectorTS, vectorNonce)
	other := vectorSecret()
	other[0] ^= 1
	rows := []struct {
		name string
		sig  string
	}{
		{"other secret", Sign(other, vectorTarget, vectorTS, vectorNonce)},
		{"since changed", Sign(secret, "/feed?since=abd&days=7", vectorTS, vectorNonce)},
		{"days changed", Sign(secret, "/feed?since=abc&days=8", vectorTS, vectorNonce)},
		{"query order changed", Sign(secret, "/feed?days=7&since=abc", vectorTS, vectorNonce)},
		{"path case changed", Sign(secret, "/Feed?since=abc&days=7", vectorTS, vectorNonce)},
		{"time changed", Sign(secret, vectorTarget, vectorTS+1, vectorNonce)},
		{"nonce changed", Sign(secret, vectorTarget, vectorTS, "1"+vectorNonce[1:])},
		{"query dropped", Sign(secret, "/feed", vectorTS, vectorNonce)},
		{"encoded differently", Sign(secret, "/feed?since=%61bc&days=7", vectorTS, vectorNonce)},
	}
	seen := map[string]bool{base: true}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if seen[row.sig] {
				t.Fatalf("the signature did not change")
			}
			seen[row.sig] = true
		})
	}
}

func TestParseAuthorization(t *testing.T) {
	good := "SFW1 key=" + testKeyID + ", ts=1791014400, nonce=" + vectorNonce + ", sig=" + vectorSig
	rows := []struct {
		name string
		in   string
		ok   bool
	}{
		{"exact", good, true},
		{"no space after commas", "SFW1 key=" + testKeyID + ",ts=1791014400,nonce=" + vectorNonce + ",sig=" + vectorSig, true},
		{"empty", "", false},
		{"wrong scheme", "SFW2" + good[4:], false},
		{"lower-case scheme", "sfw1" + good[4:], false},
		{"upper-case hex key", strings.Replace(good, testKeyID, "ABCDEF0123456789", 1), false},
		{"short key", strings.Replace(good, testKeyID, testKeyID[:15], 1), false},
		{"long key", strings.Replace(good, testKeyID, testKeyID+"0", 1), false},
		{"short nonce", strings.Replace(good, vectorNonce, vectorNonce[:31], 1), false},
		{"short sig", good[:len(good)-1], false},
		{"long sig", good + "0", false},
		{"upper-case sig", strings.Replace(good, vectorSig, strings.ToUpper(vectorSig), 1), false},
		{"13 digit time", strings.Replace(good, "1791014400", "1791014400000", 1), false},
		{"signed time", strings.Replace(good, "ts=1791014400", "ts=-1791014400", 1), false},
		{"empty time", strings.Replace(good, "ts=1791014400", "ts=", 1), false},
		{"leading space", " " + good, false},
		{"trailing space", good + " ", false},
		{"trailing newline", good + "\n", false},
		{"embedded newline", strings.Replace(good, ", ts", "\n, ts", 1), false},
		{"fields reordered", "SFW1 ts=1791014400, key=" + testKeyID + ", nonce=" + vectorNonce + ", sig=" + vectorSig, false},
		{"a field twice", good + ", sig=" + vectorSig, false},
		{"two spaces", strings.Replace(good, ", ts", ",  ts", 1), false},
		{"tab", strings.Replace(good, ", ts", ",\tts", 1), false},
		{"very long", good + strings.Repeat("a", 10000), false},
		{"unicode digit", strings.Replace(good, "ts=1791014400", "ts=١٧٩١٠١٤٤٠٠", 1), false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			az, ok := ParseAuthorization(row.in)
			if ok != row.ok {
				t.Fatalf("ok = %v, want %v", ok, row.ok)
			}
			if ok && az.TS != 1791014400 {
				t.Fatalf("ts %d", az.TS)
			}
		})
	}
}

func TestSecretFromText(t *testing.T) {
	rows := []struct {
		name string
		in   string
		ok   bool
	}{
		{"the vector", vectorSecretText, true},
		{"with spaces from pasting", vectorSecretText[:20] + " " + vectorSecretText[20:] + "\n", true},
		{"empty", "", false},
		{"one short", vectorSecretText[:42], false},
		{"one long", vectorSecretText + "A", false},
		{"bits left over", vectorSecretText[:42] + "B", false},
		{"padding", vectorSecretText + "=", false},
		{"plus", strings.Replace(vectorSecretText, "Q", "+", 1), false},
		{"slash", strings.Replace(vectorSecretText, "Q", "/", 1), false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if _, err := SecretFromText(row.in); (err == nil) != row.ok {
				t.Fatalf("err = %v, want ok=%v", err, row.ok)
			}
		})
	}
}

func TestRefusals(t *testing.T) {
	good := "/feed?days=7"
	rows := []struct {
		name   string
		setup  func(r *rig)
		build  func(r *rig) *http.Request
		status int
		reason string // part of the error text the owner will read
	}{
		{name: "no header", build: func(r *rig) *http.Request {
			req := r.signed(good)
			req.Header.Del("Authorization")
			return req
		}, status: 401, reason: "malformed"},
		{name: "wrong scheme", build: func(r *rig) *http.Request {
			req := r.signed(good)
			req.Header.Set("Authorization", "Bearer "+strings.TrimPrefix(req.Header.Get("Authorization"), "SFW1 "))
			return req
		}, status: 401, reason: "malformed"},
		{name: "two headers", build: func(r *rig) *http.Request {
			req := r.signed(good)
			req.Header.Add("Authorization", req.Header.Get("Authorization"))
			return req
		}, status: 401, reason: "malformed"},
		{name: "unknown key", build: func(r *rig) *http.Request {
			return signedAt(good, vectorSecret(), "ffffffffffffffff", r.now.Unix(), freshNonce())
		}, status: 401, reason: "unknown key"},
		{name: "wrong secret", build: func(r *rig) *http.Request {
			s := vectorSecret()
			s[31] ^= 0xff
			return signedAt(good, s, testKeyID, r.now.Unix(), freshNonce())
		}, status: 401, reason: "signature"},
		{name: "revoked key", setup: func(r *rig) { r.keys.Revoke(testKeyID) }, build: func(r *rig) *http.Request { return r.signed(good) },
			status: 401, reason: "revoked"},
		{name: "300 seconds fast is allowed", build: func(r *rig) *http.Request {
			return signedAt(good, vectorSecret(), testKeyID, r.now.Unix()+300, freshNonce())
		}, status: 200},
		{name: "300 seconds slow is allowed", build: func(r *rig) *http.Request {
			return signedAt(good, vectorSecret(), testKeyID, r.now.Unix()-300, freshNonce())
		}, status: 200},
		{name: "301 seconds fast", build: func(r *rig) *http.Request {
			return signedAt(good, vectorSecret(), testKeyID, r.now.Unix()+301, freshNonce())
		}, status: 401, reason: "time"},
		{name: "301 seconds slow", build: func(r *rig) *http.Request {
			return signedAt(good, vectorSecret(), testKeyID, r.now.Unix()-301, freshNonce())
		}, status: 401, reason: "time"},
		{name: "target changed after signing", build: func(r *rig) *http.Request {
			req := r.signed(good)
			req.RequestURI = "/feed?days=8"
			return req
		}, status: 401, reason: "signature"},
		{name: "time changed after signing", build: func(r *rig) *http.Request {
			req := r.signed(good)
			req.Header.Set("Authorization", strings.Replace(req.Header.Get("Authorization"), "ts="+strconv.FormatInt(r.now.Unix(), 10), "ts="+strconv.FormatInt(r.now.Unix()+1, 10), 1))
			return req
		}, status: 401, reason: "signature"},
		{name: "nonce changed after signing", build: func(r *rig) *http.Request {
			req := r.signed(good)
			a := req.Header.Get("Authorization")
			i := strings.Index(a, "nonce=") + 6
			req.Header.Set("Authorization", a[:i]+"f"+a[i+1:])
			return req
		}, status: 401, reason: "signature"},
		{name: "POST", build: func(r *rig) *http.Request { req := r.signed(good); req.Method = "POST"; return req }, status: 405},
		{name: "HEAD", build: func(r *rig) *http.Request { req := r.signed(good); req.Method = "HEAD"; return req }, status: 405},
		{name: "PUT", build: func(r *rig) *http.Request { req := r.signed(good); req.Method = "PUT"; return req }, status: 405},
		{name: "DELETE", build: func(r *rig) *http.Request { req := r.signed(good); req.Method = "DELETE"; return req }, status: 405},
		{name: "wrong path", build: func(r *rig) *http.Request {
			req := r.signed("/other?days=7")
			return req
		}, status: 404},
		{name: "trailing slash", build: func(r *rig) *http.Request { return r.signed("/feed/?days=7") }, status: 404},
		{name: "double slash", build: func(r *rig) *http.Request { return r.signed("//feed?days=7") }, status: 404},
		{name: "upper-case path", build: func(r *rig) *http.Request { return r.signed("/FEED?days=7") }, status: 404},
		{name: "encoded path", build: func(r *rig) *http.Request { return r.signed("/%66eed?days=7") }, status: 404},
		{name: "absolute form target", build: func(r *rig) *http.Request { return r.signed("http://x/feed?days=7") }, status: 404},
		{name: "switched off", setup: func(r *rig) { r.h.cfg.Enabled = func(string) bool { return false } }, build: func(r *rig) *http.Request { return r.signed(good) }, status: 404},
		{name: "scope not allowed", setup: func(r *rig) {}, build: func(r *rig) *http.Request {
			return r.signed("/feed?scopes=events,bogus")
		}, status: 403},
		{name: "duplicate since", build: func(r *rig) *http.Request { return r.signed("/feed?since=a&since=b") }, status: 400},
		{name: "bad escape in query", build: func(r *rig) *http.Request { return r.signed("/feed?since=%zz") }, status: 400},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := newRig(t)
			if row.setup != nil {
				row.setup(r)
			}
			w := r.do(row.build(r))
			if w.Code != row.status {
				t.Fatalf("status %d, want %d: %s", w.Code, row.status, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("content type %q", ct)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("cache control %q", w.Header().Get("Cache-Control"))
			}
			if row.status != 200 {
				msg := errText(t, w)
				if msg == "" {
					t.Fatalf("no error text: %s", w.Body.String())
				}
				if row.reason != "" && !strings.Contains(msg, row.reason) {
					t.Fatalf("error %q does not say %q", msg, row.reason)
				}
			}
			if row.status == 405 && w.Header().Get("Allow") != "GET" {
				t.Fatalf("Allow = %q", w.Header().Get("Allow"))
			}
		})
	}
}

func TestNoTLSIsNotFoundByDefault(t *testing.T) {
	r := newRig(t, func(c *Config, _ *Key) { c.AllowInsecure = false })
	if w := r.do(r.signed("/feed")); w.Code != 404 {
		t.Fatalf("plain http: %d", w.Code)
	}
	req := r.signed("/feed")
	req.TLS = &tlsState
	if w := r.do(req); w.Code != 200 {
		t.Fatalf("with TLS: %d %s", w.Code, w.Body.String())
	}
}

func TestReplayIsRefusedWhateverTheTimeUntilTheNonceExpires(t *testing.T) {
	r := newRig(t)
	n := freshNonce()
	send := func(ts int64) int {
		return r.do(signedAt("/feed", vectorSecret(), testKeyID, ts, n)).Code
	}
	if c := send(r.now.Unix()); c != 200 {
		t.Fatalf("first: %d", c)
	}
	if c := send(r.now.Unix()); c != 401 {
		t.Fatalf("identical replay: %d", c)
	}
	// a fresh signature (another time) with the same nonce is still a repeat: the nonce is what is remembered
	if c := send(r.now.Unix() + 1); c != 401 {
		t.Fatalf("same nonce, new signature: %d", c)
	}
	r.setNow(r.now.Add(599 * time.Second))
	if c := send(r.now.Unix()); c != 401 {
		t.Fatalf("599 seconds later: %d", c)
	}
	r.setNow(r.now.Add(2 * time.Second))
	if c := send(r.now.Unix()); c != 200 {
		t.Fatalf("601 seconds later the nonce may be used again: %d", c)
	}
}

func TestSixtyAnHourThenRetryAfter(t *testing.T) {
	r := newRig(t)
	for i := 0; i < PerHour; i++ {
		if w := r.do(r.signed("/feed")); w.Code != 200 {
			t.Fatalf("request %d: %d", i+1, w.Code)
		}
		r.setNow(r.now.Add(time.Second))
	}
	w := r.do(r.signed("/feed"))
	if w.Code != 429 {
		t.Fatalf("61st: %d", w.Code)
	}
	retry, err := strconv.Atoi(w.Header().Get("Retry-After"))
	if err != nil || retry < 1 || retry > 3600 {
		t.Fatalf("Retry-After %q", w.Header().Get("Retry-After"))
	}
	// the first of the 60 was at T0; one hour after it a place frees up. now is T0+60, so the wait is 3540 seconds.
	if retry != 3540 {
		t.Fatalf("Retry-After = %d, want 3540", retry)
	}
	if !strings.Contains(errText(t, w), "60") {
		t.Fatalf("the error does not say the limit: %s", w.Body.String())
	}
	r.setNow(r.now.Add(time.Duration(retry) * time.Second))
	if w := r.do(r.signed("/feed")); w.Code != 200 {
		t.Fatalf("after the wait: %d %s", w.Code, w.Body.String())
	}
}

// Only a correctly signed request counts: wrong signatures neither use up the hour nor burn a nonce.
func TestOnlyCorrectlySignedRequestsCount(t *testing.T) {
	r := newRig(t)
	burnt := freshNonce()
	for i := 0; i < 300; i++ {
		req := signedAt("/feed", vectorSecret(), testKeyID, r.now.Unix(), freshNonce())
		a := req.Header.Get("Authorization")
		req.Header.Set("Authorization", a[:len(a)-1]+map[bool]string{true: "0", false: "1"}[a[len(a)-1] != '0'])
		if w := r.do(req); w.Code != 401 {
			t.Fatalf("bad signature %d: %d", i, w.Code)
		}
	}
	// a bad signature carrying a nonce must not make that nonce unusable for the real owner of the key
	bad := signedAt("/feed", vectorSecret(), testKeyID, r.now.Unix(), burnt)
	a := bad.Header.Get("Authorization")
	bad.Header.Set("Authorization", a[:len(a)-1]+map[bool]string{true: "0", false: "1"}[a[len(a)-1] != '0'])
	if w := r.do(bad); w.Code != 401 {
		t.Fatalf("bad: %d", w.Code)
	}
	if w := r.do(signedAt("/feed", vectorSecret(), testKeyID, r.now.Unix(), burnt)); w.Code != 200 {
		t.Fatalf("the nonce of a refused request was remembered: %d", w.Code)
	}
	for i := 1; i < PerHour; i++ {
		if w := r.do(r.signed("/feed")); w.Code != 200 {
			t.Fatalf("good request %d after the flood: %d", i, w.Code)
		}
	}
	if w := r.do(r.signed("/feed")); w.Code != 429 {
		t.Fatalf("limit: %d", w.Code)
	}
	// refused requests (401, 403) did not move the hour either: 60 were allowed, not 59
	r2 := newRig(t)
	for i := 0; i < 100; i++ {
		r2.do(r2.signed("/feed?scopes=bogus")) // 403: signed, so it counts
	}
	if w := r2.do(r2.signed("/feed")); w.Code != 429 {
		t.Fatalf("a correctly signed request that is refused for its scope still counts: %d", w.Code)
	}
}

func TestAKeyReadsOneSiteOnly(t *testing.T) {
	r := newRig(t, func(c *Config, k *Key) {})
	// the same store holds a key for another site; its secret is also the vector's, so only the site tells them apart
	k2 := Key{ID: "aaaaaaaaaaaaaaaa", SiteID: otherSite, Secret: vectorSecret(), Scopes: []string{"events"}, Addresses: "cut"}
	if err := r.keys.Add(k2); err != nil {
		t.Fatal(err)
	}
	w := r.do(signedAt("/feed", vectorSecret(), "aaaaaaaaaaaaaaaa", r.now.Unix(), freshNonce()))
	if w.Code != 401 || !strings.Contains(errText(t, w), "unknown key") {
		t.Fatalf("a key for another site: %d %s", w.Code, w.Body.String())
	}
	if len(r.src.calls) != 0 {
		t.Fatalf("the source was asked about a site on a refused request: %v", r.src.calls)
	}
}

func TestFrame(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 3; i++ {
		r.src.events = append(r.src.events, goodEvent(3-i))
	}
	w := r.do(r.signed("/feed?days=3"))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	m := decode(t, w)
	if m["feed"] != float64(1) {
		t.Fatalf("feed = %v", m["feed"])
	}
	if g, _ := m["generated"].(string); g != "2026-10-03T08:00:00Z" {
		t.Fatalf("generated = %q", g)
	}
	site := m["site"].(map[string]any)
	if site["id"] != testSite || site["name"] != "Alpha Plumbing" || site["policy_rev"] != float64(3) {
		t.Fatalf("site = %v", site)
	}
	scopes := m["scopes"].([]any)
	if len(scopes) != 5 || scopes[0] != "events" || scopes[4] != "marks" {
		t.Fatalf("scopes = %v", scopes)
	}
	if m["addresses"] != "cut" {
		t.Fatalf("addresses = %v", m["addresses"])
	}
	if _, ok := m["cursor"].(string); !ok {
		t.Fatalf("no cursor")
	}
	if more, ok := m["more"].(bool); !ok || more {
		t.Fatalf("more = %v", m["more"])
	}
	events := m["events"].([]any)
	if len(events) != 3 {
		t.Fatalf("events = %d", len(events))
	}
	// newest first
	first := events[0].(map[string]any)["t"].(string)
	last := events[2].(map[string]any)["t"].(string)
	if first <= last {
		t.Fatalf("not newest first: %s then %s", first, last)
	}
	for _, k := range []string{"traffic", "ips", "health", "marks"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("section %s missing", k)
		}
	}
	if _, ok := m["health"].(map[string]any)["errors"].([]any); !ok {
		t.Fatalf("health.errors is not a list: %s", w.Body.String())
	}
	// determinism: the same state gives the same bytes (the reader recognises repeats by their content)
	w2 := r.do(r.signed("/feed?days=3"))
	if w.Body.String() != w2.Body.String() {
		t.Fatalf("two answers differ")
	}
}

func TestOnlyTheScopesAskedForAreBuilt(t *testing.T) {
	rows := []struct {
		name  string
		query string
		want  []string
	}{
		{"all by default", "/feed", []string{"events", "traffic", "ips", "health", "marks"}},
		{"one", "/feed?scopes=health", []string{"health"}},
		{"two, in canonical order", "/feed?scopes=traffic,events", []string{"events", "traffic"}},
		{"spaces", "/feed?scopes=%20health%20,%20marks", []string{"health", "marks"}},
		{"empty means all", "/feed?scopes=", []string{"events", "traffic", "ips", "health", "marks"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := newRig(t)
			w := r.do(r.signed(row.query))
			if w.Code != 200 {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			m := decode(t, w)
			var got []string
			for _, s := range m["scopes"].([]any) {
				got = append(got, s.(string))
			}
			if strings.Join(got, ",") != strings.Join(row.want, ",") {
				t.Fatalf("scopes %v, want %v", got, row.want)
			}
			for _, s := range row.want {
				if _, ok := m[s]; !ok {
					t.Fatalf("section %s missing", s)
				}
			}
			for _, s := range []string{"events", "traffic", "ips", "health", "marks"} {
				_, asked := m[s]
				calls := r.src.calls[s]
				if asked != (calls == 1) {
					t.Fatalf("section %s present=%v but the source was called %d times", s, asked, calls)
				}
			}
			for _, w := range r.src.wrong {
				t.Fatalf("source was asked about %q", w)
			}
		})
	}
}

func TestCursorAndMoreAreAlwaysThere(t *testing.T) {
	rows := []struct {
		name   string
		scopes []string
		query  string
		cursor string
	}{
		{"no events scope, no since", []string{"traffic"}, "/feed", "0"},
		{"no events scope, since echoed", []string{"traffic"}, "/feed?since=abc", "abc"},
		{"no events scope, since not a cursor", []string{"health"}, "/feed?since=%20x", "0"},
		{"only marks", []string{"marks"}, "/feed", "0"},
		{"with events", []string{"events"}, "/feed", "p0"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := newRig(t, func(c *Config, k *Key) { k.Scopes = row.scopes })
			w := r.do(r.signed(row.query))
			if w.Code != 200 {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			m := decode(t, w)
			if m["cursor"] != row.cursor {
				t.Fatalf("cursor = %v, want %q", m["cursor"], row.cursor)
			}
			if more, ok := m["more"].(bool); !ok || more {
				t.Fatalf("more = %v", m["more"])
			}
			if _, has := m["events"]; has != contains(row.scopes, "events") {
				t.Fatalf("events present = %v", has)
			}
		})
	}
}

func TestPagingFollowsMoreWithoutLosingOrRepeating(t *testing.T) {
	r := newRig(t)
	r.src.maxPage = 3
	for i := 0; i < 8; i++ {
		e := goodEvent(0)
		e.Time = nowAt().Add(time.Duration(i-8) * time.Minute)
		e.ID = strings.ToUpper(strconv.FormatInt(int64(0xA00000000000+i), 16))
		r.src.events = append(r.src.events, e)
	}
	var ids []string
	since := ""
	for page := 0; page < 10; page++ {
		target := "/feed?scopes=events"
		if since != "" {
			target = "/feed?since=" + since + "&scopes=events"
		}
		w := r.do(r.signed(target))
		if w.Code != 200 {
			t.Fatalf("page %d: %d %s", page, w.Code, w.Body.String())
		}
		m := decode(t, w)
		evs := m["events"].([]any)
		// within a page: newest first
		for i := len(evs) - 1; i >= 0; i-- {
			ids = append(ids, evs[i].(map[string]any)["id"].(string))
		}
		since = m["cursor"].(string)
		if m["more"] == false {
			break
		}
		if len(evs) == 0 {
			t.Fatalf("more with no events")
		}
	}
	if len(ids) != 8 {
		t.Fatalf("got %d events, want 8: %v", len(ids), ids)
	}
	for i, id := range ids {
		if want := strings.ToUpper(strconv.FormatInt(int64(0xA00000000000+i), 16)); id != want {
			t.Fatalf("event %d is %s, want %s", i, id, want)
		}
	}
	if since != "p8" {
		t.Fatalf("final cursor %s", since)
	}
}

func TestAnAnswerNeverPassesTheReadersCap(t *testing.T) {
	t.Run("traffic answers over TLS respect the cap", func(t *testing.T) {
		r := newRig(t)
		tops := make([]TopEntry, maxTop)
		for i := range tops {
			tops[i] = TopEntry{Name: strings.Repeat("&", 300), N: 1}
		}
		for i := 0; i < MaxDays; i++ {
			r.src.traffic = append(r.src.traffic, TrafficDay{Day: nowAt().AddDate(0, 0, -i).Format("2006-01-02"), Requests: 1, TopPages: tops, Top404: tops, TopBlocked: tops})
		}
		e := goodEvent(0)
		e.Path, e.Why = strings.Repeat("&", 300), strings.Repeat("&", 300)
		e.Detail, e.Msg, e.What = strings.Repeat("&", 400), strings.Repeat("&", 400), strings.Repeat("&", 400)
		e.UA = strings.Repeat("&", 200)
		for i := 0; i < maxSigs; i++ {
			e.Sigs = append(e.Sigs, SigMatch{ID: strings.Repeat("&", 64), Action: strings.Repeat("&", 10), Target: strings.Repeat("&", 40), Name: strings.Repeat("&", 40)})
		}
		r.src.events = []Event{e}
		r.h.cfg.AllowInsecure = false
		srv := httptest.NewTLSServer(r.h)
		defer srv.Close()
		client := srv.Client()
		for _, scopes := range []string{"traffic", "events,traffic"} {
			for _, days := range []int{90, 23, 7} {
				r.src.traffic = r.src.traffic[:days]
				target := "/feed?scopes=" + scopes + "&days=" + strconv.Itoa(days)
				req, err := http.NewRequest(http.MethodGet, srv.URL+target, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header = r.signed(target).Header
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				b, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
				resp.Body.Close()
				want := http.StatusOK
				if days == 90 || (days == 23 && scopes == "events,traffic") {
					want = http.StatusInternalServerError
				}
				if err != nil || resp.StatusCode != want || len(b) > maxAnswer {
					t.Fatalf("scopes=%s days=%d: status=%d bytes=%d err=%v", scopes, days, resp.StatusCode, len(b), err)
				}
				t.Logf("scopes=%s days=%d: status=%d bytes=%d", scopes, days, resp.StatusCode, len(b))
				if want == http.StatusOK {
					var m map[string]any
					if err := json.Unmarshal(b, &m); err != nil {
						t.Fatal(err)
					}
					if n := len(m["traffic"].([]any)); n != days {
						t.Fatalf("traffic days=%d, want %d", n, days)
					}
					if scopes == "events,traffic" && len(m["events"].([]any)) != 1 {
						t.Fatal("the event was lost from a bounded answer")
					}
				}
				// Restore the full valid source for the next scope combination.
				r.src.traffic = r.src.traffic[:MaxDays]
			}
		}
	})
	r := newRig(t)
	r.src.cursorPrefix = strings.Repeat("&", 507)
	big := strings.Repeat("x", 300)
	sigs := make([]SigMatch, 50)
	for i := range sigs {
		sigs[i] = SigMatch{ID: strings.Repeat("S", 64), Action: strings.Repeat("a", 10), Target: strings.Repeat("t", 40), Name: strings.Repeat("n", 40)}
	}
	for i := 0; i < 1500; i++ {
		e := goodEvent(0)
		e.Time = nowAt().Add(time.Duration(i-1500) * time.Second)
		e.Path, e.Why, e.Detail, e.Msg, e.What = big, big, strings.Repeat("d", 400), strings.Repeat("m", 400), strings.Repeat("w", 400)
		e.UA = strings.Repeat("u", 200)
		e.Sigs = sigs
		r.src.events = append(r.src.events, e)
	}
	total := 0
	since := ""
	seen := 0
	for page := 0; page < 40; page++ {
		target := "/feed?scopes=events"
		if since != "" {
			target += "&since=" + url.QueryEscape(since)
		}
		w := r.do(r.signed(target))
		if w.Code != 200 {
			t.Fatalf("page %d: %d %s", page, w.Code, w.Body.String())
		}
		if w.Body.Len() > maxAnswer {
			t.Fatalf("page %d is %d bytes: the feed budget is 6 MiB", page, w.Body.Len())
		}
		m := decode(t, w)
		seen += len(m["events"].([]any))
		total++
		since = m["cursor"].(string)
		if m["more"] == false {
			break
		}
	}
	if seen != 1500 {
		t.Fatalf("saw %d events over %d pages, want 1500", seen, total)
	}
	if total < 2 {
		t.Fatalf("the answer was not split: %d page(s)", total)
	}
}

func TestSourceBreakingItsContractIsAnErrorNotAWrongAnswer(t *testing.T) {
	t.Run("more traffic days than requested", func(t *testing.T) {
		r := newRig(t)
		for i := 0; i < 8; i++ {
			r.src.traffic = append(r.src.traffic, TrafficDay{Day: nowAt().AddDate(0, 0, -i).Format("2006-01-02"), Requests: 1})
		}
		w := r.do(r.signed("/feed?scopes=traffic&days=7"))
		if w.Code != 500 {
			t.Fatalf("source returned more rows than requested: status=%d", w.Code)
		}
	})
	rows := []struct {
		name  string
		setup func(s *memSource)
	}{
		{"more events than asked", func(s *memSource) {
			for i := 0; i <= MaxEvents; i++ {
				s.events = append(s.events, goodEvent(0))
			}
			s.ignoreMax = true
		}},
		{"a cursor the reader would refuse", func(s *memSource) { s.events = []Event{goodEvent(0)}; s.badCursor = true }},
		{"no cursor after an entry that has to be split off", func(s *memSource) {
			big := strings.Repeat("x", 400)
			sg := make([]SigMatch, 50)
			for i := range sg {
				sg[i] = SigMatch{ID: strings.Repeat("S", 64), Action: "a", Target: "t", Name: "n"}
			}
			for i := 0; i < 1800; i++ {
				e := goodEvent(0)
				e.Why, e.Detail, e.Msg, e.What, e.Sigs = big, big, big, big, sg
				e.Path, e.UA = strings.Repeat("p", 300), strings.Repeat("u", 200)
				s.events = append(s.events, e)
			}
			s.noNext = true
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := newRig(t)
			row.setup(r.src)
			w := r.do(r.signed("/feed?scopes=events"))
			if w.Code != 500 {
				t.Fatalf("status %d (%d bytes)", w.Code, w.Body.Len())
			}
		})
	}
}

func TestSourceErrorsReachNobody(t *testing.T) {
	for _, call := range []string{"site", "events", "traffic", "ips", "health", "marks"} {
		t.Run(call, func(t *testing.T) {
			r := newRig(t)
			r.src.failOn = call
			w := r.do(r.signed("/feed"))
			if w.Code != 500 {
				t.Fatalf("status %d", w.Code)
			}
			if strings.Contains(w.Body.String(), "secret detail") {
				t.Fatalf("the source's error text reached the answer: %s", w.Body.String())
			}
			if errText(t, w) == "" {
				t.Fatalf("no error text")
			}
		})
	}
}

func TestPanicInASourceIsAnErrorNotACrash(t *testing.T) {
	r := newRig(t)
	r.h.cfg.Source = panicSource{r.src}
	w := r.do(r.signed("/feed"))
	if w.Code != 500 {
		t.Fatalf("status %d", w.Code)
	}
}

type panicSource struct{ *memSource }

func (panicSource) Traffic(_ context.Context, _ string, _ int) ([]TrafficDay, error) { panic("boom") }

func TestTheSiteIdIsTheHandlersOwn(t *testing.T) {
	r := newRig(t)
	r.src.info.Name = "x"
	w := r.do(r.signed("/feed"))
	m := decode(t, w)
	if m["site"].(map[string]any)["id"] != testSite {
		t.Fatalf("site id %v", m["site"])
	}
	if len(r.src.wrong) != 0 {
		t.Fatalf("source asked about %v", r.src.wrong)
	}
}

func TestTheObserverIsNotFlooded(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 500; i++ {
		req := r.signed("/feed")
		req.Header.Set("Authorization", "garbage")
		r.do(req)
		r.do(signedAt("/feed", vectorSecret(), "ffffffffffffffff", r.now.Unix(), freshNonce()))
	}
	if n := len(r.told); n != 1 {
		t.Fatalf("a flood of requests naming no known key was reported %d times, want 1", n)
	}
	// a known key: one report per reason, and no more than 20 in all
	for i := 0; i < 500; i++ {
		s := vectorSecret()
		s[0] = byte(i)
		r.do(signedAt("/feed", s, testKeyID, r.now.Unix(), freshNonce()))
	}
	if n := len(r.told); n != 2 {
		t.Fatalf("a flood of wrong signatures was reported %d times in all, want 2", n)
	}
	var kinds []string
	for _, f := range r.told {
		kinds = append(kinds, f.Reason)
		if strings.Contains(f.Reason, "secret") {
			t.Fatal("secret in a report")
		}
	}
	r.setNow(r.now.Add(11 * time.Minute))
	r.do(signedAt("/feed", []byte("00000000000000000000000000000000"), testKeyID, r.now.Unix(), freshNonce()))
	if n := len(r.told); n != 3 {
		t.Fatalf("after ten minutes the same refusal is reported again: %d reports (%v)", n, kinds)
	}
}

func TestConcurrentRequests(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 5; i++ {
		r.src.events = append(r.src.events, goodEvent(i))
	}
	var wg sync.WaitGroup
	codes := make([]int, 80)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = r.do(r.signed("/feed?days=5")).Code
		}()
	}
	wg.Wait()
	ok, limited := 0, 0
	for _, c := range codes {
		switch c {
		case 200:
			ok++
		case 429:
			limited++
		default:
			t.Fatalf("unexpected status %d", c)
		}
	}
	if ok != PerHour || limited != 20 {
		t.Fatalf("%d answered and %d limited, want %d and %d", ok, limited, PerHour, 20)
	}
}

func TestNewChecksItsConfiguration(t *testing.T) {
	keys, src := NewMemoryKeys(), newSource()
	rows := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"minimal", Config{SiteID: testSite, Keys: keys, Source: src}, true},
		{"nested path", Config{SiteID: testSite, Keys: keys, Source: src, Path: "/sites/alpha/feed"}, true},
		{"short site id", Config{SiteID: testSite[:31], Keys: keys, Source: src}, false},
		{"upper-case site id", Config{SiteID: strings.ToUpper(testSite), Keys: keys, Source: src}, false},
		{"no keys", Config{SiteID: testSite, Source: src}, false},
		{"no source", Config{SiteID: testSite, Keys: keys}, false},
		{"path not ending in feed", Config{SiteID: testSite, Keys: keys, Source: src, Path: "/events"}, false},
		{"path with a space", Config{SiteID: testSite, Keys: keys, Source: src, Path: "/a b/feed"}, false},
		{"path with a dot segment", Config{SiteID: testSite, Keys: keys, Source: src, Path: "/a/../feed"}, false},
		{"path with a double slash", Config{SiteID: testSite, Keys: keys, Source: src, Path: "/a//feed"}, false},
		{"path with a percent", Config{SiteID: testSite, Keys: keys, Source: src, Path: "/%61/feed"}, false},
		{"relative path", Config{SiteID: testSite, Keys: keys, Source: src, Path: "feed"}, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if _, err := New(row.cfg); (err == nil) != row.ok {
				t.Fatalf("err = %v, want ok = %v", err, row.ok)
			}
		})
	}
}

func TestMemoryKeysChecksKeys(t *testing.T) {
	good := Key{ID: testKeyID, SiteID: testSite, Secret: vectorSecret(), Scopes: []string{"events"}, Addresses: "cut"}
	rows := []struct {
		name   string
		change func(k *Key)
		ok     bool
	}{
		{"good", func(k *Key) {}, true},
		{"whole addresses", func(k *Key) { k.Addresses = "whole" }, true},
		{"short id", func(k *Key) { k.ID = k.ID[:15] }, false},
		{"upper-case id", func(k *Key) { k.ID = "ABCDEF0123456789" }, false},
		{"short site", func(k *Key) { k.SiteID = k.SiteID[:31] }, false},
		{"short secret", func(k *Key) { k.Secret = k.Secret[:31] }, false},
		{"empty addresses", func(k *Key) { k.Addresses = "" }, false},
		{"unknown addresses", func(k *Key) { k.Addresses = "half" }, false},
		{"no scopes", func(k *Key) { k.Scopes = nil }, false},
		{"unknown scope", func(k *Key) { k.Scopes = []string{"events", "admin"} }, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			k := good
			row.change(&k)
			if err := NewMemoryKeys().Add(k); (err == nil) != row.ok {
				t.Fatalf("err = %v, want ok = %v", err, row.ok)
			}
		})
	}
	t.Run("duplicate", func(t *testing.T) {
		m := NewMemoryKeys()
		if err := m.Add(good); err != nil {
			t.Fatal(err)
		}
		if err := m.Add(good); err == nil {
			t.Fatal("a second key with the same id was accepted")
		}
	})
	t.Run("lookup returns a copy", func(t *testing.T) {
		m := NewMemoryKeys()
		_ = m.Add(good)
		k, _ := m.Lookup(testKeyID)
		k.Secret[0] ^= 0xff
		k.Scopes[0] = "marks"
		again, _ := m.Lookup(testKeyID)
		if again.Secret[0] != vectorSecret()[0] || again.Scopes[0] != "events" {
			t.Fatal("a caller changed the stored key")
		}
	})
	t.Run("generate", func(t *testing.T) {
		k, text, err := GenerateKey(testSite, []string{"events", "health"}, "cut")
		if err != nil {
			t.Fatal(err)
		}
		back, err := SecretFromText(text)
		if err != nil || string(back) != string(k.Secret) || !isLowerHex(k.ID, 16) {
			t.Fatalf("generated key is wrong: %v", err)
		}
		if _, _, err := GenerateKey("short", []string{"events"}, "cut"); err == nil {
			t.Fatal("a key for a malformed site id was generated")
		}
	})
}

func TestDaysAreDefaultedAndClamped(t *testing.T) {
	rows := []struct {
		query string
		want  int
	}{
		{"", 7}, {"?days=1", 1}, {"?days=7", 7}, {"?days=30", 30}, {"?days=90", 90}, {"?days=91", 90}, {"?days=500", 90}, {"?days=0", 1},
		{"?days=007", 7}, {"?days=abc", 7}, {"?days=-5", 7}, {"?days=", 7}, {"?days=1.5", 7}, {"?days=99999999999999999999", 90},
	}
	for _, row := range rows {
		t.Run(row.query, func(t *testing.T) {
			r := newRig(t)
			r.src.traffic = []TrafficDay{{Day: "2026-10-02", Requests: 1}}
			w := r.do(r.signed("/feed" + row.query))
			if w.Code != 200 {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if r.src.lastDays != row.want {
				t.Fatalf("the source was asked for %d days, want %d", r.src.lastDays, row.want)
			}
		})
	}
}
