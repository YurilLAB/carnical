// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The test vector shared with the PHP console and the Python reader (newsletter/tests/test_waf_fleet.py).
const (
	vectorSecretText = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	vectorTarget     = "/feed?since=abc&days=7"
	vectorTS         = int64(1791014400)
	vectorNonce      = "0123456789abcdef0123456789abcdef"
	vectorSig        = "987bb305649ec1e529c083e5e197dc2dce0a01d8ed8e4a10f0650381391feac0"
	vectorSigned     = "SFW1\nGET\n/feed?since=abc&days=7\n1791014400\n0123456789abcdef0123456789abcdef"

	testSite  = "5f0c1e9a7b3d24c68e1f0a9b7c5d3e21"
	otherSite = "c2d8e4f60a1b3c5d7e9f0a2b4c6d8e01"
	testKeyID = "0123456789abcdef"
)

func vectorSecret() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

// nowAt is the moment the tests run at: the vector's own time, so the vector's request is in time.
func nowAt() time.Time { return time.Unix(vectorTS, 0).UTC() }

// memSource is an EventSource over slices. It checks that it is only ever asked about the site the handler serves, and
// it counts its calls so a test can see which sections a request really asked for.
type memSource struct {
	mu       sync.Mutex
	wantSite string
	info     SiteInfo
	events   []Event
	traffic  []TrafficDay
	ips      IPs
	health   Health
	marks    []Mark
	calls    map[string]int
	wrong    []string
	failOn   string
	// maxPage limits how many events one call returns (0 = as many as asked)
	maxPage int
	// lastDays is the number of days the last Traffic call asked for
	lastDays int
	// badCursor makes the source return a cursor the reader would refuse
	badCursor bool
	// noNext leaves Entry.Next empty
	noNext bool
	// ignoreMax returns every event whatever limit was asked for
	ignoreMax bool
	// cursorPrefix exercises opaque cursors that expand during JSON encoding.
	cursorPrefix string
}

var tlsState = tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}

func newSource() *memSource {
	return &memSource{wantSite: testSite, calls: map[string]int{}, info: SiteInfo{Name: "Alpha Plumbing", Host: "alpha.example", Engine: "carnical-1", Bundle: "crs-4.30.0", Mode: "block", PolicyRev: 3, Timezone: "Australia/Brisbane"}}
}

func (m *memSource) note(call, site string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls[call]++
	if site != m.wantSite {
		m.wrong = append(m.wrong, site)
	}
	if m.failOn == call {
		return errors.New("secret detail that must never reach a visitor")
	}
	return nil
}

func (m *memSource) Site(ctx context.Context, site string) (SiteInfo, error) {
	return m.info, m.note("site", site)
}

func (m *memSource) Events(ctx context.Context, site, since string, max int) (EventPage, error) {
	if err := m.note("events", site); err != nil {
		return EventPage{}, err
	}
	start := 0
	position := strings.TrimPrefix(since, m.cursorPrefix)
	if strings.HasPrefix(position, "p") {
		if n, err := strconv.Atoi(position[1:]); err == nil && n >= 0 && n <= len(m.events) {
			start = n
		}
	}
	limit := max
	if m.maxPage > 0 && m.maxPage < limit {
		limit = m.maxPage
	}
	if m.ignoreMax {
		limit = len(m.events)
	}
	end := start + limit
	if end > len(m.events) {
		end = len(m.events)
	}
	page := EventPage{Cursor: m.cursorPrefix + "p" + strconv.Itoa(end), More: end < len(m.events)}
	for i := start; i < end; i++ {
		e := Entry{Event: m.events[i], Next: m.cursorPrefix + "p" + strconv.Itoa(i+1)}
		if m.noNext {
			e.Next = ""
		}
		page.Entries = append(page.Entries, e)
	}
	if m.badCursor {
		page.Cursor = "has a space"
	}
	return page, nil
}

func (m *memSource) Traffic(ctx context.Context, site string, days int) ([]TrafficDay, error) {
	m.mu.Lock()
	m.lastDays = days
	m.mu.Unlock()
	return m.traffic, m.note("traffic", site)
}

func (m *memSource) IPs(ctx context.Context, site string) (IPs, error) {
	return m.ips, m.note("ips", site)
}

func (m *memSource) Health(ctx context.Context, site string) (Health, error) {
	return m.health, m.note("health", site)
}

func (m *memSource) Marks(ctx context.Context, site string) ([]Mark, error) {
	return m.marks, m.note("marks", site)
}

func goodEvent(i int) Event {
	score := 12
	thr := 5
	return Event{Time: nowAt().Add(-time.Duration(i) * time.Second), Kind: "block", Sev: "high", Channel: "fw", IP: "198.51.100.77", Method: "POST",
		Path: "/wp-login.php", Score: &score, Threshold: &thr, ID: "ABCDEF012345",
		Sigs: []SigMatch{{ID: "CRS-942100", Score: &score, Action: "block", Target: "args", Name: "q"}}}
}

type rig struct {
	t    *testing.T
	h    *Handler
	src  *memSource
	keys *MemoryKeys
	now  time.Time
	mu   sync.Mutex
	told []Refusal
}

// newRig makes a handler for testSite with one key (the vector's) that may read everything and has cut addresses.
func newRig(t *testing.T, mutate ...func(*Config, *Key)) *rig {
	t.Helper()
	r := &rig{t: t, src: newSource(), keys: NewMemoryKeys(), now: nowAt()}
	key := Key{ID: testKeyID, SiteID: testSite, Secret: vectorSecret(), Scopes: []string{"events", "traffic", "ips", "health", "marks"}, Addresses: "cut"}
	cfg := Config{SiteID: testSite, Keys: r.keys, Source: r.src, AllowInsecure: true,
		Now:       func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now },
		OnRefusal: func(f Refusal) { r.mu.Lock(); r.told = append(r.told, f); r.mu.Unlock() }}
	for _, m := range mutate {
		m(&cfg, &key)
	}
	if err := r.keys.Add(key); err != nil {
		t.Fatal(err)
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.h = h
	return r
}

func (r *rig) setNow(t time.Time) { r.mu.Lock(); r.now = t; r.mu.Unlock() }

var nonceSeq struct {
	sync.Mutex
	n int
}

func freshNonce() string {
	nonceSeq.Lock()
	defer nonceSeq.Unlock()
	nonceSeq.n++
	s := strconv.FormatInt(int64(nonceSeq.n), 16)
	return strings.Repeat("0", 32-len(s)) + s
}

// signed returns a request signed by the vector's secret at the rig's clock, for target.
func (r *rig) signed(target string) *http.Request {
	r.mu.Lock()
	ts := r.now.Unix()
	r.mu.Unlock()
	return signedAt(target, vectorSecret(), testKeyID, ts, freshNonce())
}

// signedAt builds a request whose header is computed here, not by the package under test, so the test would notice if
// Authorization and the handler agreed with each other and not with the contract.
func signedAt(target string, secret []byte, keyID string, ts int64, nonce string) *http.Request {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("SFW1\nGET\n" + target + "\n" + strconv.FormatInt(ts, 10) + "\n" + nonce))
	hdr := "SFW1 key=" + keyID + ", ts=" + strconv.FormatInt(ts, 10) + ", nonce=" + nonce + ", sig=" + hex.EncodeToString(m.Sum(nil))
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RequestURI = target
	req.Header.Set("Authorization", hdr)
	return req
}

func (r *rig) do(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}
