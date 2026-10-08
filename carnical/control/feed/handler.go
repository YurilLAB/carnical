// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The rules of the feed, from PortalFeed.php.
const (
	// Skew is how far a request's time may be from the server's clock.
	Skew = 300 * time.Second
	// NonceTTL is how long a nonce is remembered. A request that repeats one is refused.
	NonceTTL = 600 * time.Second
	// PerHour is the most correctly signed requests one key may make in an hour.
	PerHour = 60

	// maxAnswer is the most bytes the handler lets an answer reach. The reader gives up past 8 MiB; this leaves room.
	maxAnswer = 6 << 20
	// maxTold is the most refusals reported to the observer in ten minutes, so a flood of bad requests cannot flood
	// whoever reads the report.
	maxTold  = 20
	toldSpan = 600 * time.Second
)

// EventSource is where the feed's data comes from. The owner connects it to the real stores. Every call is made with
// the one site the handler was made for, never a site read from the request, and the implementation must answer only
// from that site's data (docs/segmentation.md, rule T2). Implementations must be safe for concurrent use and must
// honour the context.
type EventSource interface {
	// Site describes the site. Its id is not part of this: the handler sends its own.
	Site(ctx context.Context, site string) (SiteInfo, error)
	// Events returns the events after the cursor, oldest first, at most max, each with the cursor that stands after
	// it. An empty or unrecognised cursor means "start from the last seven days". The cursors are opaque to the
	// handler; they must be 1 to 512 printable ASCII characters without spaces, because that is all the reader keeps.
	Events(ctx context.Context, site, since string, max int) (EventPage, error)
	// Traffic returns one row per day for up to the last `days` days, newest day last.
	Traffic(ctx context.Context, site string, days int) ([]TrafficDay, error)
	// IPs returns the current bans and the addresses with the most points.
	IPs(ctx context.Context, site string) (IPs, error)
	// Health returns the health block. Every entry in Errors becomes a red alert on the owner's Desk.
	Health(ctx context.Context, site string) (Health, error)
	// Marks returns the firm's marks on events.
	Marks(ctx context.Context, site string) ([]Mark, error)
}

// Refusal is what the observer is told about a refused request. It holds no request content and no secret.
type Refusal struct {
	Status int
	KeyID  string // empty when the request named no key this handler knows
	Reason string
}

// Config makes a Handler.
type Config struct {
	// SiteID is the one site this handler answers for: 32 lower-case hex digits. It becomes the id in every answer.
	SiteID string
	// Path is the exact path served, ending in /feed and using only A-Za-z0-9._~/- (the reader insists). Default /feed.
	Path string
	// Keys finds sharing keys. A key for another site is treated as an unknown key.
	Keys KeyStore
	// Source provides the data.
	Source EventSource
	// Enabled, when set, says whether the site's feed is switched on. Off answers 404 to everything.
	Enabled func(site string) bool
	// Now is the clock; default time.Now.
	Now func() time.Time
	// AllowInsecure serves requests that did not arrive over TLS. The feed is only ever read over https, so the default
	// is to answer 404 to anything else; this is for tests behind a recorder.
	AllowInsecure bool
	// OnRefusal, when set, is told about refusals, at most 20 in ten minutes and at most one for each key and reason,
	// and at most one in ten minutes for requests that named no known key. It must be quick and must not block.
	OnRefusal func(Refusal)
	// Timeout bounds the calls to the Source for one request; default 15 seconds.
	Timeout time.Duration
}

// Handler answers feed requests for one site.
type Handler struct {
	cfg    Config
	siteID string
	path   string
	now    func() time.Time

	mu    sync.Mutex
	state map[string]*keyState
	told  map[string]time.Time
	// unknownAt is when a request that named no known key was last reported.
	unknownAt time.Time
	sweptAt   time.Time
}

// keyState is what is remembered about one key: the nonces of the last ten minutes and the times of the last hour's
// requests. Only a correctly signed request adds to either.
type keyState struct {
	nonces map[string]time.Time
	hits   []time.Time
}

var pathRE = regexp.MustCompile(`\A[A-Za-z0-9._~/-]+\z`)

// New checks the configuration and returns a Handler.
func New(cfg Config) (*Handler, error) {
	if !isLowerHex(cfg.SiteID, 32) {
		return nil, errors.New("feed: SiteID must be 32 lower-case hex digits")
	}
	if cfg.Keys == nil || cfg.Source == nil {
		return nil, errors.New("feed: Keys and Source are required")
	}
	p := cfg.Path
	if p == "" {
		p = "/feed"
	}
	if !validFeedPath(p) {
		return nil, errors.New("feed: Path must start with /, end in /feed and use only letters, digits and . _ ~ / -")
	}
	h := &Handler{cfg: cfg, siteID: cfg.SiteID, path: p, now: cfg.Now, state: map[string]*keyState{}, told: map[string]time.Time{}}
	if h.now == nil {
		h.now = time.Now
	}
	if h.cfg.Timeout <= 0 {
		h.cfg.Timeout = 15 * time.Second
	}
	return h, nil
}

// Path is the exact path the handler serves; mount it there.
func (h *Handler) Path() string { return h.path }

// SiteID is the site the handler answers for.
func (h *Handler) SiteID() string { return h.siteID }

func validFeedPath(p string) bool {
	if !strings.HasPrefix(p, "/") || !strings.HasSuffix(p, "/feed") || strings.Contains(p, "//") || !pathRE.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	defer func() {
		if rec := recover(); rec != nil {
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			h.reply(w, http.StatusInternalServerError, "the feed could not be built right now", nil)
		}
	}()

	target := r.RequestURI
	path, rawQuery, _ := strings.Cut(target, "?")
	if path != h.path || (r.TLS == nil && !h.cfg.AllowInsecure) {
		h.reply(w, http.StatusNotFound, "nothing here", nil)
		return
	}
	if h.cfg.Enabled != nil && !h.cfg.Enabled(h.siteID) {
		h.reply(w, http.StatusNotFound, "nothing here", nil)
		return
	}
	if r.Method != http.MethodGet {
		h.reply(w, http.StatusMethodNotAllowed, "the feed answers GET requests only", http.Header{"Allow": {"GET"}})
		return
	}
	now := h.now()

	vals := r.Header.Values("Authorization")
	if len(vals) != 1 {
		h.refuse(w, now, http.StatusUnauthorized, "malformed", "", "missing or malformed Authorization header: expected SFW1 key=<16 hex>, ts=<unix seconds>, nonce=<32 hex>, sig=<64 hex>", nil)
		return
	}
	az, ok := ParseAuthorization(vals[0])
	if !ok {
		h.refuse(w, now, http.StatusUnauthorized, "malformed", "", "missing or malformed Authorization header: expected SFW1 key=<16 hex>, ts=<unix seconds>, nonce=<32 hex>, sig=<64 hex>", nil)
		return
	}
	key, found := h.cfg.Keys.Lookup(az.KeyID)
	if !found || key.SiteID != h.siteID {
		h.refuse(w, now, http.StatusUnauthorized, "unknown_key", "", "unknown key", nil)
		return
	}
	if key.Revoked {
		h.refuse(w, now, http.StatusUnauthorized, "revoked", key.ID, "this key was revoked", nil)
		return
	}
	if d := now.Unix() - az.TS; d > int64(Skew/time.Second) || -d > int64(Skew/time.Second) {
		h.refuse(w, now, http.StatusUnauthorized, "skew", key.ID, "the time (ts) is more than five minutes from the server's clock", nil)
		return
	}
	if len(key.Secret) != 32 {
		h.refuse(w, now, http.StatusUnauthorized, "damaged", key.ID, "this key cannot be used: its secret is damaged", nil)
		return
	}
	// The signature covers the target exactly as sent, so it is checked against r.RequestURI and nothing re-encoded.
	if !hmac.Equal([]byte(sign(key.Secret, target, az.TSText, az.Nonce)), []byte(az.Sig)) {
		h.refuse(w, now, http.StatusUnauthorized, "signature", key.ID, "the signature is wrong", nil)
		return
	}
	// A correctly signed request: its nonce and its place in the hour's count are remembered together, so nobody
	// without the secret can fill the memory or use up a key's hour.
	switch verdict, retry := h.admit(key.ID, az.Nonce, now); verdict {
	case admitNonce:
		h.refuse(w, now, http.StatusUnauthorized, "nonce", key.ID, "this nonce was used in the last ten minutes", nil)
		return
	case admitRate:
		h.refuse(w, now, http.StatusTooManyRequests, "rate", key.ID, "more than "+strconv.Itoa(PerHour)+" requests in an hour with this key",
			http.Header{"Retry-After": {strconv.Itoa(retry)}})
		return
	}

	q, err := url.ParseQuery(rawQuery)
	if err != nil || len(q["since"]) > 1 || len(q["days"]) > 1 || len(q["scopes"]) > 1 {
		h.refuse(w, now, http.StatusBadRequest, "bad_query", key.ID, "the query is not one the feed understands", nil)
		return
	}
	allowed := intersect(scopeOrder, key.Scopes)
	var asked []string
	if s := strings.TrimSpace(q.Get("scopes")); s != "" {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				asked = append(asked, p)
			}
		}
	}
	for _, s := range asked {
		if !contains(allowed, s) {
			h.refuse(w, now, http.StatusForbidden, "scope", key.ID, "this key may not read one of the things asked for", nil)
			return
		}
	}
	scopes := allowed
	if len(asked) > 0 {
		scopes = intersect(scopeOrder, asked)
	}
	days := 7
	if d := q.Get("days"); isDigits(d) {
		days = clampDays(d)
	}
	since := q.Get("since")
	if !validCursor(since) {
		since = ""
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.Timeout)
	defer cancel()
	body, err := h.build(ctx, key, scopes, days, since, now)
	if err != nil {
		h.reply(w, http.StatusInternalServerError, "the feed could not be built right now", nil)
		return
	}
	hd.Set("Content-Type", "application/json")
	hd.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

type admitVerdict int

const (
	admitOK admitVerdict = iota
	admitNonce
	admitRate
)

// admit records a correctly signed request, or refuses it for a repeated nonce or for the hour's count.
func (h *Handler) admit(id, nonce string, now time.Time) (admitVerdict, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweep(now)
	st := h.state[id]
	if st == nil {
		st = &keyState{nonces: map[string]time.Time{}}
	}
	for n, t := range st.nonces {
		if !t.After(now.Add(-NonceTTL)) {
			delete(st.nonces, n)
		}
	}
	hits := st.hits[:0]
	for _, t := range st.hits {
		if t.After(now.Add(-time.Hour)) {
			hits = append(hits, t)
		}
	}
	st.hits = hits
	h.state[id] = st
	if _, seen := st.nonces[nonce]; seen {
		return admitNonce, 0
	}
	if len(st.hits) >= PerHour {
		oldest := st.hits[0]
		for _, t := range st.hits {
			if t.Before(oldest) {
				oldest = t
			}
		}
		retry := int(oldest.Add(time.Hour).Sub(now) / time.Second)
		if retry < 1 {
			retry = 1
		}
		return admitRate, retry
	}
	st.nonces[nonce] = now
	st.hits = append(st.hits, now)
	return admitOK, 0
}

// sweep drops the state of keys with nothing left to remember, at most once a minute.
func (h *Handler) sweep(now time.Time) {
	if now.Sub(h.sweptAt) < time.Minute {
		return
	}
	h.sweptAt = now
	for id, st := range h.state {
		live := false
		for _, t := range st.hits {
			if t.After(now.Add(-time.Hour)) {
				live = true
				break
			}
		}
		if !live {
			delete(h.state, id)
		}
	}
}

// reply writes a JSON error as {"error": "..."}, the form the reader looks for.
func (h *Handler) reply(w http.ResponseWriter, status int, msg string, extra http.Header) {
	for k, v := range extra {
		w.Header()[k] = v
	}
	b, _ := json.Marshal(map[string]string{"error": msg})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// refuse writes a refusal and tells the observer, within the limits that keep the observer from being flooded.
func (h *Handler) refuse(w http.ResponseWriter, now time.Time, status int, reason, keyID, msg string, extra http.Header) {
	h.reply(w, status, msg, extra)
	if h.cfg.OnRefusal == nil || !h.shouldTell(now, status, reason, keyID) {
		return
	}
	h.cfg.OnRefusal(Refusal{Status: status, KeyID: keyID, Reason: reason})
}

func (h *Handler) shouldTell(now time.Time, status int, reason, keyID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if keyID == "" {
		// Anyone can send these, so they are reported once in ten minutes and take no per-key state.
		if now.Sub(h.unknownAt) < toldSpan {
			return false
		}
		h.unknownAt = now
		return true
	}
	for k, t := range h.told {
		if !t.After(now.Add(-toldSpan)) {
			delete(h.told, k)
		}
	}
	k := keyID + "|" + strconv.Itoa(status) + "|" + reason
	if _, said := h.told[k]; said || len(h.told) >= maxTold {
		return false
	}
	h.told[k] = now
	return true
}

// frame is the answer. The sections are held as `any` so a section that is on but empty is sent as [] and one that
// is off is left out, which a slice with omitempty cannot tell apart.
type frame struct {
	Feed      int      `json:"feed"`
	Generated string   `json:"generated"`
	Site      wireSite `json:"site"`
	Scopes    []string `json:"scopes"`
	Addresses string   `json:"addresses"`
	Events    any      `json:"events,omitempty"`
	Cursor    string   `json:"cursor"`
	More      bool     `json:"more"`
	Traffic   any      `json:"traffic,omitempty"`
	IPs       any      `json:"ips,omitempty"`
	Health    any      `json:"health,omitempty"`
	Marks     any      `json:"marks,omitempty"`
}

var errSource = errors.New("feed: the source broke its contract")

// build collects the sections the key asked for and encodes the answer.
func (h *Handler) build(ctx context.Context, key Key, scopes []string, days int, since string, now time.Time) ([]byte, error) {
	cut := key.Addresses != "whole"
	gen, ok := formatTime(now)
	if !ok {
		return nil, errSource
	}
	info, err := h.cfg.Source.Site(ctx, h.siteID)
	if err != nil {
		return nil, err
	}
	addresses := "cut"
	if !cut {
		addresses = "whole"
	}
	f := frame{Feed: 1, Generated: gen, Addresses: addresses, Scopes: append([]string{}, scopes...),
		Site: wireSite{ID: h.siteID, Name: clip(info.Name, 120), Host: clip(info.Host, 255), Engine: clip(info.Engine, 40),
			Bundle: clip(info.Bundle, 40), Mode: clip(info.Mode, 20), PolicyRev: clampCount(info.PolicyRev), Timezone: clip(info.Timezone, 64)}}
	dropped := 0

	// Events are read and checked first, but sent last, because how many fit depends on the size of the rest.
	var page EventPage
	var raws []json.RawMessage
	var valid []bool
	if contains(scopes, ScopeEvents) {
		page, err = h.cfg.Source.Events(ctx, h.siteID, since, MaxEvents)
		if err != nil {
			return nil, err
		}
		if len(page.Entries) > MaxEvents || !validCursor(page.Cursor) {
			return nil, errSource
		}
		raws = make([]json.RawMessage, len(page.Entries))
		valid = make([]bool, len(page.Entries))
		for i, e := range page.Entries {
			b, ok := MarshalEvent(e.Event, cut)
			if !ok {
				dropped++
				continue
			}
			raws[i], valid[i] = b, true
		}
	}
	if contains(scopes, ScopeTraffic) {
		rows, err := h.cfg.Source.Traffic(ctx, h.siteID, days)
		if err != nil {
			return nil, err
		}
		if len(rows) > days {
			return nil, errSource
		}
		out := make([]wireTraffic, 0, len(rows))
		for _, d := range rows {
			w, ok := toWireTraffic(d)
			if !ok {
				dropped++
				continue
			}
			out = append(out, w)
		}
		f.Traffic = out
	}
	if contains(scopes, ScopeIPs) {
		in, err := h.cfg.Source.IPs(ctx, h.siteID)
		if err != nil {
			return nil, err
		}
		w, d := toWireIPs(in, cut)
		dropped += d
		f.IPs = w
	}
	if contains(scopes, ScopeMarks) {
		in, err := h.cfg.Source.Marks(ctx, h.siteID)
		if err != nil {
			return nil, err
		}
		out := make([]wireMark, 0, len(in))
		for _, m := range in {
			if len(out) >= maxMarks {
				break
			}
			w, ok := toWireMark(m, cut)
			if !ok {
				dropped++
				continue
			}
			out = append(out, w)
		}
		f.Marks = out
	}
	if contains(scopes, ScopeHealth) {
		in, err := h.cfg.Source.Health(ctx, h.siteID)
		if err != nil {
			return nil, err
		}
		var notes []string
		if dropped > 0 {
			notes = []string{fmt.Sprintf("%d entries were left out of this answer because they were not in the form feed version 1 allows", dropped)}
		}
		f.Health = toWireHealth(in, notes)
	}

	// The cursor and "more" are always sent, even by a key that cannot read events: the reader refuses an answer
	// without them. Such a key has no events to place a cursor on, so it is given back what it sent (when that is a
	// cursor the reader would keep) so that its stored place does not change, or a fixed one.
	if !contains(scopes, ScopeEvents) {
		f.Cursor = "0"
		if validCursor(since) {
			f.Cursor = since
		}
		return marshalAnswer(f)
	}

	f.Events = []json.RawMessage{}
	base, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	// Any accepted cursor can grow to six bytes per ASCII character when JSON
	// escapes it. Reserve room for either the page cursor or an entry cursor.
	used := len(base) + 6*512
	if used > maxAnswer {
		return nil, errSource
	}
	chosen := make([]json.RawMessage, 0, len(raws))
	consumed := 0
	for i := range raws {
		if !valid[i] {
			consumed = i + 1
			continue
		}
		if used+len(raws[i])+1 > maxAnswer {
			if consumed == 0 {
				return nil, errSource
			}
			break
		}
		used += len(raws[i]) + 1
		chosen = append(chosen, raws[i])
		consumed = i + 1
	}
	if consumed == len(raws) {
		f.Cursor, f.More = page.Cursor, page.More
	} else {
		next := page.Entries[consumed-1].Next
		if !validCursor(next) {
			return nil, errSource
		}
		f.Cursor, f.More = next, true
	}
	// newest first
	for i, j := 0, len(chosen)-1; i < j; i, j = i+1, j-1 {
		chosen[i], chosen[j] = chosen[j], chosen[i]
	}
	f.Events = chosen
	return marshalAnswer(f)
}

// marshalAnswer also bounds answers without events and checks the final JSON
// size after escaping, before any part of the response is written.
func marshalAnswer(f frame) ([]byte, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	if len(b) > maxAnswer {
		return nil, errSource
	}
	return b, nil
}

// validCursor is the reader's rule for a cursor: 1 to 512 printable ASCII characters, no spaces.
func validCursor(s string) bool {
	if len(s) == 0 || len(s) > 512 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func clampDays(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n > MaxDays {
		return MaxDays
	}
	if n < 1 {
		return 1
	}
	return n
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// intersect returns the members of order that appear in set, in the order of order and without repeats.
func intersect(order, set []string) []string {
	out := []string{}
	for _, o := range order {
		if contains(set, o) {
			out = append(out, o)
		}
	}
	return out
}
