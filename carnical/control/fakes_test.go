// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/YurilLAB/coraza/carnical/control/feed"
)

// The in-memory fakes the tests connect to the server. Each records how often it was called, so a test can show that a
// refused request never reached a store.

type memPolicyStore struct {
	mu      sync.Mutex
	docs    map[string][]Document // tenant -> revisions 1..n (index i is revision i+1)
	meta    map[string][]PutMeta
	touched map[string]int // calls per tenant, of every kind
	fail    error
}

func newMemPolicyStore() *memPolicyStore {
	return &memPolicyStore{docs: map[string][]Document{}, meta: map[string][]PutMeta{}, touched: map[string]int{}}
}

func (m *memPolicyStore) touch(tenant string) { m.touched[tenant]++ }

func (m *memPolicyStore) Get(ctx context.Context, tenant string) (Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touch(tenant)
	if m.fail != nil {
		return Document{}, m.fail
	}
	d := m.docs[tenant]
	if len(d) == 0 {
		return Document{}, ErrNotFound
	}
	return d[len(d)-1], nil
}

func (m *memPolicyStore) Put(ctx context.Context, tenant string, body []byte, expect uint64, meta PutMeta) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touch(tenant)
	if m.fail != nil {
		return 0, m.fail
	}
	if uint64(len(m.docs[tenant])) != expect {
		return 0, ErrConflict
	}
	rev := expect + 1
	m.docs[tenant] = append(m.docs[tenant], Document{Revision: rev, Body: append([]byte(nil), body...), Updated: time.Unix(1_800_000_000+int64(rev), 0)})
	m.meta[tenant] = append(m.meta[tenant], meta)
	return rev, nil
}

func (m *memPolicyStore) Revision(ctx context.Context, tenant string, revision uint64) (Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touch(tenant)
	if m.fail != nil {
		return Document{}, m.fail
	}
	d := m.docs[tenant]
	if revision < 1 || revision > uint64(len(d)) {
		return Document{}, ErrNotFound
	}
	return d[revision-1], nil
}

func (m *memPolicyStore) History(ctx context.Context, tenant string, before uint64, limit int) ([]HistoryEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touch(tenant)
	if m.fail != nil {
		return nil, m.fail
	}
	var out []HistoryEntry
	n := uint64(len(m.docs[tenant]))
	if before == 0 || before > n+1 {
		before = n + 1
	}
	for rev := before - 1; rev >= 1 && len(out) < limit; rev-- {
		md := m.meta[tenant][rev-1]
		out = append(out, HistoryEntry{Revision: rev, At: m.docs[tenant][rev-1].Updated, Actor: md.Actor, Credential: md.Credential, Kind: md.Kind,
			RolledBackTo: md.RolledBackTo, Weakening: md.Weakening})
	}
	return out, nil
}

func (m *memPolicyStore) total() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.touched {
		n += c
	}
	return n
}

func (m *memPolicyStore) revisions(tenant string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.docs[tenant])
}

// fakeValidator knows a tiny policy language: {"mode": "block|monitor|off", "threshold": n, "invalid": bool, "fail": bool,
// "panic": bool}. Lowering the mode or raising the threshold weakens it, measured against the defaults (block, 5) when
// there is no policy yet.
type fakeValidator struct {
	mu    sync.Mutex
	calls int
}

type fakePolicy struct {
	Mode      string `json:"mode"`
	Threshold int    `json:"threshold"`
	Invalid   bool   `json:"invalid"`
	Fail      bool   `json:"fail"`
	Panic     bool   `json:"panic"`
	Note      string `json:"note"`
}

var modeRank = map[string]int{"off": 0, "monitor": 1, "block": 2}

func parsePolicy(b []byte, def fakePolicy) fakePolicy {
	p := def
	if b != nil {
		_ = json.Unmarshal(b, &p)
	}
	return p
}

func (v *fakeValidator) Validate(ctx context.Context, tenant string, current, proposed []byte) (Validation, error) {
	v.mu.Lock()
	v.calls++
	v.mu.Unlock()
	def := fakePolicy{Mode: "block", Threshold: 5}
	cur := parsePolicy(current, def)
	var raw map[string]any
	_ = json.Unmarshal(proposed, &raw)
	next := parsePolicy(proposed, def)
	if next.Panic {
		panic("validator exploded: customer content must not leak")
	}
	if next.Fail {
		return Validation{}, errors.New("validator failed with a secret detail")
	}
	var out Validation
	if next.Invalid {
		out.Problems = append(out.Problems, Problem{Code: "invalid_field", Message: "the policy has a field that cannot be used"})
	}
	if _, ok := modeRank[next.Mode]; !ok {
		out.Problems = append(out.Problems, Problem{Code: "unknown_mode", Message: "the mode must be block, monitor or off"})
		return out, nil
	}
	if modeRank[next.Mode] < modeRank[cur.Mode] {
		out.Weakening = append(out.Weakening, Change{Code: "mode_lowered", Summary: "Attacks will be " + map[string]string{"monitor": "noted but let through", "off": "ignored completely"}[next.Mode] + " instead of blocked."})
	}
	if next.Threshold > cur.Threshold {
		out.Weakening = append(out.Weakening, Change{Code: "threshold_raised", Summary: "Requests will need a higher score before they are blocked."})
	}
	if next.Mode != cur.Mode {
		out.Diff = append(out.Diff, "The mode changes from "+cur.Mode+" to "+next.Mode+".")
	}
	if next.Threshold != cur.Threshold {
		out.Diff = append(out.Diff, "The threshold changes from "+strconv.Itoa(cur.Threshold)+" to "+strconv.Itoa(next.Threshold)+".")
	}
	return out, nil
}

type fakePublisher struct {
	mu          sync.Mutex
	seq         uint64
	calls       []PublishMeta
	revs        []uint64
	err         error
	panicBefore bool          // fail before any publish side effect
	gate        chan struct{} // when set, Publish waits for it
	in          chan struct{} // told when a Publish has started
}

func (p *fakePublisher) Publish(ctx context.Context, tenant string, revision uint64, meta PublishMeta) (PublishResult, error) {
	if p.panicBefore {
		panic("signer unreachable at 10.1.2.3")
	}
	if p.in != nil {
		p.in <- struct{}{}
	}
	if p.gate != nil {
		<-p.gate
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return PublishResult{}, p.err
	}
	p.seq++
	p.calls = append(p.calls, meta)
	p.revs = append(p.revs, revision)
	return PublishResult{Sequence: 1000 + p.seq}, nil
}

func (p *fakePublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

type fakeStatus struct{ status TenantStatus }

func (f *fakeStatus) Status(ctx context.Context, tenant string) (TenantStatus, error) {
	return f.status, nil
}

// fakeEvents pages over lists with the cursors "c0", "c1" ... (positions).
type fakeEvents struct {
	mu      sync.Mutex
	events  map[string][]feed.Event
	traffic map[string][]feed.TrafficDay
	calls   int
	// over makes it return one more item than asked for
	over bool
	err  error
}

func newFakeEvents() *fakeEvents {
	return &fakeEvents{events: map[string][]feed.Event{}, traffic: map[string][]feed.TrafficDay{}}
}

func position(cursor string) int {
	if strings.HasPrefix(cursor, "c") {
		if n, err := strconv.Atoi(cursor[1:]); err == nil && n >= 0 {
			return n
		}
	}
	return 0
}

func (f *fakeEvents) Events(ctx context.Context, tenant string, q PageQuery) (EventsPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return EventsPage{}, f.err
	}
	all := f.events[tenant]
	start := position(q.Cursor)
	if start > len(all) {
		start = len(all)
	}
	end := start + q.Limit
	if f.over {
		end++
	}
	if end > len(all) {
		end = len(all)
	}
	page := EventsPage{Events: append([]feed.Event(nil), all[start:end]...), More: end < len(all)}
	page.Next = "c" + strconv.Itoa(end)
	return page, nil
}

func (f *fakeEvents) Traffic(ctx context.Context, tenant string, q PageQuery) (TrafficPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	all := f.traffic[tenant]
	start := position(q.Cursor)
	if start > len(all) {
		start = len(all)
	}
	end := start + q.Limit
	if end > len(all) {
		end = len(all)
	}
	return TrafficPage{Days: append([]feed.TrafficDay(nil), all[start:end]...), More: end < len(all), Next: "c" + strconv.Itoa(end)}, nil
}

type memHosts struct {
	mu       sync.Mutex
	byTenant map[string]map[string]Host
	owner    map[string]string // verified hostname -> tenant
	calls    int
}

func newMemHosts() *memHosts {
	return &memHosts{byTenant: map[string]map[string]Host{}, owner: map[string]string{}}
}

func (m *memHosts) Add(ctx context.Context, tenant, hostname, token string) (Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if o, ok := m.owner[hostname]; ok && o != tenant {
		return Host{}, ErrHostTaken
	}
	if m.byTenant[tenant] == nil {
		m.byTenant[tenant] = map[string]Host{}
	}
	if h, ok := m.byTenant[tenant][hostname]; ok {
		return h, nil
	}
	h := Host{Hostname: hostname, State: HostPending, Token: token, CreatedAt: time.Unix(1_800_000_000, 0)}
	m.byTenant[tenant][hostname] = h
	return h, nil
}

func (m *memHosts) List(ctx context.Context, tenant string) ([]Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	var out []Host
	for _, h := range m.byTenant[tenant] {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, nil
}

func (m *memHosts) Get(ctx context.Context, tenant, hostname string) (Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	h, ok := m.byTenant[tenant][hostname]
	if !ok {
		return Host{}, ErrNotFound
	}
	return h, nil
}

func (m *memHosts) MarkVerified(ctx context.Context, tenant, hostname string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if o, ok := m.owner[hostname]; ok && o != tenant {
		return ErrHostTaken
	}
	h, ok := m.byTenant[tenant][hostname]
	if !ok {
		return ErrNotFound
	}
	h.State, h.VerifiedAt, h.CheckedAt = HostVerified, &at, &at
	m.byTenant[tenant][hostname] = h
	m.owner[hostname] = tenant
	return nil
}

func (m *memHosts) MarkChecked(ctx context.Context, tenant, hostname string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	h, ok := m.byTenant[tenant][hostname]
	if !ok {
		return ErrNotFound
	}
	h.CheckedAt = &at
	m.byTenant[tenant][hostname] = h
	return nil
}

// routable is what the edge would ask: is this name verified, and for whom?
func (m *memHosts) routable(hostname string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.owner[hostname]
	return t, ok
}

type fakeVerifier struct {
	mu     sync.Mutex
	result map[string]bool
	err    error
	calls  []string
	seen   []string // "name=value" of each check
}

func (f *fakeVerifier) Verify(ctx context.Context, hostname, name, value string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, hostname)
	f.seen = append(f.seen, name+"="+value)
	if f.err != nil {
		return false, f.err
	}
	return f.result[hostname], nil
}

// memAudit keeps entries in memory and can be told to fail.
type memAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
	failing bool
}

func (a *memAudit) Append(e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failing {
		return errors.New("disk full")
	}
	e.Seq = uint64(len(a.entries) + 1)
	a.entries = append(a.entries, e)
	return nil
}

func (a *memAudit) all() []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AuditEntry(nil), a.entries...)
}

func (a *memAudit) last() AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.entries) == 0 {
		return AuditEntry{}
	}
	return a.entries[len(a.entries)-1]
}

func (a *memAudit) setFailing(v bool) {
	a.mu.Lock()
	a.failing = v
	a.mu.Unlock()
}

// fakeClock is a clock a test moves.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}
