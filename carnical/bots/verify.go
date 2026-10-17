// SPDX-License-Identifier: Apache-2.0

package bots

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Settings of a Verifier.
const (
	// lookupTimeout bounds one check: the reverse lookup and the forward lookups of the names it gave.
	lookupTimeout = 2 * time.Second
	// verifiedFor and refutedFor are how long an answer is kept. A failed lookup is kept briefly: it says nothing about
	// the address, but a client must not be able to make every request start a new one.
	verifiedFor, refutedFor, failedFor = 24 * time.Hour, time.Hour, time.Minute
	// maxNames is how many names of one address are checked.
	maxNames = 4
	// DefaultLookups is how many checks run at once by default; DefaultCache how many answers are kept.
	DefaultLookups = 8
	DefaultCache   = 65536
)

// Resolver is the part of net.Resolver a Verifier uses.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Verifier checks that a client claiming to be a search engine's crawler comes from that engine, as each engine asks
// sites to: the address's DNS name must be in one of the engine's domains, and the name must resolve back to the address.
// Answers are cached. A client that does not pass is not the engine, including when the lookup fails: the reverse zone
// of an address is its owner's, so an impostor can make it fail at will. It is safe for concurrent use.
type Verifier struct {
	res   Resolver
	slots chan struct{}
	max   int
	now   func() time.Time

	mu    sync.Mutex
	cache map[verifyKey]*verifyEntry
}

type verifyKey struct {
	addr   netip.Addr
	engine Engine
}

type verifyEntry struct {
	done  chan struct{} // closed once ok and until are set
	ok    bool
	until time.Time
}

// NewVerifier makes a Verifier that runs at most lookups checks at once and keeps at most cache answers. A nil res is
// net.DefaultResolver; zero sizes take the defaults.
func NewVerifier(res Resolver, lookups, cache int) *Verifier {
	if res == nil {
		res = net.DefaultResolver
	}
	if lookups <= 0 {
		lookups = DefaultLookups
	}
	if cache <= 0 {
		cache = DefaultCache
	}
	return &Verifier{res: res, slots: make(chan struct{}, lookups), max: cache, now: time.Now, cache: map[verifyKey]*verifyEntry{}}
}

// Verify reports whether addr is one of engine's crawlers. It waits for a check that is not cached yet, at most
// lookupTimeout or until ctx ends. When every check slot is taken, as under a flood of impostors from many addresses,
// the answer is no: the engine's own crawlers come from addresses that are already cached.
func (v *Verifier) Verify(ctx context.Context, addr netip.Addr, engine Engine) bool {
	if int(engine) == 0 || int(engine) >= numEngines || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	k := verifyKey{addr, engine}
	now := v.now()
	v.mu.Lock()
	e := v.cache[k]
	if e != nil {
		select {
		case <-e.done:
			if now.Before(e.until) {
				v.mu.Unlock()
				return e.ok
			}
			e = nil // expired: check again
		default: // a check is running: wait for it
		}
	}
	if e == nil {
		select {
		case v.slots <- struct{}{}:
		default:
			v.mu.Unlock()
			return false
		}
		if len(v.cache) >= v.max {
			v.evict(now)
		}
		e = &verifyEntry{done: make(chan struct{})}
		v.cache[k] = e
		go v.check(e, addr, engine) // #nosec G118 -- the check outlives this request on purpose: other requests wait for its answer.
	}
	v.mu.Unlock()
	select {
	case <-e.done:
		return e.ok
	case <-ctx.Done():
		return false
	}
}

// check runs one check, outside any request, so that a client that goes away does not leave the answer unset.
func (v *Verifier) check(e *verifyEntry, addr netip.Addr, engine Engine) {
	defer func() { <-v.slots }()
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	ok, err := v.lookup(ctx, addr, engine)
	ttl := refutedFor
	switch {
	case ok:
		ttl = verifiedFor
	case err != nil:
		ttl = failedFor
	}
	e.ok, e.until = ok, v.now().Add(ttl)
	close(e.done)
}

// lookup does the reverse lookup and the forward ones. An error is a lookup that failed, not an answer.
func (v *Verifier) lookup(ctx context.Context, addr netip.Addr, engine Engine) (bool, error) {
	names, err := v.res.LookupAddr(ctx, addr.String())
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}
		return false, err
	}
	var failed error
	checked := 0
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if !inDomains(name, engines[engine].domains) {
			continue
		}
		if checked++; checked > maxNames {
			break
		}
		ips, err := v.res.LookupNetIP(ctx, "ip", name)
		if err != nil {
			failed = err
			continue
		}
		for _, ip := range ips {
			if ip.Unmap() == addr {
				return true, nil
			}
		}
	}
	return false, failed
}

// inDomains reports whether name is one of the domains or a name under one.
func inDomains(name string, domains []string) bool {
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, d) && name[len(name)-len(d)-1] == '.' {
			return true
		}
	}
	return false
}

// evict makes room in a full cache: the expired answers go, and if that is not enough, an eighth of the rest. A check
// still running is never dropped, so its waiters keep their entry. v.mu is held.
func (v *Verifier) evict(now time.Time) {
	for k, e := range v.cache {
		select {
		case <-e.done:
			if !now.Before(e.until) {
				delete(v.cache, k)
			}
		default:
		}
	}
	for k, e := range v.cache {
		if len(v.cache) < v.max-v.max/8 {
			return
		}
		select {
		case <-e.done:
			delete(v.cache, k)
		default:
		}
	}
}
