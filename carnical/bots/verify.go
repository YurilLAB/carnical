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
	// maxPerNetwork is how many checks of one network (an IPv4 /24, an IPv6 /48) run at once, so that one network's
	// impostors, whose own reverse zone can answer as slowly as it likes, cannot hold every slot.
	maxPerNetwork = 2
	// maxNetworks is how many networks with a verified crawler are remembered (see Verifier.TrustNetworks).
	maxNetworks = 4096
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
//
// Impostors cannot crowd the engine's crawlers out of the cache: a verified answer is the last kind a full cache drops,
// and one network runs at most maxPerNetwork checks at once. When no check can start the answer is no, unless
// TrustNetworks is set.
type Verifier struct {
	// TrustNetworks, set before the Verifier is used, lets an address pass unchecked when no check can start and a
	// crawler of the same engine was verified in its network (its /24 or /48) within verifiedFor. It keeps an engine's
	// crawlers passing under a flood of impostors, but trusts every address of such a network as the engine's: leave
	// it off where a network's addresses need not belong to one owner, as in a cloud's shared ranges.
	TrustNetworks bool

	res   Resolver
	slots chan struct{}
	max   int
	now   func() time.Time

	mu    sync.Mutex
	cache map[verifyKey]*verifyEntry
	busy  map[netip.Prefix]int // checks running, by network
	nets  map[netKey]time.Time // networks with a verified crawler, until when
}

type netKey struct {
	net    netip.Prefix
	engine Engine
}

// network is the network an address's checks are counted by: its /24 or /48.
func network(a netip.Addr) netip.Prefix {
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
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
	return &Verifier{res: res, slots: make(chan struct{}, lookups), max: cache, now: time.Now, cache: map[verifyKey]*verifyEntry{},
		busy: map[netip.Prefix]int{}, nets: map[netKey]time.Time{}}
}

// Verify reports whether addr is one of engine's crawlers. It waits for a check that is not cached yet, at most
// lookupTimeout or until ctx ends. When no check can start (every slot is taken, as under a flood of impostors from many
// addresses, or the address's network has its share running), the answer is no; with TrustNetworks it is yes for an
// address in a network where one of engine's crawlers was verified.
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
		nw := network(addr)
		if v.busy[nw] >= maxPerNetwork {
			ok := v.knownNetwork(nw, engine, now)
			v.mu.Unlock()
			return ok
		}
		select {
		case v.slots <- struct{}{}:
		default:
			ok := v.knownNetwork(nw, engine, now)
			v.mu.Unlock()
			return ok
		}
		if len(v.cache) >= v.max {
			v.evict(now)
		}
		v.busy[nw]++
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
	now := v.now()
	e.ok, e.until = ok, now.Add(ttl)
	close(e.done)
	nw := network(addr)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.busy[nw]--; v.busy[nw] <= 0 {
		delete(v.busy, nw)
	}
	if ok && v.TrustNetworks {
		if len(v.nets) >= maxNetworks {
			v.forgetNetwork(now)
		}
		v.nets[netKey{nw, engine}] = e.until
	}
}

// knownNetwork reports whether a crawler of engine was verified in nw and the answer still holds. v.mu is held.
func (v *Verifier) knownNetwork(nw netip.Prefix, engine Engine, now time.Time) bool {
	if !v.TrustNetworks {
		return false
	}
	until, ok := v.nets[netKey{nw, engine}]
	return ok && now.Before(until)
}

// forgetNetwork makes room among the verified networks: the expired go, or else one of the others. v.mu is held.
func (v *Verifier) forgetNetwork(now time.Time) {
	for k, until := range v.nets {
		if !now.Before(until) {
			delete(v.nets, k)
		}
	}
	for k := range v.nets {
		if len(v.nets) < maxNetworks {
			return
		}
		delete(v.nets, k)
	}
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

// evict makes room in a full cache: the expired answers go, then the answers that refuted a claim, and only if that is
// not enough the verified ones, until an eighth of the cache is free. A flood of impostors therefore drops its own
// answers, not the crawlers'. A check still running is never dropped, so its waiters keep their entry. v.mu is held.
func (v *Verifier) evict(now time.Time) {
	room := v.max - v.max/8
	for pass := 0; pass < 3 && len(v.cache) >= room; pass++ {
		for k, e := range v.cache {
			if len(v.cache) < room {
				return
			}
			select {
			case <-e.done:
				if pass == 0 && !now.Before(e.until) || pass == 1 && !e.ok || pass == 2 {
					delete(v.cache, k)
				}
			default:
			}
		}
	}
}
