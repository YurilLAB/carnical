package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// A customer chooses where their origin is, so the edge must not trust that choice: an origin named as
// 169.254.169.254, 127.0.0.1, 10.0.0.5, or a name that resolves there, would turn the edge into a way to reach the
// machine's own services, the cloud metadata service and the private network behind it, which is exactly where the
// backend lives. The check is made on the address the connection is really about to use, after the name has been
// resolved, so a name that answers with a public address first and a private one later gets nothing.

// OriginPolicy decides which addresses the edge may connect to for a site.
type OriginPolicy struct {
	// Allow lists address ranges that are permitted even though they are not public, for an origin that really is on
	// a private network or the same machine. It is set by the operator for a named site, never by a customer.
	Allow []netip.Prefix
}

// ParseOriginAllow reads a comma-separated list of addresses and CIDR ranges for OriginPolicy.Allow. A range of /0 is
// refused: it would switch the policy off.
func ParseOriginAllow(list string) ([]netip.Prefix, error) { return parseRanges(list, "origin range") }

var refused = mustPrefixes(
	// IPv4
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
	"192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
	// Azure's platform address: the DNS resolver, DHCP and the wire server the VM agent talks to, which every Azure VM can
	// reach although it is outside 169.254.0.0/16.
	"168.63.129.16/32",
	// IPv6: unspecified, loopback, translation and tunnelling prefixes that can carry an IPv4 address inside,
	// documentation, unique local, link local, site local and multicast
	"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16",
	"fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// Check reports why the edge must not connect to ip, or nil if it may.
func (p OriginPolicy) Check(ip netip.Addr) error {
	ip = ip.Unmap() // ::ffff:127.0.0.1 is 127.0.0.1
	if !ip.IsValid() || ip.Zone() != "" {
		return errors.New("not a usable address")
	}
	for _, a := range p.Allow {
		if a.Contains(ip) {
			return nil
		}
	}
	for _, r := range refused {
		if r.Contains(ip) {
			return fmt.Errorf("%s is not a public address (%s)", ip, r)
		}
	}
	if isLocalAddr(ip) {
		return fmt.Errorf("%s is an address of this machine", ip) // a public origin that is this edge would loop
	}
	return nil
}

// Control is for net.Dialer.Control: it runs once per connection attempt with the resolved address.
func (p OriginPolicy) Control(network, address string, _ syscall.RawConn) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("network %q is not allowed", network)
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("unreadable address %q", address)
	}
	return p.Check(ap.Addr())
}

// Dialer returns a dialer that applies the policy to every connection it makes.
func (p OriginPolicy) Dialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: p.Control}
}

// Only retry local address collisions while creating a TCP connection. No HTTP
// bytes have been written here; established-connection failures must never replay
// a non-idempotent request. Each fresh dial still executes OriginPolicy.Control.
func dialBindRetry(ctx context.Context, network, address string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error, int) {
	retries := 0
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err, retries
		}
		if attempt > 0 {
			retries++
		}
		conn, err := dial(ctx, network, address)
		// Windows syscall.EADDRINUSE is a Go compatibility errno, distinct
		// from Winsock's observed WSAEADDRINUSE (10048).
		collision := errors.Is(err, syscall.EADDRINUSE) || runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10048))
		if err == nil || !collision || attempt == 2 {
			return conn, err, retries
		}
	}
}

// CheckHost resolves host and checks every address it gives. It is for deciding whether to accept an origin when it
// is registered and for checking it again later: the dial-time check is the one that cannot be fooled, this one is
// the early, readable error and the way to notice a name that has since moved somewhere it must not.
func (p OriginPolicy) CheckHost(ctx context.Context, host string) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		return p.Check(ip)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolving %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("%s has no address", host)
	}
	for _, a := range addrs {
		if err := p.Check(a); err != nil {
			return fmt.Errorf("%s: %w", host, err)
		}
	}
	return nil
}

var (
	localMu    sync.Mutex
	localAt    time.Time
	localAddrs map[netip.Addr]struct{}
)

// isLocalAddr reports whether ip is an address of one of this machine's interfaces. The list is kept for a short time
// because a dial is not rare enough to ask the system every time, and not frequent enough to need it fresher.
func isLocalAddr(ip netip.Addr) bool {
	localMu.Lock()
	defer localMu.Unlock()
	if localAddrs == nil || time.Since(localAt) > 15*time.Second {
		localAddrs = map[netip.Addr]struct{}{}
		localAt = time.Now()
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if v, ok := netip.AddrFromSlice(ipn.IP); ok {
						localAddrs[v.Unmap()] = struct{}{}
					}
				}
			}
		}
	}
	_, ok := localAddrs[ip]
	return ok
}
