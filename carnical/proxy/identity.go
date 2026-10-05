package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// ParseTrusted reads a comma-separated list of addresses and CIDR ranges that may tell the proxy who a visitor is
// through X-Forwarded-For (a load balancer or CDN in front of it). A range that covers every address is refused:
// it would let any client choose its own address.
func ParseTrusted(list string) ([]netip.Prefix, error) { return parseRanges(list, "trusted proxy") }

// parseRanges reads a comma-separated list of addresses and CIDR ranges; what names them in an error.
func parseRanges(list, what string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var prefix netip.Prefix
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("%s %q: %w", what, part, err)
			}
			prefix = p
		} else {
			a, err := netip.ParseAddr(part)
			if err != nil {
				return nil, fmt.Errorf("%s %q: %w", what, part, err)
			}
			if a.Zone() != "" { // PrefixFrom would silently drop the zone
				return nil, fmt.Errorf("%s %q: an address with a zone is not allowed", what, part)
			}
			prefix = netip.PrefixFrom(a, a.BitLen())
		}
		if err := checkTrusted(prefix); err != nil {
			return nil, fmt.Errorf("%s %q: %w", what, part, err)
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

func checkTrusted(p netip.Prefix) error {
	switch {
	case !p.IsValid() || p.Addr().Zone() != "":
		return errors.New("not a valid address range")
	case p.Addr().Is4In6():
		return errors.New("write an IPv4 range as IPv4, not as an IPv4-mapped IPv6 range")
	case p.Bits() == 0:
		return errors.New("a range of /0 covers every address; list the actual ones")
	}
	return nil
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientAddr is the visitor's address. A connection from an untrusted peer is the visitor, whatever headers it
// sends. For a trusted peer the X-Forwarded-For chain is read from the right, up to the first address that is not
// itself trusted, so a client cannot choose its address by adding entries to the left. Every X-Forwarded-For
// header line counts, and anything that is not an address is an error rather than a guess.
func clientAddr(r *http.Request, trusted []netip.Prefix) (netip.Addr, uint16, error) {
	host, portText, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, 0, errors.New("invalid connection address")
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || peer.Zone() != "" {
		return netip.Addr{}, 0, errors.New("invalid connection address")
	}
	port, _ := strconv.ParseUint(portText, 10, 16)
	peer = peer.Unmap()
	if !isTrusted(peer, trusted) {
		return peer, uint16(port), nil
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer, uint16(port), nil
	}
	parts := strings.Split(strings.Join(values, ","), ",")
	if len(parts) > 64 {
		return netip.Addr{}, 0, errors.New("forwarding chain too long")
	}
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil || a.Zone() != "" {
			return netip.Addr{}, 0, errors.New("invalid forwarding chain")
		}
		a = a.Unmap()
		if !isTrusted(a, trusted) {
			return a, uint16(port), nil
		}
		peer = a
	}
	return peer, uint16(port), nil
}
