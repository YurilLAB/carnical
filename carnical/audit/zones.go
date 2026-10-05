package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
)

// Map is the written-down segmentation: which zones exist, where they are, and which of them may talk to which. It is
// the one description the checks work from, so a change to the real network that is not in the map is a finding, and
// a change to the map that is not in the real network is one too.
type Map struct {
	// Here is the zone this machine is in, so the checks know which side of each wall they are standing on.
	Here  string `json:"here"`
	Zones []Zone `json:"zones"`
	// Flows are the only connections that are allowed, as zone names. Anything else is a wall.
	Flows []Flow `json:"flows"`
}

// Zone is a set of machines that trust each other and are trusted the same by everyone else.
type Zone struct {
	Name string `json:"name"`
	// Internal marks Carnical's own side. An origin address inside an internal zone is always refused.
	Internal bool `json:"internal"`
	// Prefixes are the address ranges of the zone.
	Prefixes []string `json:"prefixes"`
	// Services are the listeners the checks probe from other zones: host:port, where host is an address or a name.
	Services []Service `json:"services"`
}

// Service is one listener in a zone.
type Service struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
	// User, if set, is who must own the listening socket on this machine: a name, or several separated by commas. A socket
	// that systemd opened for a service (socket activation) is owned by root, so list both.
	User string `json:"user,omitempty"`
}

// Flow allows connections from one zone to another.
type Flow struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// LoadMap reads and validates a zone map. Unknown fields are an error: a misspelt key must not quietly drop a wall.
func LoadMap(r io.Reader) (Map, error) {
	var m Map
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Map{}, fmt.Errorf("reading the zone map: %w", err)
	}
	return m, m.Validate()
}

// Validate checks that the map is consistent.
func (m Map) Validate() error {
	names := map[string]*Zone{}
	for i := range m.Zones {
		z := &m.Zones[i]
		if z.Name == "" || z.Name != strings.TrimSpace(z.Name) {
			return errors.New("every zone needs a name")
		}
		if names[z.Name] != nil {
			return fmt.Errorf("zone %q is listed twice", z.Name)
		}
		names[z.Name] = z
		for _, p := range z.Prefixes {
			if _, err := netip.ParsePrefix(p); err != nil {
				return fmt.Errorf("zone %q: prefix %q: %w", z.Name, p, err)
			}
		}
		for _, s := range z.Services {
			if _, _, err := net.SplitHostPort(s.Addr); err != nil || s.Name == "" {
				return fmt.Errorf("zone %q: service %q needs a name and a host:port address", z.Name, s.Name)
			}
		}
	}
	if m.Here != "" && names[m.Here] == nil {
		return fmt.Errorf("\"here\" names zone %q, which is not in the map", m.Here)
	}
	for _, f := range m.Flows {
		if names[f.From] == nil || names[f.To] == nil {
			return fmt.Errorf("flow %s -> %s names a zone that is not in the map", f.From, f.To)
		}
		if f.From == f.To {
			return fmt.Errorf("flow %s -> %s is a zone talking to itself", f.From, f.To)
		}
	}
	return nil
}

// Allowed reports whether a connection from one zone to another is permitted.
func (m Map) Allowed(from, to string) bool {
	for _, f := range m.Flows {
		if f.From == from && f.To == to {
			return true
		}
	}
	return false
}

// internalAddrs lists addresses that sit inside the internal zones: the ends of every prefix and every service that
// is written as an address.
func (m Map) internalAddrs() []netip.Addr {
	var out []netip.Addr
	for _, z := range m.Zones {
		if !z.Internal {
			continue
		}
		for _, p := range z.Prefixes {
			pf, _ := netip.ParsePrefix(p)
			out = append(out, pf.Masked().Addr(), lastAddr(pf))
		}
		for _, s := range z.Services {
			if host, _, err := net.SplitHostPort(s.Addr); err == nil {
				if a, err := netip.ParseAddr(host); err == nil {
					out = append(out, a)
				}
			}
		}
	}
	return out
}

// lastAddr is the highest address in a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().AsSlice()
	for i := range a {
		bits := 8
		if rem := p.Bits() - i*8; rem < 8 {
			bits = max(rem, 0)
		}
		a[i] |= byte(0xff >> bits)
	}
	last, _ := netip.AddrFromSlice(a)
	return last
}
