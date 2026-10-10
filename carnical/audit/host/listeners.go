package host

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/audit"
)

// Listener is a TCP socket that is waiting for connections.
type Listener struct {
	Addr netip.Addr
	Port uint16
	UID  int
}

// ParseNetTCP reads /proc/net/tcp or /proc/net/tcp6 and returns the sockets in the LISTEN state. Addresses are written in
// hexadecimal, each 32-bit word in the machine's byte order (little-endian on every machine this runs on).
func ParseNetTCP(data []byte, v6 bool) ([]Listener, error) {
	var out []Listener
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Scan() // the header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[3] != "0A" { // 0A is TCP_LISTEN
			continue
		}
		addr, port, err := parseHexAddr(f[1], v6)
		if err != nil {
			return nil, err
		}
		uid, err := strconv.Atoi(f[7])
		if err != nil {
			return nil, fmt.Errorf("bad uid %q", f[7])
		}
		out = append(out, Listener{Addr: addr, Port: port, UID: uid})
	}
	return out, sc.Err()
}

func parseHexAddr(s string, v6 bool) (netip.Addr, uint16, error) {
	hostHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(hostHex)
	if err != nil || (!v6 && len(raw) != 4) || (v6 && len(raw) != 16) {
		return netip.Addr{}, 0, fmt.Errorf("bad address %q", s)
	}
	for i := 0; i+4 <= len(raw); i += 4 { // each word is in host byte order
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("bad port %q", s)
	}
	addr, _ := netip.AddrFromSlice(raw)
	return addr.Unmap(), uint16(port), nil
}

// Listeners checks that only the sockets the zone map declares are listening, on the addresses declared and owned by the users
// declared. Anything else (a reverse-shell listener, a debug port, a service started by hand) is an incident or a mistake.
func Listeners(src Source, declared []audit.Service) audit.Check {
	return audit.Check{
		Name: "host-listeners", Zone: "",
		What: "Only the TCP sockets written in the zone map are listening, no wider than declared and owned by the user declared.",
		Run: func(ctx context.Context) audit.Outcome {
			if why := linux(); why != "" {
				return audit.Outcome{SkipReason: why}
			}
			var all []Listener
			for _, f := range []struct {
				path string
				v6   bool
			}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
				data, err := src.ReadFile(f.path)
				if err != nil {
					if f.v6 {
						continue // a machine with no IPv6
					}
					return audit.Outcome{SkipReason: "cannot read " + f.path + ": " + err.Error()}
				}
				ls, err := ParseNetTCP(data, f.v6)
				if err != nil {
					return audit.Outcome{SkipReason: "cannot read " + f.path + ": " + err.Error()}
				}
				all = append(all, ls...)
			}
			uids, _ := users(src)
			names := map[int]string{}
			for n, u := range uids {
				names[u] = n
			}

			var out audit.Outcome
			for _, l := range all {
				out.Checked++
				who := names[l.UID]
				if who == "" {
					who = "uid " + strconv.Itoa(l.UID)
				}
				var matches []audit.Service
				for _, d := range declared {
					if _, p, err := net.SplitHostPort(d.Addr); err == nil && p == strconv.Itoa(int(l.Port)) {
						matches = append(matches, d)
					}
				}
				if len(matches) == 0 {
					out.Problems = append(out.Problems, fmt.Sprintf("%s:%d is listening, owned by %s, and is not in the zone map", l.Addr, l.Port, who))
					continue
				}
				ok := false
				var why string
				for _, d := range matches {
					if why = listenerMismatch(l, who, d); why == "" {
						ok = true
						break
					}
				}
				if !ok {
					out.Problems = append(out.Problems, fmt.Sprintf("%s:%d (%s): %s", l.Addr, l.Port, who, why))
				}
			}
			sort.Strings(out.Problems)
			return out
		},
	}
}

// listenerMismatch says why a listener is not the declared service, or "" if it is.
func listenerMismatch(l Listener, who string, d audit.Service) string {
	host, _, _ := net.SplitHostPort(d.Addr)
	want, err := netip.ParseAddr(host)
	if err != nil && d.User == "" {
		// A name says nothing about this machine's addresses, and with no user the owner cannot be checked either: any
		// socket on the port would pass for it, including one for a service in another zone.
		return fmt.Sprintf("%s is declared by name with no user, so this socket cannot be told apart from another on port %d", d.Name, l.Port)
	}
	if err == nil && want.Unmap() != l.Addr {
		if l.Addr.IsUnspecified() {
			return fmt.Sprintf("it listens on every address, but %s is declared for %s", d.Addr, d.Name)
		}
		return fmt.Sprintf("it listens on %s, but %s is declared for %s", l.Addr, d.Addr, d.Name)
	}
	if d.User != "" {
		for _, u := range strings.Split(d.User, ",") {
			if strings.TrimSpace(u) == who {
				return ""
			}
		}
		return fmt.Sprintf("it is owned by %s, but %s is declared to be run by %s", who, d.Name, d.User)
	}
	return ""
}
