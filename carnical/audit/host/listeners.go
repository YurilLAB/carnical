package host

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/audit"
)

// Listener is a socket anyone may reach: a TCP or SCTP socket that is waiting for connections, or a UDP or UDP-Lite
// socket that takes packets from any sender.
type Listener struct {
	Addr  netip.Addr
	Port  uint16
	UID   int
	Proto string // "" for TCP, or one of the protocols below; the check sets it from the table the socket was in
}

// The protocols besides TCP whose sockets any user may open, each with ports of its own. A zone map declares TCP and UDP
// services; nothing it describes speaks the other two.
const (
	protoUDP     = "udp"
	protoUDPLite = "udplite"
	protoSCTP    = "sctp"
)

// protoLabel is how a finding names a socket's protocol.
var protoLabel = map[string]string{protoUDP: " (UDP)", protoUDPLite: " (UDP-Lite)", protoSCTP: " (SCTP)"}

// ParseNetUDP reads /proc/net/udp or /proc/net/udp6 (or the UDP-Lite tables, which are written the same way) and
// returns the sockets that are bound and name no peer address: those take a packet from any address that sends one,
// which is what listening is for UDP. A connected socket (a resolver's or a time client's own query) is left out: it
// hears only packets that carry the address of the one peer it named, and every query in flight would be a finding.
// Whether such a packet can be forged from elsewhere is for the packet policy to settle, not for this list.
func ParseNetUDP(data []byte, v6 bool) ([]Listener, error) {
	var out []Listener
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Scan() // the header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) < 8 {
			return nil, fmt.Errorf("a line cut short: %q", sc.Text()) // it could be the socket this is read for
		}
		addr, port, err := parseHexAddr(f[1], v6)
		if err != nil {
			return nil, err
		}
		peer, _, err := parseHexAddr(f[2], v6)
		if err != nil {
			return nil, err
		}
		if !peer.IsUnspecified() {
			continue
		}
		uid, err := strconv.Atoi(f[7])
		if err != nil {
			return nil, fmt.Errorf("bad uid %q", f[7])
		}
		out = append(out, Listener{Addr: addr, Port: port, UID: uid})
	}
	return out, sc.Err()
}

// ParseSCTPEndpoints reads /proc/net/sctp/eps, which is there once anything on the machine has opened an SCTP socket,
// and returns the endpoints that are listening, one for each address they are bound to. An endpoint that is bound and
// not listening takes no association.
func ParseSCTPEndpoints(data []byte) ([]Listener, error) {
	var out []Listener
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Scan() // the header
	for sc.Scan() {
		// endpoint, socket, socket type, socket state, hash bucket, port, uid, inode, then the local addresses
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) < 8 {
			return nil, fmt.Errorf("a line cut short: %q", sc.Text())
		}
		if f[3] != "10" { // 10 is LISTENING, the state TCP calls 0A
			continue
		}
		port, err := strconv.ParseUint(f[5], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("bad port %q", f[5])
		}
		uid, err := strconv.Atoi(f[6])
		if err != nil {
			return nil, fmt.Errorf("bad uid %q", f[6])
		}
		if len(f) == 8 {
			return nil, fmt.Errorf("a listening endpoint with no address: %q", sc.Text())
		}
		for _, a := range f[8:] {
			addr, err := netip.ParseAddr(a)
			if err != nil {
				return nil, fmt.Errorf("bad address %q", a)
			}
			out = append(out, Listener{Addr: addr.Unmap(), Port: uint16(port), UID: uid})
		}
	}
	return out, sc.Err()
}

// ParseNetTCP reads /proc/net/tcp or /proc/net/tcp6 and returns the sockets in the LISTEN state. Addresses are written in
// hexadecimal, each 32-bit word in the machine's byte order (little-endian on every machine this runs on).
func ParseNetTCP(data []byte, v6 bool) ([]Listener, error) {
	var out []Listener
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Scan() // the header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) < 8 {
			return nil, fmt.Errorf("a line cut short: %q", sc.Text()) // it could be the listener
		}
		if f[3] != "0A" { // 0A is TCP_LISTEN
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
// UDP has no listening state, so there it is every socket that is bound and takes packets from any sender; a service
// declared with "proto": "udp" answers for one. UDP-Lite and SCTP sockets, which any user may open, are read from their
// own tables and nothing answers for them.
func Listeners(src Source, declared []audit.Service) audit.Check {
	return audit.Check{
		Name: "host-listeners", Zone: "",
		What: "Only the sockets written in the zone map are listening (TCP) or open to any sender (UDP), no wider than declared and owned by the user declared.",
		Run: func(ctx context.Context) audit.Outcome {
			if why := linux(); why != "" {
				return audit.Outcome{SkipReason: why}
			}
			var all []Listener
			var out audit.Outcome
			for _, f := range []struct {
				path  string
				v6    bool
				proto string
			}{
				{"/proc/net/tcp", false, ""}, {"/proc/net/tcp6", true, ""},
				{"/proc/net/udp", false, protoUDP}, {"/proc/net/udp6", true, protoUDP},
				{"/proc/net/udplite", false, protoUDPLite}, {"/proc/net/udplite6", true, protoUDPLite},
				{"/proc/net/sctp/eps", false, protoSCTP},
			} {
				var ls []Listener
				data, err := src.ReadFile(f.path)
				if err == nil {
					switch f.proto {
					case "":
						ls, err = ParseNetTCP(data, f.v6)
					case protoSCTP:
						ls, err = ParseSCTPEndpoints(data)
					default:
						ls, err = ParseNetUDP(data, f.v6)
					}
				}
				switch {
				case err == nil:
				case f.path == "/proc/net/tcp":
					return audit.Outcome{SkipReason: "cannot read " + f.path + ": " + err.Error()} // nothing can be said here
				case errors.Is(err, fs.ErrNotExist) && f.path != "/proc/net/udp":
					continue // a machine with no IPv6, or a kernel with no UDP-Lite, or one where nothing has opened SCTP
				default:
					// A table that is there and was not read may hold the socket this check is for: that is a finding, and
					// not a reason to say nothing of the others.
					out.Problems = append(out.Problems, fmt.Sprintf("%s cannot be read, so its sockets were not checked: %v", f.path, err))
					continue
				}
				for i := range ls {
					ls[i].Proto = f.proto
				}
				all = append(all, ls...)
			}
			uids, _ := users(src)
			names := map[int]string{}
			for n, u := range uids {
				names[u] = n
			}

			for _, l := range all {
				out.Checked++
				who := names[l.UID]
				if who == "" {
					who = "uid " + strconv.Itoa(l.UID)
				}
				var matches []audit.Service
				for _, d := range declared {
					if _, p, err := net.SplitHostPort(d.Addr); err == nil && p == strconv.Itoa(int(l.Port)) && answers(d, l) {
						matches = append(matches, d)
					}
				}
				where := netip.AddrPortFrom(l.Addr, l.Port).String() + protoLabel[l.Proto]
				if len(matches) == 0 {
					state := "is listening"
					if l.Proto == protoUDP || l.Proto == protoUDPLite {
						state = "takes packets from any sender"
					}
					out.Problems = append(out.Problems, fmt.Sprintf("%s %s, owned by %s, and is not in the zone map", where, state, who))
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
					out.Problems = append(out.Problems, fmt.Sprintf("%s (%s): %s", where, who, why))
				}
			}
			sort.Strings(out.Problems)
			return out
		},
	}
}

// answers reports whether a declared service is of a listener's protocol. A TCP service does not answer for a UDP socket
// on its port, nor the other way round, and no service answers for UDP-Lite or SCTP.
func answers(d audit.Service, l Listener) bool {
	switch l.Proto {
	case "":
		return !d.UDP()
	case protoUDP:
		return d.UDP()
	}
	return false
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
