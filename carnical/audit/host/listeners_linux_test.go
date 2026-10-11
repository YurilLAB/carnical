//go:build linux

package host

import (
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/YurilLAB/coraza/carnical/audit"
)

// Sockets of the protocols that any user may open besides TCP and UDP, on a real kernel: each is found, and a service
// declared on its port, of the protocol nearest to it and owned by the right user, does not answer for it. (Its own
// file: the sockets take calls that only Linux has.)
func TestListenersFindsRealSocketsOfOtherProtocols(t *testing.T) {
	for _, tt := range []struct {
		name            string
		kind, protocol  int
		listen          bool
		declared, label string
	}{
		{"UDP-Lite", syscall.SOCK_DGRAM, 136, false, "udp", " (UDP-Lite) takes packets from any sender"},
		{"SCTP", syscall.SOCK_STREAM, 132, true, "tcp", " (SCTP) is listening"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fd, err := syscall.Socket(syscall.AF_INET, tt.kind, tt.protocol)
			if err != nil {
				t.Skipf("this kernel has no %s: %v", tt.name, err)
			}
			defer syscall.Close(fd)
			if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
				t.Fatal(err)
			}
			sa, err := syscall.Getsockname(fd)
			if err != nil {
				t.Fatal(err)
			}
			port := strconv.Itoa(sa.(*syscall.SockaddrInet4).Port)
			problems := func() string {
				r := run(Listeners(OS{}, []audit.Service{{Name: "test", Addr: "127.0.0.1:" + port, Proto: tt.declared, User: currentUserName(t)}}))
				if r.Status == audit.Skip {
					t.Skip(r.Note)
				}
				return strings.Join(r.Problems, "\n")
			}
			if tt.listen {
				// Bound and not yet listening, it takes no association and is nobody's way in.
				if got := problems(); strings.Contains(got, "127.0.0.1:"+port+" (") {
					t.Fatalf("a socket that is not listening was reported:\n%s", got)
				}
				if err := syscall.Listen(fd, 1); err != nil {
					t.Fatal(err)
				}
			}
			if got := problems(); !strings.Contains(got, "127.0.0.1:"+port+tt.label) {
				t.Fatalf("a %s socket nobody can declare was not found:\n%s", tt.name, got)
			}
		})
	}
}
