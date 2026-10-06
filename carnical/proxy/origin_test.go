package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/crs"
)

func TestOriginPolicyCheck(t *testing.T) {
	private := OriginPolicy{Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	tests := []struct {
		name   string
		policy OriginPolicy
		ip     string
		ok     bool
	}{
		{"public v4", OriginPolicy{}, "93.184.216.34", true},
		{"public v4 dns", OriginPolicy{}, "8.8.8.8", true},
		{"public v6", OriginPolicy{}, "2606:4700:4700::1111", true},
		{"loopback", OriginPolicy{}, "127.0.0.1", false},
		{"loopback elsewhere in the range", OriginPolicy{}, "127.9.9.9", false},
		{"v6 loopback", OriginPolicy{}, "::1", false},
		{"v4-mapped loopback", OriginPolicy{}, "::ffff:127.0.0.1", false},
		{"v4-mapped metadata", OriginPolicy{}, "::ffff:169.254.169.254", false},
		{"rfc1918 10", OriginPolicy{}, "10.1.2.3", false},
		{"rfc1918 172", OriginPolicy{}, "172.31.255.255", false},
		{"rfc1918 192", OriginPolicy{}, "192.168.1.1", false},
		{"just outside 172.16/12", OriginPolicy{}, "172.32.0.1", true},
		{"cloud metadata", OriginPolicy{}, "169.254.169.254", false},
		{"aws v6 metadata", OriginPolicy{}, "fd00:ec2::254", false},
		{"carrier-grade nat", OriginPolicy{}, "100.64.0.1", false},
		{"unspecified", OriginPolicy{}, "0.0.0.0", false},
		{"v6 unspecified", OriginPolicy{}, "::", false},
		{"multicast", OriginPolicy{}, "224.0.0.1", false},
		{"broadcast", OriginPolicy{}, "255.255.255.255", false},
		{"nat64 carrying 127.0.0.1", OriginPolicy{}, "64:ff9b::7f00:1", false},
		{"6to4 carrying 127.0.0.1", OriginPolicy{}, "2002:7f00:1::1", false},
		{"link-local v6", OriginPolicy{}, "fe80::1", false},
		{"unique local v6", OriginPolicy{}, "fc00::1", false},
		{"zone", OriginPolicy{}, "fe80::1%eth0", false},
		{"an allowed private range", private, "10.1.2.3", true},
		{"beside an allowed range", private, "172.16.0.1", false},
		{"metadata stays refused when a range is allowed", private, "169.254.169.254", false},
		{"allowing loopback", loopback, "127.0.0.1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Check(netip.MustParseAddr(tt.ip))
			if (err == nil) != tt.ok {
				t.Fatalf("Check(%s) = %v, want ok=%v", tt.ip, err, tt.ok)
			}
		})
	}
}

func TestOriginPolicyRefusesThisMachinesOwnAddress(t *testing.T) {
	// A public address is fine unless it is one of this machine's own, which would send the request back here.
	public := netip.MustParseAddr("8.8.8.8")
	if err := (OriginPolicy{}).Check(public); err != nil {
		t.Fatalf("the control address is refused: %v", err)
	}
	localMu.Lock()
	saved, savedAt := localAddrs, localAt
	localAddrs, localAt = map[netip.Addr]struct{}{public: {}}, time.Now()
	localMu.Unlock()
	t.Cleanup(func() { localMu.Lock(); localAddrs, localAt = saved, savedAt; localMu.Unlock() })
	if err := (OriginPolicy{}).Check(public); err == nil {
		t.Fatal("an address of this machine was accepted")
	}
}

func TestOriginPolicyControlOnlyAllowsTCPToAnAddress(t *testing.T) {
	tests := []struct {
		name, network, address string
		ok                     bool
	}{
		{"public tcp4", "tcp4", "93.184.216.34:443", true},
		{"public tcp6", "tcp6", "[2606:4700:4700::1111]:443", true},
		{"private", "tcp4", "10.0.0.1:80", false},
		{"udp", "udp", "93.184.216.34:53", false},
		{"unix", "unix", "/var/run/docker.sock", false},
		{"not an address", "tcp", "origin.example.com:80", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := (OriginPolicy{}).Control(tt.network, tt.address, nil); (err == nil) != tt.ok {
				t.Fatalf("Control(%s, %s) = %v, want ok=%v", tt.network, tt.address, err, tt.ok)
			}
		})
	}
}

// Dial attempts and cancellation precede HTTP/engine processing; an engine
// profile cannot inject an OS bind collision or assert no request replay.
func TestDialBindRetry(t *testing.T) {
	for _, tc := range []struct {
		name            string
		err             error
		failures, calls int
		cancel          bool
		live            bool
	}{
		{"success", nil, 0, 1, false, false},
		{"one collision", fmt.Errorf("bind: %w", syscall.EADDRINUSE), 1, 2, false, false},
		{"persistent collision is bounded", syscall.EADDRINUSE, 10, 3, false, false},
		{"EOF is not replayed", io.EOF, 1, 1, false, false},
		{"policy error is not retried", errors.New("origin denied"), 1, 1, false, false},
		{"other socket failure is not retried", syscall.ECONNRESET, 1, 1, false, false},
		{"cancel before retry", syscall.EADDRINUSE, 10, 1, true, false},
		{"Winsock collision", syscall.Errno(10048), 1, map[bool]int{true: 2, false: 1}[runtime.GOOS == "windows"], false, false},
		{"live socket collision then fresh source port", nil, 1, 2, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			target, wantNetwork := "origin.example.test:443", "tcp"
			var liveDial func(context.Context, string, string) (net.Conn, error)
			if tc.live {
				occupied, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer occupied.Close()
				origin, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer origin.Close()
				target, wantNetwork = origin.Addr().String(), "tcp4"
				liveDial = func(ctx context.Context, network, address string) (net.Conn, error) {
					d := loopback.Dialer()
					if calls == 1 {
						d.LocalAddr = occupied.Addr()
					}
					return d.DialContext(ctx, network, address)
				}
			}
			conn, err, retries := dialBindRetry(ctx, wantNetwork, target, func(ctx context.Context, network, address string) (net.Conn, error) {
				calls++
				if network != wantNetwork || address != target {
					t.Fatal("dial target changed")
				}
				if liveDial != nil {
					return liveDial(ctx, network, address)
				}
				if tc.cancel {
					cancel()
				}
				if calls <= tc.failures {
					return nil, tc.err
				}
				return nil, nil
			})
			if conn != nil {
				conn.Close()
			}
			if calls != tc.calls || retries != calls-1 || (err == nil) != (calls > tc.failures) {
				t.Fatalf("calls=%d retries=%d err=%v", calls, retries, err)
			}
		})
	}
}

func TestAnOriginAtAPrivateAddressIsNotReached(t *testing.T) {
	// The address is written into the config: refused when the proxy is built.
	for _, bad := range []string{"http://127.0.0.1:8080", "http://169.254.169.254", "http://10.0.0.5", "http://[::1]:8080", "https://[::ffff:127.0.0.1]"} {
		u, _ := url.Parse(bad)
		if _, err := New(Config{Upstream: u, CRS: crs.DefaultSettings()}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}

	// A name is only known to be safe when a connection is made, so a name that resolves to the loopback address is
	// refused at that moment. The same request goes through once the range is allowed, which shows the refusal is
	// the policy and not a broken test.
	refusedByName := func(c *Config) {
		c.Origin = OriginPolicy{}
		c.Upstream = &url.URL{Scheme: "http", Host: "localhost:" + c.Upstream.Port()}
	}
	allowedByName := func(c *Config) {
		c.Origin = loopback
		c.Upstream = &url.URL{Scheme: "http", Host: "localhost:" + c.Upstream.Port()}
	}

	s := start(t, refusedByName)
	if status, _ := s.raw(t, get("/page")); status != http.StatusBadGateway {
		t.Fatalf("a name that resolves to the loopback address: %d, want 502", status)
	}
	if n := len(s.up.requests()); n != 0 {
		t.Fatalf("the origin received %d request(s) it must not have", n)
	}

	s = start(t, allowedByName)
	if status, _ := s.raw(t, get("/page")); status != http.StatusOK {
		t.Fatalf("the same name with the range allowed: %d, want 200", status)
	}
	if n := len(s.up.requests()); n != 1 {
		t.Fatalf("the origin received %d request(s), want 1", n)
	}
}

func TestCheckHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tests := []struct {
		name   string
		policy OriginPolicy
		host   string
		ok     bool
	}{
		{"public literal", OriginPolicy{}, "93.184.216.34", true},
		{"private literal", OriginPolicy{}, "10.0.0.1", false},
		{"a name that is the loopback address", OriginPolicy{}, "localhost", false},
		{"the same name with the range allowed", loopback, "localhost", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.policy.CheckHost(ctx, tt.host); (err == nil) != tt.ok {
				t.Fatalf("CheckHost(%s) = %v, want ok=%v", tt.host, err, tt.ok)
			}
		})
	}
}

func TestOriginAllowListIsChecked(t *testing.T) {
	tests := []struct {
		name, list string
		ok         bool
	}{
		{"empty", "", true},
		{"a range and an address", "10.0.0.0/24, 192.168.5.7", true},
		{"v6", "fd00::/8", true},
		{"everything", "0.0.0.0/0", false},
		{"everything in v6", "::/0", false},
		{"not an address", "origin.example.com", false},
		{"a zone", "fe80::1%eth0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseOriginAllow(tt.list); (err == nil) != tt.ok {
				t.Fatalf("ParseOriginAllow(%q) = %v, want ok=%v", tt.list, err, tt.ok)
			}
		})
	}
	// The same rule when the policy is built in code instead of from the command line.
	u, _ := url.Parse("https://origin.example.com")
	if _, err := New(Config{Upstream: u, CRS: crs.DefaultSettings(), Origin: OriginPolicy{Allow: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}}); err == nil {
		t.Fatal("New accepted an allow-all origin range")
	}
}
