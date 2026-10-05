package audit

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/YurilLAB/coraza/carnical/proxy"
)

// sentinels are addresses that must never be reachable as an origin whatever the map says: the machine itself, the
// cloud metadata services, and a private address of each kind.
var sentinels = []string{
	"127.0.0.1", "::1", "169.254.169.254", "fd00:ec2::254", "100.100.100.200", "10.0.0.1", "172.16.0.1", "192.168.0.1",
	"fe80::1", "0.0.0.0",
}

// publicControl is a public address used to prove the policy still allows what it should.
const publicControl = "93.184.216.34"

// OriginGuard checks that the origin policy the edge really runs with still refuses every address inside Carnical's
// own zones and the usual internal targets. It watches the one setting, the allow list, that could quietly turn the
// guard into a way into the backend: someone adds a private range for one customer's tunnel and it happens to cover
// the control plane.
func OriginGuard(zm Map, policy proxy.OriginPolicy) Check {
	return Check{
		Name: "origin-guard", Zone: "edge",
		What: "A customer's origin can never be an address inside Carnical's own zones, this machine, or a metadata service.",
		Run: func(ctx context.Context) Outcome {
			var out Outcome
			if err := policy.Check(netip.MustParseAddr(publicControl)); err != nil {
				out.Problems = append(out.Problems, "the policy refuses a public address, so its refusals prove nothing: "+err.Error())
				return out
			}
			out.Checked++
			var addrs []netip.Addr
			for _, s := range sentinels {
				addrs = append(addrs, netip.MustParseAddr(s))
			}
			addrs = append(addrs, zm.internalAddrs()...)
			seen := map[netip.Addr]bool{}
			for _, a := range addrs {
				if seen[a] {
					continue
				}
				seen[a] = true
				out.Checked++
				if err := policy.Check(a); err == nil {
					out.Problems = append(out.Problems, fmt.Sprintf("an origin at %s would be allowed", a))
				}
			}
			sort.Strings(out.Problems)
			return out
		},
	}
}

// Dialer opens a connection; net.Dialer.DialContext fits.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// ZoneReach checks, from this machine's zone, that every listener in every other zone is reachable exactly when the
// map allows it. A wall that is open is a finding; so is a flow that is allowed but cannot connect, because then
// either the network or the map is wrong and the check is not seeing what it thinks it is.
func ZoneReach(zm Map, dial Dialer) Check {
	return Check{
		Name: "zone-reach", Zone: zm.Here,
		What: "From this zone, only the connections written in the zone map can be made.",
		Run: func(ctx context.Context) Outcome {
			if zm.Here == "" {
				return Outcome{SkipReason: "the zone map does not say which zone this machine is in"}
			}
			type probe struct{ zone, service, addr string }
			var probes []probe
			for _, z := range zm.Zones {
				if z.Name == zm.Here {
					continue
				}
				for _, s := range z.Services {
					probes = append(probes, probe{z.Name, s.Name, s.Addr})
				}
			}
			var (
				mu  sync.Mutex
				out Outcome
				wg  sync.WaitGroup
			)
			sem := make(chan struct{}, 8)
			for _, p := range probes {
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer func() { <-sem; wg.Done() }()
					cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
					defer cancel()
					conn, err := dial(cctx, "tcp", p.addr)
					reached := err == nil
					if conn != nil {
						conn.Close()
					}
					allowed := zm.Allowed(zm.Here, p.zone)
					mu.Lock()
					defer mu.Unlock()
					out.Checked++
					switch {
					case reached && !allowed:
						out.Problems = append(out.Problems, fmt.Sprintf("%s can reach %s/%s, which the zone map does not allow", zm.Here, p.zone, p.service))
					case !reached && allowed:
						out.Problems = append(out.Problems, fmt.Sprintf("%s is allowed to reach %s/%s but cannot", zm.Here, p.zone, p.service))
					}
				}()
			}
			wg.Wait()
			sort.Strings(out.Problems)
			return out
		},
	}
}
