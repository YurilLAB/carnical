// SPDX-License-Identifier: Apache-2.0

//go:build linux

package proxy

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/shield"
)

// A real flood through the real proxy: a thousand source addresses (Linux lets a socket use any 127.x.y.z address, so
// each bot really is a different address to the kernel and the proxy), one program's fingerprint, a cache-busting target,
// while twenty regular visitors keep using the site. Linux only: other systems do not route all of 127/8 to loopback.
func TestAFloodFromAThousandAddressesThroughTheProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("live flood")
	}
	for _, monitor := range []bool{false, true} {
		name := "mitigating"
		if monitor {
			name = "monitor only (control)"
		}
		t.Run(name, func(t *testing.T) {
			res := flood(t, monitor)
			t.Logf("detected %.1fs after the flood began; after detection: visitors %d/%d served, flood %d/%d reached the application",
				res.detected.Seconds(), res.legitOK, res.legitSent, res.attackOK, res.attackSent)
			if res.detected <= 0 || res.detected > 8*time.Second {
				t.Fatalf("the attack was not detected in time (%v)", res.detected)
			}
			legit := float64(res.legitOK) / float64(max(res.legitSent, 1))
			attack := float64(res.attackOK) / float64(max(res.attackSent, 1))
			if !monitor && (legit < 0.95 || attack > 0.1 || res.attackSent < 2000) {
				t.Fatalf("visitors served %.1f%%, flood admitted %.1f%%", 100*legit, 100*attack)
			}
			if monitor && attack < 0.8 {
				t.Fatalf("in monitor mode the flood should reach the application, but only %.1f%% did", 100*attack)
			}
		})
	}
}

type floodResult struct {
	detected                                 time.Duration
	legitOK, legitSent, attackOK, attackSent int64
}

func flood(t *testing.T, monitor bool) floodResult {
	sh, err := shield.New(shield.Config{
		MonitorOnly: monitor, KnownAfter: 3, KnownMinAge: 3 * time.Second, MinUnknownRate: 5, ClusterRate: 2,
		// The per-network limit would stop this flood on its own (its bots share four /24s); it is set out of the way so
		// that the attack detection and mitigation are what is measured.
		SubnetRate: 1e6, SubnetBurst: 1e6, ConnRate: 1000, ConnBurst: 1000, MaxConns: 10000,
		Detector: shield.DetectorConfig{Warmup: 4 * time.Second, Tau: time.Minute, MinAttackRate: 50, Confirm: 2,
			MinAttack: 30 * time.Second, ExitQuiet: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sh.Close)
	up := newUpstream(t)
	target, _ := url.Parse(up.URL)
	cfg := Config{Upstream: target, CRS: crs.DefaultSettings(), Origin: loopback, Shield: sh, MaxConnsPerIP: -1}
	cfg.CRS.Mode = crs.ModeOff // the rule set is not what is being measured
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := e.Server("")
	go srv.Serve(sh.Listener(ln))
	t.Cleanup(func() { srv.Close() })
	base := "http://" + ln.Addr().String()

	clients := map[string]*http.Client{}
	var cmu sync.Mutex
	client := func(local string) *http.Client {
		cmu.Lock()
		defer cmu.Unlock()
		if c := clients[local]; c != nil {
			return c
		}
		d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(local)}, Timeout: 3 * time.Second}
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: d.DialContext, MaxIdleConnsPerHost: 2}}
		clients[local] = c
		return c
	}
	t.Cleanup(func() {
		for _, c := range clients {
			c.CloseIdleConnections()
		}
	})
	send := func(local, path, ua string) bool {
		r, _ := http.NewRequest(http.MethodGet, base+path, nil)
		r.Header.Set("User-Agent", ua)
		if ua == "python-requests/2.32.3" {
			r.Header.Set("Accept", "*/*")
		} else {
			r.Header.Set("Accept", "text/css,*/*;q=0.1")
			r.Header.Set("Accept-Language", "en-AU,en;q=0.9")
			r.Header.Set("Sec-Fetch-Mode", "no-cors")
		}
		resp, err := client(local).Do(r)
		if err != nil {
			return false
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}

	var res floodResult
	var detectedAt atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	// Twenty regular visitors, one request a second each, from the start.
	for i := 1; i <= 20; i++ {
		wg.Add(1)
		go func(local string) {
			defer wg.Done()
			for n := 0; ctx.Err() == nil; n++ {
				ok := send(local, fmt.Sprintf("/static/page-%d.css", n%7), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/143.0")
				if detectedAt.Load() != 0 {
					atomic.AddInt64(&res.legitSent, 1)
					if ok {
						atomic.AddInt64(&res.legitOK, 1)
					}
				}
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
				}
			}
		}(fmt.Sprintf("127.2.0.%d", i))
	}
	time.Sleep(7 * time.Second) // the baseline and the visitors' standing are learnt
	if st := sh.State(); st != shield.Normal {
		t.Fatalf("before the flood the state is %v", st)
	}
	began := time.Now()
	go func() {
		for ctx.Err() == nil {
			if sh.State() == shield.Attack && detectedAt.Load() == 0 {
				detectedAt.Store(int64(time.Since(began)))
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	floodCtx, stopFlood := context.WithTimeout(ctx, 12*time.Second)
	defer stopFlood()
	var fwg sync.WaitGroup
	for g := 0; g < 100; g++ {
		fwg.Add(1)
		go func(seed uint64) {
			defer fwg.Done()
			r := rand.New(rand.NewPCG(seed, 1))
			for floodCtx.Err() == nil {
				i := r.IntN(1000)
				ok := send(fmt.Sprintf("127.1.%d.%d", i/250, i%250+1), fmt.Sprintf("/?r=%d", r.Int64()), "python-requests/2.32.3")
				if detectedAt.Load() != 0 {
					atomic.AddInt64(&res.attackSent, 1)
					if ok {
						atomic.AddInt64(&res.attackOK, 1)
					}
				}
				time.Sleep(40 * time.Millisecond)
			}
		}(uint64(g))
	}
	fwg.Wait()
	cancel()
	wg.Wait()
	res.detected = time.Duration(detectedAt.Load())
	snap := sh.Snapshot()
	if snap.Current != nil {
		t.Logf("record: %d addresses, %d networks, %d refused, %d banned, reasons %q", snap.Current.Sources, snap.Current.Networks,
			snap.Current.Refused, snap.Current.Banned, snap.Current.Reasons)
	}
	return res
}
