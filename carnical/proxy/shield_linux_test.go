// SPDX-License-Identifier: Apache-2.0

//go:build linux

package proxy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/notify"
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
			res := flood(t, monitor, floodProfile{addrs: 1000, senders: 100, pace: 40 * time.Millisecond, duration: 12 * time.Second, keepAlive: true, alerts: !monitor})
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
			if !monitor {
				// The alert endpoint was told, while the flood went on, what was attacked: the proxy's port, over plain
				// HTTP/1.1, by a request flood from many new addresses, with the mitigation on.
				var start *notify.Message
				for i := range res.alerts {
					if res.alerts[i].Event == notify.AttackStart {
						start = &res.alerts[i]
						break
					}
				}
				if start == nil || start.Attack == nil {
					t.Fatalf("no attack_start reached the endpoint: %+v", res.alerts)
				}
				a := start.Attack
				t.Logf("attack_start: %s; ports %+v kinds %q", start.Text, a.Ports, a.Kinds)
				if len(a.Ports) != 1 || a.Ports[0].Port != res.port || a.Ports[0].Protocol != "tcp" || a.Ports[0].Requests == 0 ||
					a.Mode != "on" || a.TLS != 0 || a.HTTP2 != 0 || a.Plain == 0 || a.Addresses < 500 || !a.Window || start.Severity != "critical" {
					t.Fatalf("the alert does not name the attacked port %d and protocol: %+v", res.port, a)
				}
				for _, k := range []string{"request_flood", "one_client_tool"} {
					if !slices.Contains(a.Kinds, k) {
						t.Fatalf("the alert's kinds %q lack %s", a.Kinds, k)
					}
				}
			}
		})
	}
}

// alertReceiver is an alert endpoint over TLS that keeps the messages whose signature verifies, and counts the others.
func alertReceiver(t *testing.T, secret []byte) (*httptest.Server, func() ([]notify.Message, int)) {
	t.Helper()
	var mu sync.Mutex
	var got []notify.Message
	bad := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, notify.MaxBody+1))
		var m notify.Message
		ok := notify.Verify(secret, r.Header.Get("X-Carnical-Timestamp"), r.Header.Get("X-Carnical-Signature"), body, time.Now(), 5*time.Minute) &&
			json.Unmarshal(body, &m) == nil
		mu.Lock()
		if ok {
			got = append(got, m)
		} else {
			bad++
		}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, func() ([]notify.Message, int) {
		mu.Lock()
		defer mu.Unlock()
		return append([]notify.Message(nil), got...), bad
	}
}

// A bigger, faster flood through the same proxy: four thousand source addresses and 135,500 requests sent as fast as the
// clients can, with no pacing between them, while the regular visitors keep using the site. It stresses the same
// detection and mitigation at a higher offered rate and a wider spread than the thousand-address flood above. The clients
// do not keep connections alive, so the generator holds no more open sockets than it has senders however many it sends.
func TestABiggerFloodOfManyAddressesThroughTheProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("live flood")
	}
	// Opt-in: this sends 135,500 requests as fast as the clients can, so how long it
	// takes depends on the machine. It is a deliberate big run, like the 750k loadtest,
	// not part of the default suite. Set CARNICAL_BIG_FLOOD=1 to run it.
	if os.Getenv("CARNICAL_BIG_FLOOD") == "" {
		t.Skip("set CARNICAL_BIG_FLOOD=1 to run the 135,500-request flood")
	}
	const budget = 135_500
	for _, monitor := range []bool{false, true} {
		name := "mitigating"
		if monitor {
			name = "monitor only (control)"
		}
		t.Run(name, func(t *testing.T) {
			res := flood(t, monitor, floodProfile{addrs: 4000, senders: 120, budget: budget})
			t.Logf("sent %d requests; detected %.1fs after the flood began; after detection: visitors %d/%d served, flood %d/%d reached the application",
				res.sent, res.detected.Seconds(), res.legitOK, res.legitSent, res.attackOK, res.attackSent)
			if res.sent != budget {
				t.Fatalf("the flood sent %d requests, want %d", res.sent, budget)
			}
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

// floodProfile is how a flood is sent. addrs source addresses are spread over addrs/250 adjacent /24s, senders send
// concurrently, and pace is the wait between one sender's requests (zero sends as fast as it can). A flood runs for
// duration, or, when budget is set, until budget requests have been sent. keepAlive reuses connections per source.
type floodProfile struct {
	addrs, senders int
	pace           time.Duration
	duration       time.Duration
	budget         int64
	keepAlive      bool
	alerts         bool // the shield's attack events go to an alert endpoint, as carnical's -alert-endpoint sends them
}

type floodResult struct {
	detected                                 time.Duration
	legitOK, legitSent, attackOK, attackSent int64
	sent                                     int64
	alerts                                   []notify.Message // what the alert endpoint received, signature checked
	port                                     uint16           // the proxy's port
}

func flood(t *testing.T, monitor bool, prof floodProfile) floodResult {
	var sender *notify.Sender
	var received func() ([]notify.Message, int)
	var onEvent func(shield.Event)
	if prof.alerts {
		secret := []byte("flood-test-secret-0123456789abcdef0123")
		var srv *httptest.Server
		srv, received = alertReceiver(t, secret)
		u, err := notify.ParseURL(srv.URL + "/carnical")
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(srv.Certificate())
		// The guarded dialer carnical uses: the receiver is on loopback, so it is allowed as the origin is.
		sender, err = notify.New(notify.Config{URL: u, Secret: secret, Dial: loopback.Dialer().DialContext, RootCAs: roots})
		if err != nil {
			t.Fatal(err)
		}
		kinds := map[string]notify.Event{"attack_start": notify.AttackStart, "attack_update": notify.AttackUpdate, "attack_end": notify.AttackEnd}
		onEvent = func(ev shield.Event) {
			if k, ok := kinds[ev.Kind]; ok {
				sender.Send(notify.FromShield(k, ev, "flood.test", ev.Incident.Start.String()))
			}
		}
	}
	sh, err := shield.New(shield.Config{OnEvent: onEvent,
		MonitorOnly: monitor, KnownAfter: 3, KnownMinAge: 3 * time.Second, MinUnknownRate: 5, ClusterRate: 2,
		// The per-network limit would stop this flood on its own (its bots share four /24s); it is set out of the way so
		// that the attack detection and mitigation are what is measured.
		SubnetRate: 1e6, SubnetBurst: 1e6, ConnRate: 1000, ConnBurst: 1000, MaxConns: 10000,
		Detector: shield.DetectorConfig{Warmup: 4 * time.Second, MinHistory: 3 * time.Second, Tau: time.Minute, MinAttackRate: 50, Confirm: 2,
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
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: d.DialContext, MaxIdleConnsPerHost: 2, DisableKeepAlives: !prof.keepAlive}}
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
	// A count-bounded flood still gets a generous deadline so a wedged client can never hang the test.
	limit := prof.duration
	if prof.budget > 0 {
		limit = 90 * time.Second
	}
	floodCtx, stopFlood := context.WithTimeout(ctx, limit)
	defer stopFlood()
	var claimed atomic.Int64
	more := func() bool {
		if prof.budget == 0 {
			return floodCtx.Err() == nil
		}
		return floodCtx.Err() == nil && claimed.Add(1) <= prof.budget
	}
	var fwg sync.WaitGroup
	for g := 0; g < prof.senders; g++ {
		fwg.Add(1)
		go func(seed uint64) {
			defer fwg.Done()
			r := rand.New(rand.NewPCG(seed, 1))
			for more() {
				i := r.IntN(prof.addrs)
				ok := send(fmt.Sprintf("127.1.%d.%d", i/250, i%250+1), fmt.Sprintf("/?r=%d", r.Int64()), "python-requests/2.32.3")
				atomic.AddInt64(&res.sent, 1)
				if detectedAt.Load() != 0 {
					atomic.AddInt64(&res.attackSent, 1)
					if ok {
						atomic.AddInt64(&res.attackOK, 1)
					}
				}
				if prof.pace > 0 {
					time.Sleep(prof.pace)
				}
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
	res.port = ln.Addr().(*net.TCPAddr).AddrPort().Port()
	if sender != nil {
		sender.Close(5 * time.Second)
		var bad int
		res.alerts, bad = received()
		if st := sender.Stats(); bad != 0 || st.Failed != 0 || st.Dropped != 0 {
			t.Fatalf("alert delivery: %d messages failed verification, stats %+v", bad, st)
		}
	}
	return res
}
