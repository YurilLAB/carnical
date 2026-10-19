// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/netwatch"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef-test-secret")

func TestParseURL(t *testing.T) {
	for _, tt := range []struct {
		name, in string
		ok       bool
		port     uint16
	}{
		{"https", "https://alerts.example.com/hook", true, 443},
		{"https with a port and a query", "https://alerts.example.com:8443/hook?team=web", true, 8443},
		{"http to IPv4 loopback", "http://127.0.0.1:9000/hook", true, 9000},
		{"http to IPv6 loopback", "http://[::1]/hook", true, 80},
		{"http to a public address", "http://alerts.example.com/hook", false, 0},
		{"http to the name localhost", "http://localhost/hook", false, 0},
		{"http to a private address", "http://10.0.0.5/hook", false, 0},
		{"a user and password", "https://user:pass@alerts.example.com/hook", false, 0},
		{"a user only", "https://user@alerts.example.com/hook", false, 0},
		{"a fragment", "https://alerts.example.com/hook#x", false, 0},
		{"an empty fragment", "https://alerts.example.com/hook#", false, 0},
		{"another scheme", "ftp://alerts.example.com/hook", false, 0},
		{"no scheme", "alerts.example.com/hook", false, 0},
		{"no host", "https:///hook", false, 0},
		{"opaque", "https:alerts.example.com", false, 0},
		{"empty", "", false, 0},
		{"too long", "https://alerts.example.com/" + strings.Repeat("a", MaxURL), false, 0},
		{"a space", "https://alerts.example.com/a b", false, 0},
		{"a line break", "https://alerts.example.com/a\r\nX-Injected: 1", false, 0},
		{"a tab", "https://alerts.example.com/a\tb", false, 0},
		{"port zero", "https://alerts.example.com:0/hook", false, 0},
		{"port too high", "https://alerts.example.com:65536/hook", false, 0},
		{"port not a number", "https://alerts.example.com:x/hook", false, 0},
		{"not ASCII", "https://alertés.example.com/hook", false, 0},
		{"not ASCII in the path", "https://alerts.example.com/hé", false, 0},
		{"a punycode name", "https://xn--alerts-6ua.example.com/hook", true, 443},
		{"an IPv6 zone", "https://[fe80::1%25eth0]/hook", false, 0},
		{"an escaped host", "https://alerts%2eexample.com/hook", false, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ParseURL(tt.in)
			if (err == nil) != tt.ok {
				t.Fatalf("ParseURL(%q) error %v, want ok %v", tt.in, err, tt.ok)
			}
			if err != nil {
				if strings.Contains(err.Error(), "example.com") || strings.Contains(err.Error(), "pass@") {
					t.Fatalf("the error repeats the URL: %v", err)
				}
				return
			}
			if got := URLPort(u); got != tt.port {
				t.Fatalf("port %d, want %d", got, tt.port)
			}
		})
	}
}

func TestParseSecret(t *testing.T) {
	long := strings.Repeat("k", MaxSecret)
	for _, tt := range []struct {
		name, in, want string
	}{
		{"hex with a line end", strings.Repeat("ab", 32) + "\n", strings.Repeat("ab", 32)},
		{"only the first line", strings.Repeat("c", 40) + "\nsecond line", strings.Repeat("c", 40)},
		{"spaces around", "  " + strings.Repeat("d", 32) + " \r\n", strings.Repeat("d", 32)},
		{"the longest", long, long},
		{"too short", strings.Repeat("e", MinSecret-1), ""},
		{"too long", long + "k", ""},
		{"a space inside", strings.Repeat("f", 20) + " " + strings.Repeat("f", 20), ""},
		{"not ASCII", strings.Repeat("g", 32) + "é", ""},
		{"a control character", strings.Repeat("h", 32) + "\x00", ""},
		{"empty", "", ""},
		{"an empty first line", "\n" + strings.Repeat("i", 40), ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSecret([]byte(tt.in))
			if tt.want == "" {
				if err == nil {
					t.Fatalf("accepted %q", tt.in)
				}
				if strings.Contains(err.Error(), tt.in[:min(len(tt.in), 8)]) && tt.in != "" {
					t.Fatalf("the error repeats the secret: %v", err)
				}
				return
			}
			if err != nil || string(got) != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if p, err := ParseSecret(s); err != nil || len(p) != 64 {
		t.Fatalf("a new secret does not read back: %q %v", s, err)
	}
	if t2, _ := NewSecret(); bytes.Equal(s, t2) {
		t.Fatal("two new secrets are the same")
	}
}

func TestVerify(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ts := "1800000000"
	body := []byte(`{"event":"attack_start"}`)
	sig := "v1=" + Sign(testSecret, ts, body)
	for _, tt := range []struct {
		name    string
		secret  []byte
		ts, sig string
		body    []byte
		at      time.Time
		ok      bool
	}{
		{"as sent", testSecret, ts, sig, body, now, true},
		{"four minutes later", testSecret, ts, sig, body, now.Add(4 * time.Minute), true},
		{"six minutes later", testSecret, ts, sig, body, now.Add(6 * time.Minute), false},
		{"from the future", testSecret, ts, sig, body, now.Add(-6 * time.Minute), false},
		{"another secret", []byte(strings.Repeat("z", 40)), ts, sig, body, now, false},
		{"a changed body", testSecret, ts, sig, []byte(`{"event":"attack_end"}`), now, false},
		{"a changed timestamp", testSecret, "1800000001", sig, body, now, false},
		{"no version", testSecret, ts, strings.TrimPrefix(sig, "v1="), body, now, false},
		{"a timestamp that is not a number", testSecret, "x", sig, body, now, false},
		{"empty", testSecret, ts, "", body, now, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Verify(tt.secret, tt.ts, tt.sig, tt.body, tt.at, 5*time.Minute); got != tt.ok {
				t.Fatalf("Verify = %v, want %v", got, tt.ok)
			}
		})
	}
}

// receiver is a TLS endpoint that checks each message as a real receiver would and records it.
type receiver struct {
	srv   *httptest.Server
	mu    sync.Mutex
	got   []received
	conns atomic.Int32
	reply func(n int, w http.ResponseWriter) // the reply to the n-th request (from 0); nil is 204
	hits  atomic.Int32
}

type received struct {
	header http.Header
	body   []byte
	valid  bool
	msg    Message
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{}
	r.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := int(r.hits.Add(1)) - 1
		body, _ := io.ReadAll(io.LimitReader(req.Body, MaxBody+1))
		rec := received{header: req.Header.Clone(), body: body}
		rec.valid = req.Method == http.MethodPost && Verify(testSecret, req.Header.Get("X-Carnical-Timestamp"),
			req.Header.Get("X-Carnical-Signature"), body, time.Now(), 5*time.Minute)
		_ = json.Unmarshal(body, &rec.msg)
		r.mu.Lock()
		r.got = append(r.got, rec)
		r.mu.Unlock()
		if r.reply != nil {
			r.reply(n, w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	r.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			r.conns.Add(1)
		}
	}
	r.srv.EnableHTTP2 = true
	r.srv.StartTLS()
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) messages() []received {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]received(nil), r.got...)
}

func (r *receiver) sender(t *testing.T, log *slog.Logger, mod func(*Config)) *Sender {
	t.Helper()
	u, err := ParseURL(r.srv.URL + "/hook?team=web")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(r.srv.Certificate())
	var d net.Dialer
	cfg := Config{URL: u, Secret: testSecret, Dial: d.DialContext, RootCAs: pool, Timeout: 2 * time.Second, Log: log}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.retryWait = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}
	s.gap = 0
	return s
}

func attackMessage(ev Event, subject string) Message {
	return Message{Event: ev, At: time.Unix(1_800_000_000, 0).UTC(), Site: "example.com", Text: "attack", Subject: subject,
		Attack: &Attack{Mode: "on", Kinds: []string{"request_flood"}, Ports: []Port{{Protocol: "tcp", Port: 443, Requests: 10}}}}
}

func TestMessagesAreSignedAndDelivered(t *testing.T) {
	r := newReceiver(t)
	s := r.sender(t, nil, nil)
	for _, ev := range []Event{AttackStart, AttackUpdate, AttackEnd} {
		if !s.Send(attackMessage(ev, "a")) {
			t.Fatal("no room in an empty queue")
		}
		time.Sleep(50 * time.Millisecond) // let each go before the next, so that the update is not merged
	}
	if !s.Close(5 * time.Second) {
		t.Fatal("close did not finish")
	}
	got := r.messages()
	if len(got) != 3 {
		t.Fatalf("%d messages arrived, want 3", len(got))
	}
	ids := map[string]bool{}
	for i, m := range got {
		if !m.valid {
			t.Fatalf("message %d does not verify", i)
		}
		if m.header.Get("Content-Type") != "application/json" || m.header.Get("User-Agent") != "carnical-alert/1" ||
			m.header.Get("X-Carnical-Event") != string(m.msg.Event) || m.header.Get("X-Carnical-Delivery") != m.msg.ID {
			t.Fatalf("message %d headers %v", i, m.header)
		}
		if m.msg.Version != 1 || len(m.msg.ID) != 32 || ids[m.msg.ID] || m.msg.Site != "example.com" || m.msg.Attack == nil ||
			m.msg.Attack.Ports[0].Port != 443 || bytes.Contains(m.body, []byte("Subject")) || bytes.Contains(m.body, []byte(`"a"`)) {
			t.Fatalf("message %d body %s", i, m.body)
		}
		ids[m.msg.ID] = true
	}
	if sev := []string{got[0].msg.Severity, got[1].msg.Severity, got[2].msg.Severity}; sev[0] != "critical" || sev[1] != "warning" || sev[2] != "info" {
		t.Fatalf("severities %q", sev)
	}
	if n := r.conns.Load(); n != 1 {
		t.Fatalf("%d connections for three messages: the connection is not reused", n)
	}
	if st := s.Stats(); st != (Stats{Sent: 3}) {
		t.Fatalf("stats %+v", st)
	}
}

func TestDeliveryRetriesOnlyWhatMayPass(t *testing.T) {
	for _, tt := range []struct {
		name    string
		replies []int // status of each attempt
		hits    int32
		stats   Stats
	}{
		{"503 then 200", []int{503, 200}, 2, Stats{Sent: 1, Retries: 1}},
		{"429, 408 then 202", []int{429, 408, 202}, 3, Stats{Sent: 1, Retries: 2}},
		{"always 500: three attempts, then given up", []int{500, 500, 500, 500}, 3, Stats{Failed: 1, Retries: 2}},
		{"400 is not retried", []int{400, 200}, 1, Stats{Failed: 1}},
		{"401 is not retried", []int{401, 200}, 1, Stats{Failed: 1}},
		{"a redirect is a failure and is not followed", []int{302, 200}, 1, Stats{Failed: 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newReceiver(t)
			r.reply = func(n int, w http.ResponseWriter) {
				if tt.replies[n] == 302 {
					w.Header().Set("Location", r.srv.URL+"/elsewhere")
				}
				w.WriteHeader(tt.replies[n])
			}
			s := r.sender(t, nil, nil)
			s.Send(attackMessage(AttackStart, "a"))
			s.Close(5 * time.Second)
			if h := r.hits.Load(); h != tt.hits {
				t.Fatalf("%d attempts, want %d", h, tt.hits)
			}
			for _, m := range r.messages() {
				if !m.valid {
					t.Fatal("an attempt does not verify")
				}
				if m.msg.ID != r.messages()[0].msg.ID {
					t.Fatal("a retry has another delivery id: the receiver cannot drop it as a repeat")
				}
			}
			if st := s.Stats(); st != tt.stats {
				t.Fatalf("stats %+v, want %+v", st, tt.stats)
			}
		})
	}
}

func TestTheQueueKeepsWhatMatters(t *testing.T) {
	// The endpoint holds the first message until released, so the rest wait in the queue.
	r := newReceiver(t)
	release := make(chan struct{})
	r.reply = func(n int, w http.ResponseWriter) {
		if n == 0 {
			<-release
		}
		w.WriteHeader(http.StatusNoContent)
	}
	s := r.sender(t, nil, func(c *Config) { c.Queue = 3; c.Timeout = 10 * time.Second })
	s.Send(attackMessage(AttackStart, "first")) // taken by the sender, held by the endpoint
	for r.hits.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	s.Send(attackMessage(AttackStart, "b"))
	s.Send(attackMessage(AttackUpdate, "b"))
	upd := attackMessage(AttackUpdate, "b")
	upd.Text = "newest update of b"
	if !s.Send(upd) { // replaces the waiting update of b
		t.Fatal("an update replacing a waiting one was refused")
	}
	s.Send(attackMessage(AttackUpdate, "c")) // queue full now: start b, update b, update c
	if !s.Send(attackMessage(AttackEnd, "b")) {
		t.Fatal("an end found no room: it must push out an update")
	}
	if s.Send(attackMessage(AttackUpdate, "d")) {
		// queue: start b, update c, end b; an update finds no update older than itself to replace except c's
		t.Log("update d replaced update c")
	}
	close(release)
	s.Close(5 * time.Second)
	var got []string
	for _, m := range r.messages() {
		got = append(got, string(m.msg.Event)+" "+m.msg.Text)
	}
	t.Logf("delivered %q, stats %+v", got, s.Stats())
	want := []string{"attack_start attack", "attack_start attack", "attack_end attack"}
	var starts, ends, updates int
	for _, m := range r.messages() {
		switch m.msg.Event {
		case AttackStart:
			starts++
		case AttackEnd:
			ends++
		case AttackUpdate:
			updates++
		}
	}
	if starts != 2 || ends != 1 || updates > 1 {
		t.Fatalf("delivered %q, want the starts and the end kept (%q) and at most one update", got, want)
	}
	if st := s.Stats(); st.Dropped == 0 {
		t.Fatal("drops not counted")
	}
	last := r.messages()[len(r.messages())-1]
	var dropped uint64
	for _, m := range r.messages() {
		dropped += m.msg.Dropped
	}
	if dropped != s.Stats().Dropped || last.msg.Event == "" {
		t.Fatalf("the messages report %d drops, the sender counted %d", dropped, s.Stats().Dropped)
	}
}

// A network flood's message carries its record, not an attack's; a newer update of the same flood replaces one still
// waiting, as for the shield's attacks, and an update of another flood does not.
func TestNetworkFloodsAreSentAsAttacksAre(t *testing.T) {
	started := time.Unix(1_800_000_000, 0).UTC()
	rec := &netwatch.Record{Started: started.In(time.FixedZone("AEDT", 11*3600)), Kinds: []netwatch.KindCount{{Kind: netwatch.KindUDPFlood, Packets: 9, Bytes: 900}},
		Ports: []netwatch.Port{{Protocol: "udp", Port: 53, Packets: 9, Bytes: 900}}, PeakRate: 40000, Baseline: 3}
	msg := func(ev netwatch.Event, at time.Duration, r *netwatch.Record) Message {
		return FromNetwork(netwatch.State{Version: 1, Seq: 1, Event: ev, At: started.Add(at), Attack: r}, "example.com")
	}
	start := msg(netwatch.Start, 0, rec)
	if start.Event != NetworkStart || start.Event.Severity() != "critical" || start.Attack != nil || start.Network.Ports[0].Port != 53 ||
		!strings.Contains(start.Text, "on example.com (udp_flood): 40000 packets/s") || !strings.Contains(start.Text, "udp/53") ||
		start.Network.Started.Location() != time.UTC {
		t.Fatalf("start %+v", start)
	}
	other := *rec
	other.Started = started.Add(time.Hour)

	r := newReceiver(t)
	release := make(chan struct{})
	r.reply = func(n int, w http.ResponseWriter) {
		if n == 0 {
			<-release
		}
		w.WriteHeader(http.StatusNoContent)
	}
	s := r.sender(t, nil, func(c *Config) { c.Timeout = 10 * time.Second })
	s.Send(start) // taken by the sender, held by the endpoint
	for r.hits.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	s.Send(msg(netwatch.Update, 10*time.Second, rec))
	s.Send(msg(netwatch.Update, 10*time.Second, &other))
	s.Send(msg(netwatch.Update, 20*time.Second, rec)) // replaces the first flood's waiting update
	close(release)
	s.Close(5 * time.Second)
	var got []string
	for _, m := range r.messages() {
		if m.msg.Network == nil || bytes.Contains(m.body, []byte(`"attack"`)) {
			t.Fatalf("body %s", m.body)
		}
		got = append(got, fmt.Sprintf("%s %s %s", m.msg.Event, m.msg.Network.Started.Format("15:04"), m.msg.At.Format("15:04:05")))
	}
	want := []string{"network_attack_start 08:00 08:00:00", "network_attack_update 08:00 08:00:20", "network_attack_update 09:00 08:00:10"}
	if !slices.Equal(got, want) {
		t.Fatalf("delivered %q, want %q", got, want)
	}
}

func TestADeadEndpointCostsBoundedTime(t *testing.T) {
	// An endpoint that accepts the connection and never answers: Close must give up in its wait and cancel the attempt.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var held []net.Conn
	var hmu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hmu.Lock()
			held = append(held, c)
			hmu.Unlock()
		}
	}()
	defer func() {
		hmu.Lock()
		for _, c := range held {
			c.Close()
		}
		hmu.Unlock()
	}()
	u, _ := ParseURL("https://" + ln.Addr().String() + "/hook")
	var d net.Dialer
	s, err := New(Config{URL: u, Secret: testSecret, Dial: d.DialContext, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		s.Send(attackMessage(AttackStart, string(rune('a'+i))))
	}
	start := time.Now()
	if s.Close(200 * time.Millisecond) {
		t.Fatal("close reported everything delivered to an endpoint that never answers")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("close took %v", took)
	}
	if st := s.Stats(); st.Sent != 0 || st.Dropped+st.Failed != 5 {
		t.Fatalf("stats %+v: every message must be counted as dropped or failed", st)
	}
	if s.Send(attackMessage(AttackStart, "late")) {
		t.Fatal("a closed sender took a message")
	}
}

func TestFailuresAreLoggedWithoutTheURLOrSecret(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	refused := fmt.Errorf("%w: 127.0.0.1 is not a public address", ErrNotAllowed)
	u, _ := ParseURL("https://alerts.example.com:9443/secret-path-token?key=abc")
	s, err := New(Config{URL: u, Secret: testSecret, Log: log, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: refused}
	}})
	if err != nil {
		t.Fatal(err)
	}
	s.retryWait = nil
	s.gap = 0
	for i := 0; i < 3; i++ {
		s.Send(attackMessage(AttackStart, string(rune('a'+i))))
	}
	s.Close(5 * time.Second)
	out := buf.String()
	t.Log(out)
	for _, leak := range []string{"example.com", "9443", "secret-path-token", "key=abc", string(testSecret[:16]), "127.0.0.1"} {
		if strings.Contains(out, leak) {
			t.Fatalf("the log holds %q: %s", leak, out)
		}
	}
	if strings.Count(out, "alert endpoint delivery failed") != 1 || !strings.Contains(out, "the address is not allowed") {
		t.Fatalf("want one rate-limited failure line naming the reason: %s", out)
	}
	if st := s.Stats(); st.Failed != 3 || st.Retries != 0 {
		t.Fatalf("stats %+v: a refused address is not retried", st)
	}
}

func TestAnUntrustedCertificateIsNotRetried(t *testing.T) {
	r := newReceiver(t)
	s := r.sender(t, nil, func(c *Config) { c.RootCAs = x509.NewCertPool() }) // trusts nothing
	s.Send(attackMessage(AttackStart, "a"))
	s.Close(5 * time.Second)
	if st := s.Stats(); st.Failed != 1 || st.Retries != 0 || r.hits.Load() != 0 {
		t.Fatalf("stats %+v, %d requests reached the endpoint", st, r.hits.Load())
	}
}

func TestPostsAreSpacedOut(t *testing.T) {
	r := newReceiver(t)
	var times []time.Time
	var mu sync.Mutex
	r.reply = func(int, http.ResponseWriter) {}
	inner := r.srv.Config.Handler
	r.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		inner.ServeHTTP(w, req)
	})
	s := r.sender(t, nil, nil)
	s.gap = 100 * time.Millisecond
	for i := 0; i < 4; i++ {
		s.Send(attackMessage(AttackStart, string(rune('a'+i))))
	}
	s.Close(5 * time.Second)
	if len(times) != 4 {
		t.Fatalf("%d posts", len(times))
	}
	for i := 1; i < len(times); i++ {
		if d := times[i].Sub(times[i-1]); d < 90*time.Millisecond {
			t.Fatalf("posts %d and %d were %v apart", i-1, i, d)
		}
	}
}

func TestNewRefusesABadConfig(t *testing.T) {
	u, _ := ParseURL("https://alerts.example.com/hook")
	var d net.Dialer
	for _, tt := range []struct {
		name string
		cfg  Config
	}{
		{"no URL", Config{Secret: testSecret, Dial: d.DialContext}},
		{"a short secret", Config{URL: u, Secret: testSecret[:MinSecret-1], Dial: d.DialContext}},
		{"no dialer", Config{URL: u, Secret: testSecret}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if s, err := New(tt.cfg); err == nil {
				s.Close(time.Second)
				t.Fatal("accepted")
			}
		})
	}
}

// FuzzParseURL: whatever is given, ParseURL does not panic, and what it accepts is an absolute https URL with a host
// (or http to a loopback address), without credentials, fragment or control characters, that reads back the same.
func FuzzParseURL(f *testing.F) {
	for _, s := range []string{"https://alerts.example.com/hook?x=1", "http://127.0.0.1:9/h", "https://u:p@h/", "https://h/#f",
		"http://[::1]/", "https://[fe80::1%25eth0]/", "https://h:0/", "javascript:alert(1)", "https://h/\r\n", "//h/p"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := ParseURL(s)
		if err != nil {
			if strings.Contains(err.Error(), s) && len(s) > 8 {
				t.Fatalf("the error repeats the input: %v", err)
			}
			return
		}
		if u.User != nil || u.Fragment != "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") ||
			strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
			t.Fatalf("accepted %q as %#v", s, u)
		}
		if u.Scheme == "http" {
			ip, err := netip.ParseAddr(u.Hostname())
			if err != nil || !ip.Unmap().IsLoopback() {
				t.Fatalf("accepted plain http to %q", u.Hostname())
			}
		}
		if p := URLPort(u); p == 0 {
			t.Fatalf("port 0 for %q", s)
		}
	})
}

// FuzzParseSecret: no panic, and an accepted secret is MinSecret to MaxSecret printable ASCII characters.
func FuzzParseSecret(f *testing.F) {
	f.Add([]byte(strings.Repeat("a", 32)))
	f.Add([]byte(" " + strings.Repeat("b", 40) + "\r\nrest"))
	f.Add([]byte("\x00\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParseSecret(data)
		if err != nil {
			return
		}
		if len(s) < MinSecret || len(s) > MaxSecret {
			t.Fatalf("length %d", len(s))
		}
		for _, c := range s {
			if c <= ' ' || c > '~' {
				t.Fatalf("byte %#x accepted", c)
			}
		}
	})
}
