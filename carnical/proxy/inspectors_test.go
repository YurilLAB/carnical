// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/apiguard"
	"github.com/YurilLAB/coraza/carnical/inspect"
	"github.com/YurilLAB/coraza/carnical/vpatch"
)

// fakeInspector runs a function, so that each test says what its inspector does.
type fakeInspector struct {
	name string
	fn   func(*inspect.Request) inspect.Result
}

func (f fakeInspector) Name() string                              { return f.name }
func (f fakeInspector) Inspect(r *inspect.Request) inspect.Result { return f.fn(r) }

type matches struct {
	mu sync.Mutex
	m  []Match
}

func (s *matches) record(m Match) { s.mu.Lock(); s.m = append(s.m, m); s.mu.Unlock() }
func (s *matches) all() []Match {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Match(nil), s.m...)
}

func TestInspectorsRefuseRecordAndPassOn(t *testing.T) {
	block := fakeInspector{"blocker", func(r *inspect.Request) inspect.Result {
		if strings.HasPrefix(r.Path, "/evil") {
			return inspect.Result{Verdicts: []inspect.Verdict{{ID: 5001001, Message: "an evil path", Block: true, Status: 418, Severity: "high"}}}
		}
		return inspect.Result{}
	}}
	watch := fakeInspector{"watcher", func(r *inspect.Request) inspect.Result {
		if strings.HasPrefix(r.Path, "/odd") {
			return inspect.Result{Verdicts: []inspect.Verdict{{ID: 5001002, Message: "an odd path", Severity: "low"}}}
		}
		return inspect.Result{}
	}}
	var seen matches
	s := start(t, func(c *Config) {
		ruleSetOff(c)
		c.Inspectors = []inspect.Inspector{block, watch}
		c.OnMatch = seen.record
	})

	if status, _ := s.raw(t, get("/evil/x")); status != 418 {
		t.Fatalf("a blocked request: %d, want 418", status)
	}
	if n := len(s.up.requests()); n != 0 {
		t.Fatalf("a blocked request reached the application (%d)", n)
	}
	if status, _ := s.raw(t, get("/odd/x")); status != 200 {
		t.Fatalf("a request that is only watched: %d, want 200", status)
	}
	if status, _ := s.raw(t, get("/fine")); status != 200 {
		t.Fatalf("an ordinary request: %d", status)
	}
	got := seen.all()
	if len(got) != 2 || got[0].RuleID != 5001001 || !got[0].Disruptive || got[0].Severity != "HIGH" || got[1].RuleID != 5001002 || got[1].Disruptive {
		t.Fatalf("what was recorded: %+v", got)
	}
}

func TestInspectorsSeeTheBodyAndCanReplaceItAndTheHeaders(t *testing.T) {
	var firstSaw, secondSaw string
	first := fakeInspector{"first", func(r *inspect.Request) inspect.Result {
		firstSaw = string(r.Body)
		return inspect.Result{Body: []byte(strings.ToUpper(string(r.Body))), DelHeader: []string{"X-Remove-Me"}, SetHeader: map[string]string{"X-Added": "by-inspector"}}
	}}
	second := fakeInspector{"second", func(r *inspect.Request) inspect.Result {
		secondSaw = string(r.Body)
		return inspect.Result{}
	}}
	for _, chunked := range []bool{false, true} {
		name := "with a length"
		if chunked {
			name = "chunked"
		}
		t.Run(name, func(t *testing.T) {
			s := start(t, func(c *Config) { ruleSetOff(c); c.Inspectors = []inspect.Inspector{first, second} })
			body := "a=hello&b=world"
			request := "POST /submit HTTP/1.1\r\n" + preamble + "X-Remove-Me: yes\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n"
			if chunked {
				request += "Transfer-Encoding: chunked\r\n\r\n" + strconv.FormatInt(int64(len(body)), 16) + "\r\n" + body + "\r\n0\r\n\r\n"
			} else {
				request += "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
			}
			if status, _ := s.raw(t, request); status != 200 {
				t.Fatalf("status %d", status)
			}
			got := s.up.requests()
			if len(got) != 1 {
				t.Fatalf("%d requests", len(got))
			}
			if firstSaw != body || secondSaw != strings.ToUpper(body) {
				t.Fatalf("the first inspector saw %q and the second %q", firstSaw, secondSaw)
			}
			if string(got[0].Body) != strings.ToUpper(body) {
				t.Fatalf("the application received %q", got[0].Body)
			}
			if got[0].Header.Get("X-Remove-Me") != "" || got[0].Header.Get("X-Added") != "by-inspector" {
				t.Fatalf("header edits: %v", got[0].Header)
			}
		})
	}
}

func TestInspectorsRunOnARequestWithNoBody(t *testing.T) {
	var sawBody bool
	called := 0
	s := start(t, func(c *Config) {
		ruleSetOff(c)
		c.Inspectors = []inspect.Inspector{fakeInspector{"x", func(r *inspect.Request) inspect.Result {
			called++
			sawBody = r.Body != nil
			if r.Method != "GET" || r.Path != "/a/b" || r.RawQuery != "x=1" || r.Host != "shop.example.test" || !r.Client.IsValid() {
				t.Errorf("the request as inspected: %+v", r)
			}
			return inspect.Result{}
		}}}
	})
	s.raw(t, get("/a/b?x=1"))
	if called != 1 || sawBody {
		t.Fatalf("called %d times, saw a body: %v", called, sawBody)
	}
}

func TestAnInspectorThatPanicsRefusesTheRequestAndNotTheProxy(t *testing.T) {
	// armed makes the clocks below panic, so that the guard and the engine fail inside Inspect, where a bug of theirs would.
	var armed atomic.Bool
	clock := func() time.Time {
		if armed.Load() {
			panic("SECRET_INSPECTOR_CREDENTIAL")
		}
		return time.Now()
	}
	guard := func(mode apiguard.Mode) inspect.Inspector {
		g, err := apiguard.New(apiguard.Config{Mode: mode, Clock: clock})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	patches := func(mode vpatch.Mode) inspect.Inspector {
		e := vpatch.New(vpatch.Options{Mode: mode, Now: clock})
		rep := e.Load([]vpatch.Signature{{ID: "NEVER", Category: "other", Severity: "high", Description: "a path never asked for",
			Condition: vpatch.Condition{Operator: "contains", Pattern: "/never", Targets: []string{"path"}}}})
		if rep.LoadedTotal != 1 {
			t.Fatalf("the signature was not loaded: %+v", rep)
		}
		return e
	}
	boom := fakeInspector{"boom", func(r *inspect.Request) inspect.Result {
		if armed.Load() {
			panic(r.RawQuery)
		}
		return inspect.Result{}
	}}
	tests := []struct {
		name       string
		inspector  inspect.Inspector
		want       int
		id         int
		disruptive bool
	}{
		{"an inspector with no recovery of its own", boom, http.StatusServiceUnavailable, idInspectorFailed, true},
		{"the API guard in enforce", guard(apiguard.ModeEnforce), http.StatusServiceUnavailable, apiguard.IDInternalError, true},
		{"the API guard in monitor", guard(apiguard.ModeMonitor), http.StatusOK, apiguard.IDInternalError, false},
		{"the virtual patches in block", patches(vpatch.ModeBlock), http.StatusServiceUnavailable, vpatch.IDInternalError, true},
		{"the virtual patches in monitor", patches(vpatch.ModeMonitor), http.StatusOK, vpatch.IDInternalError, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen matches
			s := start(t, func(c *Config) {
				ruleSetOff(c)
				c.Inspectors = []inspect.Inspector{tt.inspector}
				c.OnMatch = seen.record
			})
			armed.Store(true)
			status, _ := s.raw(t, get("/api/boom?token=SECRET_INSPECTOR_CREDENTIAL"))
			armed.Store(false)
			if status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
			if reached := len(s.up.requests()) > 0; reached != (tt.want == http.StatusOK) {
				t.Fatalf("reached the application: %v", reached)
			}
			if got := seen.all(); len(got) != 1 || got[0].RuleID != tt.id || got[0].Disruptive != tt.disruptive {
				t.Fatalf("what was recorded: %+v", got)
			}
			for _, m := range seen.all() {
				if strings.Contains(m.Message+m.ExpandedMessage, "SECRET_INSPECTOR_CREDENTIAL") {
					t.Fatal("default failure log exposes panic data")
				}
			}
			if status, _ := s.raw(t, get("/api/fine")); status != 200 {
				t.Fatalf("the proxy did not carry on: %d", status)
			}
		})
	}
}

func TestUploadsStillReachInspectorsWithTheirBody(t *testing.T) {
	var size int
	s := start(t, func(c *Config) {
		ruleSetOff(c)
		c.CRS.RequestBodyLimit = 1 << 20
		c.Inspectors = []inspect.Inspector{fakeInspector{"x", func(r *inspect.Request) inspect.Result {
			size = len(r.Body)
			if r.ContentType() != "multipart/form-data" {
				t.Errorf("content type %q", r.ContentType())
			}
			return inspect.Result{}
		}}}
	})
	body := multipartBody(filePart("photo.jpg", strings.Repeat("A", 5000)))
	if status, _ := s.raw(t, uploadRequest(body)); status != 200 {
		t.Fatalf("status %d", status)
	}
	if size != len(body) {
		t.Fatalf("the inspector saw %d bytes of %d", size, len(body))
	}
	got := s.up.requests()
	if len(got) != 1 || len(got[0].Body) != len(body) {
		t.Fatalf("the application received %d bytes", len(got[0].Body))
	}
}

func TestContentType(t *testing.T) {
	tests := map[string]string{"": "", "text/plain": "text/plain", "Application/JSON; charset=UTF-8": "application/json", " multipart/form-data ;boundary=x": "multipart/form-data"}
	for in, want := range tests {
		r := &inspect.Request{Header: http.Header{"Content-Type": {in}}}
		if got := r.ContentType(); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
