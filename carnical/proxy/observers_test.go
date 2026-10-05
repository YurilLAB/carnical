package proxy

import (
	"sync"
	"testing"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

type observation struct {
	path   string
	status int
	body   string
}

type recorder struct {
	mu  sync.Mutex
	got []observation
}

func (r *recorder) Observe(req *inspect.Request, status int) {
	r.mu.Lock()
	r.got = append(r.got, observation{req.Path, status, string(req.Body)})
	r.mu.Unlock()
}

func (r *recorder) all() []observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]observation(nil), r.got...)
}

func TestObserversAreToldWhatTheApplicationAnsweredAndOnlyForRequestsThatWentThrough(t *testing.T) {
	var rec recorder
	block := fakeInspector{"blocker", func(r *inspect.Request) inspect.Result {
		if r.Path == "/refused" {
			return inspect.Result{Verdicts: []inspect.Verdict{{ID: 5001001, Block: true}}}
		}
		return inspect.Result{}
	}}
	s := start(t, func(c *Config) {
		ruleSetOff(c)
		c.Inspectors = []inspect.Inspector{block}
		c.Observers = []inspect.Observer{&rec}
	})
	s.raw(t, get("/page"))
	s.raw(t, get("/refused"))
	s.raw(t, post("a=1"))
	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("%d observations, want 2 (the refused request is not observed): %+v", len(got), got)
	}
	if got[0] != (observation{"/page", 200, ""}) || got[1] != (observation{"/submit", 200, "a=1"}) {
		t.Fatalf("%+v", got)
	}
}

func TestOnlyASingleGzipOrDeflateEncodingIsLetThroughWhenAllowed(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		allow   bool
		want    int
	}{
		{"gzip, not allowed", []string{"Content-Encoding: gzip\r\n"}, false, 415},
		{"gzip, allowed", []string{"Content-Encoding: gzip\r\n"}, true, 200},
		{"deflate, allowed", []string{"Content-Encoding: deflate\r\n"}, true, 200},
		{"identity", []string{"Content-Encoding: identity\r\n"}, false, 200},
		{"brotli, allowed", []string{"Content-Encoding: br\r\n"}, true, 415},
		{"two layers, allowed", []string{"Content-Encoding: gzip, gzip\r\n"}, true, 415},
		{"two headers, allowed", []string{"Content-Encoding: gzip\r\n", "Content-Encoding: gzip\r\n"}, true, 415},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := start(t, func(c *Config) { ruleSetOff(c); c.AllowRequestEncoding = tt.allow })
			status, _ := s.raw(t, get("/page", tt.headers...))
			if status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
		})
	}
}
