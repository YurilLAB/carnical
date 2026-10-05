package formats_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/formats"
	"github.com/YurilLAB/coraza/carnical/inspect"
	"github.com/YurilLAB/coraza/carnical/proxy"
)

// These tests run the inspector inside the real proxy, with a real application behind it, and look at what the application received.

type received struct {
	header        http.Header
	body          []byte
	contentLength int64
	transfer      []string
}

type app struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []received
}

func (a *app) requests() []received {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]received(nil), a.reqs...)
}

type matches struct {
	mu sync.Mutex
	m  []proxy.Match
}

func (s *matches) record(m proxy.Match) { s.mu.Lock(); s.m = append(s.m, m); s.mu.Unlock() }
func (s *matches) all() []proxy.Match {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]proxy.Match(nil), s.m...)
}

type edge struct {
	app   *app
	addr  string
	seen  *matches
	proxy *proxy.Edge
}

var loopback = proxy.OriginPolicy{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}}

func startEdge(t *testing.T, pol formats.Policy, allowEncoding bool) *edge {
	t.Helper()
	a := &app{}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		a.mu.Lock()
		a.reqs = append(a.reqs, received{r.Header.Clone(), body, r.ContentLength, append([]string(nil), r.TransferEncoding...)})
		a.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("reached the application"))
	}))
	t.Cleanup(a.Close)
	target, _ := url.Parse(a.URL)
	in := formats.New(pol)
	if in.Err() != nil {
		t.Fatal(in.Err())
	}
	seen := &matches{}
	cfg := proxy.Config{Upstream: target, CRS: crs.DefaultSettings(), Origin: loopback, Inspectors: []inspect.Inspector{in},
		AllowRequestEncoding: allowEncoding, OnMatch: seen.record}
	cfg.CRS.Mode = crs.ModeOff // the rule set is not under test: these checks must hold with it off
	e, err := proxy.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = e.Server("")
	srv.Start()
	t.Cleanup(srv.Close)
	return &edge{a, strings.TrimPrefix(srv.URL, "http://"), seen, e}
}

// send writes exactly these bytes and returns the status of the response.
func (e *edge) send(t *testing.T, raw string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", e.addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	io.Copy(&out, conn)
	resp, err := http.ReadResponse(bufio.NewReader(&out), nil)
	if err != nil {
		t.Fatalf("no response: %v (%q)", err, out.String())
	}
	return resp.StatusCode
}

const preamble = "Host: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: */*\r\nConnection: close\r\n"

func post(path, contentType string, extra []string, body string) string {
	h := "POST " + path + " HTTP/1.1\r\n" + preamble
	if contentType != "" {
		h += "Content-Type: " + contentType + "\r\n"
	}
	for _, e := range extra {
		h += e + "\r\n"
	}
	return h + "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

func gzipped(s string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

func TestGzipJSONReachesTheApplicationDecompressedWithTheRightLength(t *testing.T) {
	json := `{"user":"alice","note":"` + strings.Repeat("a long and repetitive note ", 40) + `","roles":["admin","dev"]}`
	packed := gzipped(json)
	if len(packed) >= len(json) {
		t.Fatalf("the test body does not compress: %d >= %d", len(packed), len(json))
	}
	e := startEdge(t, formats.Policy{}, true)

	t.Run("with a content length", func(t *testing.T) {
		if status := e.send(t, post("/api/save", "application/json", []string{"Content-Encoding: gzip"}, packed)); status != 200 {
			t.Fatalf("status %d", status)
		}
		got := e.app.requests()
		last := got[len(got)-1]
		if string(last.body) != json {
			t.Fatalf("the application received %d bytes that are not the decompressed body", len(last.body))
		}
		if last.contentLength != int64(len(json)) {
			t.Fatalf("Content-Length %d, want %d", last.contentLength, len(json))
		}
		if last.header.Get("Content-Encoding") != "" {
			t.Fatalf("Content-Encoding reached the application: %q", last.header.Get("Content-Encoding"))
		}
		if len(last.transfer) != 0 {
			t.Fatalf("Transfer-Encoding %v", last.transfer)
		}
		if last.header.Get("Content-Length") != strconv.Itoa(len(json)) {
			t.Fatalf("the Content-Length header is %q", last.header.Get("Content-Length"))
		}
	})
	t.Run("sent in chunks", func(t *testing.T) {
		chunks := ""
		for i := 0; i < len(packed); i += 17 {
			end := min(i+17, len(packed))
			chunks += strconv.FormatInt(int64(end-i), 16) + "\r\n" + packed[i:end] + "\r\n"
		}
		raw := "POST /api/save HTTP/1.1\r\n" + preamble + "Content-Type: application/json\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks + "0\r\n\r\n"
		before := len(e.app.requests())
		if status := e.send(t, raw); status != 200 {
			t.Fatalf("status %d", status)
		}
		got := e.app.requests()
		if len(got) != before+1 {
			t.Fatalf("%d requests reached the application", len(got)-before)
		}
		last := got[len(got)-1]
		if string(last.body) != json || last.contentLength != int64(len(json)) || len(last.transfer) != 0 || last.header.Get("Content-Encoding") != "" {
			t.Fatalf("body %d bytes, length %d, transfer %v, encoding %q", len(last.body), last.contentLength, last.transfer, last.header.Get("Content-Encoding"))
		}
	})
	t.Run("without the setting the proxy refuses it", func(t *testing.T) {
		strict := startEdge(t, formats.Policy{}, false)
		if status := strict.send(t, post("/api/save", "application/json", []string{"Content-Encoding: gzip"}, packed)); status != 415 {
			t.Fatalf("status %d", status)
		}
		if n := len(strict.app.requests()); n != 0 {
			t.Fatalf("%d requests reached the application", n)
		}
	})
}

func TestARefusedBodyNeverReachesTheApplication(t *testing.T) {
	bomb := gzipped(strings.Repeat("0", 1<<20))
	if len(bomb) > 100<<10 {
		t.Fatalf("the bomb is %d bytes", len(bomb))
	}
	manyParams := make([]string, 5000)
	for i := range manyParams {
		manyParams[i] = "p" + strconv.Itoa(i) + "=v"
	}
	mpBase64 := "--B\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Transfer-Encoding: base64\r\n\r\nPHNjcmlwdD4=\r\n--B--\r\n"
	batch := "[" + strings.Repeat(`{"query":"{ a }"},`, 49) + `{"query":"{ a }"}]`
	tests := []struct {
		name     string
		raw      string
		status   int
		ruleID   int
		encoding bool
	}{
		{"duplicate keys with different case", post("/api", "application/json", nil, `{"role":"user","Role":"admin"}`), 400, 5002103, false},
		{"a unicode-escaped duplicate key", post("/api", "application/json", nil, `{"a":1,"`+string([]byte{92, 'u'})+`0061":2}`), 400, 5002103, false},
		{"json in utf-16", post("/api", "application/json", nil, "{\x00\"\x00a\x00\"\x00:\x001\x00}\x00"), 400, 5002020, false},
		{"json with a byte order mark", post("/api", "application/json", nil, "\xef\xbb\xbf{\"a\":1}"), 400, 5002023, false},
		{"json labelled text/plain", post("/api", "text/plain", nil, `{"transfer":1000}`), 415, 5002040, false},
		{"json labelled as a form", post("/api", "application/x-www-form-urlencoded", nil, `{"transfer":1000}`), 415, 5002040, false},
		{"a doctype with an entity", post("/soap", "text/xml", nil, `<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>`), 400, 5002202, false},
		{"a gzip bomb at a ratio of a thousand", post("/api", "application/json", []string{"Content-Encoding: gzip"}, bomb), 413, 5002075, true},
		{"two layers of gzip", post("/api", "application/json", []string{"Content-Encoding: gzip, gzip"}, gzipped(gzipped(`{}`))), 415, 0, true},
		{"a graphql batch of fifty", post("/graphql", "application/json", nil, batch), 400, 5002305, false},
		{"a graphql introspection query", post("/graphql", "application/json", nil, `{"query":"{ __schema { types { name } } }"}`), 403, 5002306, false},
		{"a multipart body with base64 inside", post("/upload", "multipart/form-data; boundary=B", nil, mpBase64), 400, 5002709, false},
		{"a form with five thousand parameters", post("/api", "application/x-www-form-urlencoded", nil, strings.Join(manyParams, "&")), 400, 5002603, false},
		{"a form with a semicolon", post("/api", "application/x-www-form-urlencoded", nil, "a=1;b=2"), 400, 5002605, false},
		{"an opaque body", post("/api", "application/octet-stream", nil, "\x00\x01\x02"), 415, 5002002, false},
		{"yaml, which is not accepted by default", post("/api", "application/yaml", nil, "a: !!python/object/apply:os.system [id]\n"), 415, 5002001, false},
		{"utf-16 declared on a form", post("/api", "application/x-www-form-urlencoded; charset=utf-16", nil, "a=1"), 415, 5002006, false},
		{"a body with no type", post("/api", "", nil, "a=1"), 415, 5002004, false},
		{"gzip of json with a duplicate key", post("/api", "application/json", []string{"Content-Encoding: gzip"}, gzipped(`{"a":1,"a":2}`)), 400, 5002103, true},
		{"a get with a body", "GET /page HTTP/1.1\r\n" + preamble + "Content-Length: 5\r\n\r\nhello", 400, 5002009, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := startEdge(t, formats.Policy{}, true)
			if status := e.send(t, tc.raw); status != tc.status {
				t.Fatalf("status %d, want %d", status, tc.status)
			}
			if n := len(e.app.requests()); n != 0 {
				t.Fatalf("the refused body reached the application (%d requests)", n)
			}
			if tc.ruleID != 0 {
				var found bool
				for _, m := range e.seen.all() {
					if m.RuleID == tc.ruleID && m.Disruptive {
						found = true
					}
					if strings.Contains(m.Message, "alice") || strings.Contains(m.Message, "etc/passwd") {
						t.Fatalf("a message quotes the request: %s", m.Message)
					}
				}
				if !found {
					t.Fatalf("rule %d was not recorded: %+v", tc.ruleID, e.seen.all())
				}
			}
		})
	}
}

func TestAcceptedBodiesReachTheApplicationUnchanged(t *testing.T) {
	mp := "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\nContent-Type: text/plain\r\n\r\nfile text\r\n--B--\r\n"
	tests := []struct{ name, ct, body string }{
		{"json", "application/json", `{"a":1,"b":[true,null],"c":{"d":"é"}}`},
		{"a json api type", "application/vnd.api+json", `{"data":{"type":"x"}}`},
		{"a form", "application/x-www-form-urlencoded", "a=1&b=hello+world&tags[]=x&tags[]=y"},
		{"multipart", "multipart/form-data; boundary=B", mp},
		{"xml", "text/xml; charset=utf-8", `<?xml version="1.0"?><methodCall><methodName>x</methodName></methodCall>`},
		{"graphql", "application/json", `{"query":"query Q($id: ID!) { user(id: $id) { name } }","variables":{"id":"1"}}`},
		{"ndjson", "application/x-ndjson", "{\"a\":1}\n{\"a\":2}\n"},
		{"plain text", "text/plain", "just some text"},
	}
	e := startEdge(t, formats.Policy{}, true)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := len(e.app.requests())
			path := "/api"
			if tc.name == "graphql" {
				path = "/graphql"
			}
			if status := e.send(t, post(path, tc.ct, nil, tc.body)); status != 200 {
				t.Fatalf("status %d", status)
			}
			got := e.app.requests()
			if len(got) != before+1 {
				t.Fatalf("%d requests reached the application", len(got)-before)
			}
			if last := got[len(got)-1]; string(last.body) != tc.body || last.contentLength != int64(len(tc.body)) {
				t.Fatalf("the body changed: %d bytes, length %d", len(last.body), last.contentLength)
			}
		})
	}
	for _, m := range e.seen.all() {
		t.Errorf("an accepted body produced a finding: %+v", m)
	}
}

func TestMonitorModeLetsTheBodyThroughAndRecordsIt(t *testing.T) {
	body := `{"role":"user","Role":"admin"}`
	e := startEdge(t, formats.Policy{Monitor: true}, true)
	if status := e.send(t, post("/api", "application/json", nil, body)); status != 200 {
		t.Fatalf("status %d", status)
	}
	got := e.app.requests()
	if len(got) != 1 || string(got[0].body) != body {
		t.Fatalf("the application received %d requests", len(got))
	}
	found := false
	for _, m := range e.seen.all() {
		if m.RuleID == 5002103 {
			found = true
			if m.Disruptive {
				t.Fatal("recorded as disruptive in monitor mode")
			}
		}
	}
	if !found {
		t.Fatalf("not recorded: %+v", e.seen.all())
	}
}

// TestAFindingTheSiteTurnedOffIsNotRecorded: the same body, with the rule off, passes without a trace.
func TestARuleSetToOffIsSilent(t *testing.T) {
	e := startEdge(t, formats.Policy{Rules: map[string]formats.Action{"json-duplicate-key": formats.Off}}, true)
	if status := e.send(t, post("/api", "application/json", nil, `{"a":1,"a":2}`)); status != 200 {
		t.Fatalf("status %d", status)
	}
	if n := len(e.seen.all()); n != 0 {
		t.Fatalf("%d findings: %+v", n, e.seen.all())
	}
}
