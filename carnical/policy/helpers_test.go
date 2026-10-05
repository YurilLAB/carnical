// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"

	"github.com/YurilLAB/coraza/carnical/proxy"
)

// mut returns Default with a change made to it.
func mut(change func(*Policy)) Policy {
	p := Default()
	change(&p)
	return p
}

// problemPaths returns the paths of the problems in an error from Validate or Decode.
func problemPaths(err error) []string {
	var e *Error
	if !errors.As(err, &e) {
		return nil
	}
	out := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		out[i] = p.Path
	}
	return out
}

// wantValid fails unless err is nil; wantInvalid fails unless err names a problem at (a path starting with) path.
func wantValid(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
}

func wantInvalid(t *testing.T, err error, path string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want a problem at %q", path)
	}
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error %v is not ErrInvalid", err)
	}
	if path == "" {
		return
	}
	for _, p := range problemPaths(err) {
		if strings.HasPrefix(p, path) {
			return
		}
	}
	t.Fatalf("problems at %v, want one at %q (%v)", problemPaths(err), path, err)
}

// wafWith builds a Coraza WAF from directives alone (no rule set) and returns it with its number of rules.
func wafWith(t testing.TB, directives string) (coraza.WAF, int, error) {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 131072\n" + directives))
	if err != nil {
		return nil, 0, err
	}
	if c, ok := waf.(experimental.WAFCloser); ok {
		t.Cleanup(func() { c.Close() })
	}
	return waf, waf.(experimental.WAFWithRules).RulesCount(), nil
}

// matched runs a request through a WAF and returns the ids of the rules that matched and logged, and whether it was interrupted.
func matched(t testing.TB, waf coraza.WAF, method, uri string, headers map[string]string, body string) (ids []int, status int) {
	t.Helper()
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection("203.0.113.5", 1234, "", 0)
	tx.ProcessURI(uri, method, "HTTP/1.1")
	for k, v := range headers {
		tx.AddRequestHeader(k, v)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		status = it.Status
	}
	if body != "" && status == 0 {
		if it, _, err := tx.WriteRequestBody([]byte(body)); err != nil {
			t.Fatal(err)
		} else if it != nil {
			status = it.Status
		}
	}
	if status == 0 {
		if it, err := tx.ProcessRequestBody(); err != nil {
			t.Fatal(err)
		} else if it != nil {
			status = it.Status
		}
	}
	for _, m := range tx.MatchedRules() {
		ids = append(ids, m.Rule().ID())
	}
	return ids, status
}

func has(ids []int, id int) bool {
	for _, i := range ids {
		if i == id {
			return true
		}
	}
	return false
}

// edge is a proxy built from a compiled policy, in front of a stand-in application, that records what the rules reported.
type edge struct {
	*proxy.Edge
	mu      sync.Mutex
	matches []proxy.Match
	reached int
}

var loopbackOrigin = proxy.OriginPolicy{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}

func newEdge(t testing.TB, p Policy) *edge {
	t.Helper()
	c, err := Compile(p)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	e := &edge{}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.reached++
		e.mu.Unlock()
		w.Header().Set("X-Powered-By", "PHP/8.3.1")
		w.Header().Set("Server", "Apache/2.4.58 (Ubuntu)")
		switch r.URL.Path {
		case "/leak":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html><body>Fatal error: Uncaught Exception: boom in /var/www/html/index.php:12\nStack trace:\n#0 {main}\n  thrown in /var/www/html/index.php on line 12</body></html>"))
			return
		case "/sets-cookie":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"})
		case "/style.css":
			w.Header().Set("Content-Type", "text/html")
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "text/plain")
		}
		w.Write([]byte("reached the application"))
	}))
	t.Cleanup(app.Close)
	u, _ := url.Parse(app.URL)
	cfg := proxy.Config{Upstream: u, Origin: loopbackOrigin}
	c.ApplyTo(&cfg)
	cfg.OnMatch = func(m proxy.Match) {
		e.mu.Lock()
		e.matches = append(e.matches, m)
		e.mu.Unlock()
	}
	edge, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(func() { edge.Close() })
	e.Edge = edge
	return e
}

const (
	browser = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
	form    = "application/x-www-form-urlencoded"
)

// send sends a request through the edge and returns the whole response. mod may change the request after the defaults are set.
func (e *edge) send(method, target string, mod func(*http.Request), body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", form)
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.Host = "shop.example.test"
	r.RemoteAddr = "203.0.113.77:40000"
	r.Header.Set("User-Agent", browser)
	r.Header.Set("Accept", "text/html,application/json")
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w
}

// do is send, and returns the status.
func (e *edge) do(method, target string, mod func(*http.Request), body string) int {
	return e.send(method, target, mod, body).Code
}

func (e *edge) ruleIDs() []int {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []int
	for _, m := range e.matches {
		out = append(out, m.RuleID)
	}
	return out
}

func (e *edge) reset() {
	e.mu.Lock()
	e.matches, e.reached = nil, 0
	e.mu.Unlock()
}

const sqlInjection = "/search?q=1%27+OR+%271%27%3D%271%27+--"
