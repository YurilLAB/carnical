// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/inspect"
	"github.com/YurilLAB/coraza/carnical/proxy"
)

// These tests put the guard in the real proxy, in front of a real HTTP server standing for the customer's application, and talk to
// the proxy over a real connection. The rule set is off, so that what is refused is refused by the guard and by nothing else.

type origin struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string // "METHOD target" of each request that reached the application
	doc  string   // what /openapi.json answers, if anything
}

func (o *origin) reached() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.seen...)
}

// newOrigin is an application that, like many, answers 200 to anything under /api: so a probe for a route that does not exist
// is answered like a real one.
func newOrigin(t testing.TB) *origin {
	t.Helper()
	o := &origin{}
	o.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/openapi.json" && o.doc != "" {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, o.doc)
			return
		}
		o.mu.Lock()
		o.seen = append(o.seen, r.Method+" "+r.URL.RequestURI())
		o.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			w.WriteHeader(201)
		}
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(o.Close)
	return o
}

type verdictLog struct {
	mu  sync.Mutex
	got []proxy.Match
}

func (l *verdictLog) add(m proxy.Match) {
	l.mu.Lock()
	l.got = append(l.got, m)
	l.mu.Unlock()
}

func (l *verdictLog) ids() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []int
	for _, m := range l.got {
		out = append(out, m.RuleID)
	}
	return out
}

func (l *verdictLog) last() proxy.Match {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.got) == 0 {
		return proxy.Match{}
	}
	return l.got[len(l.got)-1]
}

type edge struct {
	url string
	log *verdictLog
	cl  *http.Client
}

// startEdge puts a proxy in front of the origin with the guard as both its inspector and its observer.
func startEdge(t testing.TB, o *origin, g *Guard) *edge {
	t.Helper()
	target, _ := url.Parse(o.URL)
	log := &verdictLog{}
	settings := crs.DefaultSettings()
	settings.Mode = crs.ModeOff
	e, err := proxy.New(proxy.Config{
		Upstream:       target,
		CRS:            settings,
		Origin:         proxy.OriginPolicy{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}},
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, // the test is the load balancer; it says who the visitor is
		MaxConnsPerIP:  -1,
		Inspectors:     []inspect.Inspector{g},
		Observers:      []inspect.Observer{g},
		OnMatch:        log.add,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = e.Server("")
	srv.Start()
	t.Cleanup(srv.Close)
	return &edge{url: srv.URL, log: log, cl: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 8}}}
}

// do sends a request as a visitor at an address, and returns the status.
func (e *edge) do(method, target, visitor, body string, headers ...string) int {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, e.url+target, rd)
	if err != nil {
		panic(err)
	}
	req.Header.Set("X-Forwarded-For", visitor)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := e.cl.Do(req)
	if err != nil {
		panic(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// visitor is the nth distinct visitor, in a /24 of its own.
func visitor(n int) string { return ip(n) }

func TestTheGuardLearnsAnAPIFromTrafficThroughTheProxyAndThenRefusesWhatDoesNotFit(t *testing.T) {
	o := newOrigin(t)
	g, _ := testGuard(t, nil) // the defaults: nothing configured
	e := startEdge(t, o, g)

	// Real clients use the API. Every request passes: the guard has learned nothing yet, and what it has not learned it does not
	// refuse.
	for i := 0; i < 400; i++ {
		var status int
		switch i % 4 {
		case 0:
			status = e.do("GET", fmt.Sprintf("/api/items?limit=%d&sort=%s", 5+i/4%40, []string{"name", "price"}[i/4%2]), visitor(i), "")
		case 1:
			status = e.do("GET", fmt.Sprintf("/api/items/%d", 1000+i), visitor(i), "")
		case 2:
			status = e.do("POST", "/api/items", visitor(i), fmt.Sprintf(`{"title":"item %d","price":%d.5,"tags":["a","b"]}`, i, i%90))
		default:
			status = e.do("GET", fmt.Sprintf("/api/users/123e4567-e89b-12d3-a456-%012d", i), visitor(i), "")
		}
		if status != 200 && status != 201 {
			t.Fatalf("request %d was refused with %d while learning", i, status)
		}
	}
	g.Flush()
	if st := g.Stats(); st.LearnedEnforce != 4 || st.Refused != 0 {
		t.Fatalf("after the training: %+v", st)
	}

	// By default what was learned is only watched: findings are logged and nothing is refused. A mass-assignment body is the one
	// refusal that does not wait for the owner, because the model has learned that no client ever sends a privileged property.
	massAssign := `{"title":"x","price":1.5,"tags":["a"],"role":"admin"}`
	before := len(o.reached())
	if status := e.do("POST", "/api/items", visitor(1), massAssign); status != 403 {
		t.Fatalf("a mass-assignment body got %d, want 403", status)
	}
	if len(o.reached()) != before {
		t.Fatal("the refused request reached the application")
	}
	if m := e.log.last(); m.RuleID != IDMassAssignRefused || !m.Disruptive {
		t.Fatalf("logged %+v", m)
	}
	// A property that is new but not privileged is only reported while the learned model is in monitor.
	if status := e.do("POST", "/api/items", visitor(4), `{"title":"x","price":1.5,"tags":["a"],"colour":"red"}`); status != 201 {
		t.Fatalf("a new property was refused in monitor mode: %d", status)
	}
	if m := e.log.last(); m.RuleID != IDLearnedUnknownProperty || m.Disruptive {
		t.Fatalf("a new property was not reported as a warning: %+v", m)
	}
	if status := e.do("GET", "/api/admin/secret-dump", visitor(2), ""); status != 200 {
		t.Fatalf("an unknown route was refused in monitor mode: %d", status)
	}
	if m := e.log.last(); m.RuleID != IDLearnedUnknownRoute || m.Disruptive {
		t.Fatalf("the unknown route was not reported as a warning: %+v", m)
	}

	// The owner has read the findings and promotes the learned model to enforce.
	if err := g.SetModes(Modes{Learned: ModeEnforce}); err != nil {
		t.Fatal(err)
	}
	refused := []struct {
		name         string
		method, path string
		body         string
		status       int
		id           int
	}{
		{"an unknown route", "GET", "/api/admin/other-dump", "", 404, IDLearnedUnknownRoute},
		{"a parameter of the wrong type", "GET", "/api/items?limit=abc&sort=name", "", 400, IDLearnedQueryParam},
		{"an injection in a number", "GET", "/api/items?limit=1%27%20OR%20%271%27%3D%271&sort=name", "", 400, IDLearnedQueryParam},
		{"a mass-assignment body", "POST", "/api/items", massAssign, 403, IDMassAssignRefused},
		{"a property that was never sent", "POST", "/api/items", `{"title":"x","price":1.5,"tags":["a"],"colour":"red"}`, 400, IDLearnedUnknownProperty},
		{"a method that was never used on the route", "DELETE", "/api/items/5", "", 405, IDLearnedMethodNotSeen},
		{"a path that is not an id where an id was", "GET", "/api/items/abc", "", 404, IDLearnedUnknownRoute},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			before := len(o.reached())
			if status := e.do(tt.method, tt.path, visitor(3), tt.body); status != tt.status {
				t.Fatalf("status %d, want %d", status, tt.status)
			}
			if len(o.reached()) != before {
				t.Fatal("the refused request reached the application")
			}
			if m := e.log.last(); !m.Disruptive || !containsID(e.log.ids(), tt.id) {
				t.Fatalf("logged %v, want %d", e.log.ids(), tt.id)
			}
		})
	}
	// And the normal traffic still passes.
	for i := 0; i < 20; i++ {
		for _, ok := range []struct {
			method, path, body string
		}{
			{"GET", "/api/items?limit=10&sort=price", ""},
			{"GET", "/api/items/4242", ""},
			{"POST", "/api/items", `{"title":"fine","price":9.5,"tags":["x","y"]}`},
			{"GET", "/api/users/123e4567-e89b-12d3-a456-426614174000", ""},
			{"HEAD", "/api/items/4242", ""},
		} {
			if status := e.do(ok.method, ok.path, visitor(500+i), ok.body); status != 200 && status != 201 {
				t.Fatalf("%s %s was refused with %d", ok.method, ok.path, status)
			}
		}
	}
}

func containsID(ids []int, want int) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestAnAttackerWhoFloodsTheProxyCannotTeachTheModelThroughIt(t *testing.T) {
	o := newOrigin(t)
	g, _ := testGuard(t, nil) // the defaults: the learned model is watched, not enforced, while it learns
	e := startEdge(t, o, g)
	for i := 0; i < 400; i++ {
		switch i % 2 {
		case 0:
			e.do("GET", fmt.Sprintf("/api/items?limit=%d", 5+i%40), visitor(i), "")
		default:
			e.do("GET", fmt.Sprintf("/api/items/%d", 1000+i), visitor(i), "")
		}
	}
	// One address sends 1,500 requests that the application answers with 200: a route that does not exist, a parameter that is not
	// there, a method nobody uses. The application does not know the difference, so the guard has to.
	attacker := "192.0.2.66"
	for i := 0; i < 500; i++ {
		e.do("GET", "/api/backdoor?cmd=id", attacker, "")
		e.do("GET", "/api/items?limit=abc", attacker, "")
		e.do("DELETE", "/api/items/5", attacker, "")
	}
	if err := g.SetModes(Modes{Learned: ModeEnforce}); err != nil { // the owner promotes the learned model
		t.Fatal(err)
	}
	for _, tt := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/api/backdoor?cmd=id", 404},
		{"GET", "/api/items?limit=abc", 400},
		{"DELETE", "/api/items/5", 405},
	} {
		// From another address, so that nothing about the attacker's own address is why it is refused.
		if status := e.do(tt.method, tt.path, "198.18.0.9", ""); status != tt.status {
			t.Fatalf("%s %s from a stranger: %d, want %d: the flood taught the guard that it is normal (last verdicts %v)", tt.method, tt.path, status, tt.status, e.log.ids()[max(0, len(e.log.ids())-3):])
		}
	}
	if status := e.do("GET", "/api/items?limit=7", "198.18.0.10", ""); status != 200 {
		t.Fatalf("normal traffic after the flood: %d", status)
	}
}

func TestAnAuthenticationEndpointIsLimitedByDefault(t *testing.T) {
	o := newOrigin(t)
	g, _ := testGuard(t, nil)
	e := startEdge(t, o, g)
	var statuses []int
	for i := 0; i < 14; i++ {
		statuses = append(statuses, e.do("POST", "/api/auth/login", "203.0.113.50", `{"email":"a@b.example","password":"guess`+fmt.Sprint(i)+`"}`))
	}
	got429 := 0
	for _, s := range statuses[:10] {
		if s != 201 {
			t.Fatalf("the first ten attempts: %v", statuses)
		}
	}
	for _, s := range statuses[10:] {
		if s == 429 {
			got429++
		}
	}
	if got429 != 4 {
		t.Fatalf("statuses %v: the attempts after the tenth must be refused with 429", statuses)
	}
	if m := e.log.last(); m.RuleID != IDAuthRateLimited || !strings.Contains(m.Message, "Retry-After: ") {
		t.Fatalf("last = %+v", m)
	}
	// Someone else logging in is not held back by it.
	if status := e.do("POST", "/api/auth/login", "203.0.113.51", `{"email":"a@b.example","password":"fine"}`); status != 201 {
		t.Fatalf("another address: %d", status)
	}
	// The other limits are warnings by default: nothing is refused for hammering an ordinary endpoint.
	for i := 0; i < 80; i++ {
		if status := e.do("GET", "/api/items", "203.0.113.52", ""); status != 200 {
			t.Fatalf("an ordinary endpoint was refused at request %d: %d", i, status)
		}
	}
	if !containsID(e.log.ids(), IDRateLimited) {
		t.Fatalf("the general limit was not even reported: %v", e.log.ids())
	}
}

func TestDiscoveryPromotionAndEnforcementThroughTheProxy(t *testing.T) {
	t.Run("numeric contract at origin", func(t *testing.T) {
		o := &origin{}
		var ids []int64
		o.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body struct{ ID int64 }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad body", 400)
				return
			}
			o.mu.Lock()
			ids = append(ids, body.ID)
			o.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			io.WriteString(w, "{}")
		}))
		t.Cleanup(o.Close)
		g, _ := testGuard(t, func(c *Config) { c.Modes.Spec = ModeEnforce })
		doc := "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"numbers\",\"version\":\"1\"},\"paths\":{\"/api/numbers\":{\"post\":{\"requestBody\":{\"required\":true,\"content\":{\"application/json\":{\"schema\":{\"type\":\"object\",\"required\":[\"id\"],\"properties\":{\"id\":{\"type\":\"integer\",\"enum\":[9007199254740992]}}}}}},\"responses\":{\"201\":{\"description\":\"ok\"}}}}}}"
		if _, err := g.ImportOpenAPI([]byte(doc)); err != nil {
			t.Fatal(err)
		}
		e := startEdge(t, o, g)
		for i, tt := range []struct {
			body   string
			status int
		}{
			{"{\"id\":9007199254740992}", 201},
			{"{\"id\":9007199254740993}", 400},
			{"{\"id\":9007199254740994}", 400},
		} {
			if got := e.do("POST", "/api/numbers", visitor(800+i), tt.body); got != tt.status {
				t.Errorf("body %s: status %d, want %d", tt.body, got, tt.status)
			}
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		if len(ids) != 1 || ids[0] != 9007199254740992 {
			t.Fatalf("origin received IDs %v, want only allowed ID", ids)
		}
	})

	o := newOrigin(t)
	o.doc = shopAPI
	g, _ := testGuard(t, func(c *Config) { c.Modes.Spec = ModeEnforce })
	e := startEdge(t, o, g)

	// The fetcher is the caller's: here it asks the origin directly, with a size cap, as the proxy's guarded transport would.
	fetch := func(ctx context.Context, path string) (int, string, []byte, error) {
		req, _ := http.NewRequestWithContext(ctx, "GET", o.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, "", nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocumentBytes+1))
		return resp.StatusCode, resp.Header.Get("Content-Type"), body, err
	}
	rep, err := g.Discover(context.Background(), fetch)
	if err != nil || rep.Routes != 13 {
		t.Fatalf("discover: %v %+v", err, rep)
	}
	// A candidate refuses nothing.
	if status := e.do("GET", "/api/v1/not-in-the-description", visitor(1), ""); status != 200 {
		t.Fatalf("a candidate refused a request: %d", status)
	}
	for i := 0; i < 40; i++ {
		var status int
		switch i % 3 {
		case 0:
			status = e.do("GET", fmt.Sprintf("/api/v1/products?limit=%d", 1+i%50), visitor(i), "")
		case 1:
			status = e.do("GET", fmt.Sprintf("/api/v1/products/%d", 1+i), visitor(i), "")
		default:
			status = e.do("POST", "/api/v1/users", visitor(i), fmt.Sprintf(`{"email":"u%d@x.example","password":"longenough"}`, i))
		}
		if status != 200 && status != 201 {
			t.Fatalf("request %d: %d", i, status)
		}
	}
	if st := g.Stats(); st.ModelState != "active" || st.Promotions != 1 {
		t.Fatalf("the description that fit 40 requests from 40 clients was not promoted: %+v", st)
	}
	for _, tt := range []struct {
		name         string
		method, path string
		body         string
		status       int
		id           int
	}{
		{"an unknown route", "GET", "/api/v1/not-in-the-description", "", 404, IDSpecUnknownRoute},
		{"a parameter of the wrong type", "GET", "/api/v1/products?limit=abc", "", 400, IDSpecQueryParam},
		{"a path parameter that is not an integer", "GET", "/api/v1/products/abc", "", 400, IDSpecPathParam},
		{"a property the schema does not allow", "POST", "/api/v1/users", `{"email":"a@b.example","password":"longenough","nickname":"x"}`, 400, IDSpecUnknownProperty},
		{"a method the route does not have", "PATCH", "/api/v1/products", "", 405, IDSpecMethodNotAllowed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if status := e.do(tt.method, tt.path, visitor(600), tt.body); status != tt.status {
				t.Fatalf("status %d, want %d", status, tt.status)
			}
			if !containsID(e.log.ids(), tt.id) {
				t.Fatalf("logged %v, want %d", e.log.ids(), tt.id)
			}
		})
	}
	if status := e.do("GET", "/api/v1/products?limit=10&sort=price", visitor(601), ""); status != 200 {
		t.Fatalf("a request that fits was refused: %d", status)
	}
}
