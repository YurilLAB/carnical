// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

type page struct {
	status int
	ct     string
	body   []byte
	err    error
}

// site is a fake origin: it answers the paths it has pages for, and everything else as a single-page application would (200 with
// its home page) or as a plain server would (404).
type site struct {
	mu    sync.Mutex
	pages map[string]page
	spa   bool
	calls []string
	hold  func(ctx context.Context, path string) // makes a fetch slow
}

func (s *site) fetch(ctx context.Context, path string) (int, string, []byte, error) {
	s.mu.Lock()
	s.calls = append(s.calls, path)
	pg, ok := s.pages[path]
	hold := s.hold
	s.mu.Unlock()
	if hold != nil {
		hold(ctx, path)
	}
	if err := ctx.Err(); err != nil {
		return 0, "", nil, err
	}
	switch {
	case ok:
		return pg.status, pg.ct, pg.body, pg.err
	case s.spa:
		return 200, "text/html; charset=utf-8", []byte("<!doctype html><html><body><div id=app></div></body></html>"), nil
	}
	return 404, "text/plain", []byte("not found"), nil
}

func ok(ct, body string) page { return page{status: 200, ct: ct, body: []byte(body)} }

func discoverGuard(t testing.TB, change func(*Config)) *Guard {
	t.Helper()
	g, _ := testGuard(t, func(c *Config) {
		c.Modes.Spec = ModeEnforce
		if change != nil {
			change(c)
		}
	})
	return g
}

func TestDiscoveryFindsADescriptionAndKeepsItAsACandidate(t *testing.T) {
	s := &site{spa: true, pages: map[string]page{"/openapi.json": ok("application/json", shopAPI)}}
	g := discoverGuard(t, nil)
	rep, err := g.Discover(context.Background(), s.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Source != "/openapi.json" || rep.Routes != 13 || rep.Format != "openapi 3.0.3" || rep.Title != "Shop API" || !strings.HasPrefix(rep.Outcome, "candidate") {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.Attempts) != 1 || rep.Attempts[0].Status != 200 || !strings.HasPrefix(rep.Attempts[0].Result, "imported") {
		t.Fatalf("attempts = %+v", rep.Attempts)
	}
	st := g.Stats()
	if st.ModelState != "candidate" || st.CandidateRoutes != 13 || st.DeclaredRoutes != 0 {
		t.Fatalf("stats = %+v", st)
	}
	// It says where it came from and when.
	snap := g.Snapshot()
	if snap.Source != "/openapi.json" || snap.Fetched.IsZero() || snap.State != ModelCandidate || len(snap.Routes) != 13 || snap.Routes[0].State != StateCandidate {
		t.Fatalf("snapshot = %+v", snap)
	}
	// A candidate refuses nothing, however much it disagrees.
	for _, r := range []string{"/api/v1/nonexistent", "/api/v1/products?limit=abc"} {
		if res := g.Inspect(mk("GET", r)); len(res.Verdicts) != 0 {
			t.Fatalf("a candidate refused %s: %+v", r, res.Verdicts)
		}
	}
}

func TestDiscoveryTriesTheWellKnownAddressesInOrder(t *testing.T) {
	s := &site{pages: map[string]page{
		"/swagger.json":     ok("application/json", shopAPI),
		"/api/openapi.json": ok("application/json", petStoreYAML),
	}}
	g := discoverGuard(t, nil)
	rep, err := g.Discover(context.Background(), s.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Source != "/swagger.json" {
		t.Fatalf("source = %s", rep.Source)
	}
	want := []string{"/openapi.json", "/openapi.yaml", "/swagger.json", "/graphql"}
	if !slices.Equal(s.calls, want) {
		t.Fatalf("asked for %v, want %v (it stops at the first description and then notes GraphQL)", s.calls, want)
	}
	if rep.Attempts[0].Status != 404 || rep.Attempts[0].Result != "status 404" {
		t.Fatalf("attempts = %+v", rep.Attempts)
	}
}

func TestDiscoveryOnlyEverAsksForPlainAddresses(t *testing.T) {
	s := &site{spa: true}
	g := discoverGuard(t, nil)
	_, err := g.Discover(context.Background(), s.fetch)
	if !errors.Is(err, ErrNoDescription) {
		t.Fatalf("err = %v", err)
	}
	allowed := append(slices.Clone(WellKnown), "/graphql")
	for _, c := range s.calls {
		if !slices.Contains(allowed, c) {
			t.Fatalf("asked for %q", c)
		}
		if strings.ContainsAny(c, "?{") {
			t.Fatalf("asked for %q, which has a query (an introspection query is never sent)", c)
		}
	}
	if len(s.calls) != len(WellKnown)+1 {
		t.Fatalf("%d requests", len(s.calls))
	}
}

func TestDiscoveryTreatsWhatTheSiteAnswersAsHostile(t *testing.T) {
	huge := strings.Repeat(" ", MaxDocumentBytes+10) + "{}"
	tests := []struct {
		name   string
		page   page
		result string // part of the attempt's result
	}{
		{"a home page answered with 200", ok("text/html", "<html></html>"), "content type"},
		{"a JSON error page", ok("application/json", `{"error":"not found"}`), ""},
		{"a document over the size limit", ok("application/json", huge), "limit"},
		{"a YAML alias bomb", ok("application/yaml", yamlBomb()), "too complex"},
		{"a document that nests a million deep", ok("application/json", `{"openapi":"3.0.0","x":`+strings.Repeat("[", 1_000_000)), "deeply"},
		{"a description served as an image", ok("image/png", shopAPI), "content type"},
		{"binary", ok("application/octet-stream", "\x00\x01\x02\x03"), "look like"},
		{"a redirect", page{status: 302, ct: "text/html", body: []byte("moved")}, "status 302"},
		{"a server error", page{status: 500, ct: "text/plain", body: []byte("oops")}, "status 500"},
		{"a fetch that fails", page{err: errors.New("connection refused: 10.0.0.1")}, "failed"},
		{"a JSON document that is not a description", ok("application/json", `{"name":"x","routes":{}}`), "not an OpenAPI"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &site{pages: map[string]page{"/openapi.json": tt.page, "/swagger.json": ok("application/json", shopAPI)}}
			g := discoverGuard(t, nil)
			start := time.Now()
			rep, err := g.Discover(context.Background(), s.fetch)
			if time.Since(start) > 5*time.Second {
				t.Fatalf("took %v", time.Since(start))
			}
			if err != nil {
				t.Fatalf("the hostile page stopped discovery: %v", err)
			}
			if rep.Source != "/swagger.json" || rep.Attempts[0].Result == "" || strings.HasPrefix(rep.Attempts[0].Result, "imported") {
				t.Fatalf("attempts = %+v, source %s", rep.Attempts, rep.Source)
			}
			if !strings.Contains(rep.Attempts[0].Result, tt.result) {
				t.Fatalf("result %q, want one containing %q", rep.Attempts[0].Result, tt.result)
			}
			if strings.Contains(rep.Attempts[0].Result, "10.0.0.1") {
				t.Fatal("the report repeats what the fetcher said")
			}
		})
	}
}

func TestADescriptionWithAReferenceLoopIsStillUsable(t *testing.T) {
	doc := `{"openapi":"3.0.0","paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Node"}}}}}}},
	"components":{"schemas":{"Node":{"type":"object","required":["id"],"properties":{"id":{"type":"integer"},"next":{"$ref":"#/components/schemas/Node"}}}}}}`
	s := &site{pages: map[string]page{"/openapi.json": ok("application/json", doc)}}
	g := discoverGuard(t, nil)
	if _, err := g.Discover(context.Background(), s.fetch); err != nil {
		t.Fatal(err)
	}
	if err := g.Promote(); err != nil {
		t.Fatal(err)
	}
	if res := g.Inspect(mk("POST", "/a", withJSON(`{"id":1,"next":{"id":2,"next":{"id":3}}}`))); len(res.Verdicts) != 0 {
		t.Fatalf("a valid chain was refused: %+v", res.Verdicts)
	}
	if res := g.Inspect(mk("POST", "/a", withJSON(`{"id":1,"next":{"id":"x"}}`))); !blocked(res) {
		t.Fatalf("a bad link in the chain was not refused: %+v", res.Verdicts)
	}
}

func TestDiscoveryHonoursItsTimeLimits(t *testing.T) {
	hold := func(ctx context.Context, path string) { <-ctx.Done() }
	t.Run("one slow fetch does not stop the rest, within the overall limit", func(t *testing.T) {
		s := &site{pages: map[string]page{"/openapi.json": ok("application/json", shopAPI)}, hold: hold}
		g := discoverGuard(t, func(c *Config) {
			c.Discovery.FetchTimeout = 30 * time.Millisecond
			c.Discovery.Timeout = 200 * time.Millisecond
		})
		start := time.Now()
		rep, err := g.Discover(context.Background(), s.fetch)
		took := time.Since(start)
		if !errors.Is(err, ErrNoDescription) || took > 3*time.Second {
			t.Fatalf("err = %v after %v", err, took)
		}
		if len(rep.Attempts) == 0 || len(rep.Attempts) > len(WellKnown) {
			t.Fatalf("attempts = %d", len(rep.Attempts))
		}
	})
	t.Run("a cancelled context stops it", func(t *testing.T) {
		s := &site{spa: true}
		g := discoverGuard(t, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := g.Discover(ctx, s.fetch)
		if !errors.Is(err, ErrNoDescription) || len(s.calls) != 0 {
			t.Fatalf("err = %v, %d requests", err, len(s.calls))
		}
	})
	t.Run("a fetcher that panics is an error, not a crash", func(t *testing.T) {
		g := discoverGuard(t, nil)
		_, err := g.Discover(context.Background(), func(context.Context, string) (int, string, []byte, error) { panic("boom") })
		if !errors.Is(err, ErrNoDescription) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a second discovery at the same time is refused", func(t *testing.T) {
		g := discoverGuard(t, nil)
		started, release := make(chan struct{}), make(chan struct{})
		go g.Discover(context.Background(), func(ctx context.Context, p string) (int, string, []byte, error) {
			select {
			case <-started:
			default:
				close(started)
			}
			<-release
			return 404, "", nil, nil
		})
		<-started
		if _, err := g.Discover(context.Background(), (&site{}).fetch); !errors.Is(err, ErrDiscoveryBusy) {
			t.Fatalf("err = %v", err)
		}
		close(release)
	})
	t.Run("no fetcher", func(t *testing.T) {
		if _, err := discoverGuard(t, nil).Discover(context.Background(), nil); err == nil {
			t.Fatal("no error")
		}
	})
}

func TestDiscoveryNotesGraphQLAndNeverReadsItsSchema(t *testing.T) {
	tests := []struct {
		name string
		page page
		want bool
	}{
		{"a GraphQL server's answer to a plain GET", page{status: 400, ct: "application/json", body: []byte(`{"errors":[{"message":"Must provide query string."}]}`)}, true},
		{"a GraphiQL page", ok("text/html", "<title>GraphiQL</title>"), true},
		{"a 404", page{status: 404, ct: "text/plain", body: []byte("nothing")}, false},
		{"a home page", ok("text/html", "<html>welcome</html>"), false},
		{"a 500 that mentions it", page{status: 500, ct: "text/plain", body: []byte("graphql exploded")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &site{pages: map[string]page{"/graphql": tt.page, "/openapi.json": ok("application/json", shopAPI)}}
			g := discoverGuard(t, nil)
			rep, err := g.Discover(context.Background(), s.fetch)
			if err != nil {
				t.Fatal(err)
			}
			if rep.GraphQL != tt.want || g.Stats().GraphQLSeen != tt.want {
				t.Fatalf("GraphQL = %v, want %v", rep.GraphQL, tt.want)
			}
		})
	}
}

func TestDiscoveryReadsTheWordPressRESTIndex(t *testing.T) {
	index := `{"name":"My Blog","namespaces":["wp/v2"],"routes":{
		"/":{"namespace":"","methods":["GET"]},
		"/wp/v2/posts":{"namespace":"wp/v2","methods":["GET","POST"]},
		"/wp/v2/posts/(?P<id>[\\d]+)":{"namespace":"wp/v2","methods":["GET","POST","PUT","PATCH","DELETE"]},
		"/wp/v2/users/(?P<id>[\\d]+)/meta/(?P<key>[\\w-]+)":{"namespace":"wp/v2","methods":["GET"]},
		"/wp/v2/search":{"namespace":"wp/v2","methods":["GET"]},
		"/odd/(?:a|b)+":{"namespace":"odd","methods":["GET"]}}}`
	s := &site{pages: map[string]page{"/wp-json/": ok("application/json", index)}}
	g := discoverGuard(t, nil)
	rep, err := g.Discover(context.Background(), s.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Source != "/wp-json/" || rep.Format != "wordpress rest index" || rep.Title != "My Blog" {
		t.Fatalf("report = %+v", rep)
	}
	if err := g.Promote(); err != nil {
		t.Fatal(err)
	}
	snap := g.Snapshot()
	if routeOf(t, snap, "GET", "/wp-json/wp/v2/posts/{id}").Params[0].Schema.Type[0] != "integer" {
		t.Fatalf("a numeric pattern did not become an integer: %+v", routeOf(t, snap, "GET", "/wp-json/wp/v2/posts/{id}"))
	}
	if routeOf(t, snap, "GET", "/wp-json/wp/v2/users/{id}/meta/{key}").Params[1].Schema.Type[0] != "string" {
		t.Fatal("the second parameter")
	}
	if !strings.Contains(strings.Join(rep.Warnings, " "), "left out") {
		t.Fatalf("a pattern that cannot be a template was not reported: %v", rep.Warnings)
	}
	if res := g.Inspect(mk("GET", "/wp-json/wp/v2/posts/abc")); !has(res, IDSpecPathParam) {
		t.Fatalf("%+v", res.Verdicts)
	}
	if res := g.Inspect(mk("GET", "/wp-json/wp/v2/posts/7")); len(res.Verdicts) != 0 {
		t.Fatalf("%+v", res.Verdicts)
	}
	if res := g.Inspect(mk("GET", "/wp-json/wp/v2/unknown")); !has(res, IDSpecUnknownRoute) {
		t.Fatalf("%+v", res.Verdicts)
	}
}

// ---- promotion ----

func fitsShop(i int) *inspect.Request {
	switch i % 3 {
	case 0:
		return mk("GET", fmt.Sprintf("/api/v1/products?limit=%d", 1+i%50), withClient(ip(i)))
	case 1:
		return mk("GET", fmt.Sprintf("/api/v1/products/%d", 1+i), withClient(ip(i)))
	}
	return mk("POST", "/api/v1/users", withClient(ip(i)), withJSON(fmt.Sprintf(`{"email":"u%d@x.example","password":"longenough"}`, i)))
}

func discovered(t testing.TB, change func(*Config)) *Guard {
	t.Helper()
	s := &site{pages: map[string]page{"/openapi.json": ok("application/json", shopAPI)}}
	g := discoverGuard(t, change)
	if _, err := g.Discover(context.Background(), s.fetch); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestACandidateIsPromotedWhenItAgreesWithEnoughRequestsFromEnoughClients(t *testing.T) {
	g := discovered(t, nil)
	for i := 0; i < 15; i++ {
		g.Observe(fitsShop(i), 200)
	}
	if st := g.Stats(); st.ModelState != "candidate" || st.CandidateAgree != 15 {
		t.Fatalf("after 15: %+v", st)
	}
	for i := 15; i < 30; i++ {
		g.Observe(fitsShop(i), 200)
	}
	st := g.Stats()
	if st.ModelState != "active" || st.Promotions != 1 || st.CandidateRoutes != 0 || st.DeclaredRoutes != 13 {
		t.Fatalf("after 30: %+v", st)
	}
	if res := g.Inspect(mk("GET", "/api/v1/secret")); !blocked(res) {
		t.Fatalf("a promoted description in enforce did not block an unknown route: %+v", res.Verdicts)
	}
}

func TestACandidateThatDisagreesWithRealTrafficIsNeverPromoted(t *testing.T) {
	g := discovered(t, nil)
	for i := 0; i < 200; i++ {
		var r *inspect.Request
		if i%2 == 0 {
			r = fitsShop(i)
		} else {
			r = mk("GET", fmt.Sprintf("/api/v1/other/%d", i), withClient(ip(i))) // real, answered 200, and not in the description
		}
		g.Observe(r, 200)
	}
	if st := g.Stats(); st.ModelState != "candidate" || st.CandidateAgree == 0 || st.CandidateDisagree < 90 {
		t.Fatalf("stats = %+v", st)
	}
	if res := g.Inspect(mk("GET", "/api/v1/other/5")); len(res.Verdicts) != 0 {
		t.Fatalf("a candidate that disagrees with the traffic refused real traffic: %+v", res.Verdicts)
	}
}

func TestACandidateAgreementFromOneClientIsNotEnough(t *testing.T) {
	g := discovered(t, nil)
	for i := 0; i < 500; i++ {
		g.Observe(mk("GET", fmt.Sprintf("/api/v1/products/%d", i+1), withClient("192.0.2.1")), 200)
	}
	if st := g.Stats(); st.ModelState != "candidate" {
		t.Fatalf("one client promoted a description: %+v", st)
	}
}

func TestPromotionCanBeManual(t *testing.T) {
	g := discovered(t, func(c *Config) { c.Discovery.ManualPromotion = true })
	for i := 0; i < 200; i++ {
		g.Observe(fitsShop(i), 200)
	}
	if st := g.Stats(); st.ModelState != "candidate" {
		t.Fatalf("promoted by itself with ManualPromotion: %+v", st)
	}
	if err := g.Promote(); err != nil {
		t.Fatal(err)
	}
	if st := g.Stats(); st.ModelState != "active" || st.Promotions != 1 {
		t.Fatalf("%+v", st)
	}
	if err := g.Promote(); err == nil {
		t.Fatal("a second promotion with no candidate succeeded")
	}
}

func TestRefreshKeepsTheOldDescriptionIfTheNewOneIsWorse(t *testing.T) {
	small := `{"openapi":"3.0.0","paths":{"/a":{"get":{}}}}`
	larger := strings.Replace(shopAPI, `"/export"`, `"/export2": {"get": {}}, "/export"`, 1)
	tests := []struct {
		name    string
		serve   string
		force   bool
		outcome string
		routes  int
	}{
		{"the same description", shopAPI, false, "unchanged", 13},
		{"a description with fewer routes is worse", small, false, "fewer routes", 13},
		{"forced, the worse one replaces it", small, true, "candidate", 1},
		{"a description with more routes is better", larger, false, "candidate", 14},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := discovered(t, nil)
			s := &site{pages: map[string]page{"/openapi.json": ok("application/json", tt.serve)}}
			rep, err := g.Refresh(context.Background(), s.fetch, tt.force)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(rep.Outcome, tt.outcome) {
				t.Fatalf("outcome %q, want %q", rep.Outcome, tt.outcome)
			}
			if got := g.Stats().CandidateRoutes; got != tt.routes {
				t.Fatalf("candidate has %d routes, want %d", got, tt.routes)
			}
		})
	}
	t.Run("a refresh that finds nothing keeps what is held", func(t *testing.T) {
		g := discovered(t, nil)
		_, err := g.Refresh(context.Background(), (&site{spa: true}).fetch, true)
		if !errors.Is(err, ErrNoDescription) || g.Stats().CandidateRoutes != 13 {
			t.Fatalf("err = %v, stats = %+v", err, g.Stats())
		}
	})
	t.Run("the description in force stays in force until the new one is shown to fit", func(t *testing.T) {
		g := discoverGuard(t, nil)
		if _, err := g.ImportOpenAPI([]byte(shopAPI)); err != nil {
			t.Fatal(err)
		}
		larger := strings.Replace(shopAPI, `"/export"`, `"/export2": {"get": {}}, "/export"`, 1)
		s := &site{pages: map[string]page{"/openapi.json": ok("application/json", larger)}}
		if _, err := g.Refresh(context.Background(), s.fetch, false); err != nil {
			t.Fatal(err)
		}
		st := g.Stats()
		if st.ModelState != "active" || st.DeclaredRoutes != 13 || st.CandidateRoutes != 14 {
			t.Fatalf("stats = %+v", st)
		}
		if res := g.Inspect(mk("GET", "/api/v1/export2")); !has(res, IDSpecUnknownRoute) {
			t.Fatalf("the old description should still decide: %+v", res.Verdicts)
		}
		// The same document the active one came from: nothing to do.
		s2 := &site{pages: map[string]page{"/openapi.json": ok("application/json", shopAPI)}}
		g2 := discoverGuard(t, nil)
		g2.ImportOpenAPI([]byte(shopAPI))
		rep, _ := g2.Refresh(context.Background(), s2.fetch, false)
		if !strings.Contains(rep.Outcome, "unchanged") || g2.Stats().CandidateRoutes != 0 {
			t.Fatalf("outcome %q, stats %+v", rep.Outcome, g2.Stats())
		}
	})
}
