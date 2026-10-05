// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// shopTraffic is what a small shop's real clients send, answered with 200: item lists with a limit and a sort, single items by
// number, creates with a JSON body, users by uuid. Clients are distinct addresses in distinct /24s.
func shopTraffic(i int) *inspect.Request {
	c := withClient(ip(i))
	uuid := fmt.Sprintf("123e4567-e89b-12d3-a456-%012d", i)
	switch i % 4 {
	case 0:
		return mk("GET", fmt.Sprintf("/api/items?limit=%d&sort=%s", 5+i/4%40, []string{"name", "price"}[i/4%2]), c)
	case 1:
		return mk("GET", fmt.Sprintf("/api/items/%d", 1000+i), c)
	case 2:
		return mk("POST", "/api/items", c, withJSON(fmt.Sprintf(`{"title":"item %d","price":%d.5,"tags":["a","b"]}`, i, i%90)))
	default:
		return mk("GET", "/api/users/"+uuid, c)
	}
}

// learnedShop is a guard that has seen 400 requests from 100 clients, with the learned model enforced.
func learnedShop(t testing.TB) (*Guard, *fakeClock) {
	g, clk := testGuard(t, func(c *Config) { c.Modes.Learned = ModeEnforce })
	for i := 0; i < 400; i++ {
		g.Observe(shopTraffic(i), 200)
	}
	g.Flush()
	return g, clk
}

func routeState(g *Guard, method, path string) State {
	for _, r := range g.Snapshot().Routes {
		if r.Method == method && r.Path == path && r.State != StateDeclared {
			return r.State
		}
	}
	return ""
}

func TestWhatIsSeenOftenFromManyClientsBecomesEnforceable(t *testing.T) {
	g, _ := learnedShop(t)
	for _, tt := range []struct {
		method, path string
		want         State
	}{
		{"GET", "/api/items", StateEnforceable},
		{"GET", "/api/items/{int}", StateEnforceable},
		{"POST", "/api/items", StateEnforceable},
		{"GET", "/api/users/{uuid}", StateEnforceable},
		{"DELETE", "/api/items/{int}", ""},
	} {
		if got := routeState(g, tt.method, tt.path); got != tt.want {
			t.Errorf("%s %s is %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
	st := g.Stats()
	if st.LearnedRoutes != 4 || st.LearnedEnforce != 4 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestLearnedRoutesRefuseWhatWasNeverSeen(t *testing.T) {
	g, _ := learnedShop(t)
	tests := []struct {
		name string
		req  *inspect.Request
		want int
	}{
		{"a normal list", mk("GET", "/api/items?limit=10&sort=price"), 0},
		{"a normal item", mk("GET", "/api/items/4242"), 0},
		{"a normal create", mk("POST", "/api/items", withJSON(`{"title":"t","price":3.5,"tags":["x"]}`)), 0},
		{"HEAD is the GET route", mk("HEAD", "/api/items/4242"), 0},
		{"an unknown route", mk("GET", "/api/admin/dump"), IDLearnedUnknownRoute},
		{"a method that was never seen on a known route", mk("DELETE", "/api/items/4242"), IDLearnedMethodNotSeen},
		{"a path that is not an integer where one was always an integer", mk("GET", "/api/items/abc"), IDLearnedUnknownRoute},
		{"an injection where an id was", mk("GET", "/api/items/1%27%20OR%201%3D1"), IDLearnedUnknownRoute},
		{"a parameter of the wrong type", mk("GET", "/api/items?limit=abc&sort=name"), IDLearnedQueryParam},
		{"a SQL injection in an integer parameter", mk("GET", "/api/items?limit=1%27%3B%20DROP%20TABLE%20items--&sort=name"), IDLearnedQueryParam},
		{"a value that was never one of the few values", mk("GET", "/api/items?limit=10&sort=password"), IDLearnedQueryParam},
		{"a parameter that was never seen", mk("GET", "/api/items?limit=10&sort=name&debug=1"), IDLearnedUnknownQuery},
		{"a body property that was never seen", mk("POST", "/api/items", withJSON(`{"title":"t","price":3.5,"tags":["x"],"colour":"red"}`)), IDLearnedUnknownProperty},
		{"a privileged property that was never seen is refused as mass assignment first", mk("POST", "/api/items", withJSON(`{"title":"t","price":3.5,"tags":["x"],"owner":"x"}`)), IDMassAssignRefused},
		{"a body value of a type never seen", mk("POST", "/api/items", withJSON(`{"title":["x"],"price":3.5,"tags":["x"]}`)), IDLearnedBodyType},
		{"a number where a string always was", mk("POST", "/api/items", withJSON(`{"title":5,"price":3.5,"tags":["x"]}`)), IDLearnedBodyType},
		{"a property that every body had is missing", mk("POST", "/api/items", withJSON(`{"price":3.5}`)), IDLearnedMissingProperty},
		{"a content type never seen on the route", mk("POST", "/api/items", withBody("application/x-www-form-urlencoded", `title=x`)), IDLearnedContentType},
		{"a body on a route that never had one", mk("GET", "/api/items/4242", withJSON(`{"a":1}`)), IDLearnedUnexpectedBody},
		{"a missing body on a route that always had one", mk("POST", "/api/items"), IDLearnedBodyMissing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := g.Inspect(tt.req)
			if tt.want == 0 {
				if len(res.Verdicts) != 0 {
					t.Fatalf("unexpected %+v", res.Verdicts)
				}
				return
			}
			if !has(res, tt.want) {
				t.Fatalf("verdicts %v, want %d", ids(res), tt.want)
			}
			if !blocked(res) {
				t.Fatalf("the learned model is enforced and did not block: %+v", res.Verdicts)
			}
		})
	}
}

func TestLearnedFindingsAreWarningsByDefault(t *testing.T) {
	g, _ := testGuard(t, nil) // Learned is monitor
	for i := 0; i < 400; i++ {
		g.Observe(shopTraffic(i), 200)
	}
	res := g.Inspect(mk("GET", "/api/admin/dump"))
	if !has(res, IDLearnedUnknownRoute) || blocked(res) {
		t.Fatalf("verdicts %+v", res.Verdicts)
	}
	g2, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeLearn })
	for i := 0; i < 400; i++ {
		g2.Observe(shopTraffic(i), 200)
	}
	if res := g2.Inspect(mk("GET", "/api/admin/dump")); len(res.Verdicts) != 0 {
		t.Fatalf("learn mode must observe and say nothing: %+v", res.Verdicts)
	}
	if g2.Stats().LearnedRoutes == 0 {
		t.Fatal("learn mode learned nothing")
	}
	g3, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeOff })
	for i := 0; i < 400; i++ {
		g3.Observe(shopTraffic(i), 200)
	}
	if g3.Stats().LearnedRoutes != 0 {
		t.Fatal("a learner that is off learned")
	}
}

func TestNothingIsRefusedAsUnknownBeforeAnythingIsKnown(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeEnforce })
	for i := 0; i < 20; i++ {
		g.Observe(shopTraffic(i), 200)
	}
	if res := g.Inspect(mk("GET", "/api/items?limit=5")); len(res.Verdicts) != 0 {
		t.Fatalf("a new guard refused a request: %+v", res.Verdicts)
	}
}

// The attack: a client floods a route with requests that the application answers with 200. However many it sends, it must not be
// able to make the guard believe the route, the parameter or the property is normal.
func TestAnAttackerFloodingFromOneClientCannotTeachTheModelAnything(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeEnforce })
	for i := 0; i < 400; i++ {
		g.Observe(shopTraffic(i), 200)
	}
	attacker := withClient("192.0.2.66")
	for i := 0; i < 5000; i++ {
		g.Observe(mk("GET", "/api/backdoor?cmd=whoami", attacker), 200)                                                                     // a route nobody else uses
		g.Observe(mk("GET", "/api/items?limit=abc&debug=1", attacker), 200)                                                                 // a type and a parameter nobody else uses
		g.Observe(mk("POST", "/api/items", attacker, withJSON(`{"title":"x","price":1,"tags":["a"],"is_admin":true,"colour":"red"}`)), 200) // properties
		g.Observe(mk("GET", "/api/items/1' OR '1'='1", attacker), 200)                                                                      // an injection where an id is
		g.Observe(mk("DELETE", "/api/items/5", attacker), 200)                                                                              // a method nobody else uses
	}
	g.Flush()
	for _, tt := range []struct {
		name string
		req  *inspect.Request
		want int
	}{
		{"the backdoor route", mk("GET", "/api/backdoor?cmd=whoami"), IDLearnedUnknownRoute},
		{"the wrong-typed parameter", mk("GET", "/api/items?limit=abc&sort=name"), IDLearnedQueryParam},
		{"the parameter", mk("GET", "/api/items?limit=10&sort=name&debug=1"), IDLearnedUnknownQuery},
		{"the property", mk("POST", "/api/items", withJSON(`{"title":"x","price":1,"tags":["a"],"colour":"red"}`)), IDLearnedUnknownProperty},
		{"the privileged property", mk("POST", "/api/items", withJSON(`{"title":"x","price":1,"tags":["a"],"is_admin":true}`)), IDMassAssignRefused},
		{"the injection", mk("GET", "/api/items/1%27%20OR%20%271%27%3D%271"), IDLearnedUnknownRoute},
		{"the method", mk("DELETE", "/api/items/5"), IDLearnedMethodNotSeen},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if res := g.Inspect(tt.req); !has(res, tt.want) || !blocked(res) {
				t.Fatalf("the flood taught the model something: verdicts %+v", res.Verdicts)
			}
		})
	}
	if routeState(g, "GET", "/api/backdoor") == StateEnforceable {
		t.Fatal("the route became enforceable")
	}
}

// Negative control for the test above: the same flood from enough clients does teach the model. If it did not, the test above
// would be passing because nothing is ever learned, not because the rule works.
func TestTheSameFloodFromEnoughClientsIsLearned(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeEnforce })
	for i := 0; i < 400; i++ {
		g.Observe(shopTraffic(i), 200)
	}
	for i := 0; i < 400; i++ {
		g.Observe(mk("GET", "/api/backdoor?cmd=whoami", withClient(ip(i%80))), 200)
	}
	g.Flush()
	if routeState(g, "GET", "/api/backdoor") != StateEnforceable {
		t.Fatal("a route seen 400 times from 80 clients was not learned")
	}
	if res := g.Inspect(mk("GET", "/api/backdoor?cmd=whoami")); len(res.Verdicts) != 0 {
		t.Fatalf("a learned route was refused: %+v", res.Verdicts)
	}
}

func TestHowManyCollaboratingClientsItTakes(t *testing.T) {
	tests := []struct {
		name    string
		clients int
		each    int
		want    State
	}{
		{"two clients", 2, 500, StateLearning},
		{"three clients", 3, 500, StateLearning},
		{"four clients sharing it equally are a quarter each", 4, 500, StateLearning},
		{"five clients sharing it equally are a fifth each, the rule's limit", 5, 20, StateEnforceable},
		{"five clients with too little between them", 5, 5, StateLearning},
		{"thirty clients, once each", 30, 1, StateEnforceable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, _ := testGuard(t, nil)
			for c := 0; c < tt.clients; c++ {
				for k := 0; k < tt.each; k++ {
					g.Observe(mk("GET", "/api/probe", withClient(ip(c))), 200)
				}
			}
			g.Flush()
			if got := routeState(g, "GET", "/api/probe"); got != tt.want {
				t.Fatalf("state %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOnlySuccessfulRequestsToAPIsAreLearnedFrom(t *testing.T) {
	tests := []struct {
		name   string
		req    *inspect.Request
		status int
		learn  bool
	}{
		{"200", mk("GET", "/api/a"), 200, true},
		{"201", mk("POST", "/api/a", withJSON(`{}`)), 201, true},
		{"304", mk("GET", "/api/a"), 304, true},
		{"399", mk("GET", "/api/a"), 399, true},
		{"400", mk("GET", "/api/a"), 400, false},
		{"401", mk("GET", "/api/a"), 401, false},
		{"404", mk("GET", "/api/a"), 404, false},
		{"500", mk("GET", "/api/a"), 500, false},
		{"100 is not a final answer", mk("GET", "/api/a"), 100, false},
		{"0", mk("GET", "/api/a"), 0, false},
		{"a page is not an API", mk("GET", "/index.html"), 200, false},
		{"OPTIONS says nothing about the API", mk("OPTIONS", "/api/a"), 200, false},
		{"a method that is not allowed is not learned", mk("TRACE", "/api/a"), 200, false},
		{"an absurd body is not evidence", mk("GET", "/api/a", withJSON(`{"q":"`+strings.Repeat("a", 20<<10)+`"}`)), 200, false},
		{"JSON sent to any path is an API", mk("POST", "/anything", withJSON(`{}`)), 200, true},
		{"HEAD is learned as GET", mk("HEAD", "/api/a"), 200, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, _ := testGuard(t, nil)
			g.Observe(tt.req, tt.status)
			if got := g.Stats().LearnedRoutes > 0; got != tt.learn {
				t.Fatalf("learned = %v, want %v", got, tt.learn)
			}
		})
	}
}

func TestRequiredMeansSeenInNinetyFivePercent(t *testing.T) {
	post := func(i int, extra string) *inspect.Request {
		return mk("POST", "/api/orders", withClient(ip(i)), withJSON(fmt.Sprintf(`{"item":%d%s}`, i, extra)))
	}
	t.Run("a property in every body is required", func(t *testing.T) {
		g, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeEnforce })
		for i := 0; i < 100; i++ {
			g.Observe(post(i, `,"qty":2`), 200)
		}
		if res := g.Inspect(mk("POST", "/api/orders", withJSON(`{"item":3}`))); !has(res, IDLearnedMissingProperty) {
			t.Fatalf("%+v", res.Verdicts)
		}
	})
	t.Run("a property in nine bodies in ten is optional", func(t *testing.T) {
		g, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeEnforce })
		for i := 0; i < 100; i++ {
			extra := `,"note":"x"`
			if i%10 == 0 {
				extra = ""
			}
			g.Observe(post(i, extra), 200)
		}
		if res := g.Inspect(mk("POST", "/api/orders", withJSON(`{"item":3}`))); len(res.Verdicts) != 0 {
			t.Fatalf("an optional property was required: %+v", res.Verdicts)
		}
	})
	t.Run("fewer than twenty bodies say nothing about what is required", func(t *testing.T) {
		g, _ := testGuard(t, func(c *Config) { c.Learn.MinObservations = 10; c.Learn.MinClients = 3; c.Modes.Learned = ModeEnforce })
		for i := 0; i < 15; i++ {
			g.Observe(post(i, `,"qty":2`), 200)
		}
		if res := g.Inspect(mk("POST", "/api/orders", withJSON(`{"item":3}`))); has(res, IDLearnedMissingProperty) {
			t.Fatalf("%+v", res.Verdicts)
		}
	})
}

func TestAPositionWithManyResourceNamesIsNotAParameterButOneWithManySlugsIs(t *testing.T) {
	t.Run("an API with fifteen resources", func(t *testing.T) {
		g, _ := testGuard(t, nil)
		names := []string{"users", "orders", "products", "invoices", "carts", "coupons", "reviews", "tags", "regions", "shipments", "returns", "wishlists", "sessions", "reports", "settings"}
		for i := 0; i < 600; i++ {
			g.Observe(mk("GET", "/api/"+names[i%len(names)], withClient(ip(i))), 200)
		}
		if n := g.Stats().CollapsedPlaces; n != 0 {
			t.Fatalf("%d positions were read as parameters", n)
		}
		g.Flush()
		if routeState(g, "GET", "/api/users") != StateEnforceable {
			t.Fatal("a resource was not learned by name")
		}
	})
	t.Run("a catalogue with a slug for each product", func(t *testing.T) {
		g, _ := testGuard(t, nil)
		for i := 0; i < 300; i++ {
			g.Observe(mk("GET", fmt.Sprintf("/api/catalogue/shoe-%c%c", 'a'+i%26, 'a'+i/26%26), withClient(ip(i))), 200)
		}
		// The slugs above all contain no digit: they are words until enough of them have been seen.
		if n := g.Stats().CollapsedPlaces; n != 1 {
			t.Fatalf("%d positions collapsed, want 1", n)
		}
		g.Flush()
		if routeState(g, "GET", "/api/catalogue/{id}") != StateEnforceable {
			t.Fatalf("routes: %v", routeNames(g.Snapshot()))
		}
		if res := g.Inspect(mk("GET", "/api/catalogue/some-new-slug")); len(res.Verdicts) != 0 {
			t.Fatalf("a slug that was not seen before was refused: %+v", res.Verdicts)
		}
	})
	t.Run("too few sightings to say", func(t *testing.T) {
		g, _ := testGuard(t, nil)
		for i := 0; i < 12; i++ {
			g.Observe(mk("GET", fmt.Sprintf("/api/catalogue/word%c", 'a'+i), withClient(ip(i))), 200)
		}
		if n := g.Stats().CollapsedPlaces; n != 0 {
			t.Fatalf("collapsed after %d sightings", 12)
		}
	})
}

func TestAnEnumerationIsLearnedOnlyFromValuesWithSupport(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeEnforce })
	for i := 0; i < 300; i++ {
		g.Observe(mk("GET", "/api/list?status="+[]string{"open", "closed", "pending"}[i%3], withClient(ip(i))), 200)
	}
	// One attacker adds a value of its own, many times.
	for i := 0; i < 500; i++ {
		g.Observe(mk("GET", "/api/list?status=x;DROP", withClient("192.0.2.9")), 200)
	}
	g.Flush()
	if res := g.Inspect(mk("GET", "/api/list?status=closed")); len(res.Verdicts) != 0 {
		t.Fatalf("a value that was learned was refused: %+v", res.Verdicts)
	}
	if res := g.Inspect(mk("GET", "/api/list?status=x;DROP")); !has(res, IDLearnedQueryParam) {
		t.Fatalf("a value one client taught was believed: %+v", res.Verdicts)
	}
	if res := g.Inspect(mk("GET", "/api/list?status=")); len(res.Verdicts) != 0 {
		t.Fatalf("an empty value was refused: %+v", res.Verdicts)
	}
}

func TestLearnedRoutesDecay(t *testing.T) {
	g, clk := testGuard(t, nil)
	for i := 0; i < 100; i++ {
		g.Observe(mk("GET", "/api/old", withClient(ip(i))), 200)
	}
	g.Observe(mk("GET", "/api/once", withClient(ip(1))), 200)
	g.Flush()
	if routeState(g, "GET", "/api/old") != StateEnforceable || routeState(g, "GET", "/api/once") != StateLearning {
		t.Fatalf("setup: %v", g.Snapshot().Routes)
	}
	clk.Advance(8 * 24 * time.Hour) // past LearningTTL (7 days), before RouteTTL (30)
	g.Sweep()
	if routeState(g, "GET", "/api/once") != "" {
		t.Error("a route that never became enforceable was kept past its time")
	}
	if routeState(g, "GET", "/api/old") != StateEnforceable {
		t.Error("an enforceable route was forgotten early")
	}
	clk.Advance(30 * 24 * time.Hour)
	g.Sweep()
	if routeState(g, "GET", "/api/old") != "" {
		t.Error("an enforceable route that has not been seen for 30 days was kept")
	}
	// A route in use is never forgotten.
	for i := 0; i < 100; i++ {
		g.Observe(mk("GET", "/api/live", withClient(ip(i))), 200)
	}
	clk.Advance(29 * 24 * time.Hour)
	g.Observe(mk("GET", "/api/live", withClient(ip(1))), 200)
	clk.Advance(29 * 24 * time.Hour)
	g.Sweep()
	if routeState(g, "GET", "/api/live") != StateEnforceable {
		t.Error("a route that is in use was forgotten")
	}
}

func TestLearningIsBoundedInMemory(t *testing.T) {
	// DistinctValues at its largest, so that the flood below is not read as a parameter and has to be held by the caps instead.
	g, _ := testGuard(t, func(c *Config) {
		c.Learn.MaxRoutes = 50
		c.Learn.MaxNodes = 500
		c.Learn.MaxPositions = 40
		c.Learn.DistinctValues = 64
	})
	word := func(i int) string { return string([]byte{'g' + byte(i%20), 'g' + byte(i/20%20), 'g' + byte(i/400%20)}) }
	for i := 0; i < 5000; i++ {
		g.Observe(mk("GET", "/api/"+word(i), withClient(ip(i))), 200)
	}
	st := g.Stats()
	if st.LearnedRoutes > 50 || st.LearnNodes > 500 || st.LearnDropped == 0 {
		t.Fatalf("stats = %+v", st)
	}
	// Properties and parameters are bounded too.
	g2, _ := testGuard(t, nil)
	var body strings.Builder
	body.WriteString("{")
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&body, `"p%d":%d,`, i, i)
	}
	body.WriteString(`"z":0}`)
	var q strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&q, "a%d=1&", i)
	}
	for i := 0; i < 50; i++ {
		g2.Observe(mk("POST", "/api/wide?"+q.String(), withClient(ip(i)), withJSON(body.String())), 200)
	}
	var wide *LearnedRoute
	for _, r := range g2.Snapshot().Routes {
		if r.Path == "/api/wide" {
			wide = r.Learned
		}
	}
	if wide == nil || len(wide.Query) > maxQueryParams || len(wide.Body.Props) > maxShapeProps || !wide.Body.Open {
		t.Fatalf("a wide request was followed past the limits: %d query params, %d properties", len(wide.Query), len(wide.Body.Props))
	}
	// A body nested very deeply is followed only so far.
	deep := strings.Repeat(`{"a":`, 30) + "1" + strings.Repeat("}", 30)
	for i := 0; i < 50; i++ {
		g2.Observe(mk("POST", "/api/deep", withClient(ip(i)), withJSON(deep)), 200)
	}
	for _, r := range g2.Snapshot().Routes {
		if r.Path == "/api/deep" {
			if n := r.Learned.Body.count(); n > maxShapeDepth+2 {
				t.Fatalf("a deep body was followed to %d nodes", n)
			}
		}
	}
}

func TestApproveAndRecordingsAreOwnerEvidence(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeEnforce })
	for i := 0; i < 400; i++ {
		g.Observe(shopTraffic(i), 200)
	}
	if res := g.Inspect(mk("GET", "/api/new/feature")); !blocked(res) {
		t.Fatalf("setup: %+v", res.Verdicts)
	}
	if err := g.Approve("GET", "/api/new/feature"); err != nil {
		t.Fatal(err)
	}
	if res := g.Inspect(mk("GET", "/api/new/feature")); len(res.Verdicts) != 0 {
		t.Fatalf("an approved route was refused: %+v", res.Verdicts)
	}
	for _, bad := range [][2]string{{"OPTIONS", "/api/x"}, {"TRACE", "/api/x"}, {"GET", "api/x"}, {"GET", ""}} {
		if err := g.Approve(bad[0], bad[1]); err == nil {
			t.Errorf("Approve(%q, %q) was accepted", bad[0], bad[1])
		}
	}
}

func TestTheLearnerIsSafeForManyRequestsAtOnce(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeEnforce })
	var wg sync.WaitGroup
	for w := 0; w < 12; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 1500; i++ {
				r := shopTraffic(w*1500 + i)
				if i%5 == 0 {
					g.Inspect(r)
				}
				g.Observe(r, 200)
				if i%500 == 0 {
					g.Snapshot()
					g.Stats()
				}
			}
		}(w)
	}
	wg.Wait()
	g.Flush()
	if routeState(g, "GET", "/api/items") != StateEnforceable {
		t.Fatalf("after 18,000 requests: %v", routeNames(g.Snapshot()))
	}
	if g.Stats().Panics != 0 {
		t.Fatal("panics")
	}
}
