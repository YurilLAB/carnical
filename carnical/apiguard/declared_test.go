// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

func shopGuard(t testing.TB, change func(*Config)) *Guard {
	t.Helper()
	g, _ := testGuard(t, func(c *Config) {
		c.Modes.Spec = ModeEnforce
		if change != nil {
			change(c)
		}
	})
	if _, err := g.ImportOpenAPI([]byte(shopAPI)); err != nil {
		t.Fatal(err)
	}
	return g
}

func auth(r *inspect.Request) { r.Header.Set("Authorization", "Bearer token-1") }

func TestRequestsAreHeldToTheApiDescription(t *testing.T) {
	longQ := strings.Repeat("q", 51)
	tests := []struct {
		name   string
		req    *inspect.Request
		want   int // the first verdict id, 0 for none
		status int
	}{
		{"a read that fits", mk("GET", "/api/v1/products?limit=10&page=2&sort=-price&q=shoes&tags=a,b"), 0, 0},
		{"HEAD is served by the GET route", mk("HEAD", "/api/v1/products?limit=10"), 0, 0},
		{"a preflight is not held to the description", mk("OPTIONS", "/api/v1/products", withHeader("Access-Control-Request-Method", "POST")), 0, 0},
		{"an OPTIONS request that is not a preflight", mk("OPTIONS", "/api/v1/products"), IDSpecMethodNotAllowed, 405},
		{"an OPTIONS request with a body", mk("OPTIONS", "/api/v1/products", withHeader("Access-Control-Request-Method", "POST"), withJSON(`{"name":"n"}`)), IDSpecMethodNotAllowed, 405},
		{"an OPTIONS request to an undescribed route", mk("OPTIONS", "/api/v1/admin/purge"), IDSpecUnknownRoute, 404},
		{"a preflight to an undescribed route", mk("OPTIONS", "/api/v1/admin/purge?all=1", withHeader("Access-Control-Request-Method", "DELETE")), IDSpecUnknownRoute, 404},
		{"a preflight for a method the route does not have", mk("OPTIONS", "/api/v1/products", withHeader("Access-Control-Request-Method", "PATCH")), IDSpecMethodNotAllowed, 405},
		{"a parameter after the ones the guard reads", mk("GET", "/api/v1/products?"+strings.Repeat("utm=x&", maxQueryPairs)+"limit=101"), IDSpecQueryParam, 400},
		// Server-side parsers (Go strconv, Python, PHP, Java) read these as numbers; the bounds still apply to the value.
		{"an integer with leading zeros", mk("GET", "/api/v1/products?limit=007"), 0, 0},
		{"an integer with a plus sign", mk("GET", "/api/v1/products?limit=%2B7"), 0, 0},
		{"leading zeros do not hide a value over the maximum", mk("GET", "/api/v1/products?limit=0101"), IDSpecQueryParam, 400},
		{"a number that is not an integer", mk("GET", "/api/v1/products?limit=7."), IDSpecQueryParam, 400},
		{"a sign twice", mk("GET", "/api/v1/products?limit=%2B-7"), IDSpecQueryParam, 400},
		{"a query parameter of the wrong type", mk("GET", "/api/v1/products?limit=abc"), IDSpecQueryParam, 400},
		{"a query parameter over its maximum", mk("GET", "/api/v1/products?limit=101"), IDSpecQueryParam, 400},
		{"a query parameter under its minimum", mk("GET", "/api/v1/products?limit=0"), IDSpecQueryParam, 400},
		{"an injection in an integer parameter", mk("GET", "/api/v1/products?page=1%27%20OR%201%3D1--"), IDSpecQueryParam, 400},
		{"a value that is not in the enum", mk("GET", "/api/v1/products?sort=evil"), IDSpecQueryParam, 400},
		{"a string over its maximum length", mk("GET", "/api/v1/products?q="+longQ), IDSpecQueryParam, 400},
		{"an array over its maximum size", mk("GET", "/api/v1/products?tags=a,b,c,d"), IDSpecQueryParam, 400},
		{"a scalar given twice", mk("GET", "/api/v1/products?limit=1&limit=2"), IDSpecQueryParam, 400},
		{"an unknown query parameter is allowed by default", mk("GET", "/api/v1/products?utm_source=x"), 0, 0},
		{"a path parameter that fits", mk("GET", "/api/v1/products/42"), 0, 0},
		{"a path parameter of the wrong type", mk("GET", "/api/v1/products/abc"), IDSpecPathParam, 400},
		{"a path parameter under its minimum", mk("GET", "/api/v1/products/0"), IDSpecPathParam, 400},
		{"a uuid path parameter that is not a uuid", mk("GET", "/api/v1/users/not-a-uuid", auth), IDSpecPathParam, 400},
		{"a uuid path parameter that is one", mk("GET", "/api/v1/users/123e4567-e89b-12d3-a456-426614174000", auth), 0, 0},
		{"an unknown route", mk("GET", "/api/v1/secret"), IDSpecUnknownRoute, 404},
		{"an unknown route in a deeper place", mk("GET", "/api/v1/products/42/secret"), IDSpecUnknownRoute, 404},
		{"a method the route does not have", mk("PATCH", "/api/v1/products"), IDSpecMethodNotAllowed, 405},
		{"a route that needs a credential and has none", mk("POST", "/api/v1/products", withJSON(`{"name":"n","price":9.99}`)), IDSpecNoCredential, 401},
		{"a create that fits", mk("POST", "/api/v1/products", auth, withJSON(`{"name":"n","price":9.99,"category":"toys","note":null}`)), 0, 0},
		{"a credential in the header the description names", mk("POST", "/api/v1/products", withHeader("X-Shop-Key", "abcdefgh"), withJSON(`{"name":"n","price":9.99}`)), 0, 0},
		{"a body missing a required property (through allOf)", mk("POST", "/api/v1/products", auth, withJSON(`{"name":"n"}`)), IDSpecBodySchema, 400},
		{"a body with a number below its minimum", mk("POST", "/api/v1/products", auth, withJSON(`{"name":"n","price":-1}`)), IDSpecBodySchema, 400},
		{"a body with a price that is not a multiple of a cent", mk("POST", "/api/v1/products", auth, withJSON(`{"name":"n","price":1.234}`)), IDSpecBodySchema, 400},
		{"a body value not in the enum", mk("POST", "/api/v1/products", auth, withJSON(`{"name":"n","price":1,"category":"drugs"}`)), IDSpecBodySchema, 400},
		{"a read-only property in a create", mk("POST", "/api/v1/products", auth, withJSON(`{"id":7,"name":"n","price":1}`)), IDSpecReadOnlyProperty, 403},
		{"a required body that is missing", mk("POST", "/api/v1/products", auth), IDSpecBodyMissing, 400},
		{"a content type the route does not take", mk("POST", "/api/v1/products", auth, withBody("text/plain", `name=n`)), IDSpecContentType, 415},
		{"a body on a route that takes none", mk("GET", "/api/v1/products", withBody("application/json", `{"a":1}`)), IDSpecUnexpectedBody, 400},
		{"a registration that fits", mk("POST", "/api/v1/users", withJSON(`{"email":"a@b.example","password":"longenough"}`)), 0, 0},
		{"a registration with a property the schema does not allow", mk("POST", "/api/v1/users", withJSON(`{"email":"a@b.example","password":"longenough","nickname":"x"}`)), IDSpecUnknownProperty, 400},
		{"a registration with a password that is too short", mk("POST", "/api/v1/users", withJSON(`{"email":"a@b.example","password":"short"}`)), IDSpecBodySchema, 400},
		{"a registration with a bad email", mk("POST", "/api/v1/users", withJSON(`{"email":"nope","password":"longenough"}`)), IDSpecBodySchema, 400},
		{"an update that sets a read-only role", mk("PATCH", "/api/v1/users/123e4567-e89b-12d3-a456-426614174000", auth, withJSON(`{"role":"admin"}`)), IDSpecReadOnlyProperty, 403},
		{"an update that fits", mk("PATCH", "/api/v1/users/123e4567-e89b-12d3-a456-426614174000", auth, withJSON(`{"name":"Alice"}`)), 0, 0},
		{"a header parameter and a pattern that fit", mk("GET", "/api/v1/orders/AB-123456", withHeader("X-Shop-Key", "12345678")), 0, 0},
		{"a required header that is missing", mk("GET", "/api/v1/orders/AB-123456", auth), IDSpecMissingParam, 400},
		{"a header that is too short", mk("GET", "/api/v1/orders/AB-123456", withHeader("X-Shop-Key", "123")), IDSpecHeaderParam, 400},
		{"a path that does not match its pattern", mk("GET", "/api/v1/orders/ab-1", withHeader("X-Shop-Key", "12345678")), IDSpecPathParam, 400},
		{"a page the description does not cover is none of its business", mk("GET", "/index.html"), 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := shopGuard(t, nil)
			res := g.Inspect(tt.req)
			if tt.want == 0 {
				if len(res.Verdicts) != 0 {
					t.Fatalf("unexpected verdicts: %+v", res.Verdicts)
				}
				return
			}
			if len(res.Verdicts) == 0 || res.Verdicts[0].ID != tt.want {
				t.Fatalf("verdicts %+v, want %d first", res.Verdicts, tt.want)
			}
			if v := res.Verdicts[0]; !v.Block || v.Status != tt.status {
				t.Fatalf("verdict %+v, want a block with status %d", v, tt.status)
			}
		})
	}
}

func TestDescriptionFindingsAreWarningsUntilThePromotedToEnforce(t *testing.T) {
	g := shopGuard(t, func(c *Config) { c.Modes.Spec = ModeDefault })
	res := g.Inspect(mk("GET", "/api/v1/secret"))
	if len(res.Verdicts) != 1 || res.Verdicts[0].ID != IDSpecUnknownRoute || res.Verdicts[0].Block {
		t.Fatalf("by default a description finding must be reported and not block: %+v", res.Verdicts)
	}
	if err := g.SetModes(Modes{Spec: ModeEnforce}); err != nil {
		t.Fatal(err)
	}
	if res := g.Inspect(mk("GET", "/api/v1/secret")); !blocked(res) {
		t.Fatalf("after the owner promotes it, it must block: %+v", res.Verdicts)
	}
}

// A segment with two parameters is one capture. The parameters after it must still be checked against their own values, and a
// value that fits must not be refused because it was checked against another parameter's schema.
func TestParametersAfterASharedSegmentKeepTheirPlace(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Spec = ModeEnforce })
	if _, err := g.ImportOpenAPI([]byte(`{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{
		"/api/r/{a}-{b}/x/{c}":{"get":{"parameters":[
			{"name":"a","in":"path","required":true,"schema":{"type":"string"}},
			{"name":"b","in":"path","required":true,"schema":{"type":"string"}},
			{"name":"c","in":"path","required":true,"schema":{"type":"integer","maximum":10}}],"responses":{"200":{"description":"ok"}}}}}}`)); err != nil {
		t.Fatal(err)
	}
	if res := g.Inspect(mk("GET", "/api/r/foo-bar/x/99999")); !has(res, IDSpecPathParam) {
		t.Fatalf("the parameter after a shared segment was not checked: %+v", res.Verdicts)
	}
	if res := g.Inspect(mk("GET", "/api/r/2024-05/x/3")); len(res.Verdicts) != 0 {
		t.Fatalf("a request that fits was refused: %+v", res.Verdicts)
	}
}

// Servers differ about which of two cookies with one name they read, and browsers send two for different paths, so every
// value is checked and a request is refused if any one fails.
func TestEveryValueOfARepeatedCookieIsChecked(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Spec = ModeEnforce })
	if _, err := g.ImportOpenAPI([]byte(`{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/api/items":{"get":{
		"parameters":[{"name":"limit","in":"cookie","schema":{"type":"integer","maximum":10}}],"responses":{"200":{"description":"ok"}}}}}}`)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cookie string
		want   bool
	}{
		{"limit=3", false},
		{"limit=99", true},
		{"limit=1; limit=99999", true},
		{"limit=99999; limit=1", true},
		{"limit=1; limit=2", false},
		{"other=1; limit=2", false},
	} {
		t.Run(tc.cookie, func(t *testing.T) {
			res := g.Inspect(mk("GET", "/api/items", withHeader("Cookie", tc.cookie)))
			if got := has(res, IDSpecCookieParam) && blocked(res); got != tc.want {
				t.Fatalf("refused %v, want %v: %+v", got, tc.want, res.Verdicts)
			}
		})
	}
}

func TestUnknownQueryParametersCanBeRefused(t *testing.T) {
	g := shopGuard(t, func(c *Config) { c.RefuseUnknownParams = true })
	for _, target := range []string{
		"/api/v1/products?limit[0]=evil", "/api/v1/products?limit[]=evil",
		"/api/v1/products?limit%5Bvalue%5D=evil", "/api/v1/products?tags[0]=evil",
	} {
		t.Run(target, func(t *testing.T) {
			if res := g.Inspect(mk("GET", target)); !has(res, IDSpecUnknownQuery) || !blocked(res) {
				t.Fatalf("an undeclared bracket alias bypassed the scalar/array contract: %+v", res.Verdicts)
			}
		})
	}
	if res := g.Inspect(mk("GET", "/api/v1/products?utm_source=x")); !has(res, IDSpecUnknownQuery) {
		t.Fatalf("verdicts %+v", res.Verdicts)
	}
	if res := g.Inspect(mk("GET", "/api/v1/products?limit=3")); len(res.Verdicts) != 0 {
		t.Fatalf("a listed parameter was refused: %+v", res.Verdicts)
	}
	t.Run("the description's own API key in the query", func(t *testing.T) {
		g, _ := testGuard(t, func(c *Config) { c.Modes.Spec = ModeEnforce; c.RefuseUnknownParams = true })
		if _, err := g.ImportOpenAPI([]byte(`{"openapi":"3.0.3","info":{"title":"t","version":"1"},
			"components":{"securitySchemes":{"key":{"type":"apiKey","in":"query","name":"api_key"}}},"security":[{"key":[]}],
			"paths":{"/api/items":{"get":{"responses":{"200":{"description":"ok"}}}}}}`)); err != nil {
			t.Fatal(err)
		}
		if res := g.Inspect(mk("GET", "/api/items?api_key=K-123")); len(res.Verdicts) != 0 {
			t.Fatalf("the credential the description names was refused as unknown: %+v", res.Verdicts)
		}
		if res := g.Inspect(mk("GET", "/api/items?api_key=K-123&debug=1")); !has(res, IDSpecUnknownQuery) {
			t.Fatalf("an unknown parameter beside it was not refused: %+v", res.Verdicts)
		}
	})
}

func TestDescriptionMessagesNameTheDescriptionAndNotTheVisitor(t *testing.T) {
	g := shopGuard(t, nil)
	res := g.Inspect(mk("GET", "/api/v1/products?limit=EVIL-VALUE"))
	if len(res.Verdicts) != 1 {
		t.Fatalf("%+v", res.Verdicts)
	}
	msg := res.Verdicts[0].Message
	if !strings.Contains(msg, "limit") || strings.Contains(msg, "EVIL") {
		t.Fatalf("message %q", msg)
	}
	res = g.Inspect(mk("POST", "/api/v1/users", withJSON(`{"email":"a@b.example","password":"longenough","EVIL-PROPERTY":1}`)))
	if len(res.Verdicts) == 0 || strings.Contains(res.Verdicts[0].Message, "EVIL") {
		t.Fatalf("%+v", res.Verdicts)
	}
}

func TestADescribedTreeOfDepthIsCheckedAndACycleDoesNotHangIt(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Spec = ModeEnforce })
	if _, err := g.ImportOpenAPI([]byte(oas31YAML)); err != nil {
		t.Fatal(err)
	}
	ok := `{"kind":"node","label":"root","children":[{"kind":"node","children":[{"kind":"node","label":null}]}]}`
	if res := g.Inspect(mk("PUT", "/nodes/3", withJSON(ok))); len(res.Verdicts) != 0 {
		t.Fatalf("a valid tree was refused: %+v", res.Verdicts)
	}
	bad := `{"kind":"node","children":[{"kind":"leaf"}]}`
	if res := g.Inspect(mk("PUT", "/nodes/3", withJSON(bad))); !blocked(res) {
		t.Fatalf("a child of the wrong kind was not refused: %+v", res.Verdicts)
	}
	if res := g.Inspect(mk("PUT", "/nodes/-3", withJSON(ok))); !has(res, IDSpecPathParam) {
		t.Fatalf("exclusiveMinimum was not applied: %+v", res.Verdicts)
	}
}
