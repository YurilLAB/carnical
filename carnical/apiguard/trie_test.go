// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"slices"
	"strings"
	"testing"
)

// modelOf makes a model out of route templates ("GET /a/{id}") the way an import would finish one.
func modelOf(t testing.TB, routes ...string) Model {
	t.Helper()
	m := Model{Format: ModelFormat}
	for _, r := range routes {
		method, path, _ := strings.Cut(r, " ")
		m.Routes = append(m.Routes, Route{Method: method, Path: path, State: StateDeclared})
	}
	m.finish(nil)
	return m
}

func TestRouteMatching(t *testing.T) {
	m := modelOf(t,
		"GET /users", "POST /users", "GET /users/{id}", "PUT /users/{id}", "GET /users/me", "GET /users/{id}/orders",
		"GET /users/me/settings", "GET /files/{name}.json", "GET /files/{name}", "GET /v{version}/ping", "GET /a/{x}/b/{y}",
		"GET /static/readme", "DELETE /a/{x}/b/{y}", "GET /",
	)
	tests := []struct {
		name   string
		method string
		path   string
		want   string // the template, or "" for no route at the path
		caps   []string
		allow  []string // when the path matches but not the method
	}{
		{"a literal path", "GET", "/users", "GET /users", nil, nil},
		{"a path with a parameter", "GET", "/users/42", "GET /users/{id}", []string{"42"}, nil},
		{"a literal wins over a parameter", "GET", "/users/me", "GET /users/me", nil, nil},
		{"a parameter is used when the literal branch has no route below it", "GET", "/users/me/orders", "GET /users/{id}/orders", []string{"me"}, nil},
		{"a literal below a literal", "GET", "/users/me/settings", "GET /users/me/settings", nil, nil},
		{"a trailing slash is ignored", "GET", "/users/42/", "GET /users/{id}", []string{"42"}, nil},
		{"HEAD is served by the GET route", "HEAD", "/users", "GET /users", nil, nil},
		{"a method the path does not have", "PATCH", "/users", "", nil, []string{"GET", "POST"}},
		{"a path that is not a route", "GET", "/nothing", "", nil, nil},
		{"too deep", "GET", "/users/42/orders/7", "", nil, nil},
		{"a suffix after the parameter", "GET", "/files/report.json", "GET /files/{name}.json", []string{"report"}, nil},
		{"the plain parameter when the suffix does not match", "GET", "/files/report.txt", "GET /files/{name}", []string{"report.txt"}, nil},
		{"a prefix before the parameter", "GET", "/v2/ping", "GET /v{version}/ping", []string{"2"}, nil},
		{"two parameters", "GET", "/a/1/b/2", "GET /a/{x}/b/{y}", []string{"1", "2"}, nil},
		{"two parameters, another method", "DELETE", "/a/1/b/2", "DELETE /a/{x}/b/{y}", []string{"1", "2"}, nil},
		{"the root", "GET", "/", "GET /", nil, nil},
		{"an empty segment is not a parameter", "GET", "/users//orders", "", nil, nil},
		{"a percent-encoded segment is decoded before it is compared", "GET", "/static/%72eadme", "GET /static/readme", nil, nil},
		{"an encoded value is captured decoded", "GET", "/users/a%20b", "GET /users/{id}", []string{"a b"}, nil},
		{"a bad escape matches nothing", "GET", "/users/%zz", "", nil, nil},
		{"more segments than the limit", "GET", "/a" + strings.Repeat("/x", MaxPathSegments), "", nil, nil},
		{"a path that does not start with a slash", "GET", "users", "", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var caps captures
			node := m.idx.lookup(tt.path, &caps)
			if tt.want == "" && tt.allow == nil {
				if node != nil {
					t.Fatalf("matched %v", node.methods)
				}
				return
			}
			if node == nil {
				t.Fatal("no match")
			}
			rt := node.route(tt.method)
			if tt.allow != nil {
				if rt != nil || !slices.Equal(node.methods, tt.allow) {
					t.Fatalf("route %v, methods %v, want none and %v", rt, node.methods, tt.allow)
				}
				return
			}
			if rt == nil || rt.Method+" "+rt.Path != tt.want {
				t.Fatalf("matched %v, want %s", rt, tt.want)
			}
			if !slices.Equal(caps.vals[:caps.n], tt.caps) {
				t.Fatalf("captures %v, want %v", caps.vals[:caps.n], tt.caps)
			}
		})
	}
}

func TestDuplicateTemplatesKeepTheFirstAndAreReported(t *testing.T) {
	var warned []string
	m := Model{Routes: []Route{{Method: "GET", Path: "/u/{id}"}, {Method: "GET", Path: "/u/{name}"}, {Method: "GET", Path: "/u/"}}}
	m.finish(func(s string) { warned = append(warned, s) })
	if len(warned) != 1 || !strings.Contains(warned[0], "repeat") {
		t.Fatalf("warnings = %v", warned)
	}
	var caps captures
	if m.idx.lookup("/u/5", &caps) == nil || m.idx.n != 2 {
		t.Fatalf("routes indexed: %d", m.idx.n)
	}
}

func TestMatchingIsFastOnALargeModel(t *testing.T) {
	var routes []string
	for i := 0; i < 3000; i++ {
		routes = append(routes, "GET /api/r"+strings.Repeat("x", i%7)+"/"+string(rune('a'+i%26))+"/{id}/items/"+strings.Repeat("y", i%5))
	}
	m := modelOf(t, routes...)
	var caps captures
	start := nowNano()
	for i := 0; i < 20000; i++ {
		caps.n = 0
		m.idx.lookup("/api/rxxx/c/42/items/yy", &caps)
		m.idx.lookup("/api/nothing/at/all", &caps)
	}
	if per := (nowNano() - start) / 40000; per > 20_000 {
		t.Fatalf("%d ns per lookup", per)
	}
}
