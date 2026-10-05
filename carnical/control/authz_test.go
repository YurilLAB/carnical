// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"sort"
	"strings"
	"testing"
)

// routeCase builds one valid request for a route, for the given credential and tenant, and arranges whatever the
// stores need for it to succeed. wantStatus is what a request that is authorised should get.
type routeCase struct {
	build      func(h *harness, as, tenant string) reqOpts
	wantStatus int
}

// routeCases has one entry for every route in the table. TestAuthorizationForEveryRoute fails for a route with no entry,
// so a route added later cannot go without its tenant and scope checks being tested.
func routeCases() map[string]routeCase {
	doc := `{"mode":"block","threshold":5}`
	return map[string]routeCase{
		"GET /v1/tenants/{tenant}/policy": {func(h *harness, as, tenant string) reqOpts {
			h.seed(tenant, doc)
			return reqOpts{as: as, target: "/v1/tenants/" + tenant + "/policy"}
		}, 200},
		"PUT /v1/tenants/{tenant}/policy": {func(h *harness, as, tenant string) reqOpts {
			return reqOpts{as: as, method: "PUT", target: "/v1/tenants/" + tenant + "/policy", body: []byte(doc), ifMatch: etag(0)}
		}, 200},
		"POST /v1/tenants/{tenant}/policy:validate": {func(h *harness, as, tenant string) reqOpts {
			return reqOpts{as: as, method: "POST", target: "/v1/tenants/" + tenant + "/policy:validate", body: []byte(doc)}
		}, 200},
		"GET /v1/tenants/{tenant}/policy/history": {func(h *harness, as, tenant string) reqOpts {
			h.seed(tenant, doc)
			return reqOpts{as: as, target: "/v1/tenants/" + tenant + "/policy/history"}
		}, 200},
		"POST /v1/tenants/{tenant}/policy:rollback": {func(h *harness, as, tenant string) reqOpts {
			h.seed(tenant, `{"mode":"block","threshold":4}`) // revision 1: stricter, so going back to it does not weaken
			h.seed(tenant, doc)
			return reqOpts{as: as, method: "POST", target: "/v1/tenants/" + tenant + "/policy:rollback", body: []byte(`{"revision":1}`), ifMatch: etag(2)}
		}, 200},
		"POST /v1/tenants/{tenant}/publish": {func(h *harness, as, tenant string) reqOpts {
			h.seed(tenant, doc)
			return reqOpts{as: as, method: "POST", target: "/v1/tenants/" + tenant + "/publish", body: []byte(`{"revision":1}`), idem: "idem-" + as + "-" + tenant[:4]}
		}, 200},
		"GET /v1/tenants/{tenant}/hosts": {func(h *harness, as, tenant string) reqOpts {
			return reqOpts{as: as, target: "/v1/tenants/" + tenant + "/hosts"}
		}, 200},
		"POST /v1/tenants/{tenant}/hosts": {func(h *harness, as, tenant string) reqOpts {
			return reqOpts{as: as, method: "POST", target: "/v1/tenants/" + tenant + "/hosts", body: []byte(`{"hostname":"shop.example.com"}`)}
		}, 201},
		"POST /v1/tenants/{tenant}/hosts/{host}:verify": {func(h *harness, as, tenant string) reqOpts {
			_, _ = h.hosts.Add(context.Background(), tenant, "shop.example.com", "tok")
			return reqOpts{as: as, method: "POST", target: "/v1/tenants/" + tenant + "/hosts/shop.example.com:verify"}
		}, 200},
		"GET /v1/tenants/{tenant}/status": {func(h *harness, as, tenant string) reqOpts {
			return reqOpts{as: as, target: "/v1/tenants/" + tenant + "/status"}
		}, 200},
		"GET /v1/tenants/{tenant}/events": {func(h *harness, as, tenant string) reqOpts {
			return reqOpts{as: as, target: "/v1/tenants/" + tenant + "/events"}
		}, 200},
		"GET /v1/tenants/{tenant}/traffic": {func(h *harness, as, tenant string) reqOpts {
			return reqOpts{as: as, target: "/v1/tenants/" + tenant + "/traffic"}
		}, 200},
		"GET /v1/credentials": {func(h *harness, as, tenant string) reqOpts {
			return reqOpts{as: as, target: "/v1/credentials"}
		}, 200},
		"POST /v1/credentials/{id}:revoke": {func(h *harness, as, tenant string) reqOpts {
			return reqOpts{as: as, method: "POST", target: "/v1/credentials/reader-a:revoke"}
		}, 200},
	}
}

func allScopesBut(s Scope) []Scope {
	var out []Scope
	for _, x := range []Scope{ScopeRead, ScopeWrite, ScopePublish, ScopeAdmin, ScopeRawAddresses} {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

func TestAuthorizationForEveryRoute(t *testing.T) {
	probe := newHarness(t)
	cases := routeCases()
	routes := probe.srv.Routes()

	// the table has what the design says it has, so a route cannot be dropped without a test noticing
	var have []string
	for _, r := range routes {
		have = append(have, r.Method+" "+r.Pattern)
	}
	sort.Strings(have)
	want := []string{"GET /healthz"}
	for k := range cases {
		want = append(want, k)
	}
	sort.Strings(want)
	if strings.Join(have, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the route table and the test cases differ.\nroutes:\n%s\ncases:\n%s", strings.Join(have, "\n"), strings.Join(want, "\n"))
	}
	if len(routes) != 15 {
		t.Fatalf("%d routes; the documented API has 15", len(routes))
	}

	for _, r := range routes {
		if r.Public {
			continue
		}
		key := r.Method + " " + r.Pattern
		c := cases[key]
		t.Run(key, func(t *testing.T) {
			// Structure derived from the pattern, not declared by hand
			if r.Tenant != strings.Contains(r.Pattern, "{tenant}") {
				t.Fatalf("Tenant = %v for %s", r.Tenant, r.Pattern)
			}
			if r.Scope == "" {
				t.Fatal("a route with no scope")
			}
			if r.Action == "" {
				t.Fatal("a route with no audit action")
			}
			needsAll := r.AllTenants
			// the tenants of a credential that is meant to be allowed: all of them for credential management, else A
			var allowedTenants []string
			if !needsAll {
				allowedTenants = []string{tenantA}
			}

			// 1. the right credential, scope and tenant is served
			h := newHarness(t)
			h.addIdentity("just-scope", allowedTenants, needsAll, r.Scope)
			w := h.do(c.build(h, "just-scope", tenantA))
			if w.Code != c.wantStatus {
				t.Fatalf("an authorised request got %d, want %d: %.300s", w.Code, c.wantStatus, w.Body.String())
			}

			// 2. every scope but the needed one is refused, and nothing is touched
			h = newHarness(t)
			h.addIdentity("all-but", allowedTenants, needsAll, allScopesBut(r.Scope)...)
			req := c.build(h, "all-but", tenantA)
			before := h.touches()
			w = h.do(req)
			if w.Code != 403 || errorOf(t, w).Code != "forbidden" {
				t.Fatalf("a credential without the %s scope got %d: %.200s", r.Scope, w.Code, w.Body.String())
			}
			if h.touches() != before {
				t.Fatal("a refused request reached a store")
			}

			if r.Tenant {
				// 3. a credential for other tenants only: refused, nothing touched, whatever scopes it has
				h = newHarness(t)
				h.addIdentity("elsewhere", []string{tenantB, tenantC}, false, ScopeRead, ScopeWrite, ScopePublish, ScopeAdmin, ScopeRawAddresses)
				req := c.build(h, "elsewhere", tenantA)
				before := h.touches()
				w := h.do(req)
				if w.Code != 403 || errorOf(t, w).Code != "forbidden" {
					t.Fatalf("a credential for other tenants got %d: %.200s", w.Code, w.Body.String())
				}
				if h.touches() != before {
					t.Fatal("a request for another tenant reached a store")
				}
				if got := w.Body.String(); strings.Contains(got, tenantA) {
					t.Fatal("the refusal names the tenant")
				}

				// 4. a credential for two tenants may use each of them, and not a third
				h = newHarness(t)
				h.addIdentity("pair", []string{tenantA, tenantC}, false, r.Scope)
				for _, tn := range []string{tenantA, tenantC} {
					if w := h.do(c.build(h, "pair", tn)); w.Code != c.wantStatus {
						t.Fatalf("a credential for two tenants, on %s: %d: %.200s", tn[:4], w.Code, w.Body.String())
					}
				}
				third := c.build(h, "pair", tenantB)
				before = h.touches()
				if w := h.do(third); w.Code != 403 {
					t.Fatalf("a credential for two tenants on a third: %d", w.Code)
				}
				if h.touches() != before {
					t.Fatal("a request for a third tenant reached a store")
				}
			}

			if needsAll {
				// 5. credential management needs a credential for every tenant, with the admin scope, on a server that allows it
				h = newHarness(t)
				h.addIdentity("admin-one", []string{tenantA}, false, ScopeAdmin)
				if w := h.do(c.build(h, "admin-one", tenantA)); w.Code != 403 {
					t.Fatalf("an admin for one tenant: %d", w.Code)
				}
				h = newHarness(t, func(c *Config) { c.AllowAllTenants = false })
				if w := h.do(c.build(h, "admin", tenantA)); w.Code != 403 {
					t.Fatalf("all tenants on a server that does not allow it: %d", w.Code)
				}
			}
		})
	}
}

// A credential that holds no scope any route needs, for another tenant, is refused everywhere before any handler runs.
func TestNoHandlerRunsBeforeTheChecks(t *testing.T) {
	h := newHarness(t)
	h.addIdentity("nothing", []string{tenantB}, false, ScopeRawAddresses)
	cases := routeCases()
	for _, r := range h.srv.Routes() {
		if r.Public {
			continue
		}
		req := cases[r.Method+" "+r.Pattern].build(h, "nothing", tenantA)
		before := h.touches()
		w := h.do(req)
		if w.Code != 403 {
			t.Fatalf("%s %s: %d", r.Method, r.Pattern, w.Code)
		}
		if h.touches() != before {
			t.Fatalf("%s %s: a handler ran", r.Method, r.Pattern)
		}
	}
}

func TestCrossTenantDataNeverLeaks(t *testing.T) {
	h := newHarness(t)
	h.seed(tenantA, `{"mode":"block","threshold":5,"note":"tenant A's private note"}`)
	h.hosts.Add(context.Background(), tenantA, "a-only.example.com", "tok-a")
	// B reads A's paths: refused, with no trace of A
	for _, p := range []string{"/policy", "/policy/history", "/hosts", "/status", "/events", "/traffic"} {
		w := h.do(reqOpts{as: "ui-b", target: "/v1/tenants/" + tenantA + p})
		if w.Code != 403 || strings.Contains(w.Body.String(), "private note") || strings.Contains(w.Body.String(), "a-only") {
			t.Fatalf("%s: %d %s", p, w.Code, w.Body.String())
		}
	}
	// B reads its own: nothing of A's
	if w := h.do(reqOpts{as: "ui-b", target: "/v1/tenants/" + tenantB + "/policy"}); w.Code != 404 || errorOf(t, w).Code != "no_policy" {
		t.Fatalf("B's own empty policy: %d %s", w.Code, w.Body.String())
	}
	if w := h.do(reqOpts{as: "ui-b", target: "/v1/tenants/" + tenantB + "/hosts"}); w.Code != 200 || strings.Contains(w.Body.String(), "a-only") {
		t.Fatalf("B's hosts: %d %s", w.Code, w.Body.String())
	}
	// B writes to A: refused, and A's policy is unchanged
	w := h.do(reqOpts{as: "ui-b", method: "PUT", target: "/v1/tenants/" + tenantA + "/policy", body: []byte(`{"mode":"off"}`), ifMatch: etag(1)})
	if w.Code != 403 {
		t.Fatalf("B writing A's policy: %d", w.Code)
	}
	if h.store.revisions(tenantA) != 1 {
		t.Fatal("A's policy changed")
	}
	// the audit log records the attempt against the tenant that was named, for the credential that made it
	last := h.audit.last()
	if last.Outcome != "denied" || last.Credential != "ui-b" || last.Tenant != tenantA || last.Detail != "forbidden" {
		t.Fatalf("audit: %+v", last)
	}
}
