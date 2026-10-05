// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"fmt"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// writeDoc describes POST /api/users with a body schema that lists name and email, and POST /api/free with a free-form body.
const writeDoc = `{"openapi":"3.0.0","paths":{
 "/api/users":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{
    "name":{"type":"string"},"email":{"type":"string"},"status":{"type":"string"},"address":{"type":"object","properties":{"city":{"type":"string"}}}}}}}}}},
 "/api/free":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"object"}}}}}},
 "/api/items":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"array","items":{"type":"object","properties":{"title":{"type":"string"}}}}}}}}}
}}`

func TestMassAssignment(t *testing.T) {
	withDoc := func(g *Guard) {
		if _, err := g.ImportOpenAPI([]byte(writeDoc)); err != nil {
			panic(err)
		}
	}
	tests := []struct {
		name   string
		setup  func(g *Guard)
		change func(*Config)
		req    *inspect.Request
		want   int // IDMassAssignFlagged, IDMassAssignRefused or 0
		block  bool
		names  string // the property the message names
	}{
		{"a role in a create is flagged, not refused, when nothing says clients never send it", nil, nil, mk("POST", "/api/users", withJSON(`{"name":"a","role":"admin"}`)), IDMassAssignFlagged, false, "role"},
		{"is_admin", nil, nil, mk("POST", "/api/users", withJSON(`{"is_admin":true}`)), IDMassAssignFlagged, false, "is_admin"},
		{"isAdmin in camel case is the same name", nil, nil, mk("PATCH", "/api/users/3", withJSON(`{"isAdmin":true}`)), IDMassAssignFlagged, false, "is_admin"},
		{"IS-ADMIN with a hyphen and capitals", nil, nil, mk("PUT", "/api/users/3", withJSON(`{"IS-ADMIN":true}`)), IDMassAssignFlagged, false, "is_admin"},
		{"nested one level down", nil, nil, mk("POST", "/api/users", withJSON(`{"profile":{"permissions":["all"]}}`)), IDMassAssignFlagged, false, "permissions"},
		{"nested in an array", nil, nil, mk("POST", "/api/bulk", withJSON(`{"users":[{"name":"a"},{"tenant_id":7}]}`)), IDMassAssignFlagged, false, "tenant_id"},
		{"a price in a write", nil, nil, mk("POST", "/api/orders", withJSON(`{"item":3,"price":0.01}`)), IDMassAssignFlagged, false, "price"},
		{"balance", nil, nil, mk("POST", "/api/wallet", withJSON(`{"balance":1000000}`)), IDMassAssignFlagged, false, "balance"},
		{"email_verified", nil, nil, mk("POST", "/api/users", withJSON(`{"emailVerified":true}`)), IDMassAssignFlagged, false, "email_verified"},
		{"no privileged property", nil, nil, mk("POST", "/api/users", withJSON(`{"name":"a","email":"a@b.example"}`)), 0, false, ""},
		{"a name that only contains one is not one", nil, nil, mk("POST", "/api/users", withJSON(`{"rolex":1,"administrator":2,"statuses":3}`)), 0, false, ""},
		{"a read is not a write", nil, nil, mk("GET", "/api/users", withJSON(`{"role":"admin"}`)), 0, false, ""},
		{"a delete is not checked", nil, nil, mk("DELETE", "/api/users/3", withJSON(`{"role":"admin"}`)), 0, false, ""},
		{"a form post is not JSON", nil, nil, mk("POST", "/api/users", withBody("application/x-www-form-urlencoded", `role=admin`)), 0, false, ""},
		{"malformed JSON is not scanned", nil, nil, mk("POST", "/api/users", withJSON(`{"role":"admin",}`)), 0, false, ""},
		{"a property the description lets a client set is left alone", withDoc, nil, mk("POST", "/api/users", withJSON(`{"name":"a","status":"active"}`)), 0, false, ""},
		{"a property the description does not list is one clients never send", withDoc, nil, mk("POST", "/api/users", withJSON(`{"name":"a","role":"admin"}`)), IDMassAssignRefused, true, "role"},
		{"the same at a nested object the description lists", withDoc, nil, mk("POST", "/api/users", withJSON(`{"address":{"city":"x","is_admin":true}}`)), IDMassAssignRefused, true, "is_admin"},
		{"a free-form body says nothing about what clients send", withDoc, nil, mk("POST", "/api/free", withJSON(`{"role":"admin"}`)), IDMassAssignFlagged, false, "role"},
		{"items of an array are checked against the item schema", withDoc, nil, mk("POST", "/api/items", withJSON(`[{"title":"a","price":1}]`)), IDMassAssignRefused, true, "price"},
		{"refusal in monitor mode does not block", withDoc, func(c *Config) { c.Modes.MassAssign = ModeMonitor }, mk("POST", "/api/users", withJSON(`{"role":"admin"}`)), IDMassAssignRefused, false, "role"},
		{"switched off", withDoc, func(c *Config) { c.Modes.MassAssign = ModeOff }, mk("POST", "/api/users", withJSON(`{"role":"admin"}`)), 0, false, ""},
		{"the whole guard in monitor never blocks", withDoc, func(c *Config) { c.Mode = ModeMonitor }, mk("POST", "/api/users", withJSON(`{"role":"admin"}`)), IDMassAssignRefused, false, "role"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, _ := testGuard(t, tt.change)
			if tt.setup != nil {
				tt.setup(g)
			}
			res := g.Inspect(tt.req)
			var got *inspect.Verdict
			for i := range res.Verdicts {
				if id := res.Verdicts[i].ID; id == IDMassAssignFlagged || id == IDMassAssignRefused {
					got = &res.Verdicts[i]
				}
			}
			switch {
			case tt.want == 0 && got != nil:
				t.Fatalf("unexpected %+v", *got)
			case tt.want != 0 && got == nil:
				t.Fatalf("no verdict, got %+v", res.Verdicts)
			case tt.want != 0:
				if got.ID != tt.want || got.Block != tt.block {
					t.Fatalf("verdict %+v, want id %d block %v", *got, tt.want, tt.block)
				}
				if !strings.Contains(got.Message, tt.names) {
					t.Fatalf("message %q does not name %q", got.Message, tt.names)
				}
			}
		})
	}
}

// What was learned counts as the description does: a property the learned model says clients never send is refused; before there is
// enough evidence the finding is only a warning.
func TestMassAssignmentIsRefusedOnlyWhereTheModelHasLearnedClientsNeverSendIt(t *testing.T) {
	g, _ := testGuard(t, nil)
	body := func(i int) string { return fmt.Sprintf(`{"name":"user %d","email":"u%d@x.example"}`, i, i) }
	post := func(i int, extra string) *inspect.Request {
		b := body(i)
		if extra != "" {
			b = strings.TrimSuffix(b, "}") + "," + extra + "}"
		}
		return mk("POST", "/api/users", withJSON(b), withClient(ip(i)))
	}
	for i := 0; i < 5; i++ {
		g.Observe(post(i, ""), 201)
	}
	if res := g.Inspect(post(900, `"role":"admin"`)); !has(res, IDMassAssignFlagged) || blocked(res) {
		t.Fatalf("with five sightings the finding must only be a warning: %+v", res.Verdicts)
	}
	for i := 5; i < 60; i++ {
		g.Observe(post(i, ""), 201)
	}
	if res := g.Inspect(post(901, `"role":"admin"`)); !has(res, IDMassAssignRefused) || !blocked(res) {
		t.Fatalf("with enough sightings from enough clients the finding must refuse: %+v", res.Verdicts)
	}
	if res := g.Inspect(post(902, "")); len(res.Verdicts) != 0 {
		t.Fatalf("an ordinary create was refused: %+v", res.Verdicts)
	}
	// Negative control: if some clients do send it, it is not "never sent".
	g2, _ := testGuard(t, nil)
	for i := 0; i < 60; i++ {
		extra := ""
		if i%2 == 0 {
			extra = `"status":"active"`
		}
		g2.Observe(post(i, extra), 201)
	}
	if res := g2.Inspect(post(901, `"status":"pending"`)); has(res, IDMassAssignRefused) {
		t.Fatalf("a property that clients do send was refused: %+v", res.Verdicts)
	}
}
