// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestADescribedModelSurvivesBeingSavedAndLoaded(t *testing.T) {
	for name, doc := range map[string]string{"shop": shopAPI, "petstore": petStoreYAML, "tree": oas31YAML} {
		t.Run(name, func(t *testing.T) {
			m := mustImport(t, doc)
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			var back Model
			if err := json.Unmarshal(data, &back); err != nil {
				t.Fatal(err)
			}
			again, _ := json.Marshal(back)
			if string(data) != string(again) {
				t.Fatal("the model changed in being saved and loaded")
			}
			// The loaded model must check requests the same way.
			g1, _ := testGuard(t, func(c *Config) { c.Modes.Spec = ModeEnforce })
			g2, _ := testGuard(t, func(c *Config) { c.Modes.Spec = ModeEnforce })
			if err := g1.SetModel(m); err != nil {
				t.Fatal(err)
			}
			if err := g2.SetModel(back); err != nil {
				t.Fatal(err)
			}
			for _, r := range []string{"/api/v1/products?limit=abc", "/api/v1/products/9", "/nodes/-1", "/v2/pet/x", "/api/v1/nothing"} {
				a, b := g1.Inspect(mk("GET", r)), g2.Inspect(mk("GET", r))
				if fmt.Sprint(ids(a)) != fmt.Sprint(ids(b)) {
					t.Fatalf("%s: %v before, %v after", r, ids(a), ids(b))
				}
			}
		})
	}
}

func TestALearnedModelSurvivesBeingSavedAndLoaded(t *testing.T) {
	g, _ := learnedShop(t)
	data, err := g.SaveLearned()
	if err != nil {
		t.Fatal(err)
	}
	g2, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeEnforce })
	if err := g2.LoadLearned(data); err != nil {
		t.Fatal(err)
	}
	if a, b := g.Stats(), g2.Stats(); a.LearnedRoutes != b.LearnedRoutes || a.LearnedEnforce != b.LearnedEnforce || b.LearnedEnforce != 4 {
		t.Fatalf("before %+v, after %+v", a, b)
	}
	data2, _ := g2.SaveLearned()
	if string(data) != string(data2) {
		t.Fatal("what was loaded does not save as what was loaded")
	}
	for _, r := range []*struct {
		req  string
		body string
	}{
		{"GET /api/items?limit=10&sort=price", ""}, {"GET /api/items?limit=abc&sort=name", ""}, {"GET /api/admin", ""},
		{"POST /api/items", `{"title":"t","price":1.5,"tags":["a"]}`}, {"POST /api/items", `{"title":"t","price":1.5,"tags":["a"],"x":1}`},
		{"GET /api/items/abc", ""}, {"DELETE /api/items/4", ""},
	} {
		method, target, _ := strings.Cut(r.req, " ")
		var opts []reqOpt
		if r.body != "" {
			opts = append(opts, withJSON(r.body))
		}
		a, b := g.Inspect(mk(method, target, opts...)), g2.Inspect(mk(method, target, opts...))
		if fmt.Sprint(ids(a)) != fmt.Sprint(ids(b)) || blocked(a) != blocked(b) {
			t.Fatalf("%s: %v before, %v after", r.req, ids(a), ids(b))
		}
	}
	// It keeps counting the same clients as the same: more of the same client does not add evidence.
	g2.Observe(mk("GET", "/api/items/5", withClient(ip(3))), 200)
}

func TestASavedModelIsReadStrictly(t *testing.T) {
	good := func() map[string]any {
		return map[string]any{"format": 1, "routes": []any{map[string]any{"method": "GET", "path": "/a", "state": "declared"}}}
	}
	mutate := func(f func(m map[string]any)) string {
		m := good()
		f(m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	route := func(m map[string]any) map[string]any { return m["routes"].([]any)[0].(map[string]any) }
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"a minimal model", mutate(func(m map[string]any) {}), true},
		{"another format version", mutate(func(m map[string]any) { m["format"] = 2 }), false},
		{"no format version", mutate(func(m map[string]any) { delete(m, "format") }), false},
		{"an unknown field", mutate(func(m map[string]any) { m["extra"] = 1 }), false},
		{"an unknown field in a route", mutate(func(m map[string]any) { route(m)["extra"] = 1 }), false},
		{"a route state that does not exist", mutate(func(m map[string]any) { route(m)["state"] = "trusted" }), false},
		{"a method that is not a method", mutate(func(m map[string]any) { route(m)["method"] = "get /" }), false},
		{"a path that does not start with a slash", mutate(func(m map[string]any) { route(m)["path"] = "a" }), false},
		{"a very long path", mutate(func(m map[string]any) { route(m)["path"] = "/" + strings.Repeat("a", 2000) }), false},
		{"a parameter in a place that does not exist", mutate(func(m map[string]any) { route(m)["params"] = []any{map[string]any{"name": "x", "in": "body"}} }), false},
		{"too many parameters", mutate(func(m map[string]any) {
			var ps []any
			for i := 0; i < MaxParamsPerRoute+1; i++ {
				ps = append(ps, map[string]any{"name": fmt.Sprint(i), "in": "query"})
			}
			route(m)["params"] = ps
		}), false},
		{"a model state that does not exist", mutate(func(m map[string]any) { m["state"] = "draft" }), false},
		{"too many routes", mutate(func(m map[string]any) {
			var rs []any
			for i := 0; i <= MaxRoutes; i++ {
				rs = append(rs, map[string]any{"method": "GET", "path": fmt.Sprintf("/r%d", i), "state": "declared"})
			}
			m["routes"] = rs
		}), false},
		{"a schema nested too deeply", mutate(func(m map[string]any) {
			var s any = map[string]any{"type": "string"}
			for i := 0; i < maxSchemaDepth+5; i++ {
				s = map[string]any{"items": s}
			}
			route(m)["body"] = s
		}), false},
		{"a schema with too many alternatives", mutate(func(m map[string]any) {
			var alts []any
			for i := 0; i < 100; i++ {
				alts = append(alts, map[string]any{})
			}
			route(m)["body"] = map[string]any{"oneOf": alts}
		}), false},
		{"learned evidence with too many clients", mutate(func(m map[string]any) {
			var slots []any
			for i := 0; i < 40; i++ {
				slots = append(slots, map[string]any{"c": i, "n": 1})
			}
			route(m)["learned"] = map[string]any{"obs": 1, "first": 1, "last": 1, "ev": map[string]any{"n": 40, "slots": slots}, "bodyEv": map[string]any{"n": 0}}
		}), false},
		{"not JSON", `format: 1`, false},
		{"empty", ``, false},
		{"two documents", `{"format":1,"routes":[]} {"format":1}`, false},
		{"a number where a string belongs", `{"format":1,"routes":[{"method":5,"path":"/a","state":"declared"}]}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m Model
			err := m.UnmarshalJSON([]byte(tt.in))
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && (m.Format != 0 || len(m.Routes) != 0) {
				t.Fatal("a refused model changed the receiver")
			}
		})
	}
	big := `{"format":1,"routes":[],"title":"` + strings.Repeat("a", maxModelBytes) + `"}`
	var m Model
	if err := m.UnmarshalJSON([]byte(big)); err == nil {
		t.Fatal("a model over the size limit was read")
	}
	g, _ := testGuard(t, nil)
	if err := g.LoadLearned([]byte(`{"format":1,"surprise":true}`)); err == nil {
		t.Fatal("LoadLearned read a model with an unknown field")
	}
	g2, _ := testGuard(t, func(c *Config) { c.Learn.MaxRoutes = 2 })
	full, _ := learnedShop(t)
	data, _ := full.SaveLearned()
	if err := g2.LoadLearned(data); err == nil {
		t.Fatal("a model larger than this guard's limits was loaded")
	}
}

func TestResetForgetsWhatWasLearned(t *testing.T) {
	g, _ := learnedShop(t)
	if g.Stats().LearnedRoutes == 0 {
		t.Fatal("setup")
	}
	g.ResetLearned()
	if st := g.Stats(); st.LearnedRoutes != 0 || st.LearnedEnforce != 0 || st.LearnNodes != 0 {
		t.Fatalf("stats = %+v", st)
	}
	if res := g.Inspect(mk("GET", "/api/admin/dump")); len(res.Verdicts) != 0 {
		t.Fatalf("a guard that forgot everything refused: %+v", res.Verdicts)
	}
}

func TestSnapshotSaysWhereEachRouteCameFrom(t *testing.T) {
	g, _ := learnedShop(t)
	g.Observe(mk("GET", "/api/rare", withClient(ip(1))), 200)
	if _, err := g.ImportOpenAPI([]byte(petStoreYAML)); err != nil {
		t.Fatal(err)
	}
	states := map[State]int{}
	for _, r := range g.Snapshot().Routes {
		states[r.State]++
	}
	if states[StateDeclared] != 5 || states[StateEnforceable] != 4 || states[StateLearning] != 1 {
		t.Fatalf("states = %v", states)
	}
	snap := g.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var back Model
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("a snapshot does not load back: %v", err)
	}
}
