// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// FuzzImportOpenAPI feeds the importer arbitrary bytes. Whatever it is given it must return and must not panic; and whatever it
// accepts must be a model that can be saved, loaded, installed in a guard and used to check a request.
func FuzzImportOpenAPI(f *testing.F) {
	for _, seed := range []string{shopAPI, petStoreYAML, oas31YAML, yamlBomb(), `{"openapi":"3.0.0","paths":{"/a/{id}":{"get":{"parameters":[{"name":"id","in":"path","schema":{"type":"integer"}}]}}}}`,
		`{"swagger":"2.0","paths":{}}`, `openapi: 3.1.0` + "\n" + `paths: {}`, `{"openapi":"3.0.0","paths":{"/a":{"$ref":"#/paths/~1a"}}}`,
		`{"openapi":"3.0.0","components":{"schemas":{"A":{"$ref":"#/components/schemas/A"}}},"paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/A"}}}}}}}}`,
		"a: &a [1]\nb: *a\n", "- - - -", "{{{{", "\x00\xff"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, _, err := ImportOpenAPI(data)
		if err != nil {
			return
		}
		saved, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("an imported model does not save: %v", err)
		}
		var back Model
		if err := json.Unmarshal(saved, &back); err != nil {
			t.Fatalf("an imported model does not load back: %v", err)
		}
		g, err := New(Config{Modes: Modes{Spec: ModeEnforce}})
		if err != nil {
			t.Fatal(err)
		}
		if err := g.SetModel(back); err != nil {
			t.Fatalf("a model that loaded cannot be installed: %v", err)
		}
		for i := range m.Routes {
			if i > 20 {
				break
			}
			r := &inspect.Request{Method: m.Routes[i].Method, Path: m.Routes[i].Path, Header: http.Header{}, Client: netip.MustParseAddr("192.0.2.1"),
				Body: []byte(`{"a":1,"b":[1,2,{"c":null}]}`)}
			r.Header.Set("Content-Type", "application/json")
			g.Inspect(r)
		}
		if g.Stats().Panics != 0 {
			t.Fatal("the guard panicked on a model the importer accepted")
		}
	})
}

// FuzzSchemaValidator gives the validator an arbitrary schema (read the way an import reads one) and an arbitrary instance. It
// must return, must not panic, and must answer the same way twice.
func FuzzSchemaValidator(f *testing.F) {
	f.Add(`{"type":"object","required":["a"],"properties":{"a":{"type":"integer","minimum":1}},"additionalProperties":false}`, `{"a":1}`)
	f.Add(`{"oneOf":[{"type":"string"},{"type":"integer"}]}`, `3`)
	f.Add(`{"anyOf":[{"type":"array","items":{"type":"string","pattern":"^a+$"}},{"type":"null"}]}`, `["aaa",1]`)
	f.Add(`{"allOf":[{"type":"object"},{"not":{"required":["x"]}}]}`, `{"x":1}`)
	f.Add(`{"type":"string","format":"email","maxLength":10}`, `"a@b.example"`)
	f.Add(`{"type":"array","uniqueItems":true,"items":{"enum":[1,2,"x"]}}`, `[1,1]`)
	f.Add(`{"type":"object","properties":{"a":{"readOnly":true}},"additionalProperties":{"type":"number","multipleOf":0.1}}`, `{"a":1,"b":0.3}`)
	f.Add(`{"type":"string","pattern":"^(a+)+$"}`, `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"`)
	f.Fuzz(func(t *testing.T, schemaJSON, instanceJSON string) {
		sv, _, err := parseJSON([]byte(schemaJSON), jsonLimits{depth: 64, nodes: 50_000})
		if err != nil {
			return
		}
		im := &importer{root: map[string]any{}, ver: "3.1", rep: &Report{}, budget: importBudget, memo: map[string]*refMemo{}, inProgress: map[string]bool{}, ignored: map[string]int{}}
		s := im.schema(sv, 0)
		if im.err != nil {
			return
		}
		dropped := 0
		s.prepare(map[*Schema]bool{}, nil2map(), &dropped)
		inst, _, err := parseJSON([]byte(instanceJSON), jsonLimits{})
		if err != nil {
			return
		}
		for _, request := range []bool{true, false} {
			v1, ok1, over1 := s.validateBody(inst, request)
			v2, ok2, over2 := s.validateBody(inst, request)
			if v1 != v2 || ok1 != ok2 || over1 != over2 {
				t.Fatalf("two validations of the same value disagree: %+v %v %v / %+v %v %v", v1, ok1, over1, v2, ok2, over2)
			}
		}
		// The same schema through the model: saved, loaded and used.
		m := Model{Format: ModelFormat, Routes: []Route{{Method: "POST", Path: "/f", State: StateDeclared, Body: s, ContentTypes: []string{"application/json"}}}, Defs: im.defs}
		saved, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("a schema does not save: %v", err)
		}
		var back Model
		if err := json.Unmarshal(saved, &back); err != nil {
			t.Fatalf("a schema does not load back: %v", err)
		}
	})
}

func FuzzParseJSON(f *testing.F) {
	for _, s := range []string{`{"a":[1,2.5,"x",null,true,{"b":{}}]}`, `"😀"`, `[[[[[]]]]]`, `{"a":1,"a":2}`, `1e999`, `"\u0000"`, "\xef\xbb\xbf{}", `{`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, _, err := parseJSON(data, jsonLimits{})
		if err != nil {
			return
		}
		out := appendJSON(nil, v, 0)
		v2, _, err := parseJSON(out, jsonLimits{})
		if err != nil {
			t.Fatalf("what appendJSON wrote does not parse: %v: %q", err, out)
		}
		if !equalValues(v, v2, 0) {
			t.Fatalf("a value changed on the way through: %q", out)
		}
	})
}

// FuzzInspect sends arbitrary requests through a guard that has a description and has learned something.
func FuzzInspect(f *testing.F) {
	f.Add("POST", "/api/v1/products/12", "limit=5&sort=name", "application/json", `{"name":"n","price":1,"role":"admin"}`, "Bearer x")
	f.Add("GET", "/api/items/%zz", "a=%&b", "text/plain", "", "")
	f.Add("TRACE", "/"+strings.Repeat("a/", 40), "x[]=1&x[]=2", "", `[[[[`, "k")
	g, _ := New(Config{Modes: Modes{Spec: ModeEnforce, Learned: ModeEnforce}})
	if _, err := g.ImportOpenAPI([]byte(shopAPI)); err != nil {
		f.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		g.Observe(shopTraffic(i), 200)
	}
	f.Fuzz(func(t *testing.T, method, path, query, ct, body, cred string) {
		r := &inspect.Request{Method: method, Path: path, RawQuery: query, Header: http.Header{}, Client: netip.MustParseAddr("192.0.2.1"), Body: []byte(body)}
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		if cred != "" {
			r.Header.Set("Authorization", cred)
		}
		g.Inspect(r)
		g.Observe(r, 200)
		if g.Stats().Panics != 0 {
			t.Fatalf("the guard panicked on %q %q %q", method, path, query)
		}
	})
}

func FuzzModelUnmarshal(f *testing.F) {
	g, _ := New(Config{})
	for i := 0; i < 200; i++ {
		g.Observe(shopTraffic(i), 200)
	}
	g.Flush()
	saved, _ := g.SaveLearned()
	described, _ := json.Marshal(mustImportFuzz(shopAPI))
	f.Add(saved)
	f.Add(described)
	f.Add([]byte(`{"format":1,"routes":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var m Model
		if err := m.UnmarshalJSON(data); err != nil {
			return
		}
		again, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("a loaded model does not save: %v", err)
		}
		var m2 Model
		if err := m2.UnmarshalJSON(again); err != nil {
			t.Fatalf("a saved model does not load: %v", err)
		}
		g2, _ := New(Config{})
		_ = g2.LoadLearned(again)
		g2.Inspect(&inspect.Request{Method: "GET", Path: "/api/items", Header: http.Header{}, Client: netip.MustParseAddr("192.0.2.1")})
	})
}

func mustImportFuzz(doc string) Model {
	m, _, err := ImportOpenAPI([]byte(doc))
	if err != nil {
		panic(err)
	}
	return m
}

func FuzzParseConfig(f *testing.F) {
	f.Add([]byte(`{"modes":{"spec":"enforce"}}`))
	f.Add([]byte(`{"rate":{"burst":{"burst":5,"per":1000000}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseConfig(data)
		if err != nil {
			return
		}
		if _, err := New(c); err != nil {
			t.Fatalf("a configuration that parsed cannot make a guard: %v", err)
		}
	})
}

func FuzzTemplateAndMatch(f *testing.F) {
	for _, s := range []string{"/api/users/42", "/", "//", "/a/%2f", "/a/%zz", "/a/{x}/b", "/" + string(make([]byte, 200))} {
		f.Add(s)
	}
	m := mustImportFuzz(shopAPI)
	f.Fuzz(func(t *testing.T, path string) {
		var buf [512]byte
		templateOf("GET", path, collapsedSet{"/api": {}}, buf[:0], func([]byte, string) {})
		var caps captures
		m.idx.lookup(path, &caps)
		isAuthPath(path)
		isAPIPath(path)
	})
}

func nil2map() map[string]*regexp.Regexp { return map[string]*regexp.Regexp{} }
