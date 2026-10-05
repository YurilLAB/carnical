// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func routeOf(t testing.TB, m Model, method, path string) *Route {
	t.Helper()
	for i := range m.Routes {
		if m.Routes[i].Method == method && m.Routes[i].Path == path {
			return &m.Routes[i]
		}
	}
	t.Fatalf("no route %s %s in %v", method, path, routeNames(m))
	return nil
}

func routeNames(m Model) []string {
	var out []string
	for _, r := range m.Routes {
		out = append(out, r.Method+" "+r.Path)
	}
	return out
}

func TestImportReadsRealDescriptions(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		format  string
		routes  []string
		secured map[string]bool
	}{
		{"openapi 3.0 in JSON with servers, refs and allOf", shopAPI, "openapi 3.0.3", []string{
			"GET /api/v1/products", "POST /api/v1/products", "GET /api/v1/products/{id}", "PUT /api/v1/products/{id}",
			"DELETE /api/v1/products/{id}", "GET /api/v1/products/{id}/reviews", "POST /api/v1/products/{id}/reviews", "POST /api/v1/users",
			"GET /api/v1/users/{userId}", "PATCH /api/v1/users/{userId}", "POST /api/v1/auth/login", "GET /api/v1/orders/{orderId}", "GET /api/v1/export"},
			map[string]bool{"GET /api/v1/products": false, "POST /api/v1/products": true, "POST /api/v1/auth/login": false, "DELETE /api/v1/products/{id}": true}},
		{"swagger 2.0 in YAML with basePath and a body parameter", petStoreYAML, "swagger 2.0", []string{
			"POST /v2/pet", "GET /v2/pet/{petId}", "DELETE /v2/pet/{petId}", "GET /v2/pet/findByStatus", "POST /v2/pet/{petId}/uploadImage"},
			map[string]bool{"POST /v2/pet": true, "GET /v2/pet/{petId}": false}},
		{"openapi 3.1 in YAML with a self-referencing schema", oas31YAML, "openapi 3.1.0", []string{"GET /nodes/{id}", "PUT /nodes/{id}"}, nil},
		{"a description with no paths", `{"openapi":"3.0.0","info":{"title":"x","version":"1"}}`, "openapi 3.0.0", nil, nil},
		{"a path item that is a reference", `{"openapi":"3.0.0","paths":{"/a":{"$ref":"#/x-items/a"}},"x-items":{"a":{"get":{"responses":{}}}}}`, "openapi 3.0.0", []string{"GET /a"}, nil},
		{"trace is left out", `{"openapi":"3.0.0","paths":{"/a":{"trace":{},"get":{}}}}`, "openapi 3.0.0", []string{"GET /a"}, nil},
		{"two servers give two prefixes", `{"openapi":"3.0.0","servers":[{"url":"https://a.test/v1"},{"url":"/v2"}],"paths":{"/a":{"get":{}}}}`, "openapi 3.0.0", []string{"GET /v1/a", "GET /v2/a"}, nil},
		{"a server variable takes its default", `{"openapi":"3.0.0","servers":[{"url":"https://a.test/{ver}","variables":{"ver":{"default":"v3"}}}],"paths":{"/a":{"get":{}}}}`, "openapi 3.0.0", []string{"GET /v3/a"}, nil},
		{"a path that is not a template is skipped", `{"openapi":"3.0.0","paths":{"a":{"get":{}},"/b?x=1":{"get":{}},"/c/{x":{"get":{}},"/ok":{"get":{}}}}`, "openapi 3.0.0", []string{"GET /ok"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, rep, err := ImportOpenAPI([]byte(tt.doc))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Format != tt.format || m.SpecVersion != tt.format {
				t.Errorf("format = %q", rep.Format)
			}
			got := routeNames(m)
			want := slices.Clone(tt.routes)
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("routes\n got %v\nwant %v", got, want)
			}
			if rep.Routes != len(want) || rep.Hash == "" || m.Hash != rep.Hash {
				t.Errorf("report = %+v", rep)
			}
			for k, want := range tt.secured {
				method, path, _ := strings.Cut(k, " ")
				if r := routeOf(t, m, method, path); r.Secured != want {
					t.Errorf("%s: secured = %v, want %v", k, r.Secured, want)
				}
			}
		})
	}
}

func TestImportRefusesWhatIsNotADescription(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"empty", ``},
		{"white space", "  \n "},
		{"an HTML page", `<!doctype html><html><body>Not found</body></html>`},
		{"a JSON array", `[1,2,3]`},
		{"a JSON object that is not a description", `{"name":"x","version":1}`},
		{"openapi 4", `{"openapi":"4.0.0","paths":{}}`},
		{"swagger 1.2", `{"swagger":"1.2","paths":{}}`},
		{"a YAML list", "- a\n- b\n"},
		{"a YAML scalar", "hello"},
		{"broken JSON", `{"openapi":"3.0.0",`},
		{"broken YAML", "openapi: 3.0.0\npaths: [unterminated"},
		{"binary", "\x00\x01\x02\xff\xfe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := ImportOpenAPI([]byte(tt.doc)); err == nil {
				t.Fatal("imported")
			}
		})
	}
}

// yamlBomb is nine levels of nine aliases each: 9^9 values once expanded, in a few hundred bytes.
func yamlBomb() string {
	var b strings.Builder
	b.WriteString("openapi: 3.0.0\nx-bomb:\n  a: &a [lol, lol, lol, lol, lol, lol, lol, lol, lol]\n")
	prev := "a"
	for _, name := range []string{"b", "c", "d", "e", "f", "g", "h", "i"} {
		fmt.Fprintf(&b, "  %s: &%s [%s]\n", name, name, strings.TrimSuffix(strings.Repeat("*"+prev+", ", 9), ", "))
		prev = name
	}
	b.WriteString("paths: {}\n")
	return b.String()
}

func TestImportDefendsAgainstAHostileDocument(t *testing.T) {
	var fanout strings.Builder
	fanout.WriteString(`{"openapi":"3.0.0","paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/L30"}}}}}}},"components":{"schemas":{"L0":{"type":"string"}`)
	for i := 1; i <= 30; i++ {
		fmt.Fprintf(&fanout, `,"L%d":{"type":"object","properties":{"a":{"$ref":"#/components/schemas/L%d"},"b":{"$ref":"#/components/schemas/L%d"}}}`, i, i-1, i-1)
	}
	fanout.WriteString(`}}}`)
	var manyRoutes strings.Builder
	manyRoutes.WriteString(`{"openapi":"3.0.0","paths":{`)
	for i := 0; i < 5200; i++ {
		if i > 0 {
			manyRoutes.WriteByte(',')
		}
		fmt.Fprintf(&manyRoutes, `"/p%d":{"get":{}}`, i)
	}
	manyRoutes.WriteString(`}}`)
	var manyProps strings.Builder
	manyProps.WriteString(`{"openapi":"3.0.0","paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{`)
	for i := 0; i < 1500; i++ {
		if i > 0 {
			manyProps.WriteByte(',')
		}
		fmt.Fprintf(&manyProps, `"p%d":{"type":"string"}`, i)
	}
	manyProps.WriteString(`}}}}}}}}}`)

	tests := []struct {
		name    string
		doc     string
		wantErr string // "" means the import must succeed, with the warning below
		warn    string
	}{
		{"larger than the size limit", strings.Repeat(" ", MaxDocumentBytes+1) + "{}", "limit", ""},
		{"a YAML alias bomb", yamlBomb(), "too complex", ""},
		{"JSON nested a hundred thousand deep", `{"openapi":"3.0.0","x":` + strings.Repeat("[", 100_000), "deeply", ""},
		{"YAML nested a hundred thousand deep (flow)", "openapi: 3.0.0\nx: " + strings.Repeat("[", 100_000), "too complex", ""},
		{"YAML nested by indentation", "openapi: 3.0.0\n" + func() string {
			var b strings.Builder
			for i := 0; i < 400; i++ {
				b.WriteString(strings.Repeat(" ", i) + fmt.Sprintf("k%d:\n", i))
			}
			return b.String()
		}(), "too complex", ""},
		{"a hundred thousand dashes on one line", strings.Repeat("- ", 100_000), "too complex", ""},
		{"a YAML mapping with 300,000 keys (the library reads it in time that grows with the square: eight minutes)", "openapi: 3.0.0\nx-map:\n" + func() string {
			var b strings.Builder
			for i := 0; i < 300_000; i++ {
				fmt.Fprintf(&b, "  k%d: v\n", i)
			}
			return b.String()
		}(), "too complex", ""},
		{"a YAML mapping of many mappings, each just under the limit on its own", "openapi: 3.0.0\n" + func() string {
			var b strings.Builder
			for m := 0; m < 40; m++ {
				fmt.Fprintf(&b, "x%d:\n", m)
				for i := 0; i < 11_000; i++ {
					fmt.Fprintf(&b, "  k%d: v\n", i)
				}
			}
			return b.String()
		}(), "too complex", ""},
		{"a YAML block list of 1.2 million items", "openapi: 3.0.0\nx:\n" + strings.Repeat("- a\n", 1_200_000), "too complex", ""},
		{"a YAML flow list of 1.5 million items on one line", "openapi: 3.0.0\nx: [" + strings.Repeat("a, ", 1_500_000) + "a]\n", "too complex", ""},
		{"references that fan out to 2^30 nodes", fanout.String(), "too complex", ""},
		{"more routes than the limit", manyRoutes.String(), "routes", ""},
		{"more properties in one schema than the limit", manyProps.String(), "too complex", ""},
		{"a schema that refers to itself is read, and checked to the depth of the data", `{"openapi":"3.0.0","paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Node"}}}}}}},
			"components":{"schemas":{"Node":{"type":"object","properties":{"next":{"$ref":"#/components/schemas/Node"}}}}}}`, "", ""},
		{"two schemas that refer to each other are read", `{"openapi":"3.0.0","paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/A"}}}}}}},
			"components":{"schemas":{"A":{"type":"object","properties":{"b":{"$ref":"#/components/schemas/B"}}},"B":{"type":"object","properties":{"a":{"$ref":"#/components/schemas/A"}}}}}}`, "", ""},
		{"a reference to another host", `{"openapi":"3.0.0","paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"https://evil.example/s.json#/X"}}}}}}}}`, "", "outside the document"},
		{"a reference to a file", `{"openapi":"3.0.0","paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"file:///etc/passwd"}}}}}}}}`, "", "outside the document"},
		{"a reference that is not there", `{"openapi":"3.0.0","paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Nope"}}}}}}}}`, "", "could not be followed"},
		{"a parameter reference that loops", `{"openapi":"3.0.0","paths":{"/a":{"get":{"parameters":[{"$ref":"#/components/parameters/p"}]}}},"components":{"parameters":{"p":{"$ref":"#/components/parameters/p"}}}}`, "", "chain of references"},
		{"a pattern that is not RE2", `{"openapi":"3.0.0","paths":{"/a":{"get":{"parameters":[{"name":"x","in":"query","schema":{"type":"string","pattern":"^(?=a)"}}]}}}}`, "", "not RE2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			_, rep, err := ImportOpenAPI([]byte(tt.doc))
			if took := time.Since(start); took > 5*time.Second {
				t.Fatalf("took %v", took)
			}
			switch {
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
			case tt.wantErr == "" && err != nil:
				t.Fatalf("err = %v", err)
			case tt.warn != "" && !strings.Contains(strings.Join(rep.Warnings, "\n"), tt.warn):
				t.Fatalf("warnings = %q, want one containing %q", rep.Warnings, tt.warn)
			}
		})
	}
}

func TestImportedSchemasCarryWhatTheDescriptionSays(t *testing.T) {
	m := mustImport(t, shopAPI)

	list := routeOf(t, m, "GET", "/api/v1/products")
	if len(list.Params) != 5 {
		t.Fatalf("params = %d, want 5 (limit comes from a reference)", len(list.Params))
	}
	var limit *Param
	for i := range list.Params {
		if list.Params[i].Name == "limit" {
			limit = &list.Params[i]
		}
	}
	if limit == nil || limit.Schema == nil || limit.Schema.Maximum == nil || *limit.Schema.Maximum != 100 {
		t.Fatalf("limit = %+v", limit)
	}
	if !list.NoBody {
		t.Error("a route with no requestBody takes no body")
	}

	create := routeOf(t, m, "POST", "/api/v1/products")
	if !create.BodyRequired || !slices.Equal(create.ContentTypes, []string{"application/json"}) || create.Body == nil || len(create.Body.AllOf) != 2 {
		t.Fatalf("create = %+v", create)
	}
	if !create.Secured {
		t.Error("the document's security applies to an operation that does not override it")
	}

	patch := routeOf(t, m, "PATCH", "/api/v1/users/{userId}")
	props := patch.Body.Properties
	if !props["role"].ReadOnly || !props["id"].ReadOnly || props["name"].ReadOnly {
		t.Errorf("read-only flags: %+v", props)
	}
	if patch.Body.AdditionalProperties == nil || *patch.Body.AdditionalProperties {
		t.Error("additionalProperties false was lost")
	}
	if p := routeOf(t, m, "GET", "/api/v1/users/{userId}").Params[0]; p.In != "path" || p.Schema.Format != "uuid" {
		t.Errorf("path parameter from the path item = %+v", p)
	}
	if !slices.Equal(m.CredentialHeaders, []string{"x-shop-key"}) {
		t.Errorf("credential headers = %v", m.CredentialHeaders)
	}
	if got := routeOf(t, m, "GET", "/api/v1/export"); got.ContentTypes != nil && len(got.ContentTypes) > 0 {
		t.Errorf("a response media type is not a request body type: %v", got.ContentTypes)
	}
	pet := mustImport(t, petStoreYAML)
	post := routeOf(t, pet, "POST", "/v2/pet")
	if post.Body == nil || !slices.Equal(post.ContentTypes, []string{"application/json"}) || !post.BodyRequired {
		t.Fatalf("swagger body parameter = %+v", post)
	}
	if !post.Body.Properties["id"].ReadOnly || post.Body.Properties["category"].Properties["name"] == nil {
		t.Errorf("a definition reference was not followed: %+v", post.Body.Properties)
	}
	status := routeOf(t, pet, "GET", "/v2/pet/findByStatus").Params[0]
	if status.Explode == nil || *status.Explode || !status.Required || status.Schema.Items.Enum == nil {
		t.Errorf("swagger array parameter = %+v", status)
	}
	if up := routeOf(t, pet, "POST", "/v2/pet/{petId}/uploadImage"); !slices.Equal(up.ContentTypes, []string{"multipart/form-data"}) {
		t.Errorf("upload content types = %v", up.ContentTypes)
	}
}

func TestImportIsDeterministic(t *testing.T) {
	a := mustImport(t, shopAPI)
	b := mustImport(t, shopAPI)
	ja, _ := a.MarshalJSON()
	jb, _ := b.MarshalJSON()
	if string(ja) != string(jb) {
		t.Fatal("two imports of the same document differ")
	}
}
