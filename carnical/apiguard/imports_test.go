// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func harEntry(method, url string, status int, respType, bodyType, body string, headers ...[2]string) map[string]any {
	req := map[string]any{"method": method, "url": url, "headers": []any{}}
	for _, h := range headers {
		req["headers"] = append(req["headers"].([]any), map[string]any{"name": h[0], "value": h[1]})
	}
	if body != "" {
		req["postData"] = map[string]any{"mimeType": bodyType, "text": body}
	}
	return map[string]any{"request": req, "response": map[string]any{"status": status, "content": map[string]any{"mimeType": respType, "text": strings.Repeat("x", 1000)}}}
}

func harOf(entries ...map[string]any) []byte {
	es := make([]any, len(entries))
	for i, e := range entries {
		es[i] = e
	}
	b, _ := json.Marshal(map[string]any{"log": map[string]any{"version": "1.2", "entries": es}})
	return b
}

func TestImportHAR(t *testing.T) {
	har := harOf(
		harEntry("GET", "https://shop.example.test/", 200, "text/html", "", ""),
		harEntry("GET", "https://shop.example.test/static/app.js", 200, "application/javascript", "", ""),
		harEntry("GET", "https://shop.example.test/api/v1/products?limit=10&sort=name", 200, "application/json", "", "", [2]string{"Authorization", "Bearer SECRET-TOKEN"}, [2]string{"Cookie", "sid=SECRET"}, [2]string{"Accept", "application/json"}),
		harEntry("GET", "https://shop.example.test/api/v1/products/42", 200, "application/json", "", ""),
		harEntry("POST", "https://shop.example.test/api/v1/products", 201, "application/json", "application/json", `{"name":"n","price":1.5}`),
		harEntry("GET", "https://shop.example.test/api/v1/products/9999", 404, "application/json", "", ""),
		harEntry("GET", "https://shop.example.test/xhr/cart", 200, "application/json", "", ""),
		harEntry("GET", "ftp://shop.example.test/api/x", 200, "application/json", "", ""),
		harEntry("BAD METHOD", "https://shop.example.test/api/x", 200, "application/json", "", ""),
		harEntry("GET", "https://shop.example.test/api/failing", 500, "text/html", "", ""),
	)
	obs, rep, err := ImportHAR(har)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Observations != 6 || rep.Skipped != 4 || len(obs) != 6 || rep.Kind != "har" {
		t.Fatalf("report = %+v, %d observations", rep, len(obs))
	}
	for _, o := range obs {
		if o.Request.Header.Get("Authorization") != "" || o.Request.Header.Get("Cookie") != "" {
			t.Fatal("a credential was kept")
		}
	}
	if o := obs[4]; o.Request.Method != "POST" || o.Request.Header.Get("Content-Type") != "application/json" || string(o.Request.Body) != `{"name":"n","price":1.5}` || o.Status != 201 {
		t.Fatalf("the POST = %+v", o)
	}
	if o := obs[2]; o.Request.Path != "/api/v1/products" || o.Request.RawQuery != "limit=10&sort=name" || o.Request.Host != "shop.example.test" {
		t.Fatalf("the list = %+v", o.Request)
	}

	// Teaching the guard: pages and scripts are left out, and what is left is enforceable at once.
	g, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeEnforce })
	if used := g.Learn(obs); used != 4 {
		t.Fatalf("used %d observations, want 4 (the page and the script are not API calls)", used)
	}
	g.Flush()
	for _, tt := range []struct {
		req  string
		want int
	}{
		{"GET /api/v1/products?limit=7&sort=name", 0},
		{"GET /api/v1/products/77", 0},
		{"GET /xhr/cart", 0},
		{"GET /api/v1/products?limit=abc&sort=name", IDLearnedQueryParam},
		{"GET /api/v1/orders", IDLearnedUnknownRoute},
		{"DELETE /api/v1/products/77", IDLearnedMethodNotSeen},
	} {
		method, target, _ := strings.Cut(tt.req, " ")
		res := g.Inspect(mk(method, target))
		switch {
		case tt.want == 0 && len(res.Verdicts) != 0:
			t.Errorf("%s: %+v", tt.req, res.Verdicts)
		case tt.want != 0 && !has(res, tt.want):
			t.Errorf("%s: %+v, want %d", tt.req, res.Verdicts, tt.want)
		}
	}
	// A recording is the owner's word, and only the owner's: the same counts for what visitors send are nothing like it.
	if st := g.Stats(); st.LearnedEnforce != 4 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestImportHARLimits(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		ok   bool
	}{
		{"not JSON", []byte(`log: entries`), false},
		{"no entries", []byte(`{"log":{"entries":[]}}`), false},
		{"not a HAR", []byte(`{"hello":"world"}`), false},
		{"a byte order mark is tolerated", append([]byte{0xEF, 0xBB, 0xBF}, harOf(harEntry("GET", "https://a.test/api/x", 200, "application/json", "", ""))...), true},
		{"larger than the limit", bytes.Repeat([]byte(" "), MaxHARBytes+1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ImportHAR(tt.data)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
	t.Run("only the first twenty thousand entries are read", func(t *testing.T) {
		var es []map[string]any
		for i := 0; i < maxRecordedRequests+500; i++ {
			es = append(es, harEntry("GET", fmt.Sprintf("https://a.test/api/x%d", i), 200, "application/json", "", ""))
		}
		obs, rep, err := ImportHAR(harOf(es...))
		if err != nil || len(obs) != maxRecordedRequests || len(rep.Warnings) == 0 {
			t.Fatalf("err = %v, %d observations, warnings %v", err, len(obs), rep.Warnings)
		}
	})
	t.Run("a body larger than a request carries is left out", func(t *testing.T) {
		obs, _, err := ImportHAR(harOf(harEntry("POST", "https://a.test/api/x", 200, "application/json", "application/json", strings.Repeat("a", maxRecordedBody+1))))
		if err != nil || len(obs[0].Request.Body) != 0 {
			t.Fatalf("err = %v", err)
		}
	})
}

const postmanCollection = `{
  "info": {"name": "Shop", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "variable": [{"key": "baseUrl", "value": "https://shop.example.test"}, {"key": "userId", "value": "123e4567-e89b-12d3-a456-426614174000"}],
  "item": [
    {"name": "Products", "item": [
      {"name": "List", "request": {"method": "GET", "header": [{"key": "Accept", "value": "application/json"}],
        "url": {"raw": "{{baseUrl}}/api/v1/products?limit=20&sort=name", "host": ["{{baseUrl}}"], "path": ["api", "v1", "products"],
                "query": [{"key": "limit", "value": "20"}, {"key": "sort", "value": "name"}, {"key": "debug", "value": "1", "disabled": true}]}}},
      {"name": "Get", "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/api/v1/products/:id", "path": ["api", "v1", "products", ":id"], "variable": [{"key": "id", "value": "7"}]}}},
      {"name": "Create", "request": {"method": "POST", "header": [{"key": "Content-Type", "value": "application/json"}],
        "body": {"mode": "raw", "raw": "{\"name\": \"n\", \"price\": 2.5, \"owner\": {{userId}}}"},
        "url": "{{baseUrl}}/api/v1/products"},
       "response": [{"name": "created", "code": 201}]},
      {"name": "Failing example", "request": {"method": "GET", "url": "{{baseUrl}}/api/v1/broken"}, "response": [{"code": 500}]}
    ]},
    {"name": "Users", "item": [
      {"name": "One", "request": {"method": "GET", "url": {"path": ["api", "v1", "users", "{{userId}}"]}}},
      {"name": "Login", "request": {"method": "POST", "body": {"mode": "urlencoded", "urlencoded": [{"key": "email", "value": "a@b.example"}, {"key": "password", "value": "x"}, {"key": "off", "value": "1", "disabled": true}]},
        "url": "{{baseUrl}}/api/v1/auth/login"}}
    ]},
    {"name": "Shorthand", "request": "https://shop.example.test/api/v1/ping"},
    {"name": "Nothing"}
  ]
}`

func TestImportPostman(t *testing.T) {
	obs, rep, err := ImportPostman([]byte(postmanCollection))
	if err != nil {
		t.Fatal(err)
	}
	// A request written as a bare URL is a GET; the example that answered 500 is skipped; the item with no request is not one.
	if rep.Kind != "postman" || len(obs) != 6 {
		t.Fatalf("report = %+v, %d observations", rep, len(obs))
	}
	by := map[string]Observation{}
	for _, o := range obs {
		by[o.Request.Method+" "+o.Request.Path] = o
	}
	for _, want := range []string{"GET /api/v1/products", "GET /api/v1/products/7", "POST /api/v1/products", "GET /api/v1/users/123e4567-e89b-12d3-a456-426614174000", "POST /api/v1/auth/login"} {
		if _, ok := by[want]; !ok {
			t.Errorf("missing %s in %v", want, keys(by))
		}
	}
	if o := by["GET /api/v1/products"]; o.Request.RawQuery != "limit=20&sort=name" {
		t.Errorf("a disabled query parameter was kept or an enabled one lost: %q", o.Request.RawQuery)
	}
	create := by["POST /api/v1/products"]
	if create.Status != 201 || create.Request.Header.Get("Content-Type") != "application/json" {
		t.Errorf("create = %+v", create)
	}
	if _, _, err := parseJSON(create.Request.Body, jsonLimits{}); err != nil {
		t.Errorf("a body with an unquoted variable was not made readable: %s", create.Request.Body)
	}
	login := by["POST /api/v1/auth/login"]
	if string(login.Request.Body) != "email=a%40b.example&password=x" || login.Request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("login = %q", login.Request.Body)
	}

	g, _ := testGuard(t, func(c *Config) { c.Modes.Learned = ModeEnforce })
	if used := g.Learn(obs); used != 6 {
		t.Fatalf("used %d", used)
	}
	g.Flush()
	if res := g.Inspect(mk("GET", "/api/v1/products/12")); len(res.Verdicts) != 0 {
		t.Fatalf("%+v", res.Verdicts)
	}
	if res := g.Inspect(mk("GET", "/api/v1/users/123e4567-e89b-12d3-a456-426614174999")); len(res.Verdicts) != 0 {
		t.Fatalf("a uuid path variable was not learned as a uuid: %+v", res.Verdicts)
	}
	if res := g.Inspect(mk("GET", "/api/v1/products?limit=abc&sort=name")); !has(res, IDLearnedQueryParam) {
		t.Fatalf("%+v", res.Verdicts)
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestImportPostmanLimits(t *testing.T) {
	tests := []struct {
		name string
		data string
		ok   bool
	}{
		{"not JSON", `item: x`, false},
		{"no items", `{"item":[]}`, false},
		{"items with nothing usable", `{"item":[{"name":"a"},{"name":"b","request":{"method":"GET","url":12345}}]}`, false},
		{"a request with a bad method", `{"item":[{"request":{"method":"G E T","url":{"path":["a"]}}}]}`, false},
		{"a path with a variable that has no value takes 1", `{"item":[{"request":{"method":"GET","url":{"path":["api","u","{{who}}"]}}}]}`, true},
		{"a body that is not JSON is left out", `{"item":[{"request":{"method":"POST","url":{"path":["api","a"]},"body":{"mode":"raw","raw":"not json {{x"}}}]}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ImportPostman([]byte(tt.data))
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
	t.Run("folders nested past the limit are not followed", func(t *testing.T) {
		doc := `{"item":[{"request":{"method":"GET","url":{"path":["api","top"]}}}`
		inner := `{"request":{"method":"GET","url":{"path":["api","deep"]}}}`
		for i := 0; i < maxCollectionDepth+5; i++ {
			inner = `{"name":"f","item":[` + inner + `]}`
		}
		obs, _, err := ImportPostman([]byte(doc + "," + inner + "]}"))
		if err != nil || len(obs) != 1 || obs[0].Request.Path != "/api/top" {
			t.Fatalf("err = %v, observations %d", err, len(obs))
		}
	})
	t.Run("larger than the limit", func(t *testing.T) {
		if _, _, err := ImportPostman(bytes.Repeat([]byte(" "), MaxDocumentBytes+1)); err == nil {
			t.Fatal("imported")
		}
	})
}
