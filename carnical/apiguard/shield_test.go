// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

func TestTheShield(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
		req    *inspect.Request
		want   []int // verdict ids, in order; nil for none
		block  bool
		status int
	}{
		{"an ordinary read is let through", nil, mk("GET", "/api/items?page=2"), nil, false, 0},
		{"TRACE is refused", nil, mk("TRACE", "/api/items"), []int{IDMethodNotAllowed}, true, 405},
		{"PROPFIND is refused", nil, mk("PROPFIND", "/api/items"), []int{IDMethodNotAllowed}, true, 405},
		{"a lower-case method is not a method on the list", nil, mk("get", "/api/items"), []int{IDMethodNotAllowed}, true, 405},
		{"a method that is not allowed on a page is the rule set's business", nil, mk("TRACE", "/index.html"), nil, false, 0},
		{"a request is an API request if it asks for JSON", nil, mk("TRACE", "/anything", withHeader("Accept", "application/json")), []int{IDMethodNotAllowed}, true, 405},
		{"a request is an API request if it sends JSON", nil, mk("TRACE", "/anything", withJSON(`{}`)), []int{IDMethodNotAllowed}, true, 405},
		{"a browser page request is not", nil, mk("TRACE", "/anything", withHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")), nil, false, 0},
		{"a method added to the list is allowed", func(c *Config) { c.Methods = append(c.Methods, "PROPFIND") }, mk("PROPFIND", "/api/items"), nil, false, 0},
		{"a method taken off the list is refused", func(c *Config) { c.Methods = []string{"GET", "POST"} }, mk("DELETE", "/api/items/3"), []int{IDMethodNotAllowed}, true, 405},
		{"a method rule in monitor reports and lets through", func(c *Config) { c.Modes.Methods = ModeMonitor }, mk("TRACE", "/api/items"), []int{IDMethodNotAllowed}, false, 405},
		{"a method rule that is off says nothing", func(c *Config) { c.Modes.Methods = ModeOff }, mk("TRACE", "/api/items"), nil, false, 0},
		{"a GET with a large body is refused", nil, mk("GET", "/api/items", withJSON(`{"q":"`+strings.Repeat("a", 20<<10)+`"}`)), []int{IDBodyTooLarge}, true, 413},
		{"a GET with a small body is not", nil, mk("GET", "/api/search", withJSON(`{"q":"a"}`)), nil, false, 0},
		{"a HEAD with any body is refused", nil, mk("HEAD", "/api/items", withBody("text/plain", "x")), []int{IDBodyTooLarge}, true, 413},
		{"a POST of two megabytes is refused", nil, mk("POST", "/api/items", withBody("text/plain", strings.Repeat("a", 2<<20))), []int{IDBodyTooLarge}, true, 413},
		{"a POST of a hundred kilobytes is not", nil, mk("POST", "/api/items", withBody("text/plain", strings.Repeat("a", 100<<10))), nil, false, 0},
		{"a size limit set for one method", func(c *Config) { c.BodyLimits = map[string]int64{"post": 100} }, mk("POST", "/api/items", withBody("text/plain", strings.Repeat("a", 101))), []int{IDBodyTooLarge}, true, 413},
		{"a body with no Content-Type is reported, not refused", nil, mk("POST", "/api/items", withBody("", "abc")), []int{IDContentTypeMissing}, false, 415},
		{"a Content-Type that is not a media type is reported", nil, mk("POST", "/api/items", withBody("text/@bad", "abc")), []int{IDContentTypeUnseen}, false, 415},
		{"a Content-Type with parameters is read as its media type", nil, mk("POST", "/api/items", withBody("Application/JSON; charset=utf-8", `{"a":1}`)), nil, false, 0},
		{"malformed JSON is reported", nil, mk("POST", "/api/items", withJSON(`{"a":1,}`)), []int{IDBodyMalformed}, false, 400},
		{"a repeated key is reported", nil, mk("POST", "/api/items", withJSON(`{"a":1,"a":2}`)), []int{IDBodyDuplicateKey}, false, 400},
		{"JSON nested past the limit is reported as malformed", nil, mk("POST", "/api/items", withJSON(strings.Repeat("[", 100)+strings.Repeat("]", 100))), []int{IDBodyMalformed}, false, 400},
		{"XML is not parsed as JSON", nil, mk("POST", "/api/items", withBody("application/xml", `<a>{"a":1,}</a>`)), nil, false, 0},
		{"the format rules can be enforced", func(c *Config) { c.Modes.Format = ModeEnforce }, mk("POST", "/api/items", withBody("", "abc")), []int{IDContentTypeMissing}, true, 415},
		{"the guard off says nothing", func(c *Config) { c.Mode = ModeOff }, mk("TRACE", "/api/items"), nil, false, 0},
		{"the guard in learn mode says nothing", func(c *Config) { c.Mode = ModeLearn }, mk("TRACE", "/api/items"), nil, false, 0},
		{"the guard in monitor never blocks", func(c *Config) { c.Mode = ModeMonitor }, mk("TRACE", "/api/items"), []int{IDMethodNotAllowed}, false, 405},
		{"a nil request is nothing", nil, nil, nil, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, _ := testGuard(t, tt.change)
			res := g.Inspect(tt.req)
			got := ids(res)
			if len(got) != len(tt.want) {
				t.Fatalf("verdicts %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("verdicts %v, want %v", got, tt.want)
				}
			}
			if len(got) == 0 {
				return
			}
			if blocked(res) != tt.block {
				t.Fatalf("blocked = %v, want %v (%+v)", blocked(res), tt.block, res.Verdicts)
			}
			if res.Verdicts[0].Status != tt.status {
				t.Fatalf("status %d, want %d", res.Verdicts[0].Status, tt.status)
			}
			for _, v := range res.Verdicts {
				if !strings.HasPrefix(v.Message, "apiguard: ") || v.Severity == "" {
					t.Fatalf("verdict %+v", v)
				}
			}
		})
	}
}

func TestVerdictsNeverCarryTheRequest(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Format = ModeEnforce })
	canary := "CANARY-7f3a"
	for _, r := range []*inspect.Request{
		mk("TRACE", "/api/"+canary),
		mk("POST", "/api/"+canary, withBody("text/"+canary, canary)),
		mk("POST", "/api/items?"+canary+"="+canary, withBody("application/json", `{"`+canary+`":1,"`+canary+`":2}`), withHeader("X-"+canary, canary)),
		mk("POST", "/api/items", withBody("application/json", `{"role":"`+canary+`","`+canary+`":`+canary+`}`)),
		mk("POST", "/api/items", withBody("application/json", `{"`+canary+`":{"role":"admin"}}`)),
	} {
		for _, v := range g.Inspect(r).Verdicts {
			if strings.Contains(v.Message, canary) {
				t.Fatalf("a verdict repeats the request: %q", v.Message)
			}
		}
	}
}

func TestInspectNeverPanics(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Spec, c.Modes.Learned = ModeEnforce, ModeEnforce })
	if _, err := g.ImportOpenAPI([]byte(shopAPI)); err != nil {
		t.Fatal(err)
	}
	odd := []*inspect.Request{
		{},
		{Method: "GET"},
		{Method: "GET", Path: "/api/products/%zz"},
		{Method: "POST", Path: "/api/v1/products", Header: nil, Body: []byte("{")},
		{Method: "POST", Path: "/api/v1/products", Body: []byte(strings.Repeat("[", 5000))},
		{Method: "GET", Path: "/api/v1/products", RawQuery: strings.Repeat("a=%zz&", 5000)},
		{Method: "GET", Path: "/" + strings.Repeat("a/", 5000)},
		{Method: "GET", Path: "/api/v1/products/9999999999999999999999"},
		{Method: "POST", Path: "/api/v1/users", Body: []byte(`{"email":"a@b.example","password":"12345678"}`)},
	}
	for _, r := range odd {
		g.Inspect(r)
		g.Observe(r, 200)
	}
	if g.Stats().Panics != 0 {
		t.Fatalf("the guard panicked %d times", g.Stats().Panics)
	}
}
