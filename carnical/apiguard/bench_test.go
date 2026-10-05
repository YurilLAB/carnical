// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// benchGuard has a described model in force and the learned model enforced, and limits so high that the rate limiter counts every
// request and refuses none, so that what is measured is the whole path for a request that is let through.
func benchGuard(b testing.TB, described, learned bool) *Guard {
	b.Helper()
	cfg := DefaultConfig()
	cfg.Rate.Burst = Limit{Burst: 10_000_000, Per: time.Second}
	cfg.Rate.Sustained = Limit{Burst: 10_000_000, Per: time.Minute}
	cfg.Rate.AuthBurst = Limit{Burst: 1_000_000, Per: time.Second}
	cfg.Rate.AuthSustained = Limit{Burst: 1_000_000, Per: time.Minute}
	cfg.Modes.Spec, cfg.Modes.Learned = ModeEnforce, ModeEnforce
	g, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	if described {
		if _, err := g.ImportOpenAPI([]byte(shopAPI)); err != nil {
			b.Fatal(err)
		}
	}
	if learned {
		for i := 0; i < 400; i++ {
			g.Observe(shopTraffic(i), 200)
		}
		g.Flush()
	}
	return g
}

func benchInspect(b *testing.B, g *Guard, r *inspect.Request) {
	b.Helper()
	if res := g.Inspect(r); blocked(res) {
		b.Fatalf("the benchmark request is refused: %+v", res.Verdicts)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Inspect(r)
	}
}

var (
	postBody  = `{"name":"Walking boots","price":89.95,"stock":12,"category":"tools","note":"waterproof, size 9, pair of laces included in the box"}`
	getTarget = "/api/v1/products?limit=20&page=3&sort=price&q=boots&tags=a,b"
)

func BenchmarkInspectWithTheDescription_Read(b *testing.B) {
	g := benchGuard(b, true, false)
	benchInspect(b, g, mk("GET", getTarget, withHeader("Accept", "application/json"), withHeader("User-Agent", "Mozilla/5.0")))
}

func BenchmarkInspectWithTheDescription_WriteJSON(b *testing.B) {
	g := benchGuard(b, true, false)
	benchInspect(b, g, mk("POST", "/api/v1/products", withJSON(postBody), withHeader("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc")))
}

func BenchmarkInspectWithTheDescriptionAndTheLearnedModel_WriteJSON(b *testing.B) {
	g := benchGuard(b, true, true)
	benchInspect(b, g, mk("POST", "/api/v1/products", withJSON(postBody), withHeader("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc")))
}

func BenchmarkInspectWithTheLearnedModel_Read(b *testing.B) {
	g := benchGuard(b, false, true)
	benchInspect(b, g, mk("GET", "/api/items?limit=10&sort=price"))
}

func BenchmarkInspectWithTheLearnedModel_WriteJSON(b *testing.B) {
	g := benchGuard(b, false, true)
	benchInspect(b, g, mk("POST", "/api/items", withJSON(`{"title":"t","price":3.5,"tags":["x","y"]}`)))
}

func BenchmarkInspectShieldOnly_Read(b *testing.B) {
	g := benchGuard(b, false, false)
	benchInspect(b, g, mk("GET", getTarget, withHeader("Accept", "application/json")))
}

func BenchmarkInspectShieldOnly_WriteJSON(b *testing.B) {
	g := benchGuard(b, false, false)
	benchInspect(b, g, mk("POST", "/api/v1/products", withJSON(postBody)))
}

func BenchmarkInspectAPageIsSkipped(b *testing.B) {
	g := benchGuard(b, true, true)
	benchInspect(b, g, mk("GET", "/index.html", withHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")))
}

func BenchmarkInspectParallelWithTheDescriptionAndTheLearnedModel(b *testing.B) {
	g := benchGuard(b, true, true)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			r := mk("POST", "/api/v1/products", withJSON(postBody), withHeader("Authorization", "Bearer t"), withClient(ip(i%200)))
			g.Inspect(r)
		}
	})
}

func BenchmarkObserve(b *testing.B) {
	g := benchGuard(b, false, true)
	reqs := make([]*inspect.Request, 64)
	for i := range reqs {
		reqs[i] = shopTraffic(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Observe(reqs[i%len(reqs)], 200)
	}
}

func BenchmarkRateLimiterAllow(b *testing.B) {
	clk := newClock()
	l := newLimiter(100_000, clk.Now())
	s, bu := Limit{Burst: 1 << 30, Per: time.Minute}, Limit{Burst: 1 << 28, Per: time.Second} // far above what a benchmark spends
	keys := make([]rlKey, 1000)
	for i := range keys {
		keys[i], _ = addrKey(scopeClient, mk("GET", "/").Client.Next())
		keys[i][5] = byte(i)
		keys[i][6] = byte(i >> 8)
	}
	now := clk.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.allow(keys[i%len(keys)], s, bu, now)
	}
}

func BenchmarkCredentialKey(b *testing.B) {
	l := newLimiter(1000, newClock().Now())
	a := mk("GET", "/").Client
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		l.credKey(scopeClient, a, "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	}
}

func BenchmarkRouteLookup(b *testing.B) {
	m := mustImport(b, shopAPI)
	var caps captures
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		caps.n = 0
		m.idx.lookup("/api/v1/products/12345/reviews", &caps)
	}
}

func BenchmarkParseJSONBody(b *testing.B) {
	data := []byte(postBody)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		parseJSON(data, jsonLimits{})
	}
}

func BenchmarkImportShopAPI(b *testing.B) {
	data := []byte(shopAPI)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := ImportOpenAPI(data); err != nil {
			b.Fatal(err)
		}
	}
}

// bigDocument makes a description with n routes, each with parameters and a body schema, in JSON or YAML.
func bigDocument(n int, yaml bool) []byte {
	var sb strings.Builder
	if yaml {
		sb.WriteString("openapi: 3.0.3\ninfo: {title: big, version: '1'}\npaths:\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&sb, "  /resource%d/{id}:\n    parameters:\n      - {name: id, in: path, required: true, schema: {type: integer}}\n", i)
			fmt.Fprintf(&sb, "    get:\n      parameters:\n        - {name: q, in: query, schema: {type: string, maxLength: 40}}\n        - {name: limit, in: query, schema: {type: integer, minimum: 1, maximum: 100}}\n      responses: {'200': {description: ok}}\n")
			fmt.Fprintf(&sb, "    put:\n      requestBody:\n        content:\n          application/json:\n            schema:\n              type: object\n              required: [name]\n              properties:\n                name: {type: string}\n                price: {type: number}\n                tags: {type: array, items: {type: string}}\n      responses: {'200': {description: ok}}\n")
		}
		return []byte(sb.String())
	}
	sb.WriteString(`{"openapi":"3.0.3","info":{"title":"big","version":"1"},"paths":{`)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `"/resource%d/{id}":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer"}}],`, i)
		sb.WriteString(`"get":{"parameters":[{"name":"q","in":"query","schema":{"type":"string","maxLength":40}},{"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":100}}],"responses":{"200":{"description":"ok"}}},`)
		sb.WriteString(`"put":{"requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["name"],"properties":{"name":{"type":"string"},"price":{"type":"number"},"tags":{"type":"array","items":{"type":"string"}}}}}}},"responses":{"200":{"description":"ok"}}}}`)
	}
	sb.WriteString(`}}`)
	return []byte(sb.String())
}

func BenchmarkImportLargeJSON(b *testing.B) {
	data := bigDocument(1200, false)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := ImportOpenAPI(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkImportLargeYAML(b *testing.B) {
	data := bigDocument(1200, true)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := ImportOpenAPI(data); err != nil {
			b.Fatal(err)
		}
	}
}

// TestHowLongTheLargestAllowedDocumentTakes measures what an origin that serves a hostile description can cost: a document right
// up to the size limit, in the shapes that are most expensive to read. It logs the time of each and fails only if one is
// unreasonable.
func TestHowLongTheLargestAllowedDocumentTakes(t *testing.T) {
	pad := func(unit string, header string) []byte {
		return []byte(header + strings.Repeat(unit, (MaxDocumentBytes-len(header))/len(unit)))
	}
	shapes := []struct {
		name string
		doc  func() []byte
	}{
		{"JSON, routes to the size limit", func() []byte { return bigDocument(7000, false) }},
		{"YAML, routes to the size limit", func() []byte { return bigDocument(7000, true) }},
		{"JSON, a list of 2.5 million numbers", func() []byte { return pad("1,", `{"openapi":"3.0.0","paths":{},"x-list":[`) }},
		{"YAML, a block list of 2.5 million items", func() []byte { return pad("- a\n", "openapi: 3.0.0\npaths: {}\nx-list:\n") }},
		{"YAML, a flow list of 2.5 million items", func() []byte { return pad("a, ", "openapi: 3.0.0\npaths: {}\nx-list: [") }},
		{"YAML, a mapping of 300 thousand keys", func() []byte {
			var sb strings.Builder
			sb.WriteString("openapi: 3.0.0\npaths: {}\nx-map:\n")
			for i := 0; sb.Len() < MaxDocumentBytes-32; i++ {
				fmt.Fprintf(&sb, "  k%d: v\n", i)
			}
			return []byte(sb.String())
		}},
		{"YAML, one 5 MiB string", func() []byte { return pad("a", "openapi: 3.0.0\npaths: {}\nx-pad: ") }},
		{"YAML, 5 MiB of comments", func() []byte { return pad("# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "openapi: 3.0.0\npaths: {}\n") }},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			data := sh.doc()
			if len(data) > MaxDocumentBytes {
				data = data[:MaxDocumentBytes]
			}
			start := time.Now()
			_, rep, err := ImportOpenAPI(data)
			took := time.Since(start)
			t.Logf("%d bytes, %d routes, err=%v, took %v", len(data), rep.Routes, err, took)
			if took > 20*time.Second {
				t.Fatalf("took %v", took)
			}
		})
	}
}
