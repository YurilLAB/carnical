package formats

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// These bodies exercise costly parser shapes at two sizes. The test checks a
// per-byte ceiling and a scaling limit when the input is four times larger.
// Monitor mode and raised count limits keep the scan from stopping at a refusal.

func raised(p *Policy) {
	p.MaxBodyBytes = 8 << 20
	p.JSON = JSONLimits{MaxNodes: 10_000_000, MaxKeys: 10_000_000, MaxStringLen: 8 << 20, MaxDepth: 64}
	p.XML = XMLLimits{MaxElements: 10_000_000, MaxTextLen: 8 << 20, MaxAttrValueLen: 8 << 20}
	p.Form = FormLimits{MaxParams: 10_000_000, MaxValueLen: 8 << 20}
	p.Multipart = MultipartLimits{MaxParts: 100_000}
	p.NDJSON = NDJSONLimits{MaxLines: 10_000_000}
	p.GraphQL = GraphQLLimits{MaxQueryBytes: 8 << 20, MaxFields: 10_000_000, MaxAliases: 10_000_000}
	p.YAML = YAMLLimits{MaxBytes: 8 << 20, MaxNodes: 10_000_000}
}

type shape struct {
	name string
	ct   string
	path string
	// make builds a body of about n bytes.
	make func(n int) string
}

func repeatTo(unit string, n int) string { return strings.Repeat(unit, max(1, n/len(unit))) }

func manyKeys(n int) string {
	var sb strings.Builder
	sb.WriteString("{")
	for i := 0; sb.Len() < n; i++ {
		fmt.Fprintf(&sb, `"key%d":%d,`, i, i)
	}
	sb.WriteString(`"z":0}`)
	return sb.String()
}

func wideElements(n int) string {
	var attrs strings.Builder
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&attrs, `a%d="1" `, i)
	}
	return "<r>" + repeatTo("<e "+attrs.String()+"/>", n) + "</r>"
}

var shapes = []shape{
	{"json many keys", "application/json", "/x", manyKeys},
	{"json one key repeated", "application/json", "/x", func(n int) string { return "{" + repeatTo(`"a":1,`, n) + `"z":0}` }},
	{"json escaped key", "application/json", "/x", func(n int) string { return `{"` + repeatTo(u("0041"), n) + `":1}` }},
	{"json nested arrays", "application/json", "/x", func(n int) string { return "[" + repeatTo("[1],", n) + "[1]]" }},
	{"json long string", "application/json", "/x", func(n int) string { return `{"a":"` + strings.Repeat("x", n) + `"}` }},
	{"xml many elements", "application/xml", "/x", func(n int) string { return "<r>" + repeatTo("<a/>", n) + "</r>" }},
	{"xml sixty attributes each", "application/xml", "/x", wideElements},
	{"xml comments in text", "application/xml", "/x", func(n int) string { return "<r>" + repeatTo("a<!-- -->", n) + "</r>" }},
	{"xml references", "application/xml", "/x", func(n int) string { return "<r>" + repeatTo("&amp;&#65;&#x42;", n) + "</r>" }},
	{"form many params", "application/x-www-form-urlencoded", "/x", func(n int) string { return repeatTo("a=1&", n) }},
	{"form escapes", "application/x-www-form-urlencoded", "/x", func(n int) string { return "a=" + repeatTo("%41", n) }},
	{"multipart boundary inside lines", mpType, "/x", func(n int) string {
		return "--" + bnd + "\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n" + repeatTo("--"+bnd+"x", n) + "\r\n--" + bnd + "--\r\n"
	}},
	{"multipart many parts", mpType, "/x", func(n int) string { return repeatTo(field("a", "v"), n) + closing() }},
	{"multipart large file", mpType, "/x", func(n int) string { return mp(file("f", "a.bin", strings.Repeat("\r\n-", n/2))) }},
	{"ndjson many lines", "application/x-ndjson", "/x", func(n int) string { return repeatTo("{\"a\":1}\n", n) }},
	{"graphql many fields", "application/graphql", "/graphql", func(n int) string { return "{ " + repeatTo("f ", n) + "}" }},
	{"graphql many aliases", "application/graphql", "/graphql", func(n int) string { return "{ " + repeatTo(`a: login(u: "x") `, n) + "}" }},
	{"graphql many fragments", "application/graphql", "/graphql", func(n int) string {
		const fragments = 900
		document := func(fields string) string {
			var sb strings.Builder
			sb.WriteString("{ ...F0 }\n")
			for i := 0; i < fragments; i++ {
				fmt.Fprintf(&sb, "fragment F%d on T { %s...F%d }\n", i, fields, i+1)
			}
			fmt.Fprintf(&sb, "fragment F%d on T { a }\n", fragments)
			return sb.String()
		}
		// Keep the long fragment chain and grow its selections within the definition cap.
		base := document("")
		fields := strings.Repeat("a ", max(0, (n-len(base))/(2*fragments)))
		return document(fields)
	}}}

// yamlShapes are the adversarial YAML bodies. The library that reads YAML is not linear in the size of the document (many mapping
// keys cost more than their share), so YAML is held to its size cap instead, and the cap is what the test measures.
var yamlShapes = []shape{
	{"yaml many keys", "application/yaml", "/x", func(n int) string {
		var sb strings.Builder
		for i := 0; sb.Len() < n; i++ {
			fmt.Fprintf(&sb, "k%d: v\n", i)
		}
		return sb.String()
	}},
	{"yaml short keys", "application/yaml", "/x", func(n int) string { return repeatTo("a: 1\n", n) }},
	// The previous near-node-limit shape now exercises the pair preflight.
	// The following shapes still reach parsing at the pair limit.
	{"yaml mapping below node cap", "application/yaml", "/x", func(n int) string {
		return repeatTo("a: 1\n", min(n, 4999*5)) // one mapping + two nodes per pair: 9999
	}},
	{"yaml duplicate mapping at pair cap", "application/yaml", "/x", func(n int) string { return repeatTo("a: 1\n", min(n, maxYAMLCollectionWork*5)) }},
	{"yaml unique mapping at pair cap", "application/yaml", "/x", func(n int) string {
		var sb strings.Builder
		for i := 0; i < maxYAMLCollectionWork; i++ {
			fmt.Fprintf(&sb, "k%d: 1\n", i)
		}
		return sb.String()
	}},
	{"yaml explicit null keys at work cap", "application/yaml", "/x", func(n int) string { return strings.Repeat("? a\n", maxYAMLCollectionWork) }},
	{"yaml shorthand null map at work cap", "application/yaml", "/x", func(n int) string {
		return "{" + strings.TrimSuffix(strings.Repeat("a,", maxYAMLCollectionWork), ",") + "}\n"
	}},
	{"yaml block null sequence at work cap", "application/yaml", "/x", func(n int) string { return strings.Repeat("-\n", maxYAMLCollectionWork) }},
	{"yaml flow list", "application/yaml", "/x", func(n int) string { return "[" + repeatTo("1,", n) + "1]\n" }},
	{"yaml flow maps", "application/yaml", "/x", func(n int) string { return "{" + repeatTo("a: [1, {b: c}],", n) + "z: 1}\n" }},
	{"yaml sequence of maps", "application/yaml", "/x", func(n int) string { return repeatTo("- {a: 1, b: 2}\n", n) }},
	{"yaml aliases", "application/yaml", "/x", func(n int) string { return "a: &a x\nb:\n" + repeatTo("  - *a\n", n) }},
	{"yaml comments", "application/yaml", "/x", func(n int) string { return repeatTo("# a comment line\n", n) + "a: 1\n" }},
	{"yaml long scalar", "application/yaml", "/x", func(n int) string { return "a: " + repeatTo("word ", n) + "\n" }},
}

// timeOf uses Go's benchmark calibration: each trial starts with a collected heap
// and the measured calls include steady allocation and collection costs. A short
// best-of-three sample can compare different collector or scheduler windows.
func timeOf(in *Inspector, r row) time.Duration {
	req := r.request()
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			in.Inspect(req)
		}
	})
	return time.Duration(result.NsPerOp())
}

// TestYAMLAtItsDefaultCapIsBounded measures the worst YAML bodies the default size cap lets through.
func TestYAMLAtItsDefaultCapIsBounded(t *testing.T) {
	for _, s := range yamlShapes {
		t.Run(s.name, func(t *testing.T) {
			// Leave room for each shape's closing delimiters and final line.
			// Bodies must reach the structural preflight rather than trip the byte cap.
			// The at-work-cap shapes reach parsing; over-budget shapes stop early.
			r := row{ct: s.ct, body: s.make((32 << 10) - 64), tweak: allowYAML}
			in := New(r.policy(nil, true))
			if len(r.body) > in.pol.YAML.MaxBytes {
				t.Fatalf("the body is %d bytes", len(r.body))
			}
			d := timeOf(in, r)
			t.Logf("%6d bytes %9v %7.1f ns/byte", len(r.body), d.Round(time.Microsecond), float64(d.Nanoseconds())/float64(len(r.body)))
			if d > 250*time.Millisecond {
				t.Errorf("took %v", d)
			}
		})
	}
}

// BenchmarkAdversarialBodies keeps size and allocation measurements available for
// diagnosing a cost-test failure without changing the parser or its policy.
func BenchmarkAdversarialBodies(b *testing.B) {
	for _, s := range shapes {
		for _, size := range []int{64 << 10, 256 << 10} {
			b.Run(fmt.Sprintf("%s/%dKiB", s.name, size>>10), func(b *testing.B) {
				r := row{path: s.path, ct: s.ct, body: s.make(size), tweak: raised}
				in := New(r.policy(nil, true))
				if in.Err() != nil {
					b.Fatal(in.Err())
				}
				req := r.request()
				b.SetBytes(int64(len(r.body)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					in.Inspect(req)
				}
			})
		}
	}
}

func TestAdversarialBodiesCostInProportionToTheirSize(t *testing.T) {
	const perByteCeiling = 400.0 // ns per byte: ten times what the slowest ordinary format costs, so a noisy machine does not fail it
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			small := row{path: s.path, ct: s.ct, body: s.make(64 << 10), tweak: raised}
			large := small
			large.body = s.make(256 << 10)
			if ratio := float64(len(large.body)) / float64(len(small.body)); ratio < 3.9 || ratio > 4.1 {
				t.Fatalf("the scaling fixture grew by %.2fx instead of about 4x", ratio)
			}
			in := New(small.policy(nil, true))
			if in.Err() != nil {
				t.Fatal(in.Err())
			}
			ts, tl := timeOf(in, small), timeOf(in, large)
			nsSmall := float64(ts.Nanoseconds()) / float64(len(small.body))
			nsLarge := float64(tl.Nanoseconds()) / float64(len(large.body))
			t.Logf("%7d bytes %9v %6.1f ns/byte; %7d bytes %9v %6.1f ns/byte", len(small.body), ts.Round(time.Microsecond), nsSmall, len(large.body), tl.Round(time.Microsecond), nsLarge)
			if nsLarge > perByteCeiling {
				t.Errorf("%.1f ns/byte at %d bytes", nsLarge, len(large.body))
			}
			// Four times the bytes may take four times as long, with room for caches and the collector, but not sixteen.
			if ratio := float64(tl) / float64(ts); ratio > 9 {
				t.Errorf("four times the size took %.1f times as long", ratio)
			}
		})
	}
}
