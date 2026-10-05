// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReadLegacy(t *testing.T) {
	line := func(extra string) string {
		return `{"id":"X1","category":"rce","severity":"high","operator":"rx","pattern":"a+","targets":["uri"]` + extra + "}\n"
	}
	tests := []struct {
		name    string
		in      string
		wantN   int
		wantErr string
		check   func(t *testing.T, s []Signature)
	}{
		{"verified", line(`,"_status":"verified"`), 1, "", func(t *testing.T, s []Signature) {
			if s[0].Tier != TierVerified || s[0].Pattern != "a+" || s[0].Operator != "rx" {
				t.Fatalf("%+v", s[0])
			}
		}},
		{"candidate is community", line(`,"_status":"candidate"`), 1, "", func(t *testing.T, s []Signature) {
			if s[0].Tier != TierCommunity {
				t.Fatal(s[0].Tier)
			}
		}},
		{"held is experimental", line(`,"_status":"held"`), 1, "", func(t *testing.T, s []Signature) {
			if s[0].Tier != TierExperimental {
				t.Fatal(s[0].Tier)
			}
		}},
		{"rejected is skipped", line(`,"_status":"rejected"`), 0, "", nil},
		{"no status takes the tier field", line(`,"tier":"community"`), 1, "", func(t *testing.T, s []Signature) {
			if s[0].Tier != TierCommunity {
				t.Fatal(s[0].Tier)
			}
		}},
		{"no status and no tier", line(``), 1, "", func(t *testing.T, s []Signature) {
			if s[0].Tier != "" {
				t.Fatal(s[0].Tier)
			}
		}},
		{"origin becomes a source", line(`,"sources":["et-open"],"_origin":"first-party:injection.yaml"`), 1, "", func(t *testing.T, s []Signature) {
			if !reflect.DeepEqual(s[0].Sources, []string{"et-open", "first-party:injection.yaml"}) {
				t.Fatal(s[0].Sources)
			}
		}},
		{"origin already a source is not repeated", line(`,"sources":["x"],"_origin":"x"`), 1, "", func(t *testing.T, s []Signature) {
			if len(s[0].Sources) != 1 {
				t.Fatal(s[0].Sources)
			}
		}},
		{"pm pattern as a list", `{"id":"P","severity":"low","operator":"pm","pattern":["a b","c"],"targets":["path"]}` + "\n", 1, "", func(t *testing.T, s []Signature) {
			if s[0].Pattern != "" || !reflect.DeepEqual(s[0].Patterns, []string{"a b", "c"}) {
				t.Fatalf("%+v", s[0].Condition)
			}
		}},
		{"also conditions", line(`,"also":[{"operator":"pm","pattern":["z"],"targets":["body"],"flags":"i","negate":true}]`), 1, "", func(t *testing.T, s []Signature) {
			a := s[0].Also[0]
			if !reflect.DeepEqual(a.Patterns, []string{"z"}) || a.Flags != "i" || !a.Negate {
				t.Fatalf("%+v", a)
			}
		}},
		{"blank lines are skipped", "\n" + line(``) + "  \n" + line(``), 2, "", nil},
		{"an unknown field is an error", line(`,"colour":"red"`), 0, "line 1", nil},
		{"malformed JSON names the line", line(``) + "{oops\n", 0, "line 2", nil},
		{"two values on a line", line(``)[:len(line(``))-1] + line(``), 0, "line 1", nil},
		{"pattern of the wrong type", `{"id":"P","operator":"rx","pattern":5,"targets":["path"]}` + "\n", 0, "pattern", nil},
		{"unknown status", line(`,"_status":"maybe"`), 0, "_status", nil},
		{"a line over the limit", `{"id":"` + strings.Repeat("x", maxLegacyLine) + `"}` + "\n", 0, "longer", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadLegacy(strings.NewReader(tc.in))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want one mentioning %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || len(got) != tc.wantN {
				t.Fatalf("got %d signatures, error %v", len(got), err)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestReadLegacyRealLibrary(t *testing.T) {
	sigs := library(t)
	tiers := map[string]int{}
	for _, s := range sigs {
		tiers[s.Tier]++
	}
	if tiers[TierVerified] != 1541 || tiers[TierCommunity] != 1916 || tiers[TierExperimental] != 4570 || len(sigs) != 8027 {
		t.Fatalf("tiers %v, %d signatures", tiers, len(sigs))
	}
}

func samplePack() Pack {
	a := Signature{ID: "A-1", Rev: 2, Category: "rce", Severity: "critical", Confidence: "high", Description: "a thing: with \"quotes\" and a # hash", Action: "block",
		CVEs: []string{"CVE-2024-1"}, Sources: []string{"first-party"}, Scope: []string{"wordpress:plugin:x"}, Tier: TierVerified, Expires: "2030-01-01",
		Condition: Condition{Operator: "rx", Pattern: `^/a\.php$|x{2,3}`, Flags: "i", Targets: []string{"path", "header:x-a"}, Transforms: []string{"urldecode1", "lowercase"}},
		Also:      []Condition{{Operator: "pm", Patterns: []string{"one two", "three"}, Targets: []string{"body"}, Negate: true}}}
	b := Signature{ID: "B-2", Category: "xss", Severity: "low", Condition: Condition{Operator: "contains", Pattern: "yes: no\nnewline\ttab", Targets: []string{"args"}}}
	return Pack{Name: "test pack", Version: "2026.10.05", Created: "2026-10-05T12:00:00Z", Signatures: []Signature{a, b}}
}

func TestPackRoundTrip(t *testing.T) {
	for _, format := range []string{"yaml", "json"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			var err error
			if format == "yaml" {
				err = WritePack(&buf, samplePack())
			} else {
				err = WritePackJSON(&buf, samplePack())
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadPack(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("%v\n%s", err, buf.String())
			}
			want := samplePack()
			if !reflect.DeepEqual(got.Signatures, want.Signatures) {
				t.Fatalf("signatures changed in the round trip:\n got %+v\nwant %+v\n%s", got.Signatures, want.Signatures, buf.String())
			}
			if got.Name != want.Name || got.Version != want.Version || got.Format != PackFormat || len(got.Hash) != 64 {
				t.Fatalf("%+v", got)
			}
			if got.Hash != (&Pack{Signatures: want.Signatures}).ContentHash() {
				t.Fatal("the hash is not the content hash")
			}
		})
	}
}

func TestPackHashIsTheSameForYAMLAndJSON(t *testing.T) {
	var y, j bytes.Buffer
	_ = WritePack(&y, samplePack())
	_ = WritePackJSON(&j, samplePack())
	a, _ := ReadPack(&y)
	b, _ := ReadPack(&j)
	if a.Hash == "" || a.Hash != b.Hash {
		t.Fatalf("%q %q", a.Hash, b.Hash)
	}
}

func TestReadPackRefuses(t *testing.T) {
	var good bytes.Buffer
	_ = WritePack(&good, samplePack())
	goodYAML := good.String()
	var goodJ bytes.Buffer
	_ = WritePackJSON(&goodJ, samplePack())
	goodJSON := goodJ.String()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "empty"},
		{"unknown top-level field in YAML", goodYAML + "extra: 1\n", "extra"},
		{"unknown top-level field in JSON", strings.Replace(goodJSON, `"name"`, `"colour": "red", "name"`, 1), "colour"},
		{"unknown signature field in YAML", strings.Replace(goodYAML, "category: rce", "category: rce\n    bogus: 1", 1), "bogus"},
		{"unknown signature field in JSON", strings.Replace(goodJSON, `"category": "rce"`, `"category": "rce", "bogus": 1`, 1), "bogus"},
		{"wrong format", strings.Replace(goodYAML, PackFormat, "something-else", 1), "format must be"},
		{"duplicate ID", strings.Replace(goodYAML, "id: B-2", "id: A-1", 1), "twice"},
		{"changed content", strings.Replace(goodYAML, "severity: critical", "severity: low", 1), "hash"},
		{"truncated JSON", goodJSON[:len(goodJSON)/2], "reading the pack"},
		{"a second JSON document", goodJSON + goodJSON, "after the document"},
		{"a second YAML document", goodYAML + "---\nformat: x\n", "document"},
		{"YAML anchors", "format: carnical-vpatch-1\nname: &a x\nversion: *a\ncreated: x\nsignatures: []\n", "anchors"},
		{"an invalid signature", strings.Replace(goodYAML, "tier: verified", "tier: gold", 1), "tier"},
		{"brackets nested far too deep", "format: carnical-vpatch-1\nsignatures: " + strings.Repeat("[", 100000), "nested deeper"},
		{"braces nested far too deep", "format: carnical-vpatch-1\nsignatures: " + strings.Repeat("{a: ", 100000), "nested deeper"},
		{"sequences nested far too deep", strings.Repeat("- ", 100000) + "x", "sequence markers"},
		{"indentation far too deep", "a:\n" + strings.Repeat(" ", 5000) + "b: 1\n", "indentation"},
		{"not a pack at all", "- 1\n- 2\n", "reading the pack"},
		{"too many signatures", func() string {
			p := Pack{Format: PackFormat, Signatures: make([]Signature, maxPackSignatures+1)}
			var b bytes.Buffer
			_ = WritePackJSONUnchecked(&b, p)
			return b.String()
		}(), "more than"},
		{"too large", strings.Repeat(" ", maxPackBytes) + "x", "larger than"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadPack(strings.NewReader(tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// WritePackJSONUnchecked writes without validating, for building a hostile file in a test.
func WritePackJSONUnchecked(w *bytes.Buffer, p Pack) error {
	b := []byte(`{"format":"` + p.Format + `","name":"","version":"","created":"","signatures":[`)
	w.Write(b)
	for i := range p.Signatures {
		if i > 0 {
			w.WriteByte(',')
		}
		w.WriteString(`{"id":"","severity":"","category":"","operator":"","targets":null}`)
	}
	w.WriteString("]}")
	return nil
}

func TestWritePackRefusesWhatItCouldNotRead(t *testing.T) {
	p := samplePack()
	p.Signatures[1].Tier = "gold"
	if err := WritePack(&bytes.Buffer{}, p); err == nil {
		t.Fatal("a pack with an invalid signature was written")
	}
	p = samplePack()
	p.Signatures[1].ID = p.Signatures[0].ID
	if err := WritePack(&bytes.Buffer{}, p); err == nil {
		t.Fatal("a pack with a duplicate ID was written")
	}
}

// The whole library survives conversion to a pack and back, and loads the same.
func TestLibraryPackRoundTrip(t *testing.T) {
	sigs := library(t)
	var buf bytes.Buffer
	t0 := time.Now()
	if err := WritePack(&buf, Pack{Name: "library", Version: "1", Created: "2026-10-05", Signatures: sigs}); err != nil {
		t.Fatal(err)
	}
	wrote := time.Since(t0)
	size := buf.Len()
	t0 = time.Now()
	got, err := ReadPack(&buf)
	if err != nil {
		t.Fatal(err)
	}
	read := time.Since(t0)
	t.Logf("%d signatures: pack is %.1f MiB of YAML, written in %v, read in %v", len(sigs), float64(size)/(1<<20), wrote, read)
	if len(got.Signatures) != len(sigs) {
		t.Fatalf("%d signatures back", len(got.Signatures))
	}
	for i := range sigs {
		if !reflect.DeepEqual(got.Signatures[i], sigs[i]) {
			t.Fatalf("signature %s changed:\n got %+v\nwant %+v", sigs[i].ID, got.Signatures[i], sigs[i])
		}
	}
}

func TestReadCorpusAndSamples(t *testing.T) {
	in := `{"sig":"S1","kind":"attack","request":{"method":"GET","uri":"/p?q=1","headers":{"Host":"h","User-Agent":"u"},"body":""}}
{"sig":"S1","kind":"benign","request":{"method":"POST","uri":"/x?","headers":{"content-type":"text/plain"},"body":"hi"}}
`
	got, err := ReadSamples(strings.NewReader(in))
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %d", err, len(got))
	}
	r := got[0].Request
	if got[0].Sig != "S1" || got[0].Kind != "attack" || r.Path != "/p" || r.RawQuery != "q=1" || r.Host != "h" || r.Header.Get("User-Agent") != "u" || r.Header.Get("Host") != "" {
		t.Fatalf("%+v %+v", got[0], r)
	}
	if got[1].Alt == nil || got[1].Request.Path != "/x" || got[1].Alt.Path != "/x?" {
		t.Fatalf("a URI ending in a bare question mark should be readable both ways: %+v", got[1])
	}
	corpus := `{"request":{"method":"POST","uri":"/up","headers":{"content-type":"multipart/form-data; boundary=BB"},"body":"","files":[{"field":"file","name":"a.php","content":"<?php"}]},"category":"upload"}` + "\n"
	c, err := ReadCorpus(strings.NewReader(corpus), "attack")
	if err != nil || len(c) != 1 || c[0].Kind != "attack" || c[0].Group != "upload" {
		t.Fatalf("%v %+v", err, c)
	}
	e := loadOne(t, Options{}, sig("F", cond("rx", `\.php$`, tg("filenames"))), sig("U", cond("contains", "<?php", tg("uploads"))))
	if hits := e.Match(c[0].Request); !hasHit(hits, "F") || !hasHit(hits, "U") {
		t.Fatalf("the built multipart body was not read back: %v", hits)
	}
	if _, err := ReadSamples(strings.NewReader("{nope\n")); err == nil {
		t.Fatal("a malformed line was accepted")
	}
}

// A pack whose patterns are full of brackets, in quoted and plain scalars, is not mistaken for deep nesting, and a hostile one is
// refused quickly.
func TestYAMLShapeCheck(t *testing.T) {
	ok := []string{
		"pattern: \"" + strings.Repeat("[", 500) + "\"\n",
		"pattern: '" + strings.Repeat("{", 500) + "'\n",
		"pattern: a" + strings.Repeat("[", 500) + "\n",
		"# " + strings.Repeat("[", 500) + "\nx: [a, [b, [c]]]\n",
		"x: \"he said \\\"[[[[\\\" \"\n",
		"- id: A\n  targets:\n    - path\n",
	}
	for _, in := range ok {
		if err := checkYAMLShape([]byte(in)); err != nil {
			t.Errorf("%q: %v", in[:min(len(in), 40)], err)
		}
	}
	start := time.Now()
	for _, in := range []string{strings.Repeat("[", 1<<20), strings.Repeat("{a: ", 1<<18), strings.Repeat("- ", 1<<19)} {
		if err := checkYAMLShape([]byte(in)); err == nil {
			t.Errorf("a hostile document of %d bytes was accepted", len(in))
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("refusing took %v", d)
	}
}
