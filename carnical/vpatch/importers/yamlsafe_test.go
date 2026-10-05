// SPDX-License-Identifier: Apache-2.0

package importers

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDecodeYAML(t *testing.T) {
	bomb := "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{name: "mapping", in: "name: x\nrules:\n  - a: 1\n"},
		{name: "leading document marker", in: "---\nname: x\n"},
		{name: "comment only", in: "# nothing\n", wantErr: ErrYAMLEmpty},
		{name: "empty", in: "", wantErr: ErrYAMLEmpty},
		{name: "two documents", in: "a: 1\n---\nb: 2\n", wantErr: ErrYAMLMultiple},
		{name: "anchor and alias", in: "a: &x [1]\nb: *x\n", wantErr: ErrYAMLUnsafe},
		{name: "expansion bomb", in: bomb, wantErr: ErrYAMLUnsafe},
		{name: "merge key", in: "a: &x {k: 1}\nb:\n  <<: *x\n", wantErr: ErrYAMLUnsafe},
		{name: "broken", in: "a: [1, 2\nb: {", wantErr: ErrYAMLInvalid},
		{name: "tab indentation", in: "a:\n\t- 1\n", wantErr: ErrYAMLInvalid},
		{name: "NUL byte", in: "a: \x00\n", wantErr: ErrYAMLInvalid},
		{name: "not UTF-8", in: "a: \xff\xfe\n", wantErr: ErrYAMLNotUTF8},
		{name: "too large", in: "a: " + strings.Repeat("x", 2<<20), wantErr: ErrYAMLTooLarge},
		{name: "flow brackets nested too deeply", in: strings.Repeat("[", 400) + strings.Repeat("]", 400), wantErr: ErrYAMLUnsafe},
		{name: "block nesting too deep for the tree check", in: deepBlockN(45), wantErr: errYAMLComplexity},
		{name: "indented too far", in: strings.Repeat(" ", 200) + "a: 1\n", wantErr: ErrYAMLUnsafe},
		{name: "a hundred quotes on one line is fine", in: "k: '" + strings.Repeat(`"`, 100) + "'\n"},
		{name: "thousands of quotes on one line", in: "k: " + strings.Repeat(`"`, 5000) + "\n", wantErr: ErrYAMLUnsafe},
		{name: "block scalar content is not scanned", in: "k: |\n  " + strings.Repeat(`"[{`, 5000) + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := DecodeYAML([]byte(tt.in), Limits{})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v (value %v)", err, tt.wantErr, v)
			}
		})
	}
	t.Run("values come back as plain Go types", func(t *testing.T) {
		v, err := DecodeYAML([]byte("n: 3\ns: \"x\"\nb: true\nl: [a, 2]\nm: {k: v}\n"), Limits{})
		if err != nil {
			t.Fatal(err)
		}
		m, ok := AsMap(v)
		if !ok {
			t.Fatalf("%T", v)
		}
		if s, _ := AsString(m["n"]); s != "3" {
			t.Errorf("n = %v", m["n"])
		}
		if s, _ := AsString(m["b"]); s != "true" {
			t.Errorf("b = %v", m["b"])
		}
		if l, ok := AsList(m["l"]); !ok || len(l) != 2 {
			t.Errorf("l = %v", m["l"])
		}
		if _, ok := AsMap(m["m"]); !ok {
			t.Errorf("m = %T", m["m"])
		}
	})
}

// TestDecodeYAMLAdversarial measures what hostile input of the largest accepted size costs. The bound is generous; the point is
// that it is a bound.
func TestDecodeYAMLAdversarial(t *testing.T) {
	const max = 1 << 20
	cases := map[string]string{
		"1 MiB of open brackets":        strings.Repeat("[", max),
		"1 MiB of nested lists":         strings.Repeat("- ", max/2),
		"deep block nesting":            deepBlock(max),
		"1 MiB of short sequence items": strings.Repeat("- a\n", max/4),
		"1 MiB flat mapping":            flatMap(max),
		"one 1 MiB scalar":              "k: " + strings.Repeat("a", max-8),
		"1 MiB of quotes":               strings.Repeat(`"`, max),
		"1 MiB of colons":               strings.Repeat(": ", max/2),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if len(in) > max {
				in = in[:max]
			}
			start := time.Now()
			_, err := DecodeYAML([]byte(in), Limits{MaxDocBytes: max})
			d := time.Since(start)
			t.Logf("%d bytes: %v in %v", len(in), err, d.Round(time.Millisecond))
			if d > 20*time.Second {
				t.Fatalf("took %v", d)
			}
		})
	}
}

// deepBlockN is a block mapping nested n levels, two spaces per level.
func deepBlockN(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(strings.Repeat("  ", i))
		b.WriteString("a:\n")
	}
	return b.String()
}

func deepBlock(n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n && i < 600; i++ {
		b.WriteString(strings.Repeat(" ", i))
		b.WriteString("a:\n")
	}
	return b.String()
}

func flatMap(n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		b.WriteString("k")
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString(": v\n")
	}
	return b.String()
}
