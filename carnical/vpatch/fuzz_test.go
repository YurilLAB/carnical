// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// Every parser of untrusted input has a fuzz target. Run briefly with, for example:
//
//	go test ./vpatch -run XXX -fuzz FuzzReadPack -fuzztime 30s
//
// A seed corpus of real shapes makes the first seconds count.

func FuzzReadLegacy(f *testing.F) {
	f.Add(`{"id":"A","severity":"high","operator":"rx","pattern":"a+","targets":["uri"],"_status":"verified"}` + "\n")
	f.Add(`{"id":"P","severity":"low","operator":"pm","pattern":["a","b"],"targets":["path"],"also":[{"operator":"rx","pattern":"x","targets":["body"]}]}`)
	f.Add("{\n}\n\n[1]\n")
	f.Fuzz(func(t *testing.T, in string) {
		sigs, err := ReadLegacy(strings.NewReader(in))
		if err != nil {
			return
		}
		// whatever it read must load without a panic, and be matchable
		e := New(Options{Tiers: allTiers})
		e.Load(sigs)
		_ = e.Match(mkReq("GET", "/a?b=c", nil, "d"))
	})
}

func FuzzReadPack(f *testing.F) {
	var y, j bytes.Buffer
	_ = WritePack(&y, samplePack())
	_ = WritePackJSON(&j, samplePack())
	f.Add(y.String())
	f.Add(j.String())
	f.Add("format: carnical-vpatch-1\nsignatures: []\n")
	f.Add("a: &x [*x]\n")
	f.Fuzz(func(t *testing.T, in string) {
		p, err := ReadPack(strings.NewReader(in))
		if err != nil {
			return
		}
		// what is read must write and read back to the same content
		var b bytes.Buffer
		if err := WritePack(&b, p); err != nil {
			t.Fatalf("a pack that was read could not be written: %v", err)
		}
		q, err := ReadPack(&b)
		if err != nil {
			t.Fatalf("a pack that was written could not be read: %v", err)
		}
		if q.Hash != p.Hash {
			t.Fatal("the content hash changed in the round trip")
		}
	})
}

func FuzzCompileRx(f *testing.F) {
	for _, s := range []string{`a+b`, `(?i)abc`, `a++`, `(?>a)`, `\Z`, `a$`, `\A(?=[\s\S]{0,4096}?x)(?=y)z`, `x(?=[a-z])(?:cat|curl)`, `\xc0\xaf`, `(a)\1`, `a{0,5000}`, `[]a]`, `\Qx\E`, `(?#c)a`, `(?P<n>a)`, `(?<n>a)`} {
		f.Add(s, "")
		f.Add(s, "i")
	}
	f.Fuzz(func(t *testing.T, pattern, flags string) {
		t0 := time.Now()
		defer func() {
			if d := time.Since(t0); d > time.Second {
				t.Errorf("compiling and running %q took %v", pattern, d)
			}
		}()
		p, err := compileRx(pattern, flags)
		if err != nil {
			return
		}
		// an accepted expression runs on any input in time and without a panic, and its literals are well formed
		for _, l := range p.anchors {
			if len(l) < minAnchor || len(l) > maxAnchor || l != strings.ToLower(l) {
				t.Fatalf("bad anchor %q for %q", l, pattern)
			}
			for i := 0; i < len(l); i++ {
				if l[i] >= 0x80 {
					t.Fatalf("a non-ASCII anchor %q for %q", l, pattern)
				}
			}
		}
		for _, in := range []string{"", "a", "ab\n", strings.Repeat("a", 2000), "\xc0\xaf\xff"} {
			for _, re := range p.res {
				s := in
				if p.byteMode {
					s = latin1ToUTF8(in)
				}
				_ = re.MatchString(s)
			}
		}
	})
}

func FuzzTransforms(f *testing.F) {
	for _, s := range []string{"%2e%2e%2f", "&#x3c;", `<`, "a/**/b", "dW5pb24gc2VsZWN0", "/a/../b", "\xc0\xaf", "é", "c\"a\"t"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		for name, fn := range transforms {
			out := fn(in)
			if len(out) > 8*len(in)+16 {
				t.Fatalf("%s grew %d bytes into %d", name, len(in), len(out))
			}
		}
	})
}

// fuzzEngine is a small library covering every operator, target and several transforms, so that a fuzzed request exercises the
// views and the index.
func fuzzEngine(tb testing.TB) *Engine {
	tb.Helper()
	sigs := []Signature{
		sig("F1", cond("rx", `\.\./`, tg("uri"), "urldecode")),
		sig("F2", cond("contains", "union select", tg("args", "body"), "urldecode", "lowercase", "compressspace")),
		sig("F3", cond("pm", "sqlmap nikto", tg("header:user-agent"), "lowercase")),
		sig("F4", cond("equals", "POST", tg("method")), cond("rx", `(?i)<script`, tg("args", "cookies"), "urldecode", "htmldecode")),
		sig("F5", cond("rx", `^[a-z]+$`, tg("argnames")), cond("contains", "x", tg("arg:id"))),
		sig("F6", cond("suffix", ".php", tg("filenames"), "lowercase", "trim")),
		sig("F7", cond("prefix", "eval(", tg("uploads", "body"), "base64decode")),
		sig("F8", Condition{Operator: "contains", Pattern: "ok", Targets: tg("query"), Negate: true}, cond("contains", "/admin", tg("path"), "normpath")),
		sig("F9", cond("rx", `\A(?=[\s\S]*?foo)[\s\S]*?bar`, tg("body"), "jsdecode", "cssdecode", "utf8unicode")),
	}
	e := New(Options{Tiers: allTiers, MaxWork: 1 << 24, MaxEvalTime: -1}) // a busy fuzzing machine must not look like a difference
	if rep := e.Load(sigs); len(rep.Rejected) != 0 {
		tb.Fatalf("%+v", rep.Rejected)
	}
	return e
}

// FuzzMatch feeds the engine whatever the fuzzer builds as a request. It must never panic, and the indexed answer must equal the
// brute-force answer.
func FuzzMatch(f *testing.F) {
	f.Add("GET", "/a/../b.php", "x=union+select&id=x", "ua", "c=1", "application/x-www-form-urlencoded", "body")
	f.Add("POST", "/admin/../admin", "q=%3Cscript%3E", "sqlmap/1.0", "s=%3cscript", "application/json", `{"id":"x","a":["ok"]}`)
	f.Add("PUT", "/", "", "", "", "multipart/form-data; boundary=zz", "--zz\r\nContent-Disposition: form-data; name=\"f\"; filename=\"A.PHP \"\r\n\r\neval(\r\n--zz--")
	e := fuzzEngine(f)
	f.Fuzz(func(t *testing.T, method, path, query, ua, cookie, ct, body string) {
		r := &inspect.Request{Method: method, Path: path, RawQuery: query, Header: http.Header{}, Body: []byte(body)}
		r.Header.Set("User-Agent", ua)
		r.Header.Set("Cookie", cookie)
		r.Header.Set("Content-Type", ct)
		if d := diffHits(e, r); d != "" {
			t.Fatalf("%s", d)
		}
		_ = e.Inspect(r)
	})
}
