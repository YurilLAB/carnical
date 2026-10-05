// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const library = `{"id":"V-1","category":"probe","severity":"high","operator":"contains","pattern":"/evil.php","targets":["path"],"_status":"verified"}
{"id":"C-1","category":"probe","severity":"high","operator":"rx","pattern":"x(?=[a-z])yz","targets":["path"],"_status":"candidate"}
{"id":"C-2","category":"probe","severity":"high","operator":"rx","pattern":"a(?!b)","targets":["path"],"_status":"candidate"}
{"id":"E-1","category":"probe","severity":"low","operator":"contains","pattern":"/maybe","targets":["path"],"_status":"held"}
{"id":"R-1","category":"probe","severity":"low","operator":"contains","pattern":"/never","targets":["path"],"_status":"rejected"}
`

const samples = `{"sig":"V-1","kind":"attack","request":{"method":"GET","uri":"/evil.php?x=1","headers":{"host":"h"},"body":""}}
{"sig":"V-1","kind":"benign","request":{"method":"GET","uri":"/fine","headers":{"host":"h"},"body":""}}
{"sig":"E-1","kind":"attack","request":{"method":"GET","uri":"/maybe","headers":{"host":"h"},"body":""}}
{"sig":"E-1","kind":"benign","request":{"method":"GET","uri":"/maybe-not/maybe","headers":{"host":"h"},"body":""}}
`

const benign = `{"request":{"method":"GET","uri":"/","headers":{"host":"h"},"body":""},"group":"paths"}
{"request":{"method":"GET","uri":"/evil.html","headers":{"host":"h"},"body":""},"group":"paths"}
`

const attacks = `{"request":{"method":"GET","uri":"/evil.php","headers":{"host":"h"},"body":""},"category":"probe"}
{"request":{"method":"GET","uri":"/nothing-to-see","headers":{"host":"h"},"body":""},"category":"probe"}
`

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func do(t *testing.T, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(args, &o, &e)
	return code, o.String(), e.String()
}

func TestCommands(t *testing.T) {
	dir := t.TempDir()
	lib := write(t, dir, "lib.jsonl", library)
	scopedLib := write(t, dir, "scoped.jsonl", strings.Replace(library, `"id":"V-1"`, `"id":"V-1","scope":["wordpress"]`, 1))
	smp := write(t, dir, "samples.jsonl", samples)
	ben := write(t, dir, "benign.jsonl", benign)
	atk := write(t, dir, "attack.jsonl", attacks)
	pack := filepath.Join(dir, "out.yaml")

	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  []string
		wantErr  string
	}{
		{"load verified", []string{"load", "-in", lib}, 0, []string{"read 4 signatures", "loaded 1 ", "verified", "tiers loaded: [verified]"}, ""},
		{"load every tier", []string{"load", "-in", lib, "-tiers", "verified,community,experimental"}, 0, []string{"loaded 3 ", "community", "experimental", "redundant one-class lookahead", "rejected: 1"}, ""},
		{"load reports a rejection", []string{"load", "-in", lib, "-tiers", "community", "-v"}, 0, []string{"rejected: 1", "C-2: the main condition: negative lookahead"}, ""},
		{"load excludes by prefix", []string{"load", "-in", lib, "-tiers", "verified,experimental", "-exclude", "E-"}, 0, []string{"loaded 1 ", "excluded by option 1"}, ""},
		{"validate", []string{"validate", "-sigs", lib, "-samples", smp, "-tiers", "verified,experimental"}, 0, []string{"verified: 1 signatures loaded", "pass completely (all attacks, no benign):   1", "trip one of their own benign samples:       1"}, ""},
		{"validate verbose", []string{"validate", "-sigs", lib, "-samples", smp, "-tiers", "verified,experimental", "-v"}, 0, []string{"ok   V-1", "FAIL E-1", "attacks 1/1  benign tripped 1/1"}, ""},
		{"replay", []string{"replay", "-sigs", lib, "-benign", ben, "-attack", atk, "-verify-index"}, 0, []string{"benign: 0 of 2", "attack: 1 of 2", "probe", "index check: 0 requests"}, ""},
		{"replay matching software scope", []string{"replay", "-sigs", scopedLib, "-scope", "wordpress", "-attack", atk, "-verify-index"}, 0, []string{"loaded 1 signatures", "attack: 1 of 2", "index check: 0 requests"}, ""},
		{"replay missing software scope", []string{"replay", "-sigs", scopedLib, "-attack", atk}, 1, nil, "no signatures loaded"},
		{"replay wrong software scope", []string{"replay", "-sigs", scopedLib, "-scope", "jira", "-attack", atk}, 1, nil, "no signatures loaded"},
		{"replay samples", []string{"replay", "-sigs", lib, "-samples", smp, "-tiers", "verified,experimental"}, 0, []string{"benign: 1 of 2", "attack: 2 of 2"}, ""},
		{"convert", []string{"convert", "-in", lib, "-out", pack, "-tiers", "verified,community"}, 0, []string{"wrote", "3 of 4 signatures", "hash "}, ""},
		{"load the converted pack", []string{"load", "-in", pack, "-tiers", "verified,community"}, 0, []string{"read 3 signatures", "loaded 2 ", "rejected: 1"}, ""},
		{"no arguments", nil, 2, nil, "usage"},
		{"unknown command", []string{"frobnicate"}, 2, nil, "unknown command"},
		{"load without -in", []string{"load"}, 2, nil, "-in is required"},
		{"a bad tier", []string{"load", "-in", lib, "-tiers", "gold"}, 2, nil, "not a tier"},
		{"a missing file", []string{"load", "-in", filepath.Join(dir, "nope.jsonl")}, 1, nil, "nope.jsonl"},
		{"a malformed library", []string{"load", "-in", write(t, dir, "bad.jsonl", "{oops\n")}, 1, nil, "line 1"},
		{"validate without samples", []string{"validate", "-sigs", lib}, 2, nil, "required"},
		{"a bad format", []string{"load", "-in", lib, "-format", "xml"}, 2, nil, "-format"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := do(t, tc.args...)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tc.wantCode, out, errOut)
			}
			for _, w := range tc.wantOut {
				if !strings.Contains(out, w) {
					t.Errorf("stdout lacks %q:\n%s", w, out)
				}
			}
			if tc.wantErr != "" && !strings.Contains(errOut, tc.wantErr) {
				t.Errorf("stderr lacks %q:\n%s", tc.wantErr, errOut)
			}
		})
	}
	if _, err := os.Stat(pack + ".tmp"); err == nil {
		t.Error("a temporary file was left behind")
	}
}
