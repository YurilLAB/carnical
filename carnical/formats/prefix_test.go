package formats

import (
	"strings"
	"testing"
)

// A body that stops in the middle is not a smaller valid body, and a parser that gives up at the end of its input without saying
// so would accept it. Every proper prefix of a valid document must be refused, in every format where that is so. This is also what
// covers the "ends early" report in each parser, which no hand-written row reaches from every place a document can end.

func refused(t *testing.T, in *Inspector, r row) bool {
	t.Helper()
	res := in.Inspect(r.request())
	blocked := false
	for _, v := range res.Verdicts {
		if v.ID == rInternal.id {
			t.Errorf("the inspector failed on %q: %s", r.body, v.Message)
		}
		blocked = blocked || v.Block
	}
	return blocked
}

func noTrailingSpace(s string) bool { return strings.TrimRight(s, " \t\r\n") == s }

func TestEveryProperPrefixOfAJSONDocumentIsRefused(t *testing.T) {
	n := 0
	for _, r := range jsonRows {
		b := strings.TrimSpace(r.body)
		if r.want != 0 || r.tweak != nil || b == "" || b[0] != '{' && b[0] != '[' || !noTrailingSpace(r.body) || len(r.body) > 2000 {
			continue
		}
		in := New(r.policy(nil, false))
		for k := 1; k < len(r.body); k++ {
			p := r
			p.body = r.body[:k]
			n++
			if !refused(t, in, p) {
				t.Errorf("%s: the first %d of %d bytes were accepted: %q", r.name, k, len(r.body), p.body)
				break
			}
		}
	}
	if n < 500 {
		t.Fatalf("only %d prefixes were tried", n)
	}
}

func TestEveryProperPrefixOfAnXMLDocumentIsRefused(t *testing.T) {
	n := 0
	for _, r := range xmlRows {
		if r.want != 0 || r.tweak != nil || !strings.HasPrefix(r.body, "<") || !noTrailingSpace(r.body) || strings.HasSuffix(r.body, "-->") || len(r.body) > 2000 {
			continue
		}
		in := New(r.policy(nil, false))
		for k := 1; k < len(r.body); k++ {
			p := r
			p.body = r.body[:k]
			n++
			if !refused(t, in, p) {
				t.Errorf("%s: the first %d of %d bytes were accepted: %q", r.name, k, len(r.body), p.body)
				break
			}
		}
	}
	if n < 500 {
		t.Fatalf("only %d prefixes were tried", n)
	}
}

func TestEveryProperPrefixOfAGraphQLDocumentIsRefused(t *testing.T) {
	docs := []string{
		`{ user { id name } }`,
		`query Q($id: ID!, $n: Int = 5, $l: [String!]! = ["a"]) { user(id: $id) { friends(first: $n) { name } } }`,
		`mutation { addUser(input: {name: "x", tags: ["a","b"], n: 3.5e2, ok: true, none: null, kind: ADMIN}) { id } }`,
		`query ($x: Boolean) @live { a @include(if: $x) b @skip(if: false) ... on T { c } ... @include(if: true) { d } }`,
		`{ a(x: """block""", y: "s\né", z: -1.5E+3) }`,
		`fragment F on User @a(b: 1) { id ...G }`,
		`subscription S { m { id } }`,
	}
	n := 0
	for _, d := range docs {
		in := New(Policy{})
		for k := 1; k < len(d); k++ {
			r := row{path: "/graphql", ct: "application/graphql", body: d[:k]}
			n++
			if !refused(t, in, r) {
				t.Errorf("the first %d of %d bytes of %q were accepted: %q", k, len(d), d, r.body)
				break
			}
		}
		if refused(t, in, row{path: "/graphql", ct: "application/graphql", body: d}) && !strings.Contains(d, "fragment F") {
			t.Errorf("the whole document is refused: %q", d)
		}
	}
	if n < 300 {
		t.Fatalf("only %d prefixes were tried", n)
	}
}

func TestEveryProperPrefixOfAMultipartBodyIsRefused(t *testing.T) {
	n := 0
	for _, r := range multipartRows {
		if r.want != 0 || r.tweak != nil || !strings.HasSuffix(r.body, "--\r\n") || len(r.body) > 3000 {
			continue
		}
		in := New(r.policy(nil, false))
		// Without its last line break the closing boundary is still a closing boundary, so that one prefix is valid.
		for k := 1; k < len(r.body)-2; k++ {
			p := r
			p.body = r.body[:k]
			n++
			if !refused(t, in, p) {
				t.Errorf("%s: the first %d of %d bytes were accepted: %q", r.name, k, len(r.body), p.body)
				break
			}
		}
	}
	if n < 500 {
		t.Fatalf("only %d prefixes were tried", n)
	}
}

func TestEveryProperPrefixOfACompressedBodyIsRefused(t *testing.T) {
	in := New(Policy{})
	for name, stream := range map[string]string{"gzip": gz(smallJSON), "deflate": zl(smallJSON)} {
		for k := 1; k < len(stream); k++ {
			if !refused(t, in, row{ct: appJSON, hdr: enc(name), body: stream[:k]}) {
				t.Errorf("%s: the first %d of %d bytes were accepted", name, k, len(stream))
				break
			}
		}
	}
}

// TestEveryProperPrefixOfADocumentIsRefused for NDJSON: a body cut inside a line is refused, cut between two is two records.
func TestEveryProperPrefixOfANDJSONLineIsRefused(t *testing.T) {
	in := New(Policy{})
	line := `{"a":[1,2,{"b":"c"}],"d":"é"}`
	for k := 1; k < len(line); k++ {
		if !refused(t, in, row{ct: ndjson, body: "{\"x\":1}\n" + line[:k]}) {
			t.Errorf("the first %d bytes of the line were accepted", k)
			break
		}
	}
}

func TestInspectingNothingIsAnInternalErrorAndNotACrash(t *testing.T) {
	res := New(Policy{}).Inspect(nil)
	if len(res.Verdicts) != 1 || res.Verdicts[0].ID != idInternal || !res.Verdicts[0].Block || res.Verdicts[0].Status != 503 {
		t.Fatalf("%v", res.Verdicts)
	}
	res = New(Policy{Monitor: true}).Inspect(nil)
	if len(res.Verdicts) != 1 || res.Verdicts[0].Block {
		t.Fatalf("%v", res.Verdicts)
	}
}

const idInternal = 5002991
