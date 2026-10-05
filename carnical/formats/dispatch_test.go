// SPDX-License-Identifier: Apache-2.0

package formats

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"errors"
	"mime/multipart"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

const (
	idTypeNotAllowed = 5002001
	idTypeOpaque     = 5002002
	idOpaqueTooLarge = 5002003
	idTypeMissing    = 5002004
	idTypeMalformed  = 5002005
	idCharset        = 5002006
	idTypeDupParam   = 5002007
	idTypeDupHeader  = 5002008
	idBodyOnGet      = 5002009
	idBodyTooLarge   = 5002010
	idMismatchJSON   = 5002040
	idMismatchXML    = 5002041
	idMismatchMP     = 5002042
	idPolicyInvalid  = 5002990
)

func allowOpaque(types ...string) func(*Policy) {
	return func(p *Policy) { p.AllowOpaque = types }
}

var typeRows = register("content-type", []row{
	// Accepted.
	{name: "plain text", ct: "text/plain", body: "hello world"},
	{name: "plain text that looks like a log line", ct: "text/plain", body: "[INFO] service started"},
	{name: "plain text with braces", ct: "text/plain", body: "{curly} braces are ordinary text"},
	{name: "plain text that starts with a json object and goes on", ct: "text/plain", body: `{"a":1} and then some prose`},
	{name: "plain text with a heart", ct: "text/plain", body: "<3 you"},
	{name: "plain text in windows-1252", ct: "text/plain; charset=windows-1252", body: "caf\xe9"},
	{name: "no body and no type", method: "POST"},
	{name: "get with no body", method: "GET", path: "/page", query: "a=1"},
	{name: "get with a type and no body", method: "GET", ct: appJSON},
	{name: "type in upper case", ct: "APPLICATION/JSON", body: `{"a":1}`},
	{name: "no space before the parameter", ct: "application/json;charset=UTF-8", body: `{"a":1}`},
	{name: "quoted charset", ct: `application/json; charset="utf-8"`, body: `{"a":1}`},
	{name: "trailing semicolon", ct: "application/json;", body: `{"a":1}`},
	{name: "ld+json", ct: "application/ld+json", body: `{"@id":"x"}`},
	{name: "problem+json", ct: "application/problem+json", body: `{"title":"x"}`},
	{name: "unrelated parameters", ct: "application/json; profile=x; version=2", body: `{"a":1}`},
	{name: "msgpack when the site receives it", ct: "application/msgpack", body: "\x81\xa1a\x01", tweak: allowOpaque("application/msgpack")},
	{name: "grpc by prefix", ct: "application/grpc+proto", body: "\x00\x00\x00\x00\x02\x08\x01", tweak: allowOpaque("application/grpc*")},
	{name: "a type the site adds, with no parser", ct: "application/pdf", body: "%PDF-1.4", tweak: func(p *Policy) { p.AllowedTypes = []string{"application/pdf"} }},
	{name: "a wildcard of one type", ct: "text/csv", body: "a,b\n1,2", tweak: func(p *Policy) { p.AllowedTypes = []string{"text/*"} }},
	{name: "a suffix wildcard for another suffix", ct: "application/vnd.x+yaml", body: "a: 1", tweak: func(p *Policy) { p.AllowedTypes = []string{"*+yaml"} }},

	// Types that are not allowed.
	{name: "an image", ct: "image/png", body: "\x89PNG", want: idTypeNotAllowed},
	{name: "html", ct: "text/html", body: "<html></html>", want: idTypeNotAllowed},
	{name: "a made up type", ct: "application/x-evil", body: "x", want: idTypeNotAllowed},
	{name: "yaml, which is not in the default list", ct: "application/yaml", body: "a: 1", want: idTypeNotAllowed},
	{name: "a type allowed only by another suffix", ct: "application/x+xml", body: "<a/>", want: idTypeNotAllowed,
		tweak: func(p *Policy) { p.AllowedTypes = []string{"*+json"} }},
	{name: "the allowed list names one type", ct: "text/plain", body: "x", want: idTypeNotAllowed,
		tweak: func(p *Policy) { p.AllowedTypes = []string{"application/json"} }},
	{name: "opaque: octet-stream", ct: "application/octet-stream", body: "\x00\x01\x02", want: idTypeOpaque},
	{name: "opaque: msgpack", ct: "application/msgpack", body: "\x81\xa1a\x01", want: idTypeOpaque},
	{name: "opaque: x-msgpack", ct: "application/x-msgpack", body: "\x81\xa1a\x01", want: idTypeOpaque},
	{name: "opaque: cbor", ct: "application/cbor", body: "\xa1\x61a\x01", want: idTypeOpaque},
	{name: "opaque: protobuf", ct: "application/x-protobuf", body: "\x08\x01", want: idTypeOpaque},
	{name: "opaque: google protobuf", ct: "application/vnd.google.protobuf", body: "\x08\x01", want: idTypeOpaque},
	{name: "opaque: grpc", ct: "application/grpc", body: "\x00\x00\x00\x00\x02\x08\x01", want: idTypeOpaque},
	{name: "opaque: grpc proto", ct: "application/grpc+proto", body: "\x00\x00\x00\x00\x02\x08\x01", want: idTypeOpaque},
	{name: "opaque: grpc-web", ct: "application/grpc-web+proto", body: "\x00\x00\x00\x00\x02\x08\x01", want: idTypeOpaque},
	{name: "opaque: a cbor suffix", ct: "application/vnd.x+cbor", body: "\xa0", want: idTypeOpaque},
	{name: "opaque even when listed as an allowed type", ct: "application/octet-stream", body: "x", want: idTypeOpaque,
		tweak: func(p *Policy) { p.AllowedTypes = []string{"application/octet-stream"} }},
	{name: "opaque, allowed, over the size cap", ct: "application/msgpack", body: strings.Repeat("\x01", 100), want: idOpaqueTooLarge,
		tweak: func(p *Policy) { p.AllowOpaque = []string{"application/msgpack"}; p.OpaqueMaxBytes = 99 }},
	{name: "opaque, allowed, at the size cap", ct: "application/msgpack", body: strings.Repeat("\x01", 100),
		tweak: func(p *Policy) { p.AllowOpaque = []string{"application/msgpack"}; p.OpaqueMaxBytes = 100 }},
	{name: "opaque, another type allowed", ct: "application/cbor", body: "\xa0", want: idTypeOpaque, tweak: allowOpaque("application/msgpack")},

	// A body with no usable type.
	{name: "a body with no Content-Type", body: "a=1&b=2", want: idTypeMissing},
	{name: "a body with an empty Content-Type", hdr: map[string]string{"Content-Type": "  "}, body: "a=1", want: idTypeMissing},

	// Content-Type that is not well formed.
	{name: "no subtype", ct: "application/", body: "x", want: idTypeMalformed},
	{name: "no type", ct: "/json", body: "x", want: idTypeMalformed},
	{name: "no slash", ct: "json", body: "x", want: idTypeMalformed},
	{name: "space inside the type", ct: "application/ json", body: "x", want: idTypeMalformed},
	{name: "space around the slash", ct: "application / json", body: "x", want: idTypeMalformed},
	{name: "parameter with no value", ct: "application/json; charset", body: "x", want: idTypeMalformed},
	{name: "parameter with an empty value", ct: "application/json; charset=", body: "x", want: idTypeMalformed},
	{name: "parameter with no name", ct: "application/json; =utf-8", body: "x", want: idTypeMalformed},
	{name: "space around the equals sign", ct: "application/json; charset = utf-8", body: "x", want: idTypeMalformed},
	{name: "garbage after the type", ct: "application/json charset=utf-8", body: "x", want: idTypeMalformed},
	{name: "two semicolons", ct: "application/json;; charset=utf-8", body: "x", want: idTypeMalformed},
	{name: "a quote that is not closed", ct: `application/json; charset="utf-8`, body: "x", want: idTypeMalformed},
	{name: "a quoted pair at the end", ct: `application/json; charset="utf-8\`, body: "x", want: idTypeMalformed},
	{name: "an extended parameter", ct: "application/json; charset*=utf-16''x", body: "x", want: idTypeMalformed},
	{name: "a continuation parameter", ct: "application/json; boundary*0=a; boundary*1=b", body: "x", want: idTypeMalformed},
	{name: "nine parameters", ct: "application/json; a=1; b=2; c=3; d=4; e=5; f=6; g=7; h=8; i=9", body: "x", want: idTypeMalformed},
	{name: "a very long value", ct: "application/json; x=" + strings.Repeat("a", 1100), body: "x", want: idTypeMalformed},

	// Charset.
	{name: "utf-16", ct: "application/json; charset=utf-16", body: "x", want: idCharset},
	{name: "utf-16le", ct: "text/plain; charset=UTF-16LE", body: "x", want: idCharset},
	{name: "utf-32", ct: form + "; charset=utf-32", body: "a=1", want: idCharset},
	{name: "utf-7", ct: "text/plain; charset=utf-7", body: "+ADw-script+AD4-", want: idCharset},
	{name: "shift_jis", ct: "text/plain; charset=shift_jis", body: "x", want: idCharset},
	{name: "quoted utf-16", ct: `text/plain; charset="utf-16"`, body: "x", want: idCharset},
	{name: "a charset the policy adds", ct: "text/plain; charset=koi8-r", body: "x",
		tweak: func(p *Policy) { p.AllowedCharsets = []string{"utf-8", "koi8-r"} }},
	{name: "a charset the policy removes", ct: "text/plain; charset=windows-1252", body: "x", want: idCharset,
		tweak: func(p *Policy) { p.AllowedCharsets = []string{"utf-8"} }},
	{name: "charset given twice", ct: "application/json; charset=utf-8; charset=utf-16", body: "x", want: idTypeDupParam},
	{name: "charset given twice in different case", ct: "application/json; charset=utf-8; Charset=utf-8", body: "x", want: idTypeDupParam},
	{name: "an unrelated parameter given twice", ct: "text/plain; v=1; v=1", body: "x", want: idTypeDupParam},
	{name: "boundary given twice", ct: "multipart/form-data; boundary=a; boundary=b", body: "x", want: idTypeDupParam},

	// Headers and sizes.
	{name: "two Content-Type headers", hdrs: map[string][]string{"Content-Type": {"application/json", "text/plain"}}, body: "{}", want: idTypeDupHeader},
	{name: "two identical Content-Type headers", hdrs: map[string][]string{"Content-Type": {"application/json", "application/json"}}, body: "{}", want: idTypeDupHeader},
	{name: "get with a body", method: "GET", ct: "text/plain", body: "hello", want: idBodyOnGet},
	{name: "head with a body", method: "HEAD", ct: "text/plain", body: "hello", want: idBodyOnGet},
	{name: "delete with a body is allowed", method: "DELETE", ct: appJSON, body: `{"id":1}`},
	{name: "body over the size limit", ct: "text/plain", body: strings.Repeat("x", 101), want: idBodyTooLarge,
		tweak: func(p *Policy) { p.MaxBodyBytes = 100 }},
	{name: "body at the size limit", ct: "text/plain", body: strings.Repeat("x", 100),
		tweak: func(p *Policy) { p.MaxBodyBytes = 100 }},

	// A body that is not what its type says.
	{name: "json under text/plain", ct: "text/plain", body: `{"admin":true}`, want: idMismatchJSON},
	{name: "json array under text/plain", ct: "text/plain", body: `[{"a":1}]`, want: idMismatchJSON},
	{name: "json with leading whitespace under text/plain", ct: "text/plain", body: "\n\t {\"a\": 1}\r\n", want: idMismatchJSON},
	{name: "json after a byte order mark under text/plain", ct: "text/plain", body: "\xef\xbb\xbf{\"a\":1}", want: idMismatchJSON},
	{name: "json with no Content-Type when that is allowed", body: `{"a":1}`, want: idMismatchJSON,
		tweak: func(p *Policy) { p.Rules = map[string]Action{"type-missing": Off} }},
	{name: "json under a multipart type with no boundary body", ct: "multipart/form-data; boundary=x", body: `{"a":1}`, want: idMismatchJSON},
	{name: "xml under text/plain", ct: "text/plain", body: `<?xml version="1.0"?><a/>`, want: idMismatchXML},
	{name: "an element under text/plain", ct: "text/plain", body: `<methodCall><methodName>x</methodName></methodCall>`, want: idMismatchXML},
	{name: "xml with no Content-Type when that is allowed", body: `<a/>`, want: idMismatchXML,
		tweak: func(p *Policy) { p.Rules = map[string]Action{"type-missing": Off} }},
	{name: "multipart under text/plain", ct: "text/plain", body: "--xyz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--xyz--\r\n", want: idMismatchMP},
	{name: "multipart with no Content-Type when that is allowed", body: "--xyz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--xyz--\r\n", want: idMismatchMP,
		tweak: func(p *Policy) { p.Rules = map[string]Action{"type-missing": Off} }},
})

func TestContentType(t *testing.T) { runTable(t, typeRows) }

func TestPolicyValidate(t *testing.T) {
	tests := []struct {
		name string
		p    Policy
		err  string
	}{
		{"zero policy", Policy{}, ""},
		{"default policy", DefaultPolicy(), ""},
		{"a rule set to monitor", Policy{Rules: map[string]Action{"json-duplicate-key": Monitor}}, ""},
		{"a rule set to off", Policy{Rules: map[string]Action{"form-semicolon": Off}}, ""},
		{"a rule that does not exist", Policy{Rules: map[string]Action{"json-duplicate-keys": Block}}, "not a rule name"},
		{"an action that does not exist", Policy{Rules: map[string]Action{"json-syntax": "warn"}}, "not block, monitor or off"},
		{"an empty action", Policy{Rules: map[string]Action{"json-syntax": ""}}, "not block, monitor or off"},
		{"internal-error cannot be off", Policy{Rules: map[string]Action{"internal-error": Off}}, "never let through"},
		{"policy-invalid cannot be monitor", Policy{Rules: map[string]Action{"policy-invalid": Monitor}}, "never let through"},
		{"a negative limit", Policy{JSON: JSONLimits{MaxDepth: -1}}, "json.max_depth is negative"},
		{"negative query byte cap", Policy{MaxQueryBytes: -1}, "max_query_bytes is negative"},
		{"negative query parameter cap", Policy{Query: FormLimits{MaxParams: -1}}, "query.max_params is negative"},
		{"query depth above ceiling", Policy{Query: FormLimits{MaxBracketDepth: 1001}}, "query.max_bracket_depth"},
		{"negative request field budget", Policy{GraphQL: GraphQLLimits{MaxRequestFields: -1}}, "graphql.max_request_fields is negative"},
		{"request alias budget above ceiling", Policy{GraphQL: GraphQLLimits{MaxRequestAliases: 10_000_001}}, "graphql.max_request_aliases"},
		{"negative request directive budget", Policy{GraphQL: GraphQLLimits{MaxRequestDirectives: -1}}, "graphql.max_request_directives is negative"},
		{"a limit above the ceiling", Policy{JSON: JSONLimits{MaxDepth: 5000}}, "above the ceiling"},
		{"a body limit above the ceiling", Policy{MaxBodyBytes: 1 << 40}, "max_body_bytes"},
		{"a bad type entry", Policy{AllowedTypes: []string{"json"}}, "allowed_types"},
		{"an upper case type entry", Policy{AllowedTypes: []string{"Application/JSON"}}, "allowed_types"},
		{"a suffix entry with a slash", Policy{AllowedTypes: []string{"*+js/on"}}, "allowed_types"},
		{"a wildcard of a type", Policy{AllowedTypes: []string{"text/*"}}, ""},
		{"an empty type entry", Policy{AllowedTypes: []string{""}}, "allowed_types"},
		{"everything is not a type entry", Policy{AllowedTypes: []string{"*/*"}}, "allowed_types"},
		{"a bad opaque entry", Policy{AllowOpaque: []string{"*"}}, "allow_opaque"},
		{"an opaque prefix", Policy{AllowOpaque: []string{"application/grpc*"}}, ""},
		{"a charset in capitals", Policy{AllowedCharsets: []string{"UTF-8"}}, "allowed_charsets"},
		{"a graphql path that is not a path", Policy{GraphQLPaths: []string{"graphql"}}, "graphql_paths"},
		{"a graphql path with a query", Policy{GraphQLPaths: []string{"/graphql?x=1"}}, "graphql_paths"},
		{"two mistakes are both reported", Policy{Rules: map[string]Action{"nope": Block}, JSON: JSONLimits{MaxKeys: -5}}, "max_keys"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.Validate()
			switch {
			case tt.err == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tt.err != "" && (err == nil || !strings.Contains(err.Error(), tt.err)):
				t.Fatalf("got %v, want an error with %q", err, tt.err)
			}
		})
	}
}

var policyJSONRows = []struct {
	name string
	in   string
	err  string
}{
	{"empty object", `{}`, ""},
	{"a policy", `{"monitor":true,"rules":{"json-duplicate-key":"monitor"},"json":{"max_depth":10},"allowed_types":["application/json"]}`, ""},
	{"null policy", `null`, "null"},
	{"null limit", `{"graphql":{"max_depth":null}}`, "null"},
	{"null limits object", `{"graphql":null}`, "null"},
	{"null list entry", `{"graphql_paths":[null]}`, "null"},
	{"null rules", `{"rules":null}`, "null"},
	{"duplicate mode", `{"monitor":false,"monitor":true}`, "duplicate"},
	{"duplicate limit", `{"graphql":{"max_depth":2,"max_depth":12}}`, "duplicate"},
	{"duplicate limits object", `{"graphql":{"max_depth":2},"graphql":{"max_depth":12}}`, "duplicate"},
	{"escaped duplicate", `{"monitor":false,"monit\u006fr":true}`, "duplicate"},
	{"duplicate rule", `{"rules":{"json-duplicate-key":"block","json-duplicate-key":"off"}}`, "duplicate"},
	{"case alias", `{"Monitor":true}`, "unknown field"},
	{"case alias after exact field", `{"monitor":false,"MONITOR":true}`, "unknown field"},
	{"case alias limit", `{"graphql":{"MAX_DEPTH":2}}`, "unknown field"},
	{"Go field name alias", `{"MaxBodyBytes":1024}`, "unknown field"},
	{"escaped valid field", `{"monit\u006fr":true}`, ""},
	{"empty optional lists", `{"allowed_types":[],"graphql_paths":[],"rules":{}}`, ""},
	{"maximum file size", `{}` + strings.Repeat(" ", (1<<20)-2), ""},
	{"above file size", `{}` + strings.Repeat(" ", (1<<20)-1), "1 MiB"},
	{"invalid UTF-8", "{\"graphql_paths\":[\"/\xff\"]}", "UTF-8"},
	{"extreme unexpected nesting", `{"monitor":` + strings.Repeat("[", 10000) + strings.Repeat("]", 10000) + `}`, "formats policy"},
	{"an unknown field", `{"monitr":true}`, "unknown field"},
	{"an unknown limit", `{"json":{"max_deep":1}}`, "unknown field"},
	{"a wrong type", `{"monitor":"yes"}`, "formats policy"},
	{"data after the policy", `{} {}`, "data after"},
	{"an invalid rule", `{"rules":{"nope":"block"}}`, "not a rule name"},
	{"not json", `monitor: true`, "formats policy"},
}

func TestParsePolicy(t *testing.T) {
	for _, tt := range policyJSONRows {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tt.in))
			switch {
			case tt.err == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tt.err != "" && (err == nil || !strings.Contains(err.Error(), tt.err)):
				t.Fatalf("got %v, want an error with %q", err, tt.err)
			}
		})
	}
}

func FuzzParsePolicy(f *testing.F) {
	for _, tt := range policyJSONRows {
		if len(tt.in) < 4096 {
			f.Add(tt.in)
		}
	}
	encoded, err := json.Marshal(DefaultPolicy())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(encoded))
	f.Fuzz(func(t *testing.T, input string) {
		p, err := ParsePolicy([]byte(input))
		if err != nil {
			return
		}
		if err := New(p).Err(); err != nil {
			t.Fatalf("accepted an unusable policy: %v", err)
		}
		encoded, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParsePolicy(encoded)
		if err != nil {
			t.Fatalf("accepted policy cannot round-trip: %v", err)
		}
		encodedBack, err := json.Marshal(back)
		if err != nil || !bytes.Equal(encoded, encodedBack) {
			t.Fatal("policy changed on round-trip")
		}
		// Even otherwise valid input must fail when contradictory duplicate settings are appended.
		body := bytes.TrimSpace([]byte(input))
		body = append([]byte(nil), body[:len(body)-1]...)
		if len(bytes.TrimSpace(body[1:])) > 0 {
			body = append(body, ',')
		}
		body = append(body, `"monitor":false,"monitor":true}`...)
		if _, err := ParsePolicy(body); err == nil {
			t.Fatal("contradictory duplicate configuration accepted")
		}
	})
}

func TestDefaultPolicyRoundTrips(t *testing.T) {
	p := DefaultPolicy()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePolicy(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := json.Marshal(back)
	if string(b) != string(b2) {
		t.Fatalf("the policy changed on the way:\n%s\n%s", b, b2)
	}
}

func TestAnInvalidPolicyFailsClosed(t *testing.T) {
	in := New(Policy{Rules: map[string]Action{"nope": Off}})
	if in.Err() == nil {
		t.Fatal("no error")
	}
	res := in.Inspect(row{ct: appJSON, body: `{"a":1}`}.request())
	if len(res.Verdicts) != 1 || res.Verdicts[0].ID != idPolicyInvalid || !res.Verdicts[0].Block || res.Verdicts[0].Status != 503 {
		t.Fatalf("%v", res.Verdicts)
	}
	if res := in.Inspect(row{method: "GET", path: "/"}.request()); len(res.Verdicts) != 0 {
		t.Fatalf("a request with no body was refused: %v", res.Verdicts)
	}
	if strings.Contains(res.Verdicts[0].Message, "nope") {
		t.Fatal("the message repeats the policy")
	}
}

func TestIsGraphQLPath(t *testing.T) {
	in := New(Policy{GraphQLPaths: []string{"/internal/q"}})
	for path, want := range map[string]bool{
		"/graphql": true, "/GraphQL": true, "/graphiql": true, "/api/v1/graphql": true, "/graphql/": true, "/graphql/batch": true,
		"/internal/q": true, "/": false, "": false, "/graph": false, "/graphqlx": false, "/api/graph/ql": false, "/internal/q2": false,
		"/search": false, "/a/b/c": false,
	} {
		if got := in.isGraphQLPath(path); got != want {
			t.Errorf("%q: %v, want %v", path, got, want)
		}
	}
}

// TestThePolicyIsCopied checks that changing the policy after New does not change the inspector: a limit that is edited in place
// while requests are being served would be a data race and a way to weaken the checks.
func TestThePolicyIsCopied(t *testing.T) {
	p := Policy{Rules: map[string]Action{"json-duplicate-key": Block}, AllowedTypes: []string{"application/json"}}
	in := New(p)
	p.Rules["json-duplicate-key"] = Off
	p.AllowedTypes[0] = "text/plain"
	res := in.Inspect(row{ct: appJSON, body: `{"a":1,"a":2}`}.request())
	if !has(ids(res.Verdicts), idJSONDup) {
		t.Fatalf("the inspector followed a change made to the policy afterwards: %v", res.Verdicts)
	}
}

func TestRuleCountersAreBoundedAndConcurrent(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode Action
		r    row
		id   int
	}{
		{"blocked safe mutation", Block, row{method: "HEAD", path: "/graphql", query: "query=mutation%7BSECRET_ACCOUNT%7D"}, idGQLSafeMutation},
		{"monitored batch counted once per request", Monitor, row{method: "OPTIONS", path: "/graphql", ct: appJSON,
			body: "[{\"query\":\"mutation{SECRET_ACCOUNT}\"},{\"query\":\"mutation{SECRET_ACCOUNT}\"}]"}, idGQLSafeMutation},
		{"disabled mutation rule", Off, row{method: "HEAD", path: "/graphql", query: "query=mutation%7BSECRET_ACCOUNT%7D"}, idGQLSafeMutation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := New(Policy{Rules: map[string]Action{ruleName(tc.id): tc.mode}})
			if len(in.Stats()) != 0 {
				t.Fatal("a new inspector has counters")
			}
			var wg sync.WaitGroup
			for range 20 {
				wg.Go(func() {
					for range 5 {
						in.Inspect(tc.r.request())
						_ = in.Stats() // poll while other requests update counters
					}
				})
			}
			wg.Wait()
			got := in.Stats()
			if tc.mode == Off {
				if len(got) != 0 {
					t.Fatalf("off rule produced totals: %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].ID != tc.id || got[0].Name != ruleName(tc.id) {
				t.Fatalf("unexpected labels: %+v", got)
			}
			if tc.mode == Block && (got[0].Blocked != 100 || got[0].Monitored != 0) ||
				tc.mode == Monitor && (got[0].Blocked != 0 || got[0].Monitored != 100) {
				t.Fatalf("lost or duplicated findings: %+v", got)
			}
			got[0].Name = "SECRET_ACCOUNT"
			if in.Stats()[0].Name != ruleName(tc.id) {
				t.Fatal("the snapshot shares mutable storage")
			}
		})
	}
}

func TestARequestWithNoHeadersAtAll(t *testing.T) {
	in := New(Policy{})
	res := in.Inspect(&inspect.Request{Method: "POST", Path: "/", Body: []byte("a=1")})
	if len(res.Verdicts) != 1 || res.Verdicts[0].ID != idTypeMissing {
		t.Fatalf("%v", res.Verdicts)
	}
	if res := in.Inspect(&inspect.Request{Method: "GET", Path: "/"}); len(res.Verdicts) != 0 {
		t.Fatalf("%v", res.Verdicts)
	}
}

func TestEveryRuleCanBeSetToBlockMonitorOrOff(t *testing.T) {
	for _, r := range registry {
		for _, a := range []Action{Block, Monitor, Off} {
			if r == rPolicyInvalid || r == rInternal {
				if a != Block {
					continue
				}
			}
			p := Policy{Rules: map[string]Action{r.name: a}}
			if err := p.Validate(); err != nil {
				t.Errorf("%s=%s: %v", r.name, a, err)
			}
		}
	}
}

func TestRuleTable(t *testing.T) {
	seenID, seenName := map[int]string{}, map[string]int{}
	name := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	for _, r := range Rules() {
		if r.ID < 5002000 || r.ID > 5002999 {
			t.Errorf("%s: id %d is outside 5002000-5002999", r.Name, r.ID)
		}
		if prev, dup := seenID[r.ID]; dup {
			t.Errorf("id %d is used by %s and %s", r.ID, prev, r.Name)
		}
		if prev, dup := seenName[r.Name]; dup {
			t.Errorf("name %s is used by %d and %d", r.Name, prev, r.ID)
		}
		seenID[r.ID], seenName[r.Name] = r.Name, r.ID
		if !name.MatchString(r.Name) {
			t.Errorf("%d: name %q", r.ID, r.Name)
		}
		if r.Text == "" || strings.ContainsAny(r.Text, "%\n") {
			t.Errorf("%s: text %q", r.Name, r.Text)
		}
		if r.Status < 400 || r.Status > 599 {
			t.Errorf("%s: status %d", r.Name, r.Status)
		}
		switch r.Severity {
		case "critical", "high", "medium", "low":
		default:
			t.Errorf("%s: severity %q", r.Name, r.Severity)
		}
		if r.Default != Block && r.Default != Monitor {
			t.Errorf("%s: default %q", r.Name, r.Default)
		}
	}
	if len(registry) > maxRules {
		t.Fatalf("%d rules, the bit set holds %d", len(registry), maxRules)
	}
	for i, r := range registry {
		if r.idx != i {
			t.Fatalf("rule %s has index %d at position %d", r.name, r.idx, i)
		}
	}
}

func TestEveryDetailHasText(t *testing.T) {
	seen := map[string]detail{}
	for d := detail(1); d < dCount; d++ {
		s := detailText[d]
		if s == "" {
			t.Errorf("detail %d has no text", d)
		}
		if strings.ContainsAny(s, "%\n\"") {
			t.Errorf("detail %d: %q", d, s)
		}
		if prev, dup := seen[s]; dup {
			t.Errorf("details %d and %d have the same text %q", prev, d, s)
		}
		seen[s] = d
	}
}

// TestDocumentationMatchesRules reads the table in docs/formats.md and compares it with the rules: every rule is listed with the
// identifier, default action, status and severity the code has, and nothing is listed that does not exist.
func TestDocumentationMatchesRules(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docs", "formats.md"))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[int][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "| 5002") {
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		for i := range cells {
			cells[i] = strings.Trim(strings.TrimSpace(cells[i]), "`")
		}
		id, err := strconv.Atoi(cells[0])
		if err != nil || len(cells) < 6 {
			t.Errorf("a malformed table row: %q", line)
			continue
		}
		if _, dup := listed[id]; dup {
			t.Errorf("id %d is listed twice", id)
		}
		listed[id] = cells
	}
	for _, r := range Rules() {
		cells, ok := listed[r.ID]
		if !ok {
			t.Errorf("rule %d %s is not in docs/formats.md", r.ID, r.Name)
			continue
		}
		want := []string{strconv.Itoa(r.ID), r.Name, string(r.Default), strconv.Itoa(r.Status), r.Severity, r.Text}
		for i, w := range want {
			if cells[i] != w {
				t.Errorf("rule %d: column %d is %q in the document and %q in the code", r.ID, i, cells[i], w)
			}
		}
		delete(listed, r.ID)
	}
	for id := range listed {
		t.Errorf("docs/formats.md lists %d, which is not a rule", id)
	}
}

func TestPrintRuleTable(t *testing.T) {
	if os.Getenv("FORMATS_PRINT_RULES") == "" {
		t.Skip("set FORMATS_PRINT_RULES=1 to print the table for docs/formats.md")
	}
	var sb strings.Builder
	for _, r := range Rules() {
		sb.WriteString("| " + strconv.Itoa(r.ID) + " | `" + r.Name + "` | " + string(r.Default) + " | " + strconv.Itoa(r.Status) + " | " + r.Severity + " | " + r.Text + " |\n")
	}
	t.Log("\n" + sb.String())
}

// TestOneInspectorServesManyRequestsAtOnce runs every row of every table from many goroutines on one inspector and checks that each
// gets the answer it gets alone. Run with -race to check the memory as well.
func TestOneInspectorServesManyRequestsAtOnce(t *testing.T) {
	var all []row
	for _, rows := range tables {
		for _, r := range rows {
			if r.tweak == nil && len(r.body) < 20000 {
				all = append(all, r)
			}
		}
	}
	in := New(Policy{})
	want := make([][]int, len(all))
	for i, r := range all {
		want[i] = ids(in.Inspect(r.request()).Verdicts)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for round := 0; round < 3; round++ {
				for i := range all {
					j := (i + g*7) % len(all)
					got := ids(in.Inspect(all[j].request()).Verdicts)
					if !equalInts(got, want[j]) {
						select {
						case errs <- errors.New(all[j].name):
						default:
						}
						return
					}
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("a different answer under concurrency: %v", err)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestTheInspectorDoesNotChangeTheRequest checks the contract of inspect.Inspector: the request it was given is not modified.
func TestTheInspectorDoesNotChangeTheRequest(t *testing.T) {
	in := New(Policy{})
	for _, rows := range tables {
		for _, r := range rows {
			if len(r.body) > 20000 {
				continue
			}
			req := r.request()
			before := append([]byte(nil), req.Body...)
			hdr := req.Header.Clone()
			in2 := in
			if r.tweak != nil {
				in2 = New(r.policy(nil, false))
			}
			in2.Inspect(req)
			if string(before) != string(req.Body) || len(hdr) != len(req.Header) {
				t.Fatalf("%s: the request was changed", r.name)
			}
			for k := range hdr {
				if strings.Join(hdr[k], ",") != strings.Join(req.Header[k], ",") {
					t.Fatalf("%s: header %s was changed", r.name, k)
				}
			}
		}
	}
}

func FuzzContentType(f *testing.F) {
	for _, r := range typeRows {
		f.Add(r.ct)
	}
	f.Add(`multipart/form-data; boundary="a\"b"`)
	in := New(Policy{})
	f.Fuzz(func(t *testing.T, ct string) {
		if mt, p := parseMediaType(ct); p != nil && p.d >= dCount || p == nil && (mt.typ == "" || mt.sub == "") {
			t.Fatal("parseMediaType gave a result that is neither a type nor a problem")
		}
		fuzzNoPanic(t, in, row{hdrs: map[string][]string{"Content-Type": {ct}}, body: "a=1&b=2"})
		fuzzNoPanic(t, in, row{hdrs: map[string][]string{"Content-Type": {ct}}, body: "--b\r\n\r\n--b--\r\n"})
	})
}

// FuzzInspect throws everything at the dispatcher at once: any method, type, encoding, path, query and body.
func FuzzInspect(f *testing.F) {
	for _, tables := range tables {
		for _, r := range tables {
			if len(r.body) < 4096 {
				f.Add(r.method, r.path, r.query, r.ct, r.hdr["Content-Encoding"], r.body)
			}
		}
	}
	in := New(Policy{AllowedTypes: append(defaultAllowedTypes(), "application/yaml"), AllowOpaque: []string{"application/msgpack"}})
	f.Fuzz(func(t *testing.T, method, path, query, ct, encoding, body string) {
		if !validMethod(method) || strings.ContainsAny(ct+encoding, "\r\n\x00") {
			return
		}
		r := row{method: method, path: path, query: query, ct: ct, body: body}
		if encoding != "" {
			r.hdr = enc(encoding)
		}
		fuzzNoPanic(t, in, r)
		r.body = gz(body)
		r.hdr = enc("gzip")
		fuzzNoPanic(t, in, r)
	})
}

func validMethod(m string) bool { return m == "" || isToken(m) }

// TestWhatTheStandardLibraryWritesIsAccepted checks that the bodies Go's own encoders produce (the same ones a great many clients
// produce) pass with the default policy: the strictness is aimed at hand-made bodies, not at ordinary writers.
func TestWhatTheStandardLibraryWritesIsAccepted(t *testing.T) {
	in := New(Policy{})
	t.Run("multipart writer", func(t *testing.T) {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		w.WriteField("title", "A \"quoted\" title with é and 日本語")
		w.WriteField("tags[]", "a")
		w.WriteField("tags[]", "b")
		fw, _ := w.CreateFormFile("upload", `my "photo" é.jpg`)
		fw.Write(bytes.Repeat([]byte("\x00\xff\r\n--binary\r\n"), 500))
		fw2, _ := w.CreateFormFile("empty", "empty.txt")
		fw2.Write(nil)
		w.Close()
		res := in.Inspect(row{ct: w.FormDataContentType(), body: b.String()}.request())
		if len(res.Verdicts) != 0 {
			t.Fatalf("%s", messages(res))
		}
	})
	t.Run("url values", func(t *testing.T) {
		v := url.Values{"a": {"1", "2"}, "q": {"hello world & more; é\r\nline2"}, "x[y][z]": {"1"}, "empty": {""}}
		res := in.Inspect(row{ct: form, body: v.Encode()}.request())
		// The repeated name is recorded, nothing refuses.
		for _, vd := range res.Verdicts {
			if vd.Block {
				t.Fatalf("%s", messages(res))
			}
		}
	})
	t.Run("json", func(t *testing.T) {
		b, _ := json.Marshal(map[string]any{"name": "é\u2028<>&\x01", "n": []int{1, 2, 3}, "nested": map[string]any{"a": nil, "b": 1.5e30}})
		if res := in.Inspect(row{ct: appJSON, body: string(b)}.request()); len(res.Verdicts) != 0 {
			t.Fatalf("%s: %s", b, messages(res))
		}
	})
	t.Run("xml", func(t *testing.T) {
		type item struct {
			XMLName xml.Name `xml:"item"`
			ID      int      `xml:"id,attr"`
			Name    string   `xml:"name"`
			Note    string   `xml:",comment"`
		}
		b, _ := xml.MarshalIndent(item{ID: 7, Name: "Fish & <Chips>", Note: " a note "}, "", "  ")
		if res := in.Inspect(row{ct: "application/xml", body: xml.Header + string(b)}.request()); len(res.Verdicts) != 0 {
			t.Fatalf("%s: %s", b, messages(res))
		}
	})
	t.Run("gzip writer", func(t *testing.T) {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		zw.Write([]byte(`{"a":1}`))
		zw.Close()
		if res := in.Inspect(row{ct: appJSON, hdr: enc("gzip"), body: b.String()}.request()); len(res.Verdicts) != 0 || string(res.Body) != `{"a":1}` {
			t.Fatalf("%s", messages(res))
		}
	})
}
