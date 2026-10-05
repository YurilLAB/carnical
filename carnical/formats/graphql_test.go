// SPDX-License-Identifier: Apache-2.0

package formats

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	idGQLSyntax         = 5002300
	idGQLDepth          = 5002301
	idGQLFields         = 5002302
	idGQLAliases        = 5002303
	idGQLDirs           = 5002304
	idGQLBatch          = 5002305
	idGQLIntro          = 5002306
	idGQLFrag           = 5002307
	idGQLShape          = 5002308
	idGQLLimit          = 5002309
	idGQLGetMutation    = 5002310
	idGQLRequestFields  = 5002311
	idGQLRequestAliases = 5002312
	idGQLRequestDirs    = 5002313
	appJSON             = "application/json"
)

// jq returns query as a JSON string.
func jq(query string) string {
	b, _ := json.Marshal(query)
	return string(b)
}

func gqlReq(query string) string { return `{"query":` + jq(query) + `}` }

// deepQuery is a query nested n fields deep.
func deepQuery(n int) string {
	return strings.Repeat("{ a ", n) + strings.Repeat("}", n)
}

func fieldsQuery(n int) string { return "{ " + strings.Repeat("f ", n) + "}" }

func aliasesQuery(n int) string {
	var sb strings.Builder
	sb.WriteString("{ ")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "a%d: login(user: \"x\", pass: \"y%d\") ", i, i)
	}
	sb.WriteString("}")
	return sb.String()
}

func batch(n int, query string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = gqlReq(query)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// amplified is n fragments, each spreading the one before it ten times: a document of a few hundred bytes that selects 10^n fields.
func amplified(n int) string {
	var sb strings.Builder
	sb.WriteString("query { ...F" + fmt.Sprint(n) + " }\nfragment F0 on T { a b c d e f g h i j }\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&sb, "fragment F%d on T { %s }\n", i, strings.Repeat(fmt.Sprintf("...F%d ", i-1), 10))
	}
	return sb.String()
}

// doubling spreads the previous fragment twice at every level: 2^n fields from a document that is a few lines long.
func doubling(n int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "{ ...F%d }\nfragment F0 on T { a }\n", n)
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&sb, "fragment F%d on T { ...F%d ...F%d }\n", i, i-1, i-1)
	}
	return sb.String()
}

// deepFragments is a chain of fragments, each nesting the next one field deeper: n levels from small pieces.
func deepFragments(n int) string {
	var sb strings.Builder
	sb.WriteString("{ ...F1 }\n")
	for i := 1; i < n; i++ {
		fmt.Fprintf(&sb, "fragment F%d on T { a { ...F%d } }\n", i, i+1)
	}
	fmt.Fprintf(&sb, "fragment F%d on T { a }\n", n)
	return sb.String()
}

func aliasFragments() string {
	var sb strings.Builder
	sb.WriteString("{ ...F ...F }\nfragment F on T { ")
	for i := 0; i < 15; i++ {
		fmt.Fprintf(&sb, "a%d: x ", i)
	}
	sb.WriteString("}")
	return sb.String()
}

var graphqlRows = register("graphql", []row{
	// Accepted.
	{name: "simple query", path: "/graphql", ct: appJSON, body: gqlReq(`{ user { id name } }`)},
	{name: "named query with variables", path: "/graphql", ct: appJSON,
		body: `{"query":` + jq(`query Q($id: ID!, $n: Int = 5, $l: [String!]! = ["a"]) { user(id: $id) { friends(first: $n) { name } } }`) + `,"variables":{"id":"1"},"operationName":"Q"}`},
	{name: "mutation", path: "/graphql", ct: appJSON, body: gqlReq(`mutation { addUser(input: {name: "x", tags: ["a","b"], n: 3.5e2, ok: true, none: null, kind: ADMIN}) { id } }`)},
	{name: "fragments", path: "/graphql", ct: appJSON, body: gqlReq("query { ...F }\nfragment F on Query { a b }")},
	{name: "inline fragment", path: "/graphql", ct: appJSON, body: gqlReq(`{ a { ... on B { c } ... @include(if: true) { d } } }`)},
	{name: "directives", path: "/graphql", ct: appJSON, body: gqlReq(`query ($x: Boolean) @live { a @include(if: $x) b @skip(if: false) }`)},
	{name: "typename", path: "/graphql", ct: appJSON, body: gqlReq(`{ a { __typename } }`)},
	{name: "a field aliased to the name of the schema field", path: "/graphql", ct: appJSON, body: gqlReq(`{ __schema: foo }`)},
	{name: "comments, commas and block strings", path: "/graphql", ct: appJSON, body: gqlReq("# hi\n{ a(x: \"\"\"block \\\"\"\" text\"\"\", y: 1,, z: 2) } # end")},
	{name: "a batch of three", path: "/graphql", ct: appJSON, body: batch(3, `{ a }`)},
	{name: "a batch of ten", path: "/graphql", ct: appJSON, body: batch(10, `{ a }`)},
	{name: "twenty aliases", path: "/graphql", ct: appJSON, body: gqlReq(aliasesQuery(20))},
	{name: "depth twelve", path: "/graphql", ct: appJSON, body: gqlReq(deepQuery(12))},
	{name: "five hundred fields", path: "/graphql", ct: appJSON, body: gqlReq(fieldsQuery(500))},
	{name: "persisted query", path: "/graphql", ct: appJSON, body: `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}`},
	{name: "variables and extensions null", path: "/graphql", ct: appJSON, body: `{"query":"{a}","variables":null,"operationName":null,"extensions":null}`},
	{name: "application/graphql body", path: "/graphql", ct: "application/graphql", body: `{ user { id } }`},
	{name: "get with a query", method: "GET", path: "/graphql", query: "query=%7B+user+%7B+id+%7D+%7D"},
	{name: "get with variables", method: "GET", path: "/api/graphql", query: "query=query+Q%28%24i%3AID%29%7Bu%28i%3A%24i%29%7Bid%7D%7D&variables=%7B%22i%22%3A%221%22%7D&operationName=Q"},
	{name: "form on the graphql path", path: "/graphql", ct: form, body: "query=%7Ba%7D&variables=%7B%7D"},
	{name: "a search form with a query field", method: "GET", path: "/search", query: "query=shoes&page=2"},
	{name: "a search api that takes a sql-like query", path: "/api/search", ct: appJSON, body: `{"query":"select * from users where id = 1"}`},
	{name: "an elasticsearch style query object", path: "/es/_search", ct: appJSON, body: `{"query":{"match":{"title":"x"}}}`},
	{name: "a get with a query that is only a word", method: "GET", path: "/search", query: "query=query"},
	{name: "a graphql looking query on another path is checked and passes", path: "/api/gql", ct: appJSON, body: gqlReq(`{ a { b } }`)},

	// Limits.
	{name: "request total field boundary", path: "/graphql", ct: appJSON, body: batch(2, fieldsQuery(500))},
	{name: "batch multiplies field work", path: "/graphql", ct: appJSON, body: batch(3, fieldsQuery(334)), want: idGQLRequestFields},
	{name: "request total alias boundary", path: "/graphql", ct: appJSON, body: batch(2, aliasesQuery(20))},
	{name: "batch multiplies alias work", path: "/graphql", ct: appJSON, body: batch(3, aliasesQuery(14)), want: idGQLRequestAliases},
	{name: "request total directive boundary", path: "/graphql", ct: appJSON, body: batch(2, "{ a "+strings.Repeat("@skip(if: false) ", 50)+"}")},
	{name: "batch multiplies directive work", path: "/graphql", ct: appJSON, body: batch(3, "{ a "+strings.Repeat("@skip(if: false) ", 34)+"}"), want: idGQLRequestDirs},
	{name: "total fields after fragment expansion", path: "/graphql", ct: appJSON, body: batch(3, `{ ...F ...F } fragment F on T { a b }`), want: idGQLRequestFields,
		tweak: func(p *Policy) { p.GraphQL.MaxRequestFields = 10 }},
	{name: "only selected operations count towards total", path: "/graphql", ct: appJSON,
		body:  `[{"query":"query Heavy { a b c } fragment F on T { x } query Light { ...F }","operationName":"Light"},{"query":"query Light { a } query Heavy { b c d }","operationName":"Light"}]`,
		tweak: func(p *Policy) { p.GraphQL.MaxRequestFields = 2 }},
	{name: "selected operation after an interleaved fragment", path: "/graphql", ct: appJSON,
		body: `[{"query":"query Light { a } fragment F on T { b c } query Heavy { ...F }","operationName":"Heavy"},{"query":"{a b}"}]`, want: idGQLRequestFields,
		tweak: func(p *Policy) { p.GraphQL.MaxRequestFields = 3 }},
	{name: "total limit raised for legitimate batches", path: "/graphql", ct: appJSON, body: batch(3, fieldsQuery(334)),
		tweak: func(p *Policy) { p.GraphQL.MaxRequestFields = 1002 }},
	{name: "total cost on an automatically identified endpoint", path: "/api/gql", ct: appJSON, body: batch(3, aliasesQuery(14)), want: idGQLRequestAliases},
	{name: "depth thirteen", path: "/graphql", ct: appJSON, body: gqlReq(deepQuery(13)), want: idGQLDepth},
	{name: "depth in a hundred", path: "/graphql", ct: appJSON, body: gqlReq(deepQuery(100)), want: idGQLDepth},
	{name: "depth in a thousand", path: "/graphql", ct: appJSON, body: gqlReq(deepQuery(1000)), want: idGQLDepth},
	{name: "depth through inline fragments", path: "/graphql", ct: appJSON, body: gqlReq(strings.Repeat("{ ... on T ", 150) + "{ a }" + strings.Repeat("}", 150)), want: idGQLDepth},
	{name: "depth through fragments", path: "/graphql", ct: appJSON, body: gqlReq(deepFragments(14)), want: idGQLDepth},
	{name: "five hundred and one fields", path: "/graphql", ct: appJSON, body: gqlReq(fieldsQuery(501)), want: idGQLFields},
	{name: "fields multiplied by fragments", path: "/graphql", ct: appJSON, body: gqlReq(amplified(5)), want: idGQLFields},
	{name: "fragments that double at every level", path: "/graphql", ct: appJSON, body: gqlReq(doubling(60)), want: idGQLFields},
	{name: "alias flood", path: "/graphql", ct: appJSON, body: gqlReq(aliasesQuery(50)), want: idGQLAliases},
	{name: "twenty one aliases", path: "/graphql", ct: appJSON, body: gqlReq(aliasesQuery(21)), want: idGQLAliases},
	{name: "aliases multiplied by fragments", path: "/graphql", ct: appJSON, body: gqlReq(aliasFragments()), want: idGQLAliases},
	{name: "directive overload", path: "/graphql", ct: appJSON, body: gqlReq("{ a " + strings.Repeat("@skip(if: false) ", 51) + "}"), want: idGQLDirs},
	{name: "a batch of fifty", path: "/graphql", ct: appJSON, body: batch(50, `{ a }`), want: idGQLBatch},
	{name: "a batch of eleven", path: "/graphql", ct: appJSON, body: batch(11, `{ a }`), want: idGQLBatch},
	{name: "a batch on another path", path: "/api/x", ct: appJSON, body: batch(50, `{ a { b } }`), want: idGQLBatch},
	{name: "too many operations", path: "/graphql", ct: appJSON, body: gqlReq("query A { a } query B { b } query C { c }"), want: idGQLLimit,
		tweak: func(p *Policy) { p.GraphQL.MaxOperations = 2 }},
	{name: "query too large", path: "/graphql", ct: appJSON, body: gqlReq(fieldsQuery(50)), want: idGQLLimit,
		tweak: func(p *Policy) { p.GraphQL.MaxQueryBytes = 50 }},
	{name: "a limit raised by the policy", path: "/graphql", ct: appJSON, body: gqlReq(deepQuery(20)),
		tweak: func(p *Policy) { p.GraphQL.MaxDepth = 20 }},
	{name: "a thousand and one fragments", path: "/graphql", ct: appJSON, body: gqlReq("{ a }" + strings.Repeat("\nfragment F on T { a }", 1001)), want: idGQLLimit},
	{name: "a thousand open lists in a value", path: "/graphql", ct: appJSON, body: gqlReq("{ a(x: " + strings.Repeat("[", 1000) + strings.Repeat("]", 1000) + ") }"), want: idGQLLimit},

	// Introspection.
	{name: "schema introspection", path: "/graphql", ct: appJSON, body: gqlReq(`{ __schema { types { name } } }`), want: idGQLIntro},
	{name: "type introspection", path: "/graphql", ct: appJSON, body: gqlReq(`{ __type(name: "User") { fields { name } } }`), want: idGQLIntro},
	{name: "introspection under an alias", path: "/graphql", ct: appJSON, body: gqlReq(`{ s: __schema { queryType { name } } }`), want: idGQLIntro},
	{name: "introspection in a fragment", path: "/graphql", ct: appJSON, body: gqlReq("{ ...I }\nfragment I on Query { __schema { types { name } } }"), want: idGQLIntro},
	{name: "introspection when the policy allows it", path: "/graphql", ct: appJSON, body: gqlReq(`{ __schema { types { name } } }`),
		tweak: func(p *Policy) { p.GraphQL.AllowIntrospection = true }},
	{name: "introspection by get", method: "GET", path: "/graphql", query: "query=%7B__schema%7Btypes%7Bname%7D%7D%7D", want: idGQLIntro},
	{name: "introspection by get on another path", method: "GET", path: "/api/x", query: "query=%7B__schema%7Btypes%7Bname%7D%7D%7D", want: idGQLIntro},
	{name: "introspection by form", path: "/graphql", ct: form, body: "query=%7B__schema%7Btypes%7Bname%7D%7D%7D", want: idGQLIntro},
	{name: "introspection by application/graphql", path: "/graphql", ct: "application/graphql", body: `{ __schema { types { name } } }`, want: idGQLIntro},

	// Fragments.
	{name: "a fragment that spreads itself", path: "/graphql", ct: appJSON, body: gqlReq("{ ...A }\nfragment A on T { ...A }"), want: idGQLFrag},
	{name: "two fragments that spread each other", path: "/graphql", ct: appJSON, body: gqlReq("{ ...A }\nfragment A on T { a ...B }\nfragment B on T { b ...A }"), want: idGQLFrag},
	{name: "a cycle three deep with an inline fragment", path: "/graphql", ct: appJSON, body: gqlReq("{ ...A }\nfragment A on T { ...B }\nfragment B on T { ... on U { ...C } }\nfragment C on T { ...A }"), want: idGQLFrag},
	{name: "a cycle that no operation reaches", path: "/graphql", ct: appJSON, body: gqlReq("{ a }\nfragment A on T { ...B }\nfragment B on T { ...A }"), want: idGQLFrag},
	{name: "a fragment that is not defined", path: "/graphql", ct: appJSON, body: gqlReq("{ ...Missing }"), want: idGQLFrag},
	{name: "a fragment defined twice", path: "/graphql", ct: appJSON, body: gqlReq("{ ...A }\nfragment A on T { a }\nfragment A on T { b }"), want: idGQLFrag},

	// Syntax.
	{name: "unclosed brace", path: "/graphql", ct: appJSON, body: gqlReq(`{ a { b }`), want: idGQLSyntax},
	{name: "operation with no selection", path: "/graphql", ct: appJSON, body: gqlReq(`query`), want: idGQLSyntax},
	{name: "empty selection", path: "/graphql", ct: appJSON, body: gqlReq(`{ a { } }`), want: idGQLSyntax},
	{name: "empty query string", path: "/graphql", ct: appJSON, body: gqlReq(``), want: idGQLSyntax},
	{name: "unexpected character", path: "/graphql", ct: appJSON, body: gqlReq(`{ a ? }`), want: idGQLSyntax},
	{name: "number running into a name", path: "/graphql", ct: appJSON, body: gqlReq(`{ a(x: 1a) }`), want: idGQLSyntax},
	{name: "number with a leading zero", path: "/graphql", ct: appJSON, body: gqlReq(`{ a(x: 01) }`), want: idGQLSyntax},
	{name: "unterminated string", path: "/graphql", ct: appJSON, body: gqlReq(`{ a(x: "abc) }`), want: idGQLSyntax},
	{name: "bad escape in a string", path: "/graphql", ct: appJSON, body: gqlReq(`{ a(x: "\q") }`), want: idGQLSyntax},
	{name: "lone point", path: "/graphql", ct: appJSON, body: gqlReq(`{ a . b }`), want: idGQLSyntax},
	{name: "a type definition", path: "/graphql", ct: appJSON, body: gqlReq(`type Query { a: Int }`), want: idGQLSyntax},
	{name: "a schema extension", path: "/graphql", ct: appJSON, body: gqlReq(`extend schema { query: Q }`), want: idGQLSyntax},
	{name: "an equals sign where a colon belongs in a variable", path: "/graphql", ct: appJSON, body: gqlReq(`query ($a = Int) { a }`), want: idGQLSyntax},
	{name: "an equals sign where a colon belongs in an argument", path: "/graphql", ct: appJSON, body: gqlReq(`{ a(x = 1) }`), want: idGQLSyntax},
	{name: "a number as a field name", path: "/graphql", ct: appJSON, body: gqlReq(`{ 1 }`), want: idGQLSyntax},
	{name: "a number where the selection set belongs", path: "/graphql", ct: appJSON, body: gqlReq(`query Q 1 a }`), want: idGQLSyntax},
	{name: "a fragment type condition that does not say on", path: "/graphql", ct: appJSON, body: gqlReq("{ ...F }\nfragment F in T { a }"), want: idGQLSyntax},
	{name: "variables as a string on a path that is not graphql and a query that is sql", path: "/api/search", ct: appJSON, body: `{"query":"select * from t","variables":"x"}`},
	{name: "a fragment with no on", path: "/graphql", ct: appJSON, body: gqlReq("{ ...F }\nfragment F T { a }"), want: idGQLSyntax},
	{name: "empty variable definitions", path: "/graphql", ct: appJSON, body: gqlReq(`query () { a }`), want: idGQLSyntax},
	{name: "empty arguments", path: "/graphql", ct: appJSON, body: gqlReq(`{ a() }`), want: idGQLSyntax},
	{name: "a list type nested too deeply", path: "/graphql", ct: appJSON, body: gqlReq("query ($a: " + strings.Repeat("[", 40) + "Int" + strings.Repeat("]", 40) + ") { a }"), want: idGQLLimit},
	{name: "a fragment named on", path: "/graphql", ct: appJSON, body: gqlReq(`{ a } fragment on on T { a }`), want: idGQLSyntax},
	{name: "variable with no type", path: "/graphql", ct: appJSON, body: gqlReq(`query ($a) { a }`), want: idGQLSyntax},
	{name: "application/graphql with a syntax error", path: "/graphql", ct: "application/graphql", body: `{ a { b }`, want: idGQLSyntax},
	{name: "application/graphql too deep", path: "/graphql", ct: "application/graphql", body: deepQuery(30), want: idGQLDepth},
	{name: "application/graphql with a byte order mark", path: "/graphql", ct: "application/graphql", body: "\xef\xbb\xbf{ a }", want: idBOM},
	{name: "application/graphql in utf-16", path: "/graphql", ct: "application/graphql", body: utf16le(`{ a }`), want: idWide},
	{name: "application/graphql with a NUL", path: "/graphql", ct: "application/graphql", body: "{ a\x00 }", want: idControl},
	{name: "application/graphql with invalid utf-8", path: "/graphql", ct: "application/graphql", body: "{ a(x: \"\xff\") }", want: idBadUTF8},
	{name: "a control character in the query", path: "/graphql", ct: appJSON, body: `{"query":"{ a` + u("0001") + ` }"}`, want: idControl},

	// The request envelope.
	{name: "get mutation in an explicitly permitted body", method: "GET", path: "/graphql", ct: appJSON, body: gqlReq(`mutation { deleteUser }`), want: idGQLGetMutation,
		tweak: func(p *Policy) { p.Rules["body-on-get"] = Off }},
	{name: "get mutation", method: "GET", path: "/graphql", query: "query=mutation%7BdeleteUser%7Bid%7D%7D", want: idGQLGetMutation},
	{name: "get selected mutation after a query", method: "GET", path: "/graphql", query: "query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Write", want: idGQLGetMutation},
	{name: "get selected query beside a mutation", method: "GET", path: "/graphql", query: "query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read"},
	{name: "mutation word in a get argument", method: "GET", path: "/graphql", query: "query=%7Ba%28name%3A%22mutation%22%29%7D"},
	{name: "get mutation on a discovered endpoint", method: "GET", path: "/api/gql", query: "query=mutation%7BdeleteUser%7D", want: idGQLGetMutation},
	{name: "post selected mutation", path: "/graphql", ct: appJSON, body: `{"query":"query Read { a } mutation Write { b }","operationName":"Write"}`},
	{name: "operation name preceding query", path: "/graphql", ct: appJSON, body: `{"operationName":"Read","query":"query Read { a } mutation Write { b }"}`},
	{name: "empty name for one named query", path: "/graphql", ct: appJSON, body: `{"query":"query Q { a }","operationName":""}`},
	{name: "multiple operations without a name", path: "/graphql", ct: appJSON, body: gqlReq(`query A { a } query B { b }`), want: idGQLShape},
	{name: "unknown operation name", path: "/graphql", ct: appJSON, body: `{"query":"query Q { a }","operationName":"Other"}`, want: idGQLShape},
	{name: "duplicate operation names", path: "/graphql", ct: appJSON, body: `{"query":"query Q { a } mutation Q { b }","operationName":"Q"}`, want: idGQLShape},
	{name: "anonymous operation beside named operation", path: "/graphql", ct: appJSON, body: `{"query":"{ a } query Q { b }","operationName":"Q"}`, want: idGQLShape},
	{name: "fragments without an operation", path: "/graphql", ct: appJSON, body: gqlReq(`fragment F on T { a }`), want: idGQLShape},
	{name: "variables parameter repeated", method: "GET", path: "/graphql", query: "query=%7Ba%7D&variables=%7B%7D&variables=null", want: idGQLShape},
	{name: "operation name parameter repeated", method: "GET", path: "/graphql", query: "query=query+Q%7Ba%7D&operationName=Q&operationName=Q", want: idGQLShape},
	{name: "extensions repeated with an escaped name", method: "GET", path: "/graphql", query: "query=%7Ba%7D&extensions=%7B%7D&%65xtensions=%7B%7D", want: idGQLShape},
	{name: "extensions by get are not an object", method: "GET", path: "/graphql", query: "query=%7Ba%7D&extensions=%5B1%5D", want: idGQLShape},
	{name: "persisted query extensions checked without a query", method: "GET", path: "/graphql", query: "extensions=1", want: idGQLShape},
	{name: "get extensions object", method: "GET", path: "/graphql", query: "query=%7Ba%7D&extensions=%7B%22trace%22%3Atrue%7D"},
	{name: "empty optional get parameters", method: "GET", path: "/graphql", query: "query=query+Q%7Ba%7D&variables=&operationName=&extensions="},
	{name: "duplicate protocol field by form", path: "/graphql", ct: form, body: "query=%7Ba%7D&operationName=&operationName=Q", want: idGQLShape},
	{name: "selected operation by form", path: "/graphql", ct: form, body: "query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Write"},
	{name: "variables as a string", path: "/graphql", ct: appJSON, body: `{"query":"{a}","variables":"{\"x\":1}"}`, want: idGQLShape},
	{name: "variables as an array", path: "/graphql", ct: appJSON, body: `{"query":"{a}","variables":[1]}`, want: idGQLShape},
	{name: "operation name as a number", path: "/graphql", ct: appJSON, body: `{"query":"{a}","operationName":7}`, want: idGQLShape},
	{name: "extensions as a string", path: "/graphql", ct: appJSON, body: `{"query":"{a}","extensions":"x"}`, want: idGQLShape},
	{name: "query as a number", path: "/graphql", ct: appJSON, body: `{"query":7}`, want: idGQLShape},
	{name: "query as an object", path: "/graphql", ct: appJSON, body: `{"query":{"a":1}}`, want: idGQLShape},
	{name: "a batch element that is not an object", path: "/graphql", ct: appJSON, body: `[{"query":"{a}"},1]`, want: idGQLShape},
	{name: "a scalar where a request belongs", path: "/graphql", ct: appJSON, body: `"{ a }"`, want: idGQLShape},
	{name: "the query given twice", path: "/graphql", ct: appJSON, body: `{"query":"{a}","query":"{b}"}`, want: idJSONDup},
	{name: "the query given twice in different case", path: "/graphql", ct: appJSON, body: `{"query":"{a}","Query":"{__schema{types{name}}}"}`, want: idJSONDup},
	{name: "the query given twice by get", method: "GET", path: "/graphql", query: "query=%7Ba%7D&query=%7Bb%7D", want: idGQLShape},
	{name: "a bad escape in the query by get", method: "GET", path: "/graphql", query: "query=%7Ba%zz%7D", want: idFormEscape},
	{name: "variables by get that are not json", method: "GET", path: "/graphql", query: "query=%7Ba%7D&variables=%7B", want: idJSONSyntax},
	{name: "variables by get that are an array", method: "GET", path: "/graphql", query: "query=%7Ba%7D&variables=%5B1%5D", want: idGQLShape},
	{name: "variables by get with a duplicate key", method: "GET", path: "/graphql", query: "query=%7Ba%7D&variables=%7B%22x%22%3A1%2C%22x%22%3A2%7D", want: idJSONDup},
	{name: "get with a depth over the limit", method: "GET", path: "/graphql", query: "query=" + strings.ReplaceAll(strings.ReplaceAll(deepQuery(13), "{", "%7B"), "}", "%7D"), want: idGQLDepth},
	{name: "a deep query found on a path that is not graphql", path: "/api/x", ct: appJSON, body: gqlReq(deepQuery(13)), want: idGQLDepth},
	{name: "a deep query found by get on a path that is not graphql", method: "GET", path: "/api/x", query: "query=" + strings.ReplaceAll(strings.ReplaceAll(deepQuery(13), "{", "%7B"), "}", "%7D"), want: idGQLDepth},
	{name: "a graphql path listed by the policy", path: "/internal/q", ct: appJSON, body: `{"query":"{ a"}`, want: idGQLSyntax,
		tweak: func(p *Policy) { p.GraphQLPaths = []string{"/internal/q"} }},
	{name: "a syntax error on a path that is not graphql", path: "/internal/q", ct: appJSON, body: `{"query":"{ a"}`},
	{name: "a batch of fifty on a path that is listed", path: "/internal/q", ct: appJSON, body: batch(50, `{ a }`), want: idGQLBatch,
		tweak: func(p *Policy) { p.GraphQLPaths = []string{"/internal/q"} }},
})

func TestGraphQL(t *testing.T) { runTable(t, graphqlRows) }

// TestGraphQLFragmentsAreCountedByArithmetic checks the cost of a document that would expand to more fields than there are atoms:
// it must be refused at once and not by building it.
func TestGraphQLFragmentsAreCountedByArithmetic(t *testing.T) {
	for _, n := range []int{20, 60, 90} {
		r := row{path: "/graphql", ct: appJSON, body: gqlReq(doubling(n)), want: idGQLFields}
		start := time.Now()
		if err := r.check(New(Policy{})); err != nil {
			t.Fatalf("doubling %d: %v", n, err)
		}
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Fatalf("doubling %d took %v", n, d)
		}
	}
}

// TestGraphQLMessagesNameTheLimit checks that a verdict says which limit it is and what the limit is.
func TestGraphQLMessagesNameTheLimit(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
	}{
		{gqlReq(deepQuery(13)), "graphql-depth"}, {gqlReq(fieldsQuery(501)), "limit 500"}, {gqlReq(aliasesQuery(30)), "limit 20"},
		{batch(30, `{a}`), "limit 10"}, {gqlReq(`{ __schema { types { name } } }`), "graphql-introspection"},
	} {
		in := New(Policy{})
		res := in.Inspect(row{path: "/graphql", ct: appJSON, body: tc.body}.request())
		if len(res.Verdicts) == 0 || !strings.Contains(res.Verdicts[0].Message, tc.want) {
			t.Errorf("want %q in %v", tc.want, res.Verdicts)
		}
	}
}

func FuzzGraphQL(f *testing.F) {
	for _, r := range graphqlRows {
		f.Add(r.body, r.query)
	}
	f.Add("{ a { b } }", "")
	f.Add("query ($a: [Int!]! = [1]) @x { ...F } fragment F on T { a(x: {y: \"z\"}) }", "")
	in := New(Policy{})
	f.Fuzz(func(t *testing.T, body, query string) {
		fuzzNoPanic(t, in, row{path: "/graphql", ct: appJSON, body: body})
		fuzzNoPanic(t, in, row{path: "/graphql", ct: "application/graphql", body: body})
		fuzzNoPanic(t, in, row{path: "/graphql", ct: appJSON, body: gqlReq(body)})
		fuzzNoPanic(t, in, row{method: "GET", path: "/graphql", query: query})
		fuzzNoPanic(t, in, row{method: "GET", path: "/x", query: "query=" + query})
	})
}

func BenchmarkGraphQL(b *testing.B) {
	var sb strings.Builder
	for i := 0; sb.Len() < 30<<10; i++ {
		fmt.Fprintf(&sb, "query Q%d($id: ID!, $n: Int = 5) { user(id: $id) { id name email friends(first: $n) { id name ...F%d } } }\nfragment F%d on User { id bio }\n", i, i, i)
	}
	benchRow(b, row{path: "/graphql", ct: appJSON, body: `{"query":` + jq(sb.String()) + `,"operationName":"Q0"}`, tweak: func(p *Policy) { p.GraphQL.MaxOperations = 10000 }})
}
