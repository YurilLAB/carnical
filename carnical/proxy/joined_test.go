// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// rulesRead is how many arguments the rule set reads from one place (SecArgumentsLimit in crs/base/coraza.conf). It is
// written out here so that these tests do not follow the join's own limit wherever it goes.
const rulesRead = 1000

func TestRepeatedParametersAreJoinedAsAnApplicationWould(t *testing.T) {
	mp := func(pairs ...string) []joinParam {
		var out []joinParam
		for i := 0; i+1 < len(pairs); i += 2 {
			out = append(out, joinParam{name: pairs[i], value: pairs[i+1]})
		}
		return out
	}
	// As many parameters as the rule set reads from one place, each with a name of its own.
	full := func(prefix string) string {
		many := make([]string, rulesRead)
		for i := range many {
			many[i] = fmt.Sprintf("%s%d=%d", prefix, i, i)
		}
		return strings.Join(many, "&")
	}
	pairs := func(n int) (string, []joinedArg) {
		var q []string
		var want []joinedArg
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("p%d", i)
			q = append(q, name+"=a", name+"=b")
			want = append(want, joinedArg{name, "a,b"})
		}
		return strings.Join(q, "&"), want
	}
	halfQuery, halfWant := pairs(rulesRead / 2)
	for _, tt := range []struct {
		name, query, form string
		fields            []joinParam
		cookies           []string
		want              []joinedArg
	}{
		{name: "nothing"},
		{name: "one parameter", query: "a=1"},
		{name: "different names", query: "a=1&b=2", form: "c=3", cookies: []string{"d=4; e=5"}},
		{name: "a name twice in the query", query: "q=UNION&q=SELECT+password+FROM+users", want: []joinedArg{{"q", "UNION,SELECT password FROM users"}}},
		{name: "a name twice in a form", form: "q=1%27%2F*&x=2&q=*%2FOR+1%3D1", want: []joinedArg{{"q", "1'/*,*/OR 1=1"}}},
		{name: "three values keep their order", query: "a=1&a=2&b=x&a=3", want: []joinedArg{{"a", "1,2,3"}}},
		{name: "the query before the form", query: "a=1", form: "a=2&a=3", want: []joinedArg{{"a", "1,2,3"}}},
		{name: "two names, each repeated", query: "a=1&b=x&a=2&b=y", want: []joinedArg{{"a", "1,2"}, {"b", "x,y"}}},
		{name: "names differing in case", query: "Role=user&role=admin", want: []joinedArg{{"Role", "user,admin"}}},
		{name: "names differing in the case of another alphabet", query: "%C3%89t%C3%A9=1&%C3%A9t%C3%A9=2", want: []joinedArg{{"Été", "1,2"}}},
		{name: "a name escaped the second time", query: "role=user&%72ole=admin", want: []joinedArg{{"role", "user,admin"}}},
		{name: "a name with a space spelt two ways", query: "a+b=1&a%20b=2", want: []joinedArg{{"a b", "1,2"}}},
		{name: "a name without a value", query: "flag&flag=1", want: []joinedArg{{"flag", ",1"}}},
		{name: "an escape that is not one", query: "a=%zz&a=%4", want: []joinedArg{{"a", "%zz,%4"}}},
		{name: "the items of a list", query: "ids[]=1)+UNION&ids%5B%5D=SELECT+1", want: []joinedArg{{"ids[]", "1) UNION,SELECT 1"}}},
		{name: "numbered items of a list", query: "ids[0]=a&ids[1]=b&IDS[22]=c", want: []joinedArg{{"ids[0]", "a,b,c"}}},
		{name: "a name with and without list brackets", query: "ids=a&ids[]=b", want: []joinedArg{{"ids", "a,b"}}},
		{name: "the items of a nested list", query: "f[tags][]=a&f[tags][]=b", want: []joinedArg{{"f[tags][]", "a,b"}}},
		{name: "the members of a record are not a list", query: "user[name]=a&user[mail]=b&x[1][a]=c&x[2][a]=d"},
		{name: "brackets that name nothing", query: "[]=a&[1]=b&a]=c&a[=d"},
		{name: "empty pairs and names", query: "&&=1&=2&a=1&"},
		{name: "multipart fields", fields: mp("q", "UNION", "file", "x", "q", "SELECT 1"), want: []joinedArg{{"q", "UNION,SELECT 1"}}},
		{name: "a field and the query", query: "q=UNION", fields: mp("Q", "SELECT 1"), want: []joinedArg{{"q", "UNION,SELECT 1"}}},
		{name: "list fields", fields: mp("a[]", "1", "a[]", "2"), want: []joinedArg{{"a[]", "1,2"}}},
		{name: "fields without a name", fields: mp("", "1", "", "2")},
		{name: "a cookie and a parameter", query: "q=UNION", cookies: []string{"sid=abc; q=SELECT 1"}, want: []joinedArg{{"q", "UNION,SELECT 1"}}},
		{name: "the query, the form, then the cookie", query: "q=1", form: "q=2", cookies: []string{"Q=3"}, want: []joinedArg{{"q", "1,2,3"}}},
		{name: "a cookie given twice", cookies: []string{"q=a;q=b"}},
		{name: "a cookie in two headers", cookies: []string{"q=a", "x=1; q=b"}},
		{name: "a cookie given twice beside other parameters", query: "a=1&b=2", form: "c=3", cookies: []string{"sid=x; sid=y"}},
		{name: "a parameter and a cookie given twice", query: "q=1", cookies: []string{"q=a", "x=1; q=b"}, want: []joinedArg{{"q", "1,a,b"}}},
		{name: "a field and a cookie", fields: mp("q", "UNION"), cookies: []string{"Q=SELECT 1"}, want: []joinedArg{{"q", "UNION,SELECT 1"}}},
		{name: "a cookie value is not decoded", query: "q=1", cookies: []string{"q=a+b%20c"}, want: []joinedArg{{"q", "1,a+b%20c"}}},
		{name: "cookies without a name", cookies: []string{"=a; =b; c; c;;"}},
		{name: "a query as full as the rule set reads", query: full("p") + "&p0=again", want: nil},
		{name: "a repeat at the end of a full query", query: strings.TrimPrefix(full("p"), "p0=0&") + "&p1=again", want: []joinedArg{{"p1", "1,again"}}},
		{name: "a repeat in the form after a full query", query: full("p"), form: "q=UNION&q=SELECT+1", want: []joinedArg{{"q", "UNION,SELECT 1"}}},
		{name: "a repeat in a cookie after a full query and form", query: full("p"), form: full("f"), cookies: []string{"f7=x"}, want: []joinedArg{{"f7", "7,x"}}},
		{name: "empty pairs do not use the query up", query: strings.Repeat("&", 5000) + "a=1&a=2", want: []joinedArg{{"a", "1,2"}}},
		{name: "pairs without a name do", query: strings.Repeat("=x&", rulesRead) + "a=1&a=2"},
		{name: "as many repeated names as the rule set takes", query: halfQuery, want: halfWant},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var form []byte
			if tt.form != "" {
				form = []byte(tt.form)
			}
			got := joinRepeated(tt.query, form, tt.fields, tt.cookies)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("joined %.300q, want %.300q", got, tt.want)
			}
		})
	}
}

// Few parameters are compared pair by pair and many through a table; both must find the same repeats.
func TestBothWaysOfFindingRepeatsAgree(t *testing.T) {
	for name, query := range map[string]string{
		"none":         "a=1&b=2&c=3",
		"one":          "a=1&b=2&a=3",
		"several":      "a=1&b=2&a=3&c=4&b=5&a=6&d=7&c=8",
		"all the same": "a=1&a=2&a=3&a=4",
		"interleaved":  "x=0&a=1&b=2&x=3&b=4&a=5&x=6",
	} {
		params := appendParams(nil, query)
		for own := 0; own <= len(params); own++ { // the last of them taken for cookies
			pairwise, table := joinGroups(params, own, false), joinGroups(params, own, true)
			if !reflect.DeepEqual(pairwise, table) {
				t.Errorf("%s, the first %d parameters: pair by pair %q, through a table %q", name, own, pairwise, table)
			}
		}
	}
	// More joined values than the rule set takes are cut one past its limit, so that it refuses the request.
	var params []joinParam
	for i := 0; i < rulesRead+51; i++ {
		key := fmt.Sprintf("p%d", i)
		params = append(params, joinParam{key, key, "a"}, joinParam{key, key, "b"})
	}
	if got := len(joinGroups(params, len(params), true)); got != rulesRead+1 {
		t.Errorf("%d joined values, want %d", got, rulesRead+1)
	}
	// Most requests have cookies and no parameters: nothing of theirs can be joined, and looking costs nothing.
	cookies := []string{"sid=0123456789abcdef0123456789abcdef; lang=en; consent=1; sid=again"}
	if n := testing.AllocsPerRun(100, func() { joinRepeated("", nil, nil, cookies) }); n != 0 {
		t.Errorf("%v allocations for a request with cookies and no parameters", n)
	}
}

func TestMultipartFieldsLeavesFilesOut(t *testing.T) {
	body := "--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nUNION\r\n" +
		"--b\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nq\r\n" +
		"--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nSELECT 1\r\n--b--\r\n"
	want := []joinParam{{name: "q", value: "UNION"}, {name: "q", value: "SELECT 1"}}
	if got := multipartFields([]byte(body), "b"); !reflect.DeepEqual(got, want) {
		t.Fatalf("fields %q, want %q", got, want)
	}
	for name, tc := range map[string]struct{ body, boundary string }{
		"no boundary":    {body, ""},
		"another":        {body, "c"},
		"a body cut off": {body[:40], "b"},
		"not multipart":  {"q=1&q=2", "b"},
	} {
		if got := multipartFields([]byte(tc.body), tc.boundary); len(got) != 0 {
			t.Errorf("%s: fields %q", name, got)
		}
	}
	// Only as many fields as the rule set reads, and files do not count towards them.
	var many strings.Builder
	for i := 0; i < rulesRead+5; i++ {
		fmt.Fprintf(&many, "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"f%d\"\r\n\r\nx\r\n", i)
		fmt.Fprintf(&many, "--b\r\nContent-Disposition: form-data; name=\"p%d\"\r\n\r\nx\r\n", i)
	}
	many.WriteString("--b--\r\n")
	got := multipartFields([]byte(many.String()), "b")
	if len(got) != rulesRead || got[0].name != "p0" || got[len(got)-1].name != fmt.Sprintf("p%d", rulesRead-1) {
		t.Errorf("%d fields, the last %q", len(got), got[len(got)-1].name)
	}
}

func BenchmarkJoinRepeated(b *testing.B) {
	cookies := []string{"sid=0123456789abcdef0123456789abcdef; lang=en; consent=1"}
	for name, q := range map[string]string{
		"none":     "",
		"one":      "id=42",
		"five":     "page=2&sort=price&dir=asc&q=blue+widgets&utm_source=news",
		"repeated": "color=red&color=blue&size=m&size=l&page=2",
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				joinRepeated(q, nil, nil, cookies)
			}
		})
	}
	// The most one request can ask for: as many parameters as are read in the URL and in a form, every name twice,
	// and a Cookie header as large as the server takes (32 KiB) made of the shortest cookies.
	var pairs, crumbs []string
	for i := 0; i < rulesRead/2; i++ {
		pairs = append(pairs, fmt.Sprintf("p%d=a&p%d=b", i, i))
	}
	for i := 0; len(crumbs) < (32<<10)/6; i++ {
		crumbs = append(crumbs, fmt.Sprintf("c%d=1", i%4096))
	}
	query, form, jar := strings.Join(pairs, "&"), []byte(strings.Join(pairs, "&")), []string{strings.Join(crumbs, ";")}
	b.Run("full", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			joinRepeated(query, form, nil, jar)
		}
	})
}
