package formats

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// A row is one request and what the inspector must say about it. Every format has a table of rows, accepted and refused, and the
// same check is used three ways: the table itself, the mutation test (turn off the rule a row expects and the check must fail, so
// the row really depends on that rule), and the monitor test (the same finding is recorded and nothing blocks).

type row struct {
	name   string
	method string // default POST
	path   string
	query  string
	ct     string
	hdr    map[string]string
	// hdrs are headers that are sent more than once.
	hdrs map[string][]string
	body string
	// want is the identifier of the verdict that must refuse the request, or 0 if the request must be accepted.
	want int
	// also lists identifiers that must be recorded without refusing (monitor findings).
	also []int
	// tweak changes the policy for this row only (a lower limit, another list of types).
	tweak func(*Policy)
}

func (r row) request() *inspect.Request {
	req := &inspect.Request{Method: r.method, Path: r.path, RawQuery: r.query, Header: http.Header{}}
	if req.Method == "" {
		req.Method = "POST"
	}
	if req.Path == "" {
		req.Path = "/submit"
	}
	if r.ct != "" {
		req.Header.Set("Content-Type", r.ct)
	}
	for k, v := range r.hdr {
		req.Header.Set(k, v)
	}
	for k, vs := range r.hdrs {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if r.body != "" {
		req.Body = []byte(r.body)
	}
	return req
}

func (r row) policy(rules map[string]Action, monitor bool) Policy {
	p := Policy{Monitor: monitor, Rules: map[string]Action{}}
	if r.tweak != nil {
		r.tweak(&p)
	}
	for k, v := range rules {
		p.Rules[k] = v
	}
	return p
}

func ids(vs []inspect.Verdict) []int {
	out := make([]int, len(vs))
	for i, v := range vs {
		out[i] = v.ID
	}
	return out
}

func has(list []int, id int) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

// check runs the row through an inspector and says what is wrong, or returns nil.
func (r row) check(in *Inspector) error {
	res := in.Inspect(r.request())
	var blocking, all []int
	for _, v := range res.Verdicts {
		all = append(all, v.ID)
		if v.Block {
			blocking = append(blocking, v.ID)
		}
	}
	if has(all, rInternal.id) {
		// The inspector recovers a panic and reports it, so a row that reached one still sees a refusal. No row is meant to.
		return fmt.Errorf("the inspector failed on this input: %s", messages(res))
	}
	if r.want == 0 {
		if len(blocking) != 0 {
			return fmt.Errorf("accepted request was refused: %v (%s)", blocking, messages(res))
		}
		if len(r.also) == 0 && len(all) != 0 {
			return fmt.Errorf("accepted request has verdicts: %v (%s)", all, messages(res))
		}
	} else if !has(blocking, r.want) {
		return fmt.Errorf("want a refusal %d, got blocking %v, all %v (%s)", r.want, blocking, all, messages(res))
	}
	for _, id := range r.also {
		if !has(all, id) {
			return fmt.Errorf("want a finding %d, got %v", id, all)
		}
	}
	return nil
}

func messages(res inspect.Result) string {
	var m []string
	for _, v := range res.Verdicts {
		m = append(m, v.Message)
	}
	return strings.Join(m, " | ")
}

// tables are registered by the format tests, so the cross-cutting tests can run every row of every format.
var tables = map[string][]row{}

func register(name string, rows []row) []row {
	tables[name] = rows
	return rows
}

func runTable(t *testing.T, rows []row) {
	t.Helper()
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			in := New(r.policy(nil, false))
			if in.Err() != nil {
				t.Fatalf("policy: %v", in.Err())
			}
			if err := r.check(in); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func ruleName(id int) string {
	for _, r := range registry {
		if r.id == id {
			return r.name
		}
	}
	return ""
}

// TestEveryRefusalDependsOnItsRule is the negative control for every refusal in every table. The rule the row expects is turned off;
// the same check must now fail. A refusal that survives its own rule being off was refused by something else, and the row proves
// nothing about the rule it names.
func TestEveryRefusalDependsOnItsRule(t *testing.T) {
	n := 0
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, r := range tables[name] {
			if r.want == 0 {
				continue
			}
			n++
			t.Run(name+"/"+r.name, func(t *testing.T) {
				rule := ruleName(r.want)
				if rule == "" {
					t.Fatalf("row expects %d, which is not a rule", r.want)
				}
				in := New(r.policy(map[string]Action{rule: Off}, false))
				if in.Err() != nil {
					t.Fatal(in.Err())
				}
				if err := r.check(in); err == nil {
					t.Fatalf("with %s off the row still passes: the refusal is not caused by that rule", rule)
				}
			})
		}
	}
	if n < 150 {
		t.Fatalf("only %d refusal rows across all tables", n)
	}
}

// TestMonitorModeRecordsTheSameFindingsAndRefusesNothing runs every refusal row with the policy in monitor mode.
func TestMonitorModeRecordsTheSameFindingsAndRefusesNothing(t *testing.T) {
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, r := range tables[name] {
			if r.want == 0 {
				continue
			}
			t.Run(name+"/"+r.name, func(t *testing.T) {
				in := New(r.policy(nil, true))
				res := in.Inspect(r.request())
				if !has(ids(res.Verdicts), r.want) {
					t.Fatalf("monitor mode did not record %d: %v", r.want, ids(res.Verdicts))
				}
				for _, v := range res.Verdicts {
					if v.Block {
						t.Fatalf("monitor mode refused: %d %s", v.ID, v.Message)
					}
				}
			})
		}
	}
}

// TestEveryRuleHasARefusalRow makes sure no rule is left without a table row that expects it.
func TestEveryRuleHasARefusalRow(t *testing.T) {
	covered := map[int]bool{}
	for _, rows := range tables {
		for _, r := range rows {
			if r.want != 0 {
				covered[r.want] = true
			}
			for _, id := range r.also {
				covered[id] = true
			}
		}
	}
	for _, r := range registry {
		if !covered[r.id] && r != rPolicyInvalid && r != rInternal {
			t.Errorf("rule %d %s has no row that expects it", r.id, r.name)
		}
	}
}

// TestVerdictsNeverQuoteTheRequest puts a marker in every place a request's content can reach and checks that no verdict repeats
// it. (The structure makes this impossible, because a message is built from fixed phrases and numbers; this checks that it is so.)
func TestVerdictsNeverQuoteTheRequest(t *testing.T) {
	const m = "QZXJKW9"
	cases := []row{
		{name: "json key", ct: "application/json", body: `{"` + m + `":1,"` + strings.ToLower(m) + `":2}`},
		{name: "json value", ct: "application/json", body: `{"a":"` + m + "\x01" + `"}`},
		{name: "xml element", ct: "application/xml", body: `<` + m + `><` + m + `x></` + m + `></` + m + `x>`},
		{name: "xml entity", ct: "application/xml", body: `<a>&` + strings.ToLower(m) + `;</a>`},
		{name: "xml doctype", ct: "application/xml", body: `<!DOCTYPE ` + m + ` [<!ENTITY ` + m + ` SYSTEM "file:///` + m + `">]><a/>`},
		{name: "form name", ct: "application/x-www-form-urlencoded", body: m + "=%zz&" + m + "=1;" + m},
		{name: "graphql field", path: "/graphql", ct: "application/json", body: `{"query":"{ ` + m + ` { ` + m + ` } } fragment ` + m + ` on T { ...` + m + `x }"}`},
		{name: "graphql get", method: "GET", path: "/graphql", query: "query=%7B" + m + "%7B" + m + "%7D%7D+" + m},
		{name: "multipart name", ct: "multipart/form-data; boundary=" + m, body: "--" + m + "\r\nContent-Disposition: form-data; name=\"" + m + "\"; filename=\"" + m + "\"; filename*=UTF-8''" + m + "x\r\nContent-Transfer-Encoding: " + m + "\r\n\r\nv\r\n--" + m + "--\r\n"},
		{name: "content type", ct: "application/" + m + "; " + m + "=1; " + m + "=2", body: "x"},
		{name: "charset", ct: "text/plain; charset=" + m, body: "x"},
		{name: "yaml tag", ct: "application/yaml", body: "a: !!" + m + " b\n", tweak: func(p *Policy) { p.AllowedTypes = []string{"application/yaml"} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := New(c.policy(nil, true))
			res := in.Inspect(c.request())
			if len(res.Verdicts) == 0 {
				t.Fatal("no verdicts, so the case does not test anything")
			}
			for _, v := range res.Verdicts {
				if strings.Contains(strings.ToUpper(v.Message), m) {
					t.Fatalf("verdict %d repeats the request: %s", v.ID, v.Message)
				}
			}
		})
	}
}
