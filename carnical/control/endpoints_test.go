// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/control/feed"
)

func policyTarget(tenant string) string { return "/v1/tenants/" + tenant + "/policy" }

func TestStepUpOnWeakeningChanges(t *testing.T) {
	now := epoch.Unix()
	strict := `{"mode":"block","threshold":5}`
	rows := []struct {
		name     string
		current  string // "" means no policy yet
		proposed string
		stepUp   int64 // seconds relative to now; 0 = none
		withStep bool
		status   int
		code     string
		changes  []string // weakening change codes expected in the audit trail
	}{
		{name: "a weakening change with no step-up", current: strict, proposed: `{"mode":"off","threshold":5}`, status: 403, code: "step_up_required", changes: []string{"mode_lowered"}},
		{name: "with a step-up from this second", current: strict, proposed: `{"mode":"off","threshold":5}`, withStep: true, stepUp: 0, status: 200, changes: []string{"mode_lowered"}},
		{name: "a step-up 299 seconds old", current: strict, proposed: `{"mode":"off","threshold":5}`, withStep: true, stepUp: -299, status: 200, changes: []string{"mode_lowered"}},
		{name: "a step-up exactly 300 seconds old", current: strict, proposed: `{"mode":"off","threshold":5}`, withStep: true, stepUp: -300, status: 200, changes: []string{"mode_lowered"}},
		{name: "a step-up 301 seconds old", current: strict, proposed: `{"mode":"off","threshold":5}`, withStep: true, stepUp: -301, status: 403, code: "step_up_required", changes: []string{"mode_lowered"}},
		{name: "a step-up an hour old", current: strict, proposed: `{"mode":"off","threshold":5}`, withStep: true, stepUp: -3600, status: 403, code: "step_up_required", changes: []string{"mode_lowered"}},
		{name: "a step-up 59 seconds in the future (clock skew)", current: strict, proposed: `{"mode":"off","threshold":5}`, withStep: true, stepUp: 59, status: 200, changes: []string{"mode_lowered"}},
		{name: "a step-up 61 seconds in the future", current: strict, proposed: `{"mode":"off","threshold":5}`, withStep: true, stepUp: 61, status: 403, code: "step_up_required", changes: []string{"mode_lowered"}},
		{name: "a step-up an hour in the future", current: strict, proposed: `{"mode":"off","threshold":5}`, withStep: true, stepUp: 3600, status: 403, code: "step_up_required", changes: []string{"mode_lowered"}},
		{name: "a change that does not weaken needs none", current: strict, proposed: `{"mode":"block","threshold":4}`, status: 200},
		{name: "a change that strengthens needs none", current: `{"mode":"monitor","threshold":8}`, proposed: strict, status: 200},
		{name: "the same policy again needs none", current: strict, proposed: strict, status: 200},
		{name: "two weakening changes are both named", current: strict, proposed: `{"mode":"monitor","threshold":9}`, status: 403, code: "step_up_required", changes: []string{"mode_lowered", "threshold_raised"}},
		{name: "a first policy that is weaker than the default needs one", current: "", proposed: `{"mode":"off","threshold":5}`, status: 403, code: "step_up_required", changes: []string{"mode_lowered"}},
		{name: "a first policy at the default needs none", current: "", proposed: strict, status: 200},
		{name: "a step-up does not excuse an invalid document", current: strict, proposed: `{"mode":"off","threshold":5,"invalid":true}`, withStep: true, stepUp: 0, status: 422, code: "invalid_policy"},
		{name: "an unknown mode is invalid, whatever else", current: strict, proposed: `{"mode":"nonsense"}`, status: 422, code: "invalid_policy"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newHarness(t)
			var rev uint64
			if row.current != "" {
				rev = h.seed(tenantA, row.current)
			}
			var step int64
			if row.withStep {
				step = now + row.stepUp
			}
			w := h.putPolicy("ui-a", tenantA, row.proposed, rev, step)
			if w.Code != row.status {
				t.Fatalf("status %d, want %d: %.300s", w.Code, row.status, w.Body.String())
			}
			if row.code != "" {
				if e := errorOf(t, w); e.Code != row.code {
					t.Fatalf("code %q, want %q", e.Code, row.code)
				}
			}
			stored := h.store.revisions(tenantA)
			if row.status == 200 && stored != int(rev)+1 {
				t.Fatalf("a successful write left %d revisions", stored)
			}
			if row.status != 200 && stored != int(rev) {
				t.Fatalf("a refused write changed the policy: %d revisions", stored)
			}
			if row.code == "step_up_required" {
				e := errorOf(t, w)
				var got []string
				for _, c := range e.Weakening {
					if c.Summary == "" {
						t.Fatalf("a weakening change with no words: %+v", c)
					}
					got = append(got, c.Code)
				}
				if strings.Join(got, ",") != strings.Join(row.changes, ",") {
					t.Fatalf("the refusal names %v, want %v", got, row.changes)
				}
			}
			if len(row.changes) > 0 {
				last := h.audit.last()
				if strings.Join(last.Changes, ",") != strings.Join(row.changes, ",") {
					t.Fatalf("audit changes %v, want %v (%+v)", last.Changes, row.changes, last)
				}
				if row.status == 403 && (last.Outcome != "denied" || last.Detail != "step_up_required") {
					t.Fatalf("audit: %+v", last)
				}
				if row.status == 200 && last.Detail != "step_up" {
					t.Fatalf("a step-up write is not marked in the audit log: %+v", last)
				}
			}
		})
	}

	t.Run("the refusal says in plain words what to do", func(t *testing.T) {
		h := newHarness(t)
		h.seed(tenantA, strict)
		e := errorOf(t, h.putPolicy("ui-a", tenantA, `{"mode":"off","threshold":5}`, 1, 0))
		if !strings.Contains(e.Message, HeaderStepUp) || !strings.Contains(e.Weakening[0].Summary, "ignored completely") {
			t.Fatalf("%+v", e)
		}
	})
	t.Run("a step-up is not used up by a write", func(t *testing.T) {
		h := newHarness(t)
		h.seed(tenantA, strict)
		if w := h.putPolicy("ui-a", tenantA, `{"mode":"monitor","threshold":5}`, 1, now); w.Code != 200 {
			t.Fatalf("first: %d", w.Code)
		}
		if w := h.putPolicy("ui-a", tenantA, `{"mode":"off","threshold":5}`, 2, now); w.Code != 200 {
			t.Fatalf("second, same step-up: %d", w.Code)
		}
	})
	t.Run("the validate endpoint says a step-up will be needed, and writes nothing", func(t *testing.T) {
		h := newHarness(t)
		h.seed(tenantA, strict)
		w := h.do(reqOpts{method: "POST", target: policyTarget(tenantA) + ":validate", body: []byte(`{"mode":"off","threshold":9}`)})
		var v validationJSON
		decodeBody(t, w, &v)
		if w.Code != 200 || !v.Valid || !v.StepUpRequired || len(v.Weakening) != 2 || len(v.Diff) != 2 {
			t.Fatalf("%d %+v", w.Code, v)
		}
		if !strings.Contains(v.Diff[0], "block to off") {
			t.Fatalf("diff: %v", v.Diff)
		}
		if h.store.revisions(tenantA) != 1 {
			t.Fatal("validate wrote")
		}
	})
	t.Run("rollback that weakens needs a step-up", func(t *testing.T) {
		h := newHarness(t)
		h.seed(tenantA, `{"mode":"monitor","threshold":5}`) // revision 1
		h.seed(tenantA, strict)                             // revision 2: stricter
		body := []byte(`{"revision":1}`)
		w := h.do(reqOpts{method: "POST", target: policyTarget(tenantA) + ":rollback", body: body, ifMatch: etag(2)})
		if w.Code != 403 || errorOf(t, w).Code != "step_up_required" {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		if h.store.revisions(tenantA) != 2 {
			t.Fatal("a refused rollback wrote")
		}
		w = h.do(reqOpts{method: "POST", target: policyTarget(tenantA) + ":rollback", body: body, ifMatch: etag(2), stepUp: now})
		if w.Code != 200 {
			t.Fatalf("with a step-up: %d %s", w.Code, w.Body.String())
		}
	})
}

func TestOptimisticConcurrency(t *testing.T) {
	doc := `{"mode":"block","threshold":5}`
	rows := []struct {
		name    string
		seed    int // revisions already stored
		ifMatch string
		status  int
		code    string
	}{
		{"the current revision", 1, `"1"`, 200, ""},
		{"no policy yet, revision 0", 0, `"0"`, 200, ""},
		{"no If-Match", 1, ``, 428, "precondition_required"},
		{"If-Match not a revision tag", 1, `1`, 400, "bad_request"},
		{"If-Match a list", 1, `"1","2"`, 400, "bad_request"},
		{"a stale revision", 3, `"2"`, 412, "precondition_failed"},
		{"a future revision", 1, `"2"`, 412, "precondition_failed"},
		{"revision 0 when there is a policy", 1, `"0"`, 412, "precondition_failed"},
		{"revision 1 when there is no policy", 0, `"1"`, 412, "precondition_failed"},
		{"a weak etag", 1, `W/"1"`, 400, "bad_request"},
		{"a wildcard", 1, `*`, 400, "bad_request"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newHarness(t)
			for i := 0; i < row.seed; i++ {
				h.seed(tenantA, `{"mode":"block","threshold":`+strconv.Itoa(5-i)+`}`)
			}
			w := h.do(reqOpts{method: "PUT", target: policyTarget(tenantA), body: []byte(doc), ifMatch: row.ifMatch})
			if w.Code != row.status {
				t.Fatalf("status %d, want %d: %s", w.Code, row.status, w.Body.String())
			}
			if row.code != "" && errorOf(t, w).Code != row.code {
				t.Fatalf("code %q", errorOf(t, w).Code)
			}
			if row.status == 412 {
				if got, want := w.Header().Get("ETag"), etag(uint64(row.seed)); got != want {
					t.Fatalf("a failed precondition says the current revision is %s, want %s", got, want)
				}
			}
			if row.status == 200 && w.Header().Get("ETag") != etag(uint64(row.seed)+1) {
				t.Fatalf("ETag %q", w.Header().Get("ETag"))
			}
		})
	}

	t.Run("the ETag of a GET is the If-Match of the next PUT", func(t *testing.T) {
		h := newHarness(t)
		h.seed(tenantA, doc)
		w := h.do(reqOpts{target: policyTarget(tenantA)})
		tag := w.Header().Get("ETag")
		if tag != `"1"` {
			t.Fatalf("ETag %q", tag)
		}
		if w := h.do(reqOpts{method: "PUT", target: policyTarget(tenantA), body: []byte(`{"mode":"block","threshold":4}`), ifMatch: tag}); w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})

	t.Run("two writers with the same revision: exactly one wins", func(t *testing.T) {
		h := newHarness(t)
		h.seed(tenantA, doc)
		const n = 16
		codes := make([]int, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[i] = h.do(reqOpts{method: "PUT", target: policyTarget(tenantA), body: []byte(fmt.Sprintf(`{"mode":"block","threshold":%d}`, i%5)), ifMatch: etag(1)}).Code
			}()
		}
		wg.Wait()
		ok, stale := 0, 0
		for _, c := range codes {
			switch c {
			case 200:
				ok++
			case 412:
				stale++
			default:
				t.Fatalf("unexpected status %d", c)
			}
		}
		if ok != 1 || stale != n-1 || h.store.revisions(tenantA) != 2 {
			t.Fatalf("%d won, %d lost, %d revisions", ok, stale, h.store.revisions(tenantA))
		}
	})
}

func TestGetPolicy(t *testing.T) {
	h := newHarness(t)
	if w := h.do(reqOpts{target: policyTarget(tenantA)}); w.Code != 404 || errorOf(t, w).Code != "no_policy" {
		t.Fatalf("no policy: %d %s", w.Code, w.Body.String())
	}
	doc := `{"mode":"monitor","threshold":7,"note":"é <b>&</b>"}`
	h.seed(tenantA, doc)
	w := h.do(reqOpts{target: policyTarget(tenantA)})
	var got struct {
		Revision uint64          `json:"revision"`
		Updated  string          `json:"updated"`
		Document json.RawMessage `json:"document"`
	}
	decodeBody(t, w, &got)
	if w.Code != 200 || got.Revision != 1 || got.Updated == "" {
		t.Fatalf("%d %+v", w.Code, got)
	}
	var a, b map[string]any
	_ = json.Unmarshal(got.Document, &a)
	_ = json.Unmarshal([]byte(doc), &b)
	if fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatalf("the document changed: %s", got.Document)
	}
	if w.Header().Get("ETag") != `"1"` || w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("headers %v", w.Header())
	}
	// a store that hands back something that is not a JSON object is an internal error, never passed on
	h.store.docs[tenantA][0].Body = []byte("not json")
	if w := h.do(reqOpts{target: policyTarget(tenantA)}); w.Code != 500 {
		t.Fatalf("a damaged document: %d", w.Code)
	}
}

func TestValidateEndpoint(t *testing.T) {
	h := newHarness(t)
	h.seed(tenantA, `{"mode":"block","threshold":5}`)
	rows := []struct {
		name   string
		body   string
		status int
		valid  bool
		weak   int
		diff   int
	}{
		{"unchanged", `{"mode":"block","threshold":5}`, 200, true, 0, 0},
		{"stricter", `{"mode":"block","threshold":3}`, 200, true, 0, 1},
		{"weaker", `{"mode":"monitor","threshold":5}`, 200, true, 1, 1},
		{"invalid", `{"mode":"block","invalid":true}`, 200, false, 0, 0},
		{"unknown mode", `{"mode":"x"}`, 200, false, 0, 0},
		{"not JSON", `nope`, 400, false, 0, 0},
		{"an array", `[]`, 400, false, 0, 0},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			w := h.do(reqOpts{method: "POST", target: policyTarget(tenantA) + ":validate", body: []byte(row.body)})
			if w.Code != row.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if row.status != 200 {
				return
			}
			var v validationJSON
			decodeBody(t, w, &v)
			if v.Valid != row.valid || len(v.Weakening) != row.weak || len(v.Diff) != row.diff || v.StepUpRequired != (row.weak > 0) {
				t.Fatalf("%+v", v)
			}
			if v.Problems == nil || v.Weakening == nil || v.Diff == nil {
				t.Fatal("a list was null instead of empty")
			}
		})
	}
	if h.store.revisions(tenantA) != 1 {
		t.Fatal("validate wrote")
	}
	t.Run("a validator that fails is an internal error with no text", func(t *testing.T) {
		w := h.do(reqOpts{method: "POST", target: policyTarget(tenantA) + ":validate", body: []byte(`{"fail":true}`)})
		if w.Code != 500 || strings.Contains(w.Body.String(), "secret detail") {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("what the validator says is cleaned and bounded", func(t *testing.T) {
		long := strings.Repeat("x", 1000)
		h2 := newHarness(t, func(c *Config) { c.Validator = noisyValidator{long} })
		w := h2.do(reqOpts{method: "POST", target: policyTarget(tenantA) + ":validate", body: []byte(`{}`)})
		var v validationJSON
		decodeBody(t, w, &v)
		if len(v.Problems) != 100 || len(v.Problems[0].Message) != 300 || strings.ContainsAny(v.Problems[0].Message, "\n\x00") || len(v.Diff) != 200 {
			t.Fatalf("%d problems, first %q, %d diff lines", len(v.Problems), v.Problems[0].Message, len(v.Diff))
		}
	})
}

type noisyValidator struct{ long string }

func (n noisyValidator) Validate(ctx context.Context, tenant string, current, proposed []byte) (Validation, error) {
	var v Validation
	for i := 0; i < 500; i++ {
		v.Problems = append(v.Problems, Problem{Code: "c", Message: "line\nbreak\x00" + n.long})
		v.Diff = append(v.Diff, n.long)
	}
	return v, nil
}

func TestPolicyHistoryPagination(t *testing.T) {
	h := newHarness(t)
	const revs = 12
	for i := 1; i <= revs; i++ {
		h.seed(tenantA, `{"mode":"block","threshold":`+strconv.Itoa(i)+`}`)
	}
	hist := policyTarget(tenantA) + "/history"
	type page struct {
		Entries []struct {
			Revision     uint64   `json:"revision"`
			Actor        string   `json:"actor"`
			Kind         string   `json:"kind"`
			Weakening    []string `json:"weakening"`
			RolledBackTo uint64   `json:"rolled_back_to"`
		} `json:"entries"`
		NextCursor string `json:"next_cursor"`
		HasMore    bool   `json:"has_more"`
	}
	get := func(q string) (*httptest.ResponseRecorder, page) {
		w := h.do(reqOpts{target: hist + q})
		var p page
		if w.Code == 200 {
			decodeBody(t, w, &p)
		}
		return w, p
	}

	rows := []struct {
		name    string
		query   string
		first   uint64
		count   int
		hasMore bool
	}{
		{"default page holds everything here", "", 12, 12, false},
		{"limit 1", "?limit=1", 12, 1, true},
		{"limit 5", "?limit=5", 12, 5, true},
		{"limit exactly the number of revisions", "?limit=12", 12, 12, false},
		{"limit one over", "?limit=13", 12, 12, false},
		{"limit 500", "?limit=500", 12, 12, false},
		{"limit 11 leaves one", "?limit=11", 12, 11, true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			w, p := get(row.query)
			if w.Code != 200 {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if len(p.Entries) != row.count || p.Entries[0].Revision != row.first || p.HasMore != row.hasMore || (p.NextCursor != "") != row.hasMore {
				t.Fatalf("%d entries, first %d, more %v, cursor %q", len(p.Entries), p.Entries[0].Revision, p.HasMore, p.NextCursor)
			}
			if p.Entries[0].Actor != "seed" || p.Entries[0].Kind != "put" {
				t.Fatalf("entry: %+v", p.Entries[0])
			}
		})
	}

	// following the cursors visits every revision once, newest first, whatever the page size
	for _, size := range []int{1, 2, 3, 5, 7, 11, 12, 13} {
		t.Run("walk with pages of "+strconv.Itoa(size), func(t *testing.T) {
			var seen []uint64
			cursor := ""
			for guard := 0; guard < 40; guard++ {
				q := "?limit=" + strconv.Itoa(size)
				if cursor != "" {
					q += "&cursor=" + cursor
				}
				w, p := get(q)
				if w.Code != 200 {
					t.Fatalf("%d %s", w.Code, w.Body.String())
				}
				for _, e := range p.Entries {
					seen = append(seen, e.Revision)
				}
				if !p.HasMore {
					break
				}
				cursor = p.NextCursor
			}
			if len(seen) != revs {
				t.Fatalf("saw %v", seen)
			}
			for i, r := range seen {
				if r != uint64(revs-i) {
					t.Fatalf("out of order or repeated: %v", seen)
				}
			}
		})
	}

	bad := []struct{ name, query string }{
		{"limit zero", "?limit=0"}, {"limit 501", "?limit=501"}, {"limit negative", "?limit=-1"}, {"limit text", "?limit=ten"},
		{"cursor not base64", "?cursor=!!!"}, {"cursor of the wrong content", "?cursor=" + b64("x1")}, {"cursor with a zero revision", "?cursor=" + b64("r0")},
		{"cursor with a leading zero", "?cursor=" + b64("r01")}, {"cursor with a sign", "?cursor=" + b64("r-1")}, {"cursor with text", "?cursor=" + b64("rabc")},
		{"cursor empty revision", "?cursor=" + b64("r")}, {"cursor too big for a revision", "?cursor=" + b64("r99999999999999999999999")},
		{"cursor with padding", "?cursor=cjE="},
	}
	for _, row := range bad {
		t.Run("refuses "+row.name, func(t *testing.T) {
			if w, _ := get(row.query); w.Code != 400 {
				t.Fatalf("status %d", w.Code)
			}
		})
	}
	t.Run("a cursor beyond the newest starts from the newest", func(t *testing.T) {
		_, p := get("?limit=2&cursor=" + encodeRevisionCursor(99))
		if len(p.Entries) != 2 || p.Entries[0].Revision != 12 {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("the first revision ends the list", func(t *testing.T) {
		_, p := get("?limit=5&cursor=" + encodeRevisionCursor(2))
		if len(p.Entries) != 1 || p.Entries[0].Revision != 1 || p.HasMore {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("a store that returns too much, or ignores the cursor, is an error", func(t *testing.T) {
		h2 := newHarness(t, func(c *Config) { c.Policies = lyingStore{h.store} })
		if w := h2.do(reqOpts{target: hist + "?limit=2"}); w.Code != 500 {
			t.Fatalf("too many: %d", w.Code)
		}
		if w := h2.do(reqOpts{target: hist + "?limit=2&cursor=" + encodeRevisionCursor(5)}); w.Code != 500 {
			t.Fatalf("ignored cursor: %d", w.Code)
		}
	})
	t.Run("history records who changed what and how", func(t *testing.T) {
		h3 := newHarness(t)
		h3.seed(tenantA, `{"mode":"block","threshold":5}`)
		h3.putPolicy("ui-a", tenantA, `{"mode":"off","threshold":5}`, 1, epoch.Unix())
		w := h3.do(reqOpts{target: hist})
		var p page
		decodeBody(t, w, &p)
		if p.Entries[0].Actor != "user-1" || len(p.Entries[0].Weakening) != 1 || p.Entries[0].Weakening[0] != "mode_lowered" {
			t.Fatalf("%+v", p.Entries[0])
		}
	})
}

func b64(s string) string { return encodeRaw([]byte(s)) }

type lyingStore struct{ *memPolicyStore }

func (l lyingStore) History(ctx context.Context, tenant string, before uint64, limit int) ([]HistoryEntry, error) {
	var out []HistoryEntry
	for i := 0; i < limit+5; i++ {
		out = append(out, HistoryEntry{Revision: 12 - uint64(i)})
	}
	return out, nil
}

func TestRollback(t *testing.T) {
	setup := func() *harness {
		h := newHarness(t)
		h.seed(tenantA, `{"mode":"block","threshold":3}`) // 1
		h.seed(tenantA, `{"mode":"block","threshold":4}`) // 2
		h.seed(tenantA, `{"mode":"block","threshold":5}`) // 3
		return h
	}
	rb := func(h *harness, body, ifMatch string, step int64) *httptest.ResponseRecorder {
		return h.do(reqOpts{method: "POST", target: policyTarget(tenantA) + ":rollback", body: []byte(body), ifMatch: ifMatch, stepUp: step})
	}
	rows := []struct {
		name    string
		body    string
		ifMatch string
		status  int
		code    string
	}{
		{"to the first revision", `{"revision":1}`, `"3"`, 200, ""},
		{"to the previous revision", `{"revision":2}`, `"3"`, 200, ""},
		{"to the current revision", `{"revision":3}`, `"3"`, 422, "invalid_revision"},
		{"to a revision that does not exist yet", `{"revision":4}`, `"3"`, 422, "invalid_revision"},
		{"to revision zero", `{"revision":0}`, `"3"`, 400, "bad_request"},
		{"with no revision", `{}`, `"3"`, 400, "bad_request"},
		{"with an unknown field", `{"revision":1,"force":true}`, `"3"`, 400, "bad_request"},
		{"with the revision as text", `{"revision":"1"}`, `"3"`, 400, "bad_request"},
		{"with a negative revision", `{"revision":-1}`, `"3"`, 400, "bad_request"},
		{"with no If-Match", `{"revision":1}`, ``, 428, "precondition_required"},
		{"with a stale If-Match", `{"revision":1}`, `"2"`, 412, "precondition_failed"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := setup()
			w := rb(h, row.body, row.ifMatch, 0)
			if w.Code != row.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if row.code != "" && errorOf(t, w).Code != row.code {
				t.Fatalf("code %q", errorOf(t, w).Code)
			}
			if row.status == 200 {
				var out rollbackOut
				decodeBody(t, w, &out)
				if out.Revision != 4 || h.store.revisions(tenantA) != 4 {
					t.Fatalf("%+v", out)
				}
				// the new revision has the old content, and history says it was a rollback
				var wantDoc string
				if strings.Contains(row.body, `"revision":1`) {
					wantDoc = `{"mode":"block","threshold":3}`
				} else {
					wantDoc = `{"mode":"block","threshold":4}`
				}
				if string(h.store.docs[tenantA][3].Body) != wantDoc {
					t.Fatalf("content: %s", h.store.docs[tenantA][3].Body)
				}
				m := h.store.meta[tenantA][3]
				if m.Kind != "rollback" || m.RolledBackTo != out.RolledBackTo || m.Actor != "user-1" {
					t.Fatalf("meta %+v", m)
				}
			} else if h.store.revisions(tenantA) != 3 {
				t.Fatal("a refused rollback changed the policy")
			}
		})
	}
	t.Run("a revision that was valid once and is not now", func(t *testing.T) {
		h := newHarness(t)
		h.seed(tenantA, `{"mode":"block","invalid":true}`)
		h.seed(tenantA, `{"mode":"block"}`)
		w := rb(h, `{"revision":1}`, `"2"`, 0)
		if w.Code != 422 || errorOf(t, w).Code != "invalid_policy" {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("a revision the store does not have", func(t *testing.T) {
		h := setup()
		h2 := newHarness(t, func(c *Config) { c.Policies = missingRevisions{h.store} })
		if w := h2.do(reqOpts{method: "POST", target: policyTarget(tenantA) + ":rollback", body: []byte(`{"revision":1}`), ifMatch: `"3"`}); w.Code != 404 || errorOf(t, w).Code != "revision_not_found" {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
}

type missingRevisions struct{ *memPolicyStore }

func (m missingRevisions) Revision(ctx context.Context, tenant string, revision uint64) (Document, error) {
	return Document{}, ErrNotFound
}

func TestPublish(t *testing.T) {
	target := "/v1/tenants/" + tenantA + "/publish"
	pub := func(h *harness, body, idem string) *httptest.ResponseRecorder {
		return h.do(reqOpts{method: "POST", target: target, body: []byte(body), idem: idem})
	}
	rows := []struct {
		name   string
		body   string
		idem   string
		status int
		code   string
	}{
		{"the current revision", `{"revision":2}`, "abcdefgh", 200, ""},
		{"an older revision", `{"revision":1}`, "abcdefgh", 409, "revision_not_current"},
		{"a future revision", `{"revision":3}`, "abcdefgh", 409, "revision_not_current"},
		{"revision zero", `{"revision":0}`, "abcdefgh", 400, "bad_request"},
		{"no revision", `{}`, "abcdefgh", 400, "bad_request"},
		{"an unknown field", `{"revision":2,"dry_run":true}`, "abcdefgh", 400, "bad_request"},
		{"no idempotency key", `{"revision":2}`, "", 428, "precondition_required"},
		{"a short idempotency key", `{"revision":2}`, "abc", 400, "bad_request"},
		{"an idempotency key with a comma", `{"revision":2}`, "abcd,efgh", 400, "bad_request"},
		{"a 64 character idempotency key", `{"revision":2}`, strings.Repeat("a", 64), 200, ""},
		{"a 65 character idempotency key", `{"revision":2}`, strings.Repeat("a", 65), 400, "bad_request"},
		{"a UUID idempotency key", `{"revision":2}`, "550e8400-e29b-41d4-a716-446655440000", 200, ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newHarness(t)
			h.seed(tenantA, `{"mode":"block","threshold":4}`)
			h.seed(tenantA, `{"mode":"block","threshold":5}`)
			w := pub(h, row.body, row.idem)
			if w.Code != row.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if row.code != "" && errorOf(t, w).Code != row.code {
				t.Fatalf("code %q", errorOf(t, w).Code)
			}
			if row.status == 200 {
				var out publishOut
				decodeBody(t, w, &out)
				if out.Sequence != 1001 || out.Revision != 2 {
					t.Fatalf("%+v", out)
				}
				c := h.pub.calls[0]
				if c.Actor != "user-1" || c.Credential != "ui-a" || c.IdempotencyKey != row.idem || !strings.HasPrefix(c.RequestID, "req_") {
					t.Fatalf("what the publisher was told: %+v", c)
				}
			} else if h.pub.count() != 0 {
				t.Fatal("a refused publish reached the publisher")
			}
		})
	}

	t.Run("a repeated request does the work once", func(t *testing.T) {
		h := newHarness(t)
		h.seed(tenantA, `{"mode":"block"}`)
		first := pub(h, `{"revision":1}`, "retry-key-1")
		again := pub(h, `{"revision":1}`, "retry-key-1")
		if first.Code != 200 || again.Code != 200 || first.Body.String() != again.Body.String() {
			t.Fatalf("%d %s / %d %s", first.Code, first.Body.String(), again.Code, again.Body.String())
		}
		if h.pub.count() != 1 {
			t.Fatalf("the publisher ran %d times", h.pub.count())
		}
		if again.Header().Get("Idempotent-Replay") != "true" || first.Header().Get("Idempotent-Replay") != "" {
			t.Fatalf("replay headers: %q %q", first.Header().Get("Idempotent-Replay"), again.Header().Get("Idempotent-Replay"))
		}
		if h.audit.last().Detail != "idempotent_replay" {
			t.Fatalf("audit: %+v", h.audit.last())
		}
	})
	t.Run("a repeated request gets the first answer after the revision moved on", func(t *testing.T) {
		h := newHarness(t)
		h.seed(tenantA, `{"mode":"block"}`)
		first := pub(h, `{"revision":1}`, "retry-key-1")
		h.seed(tenantA, `{"mode":"block","threshold":4}`) // another write while the first answer was lost
		again := pub(h, `{"revision":1}`, "retry-key-1")
		if first.Code != 200 || again.Code != 200 || first.Body.String() != again.Body.String() || h.pub.count() != 1 {
			t.Fatalf("%d %s / %d %s, publishes %d", first.Code, first.Body.String(), again.Code, again.Body.String(), h.pub.count())
		}
		if w := pub(h, `{"revision":1}`, "retry-key-2"); w.Code != 409 || errorOf(t, w).Code != "revision_not_current" {
			t.Fatalf("a new request for the old revision: %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("a revision that moved on while it was being published is a conflict", func(t *testing.T) {
		// The server checks before it calls the publisher, but a write can land in between; the publisher's own check,
		// made with the sequence, is the one that holds, and its refusal is the same answer as the server's.
		h := newHarness(t)
		h.seed(tenantA, `{"mode":"block"}`)
		h.pub.err = fmt.Errorf("publish: %w", ErrConflict)
		w := pub(h, `{"revision":1}`, "retry-key-1")
		if w.Code != 409 || errorOf(t, w).Code != "revision_not_current" {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		h.pub.err = nil
		if w := pub(h, `{"revision":1}`, "retry-key-1"); w.Code != 200 {
			t.Fatalf("the key was not released after the conflict: %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("the same key with a different request is refused", func(t *testing.T) {
		h := newHarness(t)
		h.seed(tenantA, `{"mode":"block"}`)
		pub(h, `{"revision":1}`, "retry-key-1")
		w := pub(h, `{"revision": 1}`, "retry-key-1")
		if w.Code != 422 || errorOf(t, w).Code != "idempotency_key_reused" {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		if h.pub.count() != 1 {
			t.Fatal("published again")
		}
	})
	t.Run("keys are per credential and per tenant", func(t *testing.T) {
		h := newHarness(t)
		h.addIdentity("ui-a2", []string{tenantA, tenantB}, false, ScopePublish)
		h.seed(tenantA, `{"mode":"block"}`)
		h.seed(tenantB, `{"mode":"block"}`)
		if w := pub(h, `{"revision":1}`, "shared-key-1"); w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		if w := h.do(reqOpts{as: "ui-a2", method: "POST", target: target, body: []byte(`{"revision":1}`), idem: "shared-key-1"}); w.Code != 200 || h.pub.count() != 2 {
			t.Fatalf("another credential with the same key: %d, publishes %d", w.Code, h.pub.count())
		}
		if w := h.do(reqOpts{as: "ui-a2", method: "POST", target: "/v1/tenants/" + tenantB + "/publish", body: []byte(`{"revision":1}`), idem: "shared-key-1"}); w.Code != 200 || h.pub.count() != 3 {
			t.Fatalf("another tenant with the same key: %d, publishes %d", w.Code, h.pub.count())
		}
	})
	t.Run("a publisher that fails releases the key", func(t *testing.T) {
		for _, panicBefore := range []bool{false, true} {
			h := newHarness(t)
			h.seed(tenantA, `{"mode":"block"}`)
			h.pub.err = errors.New("signer unreachable at 10.1.2.3")
			h.pub.panicBefore = panicBefore
			w := pub(h, `{"revision":1}`, "retry-key-1")
			if w.Code != 500 || strings.Contains(w.Body.String(), "10.1.2.3") {
				t.Fatalf("panic=%v: %d %s", panicBefore, w.Code, w.Body.String())
			}
			h.pub.err, h.pub.panicBefore = nil, false
			if w := pub(h, `{"revision":1}`, "retry-key-1"); w.Code != 200 {
				t.Fatalf("retry after a failure (panic=%v): %d %s", panicBefore, w.Code, w.Body.String())
			}
			h.pub.err = ErrUnavailable
			if w := pub(h, `{"revision":1}`, "retry-key-2"); w.Code != 503 || w.Header().Get("Retry-After") == "" {
				t.Fatalf("an unavailable publisher: %d", w.Code)
			}
		}
	})
	t.Run("a request still in progress is not run twice", func(t *testing.T) {
		h := newHarness(t)
		h.seed(tenantA, `{"mode":"block"}`)
		gate := make(chan struct{})
		h.pub.gate, h.pub.in = gate, make(chan struct{}, 2)
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- pub(h, `{"revision":1}`, "retry-key-1") }()
		<-h.pub.in
		w := pub(h, `{"revision":1}`, "retry-key-1")
		if w.Code != 409 || errorOf(t, w).Code != "in_progress" {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		close(gate)
		if w := <-done; w.Code != 200 {
			t.Fatalf("the first: %d", w.Code)
		}
		if w := pub(h, `{"revision":1}`, "retry-key-1"); w.Code != 200 || h.pub.count() != 1 {
			t.Fatalf("after it finished: %d, publishes %d", w.Code, h.pub.count())
		}
	})
	t.Run("too many keys held", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.Limits.IdempotencyPerCredential = 2 })
		h.seed(tenantA, `{"mode":"block"}`)
		for i := 0; i < 2; i++ {
			if w := pub(h, `{"revision":1}`, "retry-key-"+strconv.Itoa(i)); w.Code != 200 {
				t.Fatalf("%d: %d", i, w.Code)
			}
		}
		if w := pub(h, `{"revision":1}`, "retry-key-9"); w.Code != 503 || errorOf(t, w).Code != "idempotency_full" {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		// a key already held still replays, and keys expire after the window
		if w := pub(h, `{"revision":1}`, "retry-key-0"); w.Code != 200 {
			t.Fatalf("a held key: %d", w.Code)
		}
		h.clock.advance(25 * time.Hour)
		if w := pub(h, `{"revision":1}`, "retry-key-9"); w.Code != 200 {
			t.Fatalf("after the window: %d", w.Code)
		}
	})
	t.Run("publishing never publishes a weaker revision than the one that was approved", func(t *testing.T) {
		// only the current revision can be published, and a revision enters the history only through a write that passed
		// the weakening check, so there is no way to publish a weakening change that skipped the step-up
		h := newHarness(t)
		h.seed(tenantA, `{"mode":"block","threshold":5}`)
		h.seed(tenantA, `{"mode":"off","threshold":5}`) // arrived some other way
		if w := pub(h, `{"revision":1}`, "retry-key-1"); w.Code != 409 {
			t.Fatalf("an old revision: %d", w.Code)
		}
	})
}

func TestHosts(t *testing.T) {
	hostsT := "/v1/tenants/" + tenantA + "/hosts"
	type hostResp struct {
		Host hostJSON `json:"host"`
	}
	add := func(h *harness, name, as, tenant string) *httptest.ResponseRecorder {
		return h.do(reqOpts{as: as, method: "POST", target: "/v1/tenants/" + tenant + "/hosts", body: []byte(`{"hostname":"` + name + `"}`)})
	}
	t.Run("a hostname is not routable until it is verified", func(t *testing.T) {
		h := newHarness(t)
		w := add(h, "shop.example.com", "ui-a", tenantA)
		var r hostResp
		decodeBody(t, w, &r)
		if w.Code != 201 || r.Host.State != HostPending || r.Host.Routable || r.Host.Challenge == nil {
			t.Fatalf("%d %+v", w.Code, r.Host)
		}
		ch := r.Host.Challenge
		if ch.Type != "dns-txt" || ch.Name != "_carnical-challenge.shop.example.com" || !strings.HasPrefix(ch.Value, "carnical-verify=") || len(ch.Value) != len("carnical-verify=")+32 {
			t.Fatalf("challenge: %+v", ch)
		}
		if strings.Contains(w.Body.String(), tenantA) {
			t.Fatal("the challenge names the tenant")
		}
		if _, ok := h.hosts.routable("shop.example.com"); ok {
			t.Fatal("routable before verification")
		}
		// GET shows the state
		var list struct {
			Hosts []hostJSON `json:"hosts"`
		}
		decodeBody(t, h.do(reqOpts{target: hostsT}), &list)
		if len(list.Hosts) != 1 || list.Hosts[0].State != HostPending || list.Hosts[0].Challenge == nil || list.Hosts[0].Challenge.Value != ch.Value {
			t.Fatalf("%+v", list)
		}

		// not yet visible in DNS
		h.verify.result["shop.example.com"] = false
		w = h.do(reqOpts{method: "POST", target: hostsT + "/shop.example.com:verify"})
		r = hostResp{}
		decodeBody(t, w, &r)
		if w.Code != 200 || r.Host.State != HostPending || r.Host.CheckedAt == "" || r.Host.Routable {
			t.Fatalf("%d %+v", w.Code, r.Host)
		}
		if got := h.verify.seen[0]; got != ch.Name+"="+ch.Value {
			t.Fatalf("the verifier was asked for %q, want %q", got, ch.Name+"="+ch.Value)
		}
		if _, ok := h.hosts.routable("shop.example.com"); ok {
			t.Fatal("routable after a failed check")
		}
		// checking again at once is refused: DNS is not for hammering
		if w := h.do(reqOpts{method: "POST", target: hostsT + "/shop.example.com:verify"}); w.Code != 429 || errorOf(t, w).Code != "too_soon" || w.Header().Get("Retry-After") == "" {
			t.Fatalf("a second check at once: %d %s", w.Code, w.Body.String())
		}
		if len(h.verify.calls) != 1 {
			t.Fatalf("the verifier ran %d times", len(h.verify.calls))
		}

		// the customer adds the record
		h.clock.advance(11 * time.Second)
		h.verify.result["shop.example.com"] = true
		w = h.do(reqOpts{method: "POST", target: hostsT + "/shop.example.com:verify"})
		r = hostResp{}
		decodeBody(t, w, &r)
		if w.Code != 200 || r.Host.State != HostVerified || !r.Host.Routable || r.Host.Challenge != nil || r.Host.VerifiedAt == "" {
			t.Fatalf("%d %+v", w.Code, r.Host)
		}
		if owner, ok := h.hosts.routable("shop.example.com"); !ok || owner != tenantA {
			t.Fatalf("routable for %q %v", owner, ok)
		}
		// verifying a verified host does not ask DNS again
		n := len(h.verify.calls)
		if w := h.do(reqOpts{method: "POST", target: hostsT + "/shop.example.com:verify"}); w.Code != 200 || len(h.verify.calls) != n {
			t.Fatalf("%d, verifier calls %d", w.Code, len(h.verify.calls))
		}
	})
	t.Run("registering the same name again returns the same challenge", func(t *testing.T) {
		h := newHarness(t)
		var a, b hostResp
		w1 := add(h, "shop.example.com", "ui-a", tenantA)
		w2 := add(h, "shop.example.com", "ui-a", tenantA)
		decodeBody(t, w1, &a)
		decodeBody(t, w2, &b)
		if w1.Code != 201 || w2.Code != 200 || a.Host.Challenge.Value != b.Host.Challenge.Value {
			t.Fatalf("%d %d", w1.Code, w2.Code)
		}
	})
	t.Run("a name is lower-cased", func(t *testing.T) {
		h := newHarness(t)
		w := add(h, "Shop.Example.COM", "ui-a", tenantA)
		var r hostResp
		decodeBody(t, w, &r)
		if w.Code != 201 || r.Host.Hostname != "shop.example.com" {
			t.Fatalf("%d %+v", w.Code, r.Host)
		}
	})
	for _, bad := range []string{"", "localhost", "a", "1.2.3.4", "*.example.com", "example.com:443", "example.com/x", "exa mple.com", "example..com", ".example.com",
		"-a.example.com", "printer.local", "db.internal", "[::1]", "пример.рф", strings.Repeat("a", 64) + ".com", "example.com.", "http://example.com"} {
		t.Run("refuses "+bad, func(t *testing.T) {
			h := newHarness(t)
			w := add(h, bad, "ui-a", tenantA)
			if w.Code != 422 || errorOf(t, w).Code != "invalid_hostname" {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if h.hosts.calls != 0 {
				t.Fatal("the registry was asked")
			}
			if len(bad) >= 8 && strings.Contains(w.Body.String(), bad) {
				t.Fatal("the name was echoed")
			}
		})
	}
	t.Run("a name another tenant has verified cannot be claimed", func(t *testing.T) {
		h := newHarness(t)
		add(h, "shop.example.com", "ui-a", tenantA)
		h.verify.result["shop.example.com"] = true
		if w := h.do(reqOpts{method: "POST", target: hostsT + "/shop.example.com:verify"}); w.Code != 200 {
			t.Fatalf("verify: %d", w.Code)
		}
		w := add(h, "shop.example.com", "ui-b", tenantB)
		if w.Code != 409 || errorOf(t, w).Code != "hostname_unavailable" || strings.Contains(w.Body.String(), "ui-a") || strings.Contains(w.Body.String(), tenantA) {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("a pending claim does not block the real owner", func(t *testing.T) {
		h := newHarness(t)
		add(h, "shop.example.com", "ui-b", tenantB) // someone claims it first, and cannot prove it
		w := add(h, "shop.example.com", "ui-a", tenantA)
		if w.Code != 201 {
			t.Fatalf("%d", w.Code)
		}
		h.verify.result["shop.example.com"] = true
		h.do(reqOpts{method: "POST", target: hostsT + "/shop.example.com:verify"})
		if owner, _ := h.hosts.routable("shop.example.com"); owner != tenantA {
			t.Fatalf("routable for %q", owner)
		}
		// and the squatter's later check is refused
		h.clock.advance(time.Minute)
		w = h.do(reqOpts{as: "ui-b", method: "POST", target: "/v1/tenants/" + tenantB + "/hosts/shop.example.com:verify"})
		if w.Code != 409 {
			t.Fatalf("the squatter's check: %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("a host of another tenant is not found", func(t *testing.T) {
		h := newHarness(t)
		add(h, "shop.example.com", "ui-a", tenantA)
		if w := h.do(reqOpts{as: "ui-b", method: "POST", target: "/v1/tenants/" + tenantB + "/hosts/shop.example.com:verify"}); w.Code != 404 || errorOf(t, w).Code != "host_not_found" {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("an unknown host", func(t *testing.T) {
		h := newHarness(t)
		if w := h.do(reqOpts{method: "POST", target: hostsT + "/nothing.example.com:verify"}); w.Code != 404 {
			t.Fatalf("%d", w.Code)
		}
	})
	t.Run("a verifier that cannot answer is a bad gateway with no detail", func(t *testing.T) {
		h := newHarness(t)
		add(h, "shop.example.com", "ui-a", tenantA)
		h.verify.err = errors.New("resolver 10.9.9.9 refused")
		w := h.do(reqOpts{method: "POST", target: hostsT + "/shop.example.com:verify"})
		if w.Code != 502 || strings.Contains(w.Body.String(), "10.9.9.9") || errorOf(t, w).Code != "verification_unavailable" {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		if _, ok := h.hosts.routable("shop.example.com"); ok {
			t.Fatal("verified on an error")
		}
	})
	t.Run("a registry or verifier that is not connected is not implemented", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.Hosts, c.Verifier = nil, nil })
		for _, o := range []reqOpts{{target: hostsT}, {method: "POST", target: hostsT, body: []byte(`{"hostname":"a.example.com"}`)}, {method: "POST", target: hostsT + "/a.example.com:verify"}} {
			if w := h.do(o); w.Code != 501 {
				t.Fatalf("%s: %d", o.target, w.Code)
			}
		}
	})
	t.Run("the body must be exactly an object with a hostname", func(t *testing.T) {
		h := newHarness(t)
		for _, b := range []string{`{}`, `{"host":"a.example.com"}`, `{"hostname":"a.example.com","x":1}`, `{"hostname":5}`, `["a.example.com"]`, `{"hostname":"a.example.com"}{}`} {
			w := h.do(reqOpts{method: "POST", target: hostsT, body: []byte(b)})
			if w.Code != 400 && w.Code != 422 {
				t.Fatalf("%s: %d", b, w.Code)
			}
		}
	})
}

func TestEvents(t *testing.T) {
	mk := func(i int, ipText string) feed.Event {
		return feed.Event{Time: epoch.Add(-time.Duration(i) * time.Minute), Kind: "block", Sev: "high", IP: ipText, Path: "/wp-login.php", Why: "banned " + ipText, ID: fmt.Sprintf("%012X", 0xABC000+i)}
	}
	h := newHarness(t)
	h.events.events[tenantA] = []feed.Event{mk(0, "198.51.100.77"), mk(1, "2001:db8:abcd:1234::1"), mk(2, "203.0.113.9"), mk(3, ""), mk(4, "not an address")}
	h.events.events[tenantB] = []feed.Event{mk(0, "192.0.2.99")}

	type page struct {
		Events []struct {
			IP  string `json:"ip"`
			Why string `json:"why"`
			ID  string `json:"id"`
		} `json:"events"`
		NextCursor string `json:"next_cursor"`
		HasMore    bool   `json:"has_more"`
	}
	get := func(as, q string) (*httptest.ResponseRecorder, page) {
		w := h.do(reqOpts{as: as, target: "/v1/tenants/" + tenantA + "/events" + q})
		var p page
		if w.Code == 200 {
			decodeBody(t, w, &p)
		}
		return w, p
	}
	t.Run("addresses are cut to /24 and /48 by default", func(t *testing.T) {
		w, p := get("ui-a", "")
		if w.Code != 200 || len(p.Events) != 5 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		want := []string{"198.51.100.0", "2001:db8:abcd::", "203.0.113.0", "", ""}
		for i, e := range p.Events {
			if e.IP != want[i] {
				t.Fatalf("event %d ip %q, want %q", i, e.IP, want[i])
			}
		}
		if p.Events[0].Why != "banned 198.51.100.0" {
			t.Fatalf("an address in free text was not cut: %q", p.Events[0].Why)
		}
		for _, bad := range []string{"198.51.100.77", "1234::1", "203.0.113.9"} {
			if strings.Contains(w.Body.String(), bad) {
				t.Fatalf("%s leaked", bad)
			}
		}
	})
	t.Run("the raw-addresses scope shows them whole", func(t *testing.T) {
		_, p := get("raw-a", "")
		if p.Events[0].IP != "198.51.100.77" || p.Events[1].IP != "2001:db8:abcd:1234::1" || p.Events[0].Why != "banned 198.51.100.77" {
			t.Fatalf("%+v", p.Events)
		}
	})
	t.Run("a credential with read only gets the cut form", func(t *testing.T) {
		if _, p := get("reader-a", ""); p.Events[0].IP != "198.51.100.0" {
			t.Fatalf("%+v", p.Events[0])
		}
	})
	t.Run("only the tenant's own events", func(t *testing.T) {
		w, _ := get("ui-a", "")
		if strings.Contains(w.Body.String(), "192.0.2") {
			t.Fatal("another tenant's event")
		}
	})
	t.Run("pages of two", func(t *testing.T) {
		_, p := get("ui-a", "?limit=2")
		if len(p.Events) != 2 || !p.HasMore || p.NextCursor != "c2" || p.Events[0].ID != "000000ABC000" {
			t.Fatalf("%+v", p)
		}
		_, p = get("ui-a", "?limit=2&cursor="+p.NextCursor)
		if len(p.Events) != 2 || !p.HasMore || p.NextCursor != "c4" {
			t.Fatalf("%+v", p)
		}
		_, p = get("ui-a", "?limit=2&cursor=c4")
		if len(p.Events) != 1 || p.HasMore || p.NextCursor != "" {
			t.Fatalf("the last page: %+v", p)
		}
	})
	t.Run("a source that returns more than was asked is an error", func(t *testing.T) {
		h.events.over = true
		defer func() { h.events.over = false }()
		if w, _ := get("ui-a", "?limit=2"); w.Code != 500 {
			t.Fatalf("%d", w.Code)
		}
	})
	t.Run("a source that says more without a cursor is an error", func(t *testing.T) {
		h2 := newHarness(t, func(c *Config) { c.Events = badCursorEvents{} })
		if w := h2.do(reqOpts{target: "/v1/tenants/" + tenantA + "/events"}); w.Code != 500 {
			t.Fatalf("%d", w.Code)
		}
	})
	t.Run("a source error is uniform", func(t *testing.T) {
		h.events.err = errors.New("clickhouse at 10.0.0.9 timed out")
		defer func() { h.events.err = nil }()
		w, _ := get("ui-a", "")
		if w.Code != 500 || strings.Contains(w.Body.String(), "10.0.0.9") {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("events the feed would refuse are not sent", func(t *testing.T) {
		h.events.events[tenantC] = []feed.Event{{Kind: "BAD KIND", Sev: "high", Time: epoch}, mk(0, "198.51.100.1")}
		w := h.do(reqOpts{as: "admin", target: "/v1/tenants/" + tenantC + "/events"})
		var p page
		decodeBody(t, w, &p)
		if len(p.Events) != 1 {
			t.Fatalf("%+v", p)
		}
	})
}

type badCursorEvents struct{}

func (badCursorEvents) Events(ctx context.Context, tenant string, q PageQuery) (EventsPage, error) {
	return EventsPage{Events: []feed.Event{}, More: true, Next: "not a cursor"}, nil
}
func (badCursorEvents) Traffic(ctx context.Context, tenant string, q PageQuery) (TrafficPage, error) {
	return TrafficPage{}, nil
}

func TestTraffic(t *testing.T) {
	h := newHarness(t)
	for d := 0; d < 5; d++ {
		h.events.traffic[tenantA] = append(h.events.traffic[tenantA], feed.TrafficDay{Day: epoch.AddDate(0, 0, -d).Format("2006-01-02"), Requests: int64(100 + d), Pages: 10, Visitors: 5, Attacks: 1,
			Outcomes: map[string]int64{"c": 90}, TopPages: []feed.TopEntry{{Name: "/", N: 7}}})
	}
	h.events.traffic[tenantA] = append(h.events.traffic[tenantA], feed.TrafficDay{Day: "not a day"})
	type page struct {
		Days       []map[string]any `json:"days"`
		NextCursor string           `json:"next_cursor"`
		HasMore    bool             `json:"has_more"`
	}
	w := h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/traffic?limit=3"})
	var p page
	decodeBody(t, w, &p)
	if w.Code != 200 || len(p.Days) != 3 || !p.HasMore || p.NextCursor != "c3" || p.Days[0]["requests"] != float64(100) {
		t.Fatalf("%d %+v", w.Code, p)
	}
	w = h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/traffic?limit=3&cursor=c3"})
	decodeBody(t, w, &p)
	if len(p.Days) != 2 || p.HasMore {
		t.Fatalf("the second page (the broken day is left out): %+v", p)
	}
	if w := h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/traffic?limit=501"}); w.Code != 400 {
		t.Fatalf("%d", w.Code)
	}
}

func TestStatus(t *testing.T) {
	h := newHarness(t)
	w := h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/status"})
	var s statusJSON
	decodeBody(t, w, &s)
	if w.Code != 200 || s.Health != "ok" || s.LastPublish == nil || s.LastPublish.Sequence != 7 || len(s.Edges) != 1 || s.Edges[0].Edge != "edge-1" || s.Edges[0].Sequence != 7 {
		t.Fatalf("%d %+v", w.Code, s)
	}
	h.status.status = TenantStatus{Health: "perfect\nok"}
	w = h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/status"})
	var s2 statusJSON
	decodeBody(t, w, &s2)
	if s2.Health != "degraded" || s2.Notes == nil || s2.Edges == nil || s2.LastPublish != nil {
		t.Fatalf("an unknown health word must not pass through: %+v", s2)
	}
}

func TestCredentialsEndpoints(t *testing.T) {
	h := newHarness(t)
	w := h.do(reqOpts{as: "admin", target: "/v1/credentials"})
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var list struct {
		Credentials []credentialJSON `json:"credentials"`
	}
	decodeBody(t, w, &list)
	if len(list.Credentials) != len(h.ids) {
		t.Fatalf("%d credentials", len(list.Credentials))
	}
	// no secret or key of any kind is shown: not the signing keys, not the private keys, not the certificates' keys
	body := w.Body.String()
	for name, id := range h.ids {
		for _, secret := range []string{encodeRaw(id.cred.SigningKey), encodeRaw(id.priv), encodeRaw(id.priv.Seed()), string(id.cert.keyPEM)} {
			if strings.Contains(body, secret) {
				t.Fatalf("the list of credentials shows a key of %s", name)
			}
		}
	}
	for _, c := range list.Credentials {
		if len(c.SigningKeyFpr) != 16 {
			t.Fatalf("fingerprint %q", c.SigningKeyFpr)
		}
		if c.ID == "admin" && c.Tenants != "all" {
			t.Fatalf("tenants of admin: %v", c.Tenants)
		}
		if c.ID == "ui-a" && fmt.Sprint(c.Tenants) != "["+tenantA+"]" {
			t.Fatalf("tenants of ui-a: %v", c.Tenants)
		}
	}
	for _, field := range []string{"signing_key\"", "private", "secret", "seed"} {
		if strings.Contains(body, field) {
			t.Fatalf("the list mentions %q", field)
		}
	}

	t.Run("revoking takes effect at once", func(t *testing.T) {
		status := "/v1/tenants/" + tenantA + "/status"
		if w := h.do(reqOpts{target: status}); w.Code != 200 {
			t.Fatalf("before: %d", w.Code)
		}
		w := h.do(reqOpts{as: "admin", method: "POST", target: "/v1/credentials/ui-a:revoke"})
		var r revokeOut
		decodeBody(t, w, &r)
		if w.Code != 200 || !r.Revoked || !r.WasInForce {
			t.Fatalf("%d %+v", w.Code, r)
		}
		if w := h.do(reqOpts{target: status}); w.Code != 401 {
			t.Fatalf("after: %d", w.Code)
		}
		if reason, _ := lastFailure(h); reason != "revoked" {
			t.Fatalf("reason %q", reason)
		}
		// revoking again is not an error, and says it was not in force
		w = h.do(reqOpts{as: "admin", method: "POST", target: "/v1/credentials/ui-a:revoke"})
		decodeBody(t, w, &r)
		if w.Code != 200 || r.WasInForce {
			t.Fatalf("%d %+v", w.Code, r)
		}
		// the audit log has who revoked what
		var found bool
		for _, e := range h.audit.all() {
			if e.Action == "credentials.revoke" && e.Outcome == "ok" && e.Credential == "admin" && len(e.Changes) == 1 && e.Changes[0] == "revoked:ui-a" {
				found = true
			}
		}
		if !found {
			t.Fatal("the revocation is not in the audit log")
		}
		// and the list shows it
		w = h.do(reqOpts{as: "admin", target: "/v1/credentials"})
		decodeBody(t, w, &list)
		for _, c := range list.Credentials {
			if c.ID == "ui-a" && !c.Revoked {
				t.Fatal("the list does not show it revoked")
			}
		}
	})
	t.Run("an unknown credential", func(t *testing.T) {
		if w := h.do(reqOpts{as: "admin", method: "POST", target: "/v1/credentials/nobody-here:revoke"}); w.Code != 404 || errorOf(t, w).Code != "credential_not_found" {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("an expired credential is shown as such", func(t *testing.T) {
		h.setCred("ui-b", func(c *Credential) { c.NotAfter = epoch.Add(-time.Hour) })
		w := h.do(reqOpts{as: "admin", target: "/v1/credentials"})
		decodeBody(t, w, &list)
		for _, c := range list.Credentials {
			if c.ID == "ui-b" && !c.Expired {
				t.Fatal("not shown expired")
			}
		}
	})
}

func TestAuditIsFailClosed(t *testing.T) {
	t.Run("a change is not made if it cannot be written down", func(t *testing.T) {
		h := newHarness(t)
		h.audit.setFailing(true)
		w := h.putPolicy("ui-a", tenantA, `{"mode":"block"}`, 0, 0)
		if w.Code != 503 || errorOf(t, w).Code != "audit_unavailable" || h.store.revisions(tenantA) != 0 {
			t.Fatalf("%d %s, revisions %d", w.Code, w.Body.String(), h.store.revisions(tenantA))
		}
		if h.srv.Stats().AuditFailures == 0 {
			t.Fatal("not counted")
		}
		h.audit.setFailing(false)
		if w := h.putPolicy("ui-a", tenantA, `{"mode":"block"}`, 0, 0); w.Code != 200 {
			t.Fatalf("after the log recovered: %d", w.Code)
		}
	})
	t.Run("a read is not served if it cannot be written down", func(t *testing.T) {
		h := newHarness(t)
		h.seed(tenantA, `{"mode":"block","note":"private"}`)
		h.audit.setFailing(true)
		w := h.do(reqOpts{target: policyTarget(tenantA)})
		if w.Code != 503 || strings.Contains(w.Body.String(), "private") {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("a change that was made is reported even if its closing line cannot be written", func(t *testing.T) {
		h := newHarness(t)
		failAfter := &failAfterAudit{inner: h.audit, okLines: 1}
		h.srv.cfg.Audit = failAfter
		w := h.putPolicy("ui-a", tenantA, `{"mode":"block"}`, 0, 0)
		if w.Code != 200 || h.store.revisions(tenantA) != 1 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		if h.srv.Stats().AuditFailures != 1 {
			t.Fatalf("stats %+v", h.srv.Stats())
		}
		// and the next change is refused, because the log is not working
		if w := h.putPolicy("ui-a", tenantA, `{"mode":"block","threshold":4}`, 1, 0); w.Code != 503 {
			t.Fatalf("the next change: %d", w.Code)
		}
	})
	t.Run("a lost closing line refuses the next change even when the log works again", func(t *testing.T) {
		h := newHarness(t)
		h.srv.cfg.Audit = &failAfterAudit{inner: h.audit, okLines: 1, once: true}
		if w := h.putPolicy("ui-a", tenantA, `{"mode":"block"}`, 0, 0); w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		w := h.putPolicy("ui-a", tenantA, `{"mode":"block","threshold":4}`, 1, 0)
		if w.Code != 503 || errorOf(t, w).Code != "audit_unavailable" || h.store.revisions(tenantA) != 1 {
			t.Fatalf("the change after a lost closing line: %d %s, revisions %d", w.Code, w.Body.String(), h.store.revisions(tenantA))
		}
		if w := h.do(reqOpts{target: policyTarget(tenantA)}); w.Code != 200 {
			t.Fatalf("a read after a lost closing line: %d", w.Code)
		}
	})
	t.Run("an authentication failure that cannot be logged is still refused", func(t *testing.T) {
		h := newHarness(t)
		h.audit.setFailing(true)
		if w := h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/status", keyAs: "ui-b"}); w.Code != 401 {
			t.Fatalf("%d", w.Code)
		}
	})
}

type failAfterAudit struct {
	mu      sync.Mutex
	inner   *memAudit
	okLines int
	once    bool // fail only the first line after okLines, then work again
	n       int
}

func (f *failAfterAudit) Append(e AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.n > f.okLines && (!f.once || f.n == f.okLines+1) {
		return errors.New("disk full")
	}
	return f.inner.Append(e)
}

func TestARouteWithoutItsStoreIsNotImplemented(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Policies, c.Validator, c.Publisher, c.Status, c.Events = nil, nil, nil, nil, nil })
	for _, o := range []reqOpts{
		{target: policyTarget(tenantA)},
		{method: "PUT", target: policyTarget(tenantA), body: []byte(`{}`), ifMatch: `"0"`},
		{method: "POST", target: policyTarget(tenantA) + ":validate", body: []byte(`{}`)},
		{target: policyTarget(tenantA) + "/history"},
		{method: "POST", target: policyTarget(tenantA) + ":rollback", body: []byte(`{"revision":1}`), ifMatch: `"2"`},
		{method: "POST", target: "/v1/tenants/" + tenantA + "/publish", body: []byte(`{"revision":1}`), idem: "abcdefgh"},
		{target: "/v1/tenants/" + tenantA + "/status"},
		{target: "/v1/tenants/" + tenantA + "/events"},
		{target: "/v1/tenants/" + tenantA + "/traffic"},
	} {
		w := h.do(o)
		if w.Code != 501 || errorOf(t, w).Code != "not_implemented" {
			t.Fatalf("%s %s: %d %s", o.method, o.target, w.Code, w.Body.String())
		}
	}
	// the server still authenticates and refuses first: a credential for another tenant gets 403, not 501
	if w := h.do(reqOpts{as: "ui-b", target: policyTarget(tenantA)}); w.Code != 403 {
		t.Fatalf("%d", w.Code)
	}
}

func encodeRaw(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
