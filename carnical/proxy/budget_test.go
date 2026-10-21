package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/alert"
	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

func bigForm(kib int) string {
	return "a=" + strings.Repeat("The quick brown fox jumps over the lazy dog. ", kib*1024/46)
}

const preamble = "Host: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\n"

func post(body string) string {
	return "POST /submit HTTP/1.1\r\n" + preamble + "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
}

func TestEvaluationBudgetRefusesARequestThatCostsTooMuch(t *testing.T) {
	body := bigForm(300)
	big := func(c *Config) { c.CRS.RequestBodyLimit = 2 << 20; c.MaxFormBody = 2 << 20 }

	// How long the rules really take for this body when nothing limits them.
	unlimited := start(t, func(c *Config) { big(c); c.EvalBudget = time.Hour })
	began := time.Now()
	status, _ := unlimited.rawFor(t, 2*time.Minute, post(body))
	baseline := time.Since(began)
	if status != http.StatusOK {
		t.Fatalf("with no limit the request should be inspected and allowed: %d", status)
	}
	if baseline < 40*time.Millisecond {
		t.Skipf("this machine inspects the body in %v, too fast to show a budget working", baseline)
	}

	var seen refusals
	limited := start(t, func(c *Config) { big(c); c.EvalBudget = 5 * time.Millisecond; c.OnMatch = seen.record })
	began = time.Now()
	status, _ = limited.rawFor(t, 2*time.Minute, post(body))
	took := time.Since(began)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("a request that goes over its budget: %d, want 503", status)
	}
	if n := len(limited.up.requests()); n != 0 {
		t.Fatalf("a request that was not fully inspected reached the application (%d)", n)
	}
	if took > baseline/2 {
		t.Fatalf("refused after %v, but inspecting it in full takes %v: the work was not cut short", took, baseline)
	}
	if seen.count(idEvalBudget) == 0 {
		t.Fatal("the refusal was not reported")
	}
	t.Logf("inspecting in full: %v; refused at a 5 ms budget after %v", baseline, took)

	// Each request cut short has an alert of its own, with its id and source (G12): forwarded and not inspected in detection
	// mode, or refused there too when Config.EvalBudgetDetect asks for it, and refused in block mode.
	for _, tt := range []struct {
		name   string
		mode   crs.Mode
		cut    OverBudget
		status int
		action alert.Action
	}{
		{"in block mode the request is refused", crs.ModeBlock, "", http.StatusServiceUnavailable, alert.Blocked},
		{"in detection mode the request goes on and the overrun is reported", crs.ModeDetect, "", http.StatusOK, alert.NotInspected},
		{"in detection mode a request cut short can be refused", crs.ModeDetect, OverBudgetRefuse, http.StatusServiceUnavailable, alert.Blocked},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var seen refusals
			var mu sync.Mutex
			var alerts []alert.Alert
			s := start(t, func(c *Config) {
				big(c)
				c.EvalBudget, c.CRS.Mode, c.EvalBudgetDetect, c.OnMatch = 5*time.Millisecond, tt.mode, tt.cut, seen.record
				c.OnAlert = func(a alert.Alert) { mu.Lock(); alerts = append(alerts, a); mu.Unlock() }
			})
			if status, _ := s.rawFor(t, 2*time.Minute, post(body)); status != tt.status {
				t.Fatalf("status %d, want %d", status, tt.status)
			}
			if seen.count(idEvalBudget) == 0 {
				t.Fatal("rules left unread for want of time were not reported")
			}
			mu.Lock()
			defer mu.Unlock()
			i := slices.IndexFunc(alerts, func(a alert.Alert) bool { return a.RuleID == idEvalBudget })
			if i < 0 || alerts[i].Action != tt.action || !alerts[i].Src.IsValid() || len(alerts[i].ID) != 16 ||
				alerts[i].Sig != "carnical-5000045" || alerts[i].Status != map[bool]int{true: 503}[tt.action == alert.Blocked] {
				t.Fatalf("alerts %+v, want one %s for the budget", alerts, tt.action)
			}
		})
	}
}

func TestEvaluationBudgetDoesNotTouchNormalRequestsOrSlowUploads(t *testing.T) {
	s := start(t, nil) // the default budget
	if status, _ := s.raw(t, get("/page")); status != http.StatusOK {
		t.Fatalf("a normal request: %d", status)
	}
	if status, _ := s.raw(t, post("a=hello&b=world")); status != http.StatusOK {
		t.Fatalf("a normal form: %d", status)
	}

	// A body that takes much longer than the budget to arrive is not counted against it: the budget is for the rules.
	tiny := start(t, func(c *Config) { c.EvalBudget = 300 * time.Millisecond })
	conn, err := net.DialTimeout("tcp", tiny.addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	body := "a=hello&b=world"
	conn.Write([]byte("POST /submit HTTP/1.1\r\n" + preamble + "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n"))
	time.Sleep(900 * time.Millisecond) // three budgets pass with the headers sent and the body not
	conn.Write([]byte(body))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an upload that arrived slowly was refused: %d", resp.StatusCode)
	}
}

// A phase's timer callback can run after the phase ended. It must neither expire a later phase nor undo its expiry.
func TestALateTimerCannotCutALaterPhaseShort(t *testing.T) {
	for _, tc := range []struct {
		name string
		fire []int // callbacks run while the third phase is running; 2 is its own
	}{
		{"earlier phases' callbacks only", []int{0, 1}},
		{"an earlier callback before its own", []int{0, 2}},
		{"an earlier callback after its own", []int{2, 0}},
		{"repeated earlier callbacks after its own", []int{2, 1, 0, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var callbacks []func()
			tx := &budgetTx{ctx: &budgetCtx{Context: t.Context()}, d: time.Hour, after: func(d time.Duration, f func()) *time.Timer {
				callbacks = append(callbacks, f)
				return time.NewTimer(d)
			}}
			tx.run(func() {})
			tx.run(func() {})
			tx.run(func() {
				expired := false
				for _, i := range tc.fire {
					callbacks[i]()
					expired = expired || i == 2
					if got := errors.Is(tx.ctx.Err(), context.DeadlineExceeded); got != expired {
						t.Fatalf("after callback %d: phase expired %v, want %v", i, got, expired)
					}
				}
			})
			if err := tx.ctx.Err(); err != nil {
				t.Fatalf("a finished phase kept its budget error: %v", err)
			}
		})
	}
	t.Run("parent cancellation outlasts the phase", func(t *testing.T) {
		parent, cancel := context.WithCancel(t.Context())
		tx := &budgetTx{ctx: &budgetCtx{Context: parent}, d: time.Hour}
		tx.run(cancel)
		if !errors.Is(tx.ctx.Err(), context.Canceled) {
			t.Fatalf("parent cancellation was lost: %v", tx.ctx.Err())
		}
	})
}

// With ProcessPartial, writing the bytes that reach the response body limit runs the response body rules inside
// WriteResponseBody, so that call must wait for a slot like the phases do.
func TestAResponseBodyAtItsLimitIsEvaluatedInASlot(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecResponseBodyLimit 16
SecResponseBodyLimitAction ProcessPartial
SecRule RESPONSE_BODY "@contains secret" "id:4001,phase:4,deny,status:418"
`))
	if err != nil {
		t.Fatal(err)
	}
	slots := make(chan struct{}, 1)
	budgeted := withEvalBudget(waf, 80*time.Millisecond, slots, 16, false, nil).(experimental.WAFWithOptions)
	for _, tc := range []struct {
		name string
		body string
		busy bool
		want int
	}{
		{"under the limit is only buffered", "secret", false, 0},
		{"under the limit does not wait for a busy slot", "secret", true, 0},
		{"at the limit waits for a slot", "a secret that is long enough", true, 503},
		{"exactly at the limit waits for a slot", "0123456789secret", true, 503},
		{"at the limit with a slot is evaluated", "a secret that is long enough", false, 418},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := budgeted.NewTransactionWithOptions(experimental.Options{Context: t.Context()})
			defer tx.Close()
			tx.ProcessURI("/", "GET", "HTTP/1.1")
			tx.ProcessRequestHeaders()
			if _, err := tx.ProcessRequestBody(); err != nil {
				t.Fatal(err)
			}
			tx.AddResponseHeader("Content-Type", "text/plain")
			tx.ProcessResponseHeaders(200, "HTTP/1.1")
			if tc.busy {
				slots <- struct{}{}
				defer func() { <-slots }()
			}
			it, _, err := tx.WriteResponseBody([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			got := 0
			if it != nil {
				got = it.Status
			}
			if got != tc.want {
				t.Fatalf("interruption status %d, want %d", got, tc.want)
			}
			if tx.IsInterrupted() != (tc.want != 0) || tc.want != 0 && tx.Interruption().Status != tc.want {
				// The HTTP middleware asks the transaction, not the write, before it passes on the rest of a response.
				t.Fatalf("the transaction reports interrupted=%v (%+v)", tx.IsInterrupted(), tx.Interruption())
			}
			for _, m := range tx.MatchedRules() {
				if m.Rule().ID() == 4001 && tc.busy {
					t.Fatal("the response body rules ran without a slot")
				}
			}
		})
	}
	t.Run("a response header phase refused for want of a slot ends the response", func(t *testing.T) {
		tx := budgeted.NewTransactionWithOptions(experimental.Options{Context: t.Context()})
		defer tx.Close()
		tx.ProcessURI("/", "GET", "HTTP/1.1")
		tx.ProcessRequestHeaders()
		if _, err := tx.ProcessRequestBody(); err != nil {
			t.Fatal(err)
		}
		tx.AddResponseHeader("Content-Type", "text/plain")
		slots <- struct{}{}
		it := tx.ProcessResponseHeaders(200, "HTTP/1.1")
		<-slots
		if it == nil || it.Status != 503 || !tx.IsInterrupted() || tx.Interruption() != it {
			t.Fatalf("refusal %+v, interrupted=%v", it, tx.IsInterrupted())
		}
	})
	t.Run("writes after the limit do not wait for a busy slot", func(t *testing.T) {
		tx := budgeted.NewTransactionWithOptions(experimental.Options{Context: t.Context()})
		defer tx.Close()
		tx.ProcessURI("/", "GET", "HTTP/1.1")
		tx.ProcessRequestHeaders()
		if _, err := tx.ProcessRequestBody(); err != nil {
			t.Fatal(err)
		}
		tx.AddResponseHeader("Content-Type", "text/plain")
		tx.ProcessResponseHeaders(200, "HTTP/1.1")
		if it, _, _ := tx.WriteResponseBody([]byte("nothing to see in this part")); it != nil {
			t.Fatalf("the evaluated part was refused: %+v", it)
		}
		slots <- struct{}{}
		defer func() { <-slots }()
		if it, _, _ := tx.WriteResponseBody([]byte("more of the same")); it != nil {
			t.Fatalf("a write after the evaluated part waited for a slot: %+v", it)
		}
	})
}

func TestNegativeLimitsAreRefused(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1")
	tests := []struct {
		name string
		cfg  Config
	}{
		{"a negative budget, which would also drop the evaluation slots", Config{EvalBudget: -time.Second}},
		{"a negative form body limit, which would refuse every body", Config{MaxFormBody: -1}},
		{"a negative read timeout, which net/http takes for none", Config{ReadTimeout: -time.Second}},
		{"a write timeout over a day", Config{WriteTimeout: 25 * time.Hour}},
		// A day's read timeout would leave no write timeout that is both longer than it and within a day.
		{"a read timeout of a day", Config{ReadTimeout: 24 * time.Hour}},
		// The write deadline starts at the end of the headers: an upload that arrives inside the read timeout but past
		// it would be acted on by the application and its client never answered.
		{"a write timeout shorter than the read timeout", Config{ReadTimeout: 5 * time.Second, WriteTimeout: time.Second}},
		{"a session cookie name with a space", Config{Responses: ResponsePolicy{SessionCookies: []string{"my session"}}}},
		{"an empty session cookie name", Config{Responses: ResponsePolicy{SessionCookies: []string{""}}}},
		{"more session cookie names than are kept", Config{Responses: ResponsePolicy{SessionCookies: strings.Split(strings.Repeat("S,", MaxSessionCookies)+"S", ",")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.Upstream, tt.cfg.CRS, tt.cfg.Origin = u, crs.DefaultSettings(), loopback
			if _, err := New(tt.cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	accepted := []struct {
		name string
		cfg  Config
	}{
		{"the defaults", Config{}},
		{"a read timeout raised past the default write timeout", Config{ReadTimeout: 10 * time.Minute}},
		{"the longest read timeout, with the longest write timeout", Config{ReadTimeout: 23 * time.Hour, WriteTimeout: 24 * time.Hour}},
		{"a site's own session cookie names", Config{Responses: ResponsePolicy{SessionCookies: []string{"SHOPSESS", "__Host-SESS"}}}},
	}
	for _, tt := range accepted {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.Upstream, tt.cfg.CRS, tt.cfg.Origin = u, crs.DefaultSettings(), loopback
			e, err := New(tt.cfg)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			defer e.Close()
			// So that an upload the read timeout allows still gets its answer.
			if srv := e.Server(""); srv.WriteTimeout <= srv.ReadTimeout {
				t.Fatalf("the write timeout (%v) ends before the read timeout (%v)", srv.WriteTimeout, srv.ReadTimeout)
			}
		})
	}
}

func TestOnlyAsManyEvaluationsRunAtOnceAsThereAreSlots(t *testing.T) {
	var busyReports atomic.Int32
	tx := &budgetTx{ctx: &budgetCtx{Context: t.Context()}, d: 80 * time.Millisecond, slots: make(chan struct{}, 1),
		report: func(timedOut bool, _ string) {
			if !timedOut {
				busyReports.Add(1)
			}
		}}
	release, running := make(chan struct{}), make(chan struct{})
	done := make(chan bool)
	go func() { done <- tx.run(func() { close(running); <-release }) }()
	<-running // the one slot is in use

	began := time.Now()
	if tx.run(func() { t.Error("a second evaluation ran while the only slot was taken") }) {
		t.Fatal("a second evaluation was let in")
	}
	if waited := time.Since(began); waited < 60*time.Millisecond || waited > 2*time.Second {
		t.Fatalf("it waited %v for a slot, want about the budget (80 ms)", waited)
	}
	if n := busyReports.Load(); n != 1 {
		t.Fatalf("%d refusals for want of a slot reported, want 1", n)
	}
	close(release)
	if !<-done {
		t.Fatal("the first evaluation was refused")
	}
	ran := false
	if !tx.run(func() { ran = true }) || !ran {
		t.Fatal("the slot was not given back")
	}
}

func TestBodiesAreCappedAndAnEngineErrorIsNotAnEmpty200(t *testing.T) {
	small := func(c *Config) { c.MaxFormBody = 4 << 10; c.CRS.RequestBodyLimit = 64 << 10 }
	form := func(n int) string { return "a=" + strings.Repeat("x", n) }
	chunked := func(body string) string {
		return "POST /submit HTTP/1.1\r\n" + preamble + "Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" +
			strconv.FormatInt(int64(len(body)), 16) + "\r\n" + body + "\r\n0\r\n\r\n"
	}
	upload := func(b string) string {
		return "POST /upload HTTP/1.1\r\n" + preamble + "Content-Type: multipart/form-data; boundary=XX\r\nContent-Length: " + strconv.Itoa(len(b)) +
			"\r\nConnection: close\r\n\r\n" + b
	}
	file := func(n int) string {
		return "--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("y", n) + "\r\n"
	}
	field := func(n int) string {
		return "--XX\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\n" + strings.Repeat("z", n) + "\r\n"
	}
	multipart := func(n int) string { return upload(file(n) + "--XX--\r\n") }
	pad := strings.Repeat("z", 1000)
	tests := []struct {
		name    string
		request string
		want    int
		reaches bool
		id      int // the refusal recorded last
	}{
		{"a form under the limit", post(form(1000)), 200, true, 0},
		{"a form over the limit", post(form(5000)), 413, false, idBodyTooLarge},
		{"a chunked form under the limit", chunked(form(1000)), 200, true, 0},
		{"a chunked form over the limit, which has no length to check up front", chunked(form(5000)), 413, false, idBodyTooLarge},
		{"an upload may exceed the form limit", multipart(20000), 200, true, 0},
		{"an upload over the body limit", multipart(70000), 413, false, idBodyTooLarge},
		// The fields of a multipart body that are not files are a form, and are held to its limit.
		{"a multipart field over the form limit", upload(field(5000) + "--XX--\r\n"), 413, false, idMultipartFields},
		{"multipart fields together over the form limit", upload(field(1500) + field(1500) + field(1500) + "--XX--\r\n"), 413, false, idMultipartFields},
		{"multipart fields under the form limit beside a large file", upload(field(1500) + file(20000) + field(1500) + "--XX--\r\n"), 200, true, 0},
		{"a multipart body over the form limit that cannot be read as parts", upload(field(1000) + file(20000)), 413, false, idMultipartFields},
		// Everything but the content of the files is held to the form limit: part headers, names and file names too.
		{"a file whose part headers are over the form limit", upload("--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nX-A: " + pad + "\r\nX-B: " + pad + "\r\nX-C: " + pad + "\r\nX-D: " + pad + "\r\nX-E: " + pad + "\r\n\r\ny\r\n--XX--\r\n"), 413, false, idMultipartFields},
		{"files whose names are over the form limit together", upload(strings.Repeat("--XX\r\nContent-Disposition: form-data; name=\""+strings.Repeat("n", 1000)+"\"; filename=\""+strings.Repeat("z", 1000)+".txt\"\r\n\r\ny\r\n", 3) + "--XX--\r\n"), 413, false, idMultipartFields},
		// PHP reads a part that only filename* names as a file as a field, so it is refused rather than left uncounted.
		{"a field named as a file only by filename*, over the form limit", upload("--XX\r\nContent-Disposition: form-data; name=\"t\"; filename*=utf-8''a.txt\r\n\r\n" + strings.Repeat("z", 20000) + "\r\n--XX--\r\n"), 400, false, idAmbiguousType},
		{"a malformed chunk", "POST /submit HTTP/1.1\r\n" + preamble + "Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nZZ\r\nabc\r\n", 400, false, idBodyUnreadable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen refusals
			s := start(t, func(c *Config) { small(c); c.OnMatch = seen.record })
			status, _ := s.raw(t, tt.request)
			if status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
			if got := len(s.up.requests()) > 0; got != tt.reaches {
				t.Fatalf("reached the application: %v, want %v", got, tt.reaches)
			}
			if seen.last() != tt.id {
				t.Fatalf("recorded id %d, want %d", seen.last(), tt.id)
			}
		})
	}
	// The proxy reads every body before the engine does, so no request reaches an engine that leaves it unanswered; were
	// one to, the guard still answers and records it rather than let net/http send an empty 200.
	t.Run("an engine that does not answer", func(t *testing.T) {
		var seen refusals
		e := &Edge{cfg: Config{OnMatch: seen.record, MaxFormBody: 4 << 10}}
		w := httptest.NewRecorder()
		e.guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/page", nil))
		if w.Code != http.StatusBadRequest || seen.last() != idEngineUnanswered {
			t.Fatalf("status %d, recorded id %d", w.Code, seen.last())
		}
	})
}

// interruptingTx stands for an engine transaction whose every phase and body write ends with it.
type interruptingTx struct {
	types.Transaction
	it *types.Interruption
}

func (s interruptingTx) ProcessRequestHeaders() *types.Interruption             { return s.it }
func (s interruptingTx) ProcessRequestBody() (*types.Interruption, error)       { return s.it, nil }
func (s interruptingTx) ProcessResponseHeaders(int, string) *types.Interruption { return s.it }
func (s interruptingTx) ProcessResponseBody() (*types.Interruption, error)      { return s.it, nil }
func (s interruptingTx) Interruption() *types.Interruption                      { return s.it }
func (s interruptingTx) WriteRequestBody([]byte) (*types.Interruption, int, error) {
	return s.it, 0, nil
}
func (s interruptingTx) WriteResponseBody([]byte) (*types.Interruption, int, error) {
	return s.it, 0, nil
}
func (s interruptingTx) ReadRequestBodyFrom(io.Reader) (*types.Interruption, int, error) {
	return s.it, 0, nil
}
func (s interruptingTx) ReadResponseBodyFrom(io.Reader) (*types.Interruption, int, error) {
	return s.it, 0, nil
}

// No rule can end a request with drop or redirect any more (crs/refuse.go), so only a stand-in for the engine's
// transaction can show that the middleware would still be handed a refusal, and not an interruption it answers with an
// empty 200.
func TestEveryInterruptionReachesTheMiddlewareAsARefusal(t *testing.T) {
	for _, tc := range []struct {
		name string
		it   *types.Interruption
		want *types.Interruption
	}{
		{"no interruption", nil, nil},
		{"a deny keeps its status", &types.Interruption{RuleID: 7, Action: "deny", Status: 418},
			&types.Interruption{RuleID: 7, Action: "deny", Status: 418}},
		{"a drop", &types.Interruption{RuleID: 7, Action: "drop"}, &types.Interruption{RuleID: 7, Action: "deny", Status: 403}},
		{"a redirect", &types.Interruption{RuleID: 7, Action: "redirect", Status: 302, Data: "https://elsewhere.test/"},
			&types.Interruption{RuleID: 7, Action: "deny", Status: 403, Data: "https://elsewhere.test/"}},
		{"a deny with a success status", &types.Interruption{RuleID: 7, Action: "deny", Status: 200},
			&types.Interruption{RuleID: 7, Action: "deny", Status: 403}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &budgetTx{Transaction: interruptingTx{it: tc.it}, ctx: &budgetCtx{Context: t.Context()}, d: time.Minute}
			first := func(it *types.Interruption, _ ...any) *types.Interruption { return it }
			for what, it := range map[string]*types.Interruption{
				"request headers":       tx.ProcessRequestHeaders(),
				"request body":          first(tx.ProcessRequestBody()),
				"request body write":    first(tx.WriteRequestBody(nil)),
				"request body read":     first(tx.ReadRequestBodyFrom(strings.NewReader(""))),
				"response headers":      tx.ProcessResponseHeaders(200, "HTTP/1.1"),
				"response body":         first(tx.ProcessResponseBody()),
				"response body write":   first(tx.WriteResponseBody(nil)),
				"response body read":    first(tx.ReadResponseBodyFrom(strings.NewReader(""))),
				"the transaction's own": tx.Interruption(),
			} {
				if (it == nil) != (tc.want == nil) || it != nil && *it != *tc.want {
					t.Errorf("%s: %+v, want %+v", what, it, tc.want)
				}
			}
		})
	}
}
