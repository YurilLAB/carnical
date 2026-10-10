package proxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
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

	limited := start(t, func(c *Config) { big(c); c.EvalBudget = 5 * time.Millisecond })
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
	t.Logf("inspecting in full: %v; refused at a 5 ms budget after %v", baseline, took)
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
	budgeted := withEvalBudget(waf, 80*time.Millisecond, slots, 16).(experimental.WAFWithOptions)
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
			for _, m := range tx.MatchedRules() {
				if m.Rule().ID() == 4001 && tc.busy {
					t.Fatal("the response body rules ran without a slot")
				}
			}
		})
	}
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

func TestANegativeEvaluationBudgetIsRefused(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1")
	if _, err := New(Config{Upstream: u, CRS: crs.DefaultSettings(), Origin: loopback, EvalBudget: -time.Second}); err == nil {
		t.Fatal("a negative budget, which would also drop the evaluation slots, was accepted")
	}
}

func TestOnlyAsManyEvaluationsRunAtOnceAsThereAreSlots(t *testing.T) {
	tx := &budgetTx{ctx: &budgetCtx{Context: t.Context()}, d: 80 * time.Millisecond, slots: make(chan struct{}, 1)}
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
	multipart := func(n int) string {
		b := "--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("y", n) + "\r\n--XX--\r\n"
		return "POST /upload HTTP/1.1\r\n" + preamble + "Content-Type: multipart/form-data; boundary=XX\r\nContent-Length: " + strconv.Itoa(len(b)) +
			"\r\nConnection: close\r\n\r\n" + b
	}
	tests := []struct {
		name    string
		request string
		want    int
		reaches bool
	}{
		{"a form under the limit", post(form(1000)), 200, true},
		{"a form over the limit", post(form(5000)), 413, false},
		{"a chunked form under the limit", chunked(form(1000)), 200, true},
		{"a chunked form over the limit, which has no length to check up front", chunked(form(5000)), 413, false},
		{"an upload may exceed the form limit", multipart(20000), 200, true},
		{"an upload over the body limit", multipart(70000), 413, false},
		{"a malformed chunk", "POST /submit HTTP/1.1\r\n" + preamble + "Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nZZ\r\nabc\r\n", 400, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := start(t, small)
			status, _ := s.raw(t, tt.request)
			if status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
			if got := len(s.up.requests()) > 0; got != tt.reaches {
				t.Fatalf("reached the application: %v, want %v", got, tt.reaches)
			}
		})
	}
}
