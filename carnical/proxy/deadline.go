package proxy

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

// A hostile request can make rule evaluation expensive: a large body of the right text costs the Core Rule Set seconds
// of CPU, and a handful of those at once starves every other customer on the machine. The engine has no limit of its
// own, so each phase of evaluation is given a budget here, and a request that does not finish inside it is refused.
//
// The budget is for evaluation only. Reading a slow client's body is not counted (the server's own read timeouts deal
// with that), because a legitimate upload on a poor connection must not be refused for being slow.

// withEvalBudget wraps a WAF so that every evaluation phase of every transaction has at most d to run, and so that no
// more than cap(slots) phases run at once. The second limit is what keeps a flood of expensive requests from using up
// every core: the rest wait for a slot for at most the budget, and are refused if none comes free. respLimit is the
// response body limit the rules were given (0 if it is not known), so that only the response write that reaches it, which
// runs the response body rules, waits for a slot. report, if set, is told of every phase that found no slot (timedOut false)
// or ran out of its budget (timedOut true): neither is a matched rule, and in detection mode a phase that ran out lets the
// request go on with the rest of its rules unread, which an operator tuning the site needs to know.
func withEvalBudget(waf coraza.WAF, d time.Duration, slots chan struct{}, respLimit int64, report func(timedOut bool)) coraza.WAF {
	inner, ok := waf.(experimental.WAFWithOptions)
	if !ok || d <= 0 {
		return waf
	}
	return &budgetWAF{WAF: waf, inner: inner, d: d, slots: slots, respLimit: respLimit, report: report}
}

type budgetWAF struct {
	coraza.WAF
	inner     experimental.WAFWithOptions
	d         time.Duration
	slots     chan struct{}
	respLimit int64
	report    func(timedOut bool)
}

// NewTransactionWithOptions is the one the HTTP middleware uses.
func (w *budgetWAF) NewTransactionWithOptions(o experimental.Options) types.Transaction {
	if o.Context == nil {
		o.Context = context.Background()
	}
	ctx := &budgetCtx{Context: o.Context}
	o.Context = ctx
	tx := w.inner.NewTransactionWithOptions(o)
	// The joined values of repeated parameters (see joined.go) are arguments in a collection of their own, which the
	// request's own arguments never use, so the rules read them and nothing of the request is replaced.
	joined, _ := ctx.Value(joinedKey{}).([]joinedArg)
	for _, j := range joined {
		tx.AddPathRequestArgument(j.name, j.value)
	}
	return &budgetTx{Transaction: tx, ctx: ctx, d: w.d, slots: w.slots, respLimit: w.respLimit, report: w.report}
}

// Close releases the compiled rules of the wrapped WAF.
func (w *budgetWAF) Close() error {
	if c, ok := w.WAF.(experimental.WAFCloser); ok {
		return c.Close()
	}
	return nil
}

// budgetCtx reports itself done while a phase has run out of time. Err is what the engine consults. Each phase has a
// generation number; a timer marks only its own generation as expired, so a timer that fires late, after its phase
// ended and the next one began, cannot cut the next phase short.
type budgetCtx struct {
	context.Context
	current, expired atomic.Uint64
}

// expire retains the newest expired generation; a delayed older callback cannot undo it.
func (c *budgetCtx) expire(gen uint64) {
	for expired := c.expired.Load(); expired < gen; expired = c.expired.Load() {
		if c.expired.CompareAndSwap(expired, gen) {
			return
		}
	}
}

func (c *budgetCtx) Err() error {
	if cur := c.current.Load(); cur != 0 && c.expired.Load() == cur {
		return context.DeadlineExceeded
	}
	return c.Context.Err()
}

type budgetTx struct {
	types.Transaction
	ctx    *budgetCtx
	d      time.Duration
	slots  chan struct{}
	after  func(time.Duration, func()) *time.Timer // time.AfterFunc unless a test orders the callbacks
	report func(timedOut bool)                     // see withEvalBudget

	respLimit int64 // see withEvalBudget; 0 means every response write is budgeted
	resp      int64 // response body bytes the engine has buffered
	respOver  bool  // the write that reached the limit has been made

	refused *types.Interruption // set when a phase could not get a slot; see IsInterrupted
}

// busy is the refusal for a request that could not get a slot to be evaluated in.
var busy = &types.Interruption{Status: 503, Action: "deny"}

// refuse records that a phase was refused for want of a slot, so that the transaction counts as interrupted from then on.
func (t *budgetTx) refuse() *types.Interruption {
	t.refused = busy
	return busy
}

// IsInterrupted also reports a phase refused for want of a slot. The engine never saw that refusal, and the HTTP middleware
// asks this before it buffers and passes on the rest of a response: after a refused response header phase it would
// otherwise send the application's body behind the 503.
func (t *budgetTx) IsInterrupted() bool { return t.refused != nil || t.Transaction.IsInterrupted() }

// Interruption is the refusal for want of a slot, if there was one, or the engine's own.
func (t *budgetTx) Interruption() *types.Interruption {
	if t.refused != nil {
		return t.refused
	}
	return t.Transaction.Interruption()
}

// run gives one evaluation phase a slot and its budget. It reports false if no slot came free in time.
func (t *budgetTx) run(phase func()) bool {
	if t.slots != nil {
		wait := time.NewTimer(t.d)
		select {
		case t.slots <- struct{}{}:
			wait.Stop()
			defer func() { <-t.slots }()
		case <-wait.C:
			if t.report != nil {
				t.report(false)
			}
			return false
		}
	}
	after := t.after
	if after == nil {
		after = time.AfterFunc
	}
	gen := t.ctx.current.Add(1)
	// Stop does not wait for a callback that already started, so it can arrive during a later phase.
	timer := after(t.d, func() { t.ctx.expire(gen) })
	defer func() { timer.Stop(); t.ctx.current.Add(1) }()
	phase()
	if t.report != nil && t.ctx.expired.Load() == gen {
		t.report(true)
	}
	return true
}

func (t *budgetTx) ProcessRequestHeaders() (it *types.Interruption) {
	if !t.run(func() { it = t.Transaction.ProcessRequestHeaders() }) {
		return t.refuse()
	}
	return it
}

func (t *budgetTx) ProcessRequestBody() (it *types.Interruption, err error) {
	if !t.run(func() { it, err = t.Transaction.ProcessRequestBody() }) {
		return t.refuse(), nil
	}
	return it, err
}

func (t *budgetTx) ProcessResponseHeaders(code int, proto string) (it *types.Interruption) {
	if !t.run(func() { it = t.Transaction.ProcessResponseHeaders(code, proto) }) {
		return t.refuse()
	}
	return it
}

func (t *budgetTx) ProcessResponseBody() (it *types.Interruption, err error) {
	if !t.run(func() { it, err = t.Transaction.ProcessResponseBody() }) {
		return t.refuse(), nil
	}
	return it, err
}

// WriteResponseBody runs the response body rules itself when a response reaches the body limit with
// ProcessPartial (the default), so that write needs a slot and the budget too. The writes before it only copy bytes
// and do not wait for a slot, and nor do the ones after it, which the engine does not keep. The middleware never
// passes it a reader that could wait on the origin.
func (t *budgetTx) WriteResponseBody(b []byte) (it *types.Interruption, n int, err error) {
	if t.respLimit > 0 && (t.respOver || t.resp+int64(len(b)) < t.respLimit) {
		it, n, err = t.Transaction.WriteResponseBody(b)
		t.resp += int64(n)
		return it, n, err
	}
	if !t.run(func() { it, n, err = t.Transaction.WriteResponseBody(b) }) {
		return t.refuse(), 0, nil
	}
	t.respOver = true
	t.resp += int64(n)
	return it, n, err
}
