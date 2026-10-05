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
// every core: the rest wait for a slot for at most the budget, and are refused if none comes free.
func withEvalBudget(waf coraza.WAF, d time.Duration, slots chan struct{}) coraza.WAF {
	inner, ok := waf.(experimental.WAFWithOptions)
	if !ok || d <= 0 {
		return waf
	}
	return &budgetWAF{WAF: waf, inner: inner, d: d, slots: slots}
}

type budgetWAF struct {
	coraza.WAF
	inner experimental.WAFWithOptions
	d     time.Duration
	slots chan struct{}
}

// NewTransactionWithOptions is the one the HTTP middleware uses.
func (w *budgetWAF) NewTransactionWithOptions(o experimental.Options) types.Transaction {
	if o.Context == nil {
		o.Context = context.Background()
	}
	ctx := &budgetCtx{Context: o.Context}
	o.Context = ctx
	return &budgetTx{Transaction: w.inner.NewTransactionWithOptions(o), ctx: ctx, d: w.d, slots: w.slots}
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

func (c *budgetCtx) Err() error {
	if cur := c.current.Load(); cur != 0 && c.expired.Load() == cur {
		return context.DeadlineExceeded
	}
	return c.Context.Err()
}

type budgetTx struct {
	types.Transaction
	ctx   *budgetCtx
	d     time.Duration
	slots chan struct{}
}

// busy is the refusal for a request that could not get a slot to be evaluated in.
var busy = &types.Interruption{Status: 503, Action: "deny"}

// run gives one evaluation phase a slot and its budget. It reports false if no slot came free in time.
func (t *budgetTx) run(phase func()) bool {
	if t.slots != nil {
		wait := time.NewTimer(t.d)
		select {
		case t.slots <- struct{}{}:
			wait.Stop()
			defer func() { <-t.slots }()
		case <-wait.C:
			return false
		}
	}
	gen := t.ctx.current.Add(1)
	timer := time.AfterFunc(t.d, func() { t.ctx.expired.Store(gen) })
	defer func() { timer.Stop(); t.ctx.current.Add(1) }()
	phase()
	return true
}

func (t *budgetTx) ProcessRequestHeaders() (it *types.Interruption) {
	if !t.run(func() { it = t.Transaction.ProcessRequestHeaders() }) {
		return busy
	}
	return it
}

func (t *budgetTx) ProcessRequestBody() (it *types.Interruption, err error) {
	if !t.run(func() { it, err = t.Transaction.ProcessRequestBody() }) {
		return busy, nil
	}
	return it, err
}

func (t *budgetTx) ProcessResponseHeaders(code int, proto string) (it *types.Interruption) {
	if !t.run(func() { it = t.Transaction.ProcessResponseHeaders(code, proto) }) {
		return busy
	}
	return it
}

func (t *budgetTx) ProcessResponseBody() (it *types.Interruption, err error) {
	if !t.run(func() { it, err = t.Transaction.ProcessResponseBody() }) {
		return busy, nil
	}
	return it, err
}
