// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"context"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func newTestRule(id int) *Rule {
	r := NewRule()
	r.ID_ = id
	r.Msg, _ = macro.NewMacro("test-Msg")
	r.Tags_ = []string{
		"Test-Tag",
	}
	return r
}

func TestRuleGroupDeleteByTag(t *testing.T) {
	t.Run("matches exact case", func(t *testing.T) {
		rg := NewRuleGroup()
		if err := rg.Add(newTestRule(1)); err != nil {
			t.Fatal("Failed to add rule to rulegroup")
		}
		rg.DeleteByTag("Test-Tag")
		if rg.Count() != 0 {
			t.Error("Expected rule to be removed")
		}
	})

	t.Run("does not match different case", func(t *testing.T) {
		rg := NewRuleGroup()
		if err := rg.Add(newTestRule(1)); err != nil {
			t.Fatal("Failed to add rule to rulegroup")
		}
		rg.DeleteByTag("TEST-TAG")
		if rg.Count() != 1 {
			t.Error("Expected rule to remain when tag case does not match")
		}
	})
}

func TestRuleGroupDeleteByMsg(t *testing.T) {
	t.Run("matches exact case", func(t *testing.T) {
		rg := NewRuleGroup()
		if err := rg.Add(newTestRule(1)); err != nil {
			t.Fatal("Failed to add rule to rulegroup")
		}
		rg.DeleteByMsg("test-Msg")
		if rg.Count() != 0 {
			t.Error("Expected rule to be removed")
		}
	})

	t.Run("does not match different case", func(t *testing.T) {
		rg := NewRuleGroup()
		if err := rg.Add(newTestRule(1)); err != nil {
			t.Fatal("Failed to add rule to rulegroup")
		}
		rg.DeleteByMsg("TEST-MSG")
		if rg.Count() != 1 {
			t.Error("Expected rule to remain when message case does not match")
		}
	})
}

func TestRuleGroupDeleteByID(t *testing.T) {
	var (
		r1 = newTestRule(1)
		r2 = newTestRule(2)
		r3 = newTestRule(3)
		r4 = newTestRule(4)
		r5 = newTestRule(5)
	)

	rg := NewRuleGroup()
	for _, r := range []*Rule{r1, r2, r3, r4, r5} {
		if err := rg.Add(r); err != nil {
			t.Fatalf("Failed to add rule to rulegroup: %s", err.Error())
		}
	}

	if rg.Count() != 5 {
		t.Fatal("Unexpected rules in the rulegroup")
	}

	rg.DeleteByID(1)
	if rg.Count() != 4 {
		t.Fatal("Unexpected remaining rules in the rulegroup")
	}

	rg.DeleteByRange(2, 4)
	if rg.Count() != 1 || rg.GetRules()[0].ID() != 5 {
		t.Fatal("Unexpected remaining rule in the rulegroup")
	}
}

// It is not an engine profile because the profile harness cannot give a transaction a context.
func TestRuleEvaluationStopsWhenTheTransactionContextIsDone(t *testing.T) {
	done, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name      string
		ctx       context.Context
		engine    types.RuleEngineStatus
		wantBlock bool
	}{
		{"a live context blocks nothing", context.Background(), types.RuleEngineOn, false},
		{"a done context refuses the transaction", done, types.RuleEngineOn, true},
		{"a done context in detection-only mode refuses nothing", done, types.RuleEngineDetectionOnly, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := NewWAF()
			waf.RuleEngine = tt.engine
			if err := waf.Rules.Add(newTestRule(1)); err != nil {
				t.Fatal(err)
			}
			tx := waf.NewTransactionWithOptions(Options{Context: tt.ctx})
			defer tx.Close()
			tx.ProcessConnection("127.0.0.1", 1234, "127.0.0.1", 80)
			tx.ProcessURI("/", "GET", "HTTP/1.1")
			it := tx.ProcessRequestHeaders()
			if tt.wantBlock != (it != nil) {
				t.Fatalf("interruption %+v, want block=%v", it, tt.wantBlock)
			}
			if it != nil && it.Status != 503 {
				t.Fatalf("status %d, want 503", it.Status)
			}
		})
	}
	// A phase cut short must not hide the request from the phases after it. The rules it did not reach read later what
	// multiphase evaluation would have given them in it, the rules it reached do not read it twice, and the logging phase
	// runs whatever happened before it, a client that has gone included.
	t.Run("rules a cut phase did not reach still read the request later", func(t *testing.T) {
		tests := []struct {
			name       string
			engine     types.RuleEngineStatus
			spend      bool // rule 1 uses up the time phase 1 was given
			renew      bool // the next phase has time again, as with the proxy's per-phase budget
			wantOnce   []int
			wantStatus int
		}{
			{"a live context lets every rule read the request once", types.RuleEngineDetectionOnly, false, false, []int{10, 1, 100, 500}, 0},
			{"phase 1 out of time in detection-only mode", types.RuleEngineDetectionOnly, true, true, []int{10, 1, 100, 500}, 503},
			{"a blocking engine after the client has gone", types.RuleEngineOn, true, false, []int{1, 500}, 503},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ctx := &spentContext{Context: context.Background()}
				waf := NewWAF()
				waf.RuleEngine = tt.engine
				// Rule 10 comes before the cut, and multiphase evaluation runs it there; 100 and 500 come after it.
				for _, rule := range []struct {
					id    int
					phase types.RulePhase
					op    plugintypes.Operator
				}{
					{10, types.PhaseRequestBody, &dummyEqOperator{}},
					{1, types.PhaseRequestHeaders, &spendTimeOperator{ctx: ctx, spend: tt.spend}},
					{100, types.PhaseRequestBody, &dummyEqOperator{}},
					{500, types.PhaseLogging, &dummyEqOperator{}},
				} {
					r := newTestRule(rule.id)
					r.Phase_ = rule.phase
					if err := r.AddVariable(variables.RequestHeaders, "x-attack", false); err != nil {
						t.Fatal(err)
					}
					r.SetOperator(rule.op, "@eq", "0")
					if err := waf.Rules.Add(r); err != nil {
						t.Fatal(err)
					}
				}
				tx := waf.NewTransactionWithOptions(Options{Context: ctx})
				defer tx.Close()
				tx.AddRequestHeader("X-Attack", "0")
				tx.ProcessRequestHeaders()
				ctx.spent = ctx.spent && !tt.renew
				if _, err := tx.ProcessRequestBody(); err != nil {
					t.Fatal(err)
				}
				tx.ProcessLogging()

				matched := map[int]int{}
				for _, mr := range tx.MatchedRules() {
					matched[mr.Rule().ID()]++
				}
				for _, id := range tt.wantOnce {
					if matched[id] == 0 {
						t.Errorf("rule %d never matched, want once", id)
					}
				}
				for id, n := range matched {
					if n > 1 {
						t.Errorf("rule %d matched %d times, want once", id, n)
					}
				}
				// The refusal is recorded in either mode: a detection-only engine keeps the one it would have made.
				status := 0
				if it := tx.Interruption(); it != nil {
					status = it.Status
				} else if it := tx.DetectionOnlyInterruption(); it != nil {
					status = it.Status
				}
				if status != tt.wantStatus {
					t.Errorf("refusal status %d, want %d", status, tt.wantStatus)
				}
			})
		}
	})
}

// spentContext is done once a rule has used up the time its transaction was given.
type spentContext struct {
	context.Context
	spent bool
}

func (c *spentContext) Err() error {
	if c.spent {
		return context.DeadlineExceeded
	}
	return c.Context.Err()
}

// spendTimeOperator matches anything, and uses up the time of its transaction on the way if spend is set.
type spendTimeOperator struct {
	ctx   *spentContext
	spend bool
}

func (o *spendTimeOperator) Evaluate(plugintypes.TransactionState, string) bool {
	o.ctx.spent = o.ctx.spent || o.spend
	return true
}
