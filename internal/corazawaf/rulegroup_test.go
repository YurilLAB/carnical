// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"context"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/types"
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
}
