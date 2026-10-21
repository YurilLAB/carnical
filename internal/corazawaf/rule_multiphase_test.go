// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.rule.multiphase_evaluation

package corazawaf

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestARGSSplit(t *testing.T) {
	rule := NewRule()
	key := "something"
	if err := rule.AddVariable(variables.Args, key, false); err != nil {
		t.Error(err)
	}
	// ARGS concatenates the GET, POST and path arguments; each is read in the phase it is ready in.
	want := []variables.RuleVariable{variables.ArgsGet, variables.ArgsPost, variables.ArgsPath}
	if len(rule.variables) != len(want) {
		t.Fatalf("Expected %d variables, got %d", len(want), len(rule.variables))
	}
	for i, v := range want {
		if rule.variables[i].Variable != v || rule.variables[i].KeyStr != key {
			t.Errorf("variable %d: got %s:%s, want %s:%s", i, rule.variables[i].Variable.Name(), rule.variables[i].KeyStr, v.Name(), key)
		}
	}
}

func TestARGS_NAMESSplit(t *testing.T) {
	rule := NewRule()
	key := "name"
	if err := rule.AddVariable(variables.ArgsNames, key, false); err != nil {
		t.Error(err)
	}
	if len(rule.variables) != 2 {
		t.Fatalf("Expected 2 variables, got %d", len(rule.variables))
	}
	if rule.variables[0].Variable != variables.ArgsGetNames &&
		rule.variables[1].Variable != variables.ArgsPostNames {
		t.Errorf("Expected ArgsGetNames and ArgsPostNames variables")
	}
	if rule.variables[0].KeyStr != key && rule.variables[1].KeyStr != key {
		t.Errorf("Expected keys equal to %s, got: %s and %s", key, rule.variables[0].KeyStr, rule.variables[1].KeyStr)
	}
}

func TestRuleNegativeVariablesMulti(t *testing.T) {
	rule := NewRule()
	if err := rule.AddVariable(variables.Args, "", false); err != nil {
		t.Error(err)
	}
	// [0] ArgsGet, [1] ArgsPost, [2] ArgsPath
	if len(rule.variables) != 3 || rule.variables[0].Variable != variables.ArgsGet || rule.variables[1].Variable != variables.ArgsPost ||
		rule.variables[2].Variable != variables.ArgsPath {
		t.Fatal("Variable ARGS has not been properly added and splitted into ArgsGet, ArgsPost and ArgsPath")
	}
	for _, v := range rule.variables {
		if v.KeyRx != nil {
			t.Error("invalid key type for variables")
		}
	}

	if err := rule.AddVariableNegation(variables.Args, "test"); err != nil {
		t.Error(err)
	}
	for i, v := range rule.variables {
		if len(v.Exceptions) != 1 || v.Exceptions[0].KeyStr != "test" {
			t.Errorf("variable %d: got %d exceptions, expected 1", i, len(v.Exceptions))
		}
	}

	if err := rule.AddVariable(variables.Args, "/test.*/", false); err != nil {
		t.Error(err)
	}
	// [3] ArgsGet regex, [4] ArgsPost regex, [5] ArgsPath regex
	for _, v := range rule.variables[3:] {
		if v.KeyRx == nil || v.KeyRx.String() != "test.*" {
			t.Error("variable regex cannot be nil")
		}
	}

	if err := rule.AddVariableNegation(variables.Args, "test2"); err != nil {
		t.Error(err)
	}
	// The names have both exceptions, the regexes the second only.
	for i, v := range rule.variables {
		want := 2
		if i >= 3 {
			want = 1
		}
		if len(v.Exceptions) != want || v.Exceptions[want-1].KeyStr != "test2" {
			t.Errorf("variable %d: got %d exceptions, expected %d", i, len(v.Exceptions), want)
		}
	}
}
