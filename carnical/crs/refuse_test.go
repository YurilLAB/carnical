package crs

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestRulesThatRunProgramsOrChangeTheEnvironmentDoNotCompile(t *testing.T) {
	tests := []struct {
		name, rule string
		ok         bool
	}{
		{"an ordinary operator", `SecRule ARGS "@contains evil" "id:1,phase:2,deny"`, true},
		{"an ordinary action", `SecRule ARGS "@contains evil" "id:1,phase:2,pass,setvar:tx.x=1"`, true},
		{"inspectFile", `SecRule FILES_TMPNAMES "@inspectFile /bin/true" "id:1,phase:2,deny"`, false},
		{"rbl", `SecRule REMOTE_ADDR "@rbl sbl.example.test" "id:1,phase:2,deny"`, false},
		{"geoLookup", `SecRule REMOTE_ADDR "@geoLookup" "id:1,phase:2,deny"`, false},
		{"exec", `SecRule ARGS "@contains x" "id:1,phase:2,pass,exec:/bin/true"`, false},
		{"setenv", `SecRule ARGS "@contains x" "id:1,phase:2,pass,setenv:A=%{ARGS.a}"`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\n" + tt.rule))
			if (err == nil) != tt.ok {
				t.Fatalf("error = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && !strings.Contains(err.Error(), "not available") {
				t.Fatalf("it failed, but not because it was refused: %v", err)
			}
		})
	}
}
