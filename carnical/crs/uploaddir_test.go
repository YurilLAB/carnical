package crs

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestUploadDirIsValidatedAndWritten(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "uploads")
	tests := []struct {
		name string
		dir  string
		ok   bool
	}{
		{"unset", "", true},
		{"an absolute path", abs, true},
		{"a relative path", "uploads", false},
		{"a newline that would start another directive", abs + "\nSecRuleEngine Off", false},
		{"a space", abs + " x", false},
		{"a quote", abs + "\"", false},
		{"a semicolon", abs + ";x", false},
		{"a trailing backslash that would join the next directive", abs + `\`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := DefaultSettings()
			s.UploadDir = tt.dir
			out, err := s.Directives()
			if (err == nil) != tt.ok {
				t.Fatalf("error = %v, want ok=%v", err, tt.ok)
			}
			if err != nil {
				return
			}
			has := strings.Contains(out, "SecUploadDir "+tt.dir+"\n")
			if has != (tt.dir != "") {
				t.Fatalf("SecUploadDir written: %v, want %v", has, tt.dir != "")
			}
			if !strings.Contains(out, "SecUploadKeepFiles Off\n") {
				t.Fatal("uploaded files are not set to be removed")
			}
		})
	}
}
