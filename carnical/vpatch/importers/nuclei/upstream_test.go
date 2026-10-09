// SPDX-License-Identifier: Apache-2.0

package nuclei

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// upstreamDir is where the nuclei-templates checkout the numbers in docs/signature-formats.md were measured on lives (outside the
// carnical tree). The test is skipped when it is absent.
const upstreamDir = "../../../../.attack/upstream/nuclei-templates/http"

func TestUpstream(t *testing.T) {
	if _, err := os.Stat(upstreamDir); err != nil {
		t.Skip("no nuclei-templates checkout at " + upstreamDir)
	}
	res, err := Convert(upstreamDir, importers.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := res.Report
	b, _ := json.MarshalIndent(r, "", "  ")
	t.Logf("%s", b)
	if r.FilesRead == 0 || r.Signatures == 0 {
		t.Fatalf("nothing converted: %+v", r)
	}
	for _, k := range []string{"invalid-output", "duplicate-id"} {
		if r.Partial[k] != 0 {
			t.Errorf("%s: %d (errors: %v)", k, r.Partial[k], r.Errors)
		}
	}
	for _, k := range []string{"internal-error", "yaml-invalid", "yaml-unsafe", "yaml-too-slow", "yaml-too-large", "invalid-template"} {
		if r.Skipped[k] != 0 {
			t.Errorf("%s: %d (%v)", k, r.Skipped[k], r.Examples[k])
		}
	}
}

// This exercises template conversion, not SecLang semantics, without an external template checkout.
func TestConvertMultipart(t *testing.T) {
	rows := []struct {
		name, contentType, disposition string
		upload                         bool
	}{
		{"lowercase boundary", "multipart/form-data; boundary=abc123", "Content-Disposition: form-data; name=\"file\"; filename=\"probe.php\"", true},
		{"mixed case boundary", "multipart/form-data; boundary=AbC123", "Content-Disposition: form-data; name=\"file\"; filename=\"probe.php\"", true},
		{"quoted boundary", "multipart/form-data; boundary=\"AbC123\"", "Content-Disposition: form-data; name=\"file\"; filename=\"probe.php\"", true},
		{"parameter whitespace", "Multipart/Form-Data; BOUNDARY = \"AbC123\"", "Content-Disposition: form-data; name=\"file\"; filename=\"probe.php\"", true},
		{"unquoted filename", "multipart/form-data; boundary=abc123", "Content-Disposition: form-data; name=file; filename=probe.php", true},
		{"ordinary file", "multipart/form-data; boundary=abc123", "Content-Disposition: form-data; name=file; filename=photo.jpg", false},
		{"different header", "multipart/form-data; boundary=abc123", "Content-Disposition-Other: form-data; name=\"file\"; filename=\"probe.php\"", false},
		{"different disposition", "multipart/form-data; boundary=abc123", "Content-Disposition: inline; name=\"file\"; filename=\"probe.php\"", false},
		{"conflicting boundaries", "multipart/form-data; boundary=abc123; boundary=different", "Content-Disposition: form-data; name=\"file\"; filename=\"probe.php\"", false},
		{"template variable boundary", "multipart/form-data; boundary={{boundary}}", "Content-Disposition: form-data; name=file; filename=probe.php", true},
		{"missing boundary inference", "multipart/form-data", "Content-Disposition: form-data; name=file; filename=probe.php", true},
		{"mismatched boundary", "multipart/form-data; boundary=different", "Content-Disposition: form-data; name=file; filename=probe.php", false},
		{"conflicting filenames", "multipart/form-data; boundary=abc123", "Content-Disposition: form-data; name=file; filename=probe.php; filename=photo.jpg", false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			boundary := "abc123"
			if strings.Contains(row.contentType, "AbC123") {
				boundary = "AbC123"
			}
			if strings.Contains(row.contentType, "{{boundary}}") {
				boundary = "{{boundary}}"
			}
			body := "--" + boundary + "\r\n" + row.disposition + "\r\n\r\nfixture\r\n--" + boundary + "--\r\n"
			for _, raw := range []bool{false, true} {
				t.Run(fmt.Sprintf("raw=%v", raw), func(t *testing.T) {
					block := map[string]any{"method": "POST", "path": []string{"{{BaseURL}}/upload"}, "headers": map[string]string{"Content-Type": row.contentType}, "body": body}
					if raw {
						block = map[string]any{"raw": []string{"POST /upload HTTP/1.1\r\nHost: {{Hostname}}\r\nContent-Type: " + row.contentType + "\r\n\r\n" + body}}
					}
					data, err := json.Marshal(map[string]any{"id": "multipart-regression", "info": map[string]string{"name": "Multipart upload", "severity": "high"}, "http": []any{block}})
					if err != nil {
						t.Fatal(err)
					}
					res := ConvertBytes("multipart.yaml", data, importers.Options{})
					if len(res.Signatures) != 1 {
						t.Fatalf("signatures=%d report=%+v", len(res.Signatures), res.Report)
					}
					sig := res.Signatures[0]
					wantConfidence, wantAction := "low", "log"
					if row.upload {
						wantConfidence, wantAction = "medium", "block"
					}
					if sig.Confidence != wantConfidence || sig.Action != wantAction {
						t.Fatalf("upload=%v: confidence=%q action=%q", row.upload, sig.Confidence, sig.Action)
					}
					filenameCondition := false
					for _, c := range append([]vpatch.Condition{sig.Condition}, sig.Also...) {
						for _, target := range c.Targets {
							filenameCondition = filenameCondition || target == vpatch.TargetFilenames
						}
					}
					if filenameCondition != row.upload {
						t.Fatalf("filename condition=%v, want %v", filenameCondition, row.upload)
					}
				})
			}
		})
	}
}
