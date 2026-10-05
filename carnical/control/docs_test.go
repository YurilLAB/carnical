// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The documentation (docs/control-api.md) holds the test vector and the table of endpoints. These tests fail when the code
// and the page stop agreeing, so neither can change on its own.

func readDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "docs", "control-api.md"))
	if err != nil {
		t.Skipf("the documentation is not at ../docs/control-api.md: %v", err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func TestDocumentationHasTheVector(t *testing.T) {
	doc := readDoc(t)
	r := vectorRequest()
	text, err := r.CanonicalString()
	if err != nil {
		t.Fatal(err)
	}
	key := vectorKey()
	sig, err := Sign(key, r)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	for _, want := range []string{
		hex.EncodeToString(seed),
		vectorPublicKeyText,
		hex.EncodeToString(r.BodySHA256[:]),
		hex.EncodeToString(sig),
		base64.RawURLEncoding.EncodeToString(sig),
		AuthHeader{Credential: r.Credential, Timestamp: r.Timestamp, Nonce: r.Nonce, Signature: sig}.String(),
		`{"mode":"block","threshold":5}`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the documentation does not contain %q", want)
		}
	}
	// every line of the signed text appears in the example, in order, in the block that shows it
	idx := strings.Index(doc, "signed text")
	if idx < 0 {
		t.Fatal("no signed text in the documentation")
	}
	block := doc[idx:]
	for _, line := range strings.Split(text, "\n") {
		i := strings.Index(block, line)
		if i < 0 {
			t.Fatalf("the signed text's line %q is not in the documentation's example, in order", line)
		}
		block = block[i+len(line):]
	}
	if hex.EncodeToString(sig) != vectorSignatureHex {
		t.Fatalf("the code's signature is not the vector's")
	}
}

func TestDocumentationListsEveryRouteWithItsScope(t *testing.T) {
	doc := readDoc(t)
	doc = strings.ReplaceAll(doc, "{hostname}", "{host}")
	h := newHarness(t)
	rows := map[string]string{}
	for _, line := range strings.Split(doc, "\n") {
		if !strings.HasPrefix(line, "| `GET ") && !strings.HasPrefix(line, "| `PUT ") && !strings.HasPrefix(line, "| `POST ") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 4 {
			continue
		}
		route := strings.Trim(strings.TrimSpace(cells[1]), "`")
		rows[route] = strings.TrimSpace(cells[2])
	}
	for _, r := range h.srv.Routes() {
		key := r.Method + " " + r.Pattern
		scope, ok := rows[key]
		if !ok {
			t.Errorf("the endpoint table does not list %s", key)
			continue
		}
		want := string(r.Scope)
		if r.Public {
			want = "none"
		}
		if scope != want {
			t.Errorf("%s: the documentation says scope %q, the code %q", key, scope, want)
		}
	}
	if len(rows) != len(h.srv.Routes()) {
		t.Errorf("the documentation lists %d endpoints, the code has %d", len(rows), len(h.srv.Routes()))
	}
}

func TestDocumentationLimitsAreTheDefaults(t *testing.T) {
	doc := readDoc(t)
	l := DefaultLimits()
	for _, want := range []struct {
		what string
		ok   bool
	}{
		{"body 256 KiB", l.MaxBody == 256<<10 && strings.Contains(doc, "| Body | 256 KiB |")},
		{"in flight 128 and 16", l.MaxInFlight == 128 && l.MaxInFlightPerCredential == 16 && strings.Contains(doc, "| Requests in flight, per credential | 128, 16 |")},
		{"skew 60 s and step-up 5 min", l.Skew.Seconds() == 60 && l.StepUpMaxAge.Minutes() == 5 && strings.Contains(doc, "| Clock skew; step-up age | 60 s; 5 min |")},
		{"replay 200000 and 50000", l.ReplayMax == 200000 && l.ReplayMaxPerCredential == 50000 && strings.Contains(doc, "| Replay cache, per credential | 200,000; 50,000 |")},
		{"failure threshold 3", l.FailureThreshold == 3 && l.BackoffBase.Seconds() == 1 && l.BackoffMax.Minutes() == 15 && strings.Contains(doc, "| 3; 1 s, 15 min; 15 min; 50,000 |")},
		{"pages 100 and 500", l.PageDefault == 100 && l.PageMax == 500 && strings.Contains(doc, "| Page size, default and maximum | 100, 500 |")},
	} {
		if !want.ok {
			t.Errorf("the documentation and the defaults disagree about: %s", want.what)
		}
	}
}
