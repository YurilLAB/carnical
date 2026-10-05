// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// The test vector in docs/control-api.md. The key is the Ed25519 key whose seed is the bytes 0 to 31.
func vectorKey() ed25519.PrivateKey {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func vectorRequest() SignedRequest {
	return SignedRequest{
		Method: "PUT", Host: "control.example:8443", Target: "/v1/tenants/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/policy",
		BodySHA256: sha256.Sum256([]byte(`{"mode":"block","threshold":5}`)), Timestamp: 1791201600, Nonce: "000102030405060708090a0b0c0d0e0f",
		Credential: "ui-prod", Tenant: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", User: "user-42", StepUp: 1791201500, HasStepUp: true, IfMatch: `"7"`,
	}
}

const (
	vectorCanonicalLiteral = "carnical-control-v1\nPUT\ncontrol.example:8443\n/v1/tenants/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/policy\n" +
		"4f4e113d1f639b7a12caa49ebb4fa90a9f69871d7e867d712d2118ba22a032f9\n1791201600\n000102030405060708090a0b0c0d0e0f\nui-prod\n" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nuser-42\n1791201500\n\"7\"\n-"
	vectorSignatureHex  = "778c8187b7877c9155810da2c7b54912827bfc3414c5f72f1d361adc2dd3208795573da8c8c65cc0cb28bf77c2184fbb1faa883be87d1c669c23d6d9b63d4a07"
	vectorPublicKeyText = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
)

func TestCanonicalVector(t *testing.T) {
	r := vectorRequest()
	got, err := r.CanonicalString()
	if err != nil {
		t.Fatal(err)
	}
	// built independently of CanonicalString, from the layout in the documentation
	lines := []string{"carnical-control-v1", "PUT", "control.example:8443", "/v1/tenants/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/policy",
		hex.EncodeToString(r.BodySHA256[:]), "1791201600", "000102030405060708090a0b0c0d0e0f", "ui-prod", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"user-42", "1791201500", `"7"`, "-"}
	if want := strings.Join(lines, "\n"); got != want {
		t.Fatalf("canonical string differs from the documented layout:\n%q\n%q", got, want)
	}
	key := vectorKey()
	pub := key.Public().(ed25519.PublicKey)
	sig, err := Sign(key, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("canonical: %q", got)
	t.Logf("body sha256: %s", hex.EncodeToString(r.BodySHA256[:]))
	t.Logf("public key: %s", base64.RawURLEncoding.EncodeToString(pub))
	t.Logf("signature (hex): %s", hex.EncodeToString(sig))
	t.Logf("signature (base64url): %s", base64.RawURLEncoding.EncodeToString(sig))
	t.Logf("header: %s", AuthHeader{Credential: "ui-prod", Timestamp: r.Timestamp, Nonce: r.Nonce, Signature: sig})
	if !ed25519.Verify(pub, []byte(got), sig) {
		t.Fatal("the signature does not verify")
	}
	if want := vectorCanonicalLiteral; got != want {
		t.Fatalf("canonical string changed:\n%q\n%q", got, want)
	}
	if hex.EncodeToString(sig) != vectorSignatureHex {
		t.Fatalf("signature changed: %s", hex.EncodeToString(sig))
	}
	if base64.RawURLEncoding.EncodeToString(pub) != vectorPublicKeyText {
		t.Fatalf("public key changed: %s", base64.RawURLEncoding.EncodeToString(pub))
	}
}

func TestCanonicalEveryFieldMatters(t *testing.T) {
	base := vectorRequest()
	baseText, _ := base.CanonicalString()
	rows := []struct {
		name   string
		change func(r *SignedRequest)
	}{
		{"method", func(r *SignedRequest) { r.Method = "POST" }},
		{"host", func(r *SignedRequest) { r.Host = "control.example:8444" }},
		{"target path", func(r *SignedRequest) { r.Target += "x" }},
		{"target query", func(r *SignedRequest) { r.Target += "?limit=1" }},
		{"body", func(r *SignedRequest) { r.BodySHA256[0] ^= 1 }},
		{"timestamp", func(r *SignedRequest) { r.Timestamp++ }},
		{"nonce", func(r *SignedRequest) { r.Nonce = "1" + r.Nonce[1:] }},
		{"credential", func(r *SignedRequest) { r.Credential = "ui-prod2" }},
		{"tenant", func(r *SignedRequest) { r.Tenant = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }},
		{"tenant removed", func(r *SignedRequest) { r.Tenant = "" }},
		{"user", func(r *SignedRequest) { r.User = "user-43" }},
		{"step-up time", func(r *SignedRequest) { r.StepUp++ }},
		{"step-up removed", func(r *SignedRequest) { r.HasStepUp = false }},
		{"step-up zero is not absent", func(r *SignedRequest) { r.StepUp = 0 }},
		{"if-match", func(r *SignedRequest) { r.IfMatch = `"8"` }},
		{"if-match removed", func(r *SignedRequest) { r.IfMatch = "" }},
		{"idempotency key", func(r *SignedRequest) { r.IdemKey = "abcdefgh" }},
	}
	seen := map[string]string{baseText: "the original"}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := base
			row.change(&r)
			got, err := r.CanonicalString()
			if err != nil {
				t.Fatal(err)
			}
			if prev, dup := seen[got]; dup {
				t.Fatalf("the same text as %s", prev)
			}
			seen[got] = row.name
		})
	}
	t.Run("host case does not matter", func(t *testing.T) {
		r := base
		r.Host = "Control.Example:8443"
		if got, _ := r.CanonicalString(); got != baseText {
			t.Fatal("host is not folded to lower case")
		}
	})
}

func TestCanonicalRefusesWhatCouldBeAmbiguous(t *testing.T) {
	rows := []struct {
		name   string
		change func(r *SignedRequest)
	}{
		{"newline in method", func(r *SignedRequest) { r.Method = "PU\nT" }},
		{"lower-case method", func(r *SignedRequest) { r.Method = "put" }},
		{"empty method", func(r *SignedRequest) { r.Method = "" }},
		{"newline in host", func(r *SignedRequest) { r.Host = "a\nb" }},
		{"empty host", func(r *SignedRequest) { r.Host = "" }},
		{"space in host", func(r *SignedRequest) { r.Host = "a b" }},
		{"newline in target", func(r *SignedRequest) { r.Target = "/a\n/b" }},
		{"carriage return in target", func(r *SignedRequest) { r.Target = "/a\r" }},
		{"space in target", func(r *SignedRequest) { r.Target = "/a b" }},
		{"fragment in target", func(r *SignedRequest) { r.Target = "/a#b" }},
		{"non-ASCII in target", func(r *SignedRequest) { r.Target = "/é" }},
		{"target without a slash", func(r *SignedRequest) { r.Target = "a" }},
		{"empty target", func(r *SignedRequest) { r.Target = "" }},
		{"huge target", func(r *SignedRequest) { r.Target = "/" + strings.Repeat("a", 2100) }},
		{"zero timestamp", func(r *SignedRequest) { r.Timestamp = 0 }},
		{"negative timestamp", func(r *SignedRequest) { r.Timestamp = -5 }},
		{"13-digit timestamp", func(r *SignedRequest) { r.Timestamp = 1_000_000_000_000 }},
		{"short nonce", func(r *SignedRequest) { r.Nonce = r.Nonce[1:] }},
		{"upper-case nonce", func(r *SignedRequest) { r.Nonce = strings.ToUpper(r.Nonce) }},
		{"newline in nonce", func(r *SignedRequest) { r.Nonce = r.Nonce[:31] + "\n" }},
		{"bad credential", func(r *SignedRequest) { r.Credential = "Ui-Prod" }},
		{"newline in credential", func(r *SignedRequest) { r.Credential = "ui\nprod" }},
		{"short tenant", func(r *SignedRequest) { r.Tenant = r.Tenant[1:] }},
		{"upper-case tenant", func(r *SignedRequest) { r.Tenant = strings.ToUpper(r.Tenant) }},
		{"empty user", func(r *SignedRequest) { r.User = "" }},
		{"newline in user", func(r *SignedRequest) { r.User = "a\nb" }},
		{"space in user", func(r *SignedRequest) { r.User = "a b" }},
		{"non-ASCII user", func(r *SignedRequest) { r.User = "zoë" }},
		{"long user", func(r *SignedRequest) { r.User = strings.Repeat("u", 129) }},
		{"negative step-up", func(r *SignedRequest) { r.StepUp = -1 }},
		{"newline in if-match", func(r *SignedRequest) { r.IfMatch = "\"7\"\nx" }},
		{"dash if-match", func(r *SignedRequest) { r.IfMatch = "-" }},
		{"dash idempotency key", func(r *SignedRequest) { r.IdemKey = "-" }},
		{"newline in idempotency key", func(r *SignedRequest) { r.IdemKey = "abcdefgh\nx" }},
		{"long idempotency key", func(r *SignedRequest) { r.IdemKey = strings.Repeat("k", 129) }},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := vectorRequest()
			row.change(&r)
			if s, err := r.CanonicalString(); err == nil {
				t.Fatalf("accepted: %q", s)
			}
			if _, err := Sign(vectorKey(), r); err == nil {
				t.Fatal("signed a request that cannot be written unambiguously")
			}
		})
	}
	t.Run("a bad private key", func(t *testing.T) {
		if _, err := Sign(ed25519.PrivateKey(make([]byte, 10)), vectorRequest()); err == nil {
			t.Fatal("signed with a key of the wrong length")
		}
	})
}

func TestCanonicalFieldsRoundTrip(t *testing.T) {
	r := vectorRequest()
	s, _ := r.CanonicalString()
	f, ok := CanonicalFields(s)
	if !ok || len(f) != 13 || f[0] != CanonicalPrefix || f[1] != "PUT" || f[8] != r.Tenant || f[12] != "-" {
		t.Fatalf("fields = %q", f)
	}
	if _, ok := CanonicalFields(s + "\nextra"); ok {
		t.Fatal("a fourteenth line was accepted")
	}
	if _, ok := CanonicalFields("x" + s); ok {
		t.Fatal("a wrong prefix was accepted")
	}
}

func TestParseAuthHeader(t *testing.T) {
	sig := strings.Repeat("A", 86)
	nonce := strings.Repeat("0", 32)
	good := "Carnical-Sig cred=ui-prod, ts=1791201600, nonce=" + nonce + ", sig=" + sig
	// the last character of an 86-character base64url string must leave no bits over: 'A' does, 'B' does not
	badTail := strings.Repeat("A", 85) + "B"
	rows := []struct {
		name string
		in   string
		ok   bool
	}{
		{"exact", good, true},
		{"empty", "", false},
		{"wrong scheme", strings.Replace(good, "Carnical-Sig", "Bearer", 1), false},
		{"lower-case scheme", strings.Replace(good, "Carnical-Sig", "carnical-sig", 1), false},
		{"no space after scheme", strings.Replace(good, "Carnical-Sig ", "Carnical-Sig", 1), false},
		{"two spaces after scheme", strings.Replace(good, "Carnical-Sig ", "Carnical-Sig  ", 1), false},
		{"no space after a comma", strings.Replace(good, ", ts", ",ts", 1), false},
		{"two spaces after a comma", strings.Replace(good, ", ts", ",  ts", 1), false},
		{"tab after a comma", strings.Replace(good, ", ts", ",\tts", 1), false},
		{"fields reordered", "Carnical-Sig ts=1791201600, cred=ui-prod, nonce=" + nonce + ", sig=" + sig, false},
		{"a field missing", "Carnical-Sig cred=ui-prod, ts=1791201600, sig=" + sig, false},
		{"a field twice", good + ", sig=" + sig, false},
		{"unknown field", good + ", x=1", false},
		{"credential upper case", strings.Replace(good, "ui-prod", "UI-PROD", 1), false},
		{"credential too short", strings.Replace(good, "ui-prod", "ui", 1), false},
		{"credential starting with a dash", strings.Replace(good, "ui-prod", "-ui-prod", 1), false},
		{"credential with a comma", strings.Replace(good, "ui-prod", "ui,prod", 1), false},
		{"time with a leading zero", strings.Replace(good, "ts=1791201600", "ts=01791201600", 1), false},
		{"time zero", strings.Replace(good, "ts=1791201600", "ts=0", 1), false},
		{"time negative", strings.Replace(good, "ts=1791201600", "ts=-1", 1), false},
		{"time with a plus", strings.Replace(good, "ts=1791201600", "ts=+1791201600", 1), false},
		{"13-digit time", strings.Replace(good, "ts=1791201600", "ts=1791201600000", 1), false},
		{"time empty", strings.Replace(good, "ts=1791201600", "ts=", 1), false},
		{"time in hex", strings.Replace(good, "ts=1791201600", "ts=0x6ae1", 1), false},
		{"nonce short", strings.Replace(good, nonce, nonce[1:], 1), false},
		{"nonce upper case", strings.Replace(good, nonce, strings.Repeat("A", 32), 1), false},
		{"signature short", good[:len(good)-1], false},
		{"signature long", good + "A", false},
		{"signature with padding", good[:len(good)-1] + "=", false},
		{"signature not canonical", strings.Replace(good, sig, badTail, 1), false},
		{"signature with a plus", strings.Replace(good, sig, strings.Repeat("A", 85)+"+", 1), false},
		{"trailing newline", good + "\n", false},
		{"trailing space", good + " ", false},
		{"embedded newline", strings.Replace(good, ", ts", "\n, ts", 1), false},
		{"very long", good + strings.Repeat("A", 5000), false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h, err := ParseAuthHeader(row.in)
			if (err == nil) != row.ok {
				t.Fatalf("err = %v, want ok = %v", err, row.ok)
			}
			if row.ok {
				if h.Credential != "ui-prod" || h.Timestamp != 1791201600 || h.Nonce != nonce || len(h.Signature) != 64 {
					t.Fatalf("parsed %+v", h)
				}
				if h.String() != row.in {
					t.Fatalf("does not round-trip: %q", h.String())
				}
			}
		})
	}
}

func TestTenantFromTarget(t *testing.T) {
	a := strings.Repeat("a", 32)
	rows := []struct{ in, want string }{
		{"/v1/tenants/" + a + "/policy", a},
		{"/v1/tenants/" + a, a},
		{"/v1/tenants/" + a + "?x=1", a},
		{"/v1/tenants/" + a + "x/policy", ""},
		{"/v1/tenants/" + a[:31] + "/policy", ""},
		{"/v1/tenants/" + strings.ToUpper(a) + "/policy", ""},
		{"/v1/credentials", ""},
		{"/v1/tenants/", ""},
		{"/healthz", ""},
		{"/v1/tenants/" + strings.Repeat("g", 32) + "/policy", ""},
		{"", ""},
	}
	for _, row := range rows {
		t.Run(row.in, func(t *testing.T) {
			if got := TenantFromTarget(row.in); got != row.want {
				t.Fatalf("got %q, want %q", got, row.want)
			}
		})
	}
}

func TestEverySingleTimestampSpellingIsOne(t *testing.T) {
	// the text that is signed is the text that is parsed: no leading zeros, so no two spellings of one number
	for _, s := range []string{"1", "10", "1791201600", "999999999999"} {
		n, ok := parseTimestamp(s)
		if !ok || strconv.FormatInt(n, 10) != s {
			t.Fatalf("%q: %d %v", s, n, ok)
		}
	}
	for _, s := range []string{"", "0", "01", "00", "1e3", " 1", "1 ", "1000000000000", "-1", "+1", "١"} {
		if _, ok := parseTimestamp(s); ok {
			t.Fatalf("%q accepted", s)
		}
	}
}
