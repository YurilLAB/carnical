// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func goodCredential(t *testing.T) Credential {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Credential{ID: "ui-prod", Label: "customer UI", Certs: []Fingerprint{sha256.Sum256([]byte("cert"))}, SigningKey: pub, Tenants: []string{tenantA},
		Scopes: []Scope{ScopeRead, ScopeWrite}, NotAfter: epoch.Add(time.Hour)}
}

func TestCredentialValidate(t *testing.T) {
	rows := []struct {
		name   string
		change func(c *Credential)
		ok     bool
	}{
		{"good", func(c *Credential) {}, true},
		{"all tenants", func(c *Credential) { c.Tenants, c.AllTenants = nil, true }, true},
		{"two tenants", func(c *Credential) { c.Tenants = []string{tenantA, tenantB} }, true},
		{"every scope", func(c *Credential) {
			c.Scopes = []Scope{ScopeRead, ScopeWrite, ScopePublish, ScopeAdmin, ScopeRawAddresses}
		}, true},
		{"sources", func(c *Credential) {
			c.Sources = []netipPrefix{mustPrefix("203.0.113.0/24"), mustPrefix("2001:db8::/32"), mustPrefix("198.51.100.7/32")}
		}, true},
		{"no label", func(c *Credential) { c.Label = "" }, true},
		{"id too short", func(c *Credential) { c.ID = "ab" }, false},
		{"id upper case", func(c *Credential) { c.ID = "Ui-Prod" }, false},
		{"id with a space", func(c *Credential) { c.ID = "ui prod" }, false},
		{"id starting with a dash", func(c *Credential) { c.ID = "-ui" }, false},
		{"id of 48 characters", func(c *Credential) { c.ID = strings.Repeat("a", 48) }, true},
		{"id of 49 characters", func(c *Credential) { c.ID = strings.Repeat("a", 49) }, false},
		{"id empty", func(c *Credential) { c.ID = "" }, false},
		{"label with a newline", func(c *Credential) { c.Label = "a\nb" }, false},
		{"label too long", func(c *Credential) { c.Label = strings.Repeat("a", 81) }, false},
		{"no certificates", func(c *Credential) { c.Certs = nil }, false},
		{"a certificate listed twice", func(c *Credential) { c.Certs = append(c.Certs, c.Certs[0]) }, false},
		{"17 certificates", func(c *Credential) {
			c.Certs = nil
			for i := 0; i < 17; i++ {
				c.Certs = append(c.Certs, sha256.Sum256([]byte{byte(i)}))
			}
		}, false},
		{"no signing key", func(c *Credential) { c.SigningKey = nil }, false},
		{"a short signing key", func(c *Credential) { c.SigningKey = c.SigningKey[:31] }, false},
		{"neither tenants nor all", func(c *Credential) { c.Tenants = nil }, false},
		{"all and a list", func(c *Credential) { c.AllTenants = true }, false},
		{"a tenant that is not 32 hex", func(c *Credential) { c.Tenants = []string{"abc"} }, false},
		{"a tenant in upper case", func(c *Credential) { c.Tenants = []string{strings.ToUpper(tenantC)} }, false},
		{"a tenant twice", func(c *Credential) { c.Tenants = []string{tenantA, tenantA} }, false},
		{"no scopes", func(c *Credential) { c.Scopes = nil }, false},
		{"an unknown scope", func(c *Credential) { c.Scopes = []Scope{"root"} }, false},
		{"a scope twice", func(c *Credential) { c.Scopes = []Scope{ScopeRead, ScopeRead} }, false},
		{"a /0 source", func(c *Credential) { c.Sources = []netipPrefix{mustPrefix("0.0.0.0/0")} }, false},
		{"a /0 IPv6 source", func(c *Credential) { c.Sources = []netipPrefix{mustPrefix("::/0")} }, false},
		{"an invalid source", func(c *Credential) { c.Sources = []netipPrefix{{}} }, false},
		{"no expiry", func(c *Credential) { c.NotAfter = time.Time{} }, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			c := goodCredential(t)
			row.change(&c)
			if err := c.Validate(); (err == nil) != row.ok {
				t.Fatalf("err = %v, want ok = %v", err, row.ok)
			}
		})
	}
}

func TestCredentialRules(t *testing.T) {
	c := goodCredential(t)
	c.Tenants = []string{tenantA, tenantB}
	c.Sources = []netipPrefix{mustPrefix("203.0.113.0/24"), mustPrefix("2001:db8::/32")}
	t.Run("tenants", func(t *testing.T) {
		for _, tc := range []struct {
			tenant string
			all    bool
			want   bool
		}{{tenantA, false, true}, {tenantB, false, true}, {tenantC, false, false}, {"", false, false}, {tenantA + "x", false, false}, {strings.ToUpper(tenantA), false, false}, {"all", false, false}} {
			if got := c.AllowsTenant(tc.tenant, tc.all); got != tc.want {
				t.Fatalf("AllowsTenant(%q) = %v", tc.tenant, got)
			}
		}
		all := goodCredential(t)
		all.Tenants, all.AllTenants = nil, true
		if !all.AllowsTenant(tenantC, true) || all.AllowsTenant(tenantC, false) || all.AllowsTenant("nonsense", true) {
			t.Fatal("all-tenants rules")
		}
	})
	t.Run("sources", func(t *testing.T) {
		for _, tc := range []struct {
			addr string
			want bool
		}{{"203.0.113.1", true}, {"203.0.113.255", true}, {"203.0.114.1", false}, {"2001:db8::1", true}, {"2001:db9::1", false}, {"::ffff:203.0.113.9", true}, {"198.51.100.1", false}} {
			if got := c.AllowsSource(ip(tc.addr)); got != tc.want {
				t.Fatalf("AllowsSource(%s) = %v", tc.addr, got)
			}
		}
		open := goodCredential(t)
		if !open.AllowsSource(ip("192.0.2.1")) || !open.AllowsSource(netipAddrZero()) {
			t.Fatal("a credential with no list allows every address, including one that did not parse")
		}
		if c.AllowsSource(netipAddrZero()) {
			t.Fatal("a credential with a list allowed an address that did not parse")
		}
	})
	t.Run("scopes", func(t *testing.T) {
		if !c.HasScope(ScopeRead) || c.HasScope(ScopeAdmin) || c.HasScope("") {
			t.Fatal("scopes")
		}
	})
	t.Run("certificates", func(t *testing.T) {
		other := sha256.Sum256([]byte("other"))
		c2 := c
		c2.Certs = []Fingerprint{sha256.Sum256([]byte("x")), c.Certs[0], other}
		if !c2.MatchesCert(c.Certs[0]) || !c2.MatchesCert(other) || c2.MatchesCert(Fingerprint{}) || c.MatchesCert(other) {
			t.Fatal("certificate matching")
		}
		if (&Credential{}).MatchesCert(Fingerprint{}) {
			t.Fatal("a credential with no certificates matched the zero fingerprint")
		}
	})
}

func TestParseCredentials(t *testing.T) {
	c := goodCredential(t)
	c.Sources = []netipPrefix{mustPrefix("203.0.113.0/24")}
	rec := c.Record()
	file := func(recs ...CredentialRecord) string {
		b, _ := json.Marshal(map[string]any{"credentials": recs})
		return string(b)
	}
	edit := func(f func(r *CredentialRecord)) string {
		r := rec
		f(&r)
		return file(r)
	}
	key := base64.RawURLEncoding.EncodeToString(c.SigningKey)
	rows := []struct {
		name string
		in   string
		ok   bool
	}{
		{"one credential", file(rec), true},
		{"none", `{"credentials":[]}`, true},
		{"all tenants", edit(func(r *CredentialRecord) { r.Tenants = json.RawMessage(`"all"`) }), true},
		{"a single address as a source", edit(func(r *CredentialRecord) { r.Sources = []string{"203.0.113.9", "2001:db8::1"} }), true},
		{"not JSON", `credentials`, false},
		{"an array at the top", `[]`, false},
		{"an unknown top-level field", `{"credentials":[],"x":1}`, false},
		{"an unknown field in a credential", strings.Replace(file(rec), `"revoked":false`, `"revoked":false,"admin":true`, 1), false},
		{"a repeated key", strings.Replace(file(rec), `"id":"ui-prod"`, `"id":"ui-prod","id":"other-id"`, 1), false},
		{"two credentials with one id", file(rec, rec), false},
		{"trailing data", file(rec) + ` {}`, false},
		{"a bad fingerprint", edit(func(r *CredentialRecord) { r.CertSPKI = []string{"abc"} }), false},
		{"an upper-case fingerprint", edit(func(r *CredentialRecord) { r.CertSPKI = []string{strings.ToUpper(r.CertSPKI[0])} }), false},
		{"a bad signing key", edit(func(r *CredentialRecord) { r.SigningKey = key[:20] }), false},
		{"a signing key with padding", edit(func(r *CredentialRecord) { r.SigningKey = key + "=" }), false},
		{"tenants as a number", edit(func(r *CredentialRecord) { r.Tenants = json.RawMessage(`5`) }), false},
		{"tenants as another word", edit(func(r *CredentialRecord) { r.Tenants = json.RawMessage(`"everything"`) }), false},
		{"tenants missing", edit(func(r *CredentialRecord) { r.Tenants = nil }), false},
		{"a bad tenant", edit(func(r *CredentialRecord) { r.Tenants = json.RawMessage(`["nope"]`) }), false},
		{"an unknown scope", edit(func(r *CredentialRecord) { r.Scopes = []string{"read", "root"} }), false},
		{"a source that is not an address", edit(func(r *CredentialRecord) { r.Sources = []string{"everywhere"} }), false},
		{"a /0 source", edit(func(r *CredentialRecord) { r.Sources = []string{"0.0.0.0/0"} }), false},
		{"a bad expiry", edit(func(r *CredentialRecord) { r.NotAfter = "tomorrow" }), false},
		{"no expiry", edit(func(r *CredentialRecord) { r.NotAfter = "" }), false},
		{"one good and one bad", file(rec, func() CredentialRecord { r := rec; r.ID = "other-id"; r.Scopes = nil; return r }()), false},
		{"a file over 4 MiB", `{"credentials":[],"pad":"` + strings.Repeat("a", 5<<20) + `"}`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_, err := ParseCredentials(strings.NewReader(row.in))
			if (err == nil) != row.ok {
				t.Fatalf("err = %v, want ok = %v", err, row.ok)
			}
		})
	}
	t.Run("the record round-trips", func(t *testing.T) {
		b, err := MarshalCredentials([]Credential{c})
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseCredentials(bytes.NewReader(b))
		if err != nil || len(back) != 1 {
			t.Fatalf("%v", err)
		}
		g := back[0]
		if g.ID != c.ID || !bytes.Equal(g.SigningKey, c.SigningKey) || g.Certs[0] != c.Certs[0] || g.Tenants[0] != c.Tenants[0] || len(g.Scopes) != 2 ||
			g.Sources[0] != c.Sources[0] || !g.NotAfter.Equal(c.NotAfter) || g.Revoked {
			t.Fatalf("%+v", g)
		}
	})
	t.Run("a stored credential holds no secret", func(t *testing.T) {
		b, _ := MarshalCredentials([]Credential{c})
		if strings.Contains(strings.ToLower(string(b)), "private") || strings.Contains(string(b), "seed") {
			t.Fatalf("%s", b)
		}
	})
	t.Run("fingerprints parse and print", func(t *testing.T) {
		f := sha256.Sum256([]byte("x"))
		got, err := ParseFingerprint(hex.EncodeToString(f[:]))
		if err != nil || got != f || got.String() != hex.EncodeToString(f[:]) {
			t.Fatal("round trip")
		}
		for _, bad := range []string{"", "zz", strings.Repeat("g", 64), strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
			if _, err := ParseFingerprint(bad); err == nil {
				t.Fatalf("%q accepted", bad)
			}
		}
	})
}

func TestCredentialSet(t *testing.T) {
	a := goodCredential(t)
	b := goodCredential(t)
	b.ID = "ui-staging"
	s, err := NewCredentialSet(a, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("lookup returns a copy", func(t *testing.T) {
		got, ok := s.Lookup("ui-prod")
		if !ok {
			t.Fatal("not found")
		}
		got.Scopes[0] = ScopeAdmin
		got.Tenants[0] = tenantC
		got.Certs[0] = Fingerprint{}
		got.SigningKey[0] ^= 0xff
		again, _ := s.Lookup("ui-prod")
		if again.Scopes[0] != ScopeRead || again.Tenants[0] != tenantA || again.Certs[0] == (Fingerprint{}) || again.SigningKey[0] != a.SigningKey[0] {
			t.Fatal("a caller changed a stored credential")
		}
		if _, ok := s.Lookup("nobody"); ok {
			t.Fatal("found a credential that is not there")
		}
	})
	t.Run("the credential handed in is copied", func(t *testing.T) {
		x := goodCredential(t)
		x.ID = "copied-one"
		set, _ := NewCredentialSet(x)
		x.Scopes[0] = ScopeAdmin
		if got, _ := set.Lookup("copied-one"); got.Scopes[0] != ScopeRead {
			t.Fatal("the set shares memory with its input")
		}
	})
	t.Run("list is sorted", func(t *testing.T) {
		l := s.List()
		if len(l) != 2 || l[0].ID != "ui-prod" || l[1].ID != "ui-staging" {
			t.Fatalf("%v", l)
		}
	})
	t.Run("revoke", func(t *testing.T) {
		if was, err := s.Revoke("ui-prod"); !was || err != nil {
			t.Fatalf("%v %v", was, err)
		}
		if was, _ := s.Revoke("ui-prod"); was {
			t.Fatal("revoked twice")
		}
		if was, _ := s.Revoke("nobody"); was {
			t.Fatal("revoked a credential that is not there")
		}
		if got, _ := s.Lookup("ui-prod"); !got.Revoked {
			t.Fatal("not revoked")
		}
	})
	t.Run("a set with a bad or duplicate credential is refused whole", func(t *testing.T) {
		bad := goodCredential(t)
		bad.Scopes = nil
		if _, err := NewCredentialSet(a, bad); err == nil {
			t.Fatal("a bad credential was accepted")
		}
		if _, err := NewCredentialSet(a, a); err == nil {
			t.Fatal("a duplicate was accepted")
		}
		before := s.List()
		if err := s.Replace([]Credential{bad}); err == nil {
			t.Fatal("replaced with a bad set")
		}
		if len(s.List()) != len(before) {
			t.Fatal("a refused replacement changed the set")
		}
	})
}

func TestCredentialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	a, b := goodCredential(t), goodCredential(t)
	b.ID = "ui-staging"
	write := func(cs ...Credential) {
		data, err := MarshalCredentials(cs)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	touch := func(d time.Duration) {
		when := time.Now().Add(d)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	clock := &fakeClock{t: epoch}
	write(a)
	f, err := OpenCredentialFile(path, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Lookup("ui-prod"); !ok {
		t.Fatal("not loaded")
	}
	if _, ok := f.Lookup("ui-staging"); ok {
		t.Fatal("found one that is not in the file")
	}

	t.Run("an edit is picked up without a restart", func(t *testing.T) {
		write(a, b)
		touch(time.Minute)
		clock.advance(2 * time.Second)
		if _, ok := f.Lookup("ui-staging"); !ok {
			t.Fatal("the edit was not seen")
		}
		if len(f.List()) != 2 {
			t.Fatal("list")
		}
	})
	t.Run("a file that no longer parses leaves the last good one in force", func(t *testing.T) {
		if err := os.WriteFile(path, []byte(`{"credentials": [ nonsense`), 0o600); err != nil {
			t.Fatal(err)
		}
		touch(2 * time.Minute)
		clock.advance(2 * time.Second)
		if _, ok := f.Lookup("ui-prod"); !ok {
			t.Fatal("the good set was dropped")
		}
		if f.LastError() == nil {
			t.Fatal("no error reported")
		}
		// a file that parses but weakens nothing it should not: a bad credential in it refuses the whole file
		c := goodCredential(t)
		c.ID = "ui-prod"
		c.Scopes = nil
		data, _ := json.Marshal(map[string]any{"credentials": []CredentialRecord{c.Record()}})
		_ = os.WriteFile(path, data, 0o600)
		touch(3 * time.Minute)
		clock.advance(2 * time.Second)
		got, ok := f.Lookup("ui-prod")
		if !ok || len(got.Scopes) == 0 {
			t.Fatal("a credential with its scopes removed by a typo took effect")
		}
		write(a, b)
		touch(4 * time.Minute)
		clock.advance(2 * time.Second)
		f.Lookup("ui-prod")
		if f.LastError() != nil {
			t.Fatalf("the error stayed after the file was fixed: %v", f.LastError())
		}
	})
	t.Run("a revocation is written to the file and survives a restart", func(t *testing.T) {
		was, err := f.Revoke("ui-staging")
		if err != nil || !was {
			t.Fatalf("%v %v", was, err)
		}
		if got, _ := f.Lookup("ui-staging"); !got.Revoked {
			t.Fatal("not revoked in memory")
		}
		reopened, err := OpenCredentialFile(path, clock.now)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := reopened.Lookup("ui-staging"); !got.Revoked {
			t.Fatal("not revoked on disk")
		}
		if got, _ := reopened.Lookup("ui-prod"); got.Revoked {
			t.Fatal("another credential was revoked")
		}
		if runtime.GOOS != "windows" {
			st, _ := os.Stat(path)
			if st.Mode().Perm() != 0o600 {
				t.Fatalf("mode %o", st.Mode().Perm())
			}
		}
		if was, _ := f.Revoke("ui-staging"); was {
			t.Fatal("revoked twice")
		}
		if was, _ := f.Revoke("nobody"); was {
			t.Fatal("revoked a credential that is not there")
		}
		// no temporary file is left behind
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 {
			t.Fatalf("%d files in the directory", len(entries))
		}
	})
	t.Run("a revocation does not undo an edit made meanwhile", func(t *testing.T) {
		c := goodCredential(t)
		c.ID = "ui-third"
		write(a, b, c)
		touch(5 * time.Minute)
		// no clock advance: Revoke itself looks at the file first
		if _, err := f.Revoke("ui-prod"); err != nil {
			t.Fatal(err)
		}
		if _, ok := f.Lookup("ui-third"); !ok {
			t.Fatal("the credential added by hand was lost")
		}
	})
	t.Run("a file that is not there or not valid is not opened", func(t *testing.T) {
		if _, err := OpenCredentialFile(filepath.Join(dir, "missing.json"), nil); err == nil {
			t.Fatal("opened a missing file")
		}
		bad := filepath.Join(dir, "bad.json")
		_ = os.WriteFile(bad, []byte(`{}`), 0o600)
		if _, err := OpenCredentialFile(bad, nil); err != nil {
			t.Fatalf("an empty set should be fine: %v", err)
		}
		_ = os.WriteFile(bad, []byte(`not json`), 0o600)
		if _, err := OpenCredentialFile(bad, nil); err == nil {
			t.Fatal("opened a file that is not JSON")
		}
	})
}

func netipAddrZero() netip.Addr { return netip.Addr{} }
