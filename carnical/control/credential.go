// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Scope is one thing a credential may be allowed to do.
type Scope string

// The scopes. They do not imply each other: a credential that may publish but not read cannot read.
const (
	ScopeRead         Scope = "read"
	ScopeWrite        Scope = "write"
	ScopePublish      Scope = "publish"
	ScopeAdmin        Scope = "admin"
	ScopeRawAddresses Scope = "raw-addresses" // see addresses whole instead of cut to /24 and /48
)

var allScopes = []Scope{ScopeRead, ScopeWrite, ScopePublish, ScopeAdmin, ScopeRawAddresses}

func validScope(s Scope) bool {
	for _, a := range allScopes {
		if s == a {
			return true
		}
	}
	return false
}

// Fingerprint is the SHA-256 of a certificate's SubjectPublicKeyInfo. Pinning the key, not the certificate, lets a
// certificate be renewed on the same key without touching the credential.
type Fingerprint [sha256.Size]byte

// SPKIFingerprint returns the fingerprint of a certificate's public key.
func SPKIFingerprint(c *x509.Certificate) Fingerprint {
	return sha256.Sum256(c.RawSubjectPublicKeyInfo)
}

// String is the fingerprint in lower-case hex.
func (f Fingerprint) String() string { return hex.EncodeToString(f[:]) }

// ParseFingerprint reads 64 lower-case hex digits.
func ParseFingerprint(s string) (Fingerprint, error) {
	var f Fingerprint
	if len(s) != 64 || !isLowerHex(s) {
		return f, errors.New("a fingerprint is 64 lower-case hex digits")
	}
	_, err := hex.Decode(f[:], []byte(s))
	return f, err
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

var (
	credIDRE   = regexp.MustCompile(`\A[a-z0-9][a-z0-9-]{2,47}\z`)
	tenantIDRE = regexp.MustCompile(`\A[0-9a-f]{32}\z`)
)

// ValidCredentialID reports whether s is the form of a credential id: 3 to 48 characters of a-z, 0-9 and dash,
// not starting with a dash.
func ValidCredentialID(s string) bool { return credIDRE.MatchString(s) }

// ValidTenantID reports whether s is a tenant id: exactly 32 lower-case hex digits (docs/segmentation.md rule T1).
func ValidTenantID(s string) bool { return tenantIDRE.MatchString(s) }

// Credential is one UI deployment's right to call the API. It is data only: nothing in it is a secret (the Ed25519
// key held here is the public half).
type Credential struct {
	ID    string
	Label string
	// Certs are the fingerprints of the client certificate keys this credential may connect with.
	Certs []Fingerprint
	// SigningKey is the public key whose private half the UI signs requests with.
	SigningKey ed25519.PublicKey
	// Tenants lists the tenants it may act for. AllTenants is for the owner's own tooling and is ignored unless the
	// server is configured to allow it (Config.AllowAllTenants).
	Tenants    []string
	AllTenants bool
	Scopes     []Scope
	// Sources, when not empty, are the only addresses it may connect from.
	Sources []netip.Prefix
	// NotAfter is the end of its validity. Every credential has one.
	NotAfter time.Time
	Revoked  bool
}

// HasScope reports whether the credential holds a scope.
func (c *Credential) HasScope(s Scope) bool {
	for _, x := range c.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

// AllowsTenant reports whether it may act for the tenant. allTenantsOK says whether this server honours AllTenants.
func (c *Credential) AllowsTenant(t string, allTenantsOK bool) bool {
	if !ValidTenantID(t) {
		return false
	}
	if c.AllTenants {
		return allTenantsOK
	}
	for _, x := range c.Tenants {
		if x == t {
			return true
		}
	}
	return false
}

// AllowsSource reports whether a connection from addr is allowed. With no list, every address is.
func (c *Credential) AllowsSource(addr netip.Addr) bool {
	if len(c.Sources) == 0 {
		return true
	}
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, p := range c.Sources {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// MatchesCert reports whether fp is one of the credential's. It looks at every one whatever it finds, in constant
// time for each comparison, so the time does not say which entry matched.
func (c *Credential) MatchesCert(fp Fingerprint) bool {
	match := 0
	for i := range c.Certs {
		match |= subtle.ConstantTimeCompare(c.Certs[i][:], fp[:])
	}
	return match == 1
}

// Validate checks the shape of a credential. A credential that does not validate is never loaded.
func (c *Credential) Validate() error {
	if !ValidCredentialID(c.ID) {
		return errors.New("the id must be 3 to 48 characters of a-z, 0-9 and dash, not starting with a dash")
	}
	if len(c.Label) > 80 || !printable(c.Label) {
		return errors.New("the label must be printable text of at most 80 characters")
	}
	if len(c.Certs) == 0 || len(c.Certs) > 16 {
		return errors.New("a credential needs 1 to 16 certificate fingerprints")
	}
	seen := map[Fingerprint]bool{}
	for _, f := range c.Certs {
		if seen[f] {
			return errors.New("a certificate fingerprint is listed twice")
		}
		seen[f] = true
	}
	if len(c.SigningKey) != ed25519.PublicKeySize {
		return errors.New("the signing key must be an Ed25519 public key")
	}
	if c.AllTenants {
		if len(c.Tenants) != 0 {
			return errors.New("a credential is for all tenants or for a list, not both")
		}
	} else {
		if len(c.Tenants) == 0 || len(c.Tenants) > 10000 {
			return errors.New("a credential needs at least one tenant (or all)")
		}
		t := map[string]bool{}
		for _, id := range c.Tenants {
			if !ValidTenantID(id) {
				return errors.New("a tenant id is 32 lower-case hex digits")
			}
			if t[id] {
				return errors.New("a tenant is listed twice")
			}
			t[id] = true
		}
	}
	if len(c.Scopes) == 0 {
		return errors.New("a credential needs at least one scope")
	}
	sc := map[Scope]bool{}
	for _, s := range c.Scopes {
		if !validScope(s) {
			return errors.New("unknown scope")
		}
		if sc[s] {
			return errors.New("a scope is listed twice")
		}
		sc[s] = true
	}
	if len(c.Sources) > 64 {
		return errors.New("at most 64 source ranges")
	}
	for _, p := range c.Sources {
		if !p.IsValid() {
			return errors.New("a source range is not valid")
		}
		if p.Bits() == 0 {
			return errors.New("a source range of /0 allows every address; leave the list empty instead")
		}
	}
	if c.NotAfter.IsZero() {
		return errors.New("a credential needs a not-after date")
	}
	return nil
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------------------------------------ stored form

// CredentialRecord is the JSON form of a credential. A file of them is what the owner edits.
type CredentialRecord struct {
	ID         string          `json:"id"`
	Label      string          `json:"label,omitempty"`
	CertSPKI   []string        `json:"cert_spki"`
	SigningKey string          `json:"signing_key"`
	Tenants    json.RawMessage `json:"tenants"` // a list of tenant ids, or "all"
	Scopes     []string        `json:"scopes"`
	Sources    []string        `json:"sources,omitempty"`
	NotAfter   string          `json:"not_after"`
	Revoked    bool            `json:"revoked"`
}

type credentialFile struct {
	Credentials []CredentialRecord `json:"credentials"`
}

// ParseCredentials reads a credentials file: {"credentials": [...]}. It is strict (no unknown fields, no duplicate ids,
// no trailing data) and refuses the whole file if any credential is wrong, so a typo cannot silently remove a
// restriction.
func ParseCredentials(r io.Reader) ([]Credential, error) {
	b, err := io.ReadAll(io.LimitReader(r, 4<<20+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 4<<20 {
		return nil, errors.New("control: the credentials file is larger than 4 MiB")
	}
	if err := checkJSON(b, 16); err != nil {
		return nil, fmt.Errorf("control: credentials: %w", err)
	}
	var f credentialFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("control: credentials: %w", err)
	}
	if len(f.Credentials) > 1000 {
		return nil, errors.New("control: more than 1000 credentials")
	}
	out := make([]Credential, 0, len(f.Credentials))
	ids := map[string]bool{}
	for i, rec := range f.Credentials {
		c, err := rec.Credential()
		if err != nil {
			return nil, fmt.Errorf("control: credential %d: %w", i+1, err)
		}
		if ids[c.ID] {
			return nil, fmt.Errorf("control: credential id %q appears twice", c.ID)
		}
		ids[c.ID] = true
		out = append(out, c)
	}
	return out, nil
}

// Credential converts and validates a record.
func (r CredentialRecord) Credential() (Credential, error) {
	c := Credential{ID: r.ID, Label: r.Label, Revoked: r.Revoked}
	for _, s := range r.CertSPKI {
		f, err := ParseFingerprint(s)
		if err != nil {
			return Credential{}, err
		}
		c.Certs = append(c.Certs, f)
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(r.SigningKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return Credential{}, errors.New("signing_key must be 43 characters of base64url (an Ed25519 public key)")
	}
	c.SigningKey = ed25519.PublicKey(key)
	if len(r.Tenants) == 0 {
		return Credential{}, errors.New("tenants is required")
	}
	var all string
	if json.Unmarshal(r.Tenants, &all) == nil {
		if all != "all" {
			return Credential{}, errors.New(`tenants must be a list of tenant ids or "all"`)
		}
		c.AllTenants = true
	} else if err := json.Unmarshal(r.Tenants, &c.Tenants); err != nil {
		return Credential{}, errors.New(`tenants must be a list of tenant ids or "all"`)
	}
	for _, s := range r.Scopes {
		c.Scopes = append(c.Scopes, Scope(s))
	}
	for _, s := range r.Sources {
		if p, err := netip.ParsePrefix(s); err == nil {
			c.Sources = append(c.Sources, p.Masked())
		} else if a, err := netip.ParseAddr(s); err == nil {
			c.Sources = append(c.Sources, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		} else {
			return Credential{}, errors.New("a source is an address or a range")
		}
	}
	na, err := time.Parse(time.RFC3339, r.NotAfter)
	if err != nil {
		return Credential{}, errors.New("not_after must be an RFC 3339 time")
	}
	c.NotAfter = na.UTC()
	if err := c.Validate(); err != nil {
		return Credential{}, err
	}
	return c, nil
}

// Record is the inverse of CredentialRecord.Credential.
func (c Credential) Record() CredentialRecord {
	r := CredentialRecord{ID: c.ID, Label: c.Label, SigningKey: base64.RawURLEncoding.EncodeToString(c.SigningKey),
		NotAfter: c.NotAfter.UTC().Format(time.RFC3339), Revoked: c.Revoked, CertSPKI: []string{}, Scopes: []string{}}
	for _, f := range c.Certs {
		r.CertSPKI = append(r.CertSPKI, f.String())
	}
	if c.AllTenants {
		r.Tenants = json.RawMessage(`"all"`)
	} else {
		b, _ := json.Marshal(append([]string{}, c.Tenants...))
		r.Tenants = b
	}
	for _, s := range c.Scopes {
		r.Scopes = append(r.Scopes, string(s))
	}
	for _, p := range c.Sources {
		r.Sources = append(r.Sources, p.String())
	}
	return r
}

// MarshalCredentials writes a credentials file.
func MarshalCredentials(cs []Credential) ([]byte, error) {
	f := credentialFile{Credentials: make([]CredentialRecord, 0, len(cs))}
	for _, c := range cs {
		f.Credentials = append(f.Credentials, c.Record())
	}
	return json.MarshalIndent(f, "", "  ")
}

// ------------------------------------------------------------------------------------------------ the stores

// CredentialStore finds credentials. Lookup is called on every request, so a revocation takes effect at once.
// Implementations must be safe for concurrent use and return copies.
type CredentialStore interface {
	Lookup(id string) (Credential, bool)
	// List returns every credential, sorted by id.
	List() []Credential
	// Revoke marks a credential revoked and reports whether it was in force.
	Revoke(id string) (bool, error)
}

// CredentialSet is a CredentialStore held in memory.
type CredentialSet struct {
	mu sync.RWMutex
	m  map[string]Credential
}

// NewCredentialSet validates and stores credentials.
func NewCredentialSet(cs ...Credential) (*CredentialSet, error) {
	s := &CredentialSet{}
	if err := s.Replace(cs); err != nil {
		return nil, err
	}
	return s, nil
}

// Replace swaps the whole set, after validating every credential.
func (s *CredentialSet) Replace(cs []Credential) error {
	m := make(map[string]Credential, len(cs))
	for _, c := range cs {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("control: credential %q: %w", c.ID, err)
		}
		if _, dup := m[c.ID]; dup {
			return fmt.Errorf("control: credential id %q appears twice", c.ID)
		}
		m[c.ID] = clone(c)
	}
	s.mu.Lock()
	s.m = m
	s.mu.Unlock()
	return nil
}

func clone(c Credential) Credential {
	c.Certs = append([]Fingerprint(nil), c.Certs...)
	c.SigningKey = append(ed25519.PublicKey(nil), c.SigningKey...)
	c.Tenants = append([]string(nil), c.Tenants...)
	c.Scopes = append([]Scope(nil), c.Scopes...)
	c.Sources = append([]netip.Prefix(nil), c.Sources...)
	return c
}

// Lookup implements CredentialStore.
func (s *CredentialSet) Lookup(id string) (Credential, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.m[id]
	if !ok {
		return Credential{}, false
	}
	return clone(c), true
}

// List implements CredentialStore.
func (s *CredentialSet) List() []Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Credential, 0, len(s.m))
	for _, c := range s.m {
		out = append(out, clone(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Revoke implements CredentialStore.
func (s *CredentialSet) Revoke(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[id]
	if !ok || c.Revoked {
		return false, nil
	}
	c.Revoked = true
	s.m[id] = c
	return true, nil
}

// CredentialFile is a CredentialStore kept in a JSON file. The file is re-read when its modification time or size
// changes (checked at most once a second), so the owner can edit it without a restart, and a revocation made through
// the API is written back, atomically, with mode 0600. A file that no longer parses is ignored and the last good set
// stays in force; LastError says why.
type CredentialFile struct {
	path string
	now  func() time.Time

	mu       sync.Mutex
	set      *CredentialSet
	sig      fileSig
	checked  time.Time
	lastErr  error
	failedAt fileSig
}

type fileSig struct {
	mod  time.Time
	size int64
}

// OpenCredentialFile loads the file. It fails if the file cannot be read or any credential in it is wrong.
func OpenCredentialFile(path string, now func() time.Time) (*CredentialFile, error) {
	if now == nil {
		now = time.Now
	}
	f := &CredentialFile{path: path, now: now}
	if err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *CredentialFile) load() error {
	fh, err := os.Open(f.path)
	if err != nil {
		return err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return err
	}
	cs, err := ParseCredentials(fh)
	if err != nil {
		return err
	}
	set, err := NewCredentialSet(cs...)
	if err != nil {
		return err
	}
	f.set, f.sig, f.lastErr = set, fileSig{st.ModTime(), st.Size()}, nil
	return nil
}

// refresh re-reads the file if it changed. It holds f.mu.
func (f *CredentialFile) refresh() {
	now := f.now()
	if now.Sub(f.checked) < time.Second {
		return
	}
	f.checked = now
	st, err := os.Stat(f.path)
	if err != nil {
		f.lastErr = err
		return
	}
	sig := fileSig{st.ModTime(), st.Size()}
	if sig == f.sig || sig == f.failedAt {
		return
	}
	if err := f.load(); err != nil {
		f.lastErr, f.failedAt = err, sig
	}
}

// LastError is the reason the file was last not (re)loaded, or nil.
func (f *CredentialFile) LastError() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastErr
}

// Lookup implements CredentialStore.
func (f *CredentialFile) Lookup(id string) (Credential, bool) {
	f.mu.Lock()
	f.refresh()
	set := f.set
	f.mu.Unlock()
	return set.Lookup(id)
}

// List implements CredentialStore.
func (f *CredentialFile) List() []Credential {
	f.mu.Lock()
	f.refresh()
	set := f.set
	f.mu.Unlock()
	return set.List()
}

// Revoke implements CredentialStore. The change is written to the file before it takes effect in memory.
func (f *CredentialFile) Revoke(id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checked = time.Time{}
	f.refresh()
	cs := f.set.List()
	found := false
	for i := range cs {
		if cs[i].ID == id {
			if cs[i].Revoked {
				return false, nil
			}
			cs[i].Revoked, found = true, true
		}
	}
	if !found {
		return false, nil
	}
	b, err := MarshalCredentials(cs)
	if err != nil {
		return false, err
	}
	if err := writeFileAtomic(f.path, b); err != nil {
		return false, err
	}
	if err := f.load(); err != nil {
		return false, err
	}
	return true, nil
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".credentials-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil && !isWindows() {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}
