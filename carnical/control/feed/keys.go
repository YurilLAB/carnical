// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
)

// The things a key may be allowed to read.
const (
	ScopeEvents  = "events"
	ScopeTraffic = "traffic"
	ScopeIPs     = "ips"
	ScopeHealth  = "health"
	ScopeMarks   = "marks"
)

// scopeOrder is the order scopes are listed in an answer, as the PHP console lists them.
var scopeOrder = []string{ScopeEvents, ScopeTraffic, ScopeIPs, ScopeHealth, ScopeMarks}

// Key is one sharing key: one site, one secret, a set of scopes and a choice of how addresses are shown. The id is
// 16 hex digits, the secret 32 bytes. A key reads exactly one site.
type Key struct {
	ID        string
	SiteID    string // 32 lower-case hex digits
	Secret    []byte // 32 bytes
	Scopes    []string
	Addresses string // "cut" (the default) or "whole"
	Revoked   bool
}

// KeyStore finds a key by its id. Implementations must be safe for concurrent use. The handler never changes a Key
// and never keeps its Secret beyond the request.
type KeyStore interface {
	Lookup(id string) (Key, bool)
}

// MemoryKeys is a KeyStore held in memory, for tests and for small deployments that load their keys at start.
type MemoryKeys struct {
	mu   sync.RWMutex
	keys map[string]Key
}

// NewMemoryKeys returns an empty store.
func NewMemoryKeys() *MemoryKeys { return &MemoryKeys{keys: map[string]Key{}} }

// Add stores a key after checking its shape.
func (m *MemoryKeys) Add(k Key) error {
	if !isLowerHex(k.ID, 16) {
		return errors.New("feed: a key id is 16 hex digits")
	}
	if !isLowerHex(k.SiteID, 32) {
		return errors.New("feed: a site id is 32 hex digits")
	}
	if len(k.Secret) != 32 {
		return errors.New("feed: a secret is 32 bytes")
	}
	if k.Addresses != "cut" && k.Addresses != "whole" {
		return errors.New("feed: addresses are cut or whole")
	}
	if len(k.Scopes) == 0 {
		return errors.New("feed: a key needs at least one scope")
	}
	for _, s := range k.Scopes {
		if !validScope(s) {
			return errors.New("feed: unknown scope")
		}
	}
	k.Secret = append([]byte(nil), k.Secret...)
	k.Scopes = append([]string(nil), k.Scopes...)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.keys[k.ID]; dup {
		return errors.New("feed: that key id exists")
	}
	m.keys[k.ID] = k
	return nil
}

// Revoke marks a key revoked. It reports whether the key was in force.
func (m *MemoryKeys) Revoke(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok || k.Revoked {
		return false
	}
	k.Revoked = true
	m.keys[id] = k
	return true
}

// Lookup implements KeyStore. It returns a copy, so a caller cannot change the stored key.
func (m *MemoryKeys) Lookup(id string) (Key, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k, ok := m.keys[id]
	if !ok {
		return Key{}, false
	}
	k.Secret = append([]byte(nil), k.Secret...)
	k.Scopes = append([]string(nil), k.Scopes...)
	return k, true
}

func validScope(s string) bool {
	for _, o := range scopeOrder {
		if s == o {
			return true
		}
	}
	return false
}

// GenerateKey makes a key for a site: a random id and a random 32-byte secret. The text form of the secret (43
// characters of base64url) is what the owner pastes into the console and is shown once.
func GenerateKey(siteID string, scopes []string, addresses string) (Key, string, error) {
	var idb [8]byte
	secret := make([]byte, 32)
	if _, err := rand.Read(idb[:]); err != nil {
		return Key{}, "", err
	}
	if _, err := rand.Read(secret); err != nil {
		return Key{}, "", err
	}
	k := Key{ID: hex.EncodeToString(idb[:]), SiteID: siteID, Secret: secret, Scopes: scopes, Addresses: addresses}
	if err := NewMemoryKeys().Add(k); err != nil {
		return Key{}, "", err
	}
	return k, SecretText(secret), nil
}
