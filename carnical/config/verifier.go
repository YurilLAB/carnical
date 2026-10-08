// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// Defaults and limits of a Verifier.
const (
	// DefaultMaxValidity is how long an envelope may be valid for, if the edge does not say otherwise. The control plane
	// re-signs well inside this (daily, say), so an envelope that has been lying around for longer is not one to accept.
	DefaultMaxValidity = 7 * 24 * time.Hour
	// DefaultClockSkew is how far this edge's clock may differ from the signer's.
	DefaultClockSkew = 2 * time.Minute
	// MaxClockSkew is the most skew a Verifier may be configured to forgive.
	MaxClockSkew = 15 * time.Minute
	// MaxTrustedKeys and MaxRevokedKeys bound a key list, as the release scheme's lists are bounded.
	MaxTrustedKeys = 50
	MaxRevokedKeys = 500
)

// TrustedKey is a public key that may sign configuration, with the dates between which it is believed.
type TrustedKey struct {
	// ID is KeyID(Public).
	ID string
	// Public is the 32-byte Ed25519 public key.
	Public ed25519.PublicKey
	// NotBefore and NotAfter bound when the key may be used (inclusive). They are compared with the time of acceptance.
	NotBefore, NotAfter time.Time
}

// NewTrustedKey makes a TrustedKey, working out its ID.
func NewTrustedKey(pub ed25519.PublicKey, notBefore, notAfter time.Time) (TrustedKey, error) {
	if len(pub) != ed25519.PublicKeySize {
		return TrustedKey{}, errors.New("config: not an Ed25519 public key")
	}
	if !notAfter.After(notBefore) {
		return TrustedKey{}, errors.New("config: a key's dates end before they start")
	}
	return TrustedKey{ID: KeyID(pub), Public: append(ed25519.PublicKey(nil), pub...), NotBefore: notBefore.UTC(), NotAfter: notAfter.UTC()}, nil
}

// VerifierConfig is what a Verifier is told about the edge it works for.
type VerifierConfig struct {
	// Audience is this edge's own id. An envelope for any other is refused.
	Audience string
	// Tenants are the tenants assigned to this edge. An envelope for any other is refused. It can be changed with SetTenants.
	Tenants []string
	// Store remembers the newest sequence number accepted for each tenant. It is required: a Verifier without one could
	// not refuse a replay.
	Store SeqStore
	// MaxValidity is the longest an envelope's validity may be (default DefaultMaxValidity).
	MaxValidity time.Duration
	// ClockSkew is how far outside its window an envelope is still taken as inside it (default DefaultClockSkew,
	// at most MaxClockSkew).
	ClockSkew time.Duration
}

// Verifier decides whether an envelope may be applied by one edge. It is safe for concurrent use; the keys and the
// tenant list can be replaced while it is in use.
//
// A Verifier starts with no trusted keys, so it refuses everything until SetKeys (or KeySet.Apply) has been called: an
// edge that has not yet received a signed key list enforces nothing it was not already holding.
type Verifier struct {
	audience string
	store    SeqStore
	maxValid time.Duration
	skew     time.Duration
	keys     atomic.Pointer[keyState]
	tenants  atomic.Pointer[map[string]struct{}]
}

type keyState struct {
	keys    map[string]TrustedKey
	revoked map[string]struct{}
	expires time.Time // zero: the list does not expire
}

// NewVerifier makes a Verifier.
func NewVerifier(c VerifierConfig) (*Verifier, error) {
	if !ValidAudience(c.Audience) {
		return nil, errors.New("config: the audience is not an edge id")
	}
	if c.Store == nil {
		return nil, errors.New("config: a Verifier needs a sequence store")
	}
	v := &Verifier{audience: c.Audience, store: c.Store, maxValid: c.MaxValidity, skew: c.ClockSkew}
	if v.maxValid == 0 {
		v.maxValid = DefaultMaxValidity
	}
	if v.maxValid < 0 || v.maxValid > MaxValidityCap {
		return nil, fmt.Errorf("config: the maximum validity must be positive and at most %s", MaxValidityCap)
	}
	if v.skew == 0 {
		v.skew = DefaultClockSkew
	}
	if v.skew < 0 || v.skew > MaxClockSkew {
		return nil, fmt.Errorf("config: the clock skew must be positive and at most %s", MaxClockSkew)
	}
	if err := v.SetTenants(c.Tenants); err != nil {
		return nil, err
	}
	return v, nil
}

// SetTenants replaces the tenants this edge is assigned. The new list applies to envelopes checked from now on.
func (v *Verifier) SetTenants(tenants []string) error {
	m := make(map[string]struct{}, len(tenants))
	for _, t := range tenants {
		if !ValidTenant(t) {
			return errors.New("config: a tenant id is not 32 lower-case hex digits")
		}
		m[t] = struct{}{}
	}
	v.tenants.Store(&m)
	return nil
}

// SetKeys replaces the trusted keys and the revoked key ids. expires, if not zero, is when the list stops being believed
// (the expiry of the signed key list it came from). Keys must be well formed: their IDs match their public keys, and at
// most MaxTrustedKeys are given. A revoked id wins over a listed key. The public keys are copied,
// so the caller may reuse its buffers after SetKeys returns.
func (v *Verifier) SetKeys(keys []TrustedKey, revoked []string, expires time.Time) error {
	if len(keys) > MaxTrustedKeys || len(revoked) > MaxRevokedKeys {
		return errors.New("config: the key list is longer than allowed")
	}
	st := &keyState{keys: make(map[string]TrustedKey, len(keys)), revoked: make(map[string]struct{}, len(revoked)), expires: expires}
	for _, k := range keys {
		if len(k.Public) != ed25519.PublicKeySize || k.ID != KeyID(k.Public) || !k.NotAfter.After(k.NotBefore) {
			return errors.New("config: a trusted key is not well formed")
		}
		if _, dup := st.keys[k.ID]; dup {
			return errors.New("config: a key is listed twice")
		}
		k.Public = append(ed25519.PublicKey(nil), k.Public...)
		st.keys[k.ID] = k
	}
	for _, id := range revoked {
		if !keyIDRe.MatchString(id) {
			return errors.New("config: a revoked key id is not 16 lower-case hex digits")
		}
		st.revoked[id] = struct{}{}
	}
	v.keys.Store(st)
	return nil
}

// Verify checks everything about an envelope except whether it is new: its size and shape, the key that signed it
// (listed, not revoked, inside its dates, and the list itself not out of date), the signature, that it is for this
// edge and for an assigned tenant, that its window is not empty or too long, and that now is inside it (give or take
// the clock skew). Then it refuses one older than what the edge has already accepted for the tenant, but it lets an
// envelope with the very same number through, and it records nothing, so that an edge can check again at start-up the
// envelope it is already running. An edge that is going to apply a new configuration calls Accept, never Verify.
func (v *Verifier) Verify(raw []byte, now time.Time) (*Envelope, error) {
	e, err := v.check(raw, now)
	if err != nil {
		return nil, err
	}
	last, err := v.store.Last(e.Tenant)
	if err != nil {
		return nil, err
	}
	if e.Sequence < last {
		return nil, ErrRollback
	}
	return e, nil
}

// Accept is Verify, and then, atomically with the check that the envelope's sequence number is higher than any this edge
// has accepted for the tenant, records it. Of any number of envelopes presented at once for one tenant, exactly those
// that were higher than everything accepted before them are accepted, and the highest of all always is; no number is
// accepted twice. Nothing is recorded for an envelope that fails any other check, so an envelope with a bad signature
// cannot use up a sequence number. If Accept returns an error, the edge keeps what it is running.
//
// The number is recorded before the edge applies the configuration. If the edge then fails to apply it (a payload it
// cannot compile), that sequence number is spent: the control plane has to sign the corrected configuration under a
// higher one.
func (v *Verifier) Accept(raw []byte, now time.Time) (*Envelope, error) {
	e, err := v.check(raw, now)
	if err != nil {
		return nil, err
	}
	if err := v.store.Advance(e.Tenant, e.Sequence); err != nil {
		return nil, err
	}
	return e, nil
}

// check is the order the refusals are decided in; see the notes on the Err values.
func (v *Verifier) check(raw []byte, now time.Time) (*Envelope, error) {
	if len(raw) > MaxEnvelopeBytes {
		return nil, ErrOversize
	}
	e, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	ks := v.keys.Load()
	if ks == nil {
		return nil, ErrUnknownKey
	}
	if !ks.expires.IsZero() && now.After(ks.expires) {
		return nil, ErrKeyListExpired
	}
	if _, bad := ks.revoked[e.KeyID]; bad {
		return nil, ErrRevokedKey
	}
	key, ok := ks.keys[e.KeyID]
	if !ok {
		return nil, ErrUnknownKey
	}
	if now.Before(key.NotBefore) || now.After(key.NotAfter) {
		return nil, ErrKeyNotValid
	}
	if !ed25519.Verify(key.Public, e.SigningBytes(), e.Signature) {
		return nil, ErrBadSignature
	}
	// From here on the envelope is what a trusted key signed, so what it says about itself can be believed and refused
	// on its merits.
	if e.Audience != v.audience {
		return nil, ErrWrongAudience
	}
	if _, assigned := (*v.tenants.Load())[e.Tenant]; !assigned {
		return nil, ErrWrongTenant
	}
	if w := e.NotAfter.Sub(e.NotBefore); w <= 0 || w > v.maxValid {
		return nil, ErrInvalidWindow
	}
	if now.Add(v.skew).Before(e.NotBefore) {
		return nil, ErrNotYetValid
	}
	if now.Add(-v.skew).After(e.NotAfter) {
		return nil, ErrExpired
	}
	return e, nil
}
