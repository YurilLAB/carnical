// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

// MaxValidityCap is the longest validity a Signer will give an envelope, whatever it is asked for. A Verifier applies its
// own, usually shorter, limit; this one only stops a bug or a hostile caller of the signer from minting an envelope that
// stays acceptable for years.
const MaxValidityCap = 31 * 24 * time.Hour

// Signer holds the configuration-signing key and makes envelopes. It belongs in the signer service (docs/segmentation.md,
// section 2): a different user from the control plane and the edge, which are never given the key. The key is not a
// release key and not the root key, so losing it cannot sign engine code or a key list.
//
// A Signer is safe for concurrent use. It does not decide which sequence number comes next; that is the control plane's
// record, and the number is part of what the signer is asked to sign.
type Signer struct {
	key   ed25519.PrivateKey
	keyID string
	now   func() time.Time
}

// NewSigner makes a Signer from an Ed25519 private key. The key is copied.
func NewSigner(key ed25519.PrivateKey) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("config: not an Ed25519 private key")
	}
	k := append(ed25519.PrivateKey(nil), key...)
	return &Signer{key: k, keyID: KeyID(k.Public().(ed25519.PublicKey)), now: time.Now}, nil
}

// KeyID is the identifier of the signing key, as it appears in the trusted key list.
func (s *Signer) KeyID() string { return s.keyID }

// Public is the public half of the signing key.
func (s *Signer) Public() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.key.Public().(ed25519.PublicKey)...)
}

// Sign makes an envelope for one tenant and one edge that is valid from now for the given duration. The payload must be
// a JSON document of at most MaxPayloadBytes. It refuses a tenant that is not 32 lower-case hex digits, an audience that
// is not an edge id, a sequence number that is 0 or above MaxSequence, and a validity that is not positive or is over
// MaxValidityCap.
func (s *Signer) Sign(tenant, audience string, seq uint64, validity time.Duration, payload []byte) (*Envelope, error) {
	if validity <= 0 {
		return nil, errors.New("config: the validity must be positive")
	}
	now := s.now().UTC().Truncate(time.Second)
	return s.SignWindow(tenant, audience, seq, now, now.Add(validity), payload)
}

// SignWindow is Sign with the window given as two instants. They are cut to whole seconds.
func (s *Signer) SignWindow(tenant, audience string, seq uint64, notBefore, notAfter time.Time, payload []byte) (*Envelope, error) {
	e := &Envelope{Version: Version, Tenant: tenant, Audience: audience, Sequence: seq,
		NotBefore: notBefore.UTC().Truncate(time.Second), NotAfter: notAfter.UTC().Truncate(time.Second),
		KeyID: s.keyID, Payload: append([]byte(nil), payload...)}
	if !e.NotAfter.After(e.NotBefore) {
		return nil, errors.New("config: the window ends before it starts")
	}
	if e.NotAfter.Sub(e.NotBefore) > MaxValidityCap {
		return nil, fmt.Errorf("config: the validity is longer than %s", MaxValidityCap)
	}
	e.Signature = make([]byte, ed25519.SignatureSize) // so that check() sees the right size; replaced below
	if err := e.check(); err != nil {
		return nil, err
	}
	e.Signature = ed25519.Sign(s.key, e.SigningBytes())
	return e, nil
}
