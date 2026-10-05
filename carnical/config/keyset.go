// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"
	"unicode/utf8"
)

// The key list is how an edge learns which keys may sign configuration, so that a signing key can be replaced or taken
// away without touching the edge's own installation. It is the same idea as the release scheme's keys.json: a short
// document, signed by a root key whose public half is pinned in the edge, with a sequence number that only rises, dates,
// and a list of revoked key ids (newsletter/brief/waf/keys.py, read_keys_file). What is the same: Ed25519, key ids as
// the first 16 hex digits of the SHA-256 of the public key, UTC times written 2026-10-05T08:00:00Z, base64url without
// padding, at most 50 keys and 500 revoked ids, a root key may not be listed as a signing key, and every refusal is
// whole-file.
//
// What is different, on purpose: the signed bytes start with "carnical-keys-v1" and the keys may only have the role
// "config". A release key list that the owner's root key has signed (role "keys", prefix "sfw-v1") is therefore not
// a valid Carnical key list, and the reverse, even though one root key may sign both. Without that, an old release key
// list with a high sequence number could be presented to an edge to make it forget its signing keys, or a Carnical list
// could be presented to the PHP firewall.
//
// The key list is signed as the envelope is:
//
//	"carnical-keys-v1"                      the 16 ASCII bytes, with no length and no terminator
//	then, each as a 4-byte big-endian length and the bytes:
//	  version   2 bytes, big-endian (1)
//	  root key id    the 16 ASCII characters
//	  payload   the exact bytes of the JSON payload
//
// and travels as {"v":1,"key_id":"<root key id>","payload":"<base64url>","sig":"<base64url>"}.
const (
	keysDomain = "carnical-keys-v1"
	// MaxKeyListBytes is the most a key list's JSON form may hold.
	MaxKeyListBytes = 256 << 10
	// MaxKeyListValidity is the longest a key list may say it lasts.
	MaxKeyListValidity = 366 * 24 * time.Hour
	// KeyRole is the only role a key in the list may have.
	KeyRole = "config"
)

// KeySet is a verified key list.
type KeySet struct {
	// RootID is the id of the root key that signed it.
	RootID string
	// Seq is its sequence number, which only rises.
	Seq uint64
	// Issued and Expires are the dates the list gives for itself.
	Issued, Expires time.Time
	// Keys may sign configuration between their dates.
	Keys []TrustedKey
	// Revoked are key ids that must never be believed again, whether or not they are in Keys.
	Revoked []string
}

type keyEntryJSON struct {
	ID        string   `json:"id"`
	Alg       string   `json:"alg"`
	Pub       string   `json:"pub"`
	Roles     []string `json:"roles"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
}

type keySetJSON struct {
	Schema  int            `json:"schema"`
	Seq     uint64         `json:"seq"`
	Issued  string         `json:"issued"`
	Expires string         `json:"expires"`
	Keys    []keyEntryJSON `json:"keys"`
	Revoked []string       `json:"revoked"`
}

type keyListWire struct {
	V       int    `json:"v"`
	KeyID   string `json:"key_id"`
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

func keyListMessage(rootID string, payload []byte) []byte {
	b := append([]byte(nil), keysDomain...)
	b = lp(b, []byte{0, Version})
	b = lp(b, []byte(rootID))
	return lp(b, payload)
}

// SignKeySet makes the signed JSON form of a key list. It signs nothing that VerifyKeySet would refuse: the same rules
// are applied first. k.RootID is ignored; the root key's own id is used. Keys and revoked ids are written sorted, so the
// same list always gives the same payload.
func SignKeySet(root ed25519.PrivateKey, k KeySet) ([]byte, error) {
	if len(root) != ed25519.PrivateKeySize {
		return nil, errors.New("config: not an Ed25519 private key")
	}
	rootID := KeyID(root.Public().(ed25519.PublicKey))
	p := keySetJSON{Schema: 1, Seq: k.Seq, Issued: k.Issued.UTC().Format(timeLayout), Expires: k.Expires.UTC().Format(timeLayout),
		Keys: []keyEntryJSON{}, Revoked: append([]string{}, k.Revoked...)}
	for _, key := range k.Keys {
		p.Keys = append(p.Keys, keyEntryJSON{ID: key.ID, Alg: "ed25519", Pub: b64.EncodeToString(key.Public), Roles: []string{KeyRole},
			NotBefore: key.NotBefore.UTC().Format(timeLayout), NotAfter: key.NotAfter.UTC().Format(timeLayout)})
	}
	sort.Slice(p.Keys, func(i, j int) bool { return p.Keys[i].ID < p.Keys[j].ID })
	sort.Strings(p.Revoked)
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	// Refuse to sign what would be refused, so a mistake is found by the person who made it.
	if _, err := parseKeySet(payload, rootID, []ed25519.PublicKey{root.Public().(ed25519.PublicKey)}); err != nil {
		return nil, err
	}
	sig := ed25519.Sign(root, keyListMessage(rootID, payload))
	return json.Marshal(keyListWire{V: Version, KeyID: rootID, Payload: b64.EncodeToString(payload), Sig: b64.EncodeToString(sig)})
}

// VerifyKeySet checks a signed key list against the pinned root keys, and returns it. It refuses (with the Err value that
// says why): a list over MaxKeyListBytes (ErrOversize); anything that is not exactly the form above, with an unknown or
// repeated field, a malformed key, a key id that is not the hash of its key, a role other than "config", a key listed twice,
// a root key listed as a signing key, more than 50 keys or 500 revoked ids, or a validity over MaxKeyListValidity
// (ErrMalformed); a root key that is not pinned (ErrUnknownKey); a bad signature (ErrBadSignature); a list that is not
// valid yet or has expired (ErrNotYetValid, ErrKeyListExpired). It does not check that the list is newer than the last;
// AcceptKeySet does.
func VerifyKeySet(raw []byte, roots []ed25519.PublicKey, now time.Time) (*KeySet, error) {
	if len(raw) > MaxKeyListBytes {
		return nil, ErrOversize
	}
	fields, err := flatObject(raw, 4)
	if err != nil {
		return nil, err
	}
	var w keyListWire
	var payloadText, sigText string
	for _, f := range []struct {
		name string
		dst  *string
	}{{"key_id", &w.KeyID}, {"payload", &payloadText}, {"sig", &sigText}} {
		v, ok := fields[f.name]
		if !ok || v[0] != '"' || json.Unmarshal(v, f.dst) != nil {
			return nil, ErrMalformed
		}
	}
	if v, ok := fields["v"]; !ok || !seqRe.Match(v) {
		return nil, ErrMalformed
	} else if string(v) != "1" {
		return nil, ErrUnsupportedVersion
	}
	if len(fields) != 4 || !keyIDRe.MatchString(w.KeyID) {
		return nil, ErrMalformed
	}
	payload, err := b64.DecodeString(payloadText)
	if err != nil {
		return nil, ErrMalformed
	}
	sig, err := b64.DecodeString(sigText)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrMalformed
	}
	var root ed25519.PublicKey
	for _, r := range roots {
		if len(r) == ed25519.PublicKeySize && KeyID(r) == w.KeyID {
			root = r
		}
	}
	if root == nil {
		return nil, ErrUnknownKey
	}
	if !ed25519.Verify(root, keyListMessage(w.KeyID, payload), sig) {
		return nil, ErrBadSignature
	}
	ks, err := parseKeySet(payload, w.KeyID, roots)
	if err != nil {
		return nil, err
	}
	if now.Add(DefaultClockSkew).Before(ks.Issued) {
		return nil, ErrNotYetValid
	}
	if now.After(ks.Expires) {
		return nil, ErrKeyListExpired
	}
	return ks, nil
}

// AcceptKeySet is VerifyKeySet, and then records the list's sequence number in the store under KeySetStream(root key
// id), atomically with the check that it is higher than the last list accepted from that root. An older list, which
// could bring back a key that has since been revoked, gets ErrRollback.
func AcceptKeySet(raw []byte, roots []ed25519.PublicKey, now time.Time, store SeqStore) (*KeySet, error) {
	ks, err := VerifyKeySet(raw, roots, now)
	if err != nil {
		return nil, err
	}
	if err := store.Advance(KeySetStream(ks.RootID), ks.Seq); err != nil {
		return nil, err
	}
	return ks, nil
}

// Apply gives the verifier this list's keys, revoked ids and expiry, replacing what it had.
func (k *KeySet) Apply(v *Verifier) error { return v.SetKeys(k.Keys, k.Revoked, k.Expires) }

func parseKeySet(payload []byte, rootID string, roots []ed25519.PublicKey) (*KeySet, error) {
	var p keySetJSON
	if err := strictUnmarshal(payload, &p); err != nil {
		return nil, ErrMalformed
	}
	issued, ok1 := parseTime(p.Issued)
	expires, ok2 := parseTime(p.Expires)
	if p.Schema != 1 || p.Seq < 1 || p.Seq > MaxSequence || !ok1 || !ok2 || !expires.After(issued) || expires.Sub(issued) > MaxKeyListValidity ||
		len(p.Keys) > MaxTrustedKeys || len(p.Revoked) > MaxRevokedKeys || p.Keys == nil || p.Revoked == nil {
		return nil, ErrMalformed
	}
	ks := &KeySet{RootID: rootID, Seq: p.Seq, Issued: issued, Expires: expires}
	seen := map[string]bool{}
	for _, e := range p.Keys {
		pub, err := b64.DecodeString(e.Pub)
		nb, ok1 := parseTime(e.NotBefore)
		na, ok2 := parseTime(e.NotAfter)
		if err != nil || len(pub) != ed25519.PublicKeySize || e.Alg != "ed25519" || !ok1 || !ok2 || !na.After(nb) ||
			len(e.Roles) != 1 || e.Roles[0] != KeyRole || e.ID != KeyID(pub) || seen[e.ID] {
			return nil, ErrMalformed
		}
		for _, r := range roots {
			if bytes.Equal(r, pub) {
				return nil, ErrMalformed // a root key never signs configuration
			}
		}
		seen[e.ID] = true
		ks.Keys = append(ks.Keys, TrustedKey{ID: e.ID, Public: ed25519.PublicKey(pub), NotBefore: nb, NotAfter: na})
	}
	gone := map[string]bool{}
	for _, id := range p.Revoked {
		if !keyIDRe.MatchString(id) || gone[id] {
			return nil, ErrMalformed
		}
		gone[id] = true
		ks.Revoked = append(ks.Revoked, id)
	}
	return ks, nil
}

// strictUnmarshal decodes one JSON value into v, refusing a field v does not have, a repeated name anywhere in the
// document, nesting deeper than 8, invalid UTF-8, and anything after the value.
func strictUnmarshal(raw []byte, v any) error {
	if !utf8.Valid(raw) || hasRepeatedName(raw, 8) {
		return ErrMalformed
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrMalformed
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrMalformed
	}
	return nil
}

// hasRepeatedName reports whether any object in the document names a field twice, or the document is nested deeper than
// maxDepth, or is not valid JSON. A true result means "do not read this".
func hasRepeatedName(raw []byte, maxDepth int) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	type frame struct {
		object bool
		names  map[string]struct{}
		key    bool // the next string token in an object is a name
	}
	var stack []frame
	for {
		t, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return len(stack) != 0
		}
		if err != nil {
			return true
		}
		switch tok := t.(type) {
		case json.Delim:
			switch tok {
			case '{', '[':
				if len(stack) >= maxDepth {
					return true
				}
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].key = true // the value just started; the next name comes after it
				}
				stack = append(stack, frame{object: tok == '{', names: map[string]struct{}{}, key: tok == '{'})
			default:
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].key = true
				}
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object {
				f := &stack[len(stack)-1]
				if f.key {
					if _, dup := f.names[tok]; dup {
						return true
					}
					f.names[tok] = struct{}{}
					f.key = false
					continue
				}
				f.key = true
			}
		default:
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].key = true
			}
		}
	}
}
