// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var (
	rootKey   = seededKey(120)
	rootPub   = rootKey.Public().(ed25519.PublicKey)
	roots     = []ed25519.PublicKey{rootPub}
	issued    = t0.Add(-24 * time.Hour)
	listEnds  = t0.Add(300 * 24 * time.Hour)
	keyLo     = t0.Add(-time.Hour)
	keyHi     = t0.Add(60 * 24 * time.Hour)
	configKey = seededKey(10)
)

func goodSet(t testing.TB) KeySet {
	t.Helper()
	k, err := NewTrustedKey(configKey.Public().(ed25519.PublicKey), keyLo, keyHi)
	if err != nil {
		t.Fatal(err)
	}
	return KeySet{Seq: 4, Issued: issued, Expires: listEnds, Keys: []TrustedKey{k}, Revoked: []string{"0123456789abcdef"}}
}

func signSet(t testing.TB, ks KeySet) []byte {
	t.Helper()
	raw, err := SignKeySet(rootKey, ks)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// withPayload re-signs a payload that was edited by hand, which is how a hostile or careless root would make a bad list.
func withPayload(t testing.TB, mutate func(map[string]any)) []byte {
	t.Helper()
	raw := signSet(t, goodSet(t))
	var w map[string]json.RawMessage
	json.Unmarshal(raw, &w)
	payload, _ := b64.DecodeString(strings.Trim(string(w["payload"]), `"`))
	var p map[string]any
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	mutate(p)
	edited, _ := json.Marshal(p)
	return resign(edited)
}

func resign(payload []byte) []byte {
	rootID := KeyID(rootPub)
	sig := ed25519.Sign(rootKey, keyListMessage(rootID, payload))
	out, _ := json.Marshal(keyListWire{V: Version, KeyID: rootID, Payload: b64.EncodeToString(payload), Sig: b64.EncodeToString(sig)})
	return out
}

func TestAKeyListIsVerifiedAndFeedsTheVerifier(t *testing.T) {
	raw := signSet(t, goodSet(t))
	ks, err := VerifyKeySet(raw, roots, t0)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if ks.Seq != 4 || ks.RootID != KeyID(rootPub) || len(ks.Keys) != 1 || ks.Revoked[0] != "0123456789abcdef" {
		t.Fatalf("read wrongly: %+v", ks)
	}
	r := newRig(t, NewMemSeqStore())
	v, _ := NewVerifier(VerifierConfig{Audience: edgeID, Tenants: []string{tenantA}, Store: NewMemSeqStore()})
	envelope := r.sign(t, tenantA, edgeID, 1)
	if _, err := v.Verify(envelope, t0); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("before the key list: %v", err)
	}
	if err := ks.Apply(v); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Accept(envelope, t0.Add(time.Minute)); err != nil {
		t.Fatalf("after the key list: %v", err)
	}
	// The list's own expiry applies to the verifier.
	if _, err := v.Verify(envelope, ks.Expires.Add(time.Hour)); !errors.Is(err, ErrKeyListExpired) {
		t.Fatalf("after the list expired: %v", err)
	}
}

func TestKeyListRefusals(t *testing.T) {
	good := signSet(t, goodSet(t))
	otherRoot := seededKey(200)
	flip := func(raw []byte, field string) []byte {
		var w map[string]json.RawMessage
		json.Unmarshal(raw, &w)
		s := string(w[field]) // with its quotes, so the fourth character is the third of the text
		c := byte('A')
		if s[4] == 'A' {
			c = 'B'
		}
		w[field] = json.RawMessage(s[:4] + string(c) + s[5:])
		out, _ := json.Marshal(w)
		return out
	}
	hexID := func(b byte) string { return fmt.Sprintf("%016x", uint64(b)) }
	listed := func(p map[string]any) map[string]any { return p["keys"].([]any)[0].(map[string]any) }
	tests := []struct {
		name string
		raw  []byte
		now  time.Time
		want *Refusal
	}{
		{"the good list", good, t0, nil},
		{"signature changed", flip(good, "sig"), t0, ErrBadSignature},
		{"payload changed", flip(good, "payload"), t0, ErrBadSignature},
		{"signed by a key that is not pinned", func() []byte { raw, _ := SignKeySet(otherRoot, goodSet(t)); return raw }(), t0, ErrUnknownKey},
		{"naming a pinned root but signed by another", func() []byte {
			var w map[string]json.RawMessage
			raw, _ := SignKeySet(otherRoot, goodSet(t))
			json.Unmarshal(raw, &w)
			w["key_id"] = json.RawMessage(`"` + KeyID(rootPub) + `"`)
			out, _ := json.Marshal(w)
			return out
		}(), t0, ErrBadSignature},
		{"before it was issued", good, issued.Add(-time.Hour), ErrNotYetValid},
		{"after it expired", good, listEnds.Add(time.Second), ErrKeyListExpired},
		{"on the last second", good, listEnds, nil},
		{"over the size cap", append([]byte(`{"v":1,"key_id":"`+KeyID(rootPub)+`","payload":"`), make([]byte, MaxKeyListBytes)...), t0, ErrOversize},
		{"not JSON", []byte("nope"), t0, ErrMalformed},
		{"version 2", []byte(strings.Replace(string(good), `"v":1`, `"v":2`, 1)), t0, ErrUnsupportedVersion},
		{"an unknown field in the wrapper", []byte(strings.Replace(string(good), `"v":1`, `"v":1,"x":1`, 1)), t0, ErrMalformed},
		{"a field missing in the wrapper", []byte(strings.Replace(string(good), `"v":1,`, ``, 1)), t0, ErrMalformed},
		{"a repeated field in the wrapper", []byte(strings.Replace(string(good), `"v":1`, `"v":1,"v":1`, 1)), t0, ErrMalformed},

		{"schema 2", withPayload(t, func(p map[string]any) { p["schema"] = 2 }), t0, ErrMalformed},
		{"an unknown payload field", withPayload(t, func(p map[string]any) { p["extra"] = 1 }), t0, ErrMalformed},
		{"sequence 0", withPayload(t, func(p map[string]any) { p["seq"] = 0 }), t0, ErrMalformed},
		{"sequence over the maximum", withPayload(t, func(p map[string]any) { p["seq"] = float64(MaxSequence + 1) }), t0, ErrMalformed},
		{"expires before issued", withPayload(t, func(p map[string]any) { p["expires"] = "2020-01-01T00:00:00Z" }), t0, ErrMalformed},
		{"valid for longer than allowed", withPayload(t, func(p map[string]any) { p["expires"] = "2030-01-01T00:00:00Z" }), t0, ErrMalformed},
		{"a time in the wrong form", withPayload(t, func(p map[string]any) { p["issued"] = "2026-10-04" }), t0, ErrMalformed},
		{"keys null", withPayload(t, func(p map[string]any) { p["keys"] = nil }), t0, ErrMalformed},
		{"revoked missing", withPayload(t, func(p map[string]any) { delete(p, "revoked") }), t0, ErrMalformed},
		{"a key with another role", withPayload(t, func(p map[string]any) { listed(p)["roles"] = []string{"manifest"} }), t0, ErrMalformed},
		{"a key with two roles", withPayload(t, func(p map[string]any) { listed(p)["roles"] = []string{"config", "manifest"} }), t0, ErrMalformed},
		{"a key with no roles", withPayload(t, func(p map[string]any) { listed(p)["roles"] = []string{} }), t0, ErrMalformed},
		{"a key with another algorithm", withPayload(t, func(p map[string]any) { listed(p)["alg"] = "rsa" }), t0, ErrMalformed},
		{"an id that is not the key's hash", withPayload(t, func(p map[string]any) { listed(p)["id"] = hexID(1) }), t0, ErrMalformed},
		{"a public key of the wrong length", withPayload(t, func(p map[string]any) { listed(p)["pub"] = b64.EncodeToString(make([]byte, 31)) }), t0, ErrMalformed},
		{"a public key with padding", withPayload(t, func(p map[string]any) { listed(p)["pub"] = listed(p)["pub"].(string) + "=" }), t0, ErrMalformed},
		{"a key that ends before it starts", withPayload(t, func(p map[string]any) { listed(p)["not_after"] = "2020-01-01T00:00:00Z" }), t0, ErrMalformed},
		{"the same key twice", withPayload(t, func(p map[string]any) { p["keys"] = []any{listed(p), listed(p)} }), t0, ErrMalformed},
		{"the root key as a signing key", withPayload(t, func(p map[string]any) {
			listed(p)["id"] = KeyID(rootPub)
			listed(p)["pub"] = b64.EncodeToString(rootPub)
		}), t0, ErrMalformed},
		{"a revoked id of the wrong shape", withPayload(t, func(p map[string]any) { p["revoked"] = []string{"XYZ"} }), t0, ErrMalformed},
		{"a revoked id twice", withPayload(t, func(p map[string]any) { p["revoked"] = []string{hexID(1), hexID(1)} }), t0, ErrMalformed},
		{"more revoked ids than allowed", withPayload(t, func(p map[string]any) {
			var ids []string
			for i := 0; i <= MaxRevokedKeys; i++ {
				ids = append(ids, fmt.Sprintf("%016x", i))
			}
			p["revoked"] = ids
		}), t0, ErrMalformed},
		{"more keys than allowed", withPayload(t, func(p map[string]any) {
			var ks []any
			for i := 0; i <= MaxTrustedKeys; i++ {
				pub := seededKey(byte(i)).Public().(ed25519.PublicKey)
				ks = append(ks, map[string]any{"id": KeyID(pub), "alg": "ed25519", "pub": b64.EncodeToString(pub), "roles": []string{"config"},
					"not_before": "2026-10-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z"})
			}
			p["keys"] = ks
		}), t0, ErrMalformed},
		{"a repeated name inside the payload", resign([]byte(`{"schema":1,"schema":1,"seq":1,"issued":"2026-10-01T00:00:00Z","expires":"2026-12-01T00:00:00Z","keys":[],"revoked":[]}`)), t0, ErrMalformed},
		{"a repeated name inside a key", func() []byte {
			p := `{"schema":1,"seq":1,"issued":"2026-10-01T00:00:00Z","expires":"2026-12-01T00:00:00Z","keys":[{"id":"%s","id":"%s","alg":"ed25519","pub":"%s","roles":["config"],"not_before":"2026-10-01T00:00:00Z","not_after":"2026-11-01T00:00:00Z"}],"revoked":[]}`
			pub := configKey.Public().(ed25519.PublicKey)
			return resign([]byte(fmt.Sprintf(p, KeyID(pub), KeyID(pub), b64.EncodeToString(pub))))
		}(), t0, ErrMalformed},
		{"text after the payload", resign(append([]byte(`{"schema":1,"seq":1,"issued":"2026-10-01T00:00:00Z","expires":"2026-12-01T00:00:00Z","keys":[],"revoked":[]}`), ' ', '{', '}')), t0, ErrMalformed},
		{"an empty but valid list", resign([]byte(`{"schema":1,"seq":1,"issued":"2026-10-01T00:00:00Z","expires":"2026-12-01T00:00:00Z","keys":[],"revoked":[]}`)), t0, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyKeySet(tc.raw, roots, tc.now)
			if tc.want == nil && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v (%s), want %s", err, Reason(err), tc.want.Code())
			}
		})
	}
	t.Run("a signing mistake is caught by the person who makes the list", func(t *testing.T) {
		bad := goodSet(t)
		bad.Keys[0].ID = "0123456789abcdef"
		if _, err := SignKeySet(rootKey, bad); err == nil {
			t.Error("a list with a wrong key id was signed")
		}
		bad = goodSet(t)
		bad.Expires = bad.Issued.Add(MaxKeyListValidity + time.Hour)
		if _, err := SignKeySet(rootKey, bad); err == nil {
			t.Error("a list valid for too long was signed")
		}
		if _, err := SignKeySet(rootKey[:10], goodSet(t)); err == nil {
			t.Error("a short root key was accepted")
		}
	})
}

func TestAnOlderKeyListCannotBringBackARevokedKey(t *testing.T) {
	store := NewMemSeqStore()
	cfg := configKey.Public().(ed25519.PublicKey)
	key, _ := NewTrustedKey(cfg, keyLo, keyHi)
	v1 := KeySet{Seq: 1, Issued: issued, Expires: listEnds, Keys: []TrustedKey{key}, Revoked: []string{}}
	v2 := KeySet{Seq: 2, Issued: issued, Expires: listEnds, Keys: []TrustedKey{}, Revoked: []string{key.ID}} // the key is revoked
	raw1, raw2 := signSet(t, v1), signSet(t, v2)
	steps := []struct {
		name string
		raw  []byte
		want *Refusal
	}{
		{"the first list", raw1, nil},
		{"the same list again", raw1, ErrRollback},
		{"the revoking list", raw2, nil},
		{"the old list, which still has a good signature", raw1, ErrRollback},
		{"the revoking list again", raw2, ErrRollback},
	}
	for _, s := range steps {
		_, err := AcceptKeySet(s.raw, roots, t0, store)
		if s.want == nil && err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if s.want != nil && !errors.Is(err, s.want) {
			t.Fatalf("%s: got %v", s.name, err)
		}
	}
	if last, _ := store.Last(KeySetStream(KeyID(rootPub))); last != 2 {
		t.Fatalf("the record holds %d", last)
	}
	// An envelope that a revoked key signed is refused once the revoking list is applied.
	ks, err := VerifyKeySet(raw2, roots, t0)
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, NewMemSeqStore())
	if err := ks.Apply(r.ver); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ver.Verify(r.sign(t, tenantA, edgeID, 1), t0.Add(time.Minute)); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("an envelope from the revoked key: %v", err)
	}
	t.Run("an older list from another pinned root, during a root rotation", func(t *testing.T) {
		store := NewMemSeqStore()
		rootB := seededKey(121)
		both := []ed25519.PublicKey{rootPub, rootB.Public().(ed25519.PublicKey)}
		oldA := signSet(t, KeySet{Seq: 3, Issued: issued, Expires: listEnds, Keys: []TrustedKey{key}, Revoked: []string{}})
		revokingB, err := SignKeySet(rootB, KeySet{Seq: 10, Issued: issued, Expires: listEnds, Keys: []TrustedKey{}, Revoked: []string{key.ID}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := AcceptKeySet(revokingB, both, t0, store); err != nil {
			t.Fatal(err)
		}
		if _, err := AcceptKeySet(oldA, both, t0, store); !errors.Is(err, ErrRollback) {
			t.Fatalf("root A's older list after root B revoked the key: %v", err)
		}
		// At start-up the persisted list is loaded, not accepted again; an older one must still be refused.
		if _, err := LoadKeySet(oldA, both, t0, store); !errors.Is(err, ErrRollback) {
			t.Fatalf("loading an older list at start-up: %v", err)
		}
		if ks, err := LoadKeySet(revokingB, both, t0, store); err != nil || ks.Seq != 10 {
			t.Fatalf("loading the newest list at start-up: %v", err)
		}
		newerA := signSet(t, KeySet{Seq: 20, Issued: issued, Expires: listEnds, Keys: []TrustedKey{}, Revoked: []string{key.ID}})
		if _, err := AcceptKeySet(newerA, both, t0, store); err != nil {
			t.Fatalf("a newer list from root A: %v", err)
		}
		// Once root A is unpinned, its history must still count: root B's list 15 is older than A's list 20.
		staleB, err := SignKeySet(rootB, KeySet{Seq: 15, Issued: issued, Expires: listEnds, Keys: []TrustedKey{key}, Revoked: []string{}})
		if err != nil {
			t.Fatal(err)
		}
		onlyB := both[1:]
		if _, err := AcceptKeySet(staleB, onlyB, t0, store); !errors.Is(err, ErrRollback) {
			t.Fatalf("an older list after the other root was unpinned: %v", err)
		}
		if _, err := LoadKeySet(staleB, onlyB, t0, store); !errors.Is(err, ErrRollback) {
			t.Fatalf("loading an older list after the other root was unpinned: %v", err)
		}
	})
	t.Run("a rejected list does not use up its sequence number", func(t *testing.T) {
		store := NewMemSeqStore()
		bad := flipOneByte(raw1)
		if _, err := AcceptKeySet(bad, roots, t0, store); err == nil {
			t.Fatal("accepted")
		}
		if last, _ := store.Last(KeySetStream(KeyID(rootPub))); last != 0 {
			t.Fatalf("a bad list recorded sequence %d", last)
		}
		if _, err := AcceptKeySet(raw1, roots, t0, store); err != nil {
			t.Fatalf("the good list after the bad one: %v", err)
		}
	})
}

func flipOneByte(raw []byte) []byte {
	var w map[string]json.RawMessage
	json.Unmarshal(raw, &w)
	s := string(w["sig"])
	c := byte('A')
	if s[6] == 'A' {
		c = 'B'
	}
	w["sig"] = json.RawMessage(s[:6] + string(c) + s[7:])
	out, _ := json.Marshal(w)
	return out
}

func TestHasRepeatedName(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{`{}`, false},
		{`{"a":1,"b":2}`, false},
		{`{"a":1,"a":2}`, true},
		{`{"a":{"a":1},"b":[{"a":1},{"a":2}]}`, false},
		{`{"a":{"b":1,"b":2}}`, true},
		{`{"a":[{"x":1,"x":2}]}`, true},
		{`{"a":"a","b":"a"}`, false},
		{`{"a":"b","b":"a","a":1}`, true},
		{`[{"a":1},{"a":1}]`, false},
		{`{"a":1,`, true},
		{`{"a" 1}`, true},
		{`{"a":[1,2,{"b":3,"b":4}]}`, true},
		{`{"a":null,"b":true,"c":1.5,"a":0}`, true},
		{`"just a string"`, false},
		{`[[[[[[[[[1]]]]]]]]]`, true}, // deeper than 8
		{`[[[[[[[[1]]]]]]]]`, false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := hasRepeatedName([]byte(tc.in), 8); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
