// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"testing"
	"time"
)

// FuzzDecode feeds the envelope decoder arbitrary bytes. It must never panic, and whatever it accepts must be an
// envelope that writes back to something that decodes to the same envelope, with signing bytes that do not change.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(vecWire))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"v":1}`))
	f.Add([]byte(`{"v":1,"v":1}`))
	f.Add([]byte(`[]`))
	f.Add([]byte("\xff"))
	f.Add([]byte(`{"v":1,"tenant":"00112233445566778899aabbccddeeff","audience":"a","seq":1,"not_before":"2026-10-05T00:00:00Z","not_after":"2026-10-05T00:00:01Z","key_id":"0123456789abcdef","payload":"e30","sig":"` + string(make([]byte, 86)) + `"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := Decode(raw)
		if err != nil {
			var r *Refusal
			if !asRefusal(err, &r) {
				t.Fatalf("an error that is not a Refusal: %v", err)
			}
			return
		}
		again, err := e.Marshal()
		if err != nil {
			t.Fatalf("an envelope that Decode accepted cannot be written: %v", err)
		}
		back, err := Decode(again)
		if err != nil {
			t.Fatalf("the written form is refused: %v", err)
		}
		if !reflect.DeepEqual(e, back) {
			t.Fatalf("the envelope changed through its own wire form:\n%+v\n%+v", e, back)
		}
		if !bytes.Equal(e.SigningBytes(), back.SigningBytes()) {
			t.Fatal("the signing bytes changed")
		}
		if !ValidTenant(e.Tenant) || !ValidAudience(e.Audience) || e.Sequence < 1 || e.Sequence > MaxSequence || len(e.Signature) != 64 {
			t.Fatalf("a decoded envelope that breaks the format's own rules: %+v", e)
		}
	})
}

func asRefusal(err error, target **Refusal) bool {
	for err != nil {
		if r, ok := err.(*Refusal); ok {
			*target = r
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// FuzzKeySetPayload feeds the key list parser arbitrary payload bytes. Whatever it accepts, the signer must be willing to
// sign again, and the result must read back as the same list: the parser and the writer agree on what a list is.
func FuzzKeySetPayload(f *testing.F) {
	k, _ := NewTrustedKey(configKey.Public().(ed25519.PublicKey), keyLo, keyHi)
	good, _ := SignKeySet(rootKey, KeySet{Seq: 1, Issued: issued, Expires: listEnds, Keys: []TrustedKey{k}, Revoked: []string{"0123456789abcdef"}})
	var w keyListWire
	_ = strictUnmarshal(good, &w)
	payload, _ := b64.DecodeString(w.Payload)
	f.Add(payload)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema":1,"seq":1,"issued":"2026-10-01T00:00:00Z","expires":"2026-12-01T00:00:00Z","keys":[],"revoked":[]}`))
	f.Add([]byte(`{"schema":1,"seq":1,"keys":[{"id":"x"}]}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		root := rootKey.Public().(ed25519.PublicKey)
		ks, err := parseKeySet(payload, KeyID(root), []ed25519.PublicKey{root})
		if err != nil {
			return
		}
		raw, err := SignKeySet(rootKey, *ks)
		if err != nil {
			t.Fatalf("a list the parser accepted cannot be signed: %v", err)
		}
		back, err := VerifyKeySet(raw, []ed25519.PublicKey{root}, ks.Issued.Add(time.Second))
		if err != nil {
			t.Fatalf("a list the parser accepted does not verify when signed: %v", err)
		}
		if back.Seq != ks.Seq || len(back.Keys) != len(ks.Keys) || len(back.Revoked) != len(ks.Revoked) || !back.Issued.Equal(ks.Issued) || !back.Expires.Equal(ks.Expires) {
			t.Fatalf("the list changed through signing:\n%+v\n%+v", ks, back)
		}
	})
}

// FuzzVerifyKeySetWrapper feeds the signed wrapper arbitrary bytes. Nothing but the root key can make one verify, so what is
// asserted is that it never panics and that only a Refusal comes back.
func FuzzVerifyKeySetWrapper(f *testing.F) {
	f.Add([]byte(vecKeysWire))
	f.Add([]byte(`{"v":1,"key_id":"ba8112fa4ba3d6f9","payload":"e30","sig":"AAAA"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, err := VerifyKeySet(raw, roots, t0)
		var r *Refusal
		if err != nil && !asRefusal(err, &r) {
			t.Fatalf("an error that is not a Refusal: %v", err)
		}
	})
}

// FuzzParseRecord feeds the sequence record reader arbitrary bytes: it must never panic, and anything it accepts must be
// exactly a record this package would have written.
func FuzzParseRecord(f *testing.F) {
	f.Add(record(tenantA, 1))
	f.Add(record(tenantA, MaxSequence))
	f.Add([]byte(""))
	f.Add(record(tenantA, 5)[:20])
	f.Fuzz(func(t *testing.T, data []byte) {
		seq, err := parseRecord(tenantA, data)
		if err != nil {
			return
		}
		if !bytes.Equal(record(tenantA, seq), data) {
			t.Fatalf("accepted %q, which is not the record for %d", data, seq)
		}
	})
}
