// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

// The values below were produced by testdata/vectors.py, which builds the signed bytes with Python's struct module and the
// cryptography package from the layout in docs/config-and-policy.md and shares no code with this package. They are fixed:
// if the layout changes, these change, and every deployed edge stops accepting what the signer makes.
const (
	vecConfigSeed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	vecRootSeed   = "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"
	vecConfigPub  = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
	vecConfigID   = "65b60673d6ed884b"
	vecRootPub    = "adc14011f82d1c56d956aa4f9d73d8858361a606048525e0d08c638dc75dd8c7"
	vecRootID     = "ba8112fa4ba3d6f9"

	vecSignedHex = "6361726e6963616c2d636f6e6669672d763100000002000100000020303031313232333334343535363637373838393961616262636364646565666600000009656467652d65752d3100000008000000000000000700000008000000006ac2e88000000008000000006acc230000000010363562363036373364366564383834620000001b7b22736368656d61223a312c226d6f6465223a22626c6f636b227d"
	vecSigHex    = "e6b55a1cfe887953bd17578577050020cd8d1d287a9aaceb6f84d4f9fb2e9d6719fe3626798468dc28f46e310d0364e57f5c98b8c934c84cff2f884725e6ee03"
	vecWire      = `{"v":1,"tenant":"00112233445566778899aabbccddeeff","audience":"edge-eu-1","seq":7,"not_before":"2026-10-05T00:00:00Z","not_after":"2026-10-12T00:00:00Z","key_id":"65b60673d6ed884b","payload":"eyJzY2hlbWEiOjEsIm1vZGUiOiJibG9jayJ9","sig":"5rVaHP6IeVO9F1eFdwUAIM2NHSh6mqzrb4TU-fsunWcZ_jYmeYRo3Cj0bjENA2Tlf1yYuMk0yEz_L4hHJebuAw"}`

	vecKeysSignedHex = "6361726e6963616c2d6b6579732d76310000000200010000001062613831313266613462613364366639000001357b22736368656d61223a312c22736571223a332c22697373756564223a22323032362d31302d30315430303a30303a30305a222c2265787069726573223a22323032372d31302d30315430303a30303a30305a222c226b657973223a5b7b226964223a2236356236303637336436656438383462222c22616c67223a2265643235353139222c22707562223a22656256574c6f5f6d56506c41654c4553364b6d4c703541666854726d6c623758344f4f52433630456c6d51222c22726f6c6573223a5b22636f6e666967225d2c226e6f745f6265666f7265223a22323032362d31302d30315430303a30303a30305a222c226e6f745f6166746572223a22323032372d30342d30315430303a30303a30305a227d5d2c227265766f6b6564223a5b2230313233343536373839616263646566225d7d"
	vecKeysSigHex    = "15585cf3ff4c9fe73a0298d62af6f33ddc87064a8031106d36443f6644cb08579eceb1bcff13d5b479d421437c238da1f526fce5145c8ddf9346b85741ff6a0f"
	vecKeysWire      = `{"v":1,"key_id":"ba8112fa4ba3d6f9","payload":"eyJzY2hlbWEiOjEsInNlcSI6MywiaXNzdWVkIjoiMjAyNi0xMC0wMVQwMDowMDowMFoiLCJleHBpcmVzIjoiMjAyNy0xMC0wMVQwMDowMDowMFoiLCJrZXlzIjpbeyJpZCI6IjY1YjYwNjczZDZlZDg4NGIiLCJhbGciOiJlZDI1NTE5IiwicHViIjoiZWJWV0xvX21WUGxBZUxFUzZLbUxwNUFmaFRybWxiN1g0T09SQzYwRWxtUSIsInJvbGVzIjpbImNvbmZpZyJdLCJub3RfYmVmb3JlIjoiMjAyNi0xMC0wMVQwMDowMDowMFoiLCJub3RfYWZ0ZXIiOiIyMDI3LTA0LTAxVDAwOjAwOjAwWiJ9XSwicmV2b2tlZCI6WyIwMTIzNDU2Nzg5YWJjZGVmIl19","sig":"FVhc8_9Mn-c6ApjWKvbzPdyHBkqAMRBtNkQ_ZkTLCFeezrG8_xPVtHnUIUN8I42h9Sb85RRcjd-TRrhXQf9qDw"}`
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vecKey(t testing.TB, seedHex string) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(mustHex(t, seedHex))
}

func TestVectorsFromTheIndependentImplementation(t *testing.T) {
	cfg := vecKey(t, vecConfigSeed)
	root := vecKey(t, vecRootSeed)
	if got := hex.EncodeToString(cfg.Public().(ed25519.PublicKey)); got != vecConfigPub {
		t.Fatalf("config public key %s", got)
	}
	if got := hex.EncodeToString(root.Public().(ed25519.PublicKey)); got != vecRootPub {
		t.Fatalf("root public key %s", got)
	}
	if KeyID(cfg.Public().(ed25519.PublicKey)) != vecConfigID || KeyID(root.Public().(ed25519.PublicKey)) != vecRootID {
		t.Fatal("key ids differ from the independent implementation")
	}

	t.Run("the signed bytes of an envelope are exactly the documented layout", func(t *testing.T) {
		e, err := Decode([]byte(vecWire))
		if err != nil {
			t.Fatal(err)
		}
		if got := e.SigningBytes(); !bytes.Equal(got, mustHex(t, vecSignedHex)) {
			t.Fatalf("signing bytes differ:\n got %x\nwant %s", got, vecSignedHex)
		}
		if !bytes.Equal(e.Signature, mustHex(t, vecSigHex)) {
			t.Fatal("the signature in the wire form is not the independent one")
		}
	})
	t.Run("the signer reproduces the independent signature and wire form", func(t *testing.T) {
		s, err := NewSigner(cfg)
		if err != nil {
			t.Fatal(err)
		}
		nb := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
		e, err := s.SignWindow("00112233445566778899aabbccddeeff", "edge-eu-1", 7, nb, nb.Add(7*24*time.Hour), []byte(`{"schema":1,"mode":"block"}`))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(e.Signature, mustHex(t, vecSigHex)) {
			t.Fatalf("signature %x differs from the independent one", e.Signature)
		}
		raw, err := e.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != vecWire {
			t.Fatalf("wire form differs:\n got %s\nwant %s", raw, vecWire)
		}
	})
	t.Run("the verifier accepts the independent envelope", func(t *testing.T) {
		pub, _ := NewTrustedKey(cfg.Public().(ed25519.PublicKey), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
		v, err := NewVerifier(VerifierConfig{Audience: "edge-eu-1", Tenants: []string{"00112233445566778899aabbccddeeff"}, Store: NewMemSeqStore()})
		if err != nil {
			t.Fatal(err)
		}
		if err := v.SetKeys([]TrustedKey{pub}, nil, time.Time{}); err != nil {
			t.Fatal(err)
		}
		e, err := v.Accept([]byte(vecWire), time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		if e.Sequence != 7 || string(e.Payload) != `{"schema":1,"mode":"block"}` {
			t.Fatalf("read wrongly: %+v", e)
		}
	})
	t.Run("the key list vector verifies and its signed bytes are the documented layout", func(t *testing.T) {
		ks, err := VerifyKeySet([]byte(vecKeysWire), []ed25519.PublicKey{root.Public().(ed25519.PublicKey)}, time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		if ks.Seq != 3 || len(ks.Keys) != 1 || ks.Keys[0].ID != vecConfigID || len(ks.Revoked) != 1 {
			t.Fatalf("read wrongly: %+v", ks)
		}
		w, _ := flatObject([]byte(vecKeysWire), 4)
		payload, _ := b64.DecodeString(string(w["payload"][1 : len(w["payload"])-1]))
		if got := keyListMessage(vecRootID, payload); !bytes.Equal(got, mustHex(t, vecKeysSignedHex)) {
			t.Fatalf("key list signed bytes differ from the independent ones:\n got %x", got)
		}
		if !ed25519.Verify(root.Public().(ed25519.PublicKey), mustHex(t, vecKeysSignedHex), mustHex(t, vecKeysSigHex)) {
			t.Fatal("the independent signature does not verify over the independent bytes")
		}
	})
	t.Run("signing the same key list reproduces the vector", func(t *testing.T) {
		pub, _ := NewTrustedKey(cfg.Public().(ed25519.PublicKey), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC))
		raw, err := SignKeySet(root, KeySet{Seq: 3, Issued: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Expires: time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC),
			Keys: []TrustedKey{pub}, Revoked: []string{"0123456789abcdef"}})
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != vecKeysWire {
			t.Fatalf("differs:\n got %s\nwant %s", raw, vecKeysWire)
		}
	})
}

// The same message must never verify under another purpose. A configuration envelope's signed bytes are not a key list's,
// and a key list is not an envelope, even with the same key.
func TestSignedBytesOfOnePurposeNeverVerifyAsAnother(t *testing.T) {
	cfg := vecKey(t, vecConfigSeed)
	pub := cfg.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(cfg, mustHex(t, vecKeysSignedHex))
	e, err := Decode([]byte(vecWire))
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(pub, e.SigningBytes(), sig) {
		t.Fatal("a signature over a key list verified as an envelope")
	}
	// The release scheme's prefix: "sfw-v1\n" + role + "\n" + payload. A signature made for it is not valid here.
	release := append([]byte("sfw-v1\nmanifest\n"), e.Payload...)
	if ed25519.Verify(pub, e.SigningBytes(), ed25519.Sign(cfg, release)) {
		t.Fatal("a release-scheme signature verified as an envelope")
	}
}
