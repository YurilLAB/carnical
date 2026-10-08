// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	tenantA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tenantB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tenantC = "cccccccccccccccccccccccccccccccc"
	edgeID  = "edge-1"
)

var t0 = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func seededKey(b byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b + byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// rig is an edge (a Verifier for edge-1 serving tenants A and B) and a signer whose key it trusts.
type rig struct {
	signer *Signer
	pub    ed25519.PublicKey
	trust  TrustedKey
	ver    *Verifier
	store  SeqStore
}

func newRig(t testing.TB, store SeqStore) *rig {
	t.Helper()
	key := seededKey(10)
	s, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	pub := s.Public()
	trust, err := NewTrustedKey(pub, t0.Add(-30*24*time.Hour), t0.Add(30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(VerifierConfig{Audience: edgeID, Tenants: []string{tenantA, tenantB}, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.SetKeys([]TrustedKey{trust}, nil, time.Time{}); err != nil {
		t.Fatal(err)
	}
	return &rig{signer: s, pub: pub, trust: trust, ver: v, store: store}
}

var payload = []byte(`{"schema":1,"mode":"block"}`)

// sign makes envelope bytes valid from t0 for a day.
func (r *rig) sign(t testing.TB, tenant, audience string, seq uint64) []byte {
	t.Helper()
	e, err := r.signer.SignWindow(tenant, audience, seq, t0, t0.Add(24*time.Hour), payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func wantRefusal(t *testing.T, err error, want *Refusal) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v (%s), want %v (%s)", err, Reason(err), want, want.Code())
	}
}

func TestAnEnvelopeForThisEdgeAndTenantIsAcceptedOnce(t *testing.T) {
	r := newRig(t, NewMemSeqStore())
	raw := r.sign(t, tenantA, edgeID, 5)
	e, err := r.ver.Accept(raw, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if e.Tenant != tenantA || e.Sequence != 5 || string(e.Payload) != string(payload) {
		t.Fatalf("read wrongly: %+v", e)
	}
	_, err = r.ver.Accept(raw, t0.Add(time.Minute))
	wantRefusal(t, err, ErrRollback)
}

// Every field of the envelope is covered by the signature: change any one and the envelope is refused, and for the reason
// that fits.
func TestTamperingWithAnyFieldIsRefused(t *testing.T) {
	r := newRig(t, NewMemSeqStore())
	other := seededKey(90)
	otherTrust, _ := NewTrustedKey(other.Public().(ed25519.PublicKey), t0.Add(-time.Hour), t0.Add(30*24*time.Hour))
	if err := r.ver.SetKeys([]TrustedKey{r.trust, otherTrust}, nil, time.Time{}); err != nil {
		t.Fatal(err)
	}
	base := r.sign(t, tenantA, edgeID, 7)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(base, &fields); err != nil {
		t.Fatal(err)
	}
	// the payload with one word changed: still JSON, but not what was signed
	payloadText := string(fields["payload"])
	flipped := `"` + b64.EncodeToString(bytes.Replace(payload, []byte("block"), []byte("allow"), 1)) + `"`
	sigText := string(fields["sig"])
	// The last base64 character of a 64-byte signature carries two bits of data and four spare bits, which must be zero.
	// Setting one spare bit gives text that a lax decoder reads as the same signature: the same bytes, a different spelling.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	lastDigit := strings.IndexByte(alphabet, sigText[len(sigText)-2])
	if lastDigit < 0 || lastDigit&0xf != 0 {
		t.Fatalf("the signature's last digit is not in canonical form: %d", lastDigit)
	}
	spareBits := sigText[:len(sigText)-2] + string(alphabet[lastDigit|1]) + `"`
	flippedSig := sigText[:2] + map[bool]string{true: "B", false: "A"}[sigText[2] == 'A'] + sigText[3:]

	tests := []struct {
		name  string
		field string
		value string // raw JSON; "" removes the field
		want  *Refusal
	}{
		{"version 2", "v", `2`, ErrUnsupportedVersion},
		{"version as text", "v", `"1"`, ErrMalformed},
		{"version removed", "v", ``, ErrMalformed},
		{"another assigned tenant", "tenant", `"` + tenantB + `"`, ErrBadSignature},
		{"an unassigned tenant", "tenant", `"` + tenantC + `"`, ErrBadSignature},
		{"upper-case tenant", "tenant", `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`, ErrMalformed},
		{"short tenant", "tenant", `"aaaa"`, ErrMalformed},
		{"tenant as a number", "tenant", `1`, ErrMalformed},
		{"another audience", "audience", `"edge-2"`, ErrBadSignature},
		{"audience with a space", "audience", `"edge 1"`, ErrMalformed},
		{"empty audience", "audience", `""`, ErrMalformed},
		{"sequence one higher", "seq", `8`, ErrBadSignature},
		{"sequence zero", "seq", `0`, ErrMalformed},
		{"sequence as text", "seq", `"7"`, ErrMalformed},
		{"sequence as a float", "seq", `7.0`, ErrMalformed},
		{"sequence in exponent form", "seq", `7e0`, ErrMalformed},
		{"negative sequence", "seq", `-7`, ErrMalformed},
		{"sequence over 2^53-1", "seq", `9007199254740992`, ErrMalformed},
		{"sequence with a leading zero", "seq", `07`, ErrMalformed},
		{"not_before moved", "not_before", `"2026-10-05T00:00:00Z"`, ErrBadSignature},
		{"not_before in another format", "not_before", `"2026-10-05 12:00:00"`, ErrMalformed},
		{"not_before with an offset", "not_before", `"2026-10-05T12:00:00+00:00"`, ErrMalformed},
		{"not_after moved", "not_after", `"2026-10-30T12:00:00Z"`, ErrBadSignature},
		{"not_after impossible date", "not_after", `"2026-02-31T12:00:00Z"`, ErrMalformed},
		{"another trusted key's id", "key_id", `"` + KeyID(other.Public().(ed25519.PublicKey)) + `"`, ErrBadSignature},
		{"an unknown key id", "key_id", `"0123456789abcdef"`, ErrUnknownKey},
		{"upper-case key id", "key_id", `"0123456789ABCDEF"`, ErrMalformed},
		{"payload changed", "payload", flipped, ErrBadSignature},
		{"payload with padding", "payload", payloadText[:len(payloadText)-1] + `="`, ErrMalformed},
		{"payload not base64", "payload", `"!!!!"`, ErrMalformed},
		{"payload not JSON", "payload", `"` + b64.EncodeToString([]byte("not json")) + `"`, ErrMalformed},
		{"payload empty", "payload", `""`, ErrMalformed},
		{"signature bit flipped", "sig", flippedSig, ErrBadSignature},
		{"signature truncated", "sig", sigText[:len(sigText)-5] + `"`, ErrMalformed},
		{"signature removed", "sig", ``, ErrMalformed},
		{"signature with a spare bit set (the same bytes in another spelling)", "sig", spareBits, ErrMalformed},
		{"a field the format does not have", "extra", `1`, ErrMalformed},
		{"a nested value", "extra", `{"a":1}`, ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]json.RawMessage{}
			for k, v := range fields {
				m[k] = v
			}
			if tc.value == "" {
				delete(m, tc.field)
			} else {
				m[tc.field] = json.RawMessage(tc.value)
			}
			// built by hand so that a deliberately invalid value is not rewritten by the encoder
			var parts []string
			for k, v := range m {
				parts = append(parts, fmt.Sprintf("%q:%s", k, v))
			}
			raw := []byte("{" + strings.Join(parts, ",") + "}")
			for _, mode := range []string{"Verify", "Accept"} {
				var err error
				if mode == "Verify" {
					_, err = r.ver.Verify(raw, t0.Add(time.Minute))
				} else {
					_, err = r.ver.Accept(raw, t0.Add(time.Minute))
				}
				wantRefusal(t, err, tc.want)
			}
			if last, _ := r.store.Last(tenantA); last != 0 {
				t.Fatalf("a refused envelope recorded sequence %d", last)
			}
		})
	}
	t.Run("the untouched envelope is accepted, so the rows above refuse for their own reason", func(t *testing.T) {
		if _, err := r.ver.Accept(base, t0.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a repeated field", func(t *testing.T) {
		raw := strings.Replace(string(base), `"seq":7`, `"seq":7,"seq":9`, 1)
		_, err := r.ver.Verify([]byte(raw), t0.Add(time.Minute))
		wantRefusal(t, err, ErrMalformed)
	})
	t.Run("text after the object", func(t *testing.T) {
		for _, tail := range []string{" {}", "x", "\x00", "[]"} {
			_, err := r.ver.Verify(append(append([]byte(nil), base...), tail...), t0.Add(time.Minute))
			wantRefusal(t, err, ErrMalformed)
		}
	})
	t.Run("not an object", func(t *testing.T) {
		for _, raw := range []string{``, `[]`, `null`, `"x"`, `1`, `{`, `{"v":1,`, "\xff\xfe", `{"v":1}`} {
			_, err := r.ver.Verify([]byte(raw), t0.Add(time.Minute))
			wantRefusal(t, err, ErrMalformed)
		}
	})
}

func TestAnEnvelopeForAnotherEdgeOrTenantIsRefusedOnlyAfterItsSignatureIsKnownGood(t *testing.T) {
	r := newRig(t, NewMemSeqStore())
	now := t0.Add(time.Minute)
	tests := []struct {
		name     string
		tenant   string
		audience string
		want     *Refusal
	}{
		{"for this edge and an assigned tenant", tenantA, edgeID, nil},
		{"for this edge and the other assigned tenant", tenantB, edgeID, nil},
		{"signed for another edge", tenantA, "edge-2", ErrWrongAudience},
		{"signed for a tenant this edge is not assigned", tenantC, edgeID, ErrWrongTenant},
		{"signed for another edge and another tenant", tenantC, "edge-2", ErrWrongAudience},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := r.sign(t, tc.tenant, tc.audience, 3)
			_, err := r.ver.Verify(raw, now)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			wantRefusal(t, err, tc.want)
		})
	}
	t.Run("swapping the tenant in a genuine envelope breaks the signature", func(t *testing.T) {
		raw := r.sign(t, tenantA, edgeID, 4)
		swapped := strings.Replace(string(raw), tenantA, tenantB, 1)
		_, err := r.ver.Accept([]byte(swapped), now)
		wantRefusal(t, err, ErrBadSignature)
		if last, _ := r.store.Last(tenantB); last != 0 {
			t.Fatalf("tenant B's sequence moved to %d", last)
		}
	})
	t.Run("the tenant list can change while the edge runs", func(t *testing.T) {
		raw := r.sign(t, tenantC, edgeID, 3)
		if err := r.ver.SetTenants([]string{tenantA, tenantB, tenantC}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.ver.Accept(raw, now); err != nil {
			t.Fatalf("refused after assignment: %v", err)
		}
		if err := r.ver.SetTenants([]string{tenantA}); err != nil {
			t.Fatal(err)
		}
		_, err := r.ver.Accept(r.sign(t, tenantC, edgeID, 4), now)
		wantRefusal(t, err, ErrWrongTenant)
		if err := r.ver.SetTenants([]string{"not-a-tenant"}); err == nil {
			t.Fatal("a bad tenant id was accepted")
		}
	})
}

func TestReplayAndRollback(t *testing.T) {
	r := newRig(t, NewMemSeqStore())
	now := t0.Add(time.Minute)
	seqs := []struct {
		name string
		seq  uint64
		want *Refusal
	}{
		{"the first", 5, nil},
		{"the same again", 5, ErrRollback},
		{"an older one", 4, ErrRollback},
		{"the lowest possible", 1, ErrRollback},
		{"one higher", 6, nil},
		{"a big jump", 1000, nil},
		{"back to what was current before the jump", 6, ErrRollback},
		{"the maximum", MaxSequence, nil},
		{"anything after the maximum", MaxSequence, ErrRollback},
	}
	for _, tc := range seqs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.ver.Accept(r.sign(t, tenantA, edgeID, tc.seq), now)
			if tc.want == nil && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if tc.want != nil {
				wantRefusal(t, err, tc.want)
			}
		})
	}
	t.Run("another tenant has its own sequence", func(t *testing.T) {
		if _, err := r.ver.Accept(r.sign(t, tenantB, edgeID, 1), now); err != nil {
			t.Fatalf("tenant B's first envelope refused because of tenant A's sequence: %v", err)
		}
	})
	t.Run("Verify lets the current envelope through again, and refuses an older one", func(t *testing.T) {
		r := newRig(t, NewMemSeqStore())
		cur := r.sign(t, tenantA, edgeID, 9)
		if _, err := r.ver.Accept(cur, now); err != nil {
			t.Fatal(err)
		}
		if _, err := r.ver.Verify(cur, now); err != nil {
			t.Fatalf("the current envelope is refused at start-up: %v", err)
		}
		_, err := r.ver.Verify(r.sign(t, tenantA, edgeID, 8), now)
		wantRefusal(t, err, ErrRollback)
		if last, _ := r.store.Last(tenantA); last != 9 {
			t.Fatalf("Verify changed the record to %d", last)
		}
	})
	t.Run("a sequence is not spent by an envelope that fails another check", func(t *testing.T) {
		r := newRig(t, NewMemSeqStore())
		unsigned := strings.Replace(string(r.sign(t, tenantA, edgeID, 4000)), `"sig":"`, `"sig":"AAAA`, 1)
		if _, err := r.ver.Accept([]byte(unsigned), now); err == nil {
			t.Fatal("accepted")
		}
		wrongEdge := r.sign(t, tenantA, "edge-2", 5000)
		if _, err := r.ver.Accept(wrongEdge, now); err == nil {
			t.Fatal("accepted")
		}
		expired := r.sign(t, tenantA, edgeID, 6000)
		if _, err := r.ver.Accept(expired, t0.Add(48*time.Hour)); err == nil {
			t.Fatal("accepted")
		}
		if _, err := r.ver.Accept(r.sign(t, tenantA, edgeID, 1), now); err != nil {
			t.Fatalf("a refused envelope used up the sequence numbers: %v", err)
		}
	})
	t.Run("the same envelope given to another edge is for the wrong audience", func(t *testing.T) {
		raw := r.sign(t, tenantA, edgeID, 2_000_000)
		v2, err := NewVerifier(VerifierConfig{Audience: "edge-2", Tenants: []string{tenantA}, Store: NewMemSeqStore()})
		if err != nil {
			t.Fatal(err)
		}
		_ = v2.SetKeys([]TrustedKey{r.trust}, nil, time.Time{})
		_, err = v2.Accept(raw, now)
		wantRefusal(t, err, ErrWrongAudience)
	})
}

func TestTheWindowOfAnEnvelope(t *testing.T) {
	r := newRig(t, NewMemSeqStore())
	sign := func(nb, na time.Time) []byte {
		e, err := r.signer.SignWindow(tenantA, edgeID, 1, nb, na, payload)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := e.Marshal()
		return raw
	}
	nb, na := t0, t0.Add(24*time.Hour)
	raw := sign(nb, na)
	tests := []struct {
		name string
		now  time.Time
		want *Refusal
	}{
		{"at the start", nb, nil},
		{"inside", nb.Add(time.Hour), nil},
		{"at the very end", na, nil},
		{"within the skew before the start", nb.Add(-DefaultClockSkew), nil},
		{"one second more than the skew before the start", nb.Add(-DefaultClockSkew - time.Second), ErrNotYetValid},
		{"a day before the start", nb.Add(-24 * time.Hour), ErrNotYetValid},
		{"within the skew after the end", na.Add(DefaultClockSkew), nil},
		{"one second more than the skew after the end", na.Add(DefaultClockSkew + time.Second), ErrExpired},
		{"ten days after the end", na.Add(10 * 24 * time.Hour), ErrExpired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.ver.Verify(raw, tc.now)
			if tc.want == nil && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if tc.want != nil {
				wantRefusal(t, err, tc.want)
			}
		})
	}
	t.Run("the longest validity the edge allows is accepted and one second more is not", func(t *testing.T) {
		if _, err := r.ver.Verify(sign(nb, nb.Add(DefaultMaxValidity)), nb); err != nil {
			t.Fatalf("refused: %v", err)
		}
		_, err := r.ver.Verify(sign(nb, nb.Add(DefaultMaxValidity+time.Second)), nb)
		wantRefusal(t, err, ErrInvalidWindow)
	})
	t.Run("an edge can allow less", func(t *testing.T) {
		short, err := NewVerifier(VerifierConfig{Audience: edgeID, Tenants: []string{tenantA}, Store: NewMemSeqStore(), MaxValidity: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		_ = short.SetKeys([]TrustedKey{r.trust}, nil, time.Time{})
		_, err = short.Verify(raw, nb)
		wantRefusal(t, err, ErrInvalidWindow)
	})
	t.Run("the signer refuses what a verifier would", func(t *testing.T) {
		for name, win := range map[string][2]time.Time{
			"empty":      {nb, nb},
			"inverted":   {na, nb},
			"too long":   {nb, nb.Add(MaxValidityCap + time.Second)},
			"sub-second": {nb, nb.Add(500 * time.Millisecond)},
		} {
			if _, err := r.signer.SignWindow(tenantA, edgeID, 1, win[0], win[1], payload); err == nil {
				t.Errorf("%s window signed", name)
			}
		}
	})
}

func TestKeysRotateAndAreRevoked(t *testing.T) {
	oldKey, newKey := seededKey(30), seededKey(60)
	oldSigner, _ := NewSigner(oldKey)
	newSigner, _ := NewSigner(newKey)
	rotate := t0.Add(10 * 24 * time.Hour)
	oldTrust, _ := NewTrustedKey(oldSigner.Public(), t0.Add(-100*24*time.Hour), rotate)
	newTrust, _ := NewTrustedKey(newSigner.Public(), rotate.Add(-3*24*time.Hour), rotate.Add(200*24*time.Hour))
	mk := func(s *Signer, seq uint64, at time.Time) []byte {
		e, err := s.SignWindow(tenantA, edgeID, seq, at, at.Add(24*time.Hour), payload)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := e.Marshal()
		return raw
	}
	v, _ := NewVerifier(VerifierConfig{Audience: edgeID, Tenants: []string{tenantA}, Store: NewMemSeqStore()})
	if _, err := v.Verify(mk(oldSigner, 1, t0), t0); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("a Verifier with no keys did not refuse: %v", err)
	}
	if err := v.SetKeys([]TrustedKey{oldTrust, newTrust}, nil, time.Time{}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		raw  []byte
		now  time.Time
		want *Refusal
	}{
		{"the old key before the rotation", mk(oldSigner, 1, t0), t0, nil},
		{"the new key before it is used", mk(newSigner, 2, rotate.Add(-2*24*time.Hour)), rotate.Add(-2 * 24 * time.Hour), nil},
		{"the old key after its dates", mk(oldSigner, 3, rotate), rotate.Add(time.Second), ErrKeyNotValid},
		{"the new key after the rotation", mk(newSigner, 3, rotate), rotate.Add(time.Second), nil},
		{"the new key before its dates", mk(newSigner, 4, t0), t0, ErrKeyNotValid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(tc.raw, tc.now)
			if tc.want == nil && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if tc.want != nil {
				wantRefusal(t, err, tc.want)
			}
		})
	}
	t.Run("a revoked key is refused inside its dates, with a good signature", func(t *testing.T) {
		raw := mk(oldSigner, 9, t0)
		if _, err := v.Verify(raw, t0); err != nil {
			t.Fatalf("not accepted before the revocation: %v", err)
		}
		if err := v.SetKeys([]TrustedKey{oldTrust, newTrust}, []string{oldTrust.ID}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		_, err := v.Verify(raw, t0)
		wantRefusal(t, err, ErrRevokedKey)
		_, err = v.Accept(raw, t0)
		wantRefusal(t, err, ErrRevokedKey)
	})
	t.Run("a key that was revoked and then removed from the list stays refused as revoked", func(t *testing.T) {
		if err := v.SetKeys([]TrustedKey{newTrust}, []string{oldTrust.ID}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		_, err := v.Verify(mk(oldSigner, 9, t0), t0)
		wantRefusal(t, err, ErrRevokedKey)
	})
	t.Run("the other key is unaffected by a revocation", func(t *testing.T) {
		if _, err := v.Verify(mk(newSigner, 5, rotate), rotate); err != nil {
			t.Fatalf("refused: %v", err)
		}
	})
	t.Run("a key list that has run out of date believes nothing", func(t *testing.T) {
		if err := v.SetKeys([]TrustedKey{newTrust}, nil, rotate.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(mk(newSigner, 6, rotate), rotate); err != nil {
			t.Fatalf("refused before the list's expiry: %v", err)
		}
		_, err := v.Verify(mk(newSigner, 6, rotate), rotate.Add(2*time.Hour))
		wantRefusal(t, err, ErrKeyListExpired)
	})
	t.Run("published keys are independent of caller buffers", func(t *testing.T) {
		keys := []TrustedKey{oldTrust}
		keys[0].Public = append(ed25519.PublicKey(nil), oldTrust.Public...)
		revoked := []string{newTrust.ID}
		owned, err := NewVerifier(VerifierConfig{Audience: edgeID, Tenants: []string{tenantA}, Store: NewMemSeqStore()})
		if err != nil {
			t.Fatal(err)
		}
		if err := owned.SetKeys(keys, revoked, time.Time{}); err != nil {
			t.Fatal(err)
		}
		raw := mk(oldSigner, 1, t0)
		clear(keys[0].Public)
		keys[0].ID = newTrust.ID
		revoked[0] = oldTrust.ID
		if _, err := owned.Verify(raw, t0); err != nil {
			t.Fatalf("caller reused its buffers after SetKeys: %v", err)
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				keys[0].Public[0] = byte(i)
			}
		}()
		defer wg.Wait()
		for i := 0; i < 100; i++ {
			if _, err := owned.Verify(raw, t0); err != nil {
				t.Fatalf("verification changed when caller reused its key buffer: %v", err)
			}
		}
	})
	t.Run("a key list the verifier would not be able to use is refused whole", func(t *testing.T) {
		wrongID := newTrust
		wrongID.ID = "0123456789abcdef"
		dup := []TrustedKey{newTrust, newTrust}
		many := make([]TrustedKey, MaxTrustedKeys+1)
		for i := range many {
			k, _ := NewTrustedKey(seededKey(byte(i)).Public().(ed25519.PublicKey), t0, t0.Add(time.Hour))
			many[i] = k
		}
		for name, c := range map[string]struct {
			keys    []TrustedKey
			revoked []string
		}{
			"an id that is not the key's": {[]TrustedKey{wrongID}, nil},
			"a key listed twice":          {dup, nil},
			"too many keys":               {many, nil},
			"a revoked id of bad form":    {nil, []string{"XYZ"}},
			"too many revoked ids":        {nil, make([]string, MaxRevokedKeys+1)},
		} {
			before := v.keys.Load()
			if err := v.SetKeys(c.keys, c.revoked, time.Time{}); err == nil {
				t.Errorf("%s: accepted", name)
			}
			if v.keys.Load() != before {
				t.Errorf("%s: the list in force changed although the new one was refused", name)
			}
		}
	})
}

func TestRefusalsDoNotRepeatWhatTheSenderWrote(t *testing.T) {
	r := newRig(t, NewMemSeqStore())
	secret := "deadbeefdeadbeefdeadbeefdeadbeef"
	raws := [][]byte{
		r.sign(t, secret, edgeID, 12345678), // a tenant this edge does not serve
		r.sign(t, tenantA, "audience-from-a-stranger", 12345678),
		[]byte(strings.Replace(string(r.sign(t, tenantA, edgeID, 12345678)), `"key_id":"`, `"key_id":"0000`, 1)),
		r.sign(t, tenantA, edgeID, 12345678),
	}
	_, _ = r.ver.Accept(raws[3], t0.Add(time.Minute)) // so that the last one is a rollback
	for i, raw := range raws {
		_, err := r.ver.Accept(raw, t0.Add(time.Minute))
		if err == nil {
			continue
		}
		text := err.Error()
		for _, leak := range []string{secret, tenantA, "audience-from-a-stranger", "12345678", r.trust.ID, "0000"} {
			if strings.Contains(text, leak) {
				t.Errorf("case %d: %q contains %q", i, text, leak)
			}
		}
		if Reason(err) == "other" || !strings.HasPrefix(text, "config: ") {
			t.Errorf("case %d: %q has no stable code", i, text)
		}
	}
	codes := map[string]bool{}
	for _, e := range []*Refusal{ErrOversize, ErrMalformed, ErrUnsupportedVersion, ErrUnknownKey, ErrRevokedKey, ErrKeyNotValid, ErrKeyListExpired,
		ErrBadSignature, ErrWrongAudience, ErrWrongTenant, ErrNotYetValid, ErrExpired, ErrInvalidWindow, ErrRollback, ErrStoreCorrupt} {
		if codes[e.Code()] {
			t.Errorf("code %q is used twice", e.Code())
		}
		codes[e.Code()] = true
		if Reason(e) != e.Code() || Reason(fmt.Errorf("wrapped: %w", e)) != e.Code() {
			t.Errorf("Reason(%v)", e)
		}
	}
	if Reason(errors.New("x")) != "other" || Reason(storeFailure(errors.New("disk"))) != "store" {
		t.Error("Reason of an unknown error or a store failure")
	}
	if strings.Contains(storeFailure(errors.New("open /secret/path: denied")).Error(), "secret") {
		t.Error("a store failure repeats the operating system's text")
	}
}

func TestOversizeIsRefusedBeforeAnyWork(t *testing.T) {
	r := newRig(t, NewMemSeqStore())
	if _, err := r.ver.Verify(make([]byte, MaxEnvelopeBytes+1), t0); !errors.Is(err, ErrOversize) {
		t.Fatalf("got %v", err)
	}
	// A payload one byte over the cap, in an otherwise valid envelope.
	e, _ := Decode(r.sign(t, tenantA, edgeID, 1))
	e.Payload = append([]byte(`"`), append(make([]byte, MaxPayloadBytes), '"')...)
	for i := 1; i <= MaxPayloadBytes; i++ {
		e.Payload[i] = 'a'
	}
	if _, err := e.Marshal(); !errors.Is(err, ErrOversize) {
		t.Fatalf("Marshal of an oversize payload: %v", err)
	}
	if _, err := r.signer.SignWindow(tenantA, edgeID, 1, t0, t0.Add(time.Hour), e.Payload); !errors.Is(err, ErrOversize) {
		t.Fatalf("Sign of an oversize payload: %v", err)
	}
	// And the biggest allowed one still goes through, so the cap is the line and not something below it.
	e.Payload = e.Payload[:MaxPayloadBytes]
	e.Payload[MaxPayloadBytes-1] = '"'
	signed, err := r.signer.SignWindow(tenantA, edgeID, 1, t0, t0.Add(time.Hour), e.Payload)
	if err != nil {
		t.Fatalf("a payload of exactly the cap: %v", err)
	}
	raw, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > MaxEnvelopeBytes {
		t.Fatalf("an envelope with the largest payload is %d bytes, over MaxEnvelopeBytes", len(raw))
	}
	if _, err := r.ver.Verify(raw, t0); err != nil {
		t.Fatalf("the largest allowed envelope was refused: %v", err)
	}
}

func TestSignerRefusesWhatCannotBeVerified(t *testing.T) {
	s, err := NewSigner(seededKey(1))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return t0 }
	tests := []struct {
		name     string
		tenant   string
		audience string
		seq      uint64
		validity time.Duration
		payload  []byte
		ok       bool
	}{
		{"valid", tenantA, edgeID, 1, time.Hour, payload, true},
		{"the largest sequence", tenantA, edgeID, MaxSequence, time.Hour, payload, true},
		{"the longest validity", tenantA, edgeID, 1, MaxValidityCap, payload, true},
		{"sequence zero", tenantA, edgeID, 0, time.Hour, payload, false},
		{"sequence over the maximum", tenantA, edgeID, MaxSequence + 1, time.Hour, payload, false},
		{"upper-case tenant", strings.ToUpper(tenantA), edgeID, 1, time.Hour, payload, false},
		{"a tenant of 31 digits", tenantA[:31], edgeID, 1, time.Hour, payload, false},
		{"a tenant with a non-hex digit", "g" + tenantA[1:], edgeID, 1, time.Hour, payload, false},
		{"audience upper case", tenantA, "Edge", 1, time.Hour, payload, false},
		{"audience starting with a hyphen", tenantA, "-edge", 1, time.Hour, payload, false},
		{"audience of 64 characters", tenantA, strings.Repeat("a", 64), 1, time.Hour, payload, false},
		{"audience of 63 characters", tenantA, strings.Repeat("a", 63), 1, time.Hour, payload, true},
		{"zero validity", tenantA, edgeID, 1, 0, payload, false},
		{"negative validity", tenantA, edgeID, 1, -time.Hour, payload, false},
		{"validity over the cap", tenantA, edgeID, 1, MaxValidityCap + time.Second, payload, false},
		{"an empty payload", tenantA, edgeID, 1, time.Hour, nil, false},
		{"a payload that is not JSON", tenantA, edgeID, 1, time.Hour, []byte("not json"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, err := s.Sign(tc.tenant, tc.audience, tc.seq, tc.validity, tc.payload)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok = %v", err, tc.ok)
			}
			if err == nil {
				if !e.NotBefore.Equal(t0) || e.NotAfter.Sub(e.NotBefore) != tc.validity || e.KeyID != s.KeyID() {
					t.Fatalf("the window or key id is wrong: %+v", e)
				}
				raw, err := e.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				if back, err := Decode(raw); err != nil || back.Sequence != tc.seq {
					t.Fatalf("does not survive its own wire form: %v", err)
				}
			}
		})
	}
	t.Run("the payload is copied, so the caller cannot change a signed envelope", func(t *testing.T) {
		p := []byte(`{"a":1}`)
		e, _ := s.Sign(tenantA, edgeID, 1, time.Hour, p)
		p[5] = '2'
		if string(e.Payload) != `{"a":1}` {
			t.Fatal("the envelope shares the caller's slice")
		}
	})
	t.Run("a short or long key is refused", func(t *testing.T) {
		for _, n := range []int{0, 32, 63, 65} {
			if _, err := NewSigner(make([]byte, n)); err == nil {
				t.Errorf("a key of %d bytes accepted", n)
			}
		}
	})
}

func TestVerifierConfigurationIsChecked(t *testing.T) {
	st := NewMemSeqStore()
	tests := []struct {
		name string
		c    VerifierConfig
		ok   bool
	}{
		{"valid", VerifierConfig{Audience: edgeID, Tenants: []string{tenantA}, Store: st}, true},
		{"no tenants yet", VerifierConfig{Audience: edgeID, Store: st}, true},
		{"no store", VerifierConfig{Audience: edgeID, Tenants: []string{tenantA}}, false},
		{"a bad audience", VerifierConfig{Audience: "Edge 1", Store: st}, false},
		{"a bad tenant", VerifierConfig{Audience: edgeID, Tenants: []string{"x"}, Store: st}, false},
		{"negative validity", VerifierConfig{Audience: edgeID, Store: st, MaxValidity: -1}, false},
		{"validity over the cap", VerifierConfig{Audience: edgeID, Store: st, MaxValidity: MaxValidityCap + 1}, false},
		{"skew over the maximum", VerifierConfig{Audience: edgeID, Store: st, ClockSkew: MaxClockSkew + 1}, false},
		{"negative skew", VerifierConfig{Audience: edgeID, Store: st, ClockSkew: -1}, false},
		{"the maximum skew", VerifierConfig{Audience: edgeID, Store: st, ClockSkew: MaxClockSkew}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVerifier(tc.c)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// A thousand envelopes with random sequence numbers, for several tenants, presented at once. Whatever the order they
// arrive in: no number is accepted twice for a tenant, the highest number offered for a tenant is always accepted, and
// afterwards the record holds exactly that highest number.
func TestAThousandEnvelopesPresentedAtOnce(t *testing.T) {
	stores := map[string]func(t *testing.T) SeqStore{
		"memory": func(t *testing.T) SeqStore { return NewMemSeqStore() },
		"file": func(t *testing.T) SeqStore {
			s, err := OpenFileSeqStore(filepath.Join(t.TempDir(), "seq"))
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	}
	for name, mk := range stores {
		t.Run(name, func(t *testing.T) {
			for round := 0; round < 3; round++ {
				store := mk(t)
				r := newRig(t, store)
				tenants := []string{tenantA, tenantB, "dddddddddddddddddddddddddddddddd", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
				if err := r.ver.SetTenants(tenants); err != nil {
					t.Fatal(err)
				}
				rng := rand.New(rand.NewSource(int64(round) + 1))
				type item struct {
					tenant string
					seq    uint64
					raw    []byte
				}
				items := make([]item, 1000)
				highest := map[string]uint64{}
				for i := range items {
					tn := tenants[rng.Intn(len(tenants))]
					seq := uint64(rng.Intn(300) + 1) // many repeats on purpose
					items[i] = item{tn, seq, r.sign(t, tn, edgeID, seq)}
					if seq > highest[tn] {
						highest[tn] = seq
					}
				}
				var mu sync.Mutex
				accepted := map[string][]uint64{}
				var refusedOther []error
				var wg sync.WaitGroup
				start := make(chan struct{})
				const workers = 24
				for w := 0; w < workers; w++ {
					wg.Add(1)
					go func(w int) {
						defer wg.Done()
						<-start
						for i := w; i < len(items); i += workers {
							_, err := r.ver.Accept(items[i].raw, t0.Add(time.Minute))
							mu.Lock()
							switch {
							case err == nil:
								accepted[items[i].tenant] = append(accepted[items[i].tenant], items[i].seq)
							case !errors.Is(err, ErrRollback):
								refusedOther = append(refusedOther, err)
							}
							mu.Unlock()
						}
					}(w)
				}
				close(start)
				wg.Wait()
				if len(refusedOther) > 0 {
					t.Fatalf("round %d: refused for another reason: %v", round, refusedOther[0])
				}
				total := 0
				for _, tn := range tenants {
					seen := map[uint64]bool{}
					var max uint64
					for _, s := range accepted[tn] {
						if seen[s] {
							t.Fatalf("round %d: tenant %s: sequence %d accepted twice", round, tn[:4], s)
						}
						seen[s] = true
						if s > max {
							max = s
						}
					}
					if max != highest[tn] {
						t.Fatalf("round %d: tenant %s: the highest accepted is %d, the highest offered %d", round, tn[:4], max, highest[tn])
					}
					last, err := store.Last(tn)
					if err != nil || last != highest[tn] {
						t.Fatalf("round %d: tenant %s: the record holds %d (%v), want %d", round, tn[:4], last, err, highest[tn])
					}
					total += len(accepted[tn])
				}
				t.Logf("round %d: %d of 1000 accepted, each tenant ended on its highest number", round, total)
			}
		})
	}
}
