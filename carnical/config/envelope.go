// SPDX-License-Identifier: Apache-2.0

// Package config is how a configuration reaches an edge so that a compromised control host, a network attacker or a
// replay cannot change what an edge enforces for a tenant (docs/segmentation.md, rule T5).
//
// A configuration travels as a signed Envelope. The signature covers the tenant it is for, the edge it is for, a
// sequence number, a validity window, the key that signed it and the payload, in one fixed encoding (SigningBytes), so
// that nothing about where, when or for whom it is valid can be changed without the signature failing. An edge holds a
// Verifier: it knows its own id, the tenants it is assigned, the signing keys it trusts, and the newest sequence number
// it has accepted for each tenant, and it refuses everything else.
//
// What is not here: choosing what the payload says (package policy), delivering the envelope (the control API), or what
// an edge does while it has no valid configuration. Nothing in this package opens a network connection, and nothing
// holds a secret except the signing key inside a Signer, which belongs in the signer service and never in an edge.
package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

const (
	// Version is the only envelope layout this package writes and reads.
	Version = 1

	// domain starts every signed message. It names what is signed and the layout, so that a signature made for a
	// different purpose, or for a later layout, can never be a valid signature here (and the reverse).
	domain = "carnical-config-v1"

	// MaxPayloadBytes is the most a payload may hold. A policy is at most 1 MiB, so this leaves room.
	MaxPayloadBytes = 2 << 20
	// MaxEnvelopeBytes is the most the JSON form of an envelope may hold (the payload grows by a third in base64).
	MaxEnvelopeBytes = 4 << 20
	// MaxSequence is the largest sequence number. It is the largest integer every JSON reader keeps exactly (2^53 - 1),
	// so a number cannot change on its way through a tool that reads it as a floating-point value.
	MaxSequence = 1<<53 - 1
)

var (
	tenantRe   = regexp.MustCompile(`\A[0-9a-f]{32}\z`)
	audienceRe = regexp.MustCompile(`\A[a-z0-9][a-z0-9._-]{0,62}\z`)
	keyIDRe    = regexp.MustCompile(`\A[0-9a-f]{16}\z`)
	timeRe     = regexp.MustCompile(`\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z`)
	seqRe      = regexp.MustCompile(`\A(?:0|[1-9][0-9]{0,15})\z`)
)

const timeLayout = "2006-01-02T15:04:05Z"

// ValidTenant reports whether s is a tenant id: 32 lower-case hexadecimal digits (docs/segmentation.md, T1).
func ValidTenant(s string) bool { return tenantRe.MatchString(s) }

// ValidAudience reports whether s can name an edge: 1 to 63 characters of a-z, 0-9, dot, underscore and hyphen, starting
// with a letter or a digit.
func ValidAudience(s string) bool { return audienceRe.MatchString(s) }

// KeyID is the identifier of a public key: the first 16 hexadecimal digits of the SHA-256 of its 32 bytes. It is the
// same rule the release scheme uses (newsletter/brief/waf/keys.py, key_id), so one tool can name both kinds of key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Envelope is a signed configuration for one tenant, for one edge.
type Envelope struct {
	// Version is the layout version (always 1 for now).
	Version uint16
	// Tenant is the tenant id the configuration is for (32 lower-case hex digits).
	Tenant string
	// Audience is the id of the edge it is for.
	Audience string
	// Sequence rises by at least one with every configuration for a tenant. An edge refuses one that is not higher than
	// the highest it has accepted.
	Sequence uint64
	// NotBefore and NotAfter are the window in which the envelope may be accepted, to the second, in UTC.
	NotBefore, NotAfter time.Time
	// KeyID names the key that signed it (see KeyID).
	KeyID string
	// Payload is the configuration itself, a JSON document. The envelope does not look inside it.
	Payload []byte
	// Signature is the Ed25519 signature over SigningBytes.
	Signature []byte
}

// SigningBytes returns the exact bytes that are signed. The format is fixed, and written out in docs/config-and-policy.md:
//
//	"carnical-config-v1"                      the 18 ASCII bytes of the domain, with no length and no terminator
//	then each of these fields, in this order, as a 4-byte big-endian length followed by that many bytes:
//	  version     2 bytes, big-endian                          (1)
//	  tenant      the 32 ASCII characters
//	  audience    the ASCII characters (1 to 63)
//	  sequence    8 bytes, big-endian
//	  not_before  8 bytes, big-endian two's complement, seconds since 1970-01-01T00:00:00Z
//	  not_after   8 bytes, as above
//	  key_id      the 16 ASCII characters
//	  payload     the payload bytes
//
// Because every field is length-prefixed and the order never changes, two different envelopes can never give the same
// bytes (there is no way to move a byte from one field to the next), and the domain at the front means these bytes can
// never be mistaken for anything else that is signed with the same key.
func (e *Envelope) SigningBytes() []byte {
	b := make([]byte, 0, len(domain)+8*4+2+len(e.Tenant)+len(e.Audience)+8+8+8+len(e.KeyID)+len(e.Payload))
	b = append(b, domain...)
	b = lp(b, binary.BigEndian.AppendUint16(nil, e.Version))
	b = lp(b, []byte(e.Tenant))
	b = lp(b, []byte(e.Audience))
	b = lp(b, binary.BigEndian.AppendUint64(nil, e.Sequence))
	b = lp(b, binary.BigEndian.AppendUint64(nil, uint64(e.NotBefore.Unix())))
	b = lp(b, binary.BigEndian.AppendUint64(nil, uint64(e.NotAfter.Unix())))
	b = lp(b, []byte(e.KeyID))
	b = lp(b, e.Payload)
	return b
}

// lp appends a 4-byte big-endian length and then the bytes.
func lp(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}

// wire is the JSON form, in the order the fields are written.
type wire struct {
	V         int    `json:"v"`
	Tenant    string `json:"tenant"`
	Audience  string `json:"audience"`
	Seq       uint64 `json:"seq"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Sig       string `json:"sig"`
}

var b64 = base64.RawURLEncoding.Strict()

// Marshal writes the JSON form of the envelope: one object with exactly the fields v, tenant, audience, seq,
// not_before, not_after, key_id, payload and sig. Times are written as 2026-10-05T08:00:00Z; the payload and the
// signature are base64url without padding. It refuses an envelope that Decode would refuse.
func (e *Envelope) Marshal() ([]byte, error) {
	if err := e.check(); err != nil {
		return nil, err
	}
	return json.Marshal(wire{V: int(e.Version), Tenant: e.Tenant, Audience: e.Audience, Seq: e.Sequence,
		NotBefore: e.NotBefore.UTC().Format(timeLayout), NotAfter: e.NotAfter.UTC().Format(timeLayout),
		KeyID: e.KeyID, Payload: b64.EncodeToString(e.Payload), Sig: b64.EncodeToString(e.Signature)})
}

// check is every rule about an envelope that does not need a key or a clock.
func (e *Envelope) check() error {
	switch {
	case e.Version != Version:
		return ErrUnsupportedVersion
	case !tenantRe.MatchString(e.Tenant), !audienceRe.MatchString(e.Audience), !keyIDRe.MatchString(e.KeyID):
		return ErrMalformed
	case e.Sequence < 1 || e.Sequence > MaxSequence:
		return ErrMalformed
	case len(e.Signature) != ed25519.SignatureSize:
		return ErrMalformed
	case e.NotBefore.Unix() < 0 || e.NotAfter.Unix() < 0 || e.NotBefore.Year() > 9999 || e.NotAfter.Year() > 9999:
		return ErrMalformed
	case len(e.Payload) > MaxPayloadBytes:
		return ErrOversize
	case len(e.Payload) == 0 || !json.Valid(e.Payload):
		return ErrMalformed
	}
	return nil
}

// Decode reads the JSON form of an envelope strictly. It does not check the signature or anything about what the
// envelope says; that is the Verifier's job. It never panics, uses memory in proportion to the input, and refuses (with
// ErrMalformed, ErrOversize or ErrUnsupportedVersion): input over MaxEnvelopeBytes, anything that is not a single JSON
// object, an unknown, missing or repeated field, a value of the wrong kind, text that is not valid UTF-8, a field outside
// its form, a payload that is not JSON, and base64 in any spelling but the canonical one.
func Decode(raw []byte) (*Envelope, error) {
	if len(raw) > MaxEnvelopeBytes {
		return nil, ErrOversize
	}
	fields, err := flatObject(raw, 9)
	if err != nil {
		return nil, err
	}
	str := func(name string) (string, bool) {
		v, ok := fields[name]
		if !ok || len(v) == 0 || v[0] != '"' {
			return "", false
		}
		var s string
		if json.Unmarshal(v, &s) != nil {
			return "", false
		}
		return s, true
	}
	num := func(name string) (uint64, bool) {
		v, ok := fields[name]
		if !ok || !seqRe.Match(v) {
			return 0, false
		}
		n, err := strconv.ParseUint(string(v), 10, 64)
		return n, err == nil
	}
	e := &Envelope{}
	v, ok := num("v")
	if !ok {
		return nil, ErrMalformed
	}
	var tenant, audience, nb, na, keyID, payload, sig string
	for name, dst := range map[string]*string{"tenant": &tenant, "audience": &audience, "not_before": &nb, "not_after": &na,
		"key_id": &keyID, "payload": &payload, "sig": &sig} {
		if *dst, ok = str(name); !ok {
			return nil, ErrMalformed
		}
	}
	seq, ok := num("seq")
	if !ok || len(fields) != 9 {
		return nil, ErrMalformed
	}
	e.NotBefore, ok = parseTime(nb)
	if !ok {
		return nil, ErrMalformed
	}
	if e.NotAfter, ok = parseTime(na); !ok {
		return nil, ErrMalformed
	}
	// The payload is checked for size before it is decoded, so an oversize one costs nothing.
	if base64.RawURLEncoding.DecodedLen(len(payload)) > MaxPayloadBytes {
		return nil, ErrOversize
	}
	if e.Payload, err = b64.DecodeString(payload); err != nil {
		return nil, ErrMalformed
	}
	if e.Signature, err = b64.DecodeString(sig); err != nil {
		return nil, ErrMalformed
	}
	e.Tenant, e.Audience, e.KeyID, e.Sequence = tenant, audience, keyID, seq
	if v != Version {
		// Everything above had to be well formed first, so that an unsupported version means a real one.
		return nil, ErrUnsupportedVersion
	}
	e.Version = Version
	if err := e.check(); err != nil {
		return nil, err
	}
	return e, nil
}

func parseTime(s string) (time.Time, bool) {
	if !timeRe.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(timeLayout, s)
	return t, err == nil
}

// flatObject reads a JSON object whose values are all strings or non-negative whole numbers, and returns each value's raw
// text. It refuses a repeated name, more than max fields, a nested value, input that is not valid UTF-8, anything after
// the closing brace, and any syntax error. encoding/json would silently take the last of two equal names; two readers
// that disagree about which one counts is how signed data gets read differently from how it was checked.
func flatObject(raw []byte, max int) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, ErrMalformed
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, ErrMalformed
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, ErrMalformed
		}
		key, ok := kt.(string)
		if !ok {
			return nil, ErrMalformed
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, ErrMalformed
		}
		if _, dup := out[key]; dup || len(out) >= max {
			return nil, ErrMalformed
		}
		if len(v) == 0 || (v[0] != '"' && (v[0] < '0' || v[0] > '9')) {
			return nil, ErrMalformed
		}
		out[key] = v
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, ErrMalformed
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrMalformed
	}
	return out, nil
}
