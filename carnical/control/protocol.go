// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// The names and values of the signing protocol (docs/control-api.md has the byte-by-byte description and a vector).
const (
	// AuthScheme is the first word of the Authorization header.
	AuthScheme = "Carnical-Sig"
	// HeaderActingUser carries the id of the person the UI is acting for. It is signed.
	HeaderActingUser = "Carnical-Acting-User"
	// HeaderStepUp carries the time (Unix seconds) at which the customer last proved who they are, for a request
	// that needs it. It is signed.
	HeaderStepUp = "Carnical-Stepup-At"
	// HeaderRequestID is on every response.
	HeaderRequestID = "X-Request-Id"
	// CanonicalPrefix is the first line of the signed text. It keeps a signature made for this protocol from being
	// valid in any other.
	CanonicalPrefix = "carnical-control-v1"

	maxTimestamp = int64(999_999_999_999) // 12 digits
	maxAuthLen   = 300
)

// AuthHeader is a parsed Authorization header.
type AuthHeader struct {
	Credential string
	Timestamp  int64
	Nonce      string // 32 lower-case hex digits
	Signature  []byte // 64 bytes
}

var errAuth = errors.New("control: malformed authorization header")

// ParseAuthHeader reads exactly
//
//	Carnical-Sig cred=<id>, ts=<unix seconds>, nonce=<32 hex>, sig=<86 characters of base64url>
//
// and nothing else: the four fields in that order, one comma and one space between them, no repeats, no extra text.
// It never panics and does a bounded amount of work.
func ParseAuthHeader(v string) (AuthHeader, error) {
	var h AuthHeader
	if len(v) > maxAuthLen || !strings.HasPrefix(v, AuthScheme+" ") {
		return h, errAuth
	}
	parts := strings.Split(v[len(AuthScheme)+1:], ", ")
	if len(parts) != 4 {
		return h, errAuth
	}
	for i, name := range [4]string{"cred=", "ts=", "nonce=", "sig="} {
		if !strings.HasPrefix(parts[i], name) {
			return h, errAuth
		}
		parts[i] = parts[i][len(name):]
	}
	if !ValidCredentialID(parts[0]) {
		return h, errAuth
	}
	h.Credential = parts[0]
	ts, ok := parseTimestamp(parts[1])
	if !ok {
		return h, errAuth
	}
	h.Timestamp = ts
	if len(parts[2]) != 32 || !isLowerHex(parts[2]) {
		return h, errAuth
	}
	h.Nonce = parts[2]
	if len(parts[3]) != 86 {
		return h, errAuth
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return h, errAuth
	}
	h.Signature = sig
	return h, nil
}

// parseTimestamp reads 1 to 12 digits with no leading zero (so each number has one spelling, and the text that is
// signed is the text that is parsed). Zero is not a time.
func parseTimestamp(s string) (int64, bool) {
	if len(s) == 0 || len(s) > 12 || s[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// String formats the header.
func (h AuthHeader) String() string {
	return AuthScheme + " cred=" + h.Credential + ", ts=" + strconv.FormatInt(h.Timestamp, 10) + ", nonce=" + h.Nonce +
		", sig=" + base64.RawURLEncoding.EncodeToString(h.Signature)
}

// SignedRequest is everything a signature covers. The server builds the same value from the request it received and
// checks the signature against it, so a signature made for one request is valid for no other.
type SignedRequest struct {
	Method     string
	Host       string // the Host header (the authority), so a signature for one server is not valid at another
	Target     string // the request target exactly as sent: path and query
	BodySHA256 [sha256.Size]byte
	Timestamp  int64
	Nonce      string
	Credential string
	Tenant     string // from the path; "" for routes that are not about one tenant
	User       string // the acting user's id
	StepUp     int64  // the step-up time, valid when HasStepUp
	HasStepUp  bool
	IfMatch    string // the If-Match header as sent, or ""
	IdemKey    string // the Idempotency-Key header as sent, or ""
}

// CanonicalString returns the text that is signed: the prefix and twelve fields, one per line, thirteen lines in all,
// with no line break at the end:
//
//	carnical-control-v1
//	<METHOD>
//	<host, lower case>
//	<request target as sent>
//	<hex SHA-256 of the body>
//	<timestamp>
//	<nonce>
//	<credential id>
//	<tenant id or ->
//	<acting user>
//	<step-up time or ->
//	<If-Match as sent or ->
//	<Idempotency-Key as sent or ->
//
// A field that cannot be written on one line without ambiguity (a line break, a control character, anything outside
// printable ASCII, an empty required field, or a single "-" where "absent" is written as "-") makes this return an
// error, so no two different requests can produce the same text.
func (r SignedRequest) CanonicalString() (string, error) {
	if !validMethod(r.Method) {
		return "", errors.New("control: method")
	}
	host := strings.ToLower(r.Host)
	if !validHost(host) {
		return "", errors.New("control: host")
	}
	if !validTarget(r.Target) {
		return "", errors.New("control: target")
	}
	if r.Timestamp <= 0 || r.Timestamp > maxTimestamp {
		return "", errors.New("control: timestamp")
	}
	if len(r.Nonce) != 32 || !isLowerHex(r.Nonce) {
		return "", errors.New("control: nonce")
	}
	if !ValidCredentialID(r.Credential) {
		return "", errors.New("control: credential")
	}
	tenant := "-"
	if r.Tenant != "" {
		if !ValidTenantID(r.Tenant) {
			return "", errors.New("control: tenant")
		}
		tenant = r.Tenant
	}
	if !visibleASCII(r.User, 1, 128) {
		return "", errors.New("control: user")
	}
	stepUp := "-"
	if r.HasStepUp {
		if r.StepUp < 0 || r.StepUp > maxTimestamp {
			return "", errors.New("control: step-up")
		}
		stepUp = strconv.FormatInt(r.StepUp, 10)
	}
	// "-" stands for "absent", so it cannot also be a value: the fields that may be absent either cannot be a single
	// "-" anyway (a tenant id is hex, a step-up time is digits) or are refused here (If-Match, Idempotency-Key, user).
	ifMatch, idem := "-", "-"
	if r.IfMatch != "" {
		if !visibleASCII(r.IfMatch, 1, 128) || r.IfMatch == "-" {
			return "", errors.New("control: if-match")
		}
		ifMatch = r.IfMatch
	}
	if r.IdemKey != "" {
		if !visibleASCII(r.IdemKey, 1, 128) || r.IdemKey == "-" {
			return "", errors.New("control: idempotency key")
		}
		idem = r.IdemKey
	}
	var b strings.Builder
	b.Grow(300 + len(r.Target))
	for i, f := range []string{CanonicalPrefix, r.Method, host, r.Target, hex.EncodeToString(r.BodySHA256[:]),
		strconv.FormatInt(r.Timestamp, 10), r.Nonce, r.Credential, tenant, r.User, stepUp, ifMatch, idem} {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(f)
	}
	return b.String(), nil
}

// CanonicalFields splits a canonical string back into its thirteen parts: the prefix and twelve fields. Tests and the
// fuzz target use it to check that the string is unambiguous. It reports false if there are not exactly thirteen.
func CanonicalFields(s string) ([]string, bool) {
	f := strings.Split(s, "\n")
	return f, len(f) == 13 && f[0] == CanonicalPrefix
}

// Sign signs a request with the credential's private key.
func Sign(key ed25519.PrivateKey, r SignedRequest) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("control: signing key")
	}
	s, err := r.CanonicalString()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, []byte(s)), nil
}

func validMethod(m string) bool {
	if len(m) < 3 || len(m) > 7 {
		return false
	}
	for i := 0; i < len(m); i++ {
		if m[i] < 'A' || m[i] > 'Z' {
			return false
		}
	}
	return true
}

func validHost(h string) bool {
	if len(h) == 0 || len(h) > 255 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '-' && c != ':' && c != '[' && c != ']' {
			return false
		}
	}
	return true
}

// validTarget is the structural rule for what is signed: an origin-form target in printable ASCII with no space and no
// fragment. The routing rules (routes.go) are much stricter; this one only guarantees one line.
func validTarget(t string) bool {
	if len(t) == 0 || len(t) > 2048 || t[0] != '/' {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x21 || t[i] > 0x7e || t[i] == '#' {
			return false
		}
	}
	return true
}

func visibleASCII(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// TenantFromTarget returns the tenant a request target is about: the 32 hex digits after /v1/tenants/, or "". The
// client uses it to fill the tenant field it signs; the server takes the tenant from the route it matched, which is
// the same value for every route.
func TenantFromTarget(target string) string {
	const p = "/v1/tenants/"
	if !strings.HasPrefix(target, p) || len(target) < len(p)+32 {
		return ""
	}
	t := target[len(p) : len(p)+32]
	if !ValidTenantID(t) {
		return ""
	}
	if rest := target[len(p)+32:]; rest != "" && rest[0] != '/' && rest[0] != '?' {
		return ""
	}
	return t
}
