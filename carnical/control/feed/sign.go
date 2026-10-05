// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Scheme is the first word of the Authorization header and of the signed text.
const Scheme = "SFW1"

// authRE is the header exactly as the PHP console reads it: four fields in this order, one optional space after each
// comma, nothing before or after. \A and \z are used rather than ^ and $ so no trailing newline can slip past.
var authRE = regexp.MustCompile(`\ASFW1 key=([0-9a-f]{16}), ?ts=([0-9]{1,12}), ?nonce=([0-9a-f]{32}), ?sig=([0-9a-f]{64})\z`)

// Authz is a parsed Authorization header. TSText is kept as it was sent because the signature covers the digits as
// sent, and a leading zero would change them without changing the number.
type Authz struct {
	KeyID  string
	TSText string
	TS     int64
	Nonce  string
	Sig    string
}

// ParseAuthorization reads the header value. It reports false for anything that is not exactly the documented form.
// It never panics and does a bounded amount of work (the expression is linear and the length is checked first).
func ParseAuthorization(h string) (Authz, bool) {
	// The longest valid header is "SFW1 key=" + 16 + ", ts=" + 12 + ", nonce=" + 32 + ", sig=" + 64: well under 200.
	if len(h) > 200 {
		return Authz{}, false
	}
	m := authRE.FindStringSubmatch(h)
	if m == nil {
		return Authz{}, false
	}
	ts, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil {
		return Authz{}, false
	}
	return Authz{KeyID: m[1], TSText: m[2], TS: ts, Nonce: m[3], Sig: m[4]}, true
}

// signedText is what the signature covers: the scheme, the method, the target exactly as sent, the time and the
// nonce, each on its own line. The target and the time are taken as text so a request is checked against the bytes
// that were signed.
func signedText(target, tsText, nonce string) string {
	return Scheme + "\nGET\n" + target + "\n" + tsText + "\n" + nonce
}

// SignedText returns the text a signature covers, for tests and for tools that sign requests.
func SignedText(target string, ts int64, nonce string) string {
	return signedText(target, strconv.FormatInt(ts, 10), nonce)
}

func sign(secret []byte, target, tsText, nonce string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(signedText(target, tsText, nonce)))
	return hex.EncodeToString(m.Sum(nil))
}

// Sign returns the lower-case hex signature of a request.
func Sign(secret []byte, target string, ts int64, nonce string) string {
	return sign(secret, target, strconv.FormatInt(ts, 10), nonce)
}

// Authorization returns the header value for one request. It is what the owner's console does in Python
// (feed.authorization); here it is for tests and for Go tools that read a feed.
func Authorization(keyID string, secret []byte, target string, ts int64, nonce string) (string, error) {
	if !isLowerHex(keyID, 16) || !isLowerHex(nonce, 32) {
		return "", errors.New("feed: a key id is 16 hex digits and a nonce 32")
	}
	if ts < 0 || ts > 999999999999 {
		return "", errors.New("feed: the time is out of range")
	}
	return Scheme + " key=" + keyID + ", ts=" + strconv.FormatInt(ts, 10) + ", nonce=" + nonce + ", sig=" + Sign(secret, target, ts, nonce), nil
}

// SecretText shows a 32-byte secret as the owner's console wants it pasted: 43 characters of base64url, no padding.
func SecretText(secret []byte) string { return base64.RawURLEncoding.EncodeToString(secret) }

// SecretFromText is the reverse of SecretText. It refuses anything that does not decode to exactly 32 bytes with
// nothing left over in the last character, as the reader does.
func SecretFromText(text string) ([]byte, error) {
	text = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, text)
	if len(text) != 43 {
		return nil, errors.New("feed: a key is 43 characters of base64url")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("feed: that is not a key")
	}
	return raw, nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
