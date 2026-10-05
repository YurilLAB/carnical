// SPDX-License-Identifier: Apache-2.0

package config

import "errors"

// Refusal is the reason a configuration envelope or a key list was not accepted. The values below are the only ones
// this package returns for a refusal, so a caller can compare with errors.Is and a log line can say why without
// repeating anything the sender wrote: no tenant id, key id, sequence number or payload byte is ever in the text.
// What an edge logs for each refusal is Code(), which stays the same across releases.
type Refusal struct {
	code string
	text string
}

// Error implements error.
func (r *Refusal) Error() string { return r.text }

// Code is a short stable name for the refusal, such as "rollback", for logs and counters.
func (r *Refusal) Code() string { return r.code }

func refusal(code, text string) *Refusal { return &Refusal{code: code, text: "config: " + text} }

// The refusals. Which one an envelope gets depends on the order of the checks, which is on purpose: everything about the
// sender that is only believable once the signature has been checked (the audience, the tenant, the dates, the
// sequence) is judged after it, so a refusal that names one of those means the envelope really was signed by a trusted
// key.
var (
	// ErrOversize: the envelope, or what it carries, is larger than allowed.
	ErrOversize = refusal("oversize", "the envelope is larger than allowed")
	// ErrMalformed: the bytes are not an envelope of the exact shape this package reads (an unknown, missing or repeated
	// field, a value of the wrong kind or form, a payload that is not JSON).
	ErrMalformed = refusal("malformed", "the envelope is not well formed")
	// ErrUnsupportedVersion: a well-formed envelope of a layout version this package does not know.
	ErrUnsupportedVersion = refusal("unsupported_version", "the envelope is of a version this program does not read")
	// ErrUnknownKey: signed by a key that is not in the trusted list (or no list has been loaded yet).
	ErrUnknownKey = refusal("unknown_key", "signed by a key that is not trusted")
	// ErrRevokedKey: signed by a key that has been revoked, whatever its dates say.
	ErrRevokedKey = refusal("revoked_key", "signed by a key that has been revoked")
	// ErrKeyNotValid: signed by a trusted key that is not yet valid, or no longer valid, at this time.
	ErrKeyNotValid = refusal("key_not_valid", "signed by a key outside its validity dates")
	// ErrKeyListExpired: the trusted key list itself has run out of date, so no key is believed until a newer one arrives.
	ErrKeyListExpired = refusal("key_list_expired", "the trusted key list is out of date")
	// ErrBadSignature: the signature does not match the envelope.
	ErrBadSignature = refusal("bad_signature", "the signature does not match")
	// ErrWrongAudience: a genuine envelope that is addressed to another edge.
	ErrWrongAudience = refusal("wrong_audience", "the envelope is for another edge")
	// ErrWrongTenant: a genuine envelope for a tenant this edge is not assigned.
	ErrWrongTenant = refusal("wrong_tenant", "the envelope is for a tenant this edge does not serve")
	// ErrNotYetValid: a genuine envelope whose validity has not started.
	ErrNotYetValid = refusal("not_yet_valid", "the envelope is not valid yet")
	// ErrExpired: a genuine envelope whose validity has ended.
	ErrExpired = refusal("expired", "the envelope has expired")
	// ErrInvalidWindow: a genuine envelope whose validity is empty or longer than this edge allows.
	ErrInvalidWindow = refusal("invalid_window", "the envelope's validity is empty or too long")
	// ErrRollback: a genuine envelope that is not newer than the newest this edge has accepted for the tenant.
	ErrRollback = refusal("rollback", "the envelope is not newer than the one already accepted")
	// ErrStoreCorrupt: the record of the newest accepted sequence cannot be trusted. Nothing is accepted for that tenant
	// until an operator looks at it, because guessing a number could let an old envelope back in.
	ErrStoreCorrupt = refusal("store_corrupt", "the record of accepted sequence numbers is damaged")
)

// ErrStore is returned, wrapped, when the sequence record cannot be read or written (a full disk, a permission). The
// envelope is not accepted, since accepting it without recording it would let it be replayed. errors.Is(err, ErrStore)
// is true for these; the operating system's own error is available through errors.Unwrap but is not in the text.
var ErrStore = errors.New("config: the record of accepted sequence numbers could not be read or written")

type storeError struct{ cause error }

func (e *storeError) Error() string        { return ErrStore.Error() }
func (e *storeError) Unwrap() []error      { return []error{ErrStore, e.cause} }
func storeFailure(cause error) error       { return &storeError{cause: cause} }
func isRefusal(err error, r *Refusal) bool { return errors.Is(err, r) }

// Reason returns the stable code of a refusal, "store" for a failure of the sequence record, or "other".
func Reason(err error) string {
	var r *Refusal
	switch {
	case errors.As(err, &r):
		return r.code
	case errors.Is(err, ErrStore):
		return "store"
	}
	return "other"
}
