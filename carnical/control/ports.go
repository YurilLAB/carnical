// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"errors"
	"time"

	"github.com/YurilLAB/coraza/carnical/control/feed"
)

// Errors that the interfaces below return, and that the API turns into a status. Anything else an implementation
// returns is reported to the caller as a plain internal error, with no text from the implementation.
var (
	// ErrNotFound means there is no such policy, revision or host for the tenant.
	ErrNotFound = errors.New("control: not found")
	// ErrConflict means a Put named a revision that is no longer the current one.
	ErrConflict = errors.New("control: revision conflict")
	// ErrHostTaken means another tenant already holds a verified claim on the hostname.
	ErrHostTaken = errors.New("control: hostname taken")
	// ErrUnavailable means a dependency (such as the DNS resolver) could not answer; the caller may retry.
	ErrUnavailable = errors.New("control: dependency unavailable")
)

// Document is a tenant's policy at one revision. The body is opaque to this package apart from being a JSON object.
type Document struct {
	Revision uint64
	Body     []byte
	Updated  time.Time
}

// PutMeta tells the store who made a change and why, so that its history can say.
type PutMeta struct {
	Actor        string   // the acting user, as the UI named them
	Credential   string   // the service credential that carried the request
	RequestID    string   // for matching the audit log
	Kind         string   // "put" or "rollback"
	RolledBackTo uint64   // the revision whose content was restored, for a rollback
	Weakening    []string // codes of the weakening changes this revision makes, which needed a step-up
}

// HistoryEntry is one line of a tenant's policy history.
type HistoryEntry struct {
	Revision     uint64
	At           time.Time
	Actor        string
	Credential   string
	Kind         string
	RolledBackTo uint64
	Weakening    []string
}

// PolicyStore keeps one revisioned, opaque JSON document per tenant. Implementations must be safe for concurrent use,
// must only ever touch the named tenant's data, and must make Put atomic with respect to the revision check.
type PolicyStore interface {
	// Get returns the current document, or ErrNotFound when the tenant has none yet.
	Get(ctx context.Context, tenant string) (Document, error)
	// Put stores body as the next revision if the current revision is exactly expect (0 means there is none yet), and
	// returns the new revision. It returns ErrConflict otherwise. Revisions rise by one and are never reused.
	Put(ctx context.Context, tenant string, body []byte, expect uint64, meta PutMeta) (uint64, error)
	// Revision returns an earlier document, or ErrNotFound.
	Revision(ctx context.Context, tenant string, revision uint64) (Document, error)
	// History returns up to limit entries, newest first, for revisions below before (0 means from the newest).
	History(ctx context.Context, tenant string, before uint64, limit int) ([]HistoryEntry, error)
}

// Problem is one reason a proposed document cannot be accepted.
type Problem struct {
	Code    string
	Message string
}

// Change is one change a proposed document makes. For a weakening change the summary is what the UI shows the customer
// when it asks them to confirm with their password, so it should say in plain words what gets less protected.
type Change struct {
	Code    string
	Summary string
}

// Validation is the validator's verdict on a proposed document.
type Validation struct {
	// Problems make the document unacceptable. The text must not repeat the customer's own content verbatim beyond
	// what is needed to name the field.
	Problems []Problem
	// Weakening lists the changes, against the current document, that reduce protection. A write that has any needs a
	// step-up.
	Weakening []Change
	// Diff describes every change in plain language, weakening ones included.
	Diff []string
}

// PolicyValidator checks a proposed document for a tenant and compares it with the current one (nil when there is
// none). It is the one place that knows what the document means, so it is also the one place that knows what
// weakens it. Implementations must be pure with respect to the tenant's data: no side effects.
type PolicyValidator interface {
	Validate(ctx context.Context, tenant string, current, proposed []byte) (Validation, error)
}

// PublishMeta accompanies a publish.
type PublishMeta struct {
	Actor          string
	Credential     string
	RequestID      string
	IdempotencyKey string
}

// PublishResult is what a publish returns: the sequence number of the signed configuration made for the edges.
type PublishResult struct {
	Sequence uint64
}

// Publisher turns an accepted revision into a signed configuration for the edges (docs/segmentation.md rule T5).
//
// Publish must assign a sequence only if revision is still the tenant's current revision, checked in the same transaction
// that assigns it, and otherwise return an error that wraps ErrConflict. The server checks first, but a write can land
// between that check and the publish; without the publisher's check an older publish that finishes last gets the higher
// sequence, and the edges go back to the weaker policy.
type Publisher interface {
	Publish(ctx context.Context, tenant string, revision uint64, meta PublishMeta) (PublishResult, error)
}

// EdgeAck is the newest sequence one edge has confirmed running.
type EdgeAck struct {
	Edge     string
	Sequence uint64
	At       time.Time
}

// PublishInfo describes the last publish.
type PublishInfo struct {
	Sequence uint64
	Revision uint64
	At       time.Time
	Actor    string
}

// TenantStatus is what GET status returns.
type TenantStatus struct {
	Health      string // "ok", "degraded" or "down"
	Notes       []string
	LastPublish *PublishInfo
	Edges       []EdgeAck
}

// StatusSource reports a tenant's health.
type StatusSource interface {
	Status(ctx context.Context, tenant string) (TenantStatus, error)
}

// PageQuery asks for one page. The cursor is whatever the source returned as the next cursor; this package only checks
// that it is 1 to 512 characters of base64url.
type PageQuery struct {
	Cursor string
	Limit  int
}

// EventsPage is one page of a tenant's events, newest first, with the cursor for the page after it.
type EventsPage struct {
	Events []feed.Event
	Next   string
	More   bool
}

// TrafficPage is one page of a tenant's daily traffic figures, newest first.
type TrafficPage struct {
	Days []feed.TrafficDay
	Next string
	More bool
}

// EventSource supplies a tenant's events and traffic. It is the same store the feed reads, seen a page at a time.
type EventSource interface {
	Events(ctx context.Context, tenant string, q PageQuery) (EventsPage, error)
	Traffic(ctx context.Context, tenant string, q PageQuery) (TrafficPage, error)
}

// Host states.
const (
	HostPending  = "pending"
	HostVerified = "verified"
)

// Host is a hostname a tenant has asked to have routed to its site. It is not routable until it is verified.
type Host struct {
	Hostname   string
	State      string
	Token      string // the value the customer puts in the DNS TXT record
	CreatedAt  time.Time
	VerifiedAt *time.Time
	CheckedAt  *time.Time
}

// HostRegistry keeps the tenant's hostnames. The edge routes a hostname only when its record says verified, and only
// to the tenant that holds it (docs/segmentation.md rule T4 and T9).
type HostRegistry interface {
	// Add records a pending claim with the given token. Adding a hostname the tenant already claimed returns the
	// existing record (the token is not replaced). It returns ErrHostTaken when another tenant has verified it.
	Add(ctx context.Context, tenant, hostname, token string) (Host, error)
	List(ctx context.Context, tenant string) ([]Host, error)
	Get(ctx context.Context, tenant, hostname string) (Host, error)
	// MarkVerified makes the claim verified. If another tenant verified it first it returns ErrHostTaken.
	MarkVerified(ctx context.Context, tenant, hostname string, at time.Time) error
	// MarkChecked records that a check was made and failed.
	MarkChecked(ctx context.Context, tenant, hostname string, at time.Time) error
}

// HostVerifier checks that the customer controls a hostname, normally by looking up a DNS TXT record. name is the
// record's name and value the text it must contain. It must use a resolver the owner trusts and bound its own time.
type HostVerifier interface {
	Verify(ctx context.Context, hostname, name, value string) (bool, error)
}

// Auditor is where audit lines go. FileAudit is the implementation to use.
type Auditor interface {
	Append(e AuditEntry) error
}
