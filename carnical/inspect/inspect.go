// Package inspect is the contract between the proxy and the things that look at a request before the rule set does: the
// virtual-patch signatures, the body-format checks, the API guard. It holds only types, so that each of them can be built and
// tested on its own and the proxy can run any set of them, in order, without importing them.
package inspect

import (
	"net/http"
	"net/netip"
)

// Request is a request as an inspector sees it. Everything in it was received from the visitor and is untrusted. An inspector
// must not modify it: a change is made by returning a Result.
type Request struct {
	Method string
	// Host is the Host header, as sent.
	Host string
	// Path is the request path exactly as received (no query, still percent-encoded). The proxy has already refused paths that need
	// interpreting, so a path here is in plain form.
	Path string
	// RawQuery is the query string exactly as received, without the "?".
	RawQuery string
	Header   http.Header
	// Body is the whole request body, already limited by the proxy (128 KiB unless it is a file upload), and nil if there is none.
	// If an earlier inspector replaced the body (a decompressed or normalised form), this is the replacement.
	Body []byte
	// Client is the visitor's address as the proxy worked it out (not a header the visitor wrote).
	Client netip.Addr
	// TLS is true if the visitor connected over TLS.
	TLS bool
	// Site is the name of the protected site, for an inspector that keeps state per site. Empty in a single-site proxy.
	Site string
}

// ContentType returns the media type of the request body, lower case and without parameters, or "".
func (r *Request) ContentType() string {
	ct := r.Header.Get("Content-Type")
	for i := 0; i < len(ct); i++ {
		if ct[i] == ';' {
			ct = ct[:i]
			break
		}
	}
	out := make([]byte, 0, len(ct))
	for i := 0; i < len(ct); i++ {
		c := ct[i]
		if c == ' ' || c == '\t' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}

// Verdict is one finding.
type Verdict struct {
	// ID is the identifier that appears in the log and the feed. The proxy's own refusals use 5000000 to 5000999; an inspector
	// takes the range it documents.
	ID int
	// Message says what was found in words, without the request's content.
	Message string
	// Block makes the proxy refuse the request. False means the finding is only recorded (monitor mode).
	Block bool
	// Status is the HTTP status for a refusal (default 403).
	Status int
	// Severity is critical, high, medium or low.
	Severity string
}

// Result is what an inspector returns.
type Result struct {
	Verdicts []Verdict
	// Body, if non-nil, replaces the request body for the inspectors after this one, the rule set and the application. It is how
	// a compressed body is handed on in the form that can be inspected. The proxy fixes Content-Length.
	Body []byte
	// DelHeader and SetHeader change the request headers the same way (removing Content-Encoding after a body was decompressed).
	DelHeader []string
	SetHeader map[string]string
}

// Observer is told what the application answered, for every request that was let through. It is how a component learns what a
// site's normal traffic looks like. It is not called for a request that was refused, so what it learns comes only from
// traffic that passed every check. It must not block: it runs in the response path.
type Observer interface {
	Observe(r *Request, status int)
}

// Inspector looks at a request. It must be safe for use by many requests at once, must not keep a reference to the Request after
// it returns, and must bound the time and memory it uses by the size of the Request.
type Inspector interface {
	// Name identifies the inspector in logs.
	Name() string
	Inspect(r *Request) Result
}
