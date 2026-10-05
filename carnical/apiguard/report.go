// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"strings"
	"time"
	"unicode/utf8"
)

// Report says what an import, a discovery or a bootstrap did, for the owner to read. It never holds request content: it holds
// what the description said about itself, with control characters removed and every line cut short.
type Report struct {
	// Kind is openapi, wordpress, har, postman or discovery.
	Kind string `json:"kind"`
	// Source is where the material came from: a path on the site that discovery fetched, or "supplied".
	Source string    `json:"source,omitempty"`
	When   time.Time `json:"when"`
	// Format is the description's own version, such as "openapi 3.0.3".
	Format string `json:"format,omitempty"`
	Title  string `json:"title,omitempty"`
	Hash   string `json:"hash,omitempty"`
	// Routes is how many routes a description gave. Observations is how many requests a recording gave.
	Routes       int `json:"routes,omitempty"`
	Observations int `json:"observations,omitempty"`
	// Skipped is how many entries of a recording could not be used.
	Skipped int `json:"skipped,omitempty"`
	// GraphQL is true if discovery saw a GraphQL endpoint. Its schema is not read (no introspection query is ever sent).
	GraphQL  bool     `json:"graphql,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	// WarningsDropped counts warnings left out because there were too many to list.
	WarningsDropped int `json:"warningsDropped,omitempty"`
	// Attempts lists each address discovery tried and what came of it.
	Attempts []Attempt `json:"attempts,omitempty"`
	// Outcome says what discovery did with what it found.
	Outcome string `json:"outcome,omitempty"`
}

// Attempt is one address discovery asked for.
type Attempt struct {
	Path   string `json:"path"`
	Status int    `json:"status,omitempty"`
	Result string `json:"result"`
}

const (
	maxWarnings   = 100
	maxWarningLen = 240
)

// warn adds a line to the report, cleaned. It is how the importers talk about the document they read, which the owner may not
// have written, so what it says is never trusted to be free of control characters.
func (r *Report) warn(msg string) {
	if len(r.Warnings) >= maxWarnings {
		r.WarningsDropped++
		return
	}
	r.Warnings = append(r.Warnings, clean(msg, maxWarningLen))
}

// clean makes text from an untrusted document safe to show: printable characters only, cut to n bytes on a character boundary.
func clean(s string, n int) string {
	if len(s) > n {
		cut := n
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
}
