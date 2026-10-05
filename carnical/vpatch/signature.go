// Package vpatch is Carnical's virtual-patch engine: signatures that recognise the request shape of a known exploit (a
// vulnerable plugin's endpoint, a framework's internal header, a path-traversal into a particular product) and refuse it before
// the application is reached, whatever the application version.
//
// It is separate from the Core Rule Set on purpose. The CRS looks for classes of attack with a few hundred broad rules, at a cost
// in CPU for every rule on every request. Virtual patches are thousands of narrow rules, each about one advisory; they need an
// index (most of them name a path), a way to be switched on only for the sites that run the software they are about, and a way
// to be loaded from the formats that advisories and rule feeds are published in.
//
// This file is the model every format is converted to, and the one the engine runs. It is deliberately the same shape as the
// signature library that the owner side builds from ET Open, nuclei, CrowdSec and the CRS (about 8,000 signatures, 1,541 of
// them verified), so that library loads without conversion.
package vpatch

// Tier says how far a signature is trusted. A site chooses which tiers run.
const (
	// TierVerified signatures have been shown to catch their own attack samples and to leave ordinary traffic alone, and are
	// vouched for by more than one source or by evidence of exploitation. They are on by default.
	TierVerified = "verified"
	// TierCommunity signatures come from one community source and have not been checked against ordinary traffic. Off by default.
	TierCommunity = "community"
	// TierExperimental signatures are broad or new. Off by default and never block unless a site asks for it.
	TierExperimental = "experimental"
)

// Operators a Condition can use.
const (
	OpRegex    = "rx"       // a regular expression (RE2 syntax); Flags "i" makes it case-insensitive
	OpContains = "contains" // the target contains Pattern
	OpPM       = "pm"       // the target contains any of Patterns (or the space-separated words of Pattern)
	OpEquals   = "equals"
	OpPrefix   = "prefix"
	OpSuffix   = "suffix"
)

// Targets a Condition can look at. A target may be written "header:NAME", "arg:NAME", "cookie:NAME" for one named value.
const (
	TargetURI         = "uri"         // the path and query as received
	TargetPath        = "path"        // the path only
	TargetQuery       = "query"       // the query string only
	TargetArgs        = "args"        // every value of every argument (query and form), each one separately
	TargetArgNames    = "argnames"    // every argument name
	TargetCookies     = "cookies"     // every cookie value
	TargetCookieNames = "cookienames" // every cookie name
	TargetBody        = "body"        // the request body
	TargetMethod      = "method"
	TargetHeaders     = "headers" // every header value
	TargetFilenames   = "filenames"
	TargetUploads     = "uploads" // the content of uploaded files
)

// Transforms are applied to a target's value, in order, before the operator looks at it.
//
//	urldecode1   one round of percent-decoding
//	urldecode    percent-decoding until the value stops changing (at most 3 rounds)
//	lowercase    ASCII lower case
//	normpath     collapse "/./" and "/../" and repeated slashes (Unix)
//	normpathwin  the same, treating "\" as "/" (Windows)
//	htmldecode   HTML character references
//	jsdecode     JavaScript escapes (\xNN, \uNNNN)
//	cssdecode    CSS escapes
//	utf8unicode  UTF-8 to code points (so that "%c0%af"-style overlong forms are seen)
//	nulls        remove NUL bytes
//	compressspace  runs of white space to one space
//	removespace    remove white space
//	trim           trim white space at both ends
//	base64decode   decode, if the value is valid base64
//	comments / replacecomments  remove or replace SQL and C comments
//	cmdline      the transformation the CRS calls cmdLine (remove quotes, backslashes, carets and commas used to hide a command)

// Condition is one test of a request.
type Condition struct {
	Operator string `json:"operator" yaml:"operator"`
	// Pattern is the regular expression, the string, or (for OpPM) the words.
	Pattern string `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	// Patterns is the word list for OpPM when it is given as a list.
	Patterns []string `json:"patterns,omitempty" yaml:"patterns,omitempty"`
	// Flags is "i" for a case-insensitive regular expression.
	Flags string `json:"flags,omitempty" yaml:"flags,omitempty"`
	// Targets are the parts of the request the operator looks at. The condition holds if it holds for any value of any target.
	Targets    []string `json:"targets" yaml:"targets"`
	Transforms []string `json:"transforms,omitempty" yaml:"transforms,omitempty"`
	// Negate inverts the result: the condition holds if the operator does NOT match any value.
	Negate bool `json:"negate,omitempty" yaml:"negate,omitempty"`
}

// Signature is one virtual patch. It matches when its main condition and every one of Also hold.
type Signature struct {
	// ID is unique across everything loaded, such as "CS-CVE-2024-4577-1", "NU-CVE-2023-xxxx", "ET-2012345", "FW-XXE-0001".
	ID  string `json:"id" yaml:"id"`
	Rev int    `json:"rev,omitempty" yaml:"rev,omitempty"`
	// Description says in a sentence what the signature recognises. It never holds an example of the attack.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Category is sqli, xss, rce, lfi, rfi, ssrf, xxe, ssti, php, java, upload, wordpress, probe, cve, scanner, protocol or other.
	Category string `json:"category" yaml:"category"`
	// Severity is critical, high, medium or low.
	Severity string `json:"severity" yaml:"severity"`
	// Confidence is high, medium or low: how sure the author is that a request that matches is an attack.
	Confidence string `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	// Action is "block" (the default) or "log".
	Action string `json:"action,omitempty" yaml:"action,omitempty"`
	// Score is how much it adds when scoring is used, 0 to 10.
	Score int      `json:"score,omitempty" yaml:"score,omitempty"`
	CVEs  []string `json:"cves,omitempty" yaml:"cves,omitempty"`
	// Sources say where it came from, such as "crowdsec:vpatch-CVE-2024-4577@abc123", "et-open", "nuclei", "first-party".
	Sources []string `json:"sources,omitempty" yaml:"sources,omitempty"`
	// Scope names the software it is about: "wordpress", "wordpress:plugin:contact-form-7", "php", "java", "nextjs", "spring".
	// Empty means every site. A site runs the signatures whose scope it has declared or the proxy has detected, and the empty ones.
	Scope []string `json:"scope,omitempty" yaml:"scope,omitempty"`
	// Tier is one of the Tier constants; empty means verified.
	Tier string `json:"tier,omitempty" yaml:"tier,omitempty"`
	// Expires is a date (2006-01-02) after which the signature is no longer loaded; for a patch that is useless once everyone has updated.
	Expires string `json:"expires,omitempty" yaml:"expires,omitempty"`

	// The main condition, written inline as the signature library writes it.
	Condition `yaml:",inline"`
	// Also are further conditions that must all hold.
	Also []Condition `json:"also,omitempty" yaml:"also,omitempty"`
}

// Hit is a signature that matched a request.
type Hit struct {
	ID       string
	Category string
	Severity string
	CVEs     []string
	Action   string
	Tier     string
}
