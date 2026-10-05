// SPDX-License-Identifier: Apache-2.0

// Package policy is the settings a customer controls through the web UI, validated strictly and compiled to what an edge
// runs.
//
// A Policy is a JSON document. It is plain data: no field holds code, no string is ever pasted into a rule, and every
// list, string, number and nesting depth has a limit. Decode reads one strictly (an unknown or repeated field is an
// error); Validate checks a Policy built in code; Compile turns a valid Policy into the settings of the proxy and the
// Core Rule Set (package proxy, package crs) and the few lines of SecLang that those settings cannot express: the
// exclusions, the custom rules, the address lists. Diff and Weakens say what a change does, so the web UI can ask the
// customer to confirm, with their password, a change that lowers protection.
//
// The model keeps the language the existing PHP site console uses for its settings (mode, sensitivity, rule groups,
// exclusions, custom rules, allow and block lists), and FromConsoleExport reads that console's export. What the Core Rule
// Set cannot do exactly (a score for a single signature, for example) is not offered, and FromConsoleExport says so
// instead of approximating it.
//
// The exported API is small on purpose, because other packages (the control API server, the edge) depend on it:
//
//	Default() Policy                                  a new site's policy
//	Decode([]byte) (Policy, error)                    strict JSON in, normalised and validated
//	Encode(Policy) ([]byte, error)                    canonical JSON out
//	(Policy) Validate() error, (Policy) Hash() string
//	Compile(Policy) (Compiled, error)                 what the edge runs; (Compiled) ApplyTo(*proxy.Config)
//	Diff(old, new) []Change, Weakens(old, new) []Change, Confirm(old, new) []Change
//	FromConsoleExport([]byte) (Policy, []string, error)
//	RegisterSection(name, validator) error            lets another package validate its own section
//
// Everything is safe for concurrent use. Nothing panics on any input.
package policy

import "encoding/json"

// SchemaVersion is the only schema this package reads and writes.
const SchemaVersion = 1

// Mode says what the edge does with a request the rules would stop.
type Mode string

// The modes. They are ordered from least to most protective: off, monitor, block.
const (
	// ModeBlock refuses such a request.
	ModeBlock Mode = "block"
	// ModeMonitor only records it. A new site's first days belong here: read what is flagged, add exclusions, then block.
	ModeMonitor Mode = "monitor"
	// ModeOff runs no rules. The proxy's own checks (the path, the host, the upload and WordPress checks) still run.
	ModeOff Mode = "off"
)

// Sensitivity is a preset over the Core Rule Set's paranoia level and blocking threshold (see Presets).
type Sensitivity string

// The sensitivities, from least to most protective.
const (
	SensitivityRelaxed Sensitivity = "relaxed"
	SensitivityNormal  Sensitivity = "normal"
	SensitivityStrict  Sensitivity = "strict"
)

// GroupState is what a rule group does.
type GroupState string

// The states, from least to most protective.
const (
	// GroupOff: the group's rules are not tried.
	GroupOff GroupState = "off"
	// GroupLog: the rules run and their matches are recorded, but they add nothing to the score that decides a block.
	GroupLog GroupState = "log"
	// GroupOn: the rules count.
	GroupOn GroupState = "on"
)

// APIMode is how far API protection goes. It is owned by another package; here it is only validated and compared.
type APIMode string

// The API modes, from least to most protective.
const (
	APIOff     APIMode = "off"
	APILearn   APIMode = "learn"
	APIMonitor APIMode = "monitor"
	APIEnforce APIMode = "enforce"
)

// Action is what a custom rule does when it matches.
type Action string

// The actions.
const (
	// ActionBlock refuses the request (in block mode; in monitor mode it is recorded).
	ActionBlock Action = "block"
	// ActionLog records the match and does nothing else.
	ActionLog Action = "log"
)

// Operator is how a custom rule compares a field with its value.
type Operator string

// The operators. All of them compare text; none reads a file, runs a program or reaches the network.
const (
	OpContains   Operator = "contains"
	OpEquals     Operator = "equals"
	OpBeginsWith Operator = "beginsWith"
	OpEndsWith   Operator = "endsWith"
	OpPM         Operator = "pm"
	OpRX         Operator = "rx"
)

// Policy is the customer-facing configuration of one site.
type Policy struct {
	// Schema is SchemaVersion.
	Schema int `json:"schema"`
	// Revision is the control plane's counter for this site's policies. It is not part of the policy's content: Hash ignores it.
	Revision uint64 `json:"revision"`
	// Mode is block, monitor or off.
	Mode Mode `json:"mode"`
	// Sensitivity is relaxed, normal or strict.
	Sensitivity Sensitivity `json:"sensitivity"`
	// Threshold, if set, replaces the blocking threshold of the sensitivity's preset (1 to 1000). A request is blocked when
	// the rules' scores add up to it.
	Threshold *int `json:"threshold"`
	// Body holds the limits on request bodies.
	Body BodyLimits `json:"body"`
	// AllowedMethods are the HTTP methods the site accepts. At least one.
	AllowedMethods []string `json:"allowed_methods"`
	// AllowedHosts are the only names the site answers to; a request for any other is refused. Empty means any name.
	AllowedHosts []string `json:"allowed_hosts"`
	// RuleGroups sets a group (sqli, xss, lfi, rfi, rce, php, ssrf, java, scanner, protocol) to on, log or off. A group not
	// named is on.
	RuleGroups map[string]GroupState `json:"rule_groups"`
	// Exclusions keep some kinds of rule away from some parts of the requests to one page or folder.
	Exclusions []Exclusion `json:"exclusions"`
	// CustomRules are the site's own rules, in structured form only.
	CustomRules []CustomRule `json:"custom_rules"`
	// AllowIPs are never inspected, banned or blocked. BlockIPs are refused before anything else. Both are addresses or CIDR ranges.
	AllowIPs []string `json:"allow_ips"`
	BlockIPs []string `json:"block_ips"`
	// AllowPaths are pages (a path prefix) that are never inspected, for a payment provider's webhook, say.
	AllowPaths []string `json:"allow_paths"`
	// Paths says how plain a request path must be.
	Paths PathOptions `json:"paths"`
	// Uploads says what is refused in a file upload.
	Uploads UploadOptions `json:"uploads"`
	// WordPress switches on the protections for a WordPress site.
	WordPress WordPressOptions `json:"wordpress"`
	// Responses says what the edge changes in the application's responses and whether it inspects them.
	Responses ResponseOptions `json:"responses"`
	// DenyHeaders are headers whose presence refuses the request.
	DenyHeaders []string `json:"deny_headers"`
	// Framework holds options for particular frameworks.
	Framework FrameworkOptions `json:"framework"`
	// VPatch says which tiers of virtual patch run and which software the site declares it runs.
	VPatch VPatchOptions `json:"vpatch"`
	// APIMode is off, learn, monitor or enforce. The inner settings are API.
	APIMode APIMode `json:"api_mode"`
	// API and BodyFormats belong to other packages. Here they are checked for size, depth and the form of their keys, and by
	// the validator that package registered (RegisterSection); what they mean is not this package's to say.
	API         json.RawMessage `json:"api,omitempty"`
	BodyFormats json.RawMessage `json:"body_formats,omitempty"`
	// Note is the customer's own free text about the policy. It is never compiled into anything.
	Note string `json:"note"`
}

// BodyLimits are the limits on request bodies.
type BodyLimits struct {
	// MaxUploadBytes is the most bytes of request body that are inspected, and the size of the largest file upload. A larger
	// body is refused. It is held in memory while the request is read.
	MaxUploadBytes int64 `json:"max_upload_bytes"`
	// MaxFormBytes is the largest body that is not a file upload (a form, JSON, XML). It cannot be more than MaxUploadBytes.
	// The rules cost time in proportion to a body's size, which is why it is much smaller by default.
	MaxFormBytes int64 `json:"max_form_bytes"`
}

// PathOptions loosen how plain a request path must be. The default of both is false.
type PathOptions struct {
	// AllowEncodedSlash lets %2f and %5c through, for an application that puts them in identifiers.
	AllowEncodedSlash bool `json:"allow_encoded_slash"`
	// AllowPathParams lets a semicolon through (Java's ;jsessionid=, matrix parameters).
	AllowPathParams bool `json:"allow_path_params"`
}

// UploadOptions loosen what is refused in a file upload. The default of both is false.
type UploadOptions struct {
	// AllowScriptNames lets through file names with a script extension anywhere in them, and server configuration files.
	AllowScriptNames bool `json:"allow_script_names"`
	// AllowScriptContent lets through a file whose content holds a PHP, ASP or JSP opening tag.
	AllowScriptContent bool `json:"allow_script_content"`
}

// WordPressOptions are the protections for a WordPress site.
type WordPressOptions struct {
	// Enabled switches them on.
	Enabled bool `json:"enabled"`
	// AllowXMLRPC leaves xmlrpc.php reachable (Jetpack and the mobile app use it).
	AllowXMLRPC bool `json:"allow_xmlrpc"`
	// LoginPerMinute is how many POSTs to wp-login.php one address may make a minute (1 to 600).
	LoginPerMinute int `json:"login_per_minute"`
}

// ResponseOptions are what the edge does to the application's responses.
type ResponseOptions struct {
	// KeepBanners leaves X-Powered-By, X-AspNet-Version and the Server header as the application sent them.
	KeepBanners bool `json:"keep_banners"`
	// KeepCaching leaves Cache-Control alone on responses that set a cookie or look like a static file but are HTML.
	KeepCaching bool `json:"keep_caching"`
	// Inspect also runs the Core Rule Set's response rules (information leaks, web shells). It costs latency.
	Inspect bool `json:"inspect"`
}

// FrameworkOptions are options for particular frameworks.
type FrameworkOptions struct {
	// DenyNextAction refuses any request with a Next-Action header, for a Next.js site that uses no server actions.
	DenyNextAction bool `json:"deny_next_action"`
}

// VPatchOptions are the virtual-patch settings. Package vpatch reads them.
type VPatchOptions struct {
	// Tiers are the tiers of signature that run: verified, community, experimental.
	Tiers []string `json:"tiers"`
	// Software is what the site declares it runs, such as "wordpress" or "woocommerce@9.3": the signatures about that
	// software are switched on for this site.
	Software []string `json:"software"`
}

// Exclusion keeps some kinds of rule away from some parts of the requests to one page or folder.
type Exclusion struct {
	// Path is a path prefix: it starts with / and an exact-case match of the start of the request path counts. End a folder with /.
	Path string `json:"path"`
	// Categories are the rule groups kept away. At least one.
	Categories []string `json:"categories"`
	// Targets are the parts of the request they are kept away from: args, argnames, cookies, cookienames, headers, body,
	// query, path, uri, method, filenames, or one named value (arg:NAME, cookie:NAME, header:NAME). Empty means all of the request.
	Targets []string `json:"targets"`
	// Note is the customer's own text. It is never compiled.
	Note string `json:"note,omitempty"`
}

// CustomRule is a rule of the site's own. It is data: it is compiled to a rule by this package, never read as text.
type CustomRule struct {
	// ID identifies the rule across edits (1 to 9999). It appears, as 1050000 + ID, in the edge's log.
	ID int `json:"id"`
	// Field is the part of the request it looks at: method, path, uri, query, args, argnames, cookies, cookienames, headers, body,
	// filenames, host, useragent, or one named value (arg:NAME, cookie:NAME, header:NAME).
	Field string `json:"field"`
	// Operator is contains, equals, beginsWith, endsWith, pm (any of several words) or rx (an RE2 regular expression).
	Operator Operator `json:"operator"`
	// Value is what the field is compared with (all operators but pm).
	Value string `json:"value,omitempty"`
	// Values are the words for pm.
	Values []string `json:"values,omitempty"`
	// CaseSensitive makes the comparison exact; by default case is ignored.
	CaseSensitive bool `json:"case_sensitive"`
	// Action is block or log.
	Action Action `json:"action"`
	// Note is the customer's own text about the rule. It is never compiled.
	Note string `json:"note"`
}
