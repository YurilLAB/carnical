// Package crs embeds the OWASP Core Rule Set so a Coraza WAF can run it without any files on disk, and turns a
// few typed settings (mode, paranoia level, thresholds) into the directives that configure it. A separate local/ directory
// holds Carnical's supplemental signatures; those are not part of the upstream release or its provenance manifest.
//
// The rules in owasp_crs/ are copied, never edited, by tools/update-crs from an official release after its GPG
// signature has been checked against the CRS project's pinned key. provenance.json records the release, the
// archive hash, the signer and the hash of every embedded file, and a test fails if any file differs from it.
package crs

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

//go:embed owasp_crs base local provenance.json
var files embed.FS

// DenyTag marks a rule that refuses a request on its own, with deny, rather than adding to the anomaly score. The proxy
// reports a match as disruptive only for the rule that refuses: such a rule, Coraza's base rules and the CRS rules written
// with deny (the anomaly verdicts 949110, 949111, 959100 and 959101 and the configuration checks 901001 and 901500). The
// site policy adds it to every deny rule it writes.
const DenyTag = "carnical-deny"

// FS returns the embedded files. Its root holds base/coraza.conf (Coraza's recommended configuration), owasp_crs/
// (the rule and data files, and the setup example) and provenance.json. Pass it to WithRootFS.
func FS() fs.FS { return portableFS{files} }

// portableFS accepts "\\" as well as "/" in a name. Coraza builds Include paths with the operating system's
// separator, which on Windows is a backslash that an embedded file system refuses; Linux never sends one.
type portableFS struct{ fs.FS }

func (p portableFS) Open(name string) (fs.File, error) {
	return p.FS.Open(strings.ReplaceAll(name, "\\", "/"))
}

// Provenance says where the embedded rules came from.
type Provenance struct {
	Version              string            `json:"version"`
	Source               string            `json:"source"`
	ArchiveSHA256        string            `json:"archive_sha256"`
	SignatureSHA256      string            `json:"signature_sha256"`
	SignerFingerprint    string            `json:"signer_fingerprint"`
	SignatureVerifiedUTC string            `json:"signature_verified_utc"`
	Files                map[string]string `json:"files"`
}

// Info returns the provenance of the embedded rules.
func Info() (Provenance, error) {
	raw, err := files.ReadFile("provenance.json")
	if err != nil {
		return Provenance{}, err
	}
	var p Provenance
	if err := json.Unmarshal(raw, &p); err != nil {
		return Provenance{}, fmt.Errorf("provenance.json: %w", err)
	}
	return p, nil
}

// Version is the CRS release that is embedded, such as "4.30.0".
func Version() string {
	p, err := Info()
	if err != nil {
		return "unknown"
	}
	return p.Version
}

// Mode says what the engine does with a request that reaches the blocking threshold.
type Mode string

const (
	// ModeBlock refuses such a request with a 403.
	ModeBlock Mode = "block"
	// ModeDetect only logs it. Use it first on a site, and read the log before blocking.
	ModeDetect Mode = "detect"
	// ModeOff runs no rules.
	ModeOff Mode = "off"
)

// Settings are the choices the CRS documentation asks every installation to make.
type Settings struct {
	Mode Mode
	// ParanoiaLevel 1 to 4: rules at this level and below can block. Level 1 is the CRS default and is meant to
	// give very few false positives; each level up catches more and needs more tuning for the site.
	ParanoiaLevel int
	// DetectionParanoiaLevel runs the rules of a higher level for logging only. 0 means the same as ParanoiaLevel.
	DetectionParanoiaLevel int
	// InboundThreshold is the anomaly score at which a request is blocked (CRS default 5: one critical rule).
	InboundThreshold int
	// OutboundThreshold is the same for a response; it only matters with InspectResponses.
	OutboundThreshold int
	// RequestBodyLimit is the most bytes of request body that are inspected, and a larger body is refused.
	// Default 1 MiB. Bodies are held in memory, so memory use is up to this limit
	// times the number of requests in flight.
	RequestBodyLimit int64
	// UploadDir is where the engine writes the file parts of a multipart upload while it reads them. They are
	// removed when the request ends. Empty means the system's temporary directory, which other programs share: give
	// it a directory of its own (mode 0700, owned by the service user) so that an upload is never readable by, or
	// confusable with, anything else.
	UploadDir string
	// InspectResponses also runs the CRS response rules (information leaks, web shells). It buffers responses
	// up to 512 KiB of text, HTML and XML, and costs latency, so it is off by default.
	InspectResponses bool
	// AllowedMethods replaces the CRS list (GET HEAD POST OPTIONS). REST APIs need PUT, PATCH and DELETE here.
	AllowedMethods []string
	// AllowedContentTypes are request content types accepted on top of the CRS list (rule 920420), such as git's
	// application/x-git-upload-pack-request. Each is a lower-case type/subtype without parameters. A body of a type
	// with no body processor is not read into arguments, so the rules see little of it: allow only what the site needs.
	AllowedContentTypes []string
	// AllowedExtensions are file extensions taken off the CRS list of restricted ones (rule 920440), such as .sh for a
	// site that shows shell scripts as pages. Each must be on that list.
	AllowedExtensions []string
	// WordPress lets WordPress's block editor save. Every save is a request to its REST API (/wp/v2/) whose content is
	// block markup, written as HTML comments (<!-- wp:paragraph -->), which rule 941180 refuses; that rule is kept off that
	// one argument (json.content) there, and every other rule still reads it. At paranoia level 2 and above, block markup
	// matches more rules, which the site's own exclusions must cover. The editor sends PUT,
	// PATCH and DELETE as a POST with X-HTTP-Method-Override, which rule 920450 then no longer refuses for those three
	// methods; the proxy, which sets this for a WordPress site, refuses the header itself anywhere but the REST API.
	WordPress bool
	// Before and After are extra SecLang directives run before and after the CRS rules, which is where the CRS
	// documentation puts rule exclusions. They are trusted configuration written by the operator, so never fill
	// them from a tenant's input. A rule here that refuses a request on its own (deny) is reported as the one that
	// refused it only if it carries the tag DenyTag.
	Before, After string
	// DisableLocalRules omits Carnical's supplemental injection rules. They are separate from the verified, unmodified CRS
	// release, run at PL1 and add five inbound anomaly points per finding. Mode and thresholds apply to both rule sets.
	DisableLocalRules bool
	// LocalRulesOff switches single local rules off by id, for a site whose ordinary traffic one of them refuses (an
	// admin reaching its own diagnostic page, say). At most 32 ids, each a local rule's.
	LocalRulesOff []int
	// LocalRulesOn switches on single stricter local rules (5006101 to 5006103). Ordinary requests on some sites look the
	// same as what they refuse, so one not named here only detects: it reports what it finds, which the proxy alerts on,
	// and adds nothing to the anomaly score. LocalRulesOff takes one out altogether.
	LocalRulesOn []int
	// SiteHosts are the names of this site (the proxy fills them from its AllowedHosts). The local rules that refuse an
	// address on another host let through one on these names and their subdomains. The request's own Host header says
	// nothing by itself, because the client writes it: with no names here, no address counts as this site's. At most
	// 4,096 names.
	SiteHosts []string
}

// DefaultSettings blocks at paranoia level 1 with the standard thresholds.
func DefaultSettings() Settings {
	return Settings{Mode: ModeBlock, ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, RequestBodyLimit: 1 << 20}
}

// OnlyDetects reports whether id is a stricter local rule that runs without being switched on: it reports what it finds
// and refuses nothing.
func (s Settings) OnlyDetects(id int) bool {
	return !s.DisableLocalRules && isStricterLocalRule(id) && !slices.Contains(s.LocalRulesOn, id) &&
		!slices.Contains(s.LocalRulesOff, id)
}

// ResponseBodyLimit is the response body limit base/coraza.conf gives the rules (SecResponseBodyLimit): with
// InspectResponses, the response body rules run when a response reaches it.
const ResponseBodyLimit = 512 << 10

// ResponseLimit is ResponseBodyLimit, or 0 when Before or After may change it.
func (s Settings) ResponseLimit() int64 {
	if strings.Contains(strings.ToLower(s.Before+s.After), "responsebodylimit") {
		return 0
	}
	return ResponseBodyLimit
}

var methodShape = regexp.MustCompile(`^[A-Z][A-Z-]{0,19}$`)

// pathShape keeps what is written into a SecLang directive from being able to end it or start another: no space,
// quote, newline, semicolon or backtick.
var pathShape = regexp.MustCompile(`^[A-Za-z0-9_./:\\-]+$`)

// Validate reports the first setting that is not usable.
func (s Settings) Validate() error {
	switch s.Mode {
	case ModeBlock, ModeDetect, ModeOff:
	default:
		return fmt.Errorf("mode %q is not block, detect or off", s.Mode)
	}
	if s.ParanoiaLevel < 1 || s.ParanoiaLevel > 4 {
		return fmt.Errorf("paranoia level %d is not 1 to 4", s.ParanoiaLevel)
	}
	if s.DetectionParanoiaLevel != 0 && (s.DetectionParanoiaLevel < s.ParanoiaLevel || s.DetectionParanoiaLevel > 4) {
		return fmt.Errorf("detection paranoia level %d must be 0 or from %d to 4", s.DetectionParanoiaLevel, s.ParanoiaLevel)
	}
	if s.InboundThreshold < 1 || s.InboundThreshold > 1000 || s.OutboundThreshold < 1 || s.OutboundThreshold > 1000 {
		return fmt.Errorf("thresholds must be 1 to 1000")
	}
	if s.RequestBodyLimit < 1024 || s.RequestBodyLimit > 1<<30 {
		return fmt.Errorf("request body limit must be 1 KiB to 1 GiB")
	}
	if s.UploadDir != "" && (!filepath.IsAbs(s.UploadDir) || !pathShape.MatchString(s.UploadDir)) {
		return fmt.Errorf("the upload directory must be an absolute path made of letters, digits and . _ - / : and backslash only")
	}
	// SecLang joins a line ending in a backslash to the next one, which would swallow the following directive.
	if strings.HasSuffix(s.UploadDir, `\`) {
		return fmt.Errorf("the upload directory must not end with a backslash")
	}
	for _, m := range s.AllowedMethods {
		if !methodShape.MatchString(m) {
			return fmt.Errorf("method %q is not an upper-case HTTP method", m)
		}
	}
	if len(s.AllowedMethods) > 20 {
		return fmt.Errorf("more than 20 allowed methods")
	}
	if err := s.validateLists(); err != nil {
		return err
	}
	if len(s.LocalRulesOff) > 32 {
		return fmt.Errorf("more than 32 local rules switched off")
	}
	for _, id := range s.LocalRulesOff {
		if LocalRuleMessage(id) == "" {
			return fmt.Errorf("%d is not a local rule id", id)
		}
	}
	if len(s.LocalRulesOn) > len(stricterLocalRules) {
		return fmt.Errorf("more stricter local rules switched on than there are")
	}
	for _, id := range s.LocalRulesOn {
		if !isStricterLocalRule(id) {
			return fmt.Errorf("%d is not a stricter local rule id", id)
		}
		if slices.Contains(s.LocalRulesOff, id) {
			return fmt.Errorf("local rule %d is switched both on and off", id)
		}
	}
	if len(s.SiteHosts) > maxSiteHosts {
		return fmt.Errorf("more than %d site names", maxSiteHosts)
	}
	for _, h := range s.SiteHosts {
		if !IsSiteHost(h) {
			return fmt.Errorf("a site name must be a host name or an address in lower case, without a port")
		}
	}
	return nil
}

// IsSiteHost reports whether h can be one of Settings.SiteHosts.
func IsSiteHost(h string) bool { return len(h) <= 253 && siteHostShape.MatchString(h) }

// siteHostShape is a host name or address as the proxy normalizes it. Nothing in it can end a quoted SecLang string.
var siteHostShape = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*|\[[0-9a-f:.]+\])$`)

// The rule parser reads a line at a time into a buffer of 64 KiB, and at a line that does not fit it stops without an
// error: every rule after that line would be missing, and the engine would start as if nothing were wrong. So no line
// of maxDirectiveLine bytes or more is handed to it (Directives refuses one), and the site's names, which can be many
// and long, go into as many rules as it takes to keep each under siteRuleBytes.
const (
	maxDirectiveLine = 60 << 10
	siteRuleBytes    = 8 << 10
	maxSiteHosts     = 4096
	siteRuleID       = 5006200 // the first of the rules that hold the site's names
	// siteForwardedRuleID is the first of the rules that count the forwarded hosts that are the site's names.
	siteForwardedRuleID = 5006600
)

// siteDirectives sets tx.carnical_site, which the local rules compare the host of a URL with. It starts as a value no
// host can end with, and becomes the request's Host (lower case, without a port, a trailing dot or a leading "www.")
// only when that is one of the operator's names.
func (s Settings) siteDirectives() []string {
	out := []string{
		// tx.carnical_host is the host the request was made to, as the client wrote it, for rule 5006103.
		`SecRule REQUEST_HEADERS:Host "@rx \A(.*?)\.?(?::[0-9]{1,5})?\z" "id:5006097,phase:1,pass,t:none,t:lowercase,nolog,capture,setvar:'tx.carnical_host=%{tx.1}'"`,
		`SecAction "id:5006098,phase:1,pass,t:none,nolog,setvar:'tx.carnical_site=!',setvar:tx.carnical_fwd_named=0"`,
	}
	var names []string
	for _, h := range s.SiteHosts {
		if n := regexp.QuoteMeta(strings.TrimPrefix(h, "www.")); !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return out
	}
	slices.Sort(names)
	for id := siteRuleID; len(names) > 0; id++ {
		n, size := 1, len(names[0])
		for n < len(names) && size+1+len(names[n]) <= siteRuleBytes {
			size += 1 + len(names[n])
			n++
		}
		alternatives := strings.Join(names[:n], "|")
		out = append(out, fmt.Sprintf(`SecRule REQUEST_HEADERS:Host "@rx \A(?:www\.)?(%s)\.?(?::[0-9]{1,5})?\z" `+
			`"id:%d,phase:1,pass,t:none,t:lowercase,nolog,capture,setvar:'tx.carnical_site=%%{tx.1}'"`, alternatives, id),
			// For rule 5006103: each forwarded host that is one of these names, as it reads them.
			fmt.Sprintf(`SecRule REQUEST_HEADERS:X-Forwarded-Host|REQUEST_HEADERS:X-Host|REQUEST_HEADERS:X-Original-Host `+
				`"@rx \A[\t ]*(?:www\.)?(?:%s)\.?(?::[0-9]{1,5})?[\t ]*\z" `+
				`"id:%d,phase:1,pass,t:none,t:lowercase,nolog,setvar:tx.carnical_fwd_named=+1"`, alternatives, id-siteRuleID+siteForwardedRuleID))
		names = names[n:]
	}
	return out
}

// Directives returns the SecLang that configures the engine and loads the whole CRS from FS(). Give it to
// coraza.NewWAFConfig().WithRootFS(crs.FS()).WithDirectives(...).
func (s Settings) Directives() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	engine := map[Mode]string{ModeBlock: "On", ModeDetect: "DetectionOnly", ModeOff: "Off"}[s.Mode]
	response := "Off"
	if s.InspectResponses {
		response = "On"
	}
	detection := s.DetectionParanoiaLevel
	if detection == 0 {
		detection = s.ParanoiaLevel
	}
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	line("Include base/coraza.conf")
	line("SecRuleEngine %s", engine)
	line("SecRequestBodyAccess On")
	line("SecRequestBodyLimit %d", s.RequestBodyLimit)
	line("SecRequestBodyInMemoryLimit %d", s.RequestBodyLimit) // a body that is not a file upload stays in memory
	if s.UploadDir != "" {
		line("SecUploadDir %s", s.UploadDir)
	}
	line("SecUploadKeepFiles Off")
	line("SecRequestBodyLimitAction Reject")
	line("SecResponseBodyAccess %s", response)
	line("SecAuditEngine Off") // matches are reported through the error callback, not an audit file
	line("Include owasp_crs/crs-setup.conf.example")
	line(`SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`, s.ParanoiaLevel)
	line(`SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=%d"`, detection)
	line(`SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"`,
		s.InboundThreshold, s.OutboundThreshold)
	if len(s.AllowedMethods) > 0 {
		line(`SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=%s'"`, strings.Join(s.AllowedMethods, " "))
	}
	for _, d := range s.listDirectives() {
		line("%s", d)
	}
	if s.Before != "" {
		line("%s", s.Before)
	}
	// Multiphase builds can inspect query/cookie values during phase 1. Load
	// local signatures after CRS initializes the per-PL scores, or that reset
	// would erase their findings. Keep every upstream file in sorted order.
	rules, err := fs.Glob(files, "owasp_crs/*.conf")
	if err != nil {
		return "", fmt.Errorf("list embedded CRS rules: %w", err)
	}
	initialized := false
	for _, path := range rules {
		line("Include %s", path)
		if path == "owasp_crs/REQUEST-901-INITIALIZATION.conf" {
			initialized = true
			if !s.DisableLocalRules {
				for _, d := range s.siteDirectives() {
					line("%s", d)
				}
				// What each stricter rule adds to the score: nothing until it is switched on.
				points := make([]string, 0, len(stricterLocalRules))
				for _, id := range stricterLocalRules {
					n := 0
					if slices.Contains(s.LocalRulesOn, id) {
						n = 5
					}
					points = append(points, fmt.Sprintf("setvar:tx.carnical_points_%d=%d", id, n))
				}
				line(`SecAction "id:5006099,phase:1,pass,t:none,nolog,%s"`, strings.Join(points, ","))
				line("Include local/*.conf")
				var ids []string
				for _, id := range s.LocalRulesOff {
					ids = append(ids, strconv.Itoa(id))
				}
				if len(ids) > 0 {
					line("SecRuleRemoveById %s", strings.Join(ids, " "))
				}
			}
		}
	}
	if !initialized {
		return "", fmt.Errorf("embedded CRS initialization rules are missing")
	}
	if s.After != "" {
		line("%s", s.After)
	}
	out := b.String()
	for l := range strings.Lines(out) {
		if len(l) >= maxDirectiveLine {
			return "", fmt.Errorf("a rule line of %d bytes is longer than the rule parser reads (%d): %.60q", len(l), maxDirectiveLine, l)
		}
	}
	return out, nil
}
