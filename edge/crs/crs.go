// Package crs embeds the OWASP Core Rule Set so a Coraza WAF can run it without any files on disk, and turns a
// few typed settings (mode, paranoia level, thresholds) into the directives that configure it.
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
	"regexp"
	"strings"
)

//go:embed owasp_crs base provenance.json
var files embed.FS

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
	// Default 1 MiB. Bodies are held in memory (nothing is spilled to disk), so memory use is up to this limit
	// times the number of requests in flight.
	RequestBodyLimit int64
	// InspectResponses also runs the CRS response rules (information leaks, web shells). It buffers responses
	// up to 512 KiB of text, HTML and XML, and costs latency, so it is off by default.
	InspectResponses bool
	// AllowedMethods replaces the CRS list (GET HEAD POST OPTIONS). REST APIs need PUT, PATCH and DELETE here.
	AllowedMethods []string
	// Before and After are extra SecLang directives run before and after the CRS rules, which is where the CRS
	// documentation puts rule exclusions. They are trusted configuration written by the operator, so never fill
	// them from a tenant's input.
	Before, After string
}

// DefaultSettings blocks at paranoia level 1 with the standard thresholds.
func DefaultSettings() Settings {
	return Settings{Mode: ModeBlock, ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, RequestBodyLimit: 1 << 20}
}

var methodShape = regexp.MustCompile(`^[A-Z][A-Z-]{0,19}$`)

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
	for _, m := range s.AllowedMethods {
		if !methodShape.MatchString(m) {
			return fmt.Errorf("method %q is not an upper-case HTTP method", m)
		}
	}
	if len(s.AllowedMethods) > 20 {
		return fmt.Errorf("more than 20 allowed methods")
	}
	return nil
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
	line("SecRequestBodyInMemoryLimit %d", s.RequestBodyLimit) // never spill a body to disk
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
	if s.Before != "" {
		line("%s", s.Before)
	}
	line("Include owasp_crs/*.conf")
	if s.After != "" {
		line("%s", s.After)
	}
	return b.String(), nil
}
