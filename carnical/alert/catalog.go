// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"strconv"
	"strings"
)

// Entry is what the catalog knows about a rule id: a static name, the categories and a default risk. A producer that
// knows better (a CRS verdict over the threshold, an inspector's own severity) sets the risk itself.
type Entry struct {
	Name       string
	Categories Categories
	Risk       Risk
}

// Rule id ranges. Each layer documents its own range; the catalog follows them.
const (
	baseFirst     = 200000  // Coraza's recommended configuration (crs/base/coraza.conf), loaded before the CRS
	baseLast      = 200999  //
	crsFirst      = 900000  // OWASP CRS: the family is the id divided by 1000, the number of its file
	crsLast       = 999999  //
	policyFirst   = 1000000 // site policy rules (policy/limits.go)
	policyLast    = 1099999 //
	proxyFirst    = 5000000 // the proxy's own refusals
	proxyLast     = 5000999 //
	formatsFirst  = 5002000 // formats inspector
	formatsLast   = 5002999 //
	apiFirst      = 5003000 // API guard
	apiLast       = 5003999 //
	shieldFirst   = 5004000 // flood protection
	shieldLast    = 5004999 //
	botsFirst     = 5005000 // bot policy: 5005000 and the client kind's number
	botsLast      = 5005999 //
	localFirst    = 5006000 // carnical's local CRS rules
	localLast     = 5006999 //
	gateFirst     = 5007000 // a person check (package challenge)
	gateLast      = 5007999 //
	vpatchFirst   = 5100000 // virtual patches: the engine's own below 5101000, signatures above
	vpatchSigBase = 5101000 //
	vpatchLast    = 5199999 //
)

// crsFamily is one CRS rule file: its number, name, categories and the risk of a finding below the threshold.
type crsFamily struct {
	name string
	cats Categories
}

// crsFamilies is compiled from the CRS file names (crs/owasp_crs). A finding of one rule below the anomaly threshold is
// low or info by its severity (CRSRisk); the verdict rules 949110 and 959100 are high, as are 949111 and 959101, which
// give the verdict a phase early when tx.early_blocking is set.
var crsFamilies = map[int]crsFamily{
	901: {"CRS initialization", 0},
	905: {"CRS common exceptions", 0},
	911: {"Method enforcement", Of(CatProtocol)},
	913: {"Scanner detection", Of(CatScanner)},
	920: {"Protocol enforcement", Of(CatProtocol)},
	921: {"Protocol attack", Of(CatProtocol)},
	922: {"Multipart attack", Of(CatProtocol)},
	930: {"Local file inclusion", Of(CatLFI)},
	931: {"Remote file inclusion", Of(CatRFI)},
	932: {"Remote command execution", Of(CatRCE)},
	933: {"PHP injection", Of(CatPHP)},
	934: {"Generic application attack", Of(CatGeneric)},
	941: {"Cross-site scripting", Of(CatXSS)},
	942: {"SQL injection", Of(CatSQLi)},
	943: {"Session fixation", Of(CatSession)},
	944: {"Java attack", Of(CatJava)},
	949: {"Inbound anomaly score", 0},
	950: {"Data leakage", Of(CatDataLeak)},
	951: {"SQL error leakage", Of(CatDataLeak)},
	952: {"Java error leakage", Of(CatDataLeak)},
	953: {"PHP information leakage", Of(CatDataLeak)},
	954: {"IIS information leakage", Of(CatDataLeak)},
	955: {"Web shell in a response", Of(CatDataLeak)},
	956: {"Ruby error leakage", Of(CatDataLeak)},
	959: {"Outbound anomaly score", 0},
	980: {"Anomaly score correlation", 0},
	999: {"CRS common exceptions after", 0},
}

// crsNamed overrides a family's name, category or risk for single rules.
var crsNamed = map[int]Entry{
	941100: {"Cross-site scripting (libinjection)", Of(CatXSS), RiskLow},
	942100: {"SQL injection (libinjection)", Of(CatSQLi), RiskLow},
	949110: {"Inbound anomaly score exceeded", 0, RiskHigh},
	949111: {"Inbound anomaly score exceeded in phase 1", 0, RiskHigh},
	959100: {"Outbound anomaly score exceeded", 0, RiskHigh},
	959101: {"Outbound anomaly score exceeded in phase 3", 0, RiskHigh},
}

// baseRules are the rules of Coraza's recommended configuration (crs/base/coraza.conf). The ones that refuse report a
// body, a multipart part, an argument count or a URI the engine could not take apart: a request it could not inspect
// whole, which is also how inspection is evaded.
var baseRules = map[int]Entry{
	200000: {"XML body parser selected", 0, RiskInfo},
	200001: {"JSON body parser selected", 0, RiskInfo},
	200002: {"Request body failed to parse", Of(CatProtocol), RiskMedium},
	200003: {"Multipart body failed strict validation", Of(CatEvasion), RiskMedium},
	200004: {"Too many query or path arguments", Of(CatProtocol), RiskMedium},
	200005: {"Too many body arguments", Of(CatProtocol), RiskMedium},
	200006: {"JSON body parser selected for a +json type", 0, RiskInfo},
	200009: {"Request URI failed to parse", Of(CatProtocol), RiskMedium},
}

// localRules are carnical's local CRS rules (crs/local/REQUEST-499-CARNICAL.conf); the names are the rules' own fixed
// msg, which crs.LocalRuleMessage also returns.
var localRules = map[int]Entry{
	5006001: {"XPath predicate injection syntax", Of(CatGeneric), RiskLow},
	5006002: {"XPath union injection syntax", Of(CatGeneric), RiskLow},
	5006003: {"Shell command chaining or substitution", Of(CatRCE), RiskLow},
	5006004: {"Command interpreter invocation", Of(CatRCE), RiskLow},
	5006005: {"Server template expression injection", Of(CatGeneric), RiskLow},
	5006006: {"Nested-encoded parent path traversal", Of(CatLFI), RiskLow},
	5006007: {"Java serialization stream in a request field", Of(CatJava), RiskLow},
	5006008: {"Unsafe fetch protocol or ambiguous URL authority", Of(CatGeneric), RiskLow},
	5006009: {"XPath comment obfuscation after a quote", Of(CatGeneric), RiskLow},
	5006010: {"Obfuscated shell command spelling", Of(CatRCE), RiskLow},
	5006011: {"Exploit or web shell path", Of(CatScanner), RiskLow},
	5006012: {"Debug or diagnostic interface", Of(CatScanner), RiskLow},
	5006013: {"Web application installer", Of(CatScanner), RiskLow},
	5006014: {"Scanner user agent", Of(CatScanner), RiskLow},
	5006015: {"Remote file reference in an include parameter", Of(CatRFI), RiskLow},
	5006016: {"FTP, SMB or scheme-less reference to another host", Of(CatRFI), RiskLow},
	5006017: {"Remote text or include file URL", Of(CatRFI), RiskLow},
	5006018: {"Database administration tool", Of(CatScanner), RiskLow},
	5006019: {"PHP information or test page", Of(CatScanner), RiskLow},
	5006020: {"Debugger or server console", Of(CatScanner), RiskLow},
	5006021: {"Script on another host in a URL parameter", Of(CatRFI), RiskLow},
	5006022: {"Forwarded host header that is not a host name", Of(CatProtocol), RiskLow},
	5006023: {"Unicode newline header injection (response splitting)", Of(CatProtocol), RiskLow},
	5006101: {"Console path", Of(CatScanner), RiskLow},
	5006102: {"Script on another host in a body parameter", Of(CatRFI), RiskLow},
	5006103: {"Forwarded host that is not the host asked for", Of(CatProtocol), RiskLow},
}

// proxyRules are the proxy's own refusals and reports (proxy/policy.go). The names are static; the proxy's messages
// can hold details this catalog does not repeat.
var proxyRules = map[int]Entry{
	5000001: {"Host is not one of this site's names", Of(CatPolicy), RiskMedium},
	5000002: {"Request path not in plain form", Of(CatEvasion), RiskMedium},
	5000003: {"Header this site does not accept", Of(CatPolicy), RiskMedium},
	5000004: {"Request body encoding that cannot be inspected", Of(CatEvasion), RiskMedium},
	5000005: {"Ambiguous Content-Type or multipart part", Of(CatEvasion), RiskLow},
	5000010: {"Executable upload name", Of(CatUpload), RiskHigh},
	5000011: {"Script content in an upload", Of(CatUpload), RiskHigh},
	5000012: {"Multipart form fields over the form body limit", Of(CatProtocol), RiskLow},
	5000020: {"Script in a WordPress data directory", Of(CatWordPress), RiskHigh},
	5000021: {"WordPress xmlrpc.php switched off", Of(CatWordPress), RiskLow},
	5000022: {"WordPress login rate limit", Of(CatRate), RiskLow},
	5000030: {"Too many connections from one address", Of(CatFlood), RiskLow},
	5000040: {"Request inspector failed", Of(CatInspection), RiskMedium},
	5000041: {"Rate rule table full", Of(CatRate), RiskInfo},
	5000042: {"API rate limit", Of(CatRate), RiskLow},
	5000043: {"Noncanonical HTTP method", Of(CatEvasion), RiskLow},
	5000044: {"HTTP method override header", Of(CatEvasion), RiskLow},
	5000045: {"Rule evaluation budget exhausted", Of(CatInspection), RiskMedium},
	5000046: {"No rule evaluation slot free", Of(CatInspection), RiskMedium},
	5000047: {"Rate rule limit", Of(CatRate), RiskLow},
	5000048: {"Rate rule limit (monitor)", Of(CatRate), RiskInfo},
	5000050: {"Upstream request failed", 0, RiskInfo},
	5000051: {"Upstream socket bind retried", 0, RiskInfo},
	5000052: {"Unread response ended to free an upstream", 0, RiskInfo},
	5000060: {"CrowdSec IP ban", Of(CatReputation), RiskMedium},
	5000061: {"CrowdSec decisions unavailable", Of(CatInspection), RiskInfo},
	5000070: {"CONNECT request", Of(CatProtocol), RiskMedium},
	5000071: {"Protocol upgrade or h2c", Of(CatProtocol), RiskMedium},
	5000072: {"Request target that cannot be forwarded", Of(CatEvasion), RiskMedium},
	5000073: {"Invalid client address or forwarding chain", Of(CatProtocol), RiskMedium},
	5000074: {"Request body over the size limit", Of(CatProtocol), RiskLow},
	5000075: {"Request body unreadable", Of(CatProtocol), RiskLow},
	5000076: {"Request body too slow", Of(CatProtocol), RiskInfo},
	5000077: {"Request the engine could not process", Of(CatInspection), RiskLow},
	5000078: {"Rule match lines over the per-request cap", 0, RiskInfo},
	5000079: {"WebSocket handshake the application did not switch", Of(CatProtocol), RiskLow},
}

// shieldRules are the flood protection's ids (shield/shield.go).
var shieldRules = map[int]Entry{
	5004001: {"Address over its request rate", Of(CatFlood), RiskLow},
	5004002: {"Network over its request rate", Of(CatFlood), RiskLow},
	5004003: {"Request like an ongoing attack, over its budget", Of(CatFlood), RiskLow},
	5004004: {"Unknown client during an attack, over its budget", Of(CatFlood), RiskLow},
	5004005: {"Browser challenge shown", Of(CatFlood), RiskInfo},
	5004006: {"Browser challenge failed", Of(CatFlood), RiskLow},
	5004007: {"Browser challenge solved", Of(CatFlood), RiskInfo},
	5004008: {"Banned address", Of(CatFlood, CatReputation), RiskMedium},
}

// botRules are the bot policy's ids (bots/policy.go): 5005000 and the number of the kind of client refused. A declared
// crawler or tool is low; a scanner or attack tool, and a client that claims to be a search engine from an address that
// is not the engine's, are medium: the first is probing the site, the second lying about itself.
var botRules = map[int]Entry{
	5005003: {"AI crawler", Of(CatBot), RiskLow},
	5005004: {"SEO or data-mining crawler", Of(CatBot), RiskLow},
	5005005: {"HTTP tool or script", Of(CatBot), RiskLow},
	5005006: {"Headless or automated browser", Of(CatBot), RiskLow},
	5005007: {"Scanner or attack tool", Of(CatBot, CatScanner), RiskMedium},
	5005010: {"Unidentified bot", Of(CatBot), RiskLow},
	5005011: {"Fake search engine crawler", Of(CatBot), RiskMedium},
	5005012: {"Program disguised as a browser", Of(CatBot), RiskLow},
}

// gateRules are the person check's ids (proxy/challenge.go): what a check plugged in through package challenge decided.
var gateRules = map[int]Entry{
	5007001: {"Person check refused the visitor", Of(CatBot), RiskLow},
}

// apiRules are the API guard's ids (apiguard/verdict.go). The guard's own severity sets the risk of a finding.
var apiRules = map[int]Entry{
	5003001: {"API method not allowed", Of(CatAPIContract), RiskMedium},
	5003002: {"API body too large", Of(CatAPIContract), RiskMedium},
	5003003: {"API body without Content-Type", Of(CatAPIContract), RiskLow},
	5003004: {"API Content-Type not seen before", Of(CatAPIContract), RiskLow},
	5003005: {"API JSON body malformed", Of(CatAPIContract), RiskMedium},
	5003006: {"API JSON body repeats a key", Of(CatAPIContract, CatEvasion), RiskMedium},
	5003010: {"API client rate limit", Of(CatRate), RiskLow},
	5003011: {"API authentication rate limit", Of(CatRate), RiskMedium},
	5003020: {"API privileged property in a write", Of(CatAPIContract), RiskMedium},
	5003021: {"API privileged property refused", Of(CatAPIContract), RiskHigh},
	5003100: {"API route not in the specification", Of(CatAPIContract), RiskLow},
	5003101: {"API method not in the specification", Of(CatAPIContract), RiskLow},
	5003102: {"API path parameter invalid", Of(CatAPIContract), RiskMedium},
	5003103: {"API query parameter invalid", Of(CatAPIContract), RiskMedium},
	5003104: {"API header parameter invalid", Of(CatAPIContract), RiskMedium},
	5003105: {"API cookie parameter invalid", Of(CatAPIContract), RiskMedium},
	5003106: {"API required parameter missing", Of(CatAPIContract), RiskLow},
	5003107: {"API Content-Type not in the specification", Of(CatAPIContract), RiskMedium},
	5003108: {"API body does not match its schema", Of(CatAPIContract), RiskMedium},
	5003109: {"API body property not in the specification", Of(CatAPIContract), RiskMedium},
	5003110: {"API read-only property written", Of(CatAPIContract), RiskHigh},
	5003111: {"API body missing", Of(CatAPIContract), RiskLow},
	5003112: {"API body not expected", Of(CatAPIContract), RiskLow},
	5003113: {"API query parameter not in the specification", Of(CatAPIContract), RiskLow},
	5003114: {"API credential missing", Of(CatAPIContract), RiskMedium},
	5003115: {"API request too complex to check", Of(CatAPIContract, CatInspection), RiskMedium},
	5003200: {"API route not learned", Of(CatAPIContract), RiskLow},
	5003201: {"API method not learned", Of(CatAPIContract), RiskLow},
	5003203: {"API query parameter unlike those learned", Of(CatAPIContract), RiskLow},
	5003204: {"API query parameter not learned", Of(CatAPIContract), RiskLow},
	5003205: {"API learned query parameter missing", Of(CatAPIContract), RiskLow},
	5003206: {"API Content-Type not learned", Of(CatAPIContract), RiskLow},
	5003207: {"API body type not learned", Of(CatAPIContract), RiskLow},
	5003208: {"API body property not learned", Of(CatAPIContract), RiskLow},
	5003209: {"API learned body property missing", Of(CatAPIContract), RiskLow},
	5003210: {"API body not learned", Of(CatAPIContract), RiskLow},
	5003211: {"API learned body missing", Of(CatAPIContract), RiskLow},
	5003990: {"API guard failed on the request", Of(CatInspection), RiskMedium},
}

// formatsFamilies name the formats rules by their hundred (formats/rules.go); the inspector's own severity sets the
// risk of a finding.
var formatsFamilies = map[int]string{
	0: "Body type, size or encoding",
	1: "JSON format",
	2: "XML format",
	3: "GraphQL format",
	4: "NDJSON format",
	5: "YAML format",
	6: "Form format",
	7: "Multipart format",
	8: "URL query format",
	9: "Format check failed",
}

// vpatchEngine are the virtual-patch engine's own ids (vpatch/engine.go).
var vpatchEngine = map[int]Entry{
	5100001: {"Virtual patch work allowance used up", Of(CatInspection), RiskMedium},
	5100002: {"More virtual patches matched than listed", Of(CatVirtualPatch), RiskLow},
	5100003: {"More values than virtual patches read", Of(CatInspection), RiskMedium},
	5100004: {"Virtual patch engine failed on the request", Of(CatInspection), RiskMedium},
}

// Lookup returns the catalog entry of a rule id, and whether the id is in a known range. An id in a known range with
// no entry of its own gets its range's name and category.
func Lookup(id int) (Entry, bool) {
	switch {
	case id >= baseFirst && id <= baseLast:
		if e, ok := baseRules[id]; ok {
			return e, true
		}
		return Entry{Name: "Coraza base rule", Categories: Of(CatProtocol), Risk: RiskMedium}, true
	case id >= crsFirst && id <= crsLast:
		if e, ok := crsNamed[id]; ok {
			return e, true
		}
		f, ok := crsFamilies[id/1000]
		if !ok {
			return Entry{Name: "OWASP CRS rule", Risk: RiskLow}, true
		}
		return Entry{Name: f.name, Categories: f.cats, Risk: RiskLow}, true
	case id >= policyFirst && id <= policyLast:
		return policyEntry(id), true
	case id >= proxyFirst && id <= proxyLast:
		if e, ok := proxyRules[id]; ok {
			return e, true
		}
		return Entry{Name: "Carnical proxy check", Risk: RiskLow}, true
	case id >= formatsFirst && id <= formatsLast:
		risk := RiskMedium
		if id >= 5002990 {
			risk = RiskHigh // the policy is invalid or the check failed: bodies are refused
		}
		return Entry{Name: formatsFamilies[(id-formatsFirst)/100], Categories: Of(CatFormat), Risk: risk}, true
	case id >= apiFirst && id <= apiLast:
		if e, ok := apiRules[id]; ok {
			return e, true
		}
		return Entry{Name: "API contract check", Categories: Of(CatAPIContract), Risk: RiskLow}, true
	case id >= shieldFirst && id <= shieldLast:
		if e, ok := shieldRules[id]; ok {
			return e, true
		}
		return Entry{Name: "Flood protection", Categories: Of(CatFlood), Risk: RiskLow}, true
	case id >= botsFirst && id <= botsLast:
		if e, ok := botRules[id]; ok {
			return e, true
		}
		return Entry{Name: "Bot policy", Categories: Of(CatBot), Risk: RiskLow}, true
	case id >= localFirst && id <= localLast:
		if e, ok := localRules[id]; ok {
			return e, true
		}
		return Entry{Name: "Carnical local rule", Risk: RiskInfo}, true
	case id >= gateFirst && id <= gateLast:
		if e, ok := gateRules[id]; ok {
			return e, true
		}
		return Entry{Name: "Person check", Categories: Of(CatBot), Risk: RiskLow}, true
	case id >= vpatchFirst && id <= vpatchLast:
		if e, ok := vpatchEngine[id]; ok {
			return e, true
		}
		return Entry{Name: "Virtual patch", Categories: Of(CatVirtualPatch), Risk: RiskMedium}, true
	}
	return Entry{}, false
}

// policyEntry names a site policy rule by its block (policy/limits.go).
func policyEntry(id int) Entry {
	switch (id - policyFirst) / 10000 {
	case 1:
		return Entry{Name: "Policy exclusion", Categories: Of(CatPolicy), Risk: RiskInfo}
	case 2:
		return Entry{Name: "Policy allowed address", Categories: Of(CatPolicy), Risk: RiskInfo}
	case 3:
		return Entry{Name: "Address on the block list", Categories: Of(CatReputation, CatPolicy), Risk: RiskHigh}
	case 4:
		return Entry{Name: "Policy allowed path", Categories: Of(CatPolicy), Risk: RiskInfo}
	case 5:
		return Entry{Name: "Custom rule", Categories: Of(CatPolicy), Risk: RiskMedium}
	}
	return Entry{Name: "Site policy rule", Categories: Of(CatPolicy), Risk: RiskLow}
}

// crsTags are the categories of the CRS's attack tags (tag:'attack-sqli' and so on), which name what a rule looks for
// more closely than its file does: a rule of the protocol file tagged attack-ssrf, say.
var crsTags = map[string]Category{
	"attack-sqli": CatSQLi, "attack-xss": CatXSS, "attack-rce": CatRCE, "attack-lfi": CatLFI, "attack-rfi": CatRFI,
	"attack-injection-php": CatPHP, "attack-injection-java": CatJava, "attack-injection-generic": CatGeneric,
	"attack-generic": CatGeneric, "attack-ssrf": CatGeneric, "attack-ssti": CatGeneric, "attack-fixation": CatSession,
	"attack-disclosure": CatDataLeak, "attack-protocol": CatProtocol, "attack-multipart-header": CatProtocol,
	"attack-deprecated-header": CatProtocol, "attack-reputation-scanner": CatScanner,
}

// TagCategory is the category of a CRS attack tag, or 0 for any other tag. Tags are the rule's static metadata, never
// request data.
func TagCategory(tag string) Category {
	if !strings.HasPrefix(tag, "attack-") {
		return 0
	}
	return crsTags[tag]
}

// CRSRisk is the risk of one CRS or local rule's finding below the anomaly threshold, from its severity: critical and
// error are low, everything else info. The request's verdict over the threshold is high (949110, 959100, and 949111 and
// 959101 with early blocking).
func CRSRisk(severity string) Risk {
	switch strings.ToLower(severity) {
	case "critical", "emergency", "alert", "error":
		return RiskLow
	}
	return RiskInfo
}

// InspectorRisk is the risk of an inspector's finding (formats, apiguard, vpatch) from its severity: critical and high
// are high, medium is medium, low is low, or medium when the finding refused the request.
func InspectorRisk(severity string, refused bool) Risk {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return RiskHigh
	case "medium":
		return RiskMedium
	case "low":
		if refused {
			return RiskMedium
		}
		return RiskLow
	}
	return RiskInfo
}

// Signature returns the stable signature of a numeric rule id: crs- (the CRS, carnical's local rules and Coraza's base
// rules, which run in the same engine), policy-, carnical-, formats-, apiguard-, shield-, bots-, challenge- or vpatch-
// followed by the id, or "" for an id in no known range. A virtual-patch signature has a name of its own; see
// VPatchSignature.
func Signature(id int) string {
	p := sigPrefix(id)
	if p == "" {
		return ""
	}
	var b [32]byte
	return string(strconv.AppendInt(append(b[:0], p...), int64(id), 10))
}

func sigPrefix(id int) string {
	switch {
	case id >= crsFirst && id <= crsLast, id >= localFirst && id <= localLast, id >= baseFirst && id <= baseLast:
		return "crs-"
	case id >= policyFirst && id <= policyLast:
		return "policy-"
	case id >= proxyFirst && id <= proxyLast:
		return "carnical-"
	case id >= formatsFirst && id <= formatsLast:
		return "formats-"
	case id >= apiFirst && id <= apiLast:
		return "apiguard-"
	case id >= shieldFirst && id <= shieldLast:
		return "shield-"
	case id >= botsFirst && id <= botsLast:
		return "bots-"
	case id >= gateFirst && id <= gateLast:
		return "challenge-"
	case id >= vpatchFirst && id <= vpatchLast:
		return "vpatch-"
	}
	return ""
}

// maxVPatchID is how much of a virtual-patch ID a signature keeps, so that the signature stays within MaxSig.
const maxVPatchID = MaxSig - len("vpatch-")

// VPatchSignature returns the signature of a virtual patch from its ID ("CS-CVE-2024-4577-1"): "vpatch-" and the ID,
// cut to fit MaxSig. A character outside the ID alphabet vpatch accepts is replaced by '_'.
func VPatchSignature(id string) string {
	if len(id) > maxVPatchID {
		id = id[:maxVPatchID]
	}
	b := make([]byte, 0, len("vpatch-")+len(id))
	b = append(b, "vpatch-"...)
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !vpatchIDByte(c) {
			c = '_'
		}
		b = append(b, c)
	}
	return string(b)
}

func vpatchIDByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._:-@/+", c) >= 0
}

// ValidSignature reports whether s is a signature in one of the forms Signature and VPatchSignature return, with an id
// in that form's range. Suppressions are checked with it, so that a misspelt one is refused instead of never matching.
func ValidSignature(s string) bool {
	if len(s) > MaxSig {
		return false
	}
	if rest, ok := strings.CutPrefix(s, "vpatch-"); ok {
		if rest == "" {
			return false
		}
		for i := 0; i < len(rest); i++ {
			if !vpatchIDByte(rest[i]) {
				return false
			}
		}
		return true
	}
	i := strings.IndexByte(s, '-')
	if i <= 0 || i+1 >= len(s) || len(s)-i-1 > 7 {
		return false
	}
	id, err := strconv.Atoi(s[i+1:])
	if err != nil || id <= 0 || s[i+1] == '0' || s[i+1] == '+' {
		return false
	}
	return sigPrefix(id) == s[:i+1]
}
