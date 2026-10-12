// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"regexp"
	"strings"
)

// GroupInfo describes a rule group, for a UI that lists them and for anything that needs the rule ids behind a name.
type GroupInfo struct {
	// Name is the key in Policy.RuleGroups and in an exclusion's categories.
	Name string
	// Title is what the group is, in words.
	Title string
	// First and Last are the Core Rule Set rule ids the group covers.
	First, Last int
}

// groups are the ten rule groups, by the ranges of rule ids the Core Rule Set gives its categories (which is why the groups
// are made of id ranges and not of the CRS's tags: the tags cross the ranges, 934 carries attack-rce, attack-ssrf and
// attack-ssti and 944 carries attack-rce, so a tag would put a Java rule in the RCE group).
var groups = []GroupInfo{
	{"sqli", "SQL injection", 942000, 942999},
	{"xss", "Cross-site scripting", 941000, 941999},
	{"lfi", "Reading local files", 930000, 930999},
	{"rfi", "Including remote files", 931000, 931999},
	{"rce", "Running commands", 932000, 932999},
	{"php", "PHP code injection", 933000, 933999},
	{"ssrf", "Requests to inner addresses and other generic attacks", 934000, 934999},
	{"java", "Java and Log4j", 944000, 944999},
	{"scanner", "Scanners and attack tools", 913000, 913999},
	{"protocol", "Malformed requests and protocol attacks", 920000, 922999},
}

var groupByName = func() map[string]GroupInfo {
	m := make(map[string]GroupInfo, len(groups))
	for _, g := range groups {
		m[g.Name] = g
	}
	return m
}()

// Groups returns the rule groups in a fixed order.
func Groups() []GroupInfo { return append([]GroupInfo(nil), groups...) }

// groupIndex is a group's position, used to number the rules compiled from an exclusion.
func groupIndex(name string) int {
	for i, g := range groups {
		if g.Name == name {
			return i
		}
	}
	return -1
}

var (
	methodRe   = regexp.MustCompile(`\A[A-Z][A-Z-]{0,19}\z`)
	hostLabel  = regexp.MustCompile(`\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z`)
	headerRe   = regexp.MustCompile(`\A[a-z0-9][a-z0-9-]{0,63}\z`)
	argKeyRe   = regexp.MustCompile(`\A[a-z0-9][a-z0-9_.\[\]-]{0,63}\z`)
	softwareRe = regexp.MustCompile(`\A[a-z0-9][a-z0-9._+-]{0,63}(?:@[a-z0-9][a-z0-9._+-]{0,31})?\z`)
	// pathRe is the characters a path prefix may use. None of them means anything to SecLang, so a path can never end the
	// operator it is written into or start a macro: no space, quote, backslash, percent sign, brace or control character.
	pathRe = regexp.MustCompile(`\A/[A-Za-z0-9/_.~@:=+,-]{0,199}\z`)
)

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func validPath(s string) bool {
	return len(s) <= MaxPathBytes && pathRe.MatchString(s) && !strings.Contains(s, "//") && !hasDotSegment(s)
}

func hasDotSegment(s string) bool {
	for _, seg := range strings.Split(s, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// fixedTargets are the parts of a request an exclusion or a custom rule may name, with the SecLang variable each is.
var fixedTargets = map[string]string{
	"method":      "REQUEST_METHOD",
	"path":        "REQUEST_FILENAME",
	"uri":         "REQUEST_URI",
	"query":       "QUERY_STRING",
	"args":        "ARGS",
	"argnames":    "ARGS_NAMES",
	"cookies":     "REQUEST_COOKIES",
	"cookienames": "REQUEST_COOKIES_NAMES",
	"headers":     "REQUEST_HEADERS",
	"body":        "REQUEST_BODY",
	"filenames":   "FILES",
}

// extraFields are names only a custom rule may use: they are single headers with a name of their own.
var extraFields = map[string]string{
	"host":      "REQUEST_HEADERS:host",
	"useragent": "REQUEST_HEADERS:user-agent",
}

// keyedTargets are the prefixes of a target that names one value, with the variable each reads and the form of the name.
var keyedTargets = map[string]struct {
	variable string
	keyRe    *regexp.Regexp
}{
	"arg":    {"ARGS", argKeyRe},
	"cookie": {"REQUEST_COOKIES", argKeyRe},
	"header": {"REQUEST_HEADERS", headerRe},
}

// bodyVariables are what a custom rule on the body reads. The engine keeps the body as it was sent (REQUEST_BODY) only for a
// form and for a body it has no parser for. A JSON or multipart body becomes names and values (ARGS_POST, ARGS_POST_NAMES) and
// an XML body its text and attribute values (XML:/*, XML://@*), with no REQUEST_BODY at all, so a rule that read only that
// would let the same payload through as soon as a client changed the Content-Type. What none of them holds is the content of
// an uploaded file, which the uploads section checks.
const bodyVariables = "REQUEST_BODY|ARGS_POST|ARGS_POST_NAMES|XML:/*|XML://@*"

// ruleVariables returns the SecLang variables a custom rule on a field reads, or false. It is targetVariable, widened where one
// part of a request, as the application reads it, is in more than one place in the engine:
//
//   - body: see bodyVariables;
//   - a header whose name has a hyphen (header:NAME, useragent): PHP, CGI, WSGI and IIS turn each "-" of a header's name into
//     "_", so X_Api-Key reaches such an application as the same input as X-Api-Key, and the engine keys a header by its own
//     name. The header is named by a key pattern that takes either character in each place, REQUEST_HEADERS:/^x[-_]api[-_]key$/,
//     which is how the proxy folds the two spellings for deny_headers.
//   - an argument or a cookie whose name has no bracket (arg:NAME, cookie:NAME): PHP drops the spaces in front of a name, turns
//     each "." and " " in it (and a "[" that is never closed) into "_", reads NAME[...] as NAME holding a list, and ends a name
//     at a NUL, so user.id, user+id, user[id, user_id[] and user_id%00x all reach a PHP application as $_GET['user_id']. The name
//     is a key pattern that takes each of those spellings, ARGS:/^\x20*user[_.\x20\[]id(?s:\[[^\]\x00]*\].*)?(?s:\x00.*)?$/
//     (\x20, as a space would end the variable).
//
// An exclusion keeps targetVariable: what it takes out of inspection is never widened.
func ruleVariables(field string) (string, bool) {
	if field == "body" {
		return bodyVariables, true
	}
	v, ok := targetVariable(field, true)
	if !ok {
		return "", false
	}
	// A header name is made of a-z, 0-9 and "-" only (headerRe), so the hyphen is the one character the pattern has to spell.
	if name, isHeader := strings.CutPrefix(v, "REQUEST_HEADERS:"); isHeader && strings.Contains(name, "-") {
		return "REQUEST_HEADERS:/^" + strings.ReplaceAll(name, "-", "[-_]") + "$/", true
	}
	// An argument or cookie name is made of a-z, 0-9 and . _ [ ] - (argKeyRe): without brackets, "_" and "." are the only
	// characters the pattern has to spell.
	for _, variable := range []string{"ARGS:", "REQUEST_COOKIES:"} {
		if name, keyed := strings.CutPrefix(v, variable); keyed && !strings.ContainsAny(name, "[]") {
			return variable + `/^\x20*` + phpName.Replace(name) + `(?s:\[[^\]\x00]*\].*)?(?s:\x00.*)?$/`, true
		}
	}
	return v, true
}

// phpName writes each character PHP reads as "_" in a name as the characters it reads that way.
var phpName = strings.NewReplacer("_", `[_.\x20\[]`, ".", `[_.\x20\[]`)

// targetVariable returns the SecLang variable (with its key, if it names one value) for a target or field name, or false.
func targetVariable(name string, allowExtra bool) (string, bool) {
	if v, ok := fixedTargets[name]; ok {
		return v, true
	}
	if allowExtra {
		if v, ok := extraFields[name]; ok {
			return v, true
		}
	}
	prefix, key, ok := strings.Cut(name, ":")
	if !ok {
		return "", false
	}
	k, known := keyedTargets[prefix]
	if !known || !k.keyRe.MatchString(key) {
		return "", false
	}
	return k.variable + ":" + key, true
}

// phase1Fields are the fields that are complete when the request headers have been read; everything else needs the body.
func fieldPhase(name string) int {
	switch name {
	case "method", "path", "uri", "query", "cookies", "cookienames", "headers", "host", "useragent":
		return 1
	}
	if strings.HasPrefix(name, "cookie:") || strings.HasPrefix(name, "header:") {
		return 1
	}
	return 2
}

var knownTiers = map[string]bool{"verified": true, "community": true, "experimental": true}

var (
	validModes    = map[Mode]bool{ModeBlock: true, ModeMonitor: true, ModeOff: true}
	validSens     = map[Sensitivity]bool{SensitivityRelaxed: true, SensitivityNormal: true, SensitivityStrict: true}
	validStates   = map[GroupState]bool{GroupOff: true, GroupLog: true, GroupOn: true}
	validAPIModes = map[APIMode]bool{APIOff: true, APILearn: true, APIMonitor: true, APIEnforce: true}
	validOps      = map[Operator]bool{OpContains: true, OpEquals: true, OpBeginsWith: true, OpEndsWith: true, OpPM: true, OpRX: true}
)
