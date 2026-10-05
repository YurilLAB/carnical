// SPDX-License-Identifier: Apache-2.0

package importers

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/YurilLAB/coraza/carnical/vpatch"
)

// maxScan bounds how much of any one text the metadata helpers read, so a huge description costs a fixed amount.
const maxScan = 16 << 10

var cveRe = regexp.MustCompile(`(?i)\bCVE[-_ ]?(\d{4})[-_ ]?(\d{4,7})\b`)

// CVEs finds CVE identifiers in the given texts and returns them upper-cased and written CVE-YYYY-NNNN, without duplicates, in order.
func CVEs(texts ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range texts {
		if len(t) > maxScan {
			t = t[:maxScan]
		}
		for _, m := range cveRe.FindAllStringSubmatch(t, -1) {
			id := "CVE-" + m[1] + "-" + m[2]
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}

// IDPart makes s safe to use inside a signature ID: upper case, only A-Z, 0-9, "." and "-", runs of anything else become one "-",
// and at most 80 characters.
func IDPart(s string) string {
	var b strings.Builder
	dash := false
	prevDot := false
	for _, r := range strings.ToUpper(s) {
		if b.Len() >= 80 {
			break
		}
		// A single dot is kept (SCRIPT.PHP); two in a row are a path trick, not a name, and become a separator.
		switch {
		case r >= 'A' && r <= 'Z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			dash, prevDot = false, false
		case r == '.' && !prevDot && b.Len() > 0 && !dash:
			b.WriteRune(r)
			prevDot = true
		default:
			if prevDot { // the earlier dot was not followed by a name character
				str := strings.TrimSuffix(b.String(), ".")
				b.Reset()
				b.WriteString(str)
				prevDot = false
			}
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	return strings.Trim(b.String(), "-.")
}

// Describe cleans free text for a signature's description: control characters out, runs of white space to one space, cut to max
// bytes at a character boundary. A description says what a signature recognises; it must never carry an example of the attack, so
// converters build descriptions from titles, never from payloads.
func Describe(s string, max int) string {
	if len(s) > max*4 {
		s = s[:max*4]
	}
	var b strings.Builder
	space := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if unicode.IsControl(r) || r == utf8.RuneError {
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > max {
		out = out[:max]
		for !utf8.ValidString(out) {
			out = out[:len(out)-1]
		}
	}
	return out
}

// SafeName makes a unit name safe to print in a report or an error: printable ASCII only, cut to 80 characters.
func SafeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
		if b.Len() >= 80 {
			break
		}
	}
	return b.String()
}

type textClass struct {
	category string
	re       *regexp.Regexp
}

// The order matters: the first class that matches wins, so the narrow ones come first.
var textClasses = []textClass{
	{"sqli", regexp.MustCompile(`(?i)\bsql[ -]?injection|\bsqli\b|\bblind sql`)},
	{"xxe", regexp.MustCompile(`(?i)\bxxe\b|xml external entit`)},
	{"ssti", regexp.MustCompile(`(?i)template injection|\bssti\b|expression language injection`)},
	{"ssrf", regexp.MustCompile(`(?i)\bssrf\b|server[- ]side request forgery`)},
	{"upload", regexp.MustCompile(`(?i)file upload|unrestricted upload|upload(?:ing)? (?:of )?(?:a )?(?:web ?shell|malicious|arbitrary)|\bweb ?shell\b`)},
	{"rfi", regexp.MustCompile(`(?i)remote file inclusion|\brfi\b`)},
	{"lfi", regexp.MustCompile(`(?i)local file inclusion|\blfi\b|path traversal|directory traversal|arbitrary file (?:read|download|disclosure)|file read|file disclosure|file inclusion|\.\./`)},
	{"xss", regexp.MustCompile(`(?i)cross[- ]site scripting|\bxss\b`)},
	{"java", regexp.MustCompile(`(?i)deserializ|\bjndi\b|log4(?:j|shell)|\bognl\b|spring4shell|\bstruts\b|java\b`)},
	{"rce", regexp.MustCompile(`(?i)remote code execution|\brce\b|command injection|code injection|command execution|code execution|os command|arbitrary (?:code|command)|remote command|\beval\b`)},
	{"php", regexp.MustCompile(`(?i)php object injection|php wrapper|\bphar\b|php:// ?`)},
	{"scanner", regexp.MustCompile(`(?i)\bscanner\b|\bnuclei\b|\bnikto\b|\bsqlmap\b`)},
}

// ClassifyText guesses the attack class of a rule from words in its title or description, and returns one of the model's
// categories or "" when no word matches.
func ClassifyText(texts ...string) string {
	for _, t := range texts {
		if len(t) > 4096 {
			t = t[:4096]
		}
		for _, c := range textClasses {
			if c.re.MatchString(t) {
				return c.category
			}
		}
	}
	return ""
}

var numberRe = regexp.MustCompile(`\d{1,6}`)

func firstNumber(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return numberRe.FindString(s)
}

// CategoryFromCWE maps a CWE identifier written as 79, "CWE-79", "cwe.CWE-79" or "CWE.79" to a category, or "" when it has no mapping.
func CategoryFromCWE(cwe string) string {
	s := firstNumber(cwe)
	switch s {
	case "79", "80", "83", "84", "85", "86", "87":
		return "xss"
	case "89", "564":
		return "sqli"
	case "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "73", "552":
		return "lfi"
	case "98":
		return "rfi"
	case "77", "78", "88", "74", "94", "95", "96", "917", "1321":
		return "rce"
	case "918":
		return "ssrf"
	case "611", "776":
		return "xxe"
	case "1336":
		return "ssti"
	case "434":
		return "upload"
	case "200", "538", "548":
		return "probe"
	}
	return ""
}

// SeverityFor is a default severity for a category, used when the source gives none.
func SeverityFor(category string) string {
	switch category {
	case "rce", "rfi", "ssti", "java":
		return "critical"
	case "sqli", "lfi", "upload", "xxe", "ssrf", "php", "cve":
		return "high"
	case "probe", "scanner", "protocol":
		return "low"
	}
	return "medium"
}

// ScoreFor is the score a signature adds, by how sure its author is (see vpatch.Signature.Score).
func ScoreFor(confidence string) int {
	switch confidence {
	case "high":
		return 5
	case "medium":
		return 4
	}
	return 2
}

// ActionFor is the action a signature gets: block, except where the source itself says it is unsure.
func ActionFor(confidence string) string {
	if confidence == "low" {
		return "log"
	}
	return "block"
}

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,60}$`)

var (
	wpPluginRe = regexp.MustCompile(`/wp-content/plugins/([^/?#]+)`)
	wpThemeRe  = regexp.MustCompile(`/wp-content/themes/([^/?#]+)`)
)

type scopeWord struct {
	re    *regexp.Regexp
	scope string
}

var scopeWords = func() []scopeWord {
	pairs := [][2]string{
		{`wordpress|wp-plugin|wp-theme`, "wordpress"},
		{`joomla`, "joomla"},
		{`drupal`, "drupal"},
		{`magento`, "magento"},
		{`laravel`, "laravel"},
		{`symfony`, "symfony"},
		{`typo3`, "typo3"},
		{`prestashop`, "prestashop"},
		{`opencart`, "opencart"},
		{`spring[ -]?boot|spring[ -]?cloud|spring framework|spring4shell|springframework`, "spring"},
		{`struts`, "struts"},
		{`tomcat`, "tomcat"},
		{`next\.?js`, "nextjs"},
		{`node\.?js`, "nodejs"},
		{`log4j|log4shell`, "java"},
		{`weblogic`, "weblogic"},
		{`websphere`, "websphere"},
		{`jboss|wildfly`, "jboss"},
		{`jenkins`, "jenkins"},
		{`confluence`, "confluence"},
		{`jira`, "jira"},
		{`gitlab`, "gitlab"},
		{`grafana`, "grafana"},
		{`kibana`, "kibana"},
		{`elasticsearch`, "elasticsearch"},
		{`citrix|netscaler`, "citrix"},
		{`fortinet|fortigate|fortios`, "fortinet"},
		{`exchange server|microsoft exchange`, "exchange"},
		{`sharepoint`, "sharepoint"},
		{`vmware|vcenter`, "vmware"},
		{`roundcube`, "roundcube"},
		{`phpmyadmin`, "phpmyadmin"},
		{`moodle`, "moodle"},
		{`mediawiki`, "mediawiki"},
		{`django`, "django"},
		{`rails`, "rails"},
		{`flask`, "flask"},
	}
	var out []scopeWord
	for _, p := range pairs {
		out = append(out, scopeWord{regexp.MustCompile(`(?i)\b(?:` + p[0] + `)\b`), p[1]})
	}
	return out
}()

// generic is what a more specific scope makes redundant: a signature scoped to a WordPress plugin must not also be scoped to
// every PHP site, because a scope list means "any of these".
var impliedBy = map[string][]string{
	"wordpress": {"php"},
	"joomla":    {"php"}, "drupal": {"php"}, "magento": {"php"}, "laravel": {"php"}, "symfony": {"php"}, "typo3": {"php"},
	"prestashop": {"php"}, "opencart": {"php"}, "phpmyadmin": {"php"}, "roundcube": {"php"}, "moodle": {"php"}, "mediawiki": {"php"},
	"spring": {"java"}, "struts": {"java"}, "tomcat": {"java"}, "weblogic": {"java"}, "websphere": {"java"}, "jboss": {"java"},
	"jenkins": {"java"}, "confluence": {"java"}, "jira": {"java"}, "elasticsearch": {"java"},
	"nextjs": {"nodejs"}, "django": {"python"}, "flask": {"python"}, "rails": {"ruby"},
}

// InferScope names the software a rule is about, so that a site can switch on only the signatures that apply to it. The URL
// paths a rule names are the strong evidence (/wp-content/plugins/<slug>/ names a WordPress plugin exactly); words in the title,
// description and tags are used only when the paths say nothing. A scope list means "any of these", so redundant general scopes are
// dropped (a WordPress plugin is not also "php"), and a rule that names no software has no scope and applies to every site.
func InferScope(paths []string, texts []string, tags []string) []string {
	set := map[string]bool{}
	for _, p := range paths {
		if len(p) > 2048 {
			p = p[:2048]
		}
		p = strings.ToLower(p)
		if m := wpPluginRe.FindStringSubmatch(p); m != nil && slugRe.MatchString(m[1]) {
			set["wordpress:plugin:"+m[1]] = true
		} else if m := wpThemeRe.FindStringSubmatch(p); m != nil && slugRe.MatchString(m[1]) {
			set["wordpress:theme:"+m[1]] = true
		}
		for _, w := range []string{"/wp-admin/", "/wp-json/", "/wp-login.php", "/xmlrpc.php", "/wp-includes/", "/wp-content/", "wp-cron.php"} {
			if strings.Contains(p, w) {
				set["wordpress"] = true
			}
		}
		switch {
		case strings.Contains(p, "/_next/"):
			set["nextjs"] = true
		case strings.Contains(p, "/actuator"):
			set["spring"] = true
		case strings.Contains(p, "option=com_"):
			set["joomla"] = true
		}
		path := p
		if i := strings.IndexAny(path, "?#"); i >= 0 {
			path = path[:i]
		}
		switch {
		case strings.HasSuffix(path, ".php") || strings.Contains(path, ".php/"):
			set["php"] = true
		case strings.HasSuffix(path, ".jsp") || strings.HasSuffix(path, ".jspx") || strings.HasSuffix(path, ".jsf"):
			set["java"] = true
		case strings.HasSuffix(path, ".aspx") || strings.HasSuffix(path, ".asmx") || strings.HasSuffix(path, ".ashx"):
			set["aspnet"] = true
		}
	}
	weak := map[string]bool{}
	scan := func(t string) {
		if len(t) > 2048 {
			t = t[:2048]
		}
		for _, w := range scopeWords {
			if w.re.MatchString(t) {
				weak[w.scope] = true
			}
		}
	}
	for _, t := range texts {
		scan(t)
	}
	for _, t := range tags {
		scan(t)
	}
	// Words only fill in what the paths left open: a path that says "wordpress:plugin:x" already says wordpress.
	for k := range weak {
		if k == "wordpress" && hasPrefixKey(set, "wordpress:") {
			continue
		}
		set[k] = true
	}
	if hasPrefixKey(set, "wordpress:") {
		delete(set, "wordpress")
	}
	for specific, generic := range impliedBy {
		if set[specific] || hasPrefixKey(set, specific+":") {
			for _, g := range generic {
				delete(set, g)
			}
		}
	}
	// Software named only by an extension is a weak statement; keep it only when nothing better is known.
	out := make([]string, 0, len(set))
	for k := range set {
		if scopeOK(k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

func hasPrefixKey(m map[string]bool, prefix string) bool {
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

var scopeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,100}$`)

func scopeOK(s string) bool { return scopeRe.MatchString(s) }

// ScopeProduct turns a product name from a feed's metadata into a scope, or "" when it is not usable.
func ScopeProduct(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-':
			b.WriteRune(r)
		case r == ' ' || r == '_':
			b.WriteByte('-')
		}
		if b.Len() >= 60 {
			break
		}
	}
	out := strings.Trim(b.String(), "-.")
	if !scopeOK(out) {
		return ""
	}
	return out
}

// MergeScope adds extra scopes to s without duplicates and applies the same bounds as InferScope.
func MergeScope(s []string, extra ...string) []string {
	set := map[string]bool{}
	for _, x := range s {
		set[x] = true
	}
	for _, x := range extra {
		if x != "" && scopeOK(x) {
			set[x] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

// KnownTransforms are the transforms the model defines (see the comment in vpatch/signature.go).
var KnownTransforms = map[string]bool{
	"urldecode1": true, "urldecode": true, "lowercase": true, "normpath": true, "normpathwin": true, "htmldecode": true,
	"jsdecode": true, "cssdecode": true, "utf8unicode": true, "nulls": true, "compressspace": true, "removespace": true,
	"trim": true, "base64decode": true, "comments": true, "replacecomments": true, "cmdline": true,
}

// CondTargets returns a copy of ts with duplicates removed, in first-seen order.
func CondTargets(ts []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range ts {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// NewCondition builds a Condition and copies its slices, so that conditions made from one template never share backing arrays.
func NewCondition(op, pattern string, targets []string, transforms []string) vpatch.Condition {
	c := vpatch.Condition{Operator: op, Pattern: pattern, Targets: append([]string(nil), CondTargets(targets)...)}
	if len(transforms) > 0 {
		c.Transforms = append([]string(nil), transforms...)
	}
	return c
}
