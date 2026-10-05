// SPDX-License-Identifier: Apache-2.0

package nuclei

import (
	"regexp"
	"strings"
)

// A nuclei template shows one example payload. A signature that matched only that payload would be useless the day an attacker changes a
// character, so a parameter that carries a payload gets the pattern for the whole class of attack the payload belongs to, and only on that
// parameter of that endpoint, which is why a broad pattern is acceptable here (the CRS applies them everywhere; this applies one to a
// single named argument of a single vulnerable path).
//
// The patterns are RE2, linear in the size of the value, and tested against the payloads of the real templates (see the tests).
type class struct {
	name       string
	category   string
	pattern    string
	transforms []string
	re         *regexp.Regexp
}

// classes in priority order: when a payload fits several, the first wins.
var classes = []*class{
	{name: "jndi", category: "java", transforms: []string{"urldecode"},
		pattern: `\$\{[^}]{0,60}(?:jndi|lower|upper|env|sys|java|date|ctx|bundle|k8s|docker|spring|main|log4j)[^}]{0,60}:`},
	{name: "xxe", category: "xxe", transforms: []string{"urldecode"},
		pattern: `<!ENTITY\s+(?:%\s+)?[^\s>]+\s+(?:SYSTEM|PUBLIC)\b|<!DOCTYPE[^>]{0,300}\[|xmlns:xi\s*=\s*["']http://www\.w3\.org/2001/XInclude`},
	{name: "deserialization", category: "java", transforms: []string{"urldecode"},
		pattern: `\bO:\d+:"[^"]{1,100}":\d+:\{|\ba:\d+:\{|rO0AB|\baced0005|H4sIAAAA`},
	{name: "ssti", category: "ssti", transforms: []string{"urldecode"},
		pattern: `(?:\{\{|\$\{|#\{|<%[=-]?|\{%|\*\{|@\()[^}%>]{0,100}?(?:\b\d{1,4}\s*[*+\-]\s*\d{1,4}\b|__[a-z_]+__|\b(?:config|self|request|lipsum|cycler|joiner|namespace|getclass|runtime|freemarker|execute|exec|system|popen|import|builtins|globals|class|forname|newinstance|getruntime)\b|\bT\s*\()`},
	{name: "command injection", category: "rce", transforms: []string{"urldecode"},
		pattern: `(?:[;|&\x60\n\r]|\$\(|&&|\|\|)\s*(?:id|whoami|uname|cat|ls|dir|pwd|wget|curl|sleep|ping|nslookup|echo|bash|sh|nc|ncat|netcat|python[0-9.]*|perl|php|ruby|powershell|cmd|certutil|busybox|chmod|rm|touch|tftp|ftp|telnet|base64|printf|env|hostname|ifconfig|ipconfig|net\s+user|systeminfo|tasklist|ver)\b|\$\{(?:ifs|[a-z]+:[^}]*)\}|\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|eval|assert|create_function|call_user_func(?:_array)?|file_put_contents|getRuntime|ProcessBuilder|os\.system|subprocess|child_process)\s*\(|\x60[^\x60]{1,200}\x60|\$\([^)]{1,200}\)|/bin/(?:ba|da|z)?sh\b|\bcmd(?:\.exe)?\s+/c\b|<\?(?:php|=)|\bnc\s+-[a-z]*e\b|\bpython[0-9.]*\s+-c\b|\(\)\s*\{[^}]*\}\s*;`},
	{name: "sql injection", category: "sqli", transforms: []string{"urldecode"},
		pattern: `\bunion\b[\s/*+()]+(?:all\b[\s/*+()]+|distinct\b[\s/*+()]+)?select\b|\bselect\b[^;]{1,100}\bfrom\b|\b(?:sleep|benchmark|pg_sleep|extractvalue|updatexml|load_file|group_concat|dbms_pipe\.receive_message|randomblob)\s*\(|\bwaitfor\s+delay\b|\binformation_schema\b|\b(?:or|and)\b\s*[(\s]*(?:['"]?\d+['"]?\s*[=<>]\s*['"]?\d+|['"][^'"]*['"]\s*[=<>]\s*['"])|['"]\s*(?:or|and|union|;)\s|\border\s+by\s+\d+|\bhaving\s+\d|;\s*(?:drop|insert|update|delete|select|exec)\b|'\s*--|--\s*-?\s*$|\b(?:cast|convert|char|chr|ascii|substr|substring|concat|ord|mid)\s*\(`},
	{name: "path traversal", category: "lfi", transforms: []string{"urldecode"},
		pattern: `\.\.[/\\]|\.\.%2f|%2e%2e|%252e|/etc/(?:passwd|shadow|hosts|group|issue|hostname)|/proc/(?:self|version|[0-9]+)/|\b(?:boot|win|system)\.ini\b|[a-z]:[/\\](?:windows|winnt|inetpub)|\b(?:php|file|expect|phar|zip|data|glob|ogg|ssh2|rar|compress\.[a-z]+)://|web-inf|meta-inf|\.htpasswd|\.git/|wp-config|\.env\b`},
	{name: "cross-site scripting", category: "xss", transforms: []string{"urldecode", "htmldecode"},
		pattern: `<\s*/?\s*(?:script|svg|img|iframe|body|details|math|object|embed|video|audio|input|style|marquee|link|meta|base|form|a|button|textarea|select|isindex|frame|frameset)\b|\bjavascript\s*:|\bon(?:abort|blur|change|click|dblclick|error|focus|input|key[a-z]{2,4}|load|mouse[a-z]{2,5}|pointer[a-z]{2,6}|reset|resize|scroll|select|submit|toggle|touch[a-z]{3,5}|begin|start|animation[a-z]{3,6}|transition[a-z]{3,6}|hashchange|message|pageshow|play|drag[a-z]{0,5}|drop|wheel|copy|cut|paste|beforeunload|unload)\s*=|\b(?:alert|prompt|confirm)\s*[(\x60]|\bdocument\s*\.\s*(?:cookie|domain|write|location)`},
	{name: "server-side request forgery", category: "ssrf", transforms: []string{"urldecode"},
		pattern: `^\s*(?:https?|ftp|gopher|dict|ldap|ldaps|file|sftp|tftp|jar|netdoc|rmi)://`},
}

func init() {
	for _, c := range classes {
		c.re = regexp.MustCompile("(?i)" + c.pattern)
	}
}

// internalURL is a URL that points at the server's own side of the network: the shape of a server-side request forgery payload that
// has no callback address in it.
var internalURL = regexp.MustCompile(`(?i)^\s*(?:https?|ftp|gopher|dict|ldap|file)://(?:127\.|localhost|0\.0\.0\.0|\[::1?\]|169\.254\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|metadata)`)

// decodeVariants returns the value as written and after one and two rounds of percent-decoding (templates often write a payload
// percent-encoded), without duplicates.
func decodeVariants(s string) []string {
	out := []string{s}
	cur := s
	for i := 0; i < 2; i++ {
		d := percentDecode(cur)
		if d == cur {
			break
		}
		out = append(out, d)
		cur = d
	}
	return out
}

// percentDecode decodes %XX and turns "+" into a space; a malformed escape is left as it is.
func percentDecode(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			b.WriteByte(' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// classify says which class of attack the example value in a template belongs to, or nil when it is not a payload. oob says the value
// holds the callback address, which is what a request that makes the server fetch a URL carries.
func classify(value string, oob bool) *class {
	if len(value) > 4096 {
		value = value[:4096]
	}
	vs := decodeVariants(value)
	for _, c := range classes {
		if c.name == "server-side request forgery" {
			for _, v := range vs {
				if c.re.MatchString(v) && (oob || internalURL.MatchString(v)) {
					return c
				}
			}
			continue
		}
		for _, v := range vs {
			if c.re.MatchString(v) {
				return c
			}
		}
	}
	return nil
}

// classByName returns the class with the given name.
func classByName(name string) *class {
	for _, c := range classes {
		if c.name == name {
			return c
		}
	}
	return nil
}
