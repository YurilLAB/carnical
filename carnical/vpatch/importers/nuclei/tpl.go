// SPDX-License-Identifier: Apache-2.0

package nuclei

import (
	"regexp"
	"strings"
)

// A nuclei template writes the request an exploit sends, with {{variables}} where the value does not matter or is made up at run time
// ({{randstr}}, {{interactsh-url}}), where the target's address goes ({{BaseURL}}), or where the template's own variables go. A tpl is
// such a string split into its literal and variable parts.
type seg struct {
	lit string // set when the part is plain text
	v   string // set when the part is a {{variable}} or a function call: the text between the braces
}

type tpl []seg

const maxTplBytes = 64 << 10

// parseTpl splits s at each {{ ... }}. An unclosed "{{" is plain text.
func parseTpl(s string) tpl {
	if len(s) > maxTplBytes {
		s = s[:maxTplBytes]
	}
	var out tpl
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			break
		}
		j := strings.Index(s[i+2:], "}}")
		if j < 0 {
			break
		}
		if i > 0 {
			out = append(out, seg{lit: s[:i]})
		}
		out = append(out, seg{v: strings.TrimSpace(s[i+2 : i+2+j])})
		s = s[i+2+j+2:]
	}
	if s != "" {
		out = append(out, seg{lit: s})
	}
	return out
}

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// isOOB says whether a variable is nuclei's out-of-band callback address, which marks a request that makes the target fetch a URL.
func isOOB(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "interactsh-url", "interactsh_url", "oast", "interactsh-id", "interactsh_id", "oob":
		return true
	}
	return false
}

// resolver turns the variables a template defines with a plain value into that value; everything else stays a variable.
type resolver struct {
	vars map[string]string
}

// base variables nuclei fills with the target's address: the signature is about the path, so they vanish.
var addressVars = map[string]bool{"BaseURL": true, "RootURL": true, "Hostname": true, "Host": true, "Port": true, "Scheme": true, "FQDN": true, "Path": true, "File": true, "randstr": false}

// resolve substitutes the template's literal variables (one level, so a variable defined by another stays a variable) and removes
// the address variables.
func (r resolver) resolve(t tpl) tpl {
	var out tpl
	for _, s := range t {
		if s.v == "" {
			out = appendLit(out, s.lit)
			continue
		}
		name := s.v
		if addressVars[name] {
			continue
		}
		if lit, ok := r.vars[name]; ok && identRe.MatchString(name) {
			out = appendLit(out, lit)
			continue
		}
		out = append(out, s)
	}
	return out
}

func appendLit(t tpl, lit string) tpl {
	if lit == "" {
		return t
	}
	if n := len(t); n > 0 && t[n-1].v == "" {
		t[n-1].lit += lit
		return t
	}
	return append(t, seg{lit: lit})
}

// text renders the template with a placeholder where each variable was, for looking at what shape the value has.
func (t tpl) text(placeholder string) string {
	var b strings.Builder
	for _, s := range t {
		if s.v != "" {
			b.WriteString(placeholder)
		} else {
			b.WriteString(s.lit)
		}
	}
	return b.String()
}

// literal returns the text and true when the template has no variables.
func (t tpl) literal() (string, bool) {
	var b strings.Builder
	for _, s := range t {
		if s.v != "" {
			return "", false
		}
		b.WriteString(s.lit)
	}
	return b.String(), true
}

func (t tpl) hasVar() bool {
	for _, s := range t {
		if s.v != "" {
			return true
		}
	}
	return false
}

func (t tpl) hasOOB() bool {
	for _, s := range t {
		if s.v != "" && isOOB(s.v) {
			return true
		}
	}
	return false
}

// splitAt cuts the template at the first occurrence of a byte in its literal parts: the text before, and the text after (without
// the byte). ok is false when the byte does not occur.
func (t tpl) splitAt(c byte) (before, after tpl, ok bool) {
	for i, s := range t {
		if s.v != "" {
			continue
		}
		if k := strings.IndexByte(s.lit, c); k >= 0 {
			before = append(before, t[:i]...)
			if k > 0 {
				before = append(before, seg{lit: s.lit[:k]})
			}
			if k+1 < len(s.lit) {
				after = append(after, seg{lit: s.lit[k+1:]})
			}
			after = append(after, t[i+1:]...)
			return before, after, true
		}
	}
	return t, nil, false
}

// split cuts the template at every occurrence of the byte in its literal parts.
func (t tpl) split(c byte) []tpl {
	var out []tpl
	rest := t
	for {
		b, a, ok := rest.splitAt(c)
		out = append(out, b)
		if !ok {
			return out
		}
		rest = a
	}
}

func (t tpl) hasPrefixLit(p string) bool {
	if len(t) == 0 || t[0].v != "" {
		return false
	}
	return strings.HasPrefix(t[0].lit, p)
}

// trimPrefixLit removes p from the start of the first literal part.
func (t tpl) trimPrefixLit(p string) tpl {
	if !t.hasPrefixLit(p) {
		return t
	}
	out := append(tpl(nil), t...)
	out[0].lit = strings.TrimPrefix(out[0].lit, p)
	if out[0].lit == "" {
		out = out[1:]
	}
	return out
}
