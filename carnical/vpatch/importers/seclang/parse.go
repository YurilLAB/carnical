// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"errors"
	"strings"
)

// directive is one logical line of a SecLang file: the directive name and what follows it.
type directive struct {
	name string
	rest string
	line int
}

// logicalLines joins lines that end in a backslash with the next one, drops comments and blank lines, and returns the rest with
// their line numbers. A rule longer than maxBytes is cut off and reported by the caller through its length.
func logicalLines(text string, maxBytes int) []directive {
	var out []directive
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		start := i + 1
		line := strings.TrimRight(lines[i], "\r")
		var b strings.Builder
		for {
			trimmed := strings.TrimRight(line, " \t")
			if strings.HasSuffix(trimmed, `\`) && i+1 < len(lines) {
				if b.Len() <= maxBytes {
					b.WriteString(strings.TrimSuffix(trimmed, `\`))
				}
				i++
				line = strings.TrimRight(lines[i], "\r")
				// the continuation's leading white space is not part of the rule text
				line = strings.TrimLeft(line, " \t")
				continue
			}
			if b.Len() <= maxBytes {
				b.WriteString(line)
			}
			break
		}
		s := strings.TrimSpace(b.String())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		name, rest, _ := strings.Cut(s, " ")
		if t, r, ok := strings.Cut(s, "\t"); ok && len(t) < len(name) {
			name, rest = t, r
		}
		out = append(out, directive{name: name, rest: strings.TrimSpace(rest), line: start})
	}
	return out
}

var (
	errBadQuote  = errors.New("unterminated-quote")
	errBadArgs   = errors.New("malformed-rule")
	errNoActions = errors.New("no-actions")
)

// splitWords splits the text after SecRule into at most three words: the variables, the operator and the actions. A word that starts
// with a double quote runs to the closing quote; inside it \" is a quote and every other backslash stays, which is what a
// regular expression needs.
func splitWords(s string) ([]string, error) {
	var words []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '"' {
			i++
			var b strings.Builder
			closed := false
			for i < len(s) {
				c := s[i]
				if c == '\\' && i+1 < len(s) && s[i+1] == '"' {
					b.WriteByte('"')
					i += 2
					continue
				}
				if c == '"' {
					closed = true
					i++
					break
				}
				b.WriteByte(c)
				i++
			}
			if !closed {
				return nil, errBadQuote
			}
			words = append(words, b.String())
		} else {
			j := i
			for j < len(s) && s[j] != ' ' && s[j] != '\t' {
				j++
			}
			words = append(words, s[i:j])
			i = j
		}
		if len(words) > 4 {
			return nil, errBadArgs
		}
	}
	return words, nil
}

// action is one entry of an action list: key, or key:value.
type action struct {
	key string
	val string
}

// splitActions splits "id:1,phase:2,msg:'a, b',t:lowercase" on commas outside single quotes. A backslash escapes the next character
// inside quotes.
func splitActions(s string) []action {
	var out []action
	var cur strings.Builder
	inQuote := false
	flush := func() {
		t := strings.TrimSpace(cur.String())
		cur.Reset()
		if t == "" {
			return
		}
		k, v, _ := strings.Cut(t, ":")
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
			v = v[1 : len(v)-1]
		}
		out = append(out, action{key: strings.ToLower(strings.TrimSpace(k)), val: v})
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inQuote && i+1 < len(s):
			cur.WriteByte(s[i+1])
			i++
		case c == '\'':
			inQuote = !inQuote
			cur.WriteByte(c)
		case c == ',' && !inQuote:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// variable is one entry of a rule's variable list.
type variable struct {
	name     string // upper case
	selector string // the text after ":", as written
	negated  bool   // "!NAME": an exclusion
	count    bool   // "&NAME": the number of values
}

// splitVariables reads "ARGS|!ARGS:foo|REQUEST_HEADERS:User-Agent". A "|" inside a /regex/ selector does not split.
func splitVariables(s string) []variable {
	var parts []string
	var cur strings.Builder
	inRe := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '/' && i > 0 && s[i-1] == ':':
			inRe = true
			cur.WriteByte(c)
		case c == '/' && inRe:
			inRe = false
			cur.WriteByte(c)
		case c == '|' && !inRe:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	parts = append(parts, cur.String())
	var out []variable
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v := variable{}
		for len(p) > 0 && (p[0] == '!' || p[0] == '&') {
			if p[0] == '!' {
				v.negated = true
			} else {
				v.count = true
			}
			p = p[1:]
		}
		name, sel, _ := strings.Cut(p, ":")
		v.name = strings.ToUpper(strings.TrimSpace(name))
		v.selector = strings.Trim(strings.TrimSpace(sel), "'")
		out = append(out, v)
	}
	return out
}

// operator is a parsed rule operator.
type operator struct {
	negated bool
	name    string // lower case, without "@"
	arg     string
}

// parseOperator reads "!@rx pattern". With no "@" the whole string is the pattern of @rx, as in ModSecurity.
func parseOperator(s string) operator {
	op := operator{}
	t := strings.TrimLeft(s, " \t")
	if strings.HasPrefix(t, "!") {
		op.negated = true
		t = strings.TrimLeft(t[1:], " \t")
	}
	if strings.HasPrefix(t, "@") {
		name, arg, _ := strings.Cut(t[1:], " ")
		op.name = strings.ToLower(name)
		op.arg = strings.TrimLeft(arg, " \t")
		return op
	}
	op.name = "rx"
	op.arg = t
	return op
}
