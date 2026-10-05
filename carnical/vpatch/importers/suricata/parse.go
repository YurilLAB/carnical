// SPDX-License-Identifier: Apache-2.0

package suricata

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// opt is one option of a rule: key, or key:value.
type opt struct {
	key    string
	val    string
	hasVal bool
}

// rule is a parsed Suricata or Snort rule header and its options, in order.
type rule struct {
	action string
	proto  string
	dir    string
	opts   []opt
}

var (
	errNotRule   = errors.New("not-a-rule")
	errMalformed = errors.New("malformed-rule")
	errTooLong   = errors.New("rule-too-long")
	errTooMany   = errors.New("too-many-options")
)

const maxOptions = 256

var actions = map[string]bool{"alert": true, "drop": true, "reject": true, "pass": true, "rejectsrc": true, "rejectdst": true, "rejectboth": true}

// parseRule splits "alert http $A any -> $B any (opts)" into its header words and options. The addresses and ports are read and
// dropped: a proxy sees one connection from one client, so they say nothing about a request.
func parseRule(line string) (*rule, error) {
	line = strings.TrimSpace(line)
	open := strings.Index(line, "(")
	if open < 0 || !strings.HasSuffix(line, ")") {
		return nil, errNotRule
	}
	words := headerWords(line[:open])
	if len(words) != 7 || !actions[words[0]] || (words[4] != "->" && words[4] != "<>") {
		return nil, errNotRule
	}
	opts, err := splitOptions(line[open+1 : len(line)-1])
	if err != nil {
		return nil, err
	}
	return &rule{action: words[0], proto: strings.ToLower(words[1]), dir: words[4], opts: opts}, nil
}

// headerWords splits the header on white space, keeping a bracketed list such as "[1.1.1.1, 2.2.2.2]" in one word.
func headerWords(s string) []string {
	var words []string
	var cur strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '[':
			depth++
			cur.WriteRune(r)
		case r == ']':
			if depth > 0 {
				depth--
			}
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && depth == 0:
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		words = append(words, cur.String())
	}
	return words
}

// splitOptions splits the text between the parentheses on ";". A ";" inside double quotes, or written "\;", does not split. A
// backslash makes the next character part of the same option, so that \" does not end a quoted string.
func splitOptions(s string) ([]opt, error) {
	var opts []opt
	var cur strings.Builder
	inQuote := false
	flush := func() error {
		t := strings.TrimSpace(cur.String())
		cur.Reset()
		if t == "" {
			return nil
		}
		if len(opts) >= maxOptions {
			return errTooMany
		}
		key, val, has := strings.Cut(t, ":")
		opts = append(opts, opt{key: strings.TrimSpace(key), val: strings.TrimSpace(val), hasVal: has})
		return nil
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(c)
			i++
			cur.WriteByte(s[i])
		case c == '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case c == ';' && !inQuote:
			if err := flush(); err != nil {
				return nil, err
			}
		default:
			cur.WriteByte(c)
		}
	}
	if inQuote {
		return nil, errMalformed
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return opts, nil
}

// quoted reads an option value of the form ["!"] "text" and returns the text between the quotes, still escaped, and whether the
// value was negated.
func quoted(v string) (text string, negated bool, err error) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "!") {
		negated = true
		v = strings.TrimSpace(v[1:])
	}
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", false, errMalformed
	}
	return v[1 : len(v)-1], negated, nil
}

// decodeContent turns the text of a content option into bytes: a run between "|" bars is hexadecimal bytes (white space between
// them is allowed), and outside the bars a backslash makes the next character literal.
func decodeContent(s string) ([]byte, error) {
	var out []byte
	hex := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '|' {
			hex = !hex
			continue
		}
		if hex {
			if c == ' ' || c == '\t' {
				continue
			}
			if i+1 >= len(s) || !isHexDigit(c) || !isHexDigit(s[i+1]) {
				return nil, errMalformed
			}
			v, _ := strconv.ParseUint(s[i:i+2], 16, 8)
			out = append(out, byte(v))
			i++
			continue
		}
		if c == '\\' && i+1 < len(s) {
			n := s[i+1]
			if n == '\\' || n == ';' || n == '"' || n == ':' {
				out = append(out, n)
				i++
				continue
			}
		}
		out = append(out, c)
	}
	if hex {
		return nil, errMalformed
	}
	return out, nil
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// pcreSpec is a parsed pcre option.
type pcreSpec struct {
	pattern string
	flags   string
	negated bool
}

// parsePCRE reads pcre:["!"]"/pattern/flags". The pattern is returned as written: Suricata passes it to PCRE as it is, including
// "\;" and "\"" which PCRE reads as the plain character.
func parsePCRE(v string) (pcreSpec, error) {
	text, neg, err := quoted(v)
	if err != nil {
		return pcreSpec{}, err
	}
	if len(text) < 2 || text[0] != '/' {
		return pcreSpec{}, errMalformed
	}
	end := strings.LastIndexByte(text, '/')
	if end <= 0 {
		return pcreSpec{}, errMalformed
	}
	flags := text[end+1:]
	for _, f := range flags {
		if !(f >= 'a' && f <= 'z' || f >= 'A' && f <= 'Z') {
			return pcreSpec{}, errMalformed
		}
	}
	return pcreSpec{pattern: text[1:end], flags: flags, negated: neg}, nil
}

// asciiLower lower-cases ASCII letters only, which is what Suricata's nocase does.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// intOpt reads a non-negative integer option value such as depth:12 or distance:0.
func intOpt(v string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < -1<<20 || n > 1<<24 {
		return 0, fmt.Errorf("%w: number", errMalformed)
	}
	return n, nil
}

func validText(b []byte) bool { return utf8.Valid(b) }
