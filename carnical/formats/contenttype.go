package formats

import "strings"

// This file reads Content-Type and Content-Disposition values. It is written here and does not use mime.ParseMediaType because
// what a parser accepts, and what it quietly repairs, is the very thing that differs between a firewall and an application: Go's
// accepts a space before a parameter, lower-cases names, takes RFC 2231 continuations and reports some duplicates and not others.
// This one accepts the grammar of RFC 9110 and nothing else, and says which rule an oddity breaks.

const (
	// maxHeaderValueLen bounds a Content-Type or Content-Disposition value. A boundary is at most 70 bytes, so nothing real is near it.
	maxHeaderValueLen = 1024
	// maxParams bounds the parameters in one such value.
	maxParams = 8
)

type param struct{ name, value string }

type mediaType struct {
	typ, sub string
	params   []param
}

func (m *mediaType) param(name string) (string, bool) {
	for _, p := range m.params {
		if p.name == name {
			return p.value, true
		}
	}
	return "", false
}

type pkind uint8

const (
	pkNone pkind = iota
	pkMalformed
	pkDuplicate
)

// problem says what is wrong with a header value: malformed or a duplicated parameter, which detail, and where.
type problem struct {
	kind pkind
	d    detail
	off  int
}

// tchar is a character of a token (RFC 9110 5.6.2).
func tchar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !tchar(s[i]) {
			return false
		}
	}
	return true
}

func scanToken(s string, i int) int {
	for i < len(s) && tchar(s[i]) {
		i++
	}
	return i
}

func skipOWS(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// parseMediaType reads "type/subtype; name=value; ...". The type and subtype are returned in lower case.
func parseMediaType(s string) (mediaType, *problem) {
	var m mediaType
	s = strings.Trim(s, " \t")
	if len(s) > maxHeaderValueLen {
		return m, &problem{pkMalformed, dTooLong, maxHeaderValueLen}
	}
	i := scanToken(s, 0)
	if i == 0 {
		return m, &problem{pkMalformed, dBadMediaType, 0}
	}
	m.typ = strings.ToLower(s[:i])
	if i >= len(s) || s[i] != '/' {
		return m, &problem{pkMalformed, dBadMediaType, i}
	}
	i++
	j := scanToken(s, i)
	if j == i {
		return m, &problem{pkMalformed, dBadMediaType, i}
	}
	m.sub = strings.ToLower(s[i:j])
	params, p := parseParams(s, j, false)
	if p != nil {
		return m, p
	}
	m.params = params
	return m, nil
}

// parseParams reads "; name=value" pairs from offset i to the end of s. Names are returned in lower case. A name that appears twice,
// in any case, is a duplicate. Extended parameters (RFC 2231/5987, "name*=") are allowed only where the caller expects them.
func parseParams(s string, i int, allowExtended bool) ([]param, *problem) {
	var out []param
	for {
		i = skipOWS(s, i)
		if i >= len(s) {
			return out, nil
		}
		if s[i] != ';' {
			return nil, &problem{pkMalformed, dBadParamSyntax, i}
		}
		i = skipOWS(s, i+1)
		if i >= len(s) {
			return out, nil // a trailing ";" is harmless and common
		}
		start := i
		i = scanToken(s, i)
		if i == start {
			return nil, &problem{pkMalformed, dBadParamSyntax, start}
		}
		name := strings.ToLower(s[start:i])
		if strings.IndexByte(name, '*') >= 0 && !allowExtended {
			return nil, &problem{pkMalformed, dExtendedParam, start}
		}
		if i >= len(s) || s[i] != '=' {
			return nil, &problem{pkMalformed, dBadParamSyntax, i}
		}
		i++
		var value string
		if i < len(s) && s[i] == '"' {
			var ok bool
			var d detail
			value, i, d, ok = readQuoted(s, i)
			if !ok {
				return nil, &problem{pkMalformed, d, i}
			}
		} else {
			vs := i
			i = scanToken(s, i)
			if i == vs {
				return nil, &problem{pkMalformed, dBadParamSyntax, vs}
			}
			value = s[vs:i]
		}
		for _, p := range out {
			if p.name == name {
				return nil, &problem{pkDuplicate, dNone, start}
			}
		}
		if len(out) >= maxParams {
			return nil, &problem{pkMalformed, dTooManyParams, start}
		}
		out = append(out, param{name, value})
	}
}

// readQuoted reads a quoted string starting at s[i] == '"' and returns its value with the quoted pairs resolved, and the index
// after the closing quote. Control characters other than a tab are not allowed inside it.
func readQuoted(s string, i int) (value string, next int, d detail, ok bool) {
	start := i + 1
	i = start
	var b []byte
	escaped := false
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\\':
			if i+1 >= len(s) || s[i+1] < 0x20 && s[i+1] != '\t' || s[i+1] == 0x7f {
				return "", i, dBadParamSyntax, false
			}
			if !escaped {
				b = append(b, s[start:i]...)
				escaped = true
			}
			b = append(b, s[i+1])
			i += 2
			continue
		case c == '"':
			if escaped {
				return string(b), i + 1, dNone, true
			}
			return s[start:i], i + 1, dNone, true
		case c < 0x20 && c != '\t', c == 0x7f:
			return "", i, dBadParamSyntax, false
		}
		if escaped {
			b = append(b, c)
		}
		i++
	}
	return "", i, dUnterminatedQuote, false
}

// splitDisposition reads a Content-Disposition value into its type and parameters, where the extended filename* is expected.
func splitDisposition(s string) (typ string, params []param, p *problem) {
	s = strings.Trim(s, " \t")
	if len(s) > maxHeaderValueLen {
		return "", nil, &problem{pkMalformed, dTooLong, maxHeaderValueLen}
	}
	i := scanToken(s, 0)
	if i == 0 {
		return "", nil, &problem{pkMalformed, dBadParamSyntax, 0}
	}
	params, p = parseParams(s, i, true)
	return strings.ToLower(s[:i]), params, p
}
