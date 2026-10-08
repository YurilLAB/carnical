// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Everything the guard reads that it did not write itself (a request body, an API description, a saved model) is first turned into
// a small tree of plain values: nil, bool, string, Num, []any and map[string]any. The tree is built by parsers that stop at a depth,
// a node count and a size, so what is built is bounded by what was read, and nothing downstream needs to defend itself against a
// document that is hostile only in its shape.

// Num is a JSON number kept as the text it was written with, so an integer too large for a float64 is still an integer, and a
// number is never rounded before the schema has looked at it.
type Num string

// float returns the value as a float64. ok is false if the text is not a finite number.
func (n Num) float() (f float64, ok bool) {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

// decimal keeps an exact coefficient and power. Exponents are never expanded,
// so time and memory stay proportional to the text, even for huge exponents.
type decimal struct {
	digits   string
	exp      int64
	negative bool
}

func (n Num) decimal() (decimal, bool) {
	s := string(n)
	if !validNumberText(s) {
		return decimal{}, false
	}
	d := decimal{}
	if s[0] == '-' {
		d.negative = true
		s = s[1:]
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		e, err := strconv.ParseInt(s[i+1:], 10, 64)
		if err != nil || e < -1_000_000_000 || e > 1_000_000_000 {
			return decimal{}, false
		}
		d.exp = e
		s = s[:i]
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		d.exp -= int64(len(s) - i - 1)
		s = s[:i] + s[i+1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return decimal{digits: "0"}, true
	}
	d.digits = strings.TrimRight(s, "0")
	d.exp += int64(len(s) - len(d.digits))
	return d, true
}

func (d decimal) cmp(e decimal) int {
	if d == e {
		return 0
	}
	if d.digits == "0" {
		if e.negative {
			return 1
		}
		return -1
	}
	if e.digits == "0" {
		if d.negative {
			return -1
		}
		return 1
	}
	if d.negative != e.negative {
		if d.negative {
			return -1
		}
		return 1
	}
	result := 0
	a, b := int64(len(d.digits))+d.exp, int64(len(e.digits))+e.exp
	if a < b {
		result = -1
	} else if a > b {
		result = 1
	} else {
		for i := 0; i < max(len(d.digits), len(e.digits)); i++ {
			x, y := byte('0'), byte('0')
			if i < len(d.digits) {
				x = d.digits[i]
			}
			if i < len(e.digits) {
				y = e.digits[i]
			}
			if x < y {
				result = -1
				break
			}
			if x > y {
				result = 1
				break
			}
		}
	}
	if d.negative {
		return -result
	}
	return result
}

// multipleOf cancels powers of ten in the divisor, then computes a streaming
// remainder. A float64's shortest decimal coefficient fits in uint64.
func (d decimal) multipleOf(m decimal) bool {
	if m.negative || m.digits == "0" {
		return false
	}
	if d.digits == "0" {
		return true
	}
	delta := d.exp - m.exp
	if delta < 0 {
		return false
	}
	divisor, err := strconv.ParseUint(m.digits, 10, 64)
	if err != nil || divisor > 100_000_000_000_000_000 {
		return false
	}
	for left := delta; left > 0 && divisor%2 == 0; left-- {
		divisor /= 2
	}
	for left := delta; left > 0 && divisor%5 == 0; left-- {
		divisor /= 5
	}
	var remainder uint64
	for i := range d.digits {
		remainder = (remainder*10 + uint64(d.digits[i]-'0')) % divisor
	}
	return remainder == 0
}

func floatDecimal(f float64) (decimal, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return decimal{}, false
	}
	return Num(strconv.FormatFloat(f, 'g', -1, 64)).decimal()
}

// exactFloat refuses constraints that the public float64 fields cannot retain
// as the same decimal number. Import must never silently weaken a bound.
func (n Num) exactFloat() (float64, bool) {
	f, ok := n.float()
	if !ok {
		return 0, false
	}
	d, ok1 := n.decimal()
	e, ok2 := floatDecimal(f)
	return f, ok1 && ok2 && d == e
}

// isInteger reports whether the exact number has no fractional part.
func (n Num) isInteger() bool {
	d, ok := n.decimal()
	return ok && (d.digits == "0" || d.exp >= 0)
}

// int64 returns the value as an int64 if it is an integer that fits.
func (n Num) int64() (int64, bool) {
	d, ok := n.decimal()
	if !ok || d.exp < 0 || int64(len(d.digits))+d.exp > 19 {
		return 0, false
	}
	s := d.digits + strings.Repeat("0", int(d.exp))
	if d.negative {
		s = "-" + s
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil
}

// Limits for a parse. A zero field means "use the package default".
type jsonLimits struct {
	depth int // deepest nesting of arrays and objects
	nodes int // values and object keys in all
}

// Defaults for a request body. A body is already at most 128 KiB when it gets here (the proxy holds it to that), so these are
// generous for any real document and still bound the work for a hostile one.
const (
	bodyDepth = 32
	bodyNodes = 150_000
)

var (
	errSyntax   = errors.New("not valid JSON")
	errTooDeep  = errors.New("nested too deeply")
	errTooMany  = errors.New("too many values")
	errTooLarge = errors.New("too large")
)

type jsonParser struct {
	data  []byte
	pos   int
	nodes int
	lim   jsonLimits
	dup   bool
}

// parseJSON reads exactly one JSON value (RFC 8259: no comments, no trailing commas, no byte order mark, no NaN) and nothing
// after it but white space. dup reports whether any object repeated a key; the later value wins, as in most parsers, and a caller
// that cares can treat the repetition as the sign of an attempt to be read two ways.
func parseJSON(data []byte, lim jsonLimits) (v any, dup bool, err error) {
	if lim.depth <= 0 {
		lim.depth = bodyDepth
	}
	if lim.nodes <= 0 {
		lim.nodes = bodyNodes
	}
	p := &jsonParser{data: data, lim: lim}
	p.skipWS()
	v, err = p.value(0)
	if err != nil {
		return nil, false, err
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, false, errSyntax
	}
	return v, p.dup, nil
}

func (p *jsonParser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsonParser) count() error {
	p.nodes++
	if p.nodes > p.lim.nodes {
		return errTooMany
	}
	return nil
}

func (p *jsonParser) value(depth int) (any, error) {
	if p.pos >= len(p.data) {
		return nil, errSyntax
	}
	if err := p.count(); err != nil {
		return nil, err
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		return p.str()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case c == 't':
		return p.literal("true", true)
	case c == 'f':
		return p.literal("false", false)
	case c == 'n':
		return p.literal("null", nil)
	}
	return nil, errSyntax
}

func (p *jsonParser) literal(word string, v any) (any, error) {
	if len(p.data)-p.pos < len(word) || string(p.data[p.pos:p.pos+len(word)]) != word {
		return nil, errSyntax
	}
	p.pos += len(word)
	return v, nil
}

func (p *jsonParser) number() (any, error) {
	d, i := p.data, p.pos
	start := i
	if d[i] == '-' {
		i++
	}
	if i >= len(d) {
		return nil, errSyntax
	}
	switch {
	case d[i] == '0':
		i++
	case d[i] >= '1' && d[i] <= '9':
		for i < len(d) && d[i] >= '0' && d[i] <= '9' {
			i++
		}
	default:
		return nil, errSyntax
	}
	if i < len(d) && d[i] == '.' {
		i++
		j := i
		for i < len(d) && d[i] >= '0' && d[i] <= '9' {
			i++
		}
		if i == j {
			return nil, errSyntax
		}
	}
	if i < len(d) && (d[i] == 'e' || d[i] == 'E') {
		i++
		if i < len(d) && (d[i] == '+' || d[i] == '-') {
			i++
		}
		j := i
		for i < len(d) && d[i] >= '0' && d[i] <= '9' {
			i++
		}
		if i == j {
			return nil, errSyntax
		}
	}
	p.pos = i
	return Num(d[start:i]), nil
}

func (p *jsonParser) str() (string, error) {
	d := p.data
	i := p.pos + 1
	start := i
	high := false
	for i < len(d) {
		c := d[i]
		switch {
		case c == '"':
			s := d[start:i]
			if high && !utf8.Valid(s) {
				return "", errSyntax
			}
			p.pos = i + 1
			return string(s), nil
		case c == '\\':
			return p.strSlow(start, i)
		case c < 0x20:
			return "", errSyntax
		case c >= 0x80:
			high = true
		}
		i++
	}
	return "", errSyntax
}

// strSlow finishes a string that contains an escape. The part before the first escape has been checked already.
func (p *jsonParser) strSlow(start, i int) (string, error) {
	d := p.data
	var b strings.Builder
	b.Write(d[start:i])
	for i < len(d) {
		c := d[i]
		switch {
		case c == '"':
			p.pos = i + 1
			s := b.String()
			if !utf8.ValidString(s) {
				return "", errSyntax
			}
			return s, nil
		case c == '\\':
			i++
			if i >= len(d) {
				return "", errSyntax
			}
			switch d[i] {
			case '"', '\\', '/':
				b.WriteByte(d[i])
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				r, n, ok := hex4(d, i+1)
				if !ok {
					return "", errSyntax
				}
				i += n
				if r >= 0xD800 && r < 0xDC00 {
					// A high surrogate needs its pair; a lone one becomes the replacement character, as in encoding/json.
					if i+6 < len(d) && d[i+1] == '\\' && d[i+2] == 'u' {
						if r2, _, ok := hex4(d, i+3); ok && r2 >= 0xDC00 && r2 < 0xE000 {
							r = 0x10000 + (r-0xD800)<<10 + (r2 - 0xDC00)
							i += 6
						} else {
							r = utf8.RuneError
						}
					} else {
						r = utf8.RuneError
					}
				} else if r >= 0xDC00 && r < 0xE000 {
					r = utf8.RuneError
				}
				b.WriteRune(r)
			default:
				return "", errSyntax
			}
			i++
		case c < 0x20:
			return "", errSyntax
		default:
			b.WriteByte(c)
			i++
		}
	}
	return "", errSyntax
}

// hex4 reads four hex digits at d[at:]. n is how many bytes the escape took beyond the 'u'.
func hex4(d []byte, at int) (r rune, n int, ok bool) {
	if at+4 > len(d) {
		return 0, 0, false
	}
	for k := 0; k < 4; k++ {
		c := d[at+k]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, 0, false
		}
		r = r<<4 | rune(v)
	}
	return r, 4, true
}

func (p *jsonParser) array(depth int) (any, error) {
	if depth > p.lim.depth {
		return nil, errTooDeep
	}
	p.pos++ // [
	out := []any{}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return out, nil
	}
	for {
		p.skipWS()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, errSyntax
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return out, nil
		default:
			return nil, errSyntax
		}
	}
}

func (p *jsonParser) object(depth int) (any, error) {
	if depth > p.lim.depth {
		return nil, errTooDeep
	}
	p.pos++ // {
	out := map[string]any{}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return out, nil
	}
	for {
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, errSyntax
		}
		if err := p.count(); err != nil {
			return nil, err
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, errSyntax
		}
		p.pos++
		p.skipWS()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		if _, seen := out[k]; seen {
			p.dup = true
		}
		out[k] = v
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, errSyntax
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return out, nil
		default:
			return nil, errSyntax
		}
	}
}

// jtype is the kind of a decoded value.
type jtype uint8

const (
	tNull jtype = iota
	tBool
	tInt // a number with no fractional part
	tNum // any other number
	tStr
	tArr
	tObj
	tNTypes
)

var jtypeNames = [tNTypes]string{"null", "boolean", "integer", "number", "string", "array", "object"}

func typeOf(v any) jtype {
	switch x := v.(type) {
	case nil:
		return tNull
	case bool:
		return tBool
	case Num:
		if x.isInteger() {
			return tInt
		}
		return tNum
	case string:
		return tStr
	case []any:
		return tArr
	case map[string]any:
		return tObj
	}
	return tNull
}

// appendJSON writes a decoded value back as JSON. It is used for the values a schema stores (enum and const), which must survive
// being saved and loaded. Map keys are sorted so the output is stable.
func appendJSON(b []byte, v any, depth int) []byte {
	return appendValueJSON(b, v, depth, false, nil)
}

func appendValueJSON(b []byte, v any, depth int, canonical bool, c *vctx) []byte {
	if c != nil {
		c.steps--
		if c.steps < 0 {
			c.over = true
			return nil
		}
	}
	if depth > 64 {
		return append(b, "null"...)
	}
	switch x := v.(type) {
	case nil:
		return append(b, "null"...)
	case bool:
		return strconv.AppendBool(b, x)
	case Num:
		// A Num read from JSON is already in JSON's grammar, even if it is too large for a float64 (1e999); anything else (a Num made
		// by hand) is written as 0 rather than as text that is not JSON.
		if !validNumberText(string(x)) {
			return append(b, "0"...)
		}
		if canonical {
			if c != nil {
				c.steps -= len(x) / 32
				if c.steps < 0 {
					c.over = true
					return nil
				}
			}
			if d, ok := x.decimal(); ok {
				if d.negative {
					b = append(b, '-')
				}
				b = append(b, d.digits...)
				b = append(b, 'e')
				return strconv.AppendInt(b, d.exp, 10)
			}
			if c != nil {
				c.over = true
				return nil
			}
		}
		return append(b, x...)
	case string:
		return appendQuoted(b, x)
	case []any:
		b = append(b, '[')
		for i, e := range x {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendValueJSON(b, e, depth+1, canonical, c)
		}
		return append(b, ']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		b = append(b, '{')
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendQuoted(b, k)
			b = append(b, ':')
			b = appendValueJSON(b, x[k], depth+1, canonical, c)
		}
		return append(b, '}')
	}
	return append(b, "null"...)
}

func appendQuoted(b []byte, s string) []byte {
	const hexdigits = "0123456789abcdef"
	b = append(b, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\':
				b = append(b, '\\', c)
			case c == '\n':
				b = append(b, '\\', 'n')
			case c == '\r':
				b = append(b, '\\', 'r')
			case c == '\t':
				b = append(b, '\\', 't')
			case c < 0x20 || c == 0x7f:
				b = append(b, '\\', 'u', '0', '0', hexdigits[c>>4], hexdigits[c&0xf])
			default:
				b = append(b, c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b = append(b, `�`...)
		} else {
			b = append(b, s[i:i+size]...)
		}
		i += size
	}
	return append(b, '"')
}

// equalValues compares two decoded values the way JSON Schema does for enum and const: numbers by value, everything else
// structurally.
func equalValues(a, b any, depth int) bool {
	return equalValuesBudget(a, b, depth, nil)
}

func equalValuesBudget(a, b any, depth int, c *vctx) bool {
	if c != nil {
		c.steps--
		if c.steps < 0 {
			c.over = true
			return false
		}
	}
	if depth > 64 {
		return false
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case Num:
		y, ok := b.(Num)
		if !ok {
			return false
		}
		if c != nil {
			c.steps -= (len(x) + len(y)) / 32
			if c.steps < 0 {
				c.over = true
				return false
			}
		}
		if x == y {
			return true
		}
		dx, ok1 := x.decimal()
		dy, ok2 := y.decimal()
		return ok1 && ok2 && dx == dy
	case string:
		y, ok := b.(string)
		if c != nil {
			c.steps -= (len(x) + len(y)) / 32
			if c.steps < 0 {
				c.over = true
				return false
			}
		}
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equalValuesBudget(x[i], y[i], depth+1, c) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, ok := y[k]
			if !ok || !equalValuesBudget(xv, yv, depth+1, c) {
				return false
			}
		}
		return true
	}
	return false
}
