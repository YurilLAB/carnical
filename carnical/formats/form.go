// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package formats

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// application/x-www-form-urlencoded. A browser writes only unreserved characters, "%XX" and "+", separates with "&", and encodes
// every ";", "=", "[" and control character. A body that does anything else was not written by a browser, and the places where
// frameworks read it differently (a semicolon as a separator, "%zz" kept or dropped, duplicates joined or last-wins, "a[b][c]"
// turned into nested objects, "__proto__" as a key) are where a parameter is hidden from a filter.

// gqlParams collects, from a form body or a query string, the parameters a GraphQL request is made of.
type gqlParams struct {
	query, variables, operationName, extensions string
	hasQuery, hasVars, hasOp, hasExt            bool
	duplicate, looksGQL                         bool
}

func (g *gqlParams) set(name, value string) {
	switch name {
	case "query":
		if g.hasQuery {
			g.duplicate = true
		}
		g.query, g.hasQuery = value, true
		g.looksGQL = g.looksGQL || looksLikeGraphQL([]byte(value))
	case "variables":
		g.duplicate = g.duplicate || g.hasVars
		g.variables, g.hasVars = value, true
	case "operationName":
		g.duplicate = g.duplicate || g.hasOp
		g.operationName, g.hasOp = value, true
	case "extensions":
		g.duplicate = g.duplicate || g.hasExt
		g.extensions, g.hasExt = value, true
	}
}

type formScanner struct {
	f       *finder
	lim     *FormLimits
	utf8    bool
	capture *gqlParams
	name    []byte
	val     []byte
	seen    map[string]struct{}
	fold    []byte
	dup     bool
	semi    bool
}

// checkForm checks a urlencoded body. utf8 says whether decoded names and values must be UTF-8 (they need not be when the
// Content-Type names a single-byte charset). It returns false when the caller should stop.
func (in *Inspector) checkForm(f *finder, body []byte, utf8 bool, capture *gqlParams) bool {
	fs := &formScanner{f: f, lim: &in.pol.Form, utf8: utf8, capture: capture, dup: f.active(rFormDup)}
	if fs.dup {
		fs.seen = make(map[string]struct{})
	}
	params := 0
	pos := 0
	for pos < len(body) {
		end := bytes.IndexByte(body[pos:], '&')
		if end < 0 {
			end = len(body)
		} else {
			end += pos
		}
		pair, at := body[pos:end], pos
		pos = end + 1
		if len(pair) == 0 {
			continue
		}
		params++
		if params > fs.lim.MaxParams {
			f.hitLimit(rFormLimit, dTooManyParams, fs.lim.MaxParams, at)
			return false
		}
		if !fs.pair(pair, at) {
			return false
		}
	}
	return true
}

func (fs *formScanner) pair(pair []byte, at int) bool {
	nameRaw, valRaw, hasVal := pair, []byte(nil), false
	if eq := bytes.IndexByte(pair, '='); eq >= 0 {
		nameRaw, valRaw, hasVal = pair[:eq], pair[eq+1:], true
	}
	var ok bool
	if fs.name, ok = fs.decode(fs.name[:0], nameRaw, at, true); !ok {
		return false
	}
	if hasVal {
		if fs.val, ok = fs.decode(fs.val[:0], valRaw, at+len(nameRaw)+1, false); !ok {
			return false
		}
	} else {
		fs.val = fs.val[:0]
	}
	f, lim := fs.f, fs.lim
	if len(fs.name) > lim.MaxNameLen {
		f.hitLimit(rFormLimit, dNameTooLong, lim.MaxNameLen, at)
		return false
	}
	if len(fs.val) > lim.MaxValueLen {
		f.hitLimit(rFormLimit, dValueTooLong, lim.MaxValueLen, at)
		return false
	}
	if fs.utf8 && (!utf8.Valid(fs.name) || !utf8.Valid(fs.val)) {
		if f.hit(rInvalidUTF8, at, dNone) {
			return false
		}
	}
	if bytes.IndexByte(fs.name, '[') >= 0 {
		if n := bytes.Count(fs.name, []byte{'['}); n > lim.MaxBracketDepth {
			if f.hitLimit(rFormBrkt, dNone, lim.MaxBracketDepth, at) {
				return false
			}
		}
	}
	if protoName(fs.name) && f.hit(rFormProto, at, dNone) {
		return false
	}
	if fs.dup && !bytes.HasSuffix(fs.name, []byte("[]")) {
		fs.fold = appendFolded(fs.fold[:0], fs.name, false)
		if _, seen := fs.seen[string(fs.fold)]; seen {
			if f.hit(rFormDup, at, dNone) {
				return false
			}
		} else {
			fs.seen[string(fs.fold)] = struct{}{}
		}
	}
	if fs.capture != nil && (string(fs.name) == "query" || string(fs.name) == "variables" || string(fs.name) == "operationName" || string(fs.name) == "extensions") {
		fs.capture.set(string(fs.name), string(fs.val))
	}
	return true
}

// decode appends the percent-decoded form of src to dst. at is the offset of src in the body, for positions. It reports a
// semicolon, a raw control byte, an escape that is not "%" and two hex digits, and an escaped NUL or control character. Names may
// hold no control character at all; values may hold tab, line feed and carriage return (a textarea sends them as %09, %0A, %0D).
func (fs *formScanner) decode(dst, src []byte, at int, isName bool) ([]byte, bool) {
	f := fs.f
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '+':
			dst = append(dst, ' ')
		case c == '%':
			if i+2 >= len(src) {
				if f.hit(rFormEscape, at+i, dTruncatedEscape) {
					return dst, false
				}
				dst = append(dst, c)
				continue
			}
			if !isHexDigit(src[i+1]) || !isHexDigit(src[i+2]) {
				if f.hit(rFormEscape, at+i, dBadHexEscape) {
					return dst, false
				}
				dst = append(dst, c)
				continue
			}
			b := byte(hexVal(src[i+1])<<4 | hexVal(src[i+2]))
			if isFormControl(b, isName) && f.hit(rFormCtl, at+i, dEscapedControl) {
				return dst, false
			}
			dst = append(dst, b)
			i += 2
		case c == ';':
			if f.hit(rFormSemi, at+i, dNone) {
				return dst, false
			}
			dst = append(dst, c)
		case c < 0x20 || c == 0x7f:
			if f.hit(rFormCtl, at+i, dRawControl) {
				return dst, false
			}
			dst = append(dst, c)
		default:
			dst = append(dst, c)
		}
	}
	return dst, true
}

// isFormControl reports whether a decoded byte is one a form may not carry.
func isFormControl(b byte, isName bool) bool {
	if b == 0x7f || b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
		return true
	}
	return isName && b < 0x20
}

// protoName reports whether a parameter name reaches the prototype of an object in the parsers that turn "a[b].c" into nested
// objects (qs, PHP, Rails, Express): a segment "__proto__", or a segment "constructor" followed by "prototype".
func protoName(name []byte) bool {
	if bytes.IndexAny(name, "pP") < 0 {
		return false // the cheap test first: most names have no p at all
	}
	lower := bytes.ToLower(name)
	if !bytes.Contains(lower, []byte("proto")) {
		return false
	}
	prevCtor := false
	segs := bytes.FieldsFunc(lower, func(r rune) bool { return r == '[' || r == ']' || r == '.' })
	for _, seg := range segs {
		s := string(seg)
		if s == "__proto__" || prevCtor && s == "prototype" {
			return true
		}
		prevCtor = s == "constructor"
	}
	return false
}

// unescapeQuery decodes a query string component the way a form value is decoded. It reports false for an escape that is not
// "%" and two hex digits.
func unescapeQuery(s string) (string, bool) {
	if strings.IndexByte(s, '%') < 0 && strings.IndexByte(s, '+') < 0 {
		return s, true
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			out = append(out, ' ')
		case c == '%':
			if i+2 >= len(s) || !isHexDigit(s[i+1]) || !isHexDigit(s[i+2]) {
				return "", false
			}
			out = append(out, byte(hexVal(s[i+1])<<4|hexVal(s[i+2])))
			i += 2
		default:
			out = append(out, c)
		}
	}
	return string(out), true
}
