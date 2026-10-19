// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/tidwall/gjson"
)

// jsonIter walks the members of one JSON object or array as gjson's Result.ForEach does, but one member per call, so
// that readItems can keep its place in every container on a stack of its own instead of on the call stack. ForEach
// takes a callback and cannot be resumed, so walking nested containers with it means one level of recursion per level
// of nesting, about 650 bytes of stack each: TinyGo's default 64 KiB stack for WASI overflowed on a body nested about
// 100 deep, well inside SecRequestBodyJsonDepthLimit.
//
// next and the functions below it are gjson v1.20.0's ForEach, parseString, parseAny, parseSquash, parseNumber,
// parseLiteral, unescape and runeit, copied unchanged apart from their names and the dropped Index bookkeeping, so
// that every member, and every malformed body, is read exactly as ForEach reads it. A key carries only the Type, Str
// and Num that readItems reads. FuzzJSONIterMatchesForEach checks
// that against the gjson in go.mod. gjson is licensed as follows:
//
//	The MIT License (MIT)
//
//	Copyright (c) 2016 Josh Baker
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy of
//	this software and associated documentation files (the "Software"), to deal in
//	the Software without restriction, including without limitation the rights to
//	use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
//	the Software, and to permit persons to whom the Software is furnished to do so,
//	subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in all
//	copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
//	FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
//	COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
//	IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
//	CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
type jsonIter struct {
	json    string
	i       int
	keyStr  string        // an object member's key
	keyNum  float64       // an array member's index
	single  *gjson.Result // t is not a container: ForEach calls the iterator once, with an empty key and t
	obj     bool
	yielded bool // a member was returned, so ForEach's loop steps past the byte after it
	done    bool
}

func newJSONIter(t gjson.Result) jsonIter {
	if !t.Exists() {
		return jsonIter{done: true}
	}
	if t.Type != gjson.JSON {
		value := t // only this copy is kept, so a container's t stays off the heap
		return jsonIter{single: &value}
	}
	it := jsonIter{json: t.Raw}
	json := it.json
	for ; it.i < len(json); it.i++ {
		if json[it.i] == '{' {
			it.i++
			it.obj = true
			break
		} else if json[it.i] == '[' {
			it.i++
			it.keyNum = -1
			break
		}
		if json[it.i] > ' ' {
			it.done = true
			break
		}
	}
	return it
}

// next returns the next member, as the next call of ForEach's iterator would receive it, or false at the end.
func (it *jsonIter) next() (key, value gjson.Result, ok bool) {
	if it.done {
		return key, value, false
	}
	if it.single != nil {
		it.done = true
		return gjson.Result{}, *it.single, true
	}
	json := it.json
	i := it.i
	if it.yielded {
		i++
		it.yielded = false
	}
	var str string
	var vesc bool
	for ; i < len(json); i++ {
		if it.obj {
			if json[i] != '"' {
				continue
			}
			i, str, vesc, ok = gjParseString(json, i+1)
			if !ok {
				it.done = true
				return key, value, false
			}
			if vesc {
				it.keyStr = gjUnescape(str[1 : len(str)-1])
			} else {
				it.keyStr = str[1 : len(str)-1]
			}
		} else {
			it.keyNum += 1
		}
		for ; i < len(json); i++ {
			if json[i] <= ' ' || json[i] == ',' || json[i] == ':' {
				continue
			}
			break
		}
		i, value, ok = gjParseAny(json, i, true)
		if !ok {
			it.done = true
			return key, value, false
		}
		it.i, it.yielded = i, true
		if it.obj {
			return gjson.Result{Type: gjson.String, Str: it.keyStr}, value, true
		}
		return gjson.Result{Type: gjson.Number, Num: it.keyNum}, value, true
	}
	it.done = true
	return key, value, false
}

func gjParseString(json string, i int) (int, string, bool, bool) {
	var s = i
	for ; i < len(json); i++ {
		if json[i] > '\\' {
			continue
		}
		if json[i] == '"' {
			return i + 1, json[s-1 : i+1], false, true
		}
		if json[i] == '\\' {
			i++
			for ; i < len(json); i++ {
				if json[i] > '\\' {
					continue
				}
				if json[i] == '"' {
					// look for an escaped slash
					if json[i-1] == '\\' {
						n := 0
						for j := i - 2; j > 0; j-- {
							if json[j] != '\\' {
								break
							}
							n++
						}
						if n%2 == 0 {
							continue
						}
					}
					return i + 1, json[s-1 : i+1], true, true
				}
			}
			break
		}
	}
	return i, json[s-1:], false, false
}

func gjParseAny(json string, i int, hit bool) (int, gjson.Result, bool) {
	var res gjson.Result
	var val string
	for ; i < len(json); i++ {
		if json[i] == '{' || json[i] == '[' {
			i, val = gjParseSquash(json, i)
			if hit {
				res.Raw = val
				res.Type = gjson.JSON
			}
			// gjson sets res.Index here with unsafe; the walk never reads it.
			return i, res, true
		}
		if json[i] <= ' ' {
			continue
		}
		var num bool
		switch json[i] {
		case '"':
			i++
			var vesc bool
			var ok bool
			i, val, vesc, ok = gjParseString(json, i)
			if !ok {
				return i, res, false
			}
			if hit {
				res.Type = gjson.String
				res.Raw = val
				if vesc {
					res.Str = gjUnescape(val[1 : len(val)-1])
				} else {
					res.Str = val[1 : len(val)-1]
				}
			}
			return i, res, true
		case 'n':
			if i+1 < len(json) && json[i+1] != 'u' {
				num = true
				break
			}
			fallthrough
		case 't', 'f':
			vc := json[i]
			i, val = gjParseLiteral(json, i)
			if hit {
				res.Raw = val
				switch vc {
				case 't':
					res.Type = gjson.True
				case 'f':
					res.Type = gjson.False
				}
				return i, res, true
			}
		case '+', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'i', 'I', 'N':
			num = true
		}
		if num {
			i, val = gjParseNumber(json, i)
			if hit {
				res.Raw = val
				res.Type = gjson.Number
				res.Num, _ = strconv.ParseFloat(val, 64)
			}
			return i, res, true
		}

	}
	return i, res, false
}

func gjParseSquash(json string, i int) (int, string) {
	// expects that the lead character is a '[' or '{' or '('
	// squash the value, ignoring all nested arrays and objects.
	// the first '[' or '{' or '(' has already been read
	s := i
	i++
	depth := 1
	var c byte
	for i < len(json) {
		for i < len(json)-8 {
			jslice := json[i : i+8]
			c = gjVchars[jslice[0]]
			if c != 0 {
				i += 0
				goto token
			}
			c = gjVchars[jslice[1]]
			if c != 0 {
				i += 1
				goto token
			}
			c = gjVchars[jslice[2]]
			if c != 0 {
				i += 2
				goto token
			}
			c = gjVchars[jslice[3]]
			if c != 0 {
				i += 3
				goto token
			}
			c = gjVchars[jslice[4]]
			if c != 0 {
				i += 4
				goto token
			}
			c = gjVchars[jslice[5]]
			if c != 0 {
				i += 5
				goto token
			}
			c = gjVchars[jslice[6]]
			if c != 0 {
				i += 6
				goto token
			}
			c = gjVchars[jslice[7]]
			if c != 0 {
				i += 7
				goto token
			}
			i += 8
		}
		c = gjVchars[json[i]]
		if c == 0 {
			i++
			continue
		}
	token:
		if c == 2 {
			// '"' string
			i++
			s2 := i
		nextquote:
			for i < len(json)-8 {
				jslice := json[i : i+8]
				if jslice[0] == '"' {
					i += 0
					goto strchkesc
				}
				if jslice[1] == '"' {
					i += 1
					goto strchkesc
				}
				if jslice[2] == '"' {
					i += 2
					goto strchkesc
				}
				if jslice[3] == '"' {
					i += 3
					goto strchkesc
				}
				if jslice[4] == '"' {
					i += 4
					goto strchkesc
				}
				if jslice[5] == '"' {
					i += 5
					goto strchkesc
				}
				if jslice[6] == '"' {
					i += 6
					goto strchkesc
				}
				if jslice[7] == '"' {
					i += 7
					goto strchkesc
				}
				i += 8
			}
			goto strchkstd
		strchkesc:
			if json[i-1] != '\\' {
				i++
				continue
			}
		strchkstd:
			for i < len(json) {
				if json[i] > '\\' || json[i] != '"' {
					i++
					continue
				}
				// look for an escaped slash
				if json[i-1] == '\\' {
					n := 0
					for j := i - 2; j > s2-1; j-- {
						if json[j] != '\\' {
							break
						}
						n++
					}
					if n%2 == 0 {
						i++
						goto nextquote
					}
				}
				break
			}
		} else {
			// '{', '[', '(', '}', ']', ')'
			// open close tokens
			depth += int(c) - 2
			if depth == 0 {
				i++
				return i, json[s:i]
			}
		}
		i++
	}
	return i, json[s:]
}

var gjVchars = [256]byte{
	'"': 2, '{': 3, '(': 3, '[': 3, '}': 1, ')': 1, ']': 1,
}

func gjParseNumber(json string, i int) (int, string) {
	var s = i
	i++
	for ; i < len(json); i++ {
		if json[i] <= ' ' || json[i] == ',' || json[i] == ']' ||
			json[i] == '}' {
			return i, json[s:i]
		}
	}
	return i, json[s:]
}

func gjParseLiteral(json string, i int) (int, string) {
	var s = i
	i++
	for ; i < len(json); i++ {
		if json[i] < 'a' || json[i] > 'z' {
			return i, json[s:i]
		}
	}
	return i, json[s:]
}

func gjUnescape(json string) string {
	var str = make([]byte, 0, len(json))
	for i := 0; i < len(json); i++ {
		switch {
		default:
			str = append(str, json[i])
		case json[i] < ' ':
			return string(str)
		case json[i] == '\\':
			i++
			if i >= len(json) {
				return string(str)
			}
			switch json[i] {
			default:
				return string(str)
			case '\\':
				str = append(str, '\\')
			case '/':
				str = append(str, '/')
			case 'b':
				str = append(str, '\b')
			case 'f':
				str = append(str, '\f')
			case 'n':
				str = append(str, '\n')
			case 'r':
				str = append(str, '\r')
			case 't':
				str = append(str, '\t')
			case '"':
				str = append(str, '"')
			case 'u':
				if i+5 > len(json) {
					return string(str)
				}
				r := gjRuneit(json[i+1:])
				i += 5
				if utf16.IsSurrogate(r) {
					// need another code
					if len(json[i:]) >= 6 && json[i] == '\\' &&
						json[i+1] == 'u' {
						// we expect it to be correct so just consume it
						r = utf16.DecodeRune(r, gjRuneit(json[i+2:]))
						i += 6
					}
				}
				// provide enough space to encode the largest utf8 possible
				str = append(str, 0, 0, 0, 0, 0, 0, 0, 0)
				n := utf8.EncodeRune(str[len(str)-8:], r)
				str = str[:len(str)-8+n]
				i-- // backtrack index by one
			}
		}
	}
	return string(str)
}

func gjRuneit(json string) rune {
	n, _ := strconv.ParseUint(json[:4], 16, 64)
	return rune(n) // #nosec G115 -- four hex digits are at most 0xFFFF.
}
