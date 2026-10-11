// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A parameter given more than once is read differently by every framework: PHP keeps the last value, Go and Java the
// first, and ASP.NET hands the application all of them joined with commas (as does a Node application that uses the
// array it was given as a string, and PHP code that implodes a list). An injection can be split over the values so
// that no single one is an attack: q=UNION and q=SELECT password FROM users are two harmless values to a rule and one
// statement to that application. So the rule set is also given, for each repeated name, the joined value. Nothing the
// application receives changes.

// joinedArg is a parameter name and the values it was given, joined with commas in the order they were sent.
type joinedArg struct{ name, value string }

type joinedKey struct{}

// maxJoinSource is how many parameters of the URL, and how many of the body, are looked at. It is the rule set's own
// SecArgumentsLimit (crs/base/coraza.conf): a request with more in either place is refused by rules 200004 and 200005,
// so every parameter of a request that is let through has been looked at here.
const maxJoinSource = 1000

// maxJoined is one more joined value than the rule set takes, so that a request with more is refused by the same rules
// and not passed with some of them unread.
const maxJoined = maxJoinSource + 1

// joinSmall is the number of parameters up to which names are compared pair by pair, which needs no table.
const joinSmall = 16

type joinParam struct{ key, name, value string }

// joinRepeated returns the joined value of every name given more than once in the query string, in a form body (form
// is nil when the body is something else) and in the plain fields of a multipart body, with the cookies of that name
// after them, which is the order ASP.NET's Request.Params joins them in. Names are compared after decoding, without
// regard to case, and the items of one list (ids[], ids[0], ids[1]) count as one name.
//
// A name that only cookies have is left alone, however often it is given. The joined value reaches the rules as a
// parameter, and a session cookie sent twice (which a browser does after a site moved its cookie to another domain or
// path) would be a parameter named like a session id, which the rule set refuses as session fixation; so every name
// joined here is one the rules already had as a parameter.
func joinRepeated(rawQuery string, form []byte, fields []joinParam, cookies []string) []joinedArg {
	// Most requests have no parameters, or one and no cookie, and then nothing can repeat.
	n := len(fields)
	if rawQuery != "" {
		n += min(1+strings.Count(rawQuery, "&"), maxJoinSource)
	}
	if len(form) > 0 {
		n += min(1+bytes.Count(form, []byte{'&'}), maxJoinSource)
	}
	if n == 0 {
		return nil
	}
	for _, c := range cookies {
		n += 1 + strings.Count(c, ";")
	}
	if n < 2 {
		return nil
	}
	params := appendParams(make([]joinParam, 0, n), rawQuery)
	params = appendParams(params, string(form))
	for _, f := range fields {
		if f.name != "" {
			params = append(params, joinParam{joinName(f.name), f.name, f.value})
		}
	}
	own := len(params) // the parameters; what follows is cookies
	for _, c := range cookies {
		for c != "" {
			var pair string
			pair, c, _ = strings.Cut(c, ";")
			if name, value, ok := strings.Cut(strings.TrimSpace(pair), "="); ok && name != "" {
				params = append(params, joinParam{joinName(name), name, value})
			}
		}
	}
	return joinGroups(params, own, len(params) > joinSmall)
}

// readAsForm says whether the rule set will read the body as a form. It goes by the start of the first Content-Type,
// lower-cased and trimmed, and this must go by the same: a type that only one of the two took for a form (one with a
// parameter cut short, which a strict parser refuses) would have its repeated values read apart by the rules and never
// joined here.
func readAsForm(h http.Header) bool {
	v := h.Values("Content-Type")
	return len(v) > 0 && strings.HasPrefix(strings.TrimSpace(strings.ToLower(v[0])), "application/x-www-form-urlencoded")
}

// joinGroups joins the values of the parameters that share a key, in the order the keys first appear. Only a key that
// one of the first own parameters has is joined (the rest are cookies). table chooses between two ways of finding them
// that give the same answer.
func joinGroups(params []joinParam, own int, table bool) []joinedArg {
	if len(params) < 2 {
		return nil
	}
	// next[i] is the following parameter with the key of parameter i, or 0.
	var few [joinSmall]int32
	next := few[:min(len(params), joinSmall)]
	if len(params) > joinSmall {
		next = make([]int32, len(params))
	}
	repeated := false
	if table {
		last := make(map[string]int32, len(params))
		for i := range params {
			if j, ok := last[params[i].key]; ok {
				next[j], repeated = int32(i), true
			}
			last[params[i].key] = int32(i)
		}
	} else {
		for i := range params {
			for j := i + 1; j < len(params); j++ {
				if params[j].key == params[i].key {
					next[i], repeated = int32(j), true
					break
				}
			}
		}
	}
	if !repeated {
		return nil
	}
	var out []joinedArg
	done := make([]bool, len(params))
	for i := range params[:own] {
		if done[i] || next[i] == 0 {
			continue
		}
		var b strings.Builder
		b.WriteString(params[i].value)
		for j := next[i]; j != 0; j = next[j] {
			b.WriteByte(',')
			b.WriteString(params[j].value)
			done[j] = true
		}
		if out = append(out, joinedArg{params[i].name, b.String()}); len(out) == maxJoined {
			break
		}
	}
	return out
}

// appendParams adds the first parameters of a query string or a form body, decoded once. It counts them as the rule
// set's reader does: every pair that is not empty, a name or not.
func appendParams(dst []joinParam, raw string) []joinParam {
	for seen := 0; raw != "" && seen < maxJoinSource; {
		var pair string
		pair, raw, _ = strings.Cut(raw, "&")
		if pair == "" {
			continue
		}
		seen++
		name, value, _ := strings.Cut(pair, "=")
		if name = unescapeParam(name); name != "" {
			dst = append(dst, joinParam{joinName(name), name, unescapeParam(value)})
		}
	}
	return dst
}

// unescapeParam decodes "+" and percent escapes. An escape that is not two hex digits stays as it was written, which is
// what the rule set's own reader does with it.
func unescapeParam(s string) string {
	if strings.IndexByte(s, '%') < 0 && strings.IndexByte(s, '+') < 0 {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			out = append(out, ' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			out = append(out, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// joinName is what two names are compared by: letters folded, and the last index of a list left out, so that ids,
// ids[], ids[0] and IDS[1] are one name. Some applications tell these apart; joining them all the same only gives the
// rules one more value to read.
func joinName(name string) string {
	if strings.HasSuffix(name, "]") {
		if i := strings.LastIndexByte(name, '['); i > 0 && strings.Trim(name[i+1:len(name)-1], "0123456789") == "" {
			name = name[:i]
		}
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c >= utf8.RuneSelf || c >= 'A' && c <= 'Z' {
			return strings.Map(foldRune, name)
		}
	}
	return name
}

// foldRune maps every rune of a simple case-folding orbit to one of them: a lower-case ASCII letter when there is one.
func foldRune(r rune) rune {
	least := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		least = min(least, f)
	}
	if least >= 'A' && least <= 'Z' {
		least += 'a' - 'A'
	}
	return least
}

// multipartFields returns the names and values of the first parts of a multipart body that are not files, for
// joinRepeated. It stops at the first part it cannot read: what the parts hold is checked elsewhere, this only looks
// for repeats.
func multipartFields(body []byte, boundary string) []joinParam {
	if boundary == "" {
		return nil
	}
	var out []joinParam
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for len(out) < maxJoinSource {
		part, err := mr.NextRawPart()
		if err != nil {
			return out
		}
		if part.FileName() != "" {
			continue
		}
		value, err := io.ReadAll(part)
		if err != nil {
			return out
		}
		// A field without a name still counts: the rule set counts it too.
		out = append(out, joinParam{name: part.FormName(), value: string(value)})
	}
	return out
}
