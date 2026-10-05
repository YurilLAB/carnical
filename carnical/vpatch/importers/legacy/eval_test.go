// SPDX-License-Identifier: Apache-2.0

package legacy

// This file is a small evaluator of vpatch conditions against a sample request, used only by the tests of this package. It is written
// from the descriptions in vpatch/signature.go and is independent of the engine that is built elsewhere: its job is to answer, for the
// library's signature and the converted one, "does this signature match this request?", so that the two answers can be compared. It does
// not have to be a perfect model of the engine; it has to be the same model for both sides.

import (
	"encoding/base64"
	"encoding/json"
	"html"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

type sampleRequest struct {
	Method  string            `json:"method"`
	URI     string            `json:"uri"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Files   []struct {
		Content string `json:"content"`
		Field   string `json:"field"`
		Name    string `json:"name"`
	} `json:"files"`
}

type sampleRow struct {
	Sig     string        `json:"sig"`
	Kind    string        `json:"kind"`
	Request sampleRequest `json:"request"`
}

// ctx is a request taken apart into what the targets name.
type ctx struct {
	req       sampleRequest
	path      string
	query     string
	args      [][2]string // name (lower case), value
	cookies   [][2]string
	headerAll []string
	hdr       map[string][]string
}

func newCtx(r sampleRequest) *ctx {
	c := &ctx{req: r, hdr: map[string][]string{}}
	uri := r.URI
	if i := strings.IndexByte(uri, '#'); i >= 0 {
		uri = uri[:i]
	}
	c.path, c.query, _ = strings.Cut(uri, "?")
	for k, v := range r.Headers {
		k = strings.ToLower(k)
		c.hdr[k] = append(c.hdr[k], v)
		c.headerAll = append(c.headerAll, v)
	}
	sort.Strings(c.headerAll)
	c.args = append(c.args, parseForm(c.query)...)
	ct := strings.ToLower(r.Headers["content-type"])
	switch {
	case strings.Contains(ct, "x-www-form-urlencoded"):
		c.args = append(c.args, parseForm(r.Body)...)
	case strings.Contains(ct, "json"):
		var v any
		if json.Unmarshal([]byte(r.Body), &v) == nil {
			flattenJSON("json", v, &c.args)
		}
	}
	for _, kv := range strings.Split(r.Headers["cookie"], ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		n, v, _ := strings.Cut(kv, "=")
		c.cookies = append(c.cookies, [2]string{strings.ToLower(n), v})
	}
	return c
}

func flattenJSON(prefix string, v any, out *[][2]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			flattenJSON(prefix+"."+strings.ToLower(k), e, out)
		}
	case []any:
		for _, e := range x {
			flattenJSON(prefix, e, out)
		}
	case string:
		*out = append(*out, [2]string{prefix, x})
	case float64:
		*out = append(*out, [2]string{prefix, strconv.FormatFloat(x, 'f', -1, 64)})
	}
}

func parseForm(s string) [][2]string {
	var out [][2]string
	for _, part := range strings.Split(s, "&") {
		if part == "" {
			continue
		}
		n, v, _ := strings.Cut(part, "=")
		out = append(out, [2]string{strings.ToLower(formDecode(n)), formDecode(v)})
	}
	return out
}

func formDecode(s string) string {
	d, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return d
}

// values lists what a target holds for this request.
func (c *ctx) values(target string) []string {
	switch {
	case target == vpatch.TargetURI:
		return []string{c.req.URI}
	case target == vpatch.TargetPath:
		return []string{c.path}
	case target == vpatch.TargetQuery:
		return []string{c.query}
	case target == vpatch.TargetMethod:
		return []string{c.req.Method}
	case target == vpatch.TargetBody:
		return []string{c.req.Body}
	case target == vpatch.TargetArgs:
		var out []string
		for _, a := range c.args {
			out = append(out, a[1])
		}
		return out
	case target == vpatch.TargetArgNames:
		var out []string
		for _, a := range c.args {
			out = append(out, a[0])
		}
		return out
	case target == vpatch.TargetCookies:
		var out []string
		for _, a := range c.cookies {
			out = append(out, a[1])
		}
		return out
	case target == vpatch.TargetCookieNames:
		var out []string
		for _, a := range c.cookies {
			out = append(out, a[0])
		}
		return out
	case target == vpatch.TargetHeaders:
		return c.headerAll
	case target == vpatch.TargetFilenames:
		var out []string
		for _, f := range c.req.Files {
			out = append(out, f.Name)
		}
		return out
	case target == vpatch.TargetUploads:
		var out []string
		for _, f := range c.req.Files {
			out = append(out, f.Content)
		}
		return out
	case strings.HasPrefix(target, "header:"):
		return c.hdr[strings.ToLower(target[7:])]
	case strings.HasPrefix(target, "arg:"):
		var out []string
		for _, a := range c.args {
			if a[0] == strings.ToLower(target[4:]) {
				out = append(out, a[1])
			}
		}
		return out
	case strings.HasPrefix(target, "cookie:"):
		var out []string
		for _, a := range c.cookies {
			if a[0] == strings.ToLower(target[7:]) {
				out = append(out, a[1])
			}
		}
		return out
	}
	return nil
}

func percentDecodeOnce(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

var (
	cssEscapeRe    = regexp.MustCompile(`\\([0-9a-fA-F]{1,6}) ?`)
	jsEscapeRe     = regexp.MustCompile(`\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))`)
	blockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineCommentRe  = regexp.MustCompile(`--[^\n]*`)
	spaceRunRe     = regexp.MustCompile(`\s+`)
)

func applyTransform(v, name string) string {
	switch name {
	case "urldecode1":
		return percentDecodeOnce(v)
	case "urldecode":
		for i := 0; i < 3; i++ {
			d := percentDecodeOnce(v)
			if d == v {
				break
			}
			v = d
		}
		return v
	case "lowercase":
		b := []byte(v)
		for i, ch := range b {
			if ch >= 'A' && ch <= 'Z' {
				b[i] = ch + 32
			}
		}
		return string(b)
	case "normpath", "normpathwin":
		if name == "normpathwin" {
			v = strings.ReplaceAll(v, `\`, "/")
		}
		if v == "" {
			return v
		}
		trail := strings.HasSuffix(v, "/")
		out := path.Clean(v)
		if trail && !strings.HasSuffix(out, "/") {
			out += "/"
		}
		return out
	case "htmldecode":
		return html.UnescapeString(v)
	case "jsdecode":
		return jsEscapeRe.ReplaceAllStringFunc(v, func(m string) string {
			hex := m[2:]
			n, _ := strconv.ParseUint(hex, 16, 32)
			return string(rune(n))
		})
	case "cssdecode":
		return cssEscapeRe.ReplaceAllStringFunc(v, func(m string) string {
			hex := strings.TrimSpace(m[1:])
			n, _ := strconv.ParseUint(hex, 16, 32)
			return string(rune(n))
		})
	case "nulls":
		return strings.ReplaceAll(v, "\x00", "")
	case "compressspace":
		return spaceRunRe.ReplaceAllString(v, " ")
	case "removespace":
		return spaceRunRe.ReplaceAllString(v, "")
	case "trim":
		return strings.TrimSpace(v)
	case "base64decode":
		if d, err := base64.StdEncoding.DecodeString(v); err == nil {
			return string(d)
		}
		return v
	case "comments":
		return lineCommentRe.ReplaceAllString(blockCommentRe.ReplaceAllString(v, ""), "")
	case "replacecomments":
		return blockCommentRe.ReplaceAllString(v, " ")
	case "cmdline":
		r := strings.NewReplacer(`\`, "", `"`, "", "'", "", "^", "", ",", " ", ";", " ")
		return strings.ToLower(spaceRunRe.ReplaceAllString(r.Replace(v), " "))
	}
	return v
}

var rxCache = map[string]*regexp.Regexp{}

func flagPrefix(flags string) string {
	pre := ""
	for _, f := range flags {
		if f == 'i' || f == 's' || f == 'm' {
			pre += string(f)
		}
	}
	if pre != "" {
		pre = "(?" + pre + ")"
	}
	return pre
}

// compileRx compiles a pattern; a possessive quantifier or atomic group that provably changes nothing is translated first, as the
// importers do. nil means Go cannot read the pattern.
func compileRx(pattern, flags string) *regexp.Regexp {
	pre := flagPrefix(flags)
	if re, err := regexp.Compile(pre + pattern); err == nil {
		return re
	}
	if t, err := importers.TranslatePCRE(pattern); err == nil && t != pattern {
		if re, err := regexp.Compile(pre + t); err == nil {
			return re
		}
	}
	return nil
}

// rx compiles a condition's pattern the way the model says (flags are an inline group in front). A pattern Go cannot compile returns nil.
func rx(c vpatch.Condition) *regexp.Regexp {
	key := c.Flags + "|" + c.Pattern
	if re, ok := rxCache[key]; ok {
		return re
	}
	re := compileRx(c.Pattern, c.Flags)
	rxCache[key] = re
	return re
}

// splitLookaheads reads a pattern of the form ^(?=A)(?=B)REST, which Go cannot compile, as the separate regular expressions A, B and
// REST, each of which must match at the start of the value. It returns nil when the pattern is not of that form or a part does not
// compile.
func splitLookaheads(c vpatch.Condition) []*regexp.Regexp {
	p := c.Pattern
	switch {
	case strings.HasPrefix(p, "^"):
		p = p[1:]
	case strings.HasPrefix(p, "\\A"):
		p = p[2:]
	default:
		return nil
	}
	var parts []*regexp.Regexp
	for strings.HasPrefix(p, "(?=") {
		depth, i := 0, 0
		for ; i < len(p); i++ {
			ch := p[i]
			if ch == '\\' {
				i++
				continue
			}
			if ch == '(' {
				depth++
			}
			if ch == ')' {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		if i >= len(p) {
			return nil
		}
		re := compileRx("\\A(?:"+p[3:i]+")", c.Flags)
		if re == nil {
			return nil
		}
		parts = append(parts, re)
		p = p[i+1:]
	}
	if len(parts) == 0 {
		return nil
	}
	if p != "" {
		re := compileRx("\\A(?:"+p+")", c.Flags)
		if re == nil {
			return nil
		}
		parts = append(parts, re)
	}
	return parts
}

// evalCond reports whether a condition holds for the request. ok is false when the condition cannot be evaluated here (a regular
// expression Go cannot compile).
func evalCond(c vpatch.Condition, x *ctx) (holds, ok bool) {
	if c.Operator == vpatch.OpRegex && rx(c) == nil {
		// The library writes "all of these appear" as a chain of lookaheads, which Go cannot compile. Read it as the conjunction it is.
		if lookaheadLits(c) != nil {
			return evalLookahead(c, x)
		}
		if parts := splitLookaheads(c); parts != nil {
			return evalSplit(c, parts, x)
		}
		return false, false
	}
	var any bool
	for _, t := range c.Targets {
		for _, v := range x.values(t) {
			for _, tf := range c.Transforms {
				v = applyTransform(v, tf)
			}
			if matchOne(c, v) {
				any = true
			}
		}
	}
	if c.Negate {
		return !any, true
	}
	return any, true
}

// evalSplit evaluates a lookahead pattern as the conjunction of its parts, all on the same value.
func evalSplit(c vpatch.Condition, parts []*regexp.Regexp, x *ctx) (bool, bool) {
	var any bool
	for _, t := range c.Targets {
		for _, v := range x.values(t) {
			for _, tf := range c.Transforms {
				v = applyTransform(v, tf)
			}
			all := true
			for _, re := range parts {
				if !re.MatchString(v) {
					all = false
				}
			}
			if all {
				any = true
			}
		}
	}
	if c.Negate {
		return !any, true
	}
	return any, true
}

func evalLookahead(c vpatch.Condition, x *ctx) (bool, bool) {
	lits := lookaheadLits(c)
	if lits == nil {
		return false, false
	}
	var values []string
	for _, t := range c.Targets {
		for _, v := range x.values(t) {
			for _, tf := range c.Transforms {
				v = applyTransform(v, tf)
			}
			values = append(values, v)
		}
	}
	all := len(values) > 0
	for _, l := range lits {
		found := false
		for _, v := range values {
			hay, needle := v, l.text
			if l.ci {
				hay, needle = strings.ToLower(hay), strings.ToLower(needle)
			}
			if strings.Contains(hay, needle) {
				found = true
			}
		}
		if !found {
			all = false
		}
	}
	if c.Negate {
		return !all, true
	}
	return all, true
}

func matchOne(c vpatch.Condition, v string) bool {
	switch c.Operator {
	case vpatch.OpRegex:
		return rx(c).MatchString(v)
	case vpatch.OpContains:
		return strings.Contains(v, c.Pattern)
	case vpatch.OpPrefix:
		return strings.HasPrefix(v, c.Pattern)
	case vpatch.OpSuffix:
		return strings.HasSuffix(v, c.Pattern)
	case vpatch.OpEquals:
		return v == c.Pattern
	case vpatch.OpPM:
		words := c.Patterns
		if len(words) == 0 {
			words = strings.Fields(c.Pattern)
		}
		hay := v
		fold := strings.Contains(c.Flags, "i")
		if fold {
			hay = strings.ToLower(hay)
		}
		for _, w := range words {
			if fold {
				w = strings.ToLower(w)
			}
			if strings.Contains(hay, w) {
				return true
			}
		}
	}
	return false
}

// evalSig reports whether every condition of the signature holds. ok is false if one could not be evaluated.
func evalSig(s vpatch.Signature, x *ctx) (match, ok bool) {
	match = true
	ok = true
	for _, c := range append([]vpatch.Condition{s.Condition}, s.Also...) {
		h, k := evalCond(c, x)
		if !k {
			ok = false
			continue
		}
		if !h {
			match = false
		}
	}
	if !ok {
		return false, false
	}
	return match, true
}
