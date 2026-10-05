// SPDX-License-Identifier: Apache-2.0

package suricata

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

var methodTokens = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "HEAD": true, "OPTIONS": true, "PATCH": true, "TRACE": true, "CONNECT": true,
	"PROPFIND": true, "PROPPATCH": true, "MKCOL": true, "COPY": true, "MOVE": true, "LOCK": true, "UNLOCK": true, "SEARCH": true,
}

// groupConds turns the matches in one buffer into conditions.
//
// Matches that follow one another with distance, within or the pcre flag R are one condition, a regular expression that keeps their
// order and the size of the gaps: "there is a match of the first, and after it a match of the next". That is what Suricata's
// relative matching asks for. A match that is relative to a pcre before it cannot be joined that way (Suricata looks only at the
// first match of a pcre and a regular expression looks at all), so it stands alone and the ordering is reported as a dropped
// constraint. Matches with no relative modifier are independent in Suricata too, so each is its own condition.
func (c *cvt) groupConds(g *group) ([]vpatch.Condition, error) {
	spec := buffers[g.buf]
	if spec.header {
		return c.headerConds(g)
	}
	xf := append(append([]string(nil), spec.base...), g.xforms...)
	var out []vpatch.Condition
	var seg []*atom
	flush := func() error {
		if len(seg) == 0 {
			return nil
		}
		cond, err := c.segmentCond(spec, xf, seg)
		seg = nil
		if err != nil {
			return err
		}
		out = append(out, cond)
		return nil
	}
	for i, a := range g.atoms {
		if a.negated {
			if a.relative() {
				return nil, skip("negated-relative-content")
			}
			if err := flush(); err != nil {
				return nil, err
			}
			cond, err := c.segmentCond(spec, xf, []*atom{a})
			if err != nil {
				return nil, err
			}
			// Suricata does not look in a buffer the request does not have, so "not this" needs "has one" beside it.
			if guard, ok := importers.ExistsGuard(spec.targets); ok {
				out = append(out, guard)
			}
			out = append(out, cond)
			continue
		}
		if a.relative() && len(seg) > 0 {
			switch {
			case seg[len(seg)-1].isPCRE:
				c.drop("relative-after-pcre-order")
			case a.isPCRE:
				if _, _, ok := relativeStart(a); !ok {
					c.drop("relative-pcre-order")
				} else {
					seg = append(seg, a)
					continue
				}
			default:
				seg = append(seg, a)
				continue
			}
		} else if a.relative() && i > 0 {
			c.drop("relative-after-negated-order") // the match it was relative to is a negated one, or in another section
		}
		if err := flush(); err != nil {
			return nil, err
		}
		seg = []*atom{a}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

// segmentCond makes one condition from a run of matches (a single one, or several joined by relative modifiers).
func (c *cvt) segmentCond(spec bufSpec, xf []string, seg []*atom) (vpatch.Condition, error) {
	if len(seg) == 1 && seg[0].isPCRE {
		return c.pcreCond(spec, xf, seg[0])
	}
	return c.contentCond(spec, xf, seg)
}

func (c *cvt) noteLiteral(spec bufSpec, s string) {
	for _, t := range spec.targets {
		if t == vpatch.TargetURI && len(c.uriLits) < 16 {
			c.uriLits = append(c.uriLits, s)
			return
		}
	}
}

// contentCond makes one condition from a run of contents (a single one, or several joined by distance/within).
func (c *cvt) contentCond(spec bufSpec, xf []string, seg []*atom) (vpatch.Condition, error) {
	first := seg[0]
	simple := len(seg) == 1 && !first.hasDepth && !first.hasOffset
	if simple {
		s := string(first.data)
		c.noteLiteral(spec, s)
		op := vpatch.OpContains
		switch {
		case first.startswith && first.endswith:
			op = vpatch.OpEquals
		case first.startswith:
			op = vpatch.OpPrefix
		case first.endswith:
			op = vpatch.OpSuffix
		case len(spec.targets) == 1 && spec.targets[0] == vpatch.TargetMethod && methodTokens[strings.ToUpper(s)] && !first.nocase && s == strings.ToUpper(s):
			op = vpatch.OpEquals
		}
		tf := xf
		if first.nocase {
			s = asciiLower(s)
			tf = append(append([]string(nil), xf...), "lowercase")
		}
		cond := importers.NewCondition(op, s, spec.targets, tf)
		cond.Negate = first.negated
		return cond, nil
	}

	var b strings.Builder
	// where the first one may start
	switch {
	case first.startswith:
		b.WriteString(`\A`)
	case first.hasDepth || first.hasOffset:
		off := 0
		if first.hasOffset {
			off = first.offset
		}
		if off < 0 {
			return vpatch.Condition{}, skip("negative-offset")
		}
		b.WriteString(`\A`)
		var skipped string
		var ok bool
		if first.hasDepth {
			if first.depth < len(first.data) {
				return vpatch.Condition{}, skip("depth-shorter-than-content")
			}
			skipped, ok = dot(off, off+first.depth-len(first.data))
		} else {
			skipped, ok = dot(off, -1)
			if off == 0 {
				skipped = ""
			}
		}
		if !ok {
			return vpatch.Condition{}, skip("gap-too-large")
		}
		b.WriteString(skipped)
	}
	for k, a := range seg {
		pieceBody := ""
		if k > 0 && a.isPCRE {
			// A pcre relative to the match before it is run on the text that follows that match, so its "^" means "right there"
			// and it may start anywhere after unless it is anchored.
			body, anchored, _ := relativeStart(a)
			pieceBody = body
			if !anchored {
				b.WriteString(`(?s:.)*`)
			}
		} else if k > 0 {
			d := 0
			if a.hasDist {
				d = a.distance
			}
			if d < 0 {
				return vpatch.Condition{}, skip("negative-distance")
			}
			maxGap := -1
			if a.hasWithin {
				// within is counted from where the search starts, which is distance bytes after the previous match: the rules'
				// own usage shows it ("distance:1; within:2" for a two-byte content that starts one byte after the previous one).
				maxGap = d + a.within - len(a.data)
				if maxGap < d {
					return vpatch.Condition{}, skip("within-shorter-than-content")
				}
			}
			g, ok := dot(d, maxGap)
			if !ok {
				return vpatch.Condition{}, skip("gap-too-large")
			}
			b.WriteString(g)
		}
		if a.isPCRE {
			b.WriteString(pcrePiece(a, pieceBody))
			c.noteLiteral(spec, a.pcre.pattern)
			continue
		}
		piece := regexp.QuoteMeta(string(a.data))
		if a.nocase {
			piece = "(?i:" + piece + ")"
		}
		b.WriteString(piece)
		c.noteLiteral(spec, string(a.data))
	}
	if !seg[len(seg)-1].isPCRE && seg[len(seg)-1].endswith {
		b.WriteString(`\z`)
	}
	pat, err := c.rep.CheckRegex(b.String(), "", c.lim.MaxPatternBytes)
	if err != nil {
		return vpatch.Condition{}, err
	}
	return importers.NewCondition(vpatch.OpRegex, pat, spec.targets, xf), nil
}

// relativeStart prepares a pcre that is relative to the match before it (flag R) to follow that match inside one regular expression.
// Suricata runs it on the text after the previous match, so a leading "^" or \A, or the A flag, anchors it right after that match; the
// chain says that by leaving out the gap and the anchor. A pcre that starts with a word boundary (which would see the previous match's last
// character here and the start of the text there), that has "^" under the multi-line flag, or that has an anchor anywhere but at its
// start, cannot be joined: ok is false.
func relativeStart(a *atom) (body string, anchored, ok bool) {
	p := a.pcre.pattern
	anchored = strings.Contains(a.pcre.flags, "A")
	switch {
	case strings.HasPrefix(p, "^"):
		if strings.Contains(a.pcre.flags, "m") {
			return "", false, false
		}
		anchored, p = true, p[1:]
	case strings.HasPrefix(p, `\A`):
		anchored, p = true, p[2:]
	case strings.HasPrefix(p, `\b`), strings.HasPrefix(p, `\B`), strings.HasPrefix(p, `\G`), strings.HasPrefix(p, `\Z`):
		return "", false, false
	}
	if hasInnerAnchor(p) {
		return "", false, false
	}
	if p == "" {
		return "", false, false
	}
	return p, anchored, true
}

// hasInnerAnchor reports whether a pattern has "^" or \A outside a character class.
func hasInnerAnchor(p string) bool {
	inClass := false
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == '\\':
			if !inClass && i+1 < len(p) && (p[i+1] == 'A' || p[i+1] == 'G') {
				return true
			}
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
			if i+1 < len(p) && p[i+1] == '^' {
				i++
			}
			if i+1 < len(p) && p[i+1] == ']' {
				i++
			}
		case c == '^':
			return true
		}
	}
	return false
}

// pcrePiece is a pcre written so that it can sit inside a longer regular expression: its own flags scoped to it.
func pcrePiece(a *atom, body string) string {
	inline := ""
	for _, f := range a.pcre.flags {
		if f == 'i' || f == 's' || f == 'm' {
			inline += string(f)
		}
	}
	if body == "" {
		body = a.pcre.pattern
	}
	if inline == "" {
		return "(?:" + body + ")"
	}
	return "(?" + inline + ":" + body + ")"
}

// dot is "any character, min to max times" (max < 0 means no upper bound). ok is false when a count is beyond what RE2 accepts.
func dot(min, max int) (s string, ok bool) {
	if min > 1000 || max > 1000 {
		return "", false
	}
	switch {
	case max < 0 && min == 0:
		return `(?s:.)*`, true
	case max < 0:
		return `(?s:.){` + strconv.Itoa(min) + `,}`, true
	case min == 0 && max == 0:
		return "", true
	case min == max:
		return `(?s:.){` + strconv.Itoa(min) + `}`, true
	}
	return `(?s:.){` + strconv.Itoa(min) + `,` + strconv.Itoa(max) + `}`, true
}

// pcreCond makes the condition for one pcre. The pattern is taken as written; flags i, s, m and A become the equivalent Go syntax.
func (c *cvt) pcreCond(spec bufSpec, xf []string, a *atom) (vpatch.Condition, error) {
	body := a.pcre.pattern
	flagsI := ""
	inline := ""
	for _, f := range a.pcre.flags {
		switch f {
		case 'i':
			flagsI = "i"
		case 's':
			inline += "s"
		case 'm':
			inline += "m"
		case 'A':
			body = `\A(?:` + body + `)`
		}
	}
	if inline != "" {
		body = "(?" + inline + ")" + body
	}
	p, err := c.rep.CheckRegex(body, flagsI, c.lim.MaxPatternBytes)
	if err != nil {
		return vpatch.Condition{}, err
	}
	c.noteLiteral(spec, a.pcre.pattern)
	cond := importers.NewCondition(vpatch.OpRegex, p, spec.targets, xf)
	cond.Flags = flagsI
	cond.Negate = a.negated
	return cond, nil
}

var headerLineRe = regexp.MustCompile(`(?s)^([A-Za-z][A-Za-z0-9-]{0,63}):(.*)$`)

// headerConds handles the whole-header-block buffer. In Suricata it holds "Name: value" lines, one after another; the model has one
// target per named header whose value is the part after the colon. A content that is a header line ("User-Agent: x", optionally
// with the line breaks around it) becomes a condition on that header. A content that is a piece of a value becomes a condition on
// every header value. A content that needs two lines, or the position in the block, is skipped.
func (c *cvt) headerConds(g *group) ([]vpatch.Condition, error) {
	var out []vpatch.Condition
	for i, a := range g.atoms {
		if a.isPCRE {
			return nil, skip("pcre-in-header-buffer")
		}
		if a.relative() && i > 0 {
			c.drop("header-content-order")
		}
		cond, err := c.headerCond(a, g.xforms)
		if err != nil {
			return nil, err
		}
		out = append(out, cond)
	}
	return out, nil
}

func (c *cvt) headerCond(a *atom, xf []string) (vpatch.Condition, error) {
	s := string(a.data)
	lead := strings.HasPrefix(s, "\r\n")
	if lead {
		s = s[2:]
	}
	trail := strings.HasSuffix(s, "\r\n")
	if trail {
		s = strings.TrimSuffix(s, "\r\n")
	}
	if strings.ContainsAny(s, "\r\n") {
		return vpatch.Condition{}, skip("header-spanning-lines")
	}
	if a.hasDepth || a.hasOffset {
		return vpatch.Condition{}, skip("header-position")
	}
	if m := headerLineRe.FindStringSubmatch(s); m != nil && (lead || strings.HasPrefix(m[2], " ") || strings.ContainsAny(m[1], "-") || (m[1][0] >= 'A' && m[1][0] <= 'Z')) {
		name := asciiLower(m[1])
		value := strings.TrimPrefix(m[2], " ")
		target := []string{"header:" + name}
		if value == "" {
			cond := importers.NewCondition(vpatch.OpRegex, "^", target, nil)
			cond.Negate = a.negated
			return cond, nil
		}
		op := vpatch.OpPrefix
		if trail || a.endswith {
			op = vpatch.OpEquals
		}
		tf := append([]string(nil), xf...)
		if a.nocase {
			value = asciiLower(value)
			tf = append(tf, "lowercase")
		}
		cond := importers.NewCondition(op, value, target, tf)
		cond.Negate = a.negated
		return cond, nil
	}
	if lead || trail || a.startswith || a.endswith {
		return vpatch.Condition{}, skip("header-fragment-position")
	}
	tf := append([]string(nil), xf...)
	if a.nocase {
		s = asciiLower(s)
		tf = append(tf, "lowercase")
	}
	cond := importers.NewCondition(vpatch.OpContains, s, []string{vpatch.TargetHeaders}, tf)
	cond.Negate = a.negated
	return cond, nil
}
