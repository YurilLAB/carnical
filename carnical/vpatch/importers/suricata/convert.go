// SPDX-License-Identifier: Apache-2.0

package suricata

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// skipError is a reason a rule cannot be converted.
type skipError struct{ reason string }

func (e *skipError) Error() string { return e.reason }

func skip(format string, args ...any) error {
	return &skipError{reason: fmt.Sprintf(format, args...)}
}

func reasonOf(err error) string {
	var se *skipError
	if errors.As(err, &se) {
		return se.reason
	}
	var re *importers.RegexError
	if errors.As(err, &re) {
		return "pcre:" + re.Reason
	}
	switch {
	case errors.Is(err, errNotRule), errors.Is(err, errMalformed):
		return "malformed-rule"
	case errors.Is(err, errTooMany):
		return "too-many-options"
	case errors.Is(err, errTooLong):
		return "rule-too-long"
	}
	return "invalid-rule"
}

// bufSpec says how one Suricata buffer maps to the model.
type bufSpec struct {
	targets []string
	base    []string // transforms that make the target match what Suricata's buffer holds
	header  bool     // the buffer is the whole header block, which needs the header-line handling in headerConds
}

// buffers are the request buffers this converter can express. http.uri is Suricata's normalised URI, which the model reaches as the
// URI as received plus one round of percent-decoding. A content with no buffer at all is matched against the raw request, so it
// is looked for in the URI, the header values and the body.
var buffers = map[string]bufSpec{
	"http.uri":          {targets: []string{vpatch.TargetURI}, base: []string{"urldecode1"}},
	"http.uri.raw":      {targets: []string{vpatch.TargetURI}},
	"http.method":       {targets: []string{vpatch.TargetMethod}},
	"http.request_body": {targets: []string{vpatch.TargetBody}},
	"http.cookie":       {targets: []string{"header:cookie"}},
	"http.user_agent":   {targets: []string{"header:user-agent"}},
	"http.host":         {targets: []string{"header:host"}},
	"http.host.raw":     {targets: []string{"header:host"}},
	"http.referer":      {targets: []string{"header:referer"}},
	"http.content_type": {targets: []string{"header:content-type"}},
	"http.accept":       {targets: []string{"header:accept"}},
	"http.accept_enc":   {targets: []string{"header:accept-encoding"}},
	"http.connection":   {targets: []string{"header:connection"}},
	"http.content_len":  {targets: []string{"header:content-length"}},
	"http.header":       {header: true},
	"http.header.raw":   {header: true},
	"":                  {targets: []string{vpatch.TargetURI, vpatch.TargetHeaders, vpatch.TargetBody}},
}

// stickyBuffers are the keywords that select a buffer for the options that follow them.
var stickyBuffers = map[string]string{
	"http.uri": "http.uri", "http.uri.raw": "http.uri.raw", "http.method": "http.method", "http.request_body": "http.request_body",
	"http.header": "http.header", "http.header.raw": "http.header.raw", "http.cookie": "http.cookie", "http.user_agent": "http.user_agent",
	"http.host": "http.host", "http.host.raw": "http.host.raw", "http.referer": "http.referer", "http.content_type": "http.content_type",
	"http.accept": "http.accept", "http.accept_enc": "http.accept_enc", "http.connection": "http.connection",
	"http.content_len": "http.content_len",
}

// modifierBuffers are the older spelling: a keyword after a content that moves that content to a buffer.
var modifierBuffers = map[string]string{
	"http_uri": "http.uri", "http_raw_uri": "http.uri.raw", "http_header": "http.header", "http_raw_header": "http.header.raw",
	"http_client_body": "http.request_body", "http_cookie": "http.cookie", "http_method": "http.method",
	"http_user_agent": "http.user_agent", "http_host": "http.host", "http_raw_host": "http.host.raw", "http_referer": "http.referer",
}

// unsupportedBuffers are buffers the model has no target for, or that are about the response. A rule that needs one is skipped.
var unsupportedBuffers = map[string]string{
	"http.header_names": "header-names", "http.request_line": "request-line", "http.start": "request-line",
	"http.request_header": "request-header", "http.protocol": "protocol", "http.stat_code": "response", "http.stat_msg": "response",
	"http.response_body": "response", "http.response_header": "response", "http.response_line": "response", "http.server": "response",
	"http.location": "response", "file.data": "response", "file.magic": "response", "file.name": "response", "filesize": "response",
	"http_stat_code": "response", "http_stat_msg": "response", "http_server_body": "response", "file_data": "response",
	"http_header_names": "header-names", "http_request_line": "request-line", "http_start": "request-line",
}

var pcreBuffers = map[byte]string{
	'U': "http.uri", 'I': "http.uri.raw", 'P': "http.request_body", 'H': "http.header", 'D': "http.header.raw", 'M': "http.method",
	'C': "http.cookie", 'V': "http.user_agent", 'W': "http.host", 'Z': "http.host.raw",
}

// ignored are options that say nothing about what a request looks like.
var ignored = map[string]bool{
	"msg": true, "sid": true, "rev": true, "gid": true, "classtype": true, "priority": true, "reference": true, "metadata": true,
	"target": true, "tag": true, "fast_pattern": true, "rawbytes": true, "app-layer-protocol": true, "header_lowercase": true,
	"strip_pseudo_headers": true,
}

// bufferTransforms are the keywords that transform the buffer chosen by the sticky keyword before them.
var bufferTransforms = map[string]string{
	"url_decode": "urldecode1", "to_lowercase": "lowercase", "strip_whitespace": "removespace", "compress_whitespace": "compressspace",
}

// atom is one content or pcre match, and the buffer it is looked for in.
type atom struct {
	isPCRE  bool
	buf     string
	xforms  []string
	data    []byte
	negated bool
	nocase  bool
	// position modifiers of a content
	depth, offset, distance, within         int
	hasDepth, hasOffset, hasDist, hasWithin bool
	startswith, endswith                    bool
	pcre                                    pcreSpec
	pcreRelative                            bool
}

func (a *atom) relative() bool {
	if a.isPCRE {
		return a.pcreRelative
	}
	return a.hasDist || a.hasWithin
}

// sizeCons is a bsize or urilen constraint: lo <= length <= hi, hi < 0 meaning no upper bound.
type sizeCons struct {
	buf    string
	lo, hi int
}

type cvt struct {
	opts  importers.Options
	lim   importers.Limits
	rep   *importers.Report
	drops map[string]bool
	// uriLits are literal URI fragments, for scope inference.
	uriLits []string
}

func (c *cvt) drop(kind string) { c.drops[kind] = true }

type group struct {
	buf    string
	xforms []string
	atoms  []*atom
}

// convertRule converts one parsed rule. It returns the signature, or an error whose reason says why it was skipped.
func (c *cvt) convertRule(r *rule) (*vpatch.Signature, error) {
	meta := map[string]string{}
	var (
		sid, rev  string
		msg       string
		classtype string
		cves      []string
		sizes     []sizeCons
		atoms     []*atom
		cur       string   // the sticky buffer in force
		curX      []string // transforms in force on it
		last      *atom
		section   []*atom // the atoms made since the last sticky buffer keyword
		sawHTTP   bool
	)
	for _, o := range r.opts {
		switch {
		case o.key == "msg":
			msg, _, _ = quotedLoose(o.val)
		case o.key == "sid":
			sid = o.val
		case o.key == "rev":
			rev = o.val
		case o.key == "classtype":
			classtype = o.val
		case o.key == "reference":
			if rest, ok := strings.CutPrefix(o.val, "cve,"); ok {
				cves = append(cves, "CVE-"+strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(rest)), "CVE-"))
			}
		case o.key == "metadata":
			for _, kv := range strings.Split(o.val, ",") {
				k, v, _ := strings.Cut(strings.TrimSpace(kv), " ")
				meta[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
		case o.key == "flow":
			low := strings.ToLower(o.val)
			if strings.Contains(low, "to_client") || strings.Contains(low, "from_server") {
				return nil, skip("response-direction")
			}
		case o.key == "noalert":
			return nil, skip("noalert")
		case o.key == "flowbits":
			if strings.HasPrefix(strings.ToLower(o.val), "set") {
				continue // sets state for another rule; the rule's own match is what is converted (noalert, if present, skips it)
			}
			return nil, skip("flowbits")
		case o.key == "xbits" || o.key == "flowint" || o.key == "flowvar" || o.key == "pktvar":
			return nil, skip("stateful:%s", o.key)
		case o.key == "threshold" || o.key == "detection_filter":
			c.drop("threshold")
		case ignored[o.key]:
		case stickyBuffers[o.key] != "":
			cur = stickyBuffers[o.key]
			curX = nil
			last = nil
			section = nil
			sawHTTP = true
		case unsupportedBuffers[o.key] != "":
			return nil, skip("unsupported-buffer:%s", unsupportedBuffers[o.key])
		case modifierBuffers[o.key] != "":
			if last == nil {
				return nil, skip("modifier-without-content:%s", o.key)
			}
			last.buf = modifierBuffers[o.key]
			sawHTTP = true
		case bufferTransforms[o.key] != "":
			// A transform applies to the whole sticky buffer, whether it is written before or after the contents in it.
			if cur == "" {
				return nil, skip("transform-without-buffer:%s", o.key)
			}
			curX = append(append([]string(nil), curX...), bufferTransforms[o.key])
			for _, a := range section {
				a.xforms = append([]string(nil), curX...)
			}
		case o.key == "content" || o.key == "uricontent":
			a, err := c.newContent(o, cur, curX)
			if err != nil {
				return nil, err
			}
			if o.key == "uricontent" {
				a.buf = "http.uri"
				sawHTTP = true
			}
			atoms = append(atoms, a)
			if a.buf == cur {
				section = append(section, a)
			}
			last = a
		case o.key == "pcre":
			a, err := c.newPCRE(o, cur, curX)
			if err != nil {
				return nil, err
			}
			if a.buf != "" {
				sawHTTP = true
			}
			atoms = append(atoms, a)
			if a.buf == cur {
				section = append(section, a)
			}
			last = a
		case o.key == "nocase" || o.key == "depth" || o.key == "offset" || o.key == "distance" || o.key == "within" || o.key == "startswith" || o.key == "endswith":
			if last == nil || last.isPCRE {
				return nil, skip("modifier-without-content:%s", o.key)
			}
			if err := applyModifier(last, o); err != nil {
				return nil, err
			}
		case o.key == "bsize":
			s, err := parseSize(o.val)
			if err != nil {
				return nil, err
			}
			s.buf = cur
			if cur == "" {
				return nil, skip("bsize-without-buffer")
			}
			sizes = append(sizes, s)
		case o.key == "urilen":
			val, _, _ := strings.Cut(o.val, ",")
			s, err := parseSize(val)
			if err != nil {
				return nil, err
			}
			s.buf = "http.uri.raw"
			sizes = append(sizes, s)
			sawHTTP = true
		default:
			return nil, skip("unsupported-keyword:%s", importers.SafeName(o.key))
		}
	}
	if sid == "" {
		return nil, skip("no-sid")
	}
	if r.proto != "http" && r.proto != "http1" && !(r.proto == "tcp" && sawHTTP) {
		return nil, skip("not-http-rule:%s", importers.SafeName(r.proto))
	}
	if len(atoms) == 0 && len(sizes) == 0 {
		return nil, skip("no-match-conditions")
	}
	if len(atoms)+len(sizes) > c.lim.MaxConditions*2 {
		return nil, skip("too-many-conditions")
	}

	// Group the atoms by buffer, in order of first appearance.
	var groups []*group
	for _, a := range atoms {
		var g *group
		key := a.buf + "|" + strings.Join(a.xforms, ",")
		for _, x := range groups {
			if x.buf+"|"+strings.Join(x.xforms, ",") == key {
				g = x
				break
			}
		}
		if g == nil {
			g = &group{buf: a.buf, xforms: a.xforms}
			groups = append(groups, g)
		}
		g.atoms = append(g.atoms, a)
	}
	var conds []vpatch.Condition
	hasPositive := false
	for _, g := range groups {
		gc, err := c.groupConds(g)
		if err != nil {
			return nil, err
		}
		for _, a := range g.atoms {
			if !a.negated {
				hasPositive = true // the existence guards that go with a negated match do not count as a match
			}
		}
		conds = append(conds, gc...)
	}
	for _, s := range sizes {
		sc, err := c.sizeCond(s)
		if err != nil {
			return nil, err
		}
		conds = append(conds, sc)
		hasPositive = true
	}
	if !hasPositive {
		return nil, skip("only-negated-matches")
	}
	conds = dedupe(conds)
	if len(conds) > c.lim.MaxConditions {
		return nil, skip("too-many-conditions")
	}
	mainC, also := importers.Assemble(conds)

	// ---- metadata
	sev, conf := severityFrom(meta), confidenceFrom(meta)
	category := importers.ClassifyText(msg)
	if category == "" {
		category = importers.ClassifyText(strings.ReplaceAll(meta["tag"], "_", " "))
	}
	cveAll := importers.CVEs(append(append([]string{msg, meta["cve"]}, cves...), strings.ReplaceAll(meta["cve"], "_", "-"))...)
	if category == "" {
		switch {
		case len(cveAll) > 0:
			category = "cve"
		default:
			category = "other"
		}
	}
	if sev == "" {
		sev = importers.SeverityFor(category)
	}
	if conf == "" {
		conf = "medium"
	}
	revNum, _ := strconv.Atoi(rev)
	tier := c.opts.StartTier()
	if len(c.drops) > 0 {
		tier = importers.LowerTier(tier)
	}
	rv := rev
	if c.opts.Revision != "" {
		rv = importers.SafeRevision(c.opts.Revision)
	}
	if rv == "" {
		rv = "0"
	}
	sig := &vpatch.Signature{
		ID:          "ET-" + importers.IDPart(sid),
		Rev:         revNum,
		Description: importers.Describe(msg, 300),
		Category:    category,
		Severity:    sev,
		Confidence:  conf,
		Action:      importers.ActionFor(conf),
		Score:       importers.ScoreFor(conf),
		CVEs:        cveAll,
		Sources:     []string{"suricata:" + importers.SafeToken(sid, 20) + "@" + rv},
		Scope:       importers.InferScope(c.uriLits, []string{msg}, nil),
		Tier:        tier,
		Condition:   mainC,
		Also:        also,
	}
	_ = classtype
	return sig, nil
}

func hasOpt(opts []opt, key string) bool {
	for _, o := range opts {
		if o.key == key {
			return true
		}
	}
	return false
}

// quotedLoose reads "text" and returns the text; if it is not quoted it returns the value as it is.
func quotedLoose(v string) (string, bool, error) {
	t, neg, err := quoted(v)
	if err != nil {
		return strings.TrimSpace(v), false, nil
	}
	return t, neg, nil
}

func severityFrom(meta map[string]string) string {
	switch strings.ToLower(meta["signature_severity"]) {
	case "critical":
		return "critical"
	case "major":
		return "high"
	case "minor":
		return "medium"
	case "informational":
		return "low"
	}
	return ""
}

func confidenceFrom(meta map[string]string) string {
	switch strings.ToLower(meta["confidence"]) {
	case "high", "very_high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	}
	return ""
}

func (c *cvt) newContent(o opt, cur string, curX []string) (*atom, error) {
	text, neg, err := quoted(o.val)
	if err != nil {
		return nil, skip("malformed-content")
	}
	data, err := decodeContent(text)
	if err != nil || len(data) == 0 {
		return nil, skip("malformed-content")
	}
	if len(data) > c.lim.MaxPatternBytes {
		return nil, skip("pattern-too-long")
	}
	if !validText(data) {
		return nil, skip("binary-content")
	}
	return &atom{buf: cur, xforms: append([]string(nil), curX...), data: data, negated: neg}, nil
}

func (c *cvt) newPCRE(o opt, cur string, curX []string) (*atom, error) {
	p, err := parsePCRE(o.val)
	if err != nil {
		return nil, skip("malformed-pcre")
	}
	if len(p.pattern) > c.lim.MaxPatternBytes {
		return nil, skip("pattern-too-long")
	}
	a := &atom{isPCRE: true, buf: cur, xforms: append([]string(nil), curX...), pcre: p, negated: p.negated}
	var flags []byte
	for i := 0; i < len(p.flags); i++ {
		f := p.flags[i]
		switch f {
		case 'i', 's', 'm', 'A':
			flags = append(flags, f)
		case 'R':
			a.pcreRelative = true
		case 'E', 'O', 'Q':
			// $ matches only at the very end (E), limits and no-alert: no effect on whether a request matches
		case 'x', 'G', 'K', 'S', 'Y':
			return nil, skip("pcre-flag:%c", f)
		default:
			if b, ok := pcreBuffers[f]; ok {
				if cur == "" || cur == b {
					a.buf = b
				} else {
					a.buf = b
				}
				continue
			}
			if f == 'B' {
				a.buf = ""
				continue
			}
			return nil, skip("pcre-flag:%c", f)
		}
	}
	a.pcre.flags = string(flags)
	return a, nil
}

func applyModifier(a *atom, o opt) error {
	switch o.key {
	case "nocase":
		a.nocase = true
	case "startswith":
		a.startswith = true
	case "endswith":
		a.endswith = true
	default:
		n, err := intOpt(o.val)
		if err != nil {
			return skip("malformed-%s", o.key)
		}
		switch o.key {
		case "depth":
			a.depth, a.hasDepth = n, true
		case "offset":
			a.offset, a.hasOffset = n, true
		case "distance":
			a.distance, a.hasDist = n, true
		case "within":
			a.within, a.hasWithin = n, true
		}
	}
	return nil
}

var sizeRe = regexp.MustCompile(`^\s*(<>|>=|<=|>|<|=)?\s*(\d+)\s*(?:<>\s*(\d+))?\s*$`)

// parseSize reads bsize / urilen values: 12, >12, <12, 5<>20 (exclusive on both ends).
func parseSize(v string) (sizeCons, error) {
	m := sizeRe.FindStringSubmatch(v)
	if m == nil {
		return sizeCons{}, skip("malformed-size")
	}
	n, err := strconv.Atoi(m[2])
	if err != nil || n > 1<<20 {
		return sizeCons{}, skip("bsize-too-large")
	}
	if m[3] != "" {
		hi, err := strconv.Atoi(m[3])
		if err != nil || hi > 1<<20 {
			return sizeCons{}, skip("bsize-too-large")
		}
		return sizeCons{lo: n + 1, hi: hi - 1}, nil
	}
	switch m[1] {
	case ">":
		return sizeCons{lo: n + 1, hi: -1}, nil
	case ">=":
		return sizeCons{lo: n, hi: -1}, nil
	case "<":
		return sizeCons{lo: 0, hi: n - 1}, nil
	case "<=":
		return sizeCons{lo: 0, hi: n}, nil
	}
	return sizeCons{lo: n, hi: n}, nil
}

// sizeCond says "the buffer is between lo and hi characters long" as a regular expression; RE2 allows a repeat count up to 1000.
func (c *cvt) sizeCond(s sizeCons) (vpatch.Condition, error) {
	spec, ok := buffers[s.buf]
	if !ok || spec.header || len(spec.targets) == 0 {
		return vpatch.Condition{}, skip("bsize-on-unsupported-buffer")
	}
	if s.hi >= 0 && s.hi < s.lo {
		return vpatch.Condition{}, skip("size-never-matches")
	}
	if s.lo > 1000 || s.hi > 1000 {
		return vpatch.Condition{}, skip("bsize-too-large")
	}
	var pat string
	switch {
	case s.hi < 0:
		pat = `(?s)\A.{` + strconv.Itoa(s.lo) + `,}\z`
	case s.hi == s.lo:
		pat = `(?s)\A.{` + strconv.Itoa(s.lo) + `}\z`
	default:
		pat = `(?s)\A.{` + strconv.Itoa(s.lo) + `,` + strconv.Itoa(s.hi) + `}\z`
	}
	p, err := c.rep.CheckRegex(pat, "", c.lim.MaxPatternBytes)
	if err != nil {
		return vpatch.Condition{}, err
	}
	return importers.NewCondition(vpatch.OpRegex, p, spec.targets, spec.base), nil
}

func dedupe(cs []vpatch.Condition) []vpatch.Condition {
	seen := map[string]bool{}
	var out []vpatch.Condition
	for _, c := range cs {
		k := fmt.Sprintf("%+v", c)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}
