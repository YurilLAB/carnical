// SPDX-License-Identifier: Apache-2.0

package nuclei

import (
	"encoding/json"
	"mime"
	"regexp"
	"sort"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// built is what one request became.
type built struct {
	conds   []vpatch.Condition
	cl      *class // the payload class found, if any
	payload bool   // a payload or a script upload was found: this is the shape of an exploit, not just a visit to a page
	routing bool   // a routing argument (action=..., option=...) was found
	upload  bool
	paths   []string
	pay     []payTarget
}

// payTarget is one place a payload of a class was found.
type payTarget struct {
	cl     *class
	target string
}

// addPayload records a payload of class cl in target. Payloads of the same class in several places of one request become one
// condition with several targets, which holds if any of them has one: a template that fills many arguments with its payload, or one
// vulnerable argument among decoys, is not an exploit that needs them all.
func (o *built) addPayload(cl *class, target string) {
	o.pay = append(o.pay, payTarget{cl, target})
	o.payload = true
	o.cl = firstClass(o.cl, cl)
}

// family groups targets that can be searched together.
func family(t string) string {
	switch {
	case t == "args" || t == "argnames" || strings.HasPrefix(t, "arg:"):
		return "args"
	case t == "headers" || strings.HasPrefix(t, "header:"):
		return "headers"
	}
	return t
}

// mergePayloads turns the recorded payloads into conditions, in order of first appearance.
func (o *built) mergePayloads() []vpatch.Condition {
	type key struct{ class, fam string }
	idx := map[key]int{}
	var out []vpatch.Condition
	for _, p := range o.pay {
		k := key{p.cl.name, family(p.target)}
		if i, ok := idx[k]; ok {
			dup := false
			for _, t := range out[i].Targets {
				if t == p.target {
					dup = true
				}
			}
			if !dup && len(out[i].Targets) < 64 {
				out[i].Targets = append(out[i].Targets, p.target)
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, classCond(p.cl, p.target))
	}
	return out
}

type builder struct {
	lim      importers.Limits
	rep      *importers.Report
	payloads map[string][]string
	multi    bool // the template sends more than one request
}

var identifierRe = regexp.MustCompile(`^/?[A-Za-z][A-Za-z0-9_.:/-]{0,63}$`)

// routingName says whether an argument name selects what the endpoint does (WordPress "action", Joomla "option", a "controller", a
// "rest_route"), as opposed to carrying data. Such an argument with a plain value is part of what identifies the vulnerable function.
var routingRe = regexp.MustCompile(`(?i)^(?:action|option|page|task|controller|view|module|mod|do|act|func|function|method|route|rest_route|op|operation|mode|tab|component|handler|ajax|class|ctrl)$|(?:^|[-_])action$`)

var travRe = regexp.MustCompile(`(?i)(?:\.\.[/\\;]|%2e%2e|\.%2e|%2e\.|%252e)`)

// travCondPattern is the traversal shape for a request whose path itself climbs out of a directory.
const travCondPattern = `(?:\.|%2e|%252e){2}(?:[/\\;]|%2f|%5c|%252f|%255c)`

// genericDirs are directory names that many products share, so a prefix made of them names no product.
var genericDirs = map[string]bool{"cgi-bin": true, "scripts": true, "static": true, "assets": true, "images": true, "css": true, "js": true,
	"uploads": true, "files": true, "download": true, "downloads": true, "public": true, "resources": true, "content": true, "bin": true,
	"admin": true, "api": true, "web": true, "app": true, "lib": true, "includes": true, "wp-content": true, "plugins": true, "themes": true}

var staticExt = map[string]bool{".txt": true, ".html": true, ".htm": true, ".xml": true, ".json": true, ".js": true, ".css": true, ".yml": true,
	".yaml": true, ".ini": true, ".conf": true, ".cfg": true, ".log": true, ".bak": true, ".sql": true, ".zip": true, ".gz": true, ".tar": true,
	".env": true, ".md": true, ".csv": true, ".png": true, ".jpg": true, ".gif": true, ".ico": true, ".svg": true, ".pdf": true, ".swp": true,
	".old": true, ".properties": true, ".git": true, ".map": true, ".woff": true, ".woff2": true, ".ttf": true, ".rar": true, ".7z": true, ".key": true, ".pem": true}

// request converts one request into conditions, or returns the reason it is not an exploit shape worth a signature.
func (b *builder) request(r request) (*built, error) {
	out := &built{}
	add := func(c vpatch.Condition) { out.conds = append(out.conds, c) }

	// ---- path
	pathText, pathLit := r.path.literal()
	probeText := r.path.text("{}")
	traversal := travRe.MatchString(probeText)
	if traversal {
		prefix := specificPrefix(probeText)
		if prefix == "" {
			return nil, skip("generic-traversal")
		}
		add(importers.NewCondition(vpatch.OpContains, asciiLower(prefix), []string{vpatch.TargetURI}, []string{"urldecode1", "lowercase"}))
		c := importers.NewCondition(vpatch.OpRegex, travCondPattern, []string{vpatch.TargetURI}, nil)
		c.Flags = "i"
		add(c)
		out.payload = true
		out.cl = classByName("path traversal")
		out.paths = append(out.paths, prefix)
	} else if pc, lit := b.pathCondition(r.path, pathLit, pathText); pc != nil {
		add(*pc)
		out.paths = append(out.paths, lit)
	}

	// ---- method
	if r.method != "" && r.method != "GET" {
		add(importers.NewCondition(vpatch.OpEquals, r.method, []string{vpatch.TargetMethod}, nil))
	}

	// ---- query
	for _, part := range r.query.split('&') {
		if len(part) == 0 {
			continue
		}
		name, val, hasEq := part.splitAt('=')
		if !hasEq {
			// "?<payload>": the payload is the argument's name.
			if cl := classify(part.text("VARX"), part.hasOOB()); cl != nil && cl.category != "ssrf" {
				out.addPayload(cl, "argnames")
			}
			continue
		}
		b.param(out, add, name, val, true)
	}

	// ---- body
	if len(r.body) > 0 {
		b.body(out, add, r)
	}

	// ---- headers
	for _, h := range r.headers {
		b.headerCond(out, add, h)
	}

	out.conds = append(out.conds, out.mergePayloads()...)
	if len(out.conds) == 0 {
		return nil, skip("no-exploit-shape")
	}
	if len(out.conds) > b.lim.MaxConditions {
		return nil, skip("too-many-conditions")
	}

	// A request that is only a path (and maybe a routing argument) is a visit, not an exploit shape. A single such request in a
	// template that is about an exploit endpoint is kept as a low-confidence probe; a visit that is a step of a longer sequence, or
	// a plain file, is not.
	if !out.payload {
		if b.multi {
			return nil, skip("step-without-payload")
		}
		if !out.routing && r.method == "GET" && r.query == nil && len(r.body) == 0 && isStaticFile(probeText) {
			return nil, skip("static-file-get")
		}
		if !out.routing && len(out.paths) == 0 {
			return nil, skip("no-exploit-shape")
		}
	}
	return out, nil
}

func firstClass(a, b *class) *class {
	if a != nil {
		return a
	}
	return b
}

func isStaticFile(p string) bool {
	if p == "" || p == "/" || strings.HasSuffix(p, "/") {
		return true
	}
	last := p[strings.LastIndexByte(p, '/')+1:]
	i := strings.LastIndexByte(last, '.')
	if i < 0 {
		return false
	}
	return staticExt[strings.ToLower(last[i:])]
}

// specificPrefix returns the part of a path before its first traversal marker, cut at a slash, when it names a product: at least two
// path segments, or one that is not a directory name that many products share. Otherwise "".
func specificPrefix(p string) string {
	loc := travRe.FindStringIndex(p)
	if loc == nil {
		return ""
	}
	pre := p[:loc[0]]
	if i := strings.LastIndexByte(pre, '/'); i >= 0 {
		pre = pre[:i+1]
	}
	var segs []string
	for _, s := range strings.Split(strings.Trim(pre, "/"), "/") {
		if s != "" && !strings.Contains(s, "{}") { // "{}" stands for a variable
			segs = append(segs, s)
		}
	}
	if len(segs) >= 2 {
		return pre
	}
	if len(segs) == 1 && len(segs[0]) >= 6 && !genericDirs[strings.ToLower(segs[0])] {
		return pre
	}
	return ""
}

func asciiLower(s string) string {
	bs := []byte(s)
	for i, c := range bs {
		if c >= 'A' && c <= 'Z' {
			bs[i] = c + 32
		}
	}
	return string(bs)
}

// pathCondition makes the path condition: a suffix test for a literal path (the application may be installed under a directory), a
// regular expression where the path has variables. The path target is the path as received, so it is decoded once, normalised and
// lower-cased first.
func (b *builder) pathCondition(path tpl, isLit bool, litText string) (*vpatch.Condition, string) {
	xf := []string{"urldecode1", "normpath", "lowercase"}
	if isLit {
		if litText == "" || litText == "/" {
			return nil, ""
		}
		c := importers.NewCondition(vpatch.OpSuffix, asciiLower(litText), []string{vpatch.TargetPath}, xf)
		return &c, litText
	}
	var sb strings.Builder
	lits := 0
	for _, s := range path {
		if s.v != "" {
			sb.WriteString(`[^/]+`)
			continue
		}
		lits += len(strings.Trim(s.lit, "/"))
		sb.WriteString(regexp.QuoteMeta(asciiLower(s.lit)))
	}
	if lits < 3 { // nothing but variables and slashes names no endpoint
		return nil, ""
	}
	sb.WriteString("$")
	c := importers.NewCondition(vpatch.OpRegex, sb.String(), []string{vpatch.TargetPath}, xf)
	return &c, path.text("")
}

func classCond(cl *class, target string) vpatch.Condition {
	c := importers.NewCondition(vpatch.OpRegex, cl.pattern, []string{target}, cl.transforms)
	c.Flags = "i"
	return c
}

// param handles one named argument. routing says a plain value may identify the function being called.
func (b *builder) param(out *built, add func(vpatch.Condition), name, val tpl, routing bool) {
	nm, ok := name.literal()
	if !ok || nm == "" {
		return
	}
	nm = asciiLower(strings.TrimSpace(nm))
	target := "arg:" + nm
	if !importers.ValidTarget(target) {
		return
	}
	b.paramValue(out, add, target, nm, val.text("VARX"), val.hasOOB(), val, routing)
}

func (b *builder) paramValue(out *built, add func(vpatch.Condition), target, name, text string, oob bool, val tpl, routing bool) {
	// A value that is a single variable taken from an inline payload list is classified by the payloads.
	if len(val) == 1 && val[0].v != "" {
		if list, ok := b.payloads[val[0].v]; ok {
			text = strings.Join(list, "\n")
		}
	}
	if cl := classify(text, oob); cl != nil {
		out.addPayload(cl, target)
		return
	}
	if routing && routingRe.MatchString(name) && !val.hasVar() && identifierRe.MatchString(text) {
		if strings.HasPrefix(text, "/") {
			// A route such as /wp/v2/items/1 names the route, but the number is only the example's: any id reaches the same code.
			add(importers.NewCondition(vpatch.OpRegex, routePattern(text), []string{target}, nil))
		} else {
			add(importers.NewCondition(vpatch.OpEquals, text, []string{target}, nil))
		}
		out.routing = true
	}
}

// routePattern is a regular expression for a route such as /wp/v2/items/1, with a number in place of each all-digit segment.
func routePattern(route string) string {
	segs := strings.Split(route, "/")
	for i, s := range segs {
		switch {
		case s == "":
		case strings.Trim(s, "0123456789") == "":
			segs[i] = "[0-9]+"
		default:
			segs[i] = regexp.QuoteMeta(s)
		}
	}
	return "^" + strings.Join(segs, "/") + "/?$"
}

// body looks at the request body by its content type.
func (b *builder) body(out *built, add func(vpatch.Condition), r request) {
	ct := strings.ToLower(r.contentType())
	text := r.body.text("VARX")
	oob := r.body.hasOOB()
	switch {
	case strings.Contains(ct, "multipart/form-data"):
		b.multipart(out, add, r, r.contentType())
	case strings.Contains(ct, "json") || (ct == "" && strings.HasPrefix(strings.TrimSpace(text), "{")):
		if !b.jsonBody(out, add, r.body) {
			b.rawBody(out, add, text, oob)
		}
	case strings.Contains(ct, "x-www-form-urlencoded") || (ct == "" && formLike(text)):
		for _, part := range r.body.split('&') {
			if len(part) == 0 {
				continue
			}
			name, val, hasEq := part.splitAt('=')
			if !hasEq {
				continue
			}
			b.param(out, add, name, val, true)
		}
	default:
		b.rawBody(out, add, text, oob)
	}
}

var formRe = regexp.MustCompile(`^[A-Za-z0-9_.\[\]%-]+=[^\s]*(?:&[A-Za-z0-9_.\[\]%-]+=[^\s]*)*$`)

func formLike(s string) bool { return len(s) < 8192 && formRe.MatchString(strings.TrimSpace(s)) }

// rawBody looks for an attack class in a body that has no argument structure (XML, serialised objects, plain text).
func (b *builder) rawBody(out *built, add func(vpatch.Condition), text string, oob bool) {
	cl := classify(text, oob)
	if cl == nil || cl.category == "ssrf" {
		return
	}
	out.addPayload(cl, vpatch.TargetBody)
}

func (b *builder) jsonBody(out *built, add func(vpatch.Condition), body tpl) bool {
	txt := body.text("VARX")
	var v any
	if err := json.Unmarshal([]byte(txt), &v); err != nil {
		return false
	}
	var leaves []struct{ path, val string }
	flatten("", v, 0, &leaves)
	oob := body.hasOOB()
	for _, l := range leaves {
		name := asciiLower(l.path)
		target := "arg:json." + name
		if !importers.ValidTarget(target) {
			continue
		}
		b.paramValue(out, add, target, name, l.val, oob && strings.Contains(l.val, "VARX"), tpl{{lit: l.val}}, false)
	}
	return true
}

func flatten(prefix string, v any, depth int, out *[]struct{ path, val string }) {
	if depth > 6 || len(*out) >= 64 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flatten(p, x[k], depth+1, out)
		}
	case []any:
		for _, e := range x {
			flatten(prefix, e, depth+1, out)
		}
	case string:
		if prefix != "" {
			*out = append(*out, struct{ path, val string }{prefix, x})
		}
	}
}

var (
	phpExtRe = regexp.MustCompile(`(?i)\.(?:php[0-9]?|phtml|phar|pht)$`)
	jspExtRe = regexp.MustCompile(`(?i)\.(?:jsp|jspx|jsw|jsv)$`)
	aspExtRe = regexp.MustCompile(`(?i)\.(?:asp|aspx|asa|cer|ashx)$`)
)

const (
	phpExtPattern = `\.(?:php[0-9]?|phtml|phar|pht)$`
	jspExtPattern = `\.(?:jsp|jspx|jsw|jsv)$`
	aspExtPattern = `\.(?:asp|aspx|asa|cer|ashx)$`
)

// multipart reads the parts of a multipart body: a file whose name is a script is the shape of a web shell upload, and an ordinary
// field is handled like an argument.
func (b *builder) multipart(out *built, add func(vpatch.Condition), r request, ct string) {
	text := strings.ReplaceAll(r.body.text("VARX"), "\r\n", "\n")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "multipart/form-data" {
		return
	}
	delim := ""
	if boundary := params["boundary"]; boundary != "" {
		delim = "--" + boundary
	}
	if delim == "" {
		for _, l := range strings.Split(text, "\n") {
			if strings.HasPrefix(l, "--") {
				delim = strings.TrimRight(l, "-")
				if delim == "" {
					delim = "--"
				}
				break
			}
		}
	}
	if delim == "" {
		return
	}
	parts := strings.Split(text, delim)
	for i, p := range parts {
		if i == 0 || len(p) > 32<<10 {
			continue
		}
		p = strings.TrimPrefix(p, "\n")
		head, content, _ := strings.Cut(p, "\n\n")
		var name, file string
		hasFile := false
		for _, l := range strings.Split(head, "\n") {
			headerName, value, ok := strings.Cut(l, ":")
			if !ok || !strings.EqualFold(strings.TrimSpace(headerName), "Content-Disposition") {
				continue
			}
			disposition, params, err := mime.ParseMediaType(value)
			if err != nil || disposition != "form-data" {
				continue
			}
			name = params["name"]
			file, hasFile = params["filename"]
		}
		content = strings.Trim(content, "\n -")
		if hasFile {
			var pat string
			switch {
			case phpExtRe.MatchString(file):
				pat = phpExtPattern
			case jspExtRe.MatchString(file):
				pat = jspExtPattern
			case aspExtRe.MatchString(file):
				pat = aspExtPattern
			}
			if pat != "" {
				c := importers.NewCondition(vpatch.OpRegex, pat, []string{vpatch.TargetFilenames}, nil)
				c.Flags = "i"
				add(c)
				out.payload, out.upload = true, true
			}
			continue
		}
		if name == "" {
			continue
		}
		nm := asciiLower(name)
		target := "arg:" + nm
		if !importers.ValidTarget(target) {
			continue
		}
		b.paramValue(out, add, target, nm, content, strings.Contains(content, "VARX") && r.body.hasOOB(), tpl{{lit: content}}, true)
	}
}

// exploitHeaders are headers whose presence, with any value, is part of how some exploits work (framework-internal control headers).
var exploitHeaders = map[string]bool{"x-middleware-subrequest": true, "next-action": true, "rsc-action-id": true, "x-invoke-path": true,
	"x-invoke-output": true, "x-invoke-status": true, "x-matched-path": true, "x-original-url": true, "x-rewrite-url": true}

func (b *builder) headerCond(out *built, add func(vpatch.Condition), h header) {
	if h.name == "" || h.name == "host" || h.name == "content-length" || h.name == "content-type" || h.name == "connection" {
		return
	}
	target := "header:" + h.name
	if !importers.ValidTarget(target) {
		return
	}
	text := h.val.text("VARX")
	if cl := classify(text, h.val.hasOOB()); cl != nil && cl.category != "ssrf" {
		out.addPayload(cl, target)
		return
	}
	if exploitHeaders[h.name] {
		add(importers.NewCondition(vpatch.OpRegex, "^", []string{target}, nil))
		out.payload = true
	}
}
