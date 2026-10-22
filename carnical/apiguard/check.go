// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"cmp"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// idSet maps what a check found to the verdict identifier for the level that is checking: the same check serves the described
// model and the learned one, and a finding in one is not a finding in the other.
type idSet struct {
	pathParam, queryParam, headerParam, cookieParam, missingParam, contentType, bodySchema, unknownProp, readOnly, missingProp int
	bodyMissing, unexpectedBody, unknownQuery, tooComplex, noCredential                                                        int
	// named is true if parameter and property names may be put in a message. They may where they come from the owner's own
	// description; the names in a learned model came from visitors.
	named bool
}

var declaredIDs = idSet{
	pathParam: IDSpecPathParam, queryParam: IDSpecQueryParam, headerParam: IDSpecHeaderParam, cookieParam: IDSpecCookieParam,
	missingParam: IDSpecMissingParam, contentType: IDSpecContentType, bodySchema: IDSpecBodySchema, unknownProp: IDSpecUnknownProperty,
	readOnly: IDSpecReadOnlyProperty, missingProp: IDSpecBodySchema, bodyMissing: IDSpecBodyMissing, unexpectedBody: IDSpecUnexpectedBody,
	unknownQuery: IDSpecUnknownQuery, tooComplex: IDSpecTooComplex, noCredential: IDSpecNoCredential, named: true,
}

var learnedIDs = idSet{
	queryParam: IDLearnedQueryParam, missingParam: IDLearnedMissingQuery, contentType: IDLearnedContentType, bodySchema: IDLearnedBodyType,
	unknownProp: IDLearnedUnknownProperty, readOnly: IDLearnedBodyType, missingProp: IDLearnedMissingProperty,
	bodyMissing: IDLearnedBodyMissing, unexpectedBody: IDLearnedUnexpectedBody, unknownQuery: IDLearnedUnknownQuery,
	tooComplex: IDLearnedBodyType,
}

// reqView is a request prepared for checking. The query string and the JSON body are read at most once, and only if a check wants
// them, however many checks do.
type reqView struct {
	r      *inspect.Request
	ct     string
	body   []byte
	isJSON bool

	qdone  bool
	query  []qpair
	qmore  bool // pairs past maxQueryPairs were not read
	qstore [12]qpair

	parsed bool
	val    any
	dup    bool
	perr   error
}

func (v *reqView) init(r *inspect.Request) {
	v.r, v.body = r, r.Body
	v.ct = r.ContentType()
	v.isJSON = len(v.body) > 0 && isJSONType(v.ct)
}

// q returns the decoded query parameters of the request.
func (v *reqView) q() []qpair {
	if !v.qdone {
		v.qdone = true
		v.query, v.qmore = parseQuery(v.r.RawQuery, v.qstore[:0])
	}
	return v.query
}

// json parses the body once. It is only meaningful when isJSON.
func (v *reqView) json() (val any, dup bool, err error) {
	if !v.parsed {
		v.parsed = true
		v.val, v.dup, v.perr = parseJSON(v.body, jsonLimits{depth: bodyDepth, nodes: bodyNodes})
	}
	return v.val, v.dup, v.perr
}

// queryValues returns every value a query parameter was given.
func (v *reqView) queryValues(name string, buf []string) []string {
	for _, p := range v.q() {
		if p.name == name {
			buf = append(buf, p.value)
		}
	}
	return buf
}

func hasType(s *Schema, t string) bool {
	for _, x := range s.Type {
		if x == t {
			return true
		}
	}
	return false
}

// validateText checks the values given for a parameter against its schema. A value in a URL is text, so it is read as the type
// the schema asks for before it is checked. It returns what was wrong with it, if anything.
func (p *Param) validateText(vals []string) vkind {
	s := p.Schema
	if s == nil || len(vals) == 0 {
		return vkNone
	}
	isArray := hasType(s, "array")
	if hasType(s, "object") && !isArray {
		return vkNone // an object in a URL is written in styles this guard does not read
	}
	if isJSONType(p.Media) {
		// A parameter the description gives as JSON content is one JSON value, read as such before it is checked.
		if len(vals) > 1 {
			return vkRepeated
		}
		v, _, err := parseJSON([]byte(vals[0]), jsonLimits{depth: 16, nodes: 10_000})
		if err != nil {
			return vkType
		}
		c := &vctx{steps: 20_000, request: true}
		s.validate(v, c, 0)
		if c.over {
			return vkTooComplex
		}
		return c.first.kind
	}
	if isArray {
		// OpenAPI's defaults: style form for a query or cookie parameter and simple for a path or header one, and explode only for
		// form. A simple array is written 1,2,3 whether or not it is exploded.
		style := p.Style
		if style == "" {
			style = "form"
			if p.In == "path" || p.In == "header" {
				style = "simple"
			}
		}
		explode := style == "form"
		if p.Explode != nil {
			explode = *p.Explode
		}
		var delim byte
		switch {
		case style == "simple":
			delim = ','
		case explode:
			// Each item is a pair of its own.
		case style == "spaceDelimited":
			delim = ' '
		case style == "pipeDelimited":
			delim = '|'
		default:
			delim = ','
		}
		items := make([]any, 0, 8)
		for _, v := range vals {
			parts := []string{v}
			if delim != 0 {
				parts = strings.SplitN(v, string(delim), 1001)
			}
			for _, part := range parts {
				if len(items) >= 1000 {
					return vkLength
				}
				if p.In == "header" {
					part = strings.Trim(part, " \t") // a header list may have spaces around its commas (RFC 9110, section 5.6.1)
				}
				items = append(items, bestVariant(s.Items, part))
			}
		}
		c := &vctx{steps: 20_000, request: true}
		s.validate(items, c, 0)
		if c.over {
			return vkTooComplex
		}
		return c.first.kind
	}
	if len(vals) > 1 {
		return vkRepeated
	}
	var first vkind
	for i, variant := range scalarVariants(s, vals[0]) {
		c := &vctx{steps: 20_000, request: true}
		if s.validate(variant, c, 0) && !c.over {
			return vkNone
		}
		if i == 0 {
			first = c.first.kind
			if c.over {
				first = vkTooComplex
			}
		}
	}
	return first
}

// bestVariant picks the typed reading of an array item that satisfies its schema, or the first reading if none does (so the
// failure is reported against the most natural one).
func bestVariant(s *Schema, raw string) any {
	vs := scalarVariants(s, raw)
	for _, v := range vs {
		c := &vctx{steps: 2_000, request: true}
		if s.validate(v, c, 0) && !c.over {
			return v
		}
	}
	return vs[0]
}

// cookieValues finds every value a cookie is given in the Cookie headers. Servers differ about which of several they read,
// and browsers send several for cookies set on different paths, so each of them is checked.
func cookieValues(h http.Header, name string, buf []string) []string {
	for _, line := range h.Values("Cookie") {
		for rest := line; rest != ""; {
			var pair string
			pair, rest, _ = strings.Cut(rest, ";")
			pair = strings.TrimSpace(pair)
			k, v, ok := strings.Cut(pair, "=")
			// Go's net/http, Python and Node trim spaces and tabs around the name: "limit =9" is limit to them.
			if ok && strings.Trim(k, " \t") == name {
				buf = append(buf, strings.Trim(strings.Trim(v, " \t"), `"`))
			}
		}
	}
	return buf
}

// maxFindings is how many findings one request may produce from one route. The first is what decides; the rest are for the log.
const maxFindings = 6

// checkRoute checks a request against a route, described or learned, and returns what does not fit. Nothing it returns holds
// anything the visitor sent. preflight says the request is a CORS preflight for the route: it has the route's path and query,
// which are checked in full, and none of the credential, header values, cookies or body the route asks for, which are not
// required of it. What it does carry is checked all the same.
func (g *Guard) checkRoute(rt *Route, rv *reqView, caps *captures, ids *idSet, credNames *Model, preflight bool) []finding {
	var out []finding
	add := func(id int, detail string) bool {
		if id == 0 || len(out) >= maxFindings {
			return len(out) >= maxFindings
		}
		out = append(out, finding{id: id, detail: detail})
		return len(out) >= maxFindings
	}
	c := rt.c
	if c == nil {
		return nil
	}
	r := rv.r
	if rt.Secured && !preflight && !hasCredential(r.Header, r.RawQuery, credNames) {
		add(ids.noCredential, "")
	}
	// Path parameters (a learned route's are its template).
	for i := 0; i < caps.n && i < len(c.pathParams); i++ {
		p := c.pathParams[i]
		if p == nil || p.Schema == nil {
			continue
		}
		if k := p.validateText(caps.vals[i : i+1]); k != vkNone {
			add(ids.pathParam, paramDetail(ids, p.Name, k))
		}
	}
	// Query parameters. The application reads the pairs past the ones parsed here, so a query that has more is refused rather
	// than checked in part.
	if rv.q(); rv.qmore {
		add(ids.queryParam, "more query parameters than the guard reads")
	}
	// ASP.NET Core and echo bind a query name to the parameter it names in other letters (LIMIT for limit), so its values are held
	// to that parameter too. A required parameter must still be sent in the spelling it is given.
	// PHP reads page.size, "page size" and page[size as page_size, and PHP and Express read page_size[] and page_size[0] as an
	// array of page_size's values, so those are held to a scalar parameter of that name too.
	var respelled, mangled []qpair // named by foldName
	if len(c.queryFold) > 0 {
		for _, q := range rv.q() {
			if _, known := c.query[q.name]; known {
				continue
			}
			if f := foldName(q.name); c.queryFold[f] != nil {
				respelled = append(respelled, qpair{name: f, value: q.value})
			} else if php, _ := phpName(q.name); php != q.name {
				if f := foldName(php); c.queryFold[f] != nil {
					mangled = append(mangled, qpair{name: f, value: q.value})
				}
			}
		}
	}
	var vbuf [4]string
	for i := range rt.Params {
		p := &rt.Params[i]
		if p.In != "query" {
			continue
		}
		vals := rv.queryValues(p.Name, vbuf[:0])
		if len(vals) == 0 && p.Required {
			add(ids.missingParam, paramDetail(ids, p.Name, vkRequired))
		}
		for _, q := range respelled {
			if slices.Contains(c.queryFold[q.name], p.Name) {
				vals = append(vals, q.value)
			}
		}
		for _, q := range mangled {
			if scalarParam(p) && slices.Contains(c.queryFold[q.name], p.Name) {
				vals = append(vals, q.value)
			}
		}
		if len(vals) == 0 {
			continue
		}
		if k := p.validateText(vals); k != vkNone {
			add(ids.queryParam, paramDetail(ids, p.Name, k))
		}
	}
	if (rt.StrictQuery || (ids.named && g.config().RefuseUnknownParams)) && len(rv.q()) > 0 {
		for _, q := range rv.q() {
			// The API key the description's security scheme puts in the query is the description's own parameter.
			if credNames != nil && slices.Contains(credNames.CredentialQuery, q.name) {
				continue
			}
			if _, known := c.query[q.name]; !known {
				if !hasDeepObjectPrefix(c, q.name) {
					add(ids.unknownQuery, "")
					break
				}
			}
		}
	}
	// Header and cookie parameters (described routes only).
	for _, p := range c.headers {
		vals := r.Header.Values(p.Name)
		if len(vals) == 0 {
			if p.Required && !preflight {
				add(ids.missingParam, paramDetail(ids, p.Name, vkRequired))
			}
			continue
		}
		if k := p.validateText(vals); k != vkNone {
			add(ids.headerParam, paramDetail(ids, p.Name, k))
		}
	}
	for _, p := range c.cookies {
		vals := cookieValues(r.Header, p.Name, vbuf[:0])
		if len(vals) == 0 {
			if p.Required && !preflight {
				add(ids.missingParam, paramDetail(ids, p.Name, vkRequired))
			}
			continue
		}
		for _, v := range vals {
			if k := p.validateText([]string{v}); k != vkNone {
				add(ids.cookieParam, paramDetail(ids, p.Name, k))
				break
			}
		}
	}
	// The body. One with no Content-Type is application/octet-stream (RFC 9110, section 8.3), which a described route that lists
	// its media types takes only if it says so. What was learned says nothing about such bodies: they are not recorded.
	hasBody := len(rv.body) > 0
	switch {
	case hasBody && rt.NoBody:
		add(ids.unexpectedBody, "")
	case hasBody && rv.ct != "" && !rt.acceptsContentType(rv.ct):
		add(ids.contentType, "")
	case hasBody && rv.ct == "" && ids.named && !rt.acceptsContentType("application/octet-stream"):
		add(ids.contentType, "the body has no Content-Type")
	case !hasBody && rt.BodyRequired && !preflight:
		add(ids.bodyMissing, "")
	}
	// A route that takes any type (*/*, application/*) holds a body that starts like JSON to its schema whatever it was sent as:
	// Go's encoding/json, gin and FastAPI bind it as JSON. One that does not read as JSON is the application's.
	asJSON := rv.isJSON && !(rt.c.hasCTypes && !rt.acceptsContentType(rv.ct))
	if !rv.isJSON && hasBody && rt.Body != nil && rt.c.jsonBody && startsLikeJSON(rv.body) {
		asJSON = rt.acceptsContentType(cmp.Or(rv.ct, "application/octet-stream"))
	}
	if hasBody && rt.Body != nil && asJSON {
		// A body this parser cannot read (nested past its depth, or not UTF-8) may still be one the application's decoder reads,
		// so it is refused rather than let through unchecked.
		val, _, err := rv.json()
		switch {
		case errors.Is(err, errTooDeep) || errors.Is(err, errTooMany):
			add(ids.tooComplex, "")
		case err != nil:
			if rv.isJSON {
				add(ids.bodySchema, "the body is not valid JSON")
			}
		default:
			viol, ok, over := rt.Body.validateBody(val, true)
			switch {
			case over:
				add(ids.tooComplex, "")
			case !ok:
				id := ids.bodySchema
				switch viol.kind {
				case vkUnknownProp:
					id = ids.unknownProp
				case vkReadOnly:
					id = ids.readOnly
				case vkRequired:
					id = ids.missingProp
				}
				detail := viol.kind.String()
				if ids.named && viol.where != "" {
					detail += " at " + clean(viol.where, 80)
				}
				add(id, "the body "+detail)
			}
		}
	}
	return out
}

// hasDeepObjectPrefix reports whether a query name such as filter[x] belongs to a described object parameter (written
// name[key]=value), which is listed by its base name.
// scalarParam says a parameter takes one plain value: not an array, an object or a value in a media type, whose names in brackets
// are the parameter's own.
func scalarParam(p *Param) bool {
	return p.Media == "" && p.Style != "deepObject" && p.Schema != nil && !hasType(p.Schema, "array") && !hasType(p.Schema, "object")
}

func hasDeepObjectPrefix(c *routeC, name string) bool {
	if i := strings.IndexByte(name, '['); i > 0 {
		p, ok := c.query[name[:i]]
		return ok && p.Style == "deepObject" && p.Schema != nil && hasType(p.Schema, "object")
	}
	return false
}

// paramDetail words a parameter finding. The name is put in only where it is the owner's.
func paramDetail(ids *idSet, name string, k vkind) string {
	if ids.named {
		return "parameter " + clean(name, 60) + " " + k.String()
	}
	return "a parameter " + k.String()
}
