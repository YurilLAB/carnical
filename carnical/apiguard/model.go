// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// State says how a route came to be known and how far it is trusted.
type State string

const (
	// StateDeclared: the route is in an API description the owner supplied or promoted.
	StateDeclared State = "declared"
	// StateCandidate: the route is in a description found by discovery that has not been promoted yet. It refuses nothing.
	StateCandidate State = "candidate"
	// StateEnforceable: the route was learned from traffic and has enough support (see LearnConfig) to be enforced.
	StateEnforceable State = "learned-enforceable"
	// StateLearning: the route has been seen but not often enough, or not from enough different clients, to be enforced.
	StateLearning State = "learning"
)

// ModelState is the state of a whole described model.
type ModelState string

const (
	ModelCandidate ModelState = "candidate"
	ModelActive    ModelState = "active"
)

// ModelFormat is the version of the saved form. A file with another version is refused rather than guessed at.
const ModelFormat = 1

// Limits on a model, whether imported, learned or loaded from disk.
const (
	MaxRoutes         = 5000
	MaxParamsPerRoute = 64
	MaxPathSegments   = 32
	maxPathParams     = 16
	maxModelBytes     = 32 << 20
	maxSchemaNodes    = 500_000
)

// Param is one declared parameter of a route.
type Param struct {
	Name     string  `json:"name"`
	In       string  `json:"in"` // path, query, header or cookie
	Required bool    `json:"required,omitempty"`
	Schema   *Schema `json:"schema,omitempty"`
	// Style and Explode say how an array is written in the URL (form with explode: a=1&a=2; form without: a=1,2).
	Style   string `json:"style,omitempty"`
	Explode *bool  `json:"explode,omitempty"`
}

// Route is one method on one path template, with what the API says it takes.
type Route struct {
	Method string `json:"method"`
	// Path is the template, such as /users/{id}/orders. A learned route's parameters are named for what they matched: {int},
	// {uuid}, {hex}, {token}, {date} or {id}.
	Path  string `json:"path"`
	State State  `json:"state"`

	Params []Param `json:"params,omitempty"`
	// ContentTypes are the media types a request body may have (lower case; may hold a wildcard such as application/*).
	ContentTypes []string `json:"contentTypes,omitempty"`
	// Body is the schema of a JSON request body.
	Body         *Schema `json:"body,omitempty"`
	BodyRequired bool    `json:"bodyRequired,omitempty"`
	// NoBody means the route takes no request body.
	NoBody bool `json:"noBody,omitempty"`
	// Secured means the description says a credential is expected.
	Secured bool `json:"secured,omitempty"`
	// StrictQuery means a query parameter that is not listed is a finding. Learned routes set it; a described route follows
	// Config.RefuseUnknownParams.
	StrictQuery bool `json:"strictQuery,omitempty"`

	// Learned holds the evidence behind a learned route.
	Learned *LearnedRoute `json:"learned,omitempty"`

	c *routeC
}

// Model is what the guard knows about an API: the routes and what each takes.
type Model struct {
	Format      int        `json:"format"`
	Source      string     `json:"source,omitempty"` // where a described model came from (a path or "supplied")
	Title       string     `json:"title,omitempty"`
	SpecVersion string     `json:"specVersion,omitempty"` // such as "openapi 3.0.3"
	Fetched     time.Time  `json:"fetched,omitzero"`
	Hash        string     `json:"hash,omitempty"` // SHA-256 of the description
	State       ModelState `json:"state,omitempty"`

	// CredentialHeaders, CredentialQuery and CredentialCookies are where the description says a credential goes, in addition to the
	// usual places (Authorization, X-API-Key, api_key and access_token).
	CredentialHeaders []string `json:"credentialHeaders,omitempty"`
	CredentialQuery   []string `json:"credentialQuery,omitempty"`
	CredentialCookies []string `json:"credentialCookies,omitempty"`

	// Collapsed lists the path positions a learned model turned into parameters, and Seed is the key its client identifiers were
	// made with, so that a saved model keeps counting the same clients as the same.
	Collapsed []string `json:"collapsed,omitempty"`
	Seed      uint64   `json:"seed,omitempty"`
	// SeenContentTypes is the evidence for each content type seen on API requests, for the shield's check of unseen ones.
	SeenContentTypes map[string]*Evidence `json:"seenContentTypes,omitempty"`

	// Defs holds the schemas that refer back to themselves, by the name Schema.Ref gives.
	Defs map[string]*Schema `json:"defs,omitempty"`

	Routes []Route `json:"routes"`

	idx *index
}

// routeC is what a route needs to be checked quickly, derived from the route and never saved.
type routeC struct {
	pathNames  []string
	pathParams []*Param // aligned with pathNames; nil where the template names a parameter the route does not declare
	query      map[string]*Param
	headers    []*Param
	cookies    []*Param
	required   []*Param // required query, header and cookie parameters
	ctypes     []string
	jsonBody   bool
	hasCTypes  bool
}

// MarshalJSON writes the model in its versioned form.
func (m Model) MarshalJSON() ([]byte, error) {
	type plain Model
	p := plain(m)
	p.Format = ModelFormat
	if p.Routes == nil {
		p.Routes = []Route{}
	}
	return json.Marshal(p)
}

// UnmarshalJSON reads a saved model strictly: an unknown field, a version it does not know, a document over the size limit, or
// anything that breaks the model's own limits is an error, and the receiver is left as it was.
func (m *Model) UnmarshalJSON(data []byte) error {
	if len(data) > maxModelBytes {
		return fmt.Errorf("the saved model is %d bytes; the limit is %d", len(data), maxModelBytes)
	}
	type plain Model
	var p plain
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("the saved model is not readable: %w", err)
	}
	// Parse once with the bounded, exact-number reader as well. This catches
	// trailing data and ambiguous keys, and keeps schema bounds from rounding
	// silently during the float64 decode above.
	raw, duplicates, err := parseJSON(data, jsonLimits{depth: 2*maxSchemaDepth + 16, nodes: 8 * maxSchemaNodes})
	if err != nil || duplicates {
		return errors.New("the saved model is not unambiguous bounded JSON")
	}
	root, err := foldModelFields(raw)
	if err != nil {
		return err
	}
	defs, _ := root["defs"].(map[string]any)
	for _, schema := range defs {
		if err := checkRawSchemaNumbers(schema); err != nil {
			return err
		}
	}
	routes, _ := root["routes"].([]any)
	for _, entry := range routes {
		route, err := foldModelFields(entry)
		if err != nil {
			return err
		}
		if err := checkRawSchemaNumbers(route["body"]); err != nil {
			return err
		}
		params, _ := route["params"].([]any)
		for _, entry := range params {
			param, err := foldModelFields(entry)
			if err != nil {
				return err
			}
			if err := checkRawSchemaNumbers(param["schema"]); err != nil {
				return err
			}
		}
	}
	if p.Format != ModelFormat {
		return fmt.Errorf("the saved model has format %d; this build reads format %d", p.Format, ModelFormat)
	}
	loaded := Model(p)
	if err := loaded.validateLoaded(); err != nil {
		return err
	}
	loaded.finish(nil)
	*m = loaded
	return nil
}

// validateLoaded checks a model that came from outside against the model's own limits.
func (m *Model) validateLoaded() error {
	if len(m.Routes) > MaxRoutes {
		return fmt.Errorf("the saved model has %d routes; the limit is %d", len(m.Routes), MaxRoutes)
	}
	if len(m.Collapsed) > maxPositions || len(m.CredentialHeaders) > 16 || len(m.CredentialQuery) > 16 || len(m.CredentialCookies) > 16 {
		return errors.New("the saved model has more entries than allowed")
	}
	if m.State != "" && m.State != ModelCandidate && m.State != ModelActive {
		return errors.New("the saved model has an unknown state")
	}
	if len(m.SeenContentTypes) > 32 {
		return errors.New("the saved model has too many content types")
	}
	for ct, e := range m.SeenContentTypes {
		if e == nil || !validMediaType(ct) {
			return errors.New("the saved model has an invalid content type record")
		}
		if err := e.validate(); err != nil {
			return err
		}
	}
	nodes := 0
	if len(m.Defs) > 1000 {
		return errors.New("the saved model has too many named schemas")
	}
	for name, d := range m.Defs {
		if len(name) > 512 || d == nil {
			return errors.New("the saved model has an invalid named schema")
		}
		if err := checkSchema(d, 0, &nodes); err != nil {
			return err
		}
	}
	for i := range m.Routes {
		r := &m.Routes[i]
		if !validMethodToken(r.Method) || len(r.Path) == 0 || len(r.Path) > 1024 || r.Path[0] != '/' {
			return errors.New("the saved model has a route with an invalid method or path")
		}
		switch r.State {
		case StateDeclared, StateCandidate, StateEnforceable, StateLearning:
		default:
			return errors.New("the saved model has a route with an unknown state")
		}
		if len(r.Params) > MaxParamsPerRoute || len(r.ContentTypes) > 32 {
			return errors.New("the saved model has a route with too many parameters or content types")
		}
		for j := range r.Params {
			p := &r.Params[j]
			switch p.In {
			case "path", "query", "header", "cookie":
			default:
				return errors.New("the saved model has a parameter with an unknown location")
			}
			if err := checkSchema(p.Schema, 0, &nodes); err != nil {
				return err
			}
		}
		if err := checkSchema(r.Body, 0, &nodes); err != nil {
			return err
		}
		if r.Learned != nil {
			if err := r.Learned.validate(&nodes); err != nil {
				return err
			}
		}
	}
	return nil
}

// encoding/json accepts case-insensitive struct field names. Inspect the same
// fields and reject case aliases that could otherwise carry competing bounds.
func foldModelFields(v any) (map[string]any, error) {
	source, ok := v.(map[string]any)
	if !ok {
		return nil, nil
	}
	out := make(map[string]any, len(source))
	for key, value := range source {
		// Serialized struct field names are ASCII. Application keys under
		// properties and enum values are not visited here.
		for _, r := range key {
			if r > 127 {
				return nil, errors.New("the saved model has a non-ASCII field name")
			}
		}
		name := strings.ToLower(key)
		if _, exists := out[name]; exists {
			return nil, errors.New("the saved model has ambiguous field aliases")
		}
		out[name] = value
	}
	return out, nil
}

// checkRawSchemaNumbers visits only schema positions. Objects in enum/const
// are application values, even when they contain a property named "minimum".
func checkRawSchemaNumbers(v any) error {
	s, err := foldModelFields(v)
	if err != nil || s == nil {
		return err
	}
	for _, keyword := range []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"} {
		n, ok := s[strings.ToLower(keyword)].(Num)
		if !ok {
			continue
		}
		f, ok := n.exactFloat()
		if !ok || (keyword == "multipleOf" && f <= 0) {
			return fmt.Errorf("saved schema %s cannot be retained exactly as a valid finite decimal", keyword)
		}
	}
	properties, _ := s["properties"].(map[string]any)
	for _, child := range properties {
		if err := checkRawSchemaNumbers(child); err != nil {
			return err
		}
	}
	for _, keyword := range []string{"items", "not", "additionalSchema"} {
		if err := checkRawSchemaNumbers(s[strings.ToLower(keyword)]); err != nil {
			return err
		}
	}
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		children, _ := s[keyword].([]any)
		for _, child := range children {
			if err := checkRawSchemaNumbers(child); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkSchema bounds a loaded schema: its depth, its size and the shape of what it holds.
func checkSchema(s *Schema, depth int, nodes *int) error {
	if s == nil {
		return nil
	}
	if *nodes++; *nodes > maxSchemaNodes {
		return errors.New("the saved model's schemas are too large")
	}
	if depth > maxSchemaDepth {
		return errors.New("the saved model has a schema nested too deeply")
	}
	if len(s.Ref) > 512 || len(s.Properties) > 1000 || len(s.Enum) > 1000 || len(s.OneOf) > 64 || len(s.AnyOf) > 64 || len(s.AllOf) > 64 || len(s.Pattern) > maxPatternBytes {
		return errors.New("the saved model has a schema with too many entries")
	}
	for _, bound := range []*float64{s.Minimum, s.Maximum, s.ExclusiveMinimum, s.ExclusiveMaximum, s.MultipleOf} {
		if bound != nil {
			if _, ok := floatDecimal(*bound); !ok {
				return errors.New("schema has a nonfinite numeric constraint")
			}
		}
	}
	if s.MultipleOf != nil && *s.MultipleOf <= 0 {
		return errors.New("schema multipleOf must be positive")
	}
	for _, p := range s.Properties {
		if err := checkSchema(p, depth+1, nodes); err != nil {
			return err
		}
	}
	for _, sub := range [][]*Schema{s.OneOf, s.AnyOf, s.AllOf, {s.Items, s.Not, s.AdditionalSchema}} {
		for _, x := range sub {
			if err := checkSchema(x, depth+1, nodes); err != nil {
				return err
			}
		}
	}
	return nil
}

func validMethodToken(m string) bool {
	if m == "" || len(m) > 16 {
		return false
	}
	for i := 0; i < len(m); i++ {
		if m[i] < 'A' || m[i] > 'Z' {
			return false
		}
	}
	return true
}

// finish derives what checking needs from the routes: the compiled form of each, the route index, and the patterns and enum
// values of every schema. It reports each pattern that could not be used through warn (which may be nil).
func (m *Model) finish(warn func(string)) {
	slices.SortStableFunc(m.Routes, func(a, b Route) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return strings.Compare(a.Method, b.Method)
	})
	seen := map[*Schema]bool{}
	patterns := map[string]*regexp.Regexp{}
	dropped := 0
	for i := range m.Routes {
		r := &m.Routes[i]
		r.compile()
		for j := range r.Params {
			r.Params[j].Schema.prepare(seen, patterns, &dropped)
		}
		r.Body.prepare(seen, patterns, &dropped)
	}
	for _, d := range m.Defs {
		d.prepare(seen, patterns, &dropped)
	}
	m.resolveRefs()
	if dropped > 0 && warn != nil {
		warn(fmt.Sprintf("%d pattern(s) are not RE2 or are too large for the engine and were ignored (the schema is more permissive for them)", dropped))
	}
	m.idx = buildIndex(m.Routes, warn)
}

// resolveRefs connects each Ref to the schema it names. A name that is not in Defs (a hand-edited file) stays unresolved, which
// accepts anything.
func (m *Model) resolveRefs() {
	seen := map[*Schema]bool{}
	var walk func(s *Schema)
	walk = func(s *Schema) {
		if s == nil || seen[s] {
			return
		}
		seen[s] = true
		if s.Ref != "" {
			s.ref = m.Defs[s.Ref]
		}
		for _, p := range s.Properties {
			walk(p)
		}
		walk(s.AdditionalSchema)
		walk(s.Items)
		walk(s.Not)
		for _, list := range [][]*Schema{s.OneOf, s.AnyOf, s.AllOf} {
			for _, sub := range list {
				walk(sub)
			}
		}
	}
	for i := range m.Routes {
		for j := range m.Routes[i].Params {
			walk(m.Routes[i].Params[j].Schema)
		}
		walk(m.Routes[i].Body)
	}
	for _, d := range m.Defs {
		walk(d)
	}
}

// compile derives the quick form of one route.
func (r *Route) compile() {
	c := &routeC{query: map[string]*Param{}}
	for _, seg := range splitTemplate(r.Path) {
		if seg.kind != segLiteral {
			c.pathNames = append(c.pathNames, seg.names...)
		}
	}
	c.pathParams = make([]*Param, len(c.pathNames))
	for i := range r.Params {
		p := &r.Params[i]
		switch p.In {
		case "path":
			for k, n := range c.pathNames {
				if n == p.Name {
					c.pathParams[k] = p
				}
			}
		case "query":
			c.query[p.Name] = p
			if p.Required {
				c.required = append(c.required, p)
			}
		case "header":
			c.headers = append(c.headers, p)
			if p.Required {
				c.required = append(c.required, p)
			}
		case "cookie":
			c.cookies = append(c.cookies, p)
			if p.Required {
				c.required = append(c.required, p)
			}
		}
	}
	c.ctypes = r.ContentTypes
	c.hasCTypes = len(r.ContentTypes) > 0
	for _, ct := range r.ContentTypes {
		if isJSONType(ct) || ct == "*/*" || ct == "application/*" {
			c.jsonBody = true
		}
	}
	r.c = c
}

// acceptsContentType reports whether the route's description lists the media type (or a wildcard that covers it).
func (r *Route) acceptsContentType(ct string) bool {
	if r.c == nil || !r.c.hasCTypes {
		return true
	}
	for _, want := range r.c.ctypes {
		if want == ct || want == "*/*" {
			return true
		}
		if strings.HasSuffix(want, "/*") && strings.HasPrefix(ct, want[:len(want)-1]) {
			return true
		}
	}
	return false
}

// isJSONType reports whether a media type is JSON: application/json, text/json or anything that ends in +json.
func isJSONType(ct string) bool {
	return ct == "application/json" || ct == "text/json" || strings.HasSuffix(ct, "+json")
}

// segKind says how one segment of a path template matches.
type segKind uint8

const (
	segLiteral segKind = iota
	segParam           // the whole segment is {name}
	segAffix           // a literal before and after one {name}
)

type tmplSeg struct {
	kind   segKind
	lit    string // the literal, or for an affix the prefix
	suffix string
	names  []string
}

// splitTemplate breaks a path template into segments. The leading slash is dropped; a trailing slash is ignored.
func splitTemplate(p string) []tmplSeg {
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return nil
	}
	parts := strings.Split(p, "/")
	out := make([]tmplSeg, 0, len(parts))
	for _, part := range parts {
		s := tmplSeg{}
		open := strings.IndexByte(part, '{')
		closing := strings.IndexByte(part, '}')
		switch {
		case open < 0 || closing < open:
			s.kind = segLiteral
			s.lit = unescapeSegment(part)
		case open == 0 && closing == len(part)-1 && strings.Count(part, "{") == 1:
			s.kind = segParam
			s.names = []string{part[1 : len(part)-1]}
		case strings.Count(part, "{") == 1 && strings.Count(part, "}") == 1:
			s.kind = segAffix
			s.lit = unescapeSegment(part[:open])
			s.suffix = unescapeSegment(part[closing+1:])
			s.names = []string{part[open+1 : closing]}
		default:
			// Several parameters in one segment: matched as one whole parameter, with every name kept.
			s.kind = segParam
			for _, piece := range strings.Split(part, "{")[1:] {
				if e := strings.IndexByte(piece, '}'); e >= 0 {
					s.names = append(s.names, piece[:e])
				}
			}
		}
		out = append(out, s)
	}
	return out
}

func unescapeSegment(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// index finds the routes for a request path. It is a trie keyed by path segment. A literal segment is tried before a segment with
// a prefix or suffix, and that before a plain parameter, and the search backs up when a branch has no route, so the most specific
// template that matches is always the one found, and one that is the only match is found whichever way it is written.
type index struct {
	root *trieNode
	n    int
}

type trieNode struct {
	lit      map[string]*trieNode
	affix    []affixEdge
	param    *trieNode
	byMethod map[string]*Route
	methods  []string // sorted, for the Allow list
}

type affixEdge struct {
	prefix, suffix string
	to             *trieNode
}

func buildIndex(routes []Route, warn func(string)) *index {
	ix := &index{root: &trieNode{}}
	dups := 0
	for i := range routes {
		r := &routes[i]
		n := ix.root
		for _, seg := range splitTemplate(r.Path) {
			switch seg.kind {
			case segLiteral:
				if n.lit == nil {
					n.lit = map[string]*trieNode{}
				}
				next := n.lit[seg.lit]
				if next == nil {
					next = &trieNode{}
					n.lit[seg.lit] = next
				}
				n = next
			case segAffix:
				var next *trieNode
				for _, e := range n.affix {
					if e.prefix == seg.lit && e.suffix == seg.suffix {
						next = e.to
					}
				}
				if next == nil {
					next = &trieNode{}
					n.affix = append(n.affix, affixEdge{seg.lit, seg.suffix, next})
				}
				n = next
			default:
				if n.param == nil {
					n.param = &trieNode{}
				}
				n = n.param
			}
		}
		if n.byMethod == nil {
			n.byMethod = map[string]*Route{}
		}
		if _, dup := n.byMethod[r.Method]; dup {
			dups++
			continue
		}
		n.byMethod[r.Method] = r
		n.methods = append(n.methods, r.Method)
		slices.Sort(n.methods)
		ix.n++
	}
	if dups > 0 && warn != nil {
		warn(fmt.Sprintf("%d route(s) repeat a method and path that differ only in parameter names; the first is used", dups))
	}
	return ix
}

// captures are the values of the parameters of a matched path, in template order.
type captures struct {
	vals [maxPathParams]string
	n    int
}

func (c *captures) push(v string) bool {
	if c.n >= len(c.vals) {
		return false
	}
	c.vals[c.n] = v
	c.n++
	return true
}

// lookup finds the node a path ends at.
func (ix *index) lookup(path string, c *captures) *trieNode {
	if ix == nil || ix.root == nil {
		return nil
	}
	var segs [MaxPathSegments]string
	n, ok := splitPath(path, segs[:])
	if !ok {
		return nil
	}
	return ix.root.walk(segs[:n], c)
}

// splitPath splits a request path into decoded segments. ok is false if there are more than fit, or a segment is not a valid
// escape (the proxy has already refused those, but this is a library).
func splitPath(path string, out []string) (n int, ok bool) {
	if len(path) == 0 || path[0] != '/' {
		return 0, false
	}
	p := path[1:]
	if len(p) > 0 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	if p == "" {
		return 0, true
	}
	for {
		i := strings.IndexByte(p, '/')
		seg := p
		if i >= 0 {
			seg = p[:i]
		}
		if n >= len(out) {
			return 0, false
		}
		if strings.IndexByte(seg, '%') >= 0 {
			u, err := url.PathUnescape(seg)
			if err != nil {
				return 0, false
			}
			seg = u
		}
		out[n] = seg
		n++
		if i < 0 {
			return n, true
		}
		p = p[i+1:]
	}
}

func (n *trieNode) walk(segs []string, c *captures) *trieNode {
	if len(segs) == 0 {
		if len(n.byMethod) > 0 {
			return n
		}
		return nil
	}
	s := segs[0]
	if next := n.lit[s]; next != nil {
		if found := next.walk(segs[1:], c); found != nil {
			return found
		}
	}
	mark := c.n
	for _, e := range n.affix {
		if len(s) > len(e.prefix)+len(e.suffix) && strings.HasPrefix(s, e.prefix) && strings.HasSuffix(s, e.suffix) {
			if !c.push(s[len(e.prefix) : len(s)-len(e.suffix)]) {
				continue
			}
			if found := e.to.walk(segs[1:], c); found != nil {
				return found
			}
			c.n = mark
		}
	}
	if n.param != nil && s != "" {
		if c.push(s) {
			if found := n.param.walk(segs[1:], c); found != nil {
				return found
			}
			c.n = mark
		}
	}
	return nil
}

// route returns the route for a method at a node: HEAD is served by a GET route if there is no HEAD one.
func (n *trieNode) route(method string) *Route {
	if r := n.byMethod[method]; r != nil {
		return r
	}
	if method == "HEAD" {
		return n.byMethod["GET"]
	}
	return nil
}

// Len reports how many routes the model holds.
func (m *Model) Len() int { return len(m.Routes) }
