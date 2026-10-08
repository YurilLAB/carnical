// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ErrNotOpenAPI is returned for a document that is not an OpenAPI 3.x or Swagger 2.0 description.
var ErrNotOpenAPI = errors.New("the document is not an OpenAPI 3.x or Swagger 2.0 description")

// ErrTooComplex is returned when a description expands, once its references are followed, to more than the import allows.
var ErrTooComplex = errors.New("the description is too complex: it is larger than the limits once its references are followed")

// importBudget is how many schema and parameter nodes a description may expand to, counting each use of a reference in full. It
// is what stops a description whose references fan out (A uses B twice, B uses C twice, and so on) from describing a tree of
// billions of nodes in a few kilobytes.
const importBudget = 400_000

// ImportOpenAPI reads an OpenAPI 3.0 or 3.1 or Swagger 2.0 description, in JSON or YAML, and returns the model it describes.
//
// The description is not trusted. It is limited to 5 MiB and 500,000 values (counting each use of a YAML alias in full); only
// references inside the document ("#/...") are followed, never a file or an address; a reference that is not found, that points
// outside the document, or that loops back on itself is cut and reported, and what stands in its place accepts anything, so a
// description the importer cannot fully read refuses less, never more. A pattern that is not RE2 is dropped for the same reason.
func ImportOpenAPI(data []byte) (Model, Report, error) {
	rep := Report{Kind: "openapi", Source: "supplied", When: time.Now().UTC()}
	sum := sha256.Sum256(data)
	rep.Hash = hex.EncodeToString(sum[:])
	doc, err := parseDocument(data, defaultDocLimits)
	if err != nil {
		return Model{}, rep, err
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return Model{}, rep, ErrNotOpenAPI
	}
	im := &importer{root: root, rep: &rep, budget: importBudget, memo: map[string]*refMemo{}, inProgress: map[string]bool{}, ignored: map[string]int{}}
	switch v := scalarText(root["openapi"]); {
	case strings.HasPrefix(v, "3.0"):
		im.ver = "3.0"
		rep.Format = "openapi " + v
	case strings.HasPrefix(v, "3."):
		im.ver = "3.1"
		rep.Format = "openapi " + v
	case scalarText(root["swagger"]) == "2.0":
		im.ver = "2.0"
		rep.Format = "swagger 2.0"
	default:
		return Model{}, rep, ErrNotOpenAPI
	}
	if info, ok := root["info"].(map[string]any); ok {
		rep.Title = clean(scalarText(info["title"]), 120)
	}
	m := Model{Format: ModelFormat, Hash: rep.Hash, Title: rep.Title, SpecVersion: rep.Format}
	im.credentials(&m)
	paths, _ := root["paths"].(map[string]any)
	if paths == nil {
		rep.warn("the description has no paths")
	}
	names := make([]string, 0, len(paths))
	for p := range paths {
		names = append(names, p)
	}
	slices.Sort(names)
	bases := im.basePaths()
	for _, p := range names {
		if im.err != nil {
			break
		}
		im.pathItem(&m, p, paths[p], bases)
	}
	if im.err != nil {
		return Model{}, rep, im.err
	}
	if len(m.Routes) > MaxRoutes {
		return Model{}, rep, fmt.Errorf("the description has %d routes; the limit is %d", len(m.Routes), MaxRoutes)
	}
	if im.ignored != nil && len(im.ignored) > 0 {
		keys := make([]string, 0, len(im.ignored))
		for k := range im.ignored {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		rep.warn("schema keywords this guard does not check were ignored (the schema accepts more because of them): " + strings.Join(keys, ", "))
	}
	m.Defs = im.defs
	m.finish(rep.warn)
	rep.Routes = len(m.Routes)
	return m, rep, nil
}

type refMemo struct {
	s    *Schema
	size int
}

type importer struct {
	root       map[string]any
	ver        string // 2.0, 3.0 or 3.1
	rep        *Report
	budget     int
	err        error
	memo       map[string]*refMemo
	inProgress map[string]bool
	recursive  map[string]bool
	defs       map[string]*Schema
	ignored    map[string]int
	warned     map[string]bool
}

func (im *importer) charge(n int) {
	im.budget -= n
	if im.budget < 0 && im.err == nil {
		im.err = ErrTooComplex
	}
}

// warnOnce reports a condition the first time it happens, so one flaw repeated through a large description is one line.
func (im *importer) warnOnce(key, msg string) {
	if im.warned == nil {
		im.warned = map[string]bool{}
	}
	if !im.warned[key] {
		im.warned[key] = true
		im.rep.warn(msg)
	}
}

func scalarText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case Num:
		return string(x)
	}
	return ""
}

func asBool(v any) (b, ok bool) {
	b, ok = v.(bool)
	return
}

func asInt(v any) (int, bool) {
	n, ok := v.(Num)
	if !ok {
		return 0, false
	}
	i, ok := n.int64()
	if !ok || i < 0 || i > 1<<31 {
		return 0, false
	}
	return int(i), true
}

func (im *importer) schemaNumber(v any, keyword string) (float64, bool) {
	n, ok := v.(Num)
	if !ok {
		if v != nil {
			if _, boolean := v.(bool); !boolean || (keyword != "exclusiveMinimum" && keyword != "exclusiveMaximum") {
				im.err = fmt.Errorf("schema %s must be numeric", keyword)
			}
		}
		return 0, false
	}
	f, ok := n.exactFloat()
	if !ok {
		im.err = fmt.Errorf("schema %s cannot be retained exactly as a finite decimal", keyword)
	}
	if keyword == "multipleOf" && ok && f <= 0 {
		im.err = errors.New("schema multipleOf must be positive")
		return 0, false
	}
	return f, ok
}

// resolve follows a local reference such as #/components/schemas/Pet. It never looks outside the document.
func (im *importer) resolve(ref string) (any, bool) {
	if len(ref) > 512 || !strings.HasPrefix(ref, "#") {
		return nil, false
	}
	ref = ref[1:]
	var cur any = im.root
	if ref == "" {
		return cur, true
	}
	if ref[0] != '/' {
		return nil, false
	}
	steps := 0
	for _, part := range strings.Split(ref[1:], "/") {
		if steps++; steps > 16 {
			return nil, false
		}
		if u, err := url.PathUnescape(part); err == nil {
			part = u
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch c := cur.(type) {
		case map[string]any:
			next, ok := c[part]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(c) {
				return nil, false
			}
			cur = c[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// deref follows a chain of references to the object they end at (a parameter or a request body, which are written as references
// as often as inline). A chain longer than sixteen, or one that loops, ends in nil.
func (im *importer) deref(node any) map[string]any {
	for i := 0; i < 16; i++ {
		m, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		ref, isRef := m["$ref"].(string)
		if !isRef {
			return m
		}
		target, ok := im.resolve(ref)
		if !ok {
			im.warnOnce("ref:"+ref, "a reference could not be followed: "+ref)
			return nil
		}
		node = target
	}
	im.warnOnce("refchain", "a chain of references is longer than 16 and was cut")
	return nil
}

// ---- schemas ----

func (im *importer) schema(node any, depth int) *Schema {
	if im.err != nil {
		return &Schema{}
	}
	if depth > maxSchemaDepth {
		im.warnOnce("depth", fmt.Sprintf("a schema nested deeper than %d levels was cut and accepts anything below that", maxSchemaDepth))
		return &Schema{}
	}
	switch x := node.(type) {
	case bool:
		if x {
			return &Schema{}
		}
		return &Schema{Not: &Schema{}}
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok {
			return im.schemaRef(ref, x, depth)
		}
		return im.schemaBody(x, depth)
	}
	return &Schema{}
}

func (im *importer) schemaRef(ref string, holder map[string]any, depth int) *Schema {
	if memo, ok := im.memo[ref]; ok {
		im.charge(memo.size)
		return im.withFlags(memo.s, holder)
	}
	if im.inProgress[ref] {
		// The schema is being read and refers to itself: it is named, and what refers to it points at the name.
		if im.recursive == nil {
			im.recursive = map[string]bool{}
		}
		im.recursive[ref] = true
		im.charge(1)
		return im.withFlags(&Schema{Ref: ref}, holder)
	}
	target, ok := im.resolve(ref)
	if !ok {
		im.warnOnce("ref:"+ref, "a schema reference could not be followed (it is missing, or it points outside the document): "+ref)
		im.charge(1)
		return &Schema{}
	}
	im.inProgress[ref] = true
	before := im.budget
	s := im.schema(target, depth+1)
	delete(im.inProgress, ref)
	im.memo[ref] = &refMemo{s: s, size: before - im.budget}
	if im.recursive[ref] {
		if im.defs == nil {
			im.defs = map[string]*Schema{}
		}
		if len(im.defs) >= 1000 {
			im.err = ErrTooComplex
		}
		im.defs[ref] = s
	}
	return im.withFlags(s, holder)
}

// withFlags applies the few keywords that may sit beside a $ref (nullable, readOnly, writeOnly) to a copy of the schema it
// points at. Other keywords beside a $ref are ignored, as OpenAPI 3.0 says.
func (im *importer) withFlags(s *Schema, holder map[string]any) *Schema {
	n, ro, wo := false, false, false
	if v, ok := asBool(holder["nullable"]); ok && v {
		n = true
	}
	if v, ok := asBool(holder["readOnly"]); ok && v {
		ro = true
	}
	if v, ok := asBool(holder["writeOnly"]); ok && v {
		wo = true
	}
	if !n && !ro && !wo {
		return s
	}
	cp := *s
	cp.Nullable = cp.Nullable || n
	cp.ReadOnly = cp.ReadOnly || ro
	cp.WriteOnly = cp.WriteOnly || wo
	return &cp
}

var schemaTypes = map[string]bool{"integer": true, "number": true, "string": true, "boolean": true, "object": true, "array": true, "null": true}

// ignoredKeywords are the schema keywords that are valid and that this guard does not check.
var ignoredKeywords = []string{"if", "then", "else", "patternProperties", "dependentRequired", "dependentSchemas", "dependencies",
	"unevaluatedProperties", "unevaluatedItems", "prefixItems", "contains", "propertyNames", "contentMediaType", "contentEncoding"}

func (im *importer) schemaBody(m map[string]any, depth int) *Schema {
	im.charge(1)
	s := &Schema{}
	switch t := m["type"].(type) {
	case string:
		if schemaTypes[t] {
			s.Type = []string{t}
		}
	case []any:
		for _, e := range t {
			if name, ok := e.(string); ok && schemaTypes[name] {
				s.Type = append(s.Type, name)
			}
		}
		if len(s.Type) != len(t) {
			s.Type = nil // a type this guard does not know: accept any
		}
	}
	if v, ok := asBool(m["nullable"]); ok {
		s.Nullable = v
	}
	if f, ok := m["format"].(string); ok && len(f) <= 32 {
		s.Format = f
	}
	if list, ok := m["enum"].([]any); ok {
		if len(list) > 1000 {
			im.warnOnce("enum", "an enum with more than 1000 values was ignored")
		} else {
			for _, e := range list {
				s.Enum = append(s.Enum, JSONValue{e})
			}
		}
	}
	if c, ok := m["const"]; ok && im.ver == "3.1" {
		s.Const = &JSONValue{c}
	}
	if f, ok := im.schemaNumber(m["minimum"], "minimum"); ok {
		if ex, _ := asBool(m["exclusiveMinimum"]); ex {
			s.ExclusiveMinimum = &f
		} else {
			s.Minimum = &f
		}
	}
	if f, ok := im.schemaNumber(m["maximum"], "maximum"); ok {
		if ex, _ := asBool(m["exclusiveMaximum"]); ex {
			s.ExclusiveMaximum = &f
		} else {
			s.Maximum = &f
		}
	}
	if f, ok := im.schemaNumber(m["exclusiveMinimum"], "exclusiveMinimum"); ok {
		s.ExclusiveMinimum = &f
	}
	if f, ok := im.schemaNumber(m["exclusiveMaximum"], "exclusiveMaximum"); ok {
		s.ExclusiveMaximum = &f
	}
	if f, ok := im.schemaNumber(m["multipleOf"], "multipleOf"); ok && f > 0 {
		s.MultipleOf = &f
	}
	if n, ok := asInt(m["minLength"]); ok {
		s.MinLength = &n
	}
	if n, ok := asInt(m["maxLength"]); ok {
		s.MaxLength = &n
	}
	if p, ok := m["pattern"].(string); ok {
		if len(p) <= maxPatternBytes {
			s.Pattern = p
		} else {
			im.warnOnce("pattern-len", "a pattern longer than 512 bytes was ignored")
		}
	}
	if n, ok := asInt(m["minItems"]); ok {
		s.MinItems = &n
	}
	if n, ok := asInt(m["maxItems"]); ok {
		s.MaxItems = &n
	}
	if b, ok := asBool(m["uniqueItems"]); ok {
		s.UniqueItems = b
	}
	if n, ok := asInt(m["minProperties"]); ok {
		s.MinProperties = &n
	}
	if n, ok := asInt(m["maxProperties"]); ok {
		s.MaxProperties = &n
	}
	if b, ok := asBool(m["readOnly"]); ok {
		s.ReadOnly = b
	}
	if b, ok := asBool(m["writeOnly"]); ok {
		s.WriteOnly = b
	}
	if props, ok := m["properties"].(map[string]any); ok {
		if len(props) > 1000 {
			im.err = ErrTooComplex
			return s
		}
		s.Properties = make(map[string]*Schema, len(props))
		names := make([]string, 0, len(props))
		for k := range props {
			names = append(names, k)
		}
		slices.Sort(names)
		for _, k := range names {
			s.Properties[k] = im.schema(props[k], depth+1)
		}
	}
	if req, ok := m["required"].([]any); ok {
		for _, e := range req {
			if name, ok := e.(string); ok && len(s.Required) < 1000 {
				s.Required = append(s.Required, name)
			}
		}
	}
	switch ap := m["additionalProperties"].(type) {
	case bool:
		s.AdditionalProperties = &ap
	case map[string]any:
		s.AdditionalSchema = im.schema(ap, depth+1)
	}
	if it, ok := m["items"]; ok {
		if _, isList := it.([]any); !isList {
			s.Items = im.schema(it, depth+1)
		} else {
			im.warnOnce("items-list", "an items list (a tuple) was ignored")
		}
	}
	s.AllOf = im.schemaList(m["allOf"], depth)
	s.AnyOf = im.schemaList(m["anyOf"], depth)
	s.OneOf = im.schemaList(m["oneOf"], depth)
	if n, ok := m["not"]; ok {
		s.Not = im.schema(n, depth+1)
	}
	for _, k := range ignoredKeywords {
		if _, ok := m[k]; ok {
			im.ignored[k]++
		}
	}
	return s
}

func (im *importer) schemaList(v any, depth int) []*Schema {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	if len(list) > 64 {
		im.err = ErrTooComplex
		return nil
	}
	out := make([]*Schema, 0, len(list))
	for _, e := range list {
		out = append(out, im.schema(e, depth+1))
	}
	return out
}

// ---- servers, security ----

// basePaths are the path prefixes the API is served under, from the servers (or basePath in Swagger 2).
func (im *importer) basePaths() []string {
	var out []string
	add := func(p string) {
		p = strings.TrimRight(p, "/")
		if p != "" && p[0] != '/' {
			p = "/" + p
		}
		if !slices.Contains(out, p) && len(out) < 4 {
			out = append(out, p)
		}
	}
	if im.ver == "2.0" {
		bp, _ := im.root["basePath"].(string)
		add(bp)
	} else if servers, ok := im.root["servers"].([]any); ok {
		for _, s := range servers {
			sm, _ := s.(map[string]any)
			u, _ := sm["url"].(string)
			if vars, ok := sm["variables"].(map[string]any); ok {
				for name, v := range vars {
					if vm, ok := v.(map[string]any); ok {
						if def := scalarText(vm["default"]); def != "" {
							u = strings.ReplaceAll(u, "{"+name+"}", def)
						}
					}
				}
			}
			if i := strings.Index(u, "://"); i >= 0 {
				rest := u[i+3:]
				if j := strings.IndexByte(rest, '/'); j >= 0 {
					u = rest[j:]
				} else {
					u = ""
				}
			}
			if i := strings.IndexAny(u, "?#"); i >= 0 {
				u = u[:i]
			}
			add(u)
		}
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

// credentials notes where the description says a credential goes (an apiKey scheme names a header, a query parameter or a cookie).
func (im *importer) credentials(m *Model) {
	var schemes map[string]any
	if im.ver == "2.0" {
		schemes, _ = im.root["securityDefinitions"].(map[string]any)
	} else if c, ok := im.root["components"].(map[string]any); ok {
		schemes, _ = c["securitySchemes"].(map[string]any)
	}
	names := make([]string, 0, len(schemes))
	for k := range schemes {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, k := range names {
		sm := im.deref(schemes[k])
		if sm == nil || sm["type"] != "apiKey" {
			continue
		}
		name, _ := sm["name"].(string)
		if name == "" || len(name) > 64 {
			continue
		}
		switch sm["in"] {
		case "header":
			if len(m.CredentialHeaders) < 16 {
				m.CredentialHeaders = append(m.CredentialHeaders, strings.ToLower(name))
			}
		case "query":
			if len(m.CredentialQuery) < 16 {
				m.CredentialQuery = append(m.CredentialQuery, name)
			}
		case "cookie":
			if len(m.CredentialCookies) < 16 {
				m.CredentialCookies = append(m.CredentialCookies, name)
			}
		}
	}
}

// secured reports whether an operation needs a credential: its own security list if it has one, else the document's, and a list
// that has an empty requirement in it allows anonymous access.
func (im *importer) secured(op map[string]any) bool {
	sec, has := op["security"]
	if !has {
		sec = im.root["security"]
	}
	list, ok := sec.([]any)
	if !ok || len(list) == 0 {
		return false
	}
	for _, e := range list {
		if m, ok := e.(map[string]any); ok && len(m) == 0 {
			return false
		}
	}
	return true
}

// ---- paths and operations ----

var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch"}

func (im *importer) pathItem(m *Model, path string, node any, bases []string) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") || len(path) > 1000 {
		im.rep.warn("a path that is not a path template was skipped: " + path)
		return
	}
	if strings.Count(path, "{") != strings.Count(path, "}") {
		im.rep.warn("a path with unbalanced braces was skipped: " + path)
		return
	}
	item := im.deref(node)
	if item == nil {
		return
	}
	shared := im.params(item["parameters"])
	for _, method := range httpMethods {
		opNode, ok := item[method]
		if !ok {
			continue
		}
		op, ok := opNode.(map[string]any)
		if !ok {
			continue
		}
		for _, base := range bases {
			if len(m.Routes) > MaxRoutes {
				im.err = fmt.Errorf("the description has more than %d routes", MaxRoutes)
				return
			}
			full := base + path
			if full == "" {
				full = "/"
			}
			m.Routes = append(m.Routes, im.operation(strings.ToUpper(method), full, shared, op))
		}
	}
	for _, other := range []string{"trace", "connect"} {
		if _, ok := item[other]; ok {
			im.warnOnce("method:"+other, "a "+strings.ToUpper(other)+" operation was ignored (the method is not allowed by the guard)")
		}
	}
}

// params reads a parameter list, following references.
func (im *importer) params(v any) []Param {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []Param
	for _, e := range list {
		if len(out) >= MaxParamsPerRoute {
			im.err = ErrTooComplex
			return out
		}
		pm := im.deref(e)
		if pm == nil {
			continue
		}
		in, _ := pm["in"].(string)
		name, _ := pm["name"].(string)
		if name == "" || len(name) > 256 {
			continue
		}
		switch in {
		case "path", "query", "header", "cookie":
		case "body":
			// Swagger 2: the one body parameter carries the schema of the body.
			im.charge(1)
			bp := Param{Name: name, In: "body", Schema: im.schema(pm["schema"], 0)}
			bp.Required, _ = asBool(pm["required"])
			out = append(out, bp)
			continue
		case "formData":
			fp := Param{Name: name, In: "formData"}
			if t, _ := pm["type"].(string); t == "file" {
				fp.Style = "file"
			}
			out = append(out, fp)
			continue
		default:
			continue
		}
		im.charge(1)
		p := Param{Name: name, In: in}
		p.Required, _ = asBool(pm["required"])
		if in == "path" {
			p.Required = true
		}
		if sch, ok := pm["schema"]; ok {
			p.Schema = im.schema(sch, 0)
		} else if content, ok := pm["content"].(map[string]any); ok {
			keys := make([]string, 0, len(content))
			for k := range content {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				if cm, ok := content[k].(map[string]any); ok {
					p.Schema = im.schema(cm["schema"], 0)
					break
				}
			}
		} else if im.ver == "2.0" {
			if t, _ := pm["type"].(string); t == "file" {
				continue
			}
			p.Schema = im.schemaBody(pm, 0)
			switch cf, _ := pm["collectionFormat"].(string); cf {
			case "multi":
				e := true
				p.Explode = &e
			case "ssv":
				e := false
				p.Style, p.Explode = "spaceDelimited", &e
			case "pipes":
				e := false
				p.Style, p.Explode = "pipeDelimited", &e
			default:
				e := false
				p.Explode = &e
			}
		}
		if s, ok := pm["style"].(string); ok && len(s) <= 16 {
			p.Style = s
		}
		if e, ok := asBool(pm["explode"]); ok {
			p.Explode = &e
		}
		out = append(out, p)
	}
	return out
}

func (im *importer) operation(method, path string, shared []Param, op map[string]any) Route {
	r := Route{Method: method, Path: path, State: StateDeclared, Secured: im.secured(op)}
	own := im.params(op["parameters"])
	// An operation's parameter overrides a path-level one with the same name and place.
	merged := make([]Param, 0, len(shared)+len(own))
	for _, p := range shared {
		if !hasParam(own, p) {
			merged = append(merged, p)
		}
	}
	merged = append(merged, own...)
	var bodyParam, formParam *Param
	formFile := false
	for i := range merged {
		p := &merged[i]
		switch p.In {
		case "path", "query", "header", "cookie":
			if p.In == "header" {
				switch strings.ToLower(p.Name) {
				case "content-type", "accept", "authorization":
					continue // OpenAPI says these are described elsewhere and a parameter of this name is ignored
				}
			}
			r.Params = append(r.Params, *p)
		case "body":
			bodyParam = p
		case "formData":
			formParam = p
			formFile = formFile || p.Style == "file"
		}
	}
	if len(r.Params) > MaxParamsPerRoute {
		im.err = ErrTooComplex
		return r
	}
	switch im.ver {
	case "2.0":
		im.bodyV2(&r, op, bodyParam, formParam, formFile)
	default:
		im.bodyV3(&r, op)
	}
	return r
}

func hasParam(list []Param, p Param) bool {
	for _, q := range list {
		if q.Name == p.Name && q.In == p.In {
			return true
		}
	}
	return false
}

// mediaType makes a media type from a description comparable: lower case, no parameters.
func mediaType(s string) string {
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(strings.TrimSpace(s))
}

func (im *importer) bodyV3(r *Route, op map[string]any) {
	rb := im.deref(op["requestBody"])
	if rb == nil {
		r.NoBody = true
		return
	}
	r.BodyRequired, _ = asBool(rb["required"])
	content, _ := rb["content"].(map[string]any)
	keys := make([]string, 0, len(content))
	for k := range content {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	best, bestRank := "", 99
	for _, k := range keys {
		mt := mediaType(k)
		if mt == "" || len(r.ContentTypes) >= 32 {
			continue
		}
		if !slices.Contains(r.ContentTypes, mt) {
			r.ContentTypes = append(r.ContentTypes, mt)
		}
		rank := 99
		switch {
		case mt == "application/json":
			rank = 0
		case isJSONType(mt):
			rank = 1
		case mt == "application/*":
			rank = 2
		case mt == "*/*":
			rank = 3
		}
		if rank < bestRank {
			if cm, ok := content[k].(map[string]any); ok && cm["schema"] != nil {
				best, bestRank = k, rank
			}
		}
	}
	if best != "" {
		cm := content[best].(map[string]any)
		r.Body = im.schema(cm["schema"], 0)
	}
	if len(content) == 0 {
		r.NoBody = !r.BodyRequired
	}
}

func (im *importer) bodyV2(r *Route, op map[string]any, body, form *Param, formFile bool) {
	var consumes []string
	for _, src := range []any{op["consumes"], im.root["consumes"]} {
		if list, ok := src.([]any); ok && len(list) > 0 {
			for _, e := range list {
				if s, ok := e.(string); ok && len(consumes) < 32 {
					consumes = append(consumes, mediaType(s))
				}
			}
			break
		}
	}
	switch {
	case body != nil:
		r.Body, r.BodyRequired = body.Schema, body.Required
		if len(consumes) == 0 {
			consumes = []string{"application/json"}
		}
	case form != nil:
		if len(consumes) == 0 {
			consumes = []string{"application/x-www-form-urlencoded", "multipart/form-data"}
			if formFile {
				consumes = []string{"multipart/form-data"}
			}
		}
	default:
		r.NoBody = true
		return
	}
	r.ContentTypes = consumes
}
