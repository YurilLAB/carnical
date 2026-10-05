// Package formats is Carnical's strict reader for request bodies. A firewall and the application behind it each parse the same body,
// and where their parsers differ (which of two equal JSON keys wins, whether a DOCTYPE is read, how a multipart body without a
// final boundary ends, whether a UTF-16 body is decoded) an attacker writes the body that one reads as harmless and the other
// as an attack. The WAFFLED research found 1,207 bypasses of five WAFs in exactly these differences.
//
// This package does not try to predict what the application will do. It reads each body format with a parser of its own that
// accepts only what RFC grammar allows, refuses what is ambiguous, and has a limit on everything an attacker can make large. If the
// firewall will not read a body two ways, there is no second way for the application to read it.
//
// Inspector implements inspect.Inspector. It keeps nothing between requests, so one value serves any number of them at once. Every
// refusal has an identifier from 5002000 to 5002999 (see Rules and docs/formats.md) and a message that names the rule and a byte
// position or a limit, never any of the request's content.
package formats

import (
	"strings"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// Inspector checks request bodies against a Policy.
type Inspector struct {
	pol      Policy
	act      []Action
	types    typeSet
	opaque   opaqueSet
	charsets map[string]bool
	gqlPaths map[string]bool
	err      error
}

// New builds an Inspector. Call Policy.Validate first and handle its error: an Inspector built from a policy that fails it is not a
// way to run with a weaker policy. It refuses every request that has a body (policy-invalid, 5002990) and says why in Err.
func New(p Policy) *Inspector {
	if err := p.Validate(); err != nil {
		in := &Inspector{err: err}
		in.act = in.actions(Policy{})
		return in
	}
	p = p.withDefaults()
	in := &Inspector{pol: p, types: newTypeSet(p.AllowedTypes), opaque: newOpaqueSet(p.AllowOpaque), charsets: map[string]bool{}, gqlPaths: map[string]bool{}}
	for _, c := range p.AllowedCharsets {
		in.charsets[c] = true
	}
	for _, g := range p.GraphQLPaths {
		in.gqlPaths[g] = true
	}
	in.act = in.actions(p)
	return in
}

// Err is why the policy was refused, or nil.
func (in *Inspector) Err() error { return in.err }

// Name implements inspect.Inspector.
func (in *Inspector) Name() string { return "formats" }

// actions resolves the action of every rule once, so that the check on the request path is an array lookup.
func (in *Inspector) actions(p Policy) []Action {
	act := make([]Action, len(registry))
	for _, r := range registry {
		a := r.def
		if v, ok := p.Rules[r.name]; ok {
			a = v
		}
		if p.Monitor && a == Block {
			a = Monitor
		}
		act[r.idx] = a
	}
	return act
}

// Inspect implements inspect.Inspector.
func (in *Inspector) Inspect(r *inspect.Request) (res inspect.Result) {
	f := &finder{in: in}
	defer func() {
		// A bug in a parser must not let a body through unchecked, nor take the process down.
		if p := recover(); p != nil {
			f.hit(rInternal, -1, dNone)
			res = inspect.Result{Verdicts: f.verdicts}
		}
	}()
	if in.err != nil {
		if len(r.Body) > 0 {
			f.hit(rPolicyInvalid, -1, dNone)
		}
		return inspect.Result{Verdicts: f.verdicts}
	}
	body, decoded := in.inspect(f, r)
	res.Verdicts = f.verdicts
	if decoded && !f.blocked {
		res.Body = body
		res.DelHeader = []string{"Content-Encoding"}
	}
	return res
}

// inspect runs the checks in order, stopping as soon as one refuses the request. It returns the body after decompression and
// whether there was any.
func (in *Inspector) inspect(f *finder, r *inspect.Request) (body []byte, decoded bool) {
	gqlPath := in.isGraphQLPath(r.Path)
	if r.RawQuery != "" && !in.queryCheck(f, r, gqlPath) {
		return nil, false
	}
	if len(r.Body) == 0 {
		return nil, false
	}
	if (r.Method == "GET" || r.Method == "HEAD") && f.hit(rBodyOnGet, -1, dNone) {
		return nil, false
	}
	if len(r.Body) > in.pol.MaxBodyBytes && f.hitLimit(rBodyTooLarge, dNone, in.pol.MaxBodyBytes, -1) {
		return nil, false
	}
	ci, ok := in.contentType(f, r)
	if !ok {
		return nil, false
	}
	body = r.Body
	if enc := r.Header.Values("Content-Encoding"); len(enc) > 0 {
		out, did, ok := in.decodeBody(f, enc, body)
		if !ok {
			return nil, false
		}
		if did {
			body, decoded = out, true
			if len(body) > in.pol.MaxBodyBytes && f.hitLimit(rBodyTooLarge, dNone, in.pol.MaxBodyBytes, -1) {
				return nil, false
			}
		}
	}
	if len(body) == 0 {
		return body, decoded
	}
	in.checkBody(f, ci, body, gqlPath)
	return body, decoded
}

// ctInfo is what the Content-Type header says about the body.
type ctInfo struct {
	mt      mediaType
	kind    kind
	charset string // lower case, or "" if none was given
	present bool
}

func (in *Inspector) contentType(f *finder, r *inspect.Request) (ctInfo, bool) {
	var ci ctInfo
	vals := r.Header.Values("Content-Type")
	if len(vals) > 1 && f.hit(rTypeDupHeader, -1, dNone) {
		return ci, false
	}
	if len(vals) == 0 || strings.Trim(vals[0], " \t") == "" {
		return ci, !f.hit(rTypeMissing, -1, dNone)
	}
	ci.present = true
	mt, pr := parseMediaType(vals[0])
	if pr != nil {
		rl := rTypeMalformed
		if pr.kind == pkDuplicate {
			rl = rTypeDupParam
		}
		if f.hit(rl, pr.off, pr.d) {
			return ci, false
		}
	}
	ci.mt = mt
	if in.isOpaque(mt) {
		if !in.opaque.has(mt.typ + "/" + mt.sub) {
			if f.hit(rTypeOpaque, -1, dNone) {
				return ci, false
			}
			ci.kind = kindOther
		} else {
			ci.kind = kindOpaque
		}
	} else {
		if !in.types.has(mt.typ, mt.sub) && f.hit(rTypeNotAllowed, -1, dNone) {
			return ci, false
		}
		ci.kind = kindOf(mt)
	}
	if cs, ok := mt.param("charset"); ok {
		ci.charset = strings.ToLower(cs)
		if !in.charsets[ci.charset] && f.hit(rCharset, -1, dNone) {
			return ci, false
		}
	}
	return ci, true
}

// checkBody applies the format's checks to a body (decompressed, if it was compressed).
func (in *Inspector) checkBody(f *finder, ci ctInfo, body []byte, gqlPath bool) {
	switch ci.kind {
	case kindOpaque:
		if len(body) > in.pol.OpaqueMaxBytes {
			f.hitLimit(rOpaqueTooLarge, dNone, in.pol.OpaqueMaxBytes, -1)
		}
		return
	case kindForm, kindMultipart, kindText, kindNone:
		if !in.checkSniff(f, ci, body) {
			return
		}
	}
	switch ci.kind {
	case kindForm:
		var capture *gqlParams
		if gqlPath {
			capture = &gqlParams{}
		}
		if !in.checkForm(f, body, ci.charsetIsUTF8(), capture) {
			return
		}
		if capture != nil {
			in.graphQLParams(f, capture, true)
		}
	case kindMultipart:
		boundary, _ := ci.mt.param("boundary")
		in.checkMultipart(f, body, boundary, ci.mt.sub)
	case kindJSON:
		in.checkJSONBody(f, ci, body, gqlPath)
	case kindNDJSON:
		in.checkNDJSON(f, ci, body)
	case kindXML:
		in.checkXML(f, ci, body)
	case kindGraphQL:
		in.checkGraphQLBody(f, ci, body)
	case kindYAML:
		in.checkYAML(f, ci, body)
	}
}

// charsetIsUTF8 reports whether text in the body is to be read as UTF-8: it is unless the Content-Type names a single-byte charset.
func (ci ctInfo) charsetIsUTF8() bool {
	return ci.charset == "" || ci.charset == "utf-8" || ci.charset == "us-ascii"
}

// utf8Charset is for the formats that are UTF-8 by definition (JSON, GraphQL, YAML, NDJSON): a Content-Type that names a single-byte
// charset is only harmless if the body is plain ASCII, because otherwise the filter reads UTF-8 and a parser that honours the
// header reads something else. It returns false when the request is refused.
func (in *Inspector) utf8Charset(f *finder, ci ctInfo, body []byte) bool {
	if ci.charsetIsUTF8() {
		return true
	}
	for _, c := range body {
		if c >= 0x80 {
			return !f.hit(rCharset, -1, dCharsetNotUTF8)
		}
	}
	return true
}

func (in *Inspector) isGraphQLPath(path string) bool {
	if in.gqlPaths[path] {
		return true
	}
	for len(path) > 0 {
		var seg string
		seg, path, _ = strings.Cut(path, "/")
		if strings.EqualFold(seg, "graphql") || strings.EqualFold(seg, "graphiql") {
			return true
		}
	}
	return false
}
