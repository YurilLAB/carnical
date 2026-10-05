// SPDX-License-Identifier: Apache-2.0

package formats

import (
	"strings"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// How a GraphQL request arrives: a JSON object {"query", "variables", "operationName", "extensions"}, an array of those (a batch),
// the whole body as application/graphql, a form with the same parameters, or a query string. This file finds the query in
// each and hands it to the parser in graphql.go, and checks the parts of the envelope that servers read differently.
//
// A request to a path that is a GraphQL endpoint must be a GraphQL request. A request anywhere else is only treated as GraphQL if its
// query parses as a GraphQL document, so that a search form with a "query" field is left alone.

// looksLikeGraphQL reports whether src starts the way an executable document does: a selection set, or an operation or fragment
// keyword followed by something that can follow it.
func looksLikeGraphQL(src []byte) bool {
	l := gqlLexer{src: src}
	if l.next() != dNone {
		return false
	}
	if l.isPunct('{') {
		return true
	}
	if l.kind != gName {
		return false
	}
	switch string(src[l.start:l.end]) {
	case "query", "mutation", "subscription", "fragment":
	default:
		return false
	}
	if l.next() != dNone {
		return false
	}
	return l.kind == gName || l.isPunct('{') || l.isPunct('(') || l.isPunct('@')
}

// graphQLDocument checks one document. With mustParse a document that does not parse is refused; without it, a document that does
// not look like GraphQL, or does not parse, is not GraphQL and is left alone. It returns whether the text was GraphQL and whether to
// go on.
func (in *Inspector) graphQLDocument(f *finder, src []byte, mustParse bool, operationName string) (isGQL, cont bool) {
	lim := &in.pol.GraphQL
	if !mustParse && !looksLikeGraphQL(src) {
		return false, true
	}
	if len(src) > lim.MaxQueryBytes {
		return true, !f.hitLimit(rGQLLimit, dQueryTooLarge, lim.MaxQueryBytes, -1)
	}
	if r, off := sourceProblem(src); r != nil {
		if mustParse {
			return true, !f.hit(r, off, dInGraphQL)
		}
		return false, true
	}
	doc, fail := parseGraphQL(src, lim)
	if fail != nil {
		if fail.r == rGQLSyntax && !mustParse {
			return false, true
		}
		return true, !f.hitLimit(fail.r, fail.d, fail.limit, fail.off)
	}
	if doc.intro && !lim.AllowIntrospection && f.hit(rGQLIntro, -1, dNone) {
		return true, false
	}
	rep := analyze(doc)
	switch {
	case rep.cycle && f.hit(rGQLFrag, -1, dFragmentCycle):
		return true, false
	case rep.unknown && f.hit(rGQLFrag, -1, dUnknownFragment):
		return true, false
	case rep.duplicate && f.hit(rGQLFrag, -1, dDuplicateDefinition):
		return true, false
	}
	for _, st := range rep.ops {
		switch {
		case st.depth > lim.MaxDepth && f.hitLimit(rGQLDepth, dNone, lim.MaxDepth, -1):
			return true, false
		case st.fields > lim.MaxFields && f.hitLimit(rGQLFields, dNone, lim.MaxFields, -1):
			return true, false
		case st.aliases > lim.MaxAliases && f.hitLimit(rGQLAliases, dNone, lim.MaxAliases, -1):
			return true, false
		case st.dirs > lim.MaxDirectives && f.hitLimit(rGQLDirs, dNone, lim.MaxDirectives, -1):
			return true, false
		}
	}
	op, index, valid := selectedOperation(doc, operationName)
	if !valid {
		return true, !f.hit(rGQLShape, -1, dOperationSelection)
	}
	if f.mutationRule != nil && op.opType == "mutation" && f.hit(f.mutationRule, -1, dNone) {
		return true, false
	}
	if f.hitGraphQLMethod() {
		return true, false
	}
	f.graphql.add(rep.ops[index])
	switch {
	case f.graphql.fields > lim.MaxRequestFields && f.hitLimit(rGQLRequestFields, dNone, lim.MaxRequestFields, -1):
		return true, false
	case f.graphql.aliases > lim.MaxRequestAliases && f.hitLimit(rGQLRequestAliases, dNone, lim.MaxRequestAliases, -1):
		return true, false
	case f.graphql.dirs > lim.MaxRequestDirectives && f.hitLimit(rGQLRequestDirs, dNone, lim.MaxRequestDirectives, -1):
		return true, false
	}
	return true, true
}

// selectedOperation follows GraphQL's operation selection rules without executing the document.
// Duplicate names and an anonymous operation beside another operation are invalid regardless of the selected name.
func selectedOperation(doc *gqlDoc, name string) (*gqlDef, int, bool) {
	var selected *gqlDef
	index, selectedIndex := 0, -1
	names := make(map[string]bool, doc.ops)
	for i := range doc.defs {
		op := &doc.defs[i]
		if op.fragment {
			continue
		}
		if names[op.name] || op.name == "" && doc.ops != 1 {
			return nil, -1, false
		}
		names[op.name] = true
		if name == op.name || name == "" && doc.ops == 1 {
			selected = op
			selectedIndex = index
		}
		index++
	}
	return selected, selectedIndex, selected != nil
}

// checkGraphQLBody checks an application/graphql body: the whole body is the document.
func (in *Inspector) checkGraphQLBody(f *finder, ci ctInfo, body []byte) bool {
	if !in.utf8Charset(f, ci, body) {
		return false
	}
	start, ok := f.textStart(body)
	if !ok {
		return false
	}
	_, cont := in.graphQLDocument(f, body[start:], true, "")
	return cont && !f.hitGraphQLOverride(false) && !f.hitIfMixedGraphQL()
}

// checkJSONBody checks a JSON body, and as GraphQL if it is a GraphQL request.
func (in *Inspector) checkJSONBody(f *finder, ci ctInfo, body []byte, gqlPath bool) bool {
	if !in.utf8Charset(f, ci, body) {
		return false
	}
	c := &jsonCapture{max: in.pol.GraphQL.MaxBatch + 1}
	if !scanJSON(f, body, &in.pol.JSON, c, true) {
		return false
	}
	return in.graphQLEnvelope(f, body, c, gqlPath || f.urlGraphQL)
}

// graphQLEnvelope checks what a JSON body says about GraphQL: one request or a batch.
func (in *Inspector) graphQLEnvelope(f *finder, body []byte, c *jsonCapture, gqlPath bool) bool {
	lim := &in.pol.GraphQL
	switch c.kind {
	case '{':
		return in.graphQLRequest(f, body, c.members, gqlPath)
	case '[':
		if !gqlPath && !c.graphQLPossible {
			return true
		}
		if c.nelems > lim.MaxBatch && f.hitLimit(rGQLBatch, dNone, lim.MaxBatch, -1) {
			return false
		}
		for i := range c.elems {
			if c.elems[i].kind != '{' {
				if f.hit(rGQLShape, -1, dBatchElement) {
					return false
				}
				continue
			}
			if !in.graphQLRequest(f, body, c.elems[i].members, true) {
				return false
			}
		}
		return true
	}
	if gqlPath {
		return !f.hit(rGQLShape, -1, dRootNotObject)
	}
	return true
}

// graphQLRequest checks one request object: its query, and that variables, operationName and extensions have the types the
// protocol gives them (a server that reads variables sent as a string, and one that does not, see different requests).
func (in *Inspector) graphQLRequest(f *finder, body []byte, members []jsonMember, mustParse bool) bool {
	var query, vars, opn, ext *jsonMember
	var override, caseAlias bool
	isGQL := mustParse
	for i := range members {
		m := &members[i]
		override = override || methodOverrideParam(m.key)
		canonical := graphQLParamName(m.key)
		caseAlias = caseAlias || canonical != "" && m.key != canonical
		switch canonical {
		case "query":
			query = m
		case "variables":
			vars = m
		case "operationName":
			opn = m
		case "extensions":
			ext = m
		}
	}
	// Read operationName before the query: JSON member order cannot change which operation is selected.
	var name string
	if opn != nil && opn.kind == '"' {
		name = decodeJSONString(body[opn.start+1:opn.end-1], true)
	}
	if query != nil {
		switch query.kind {
		case 'n':
		case '"':
			src := []byte(decodeJSONString(body[query.start+1:query.end-1], true))
			g, cont := in.graphQLDocument(f, src, mustParse, name)
			if !cont {
				return false
			}
			isGQL = isGQL || g
		default:
			if mustParse && f.hit(rGQLShape, query.start, dQueryNotString) {
				return false
			}
		}
	}
	if !isGQL {
		return true
	}
	if caseAlias && f.hit(rGQLShape, -1, dProtocolCaseAlias) {
		return false
	}
	if f.hitGraphQLOverride(override) {
		return false
	}
	if (query != nil || vars != nil || opn != nil || ext != nil) && (f.hitGraphQLMethod() || f.hitIfMixedGraphQL()) {
		return false
	}
	if vars != nil && vars.kind != '{' && vars.kind != 'n' && f.hit(rGQLShape, vars.start, dVariablesNotObject) {
		return false
	}
	if opn != nil && opn.kind != '"' && opn.kind != 'n' && f.hit(rGQLShape, opn.start, dOperationNameNotString) {
		return false
	}
	if ext != nil && ext.kind != '{' && ext.kind != 'n' && f.hit(rGQLShape, ext.start, dExtensionsNotObject) {
		return false
	}
	return true
}

// graphQLParams checks a GraphQL request that arrived as parameters (a query string or a form): a query, and variables as a JSON
// string. mustParse is true for a GraphQL endpoint.
func (in *Inspector) graphQLParams(f *finder, g *gqlParams, mustParse bool) bool {
	if g.duplicate {
		if (mustParse || g.looksGQL) && f.hit(rGQLShape, -1, dGivenTwice) {
			return false
		}
	}
	isGQL := mustParse
	if g.hasQuery {
		gql, cont := in.graphQLDocument(f, []byte(g.query), mustParse, g.operationName)
		if !cont {
			return false
		}
		isGQL = isGQL || gql
	}
	if !isGQL {
		return true
	}
	if g.present() && f.hitGraphQLMethod() {
		return false
	}
	if g.caseAlias && f.hit(rGQLShape, -1, dProtocolCaseAlias) {
		return false
	}
	if f.hitGraphQLOverride(g.override) {
		return false
	}
	g.isGraphQL = true
	for _, param := range []struct {
		value string
		wrong detail
	}{{g.variables, dVariablesNotObject}, {g.extensions, dExtensionsNotObject}} {
		if param.value == "" {
			continue
		}
		c := &jsonCapture{max: 1}
		if !scanJSON(f, []byte(param.value), &in.pol.JSON, c, false) {
			return false
		}
		if c.kind != '{' && c.kind != 'n' && f.hit(rGQLShape, -1, param.wrong) {
			return false
		}
	}
	return true
}

// mutationRuleForMethod retains the GET-specific policy rule while protecting the other safe HTTP methods as well.
// HEAD can be dispatched to an origin's GET handler. Method tokens remain case-sensitive, as in HTTP.
func mutationRuleForMethod(method string) *rule {
	switch method {
	case "GET":
		return rGQLGetMutation
	case "HEAD", "OPTIONS", "TRACE":
		return rGQLSafeMutation
	default:
		return nil
	}
}

// hitGraphQLMethod is a separate transport guard: disabling a mutation-specific rule must not enable nonstandard transports.
// This is a local policy, not a claim that GraphQL forbids servers from implementing other HTTP methods.
func (f *finder) hitGraphQLMethod() bool {
	return f.method != "GET" && f.method != "POST" && f.hit(rGQLHTTPMethod, -1, dNone)
}

func (f *finder) hitIfMixedGraphQL() bool {
	return f.urlProtocol && f.hit(rGQLMixedTransport, -1, dNone)
}

// Recognize protocol case aliases during inspection, then refuse their ambiguous spelling.
// Forwarding never rewrites a name or depends on the origin doing the same folding.
func graphQLParamName(name string) string {
	for _, canonical := range [...]string{"query", "variables", "operationName", "extensions"} {
		if strings.EqualFold(name, canonical) {
			return canonical
		}
	}
	return ""
}

// Only top-level transport metadata is reserved; variables remain application data.
// Bracket forms are covered because frameworks can turn them into an override parameter.
func methodOverrideParam(name string) bool {
	return strings.EqualFold(name, "_method") || len(name) > len("_method") &&
		strings.EqualFold(name[:len("_method")], "_method") && name[len("_method")] == '['
}

func (f *finder) hitGraphQLOverride(bodyOverride bool) bool {
	return (bodyOverride || f.urlOverride) && f.hit(rGQLMethodOverride, -1, dNone)
}

// queryCheck validates all query strings and discovers GraphQL on every method.
// It returns false when the caller should stop.
func (in *Inspector) queryCheck(f *finder, r *inspect.Request, gqlPath bool) bool {
	raw := r.RawQuery
	if len(raw) > in.pol.MaxQueryBytes {
		f.hitLimit(rQuerySize, dNone, in.pol.MaxQueryBytes, -1)
		return !f.blocked // retain the scan bound in monitor/off, then continue inspecting the body
	}
	var g gqlParams
	ok := checkParameters(f, []byte(raw), &in.pol.Query, true, &g, queryParameterRules)
	f.urlProtocol = g.present()
	f.urlOverride = g.override
	if !ok {
		return !f.blocked // a parser limit must not skip body inspection in monitor/off
	}
	cont := in.graphQLParams(f, &g, gqlPath)
	f.urlGraphQL = g.isGraphQL
	return cont
}
