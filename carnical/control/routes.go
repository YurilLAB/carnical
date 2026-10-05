// SPDX-License-Identifier: Apache-2.0

package control

import (
	"net/http"
	"sort"
	"strings"
)

type bodyKind int

const (
	bodyNone     bodyKind = iota // the request takes no body
	bodyEnvelope                 // one of the API's own JSON objects: strictly decoded, unknown fields refused
	bodyDocument                 // a policy document: any JSON object, opaque to this package
)

// route is one endpoint. The fields say, once, what the dispatcher checks before the handler runs, so a new endpoint
// cannot forget the checks: the scope, the tenant (taken from the pattern itself) and the body rules are all here.
type route struct {
	method  string
	pattern string
	segs    []seg
	scope   Scope // "" only for the public health check
	action  string

	public     bool
	tenant     bool // the pattern contains {tenant}: derived, not declared
	allTenants bool // credential management: needs a credential for all tenants
	mutating   bool // changes something: audited before and after
	body       bodyKind
	query      []string
	// stepUp is true when the endpoint may demand a step-up (documentation and tests read it)
	stepUp bool

	handle func(rc *reqCtx) (*result, *apiError)
}

type seg struct {
	literal string // for a fixed segment
	param   string // for {name}[suffix]
	suffix  string
}

// RouteInfo describes an endpoint for documentation and tests.
type RouteInfo struct {
	Method     string
	Pattern    string
	Scope      Scope
	Public     bool
	Tenant     bool
	AllTenants bool
	Mutating   bool
	StepUp     bool
	Action     string
}

// Routes lists every endpoint. The tests walk this list so that a route added later is checked like the others.
func (s *Server) Routes() []RouteInfo {
	out := make([]RouteInfo, 0, len(s.routes))
	for _, r := range s.routes {
		out = append(out, RouteInfo{Method: r.method, Pattern: r.pattern, Scope: r.scope, Public: r.public, Tenant: r.tenant,
			AllTenants: r.allTenants, Mutating: r.mutating, StepUp: r.stepUp, Action: r.action})
	}
	return out
}

func compile(rt *route) *route {
	for _, part := range strings.Split(rt.pattern[1:], "/") {
		if strings.HasPrefix(part, "{") {
			end := strings.IndexByte(part, '}')
			sg := seg{param: part[1:end], suffix: part[end+1:]}
			if sg.param == "tenant" {
				rt.tenant = true
			}
			rt.segs = append(rt.segs, sg)
		} else {
			rt.segs = append(rt.segs, seg{literal: part})
		}
	}
	return rt
}

func (rt *route) matchPath(parts []string) (map[string]string, bool) {
	if len(parts) != len(rt.segs) {
		return nil, false
	}
	var params map[string]string
	for i, sg := range rt.segs {
		if sg.param == "" {
			if parts[i] != sg.literal {
				return nil, false
			}
			continue
		}
		p := parts[i]
		if !strings.HasSuffix(p, sg.suffix) {
			return nil, false
		}
		v := p[:len(p)-len(sg.suffix)]
		if !validParam(sg.param, v) {
			return nil, false
		}
		if params == nil {
			params = map[string]string{}
		}
		params[sg.param] = v
	}
	return params, true
}

func validParam(name, v string) bool {
	switch name {
	case "tenant":
		return ValidTenantID(v)
	case "id":
		return ValidCredentialID(v)
	case "host":
		return validHostname(v)
	}
	return false
}

// match finds the route for a request, or says why there is none.
func (s *Server) match(method, target string) (*route, map[string]string, *apiError) {
	path, _, _ := strings.Cut(target, "?")
	parts := strings.Split(path[1:], "/")
	var found *route
	var params map[string]string
	var allow []string
	for _, rt := range s.routes {
		p, ok := rt.matchPath(parts)
		if !ok {
			continue
		}
		allow = append(allow, rt.method)
		if rt.method == method {
			found, params = rt, p
		}
	}
	if found != nil {
		return found, params, nil
	}
	if len(allow) == 0 {
		return nil, nil, &apiError{status: http.StatusNotFound, code: "not_found", msg: "there is nothing at this address"}
	}
	sort.Strings(allow)
	return nil, nil, &apiError{status: http.StatusMethodNotAllowed, code: "method_not_allowed", msg: "this method is not allowed here", allow: strings.Join(allow, ", ")}
}

// ------------------------------------------------------------------------------------------------ structure checks

// checkTarget enforces the one form of request target the API has: an absolute path of lower-case letters, digits and
// / : . -, optionally followed by ? and a query of letters, digits and = & _ . ~ -. No percent-encoding is ever
// needed, so none is allowed, which leaves no second way to write a path and nothing for a proxy and this server to
// read differently.
func checkTarget(t string) *apiError {
	bad := &apiError{status: http.StatusBadRequest, code: "bad_request", msg: "the request target is not valid"}
	if len(t) < 1 || len(t) > 2048 || t[0] != '/' {
		return bad
	}
	path, query, hasQuery := strings.Cut(t, "?")
	for i := 0; i < len(path); i++ {
		c := path[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '/' && c != ':' && c != '.' && c != '-' {
			return bad
		}
	}
	if hasQuery {
		if query == "" || len(query) > 1024 {
			return bad
		}
		for i := 0; i < len(query); i++ {
			c := query[i]
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '=' && c != '&' && c != '_' && c != '.' && c != '~' && c != '-' {
				return bad
			}
		}
	}
	return nil
}

// Headers that say "I was relayed", "treat this as another method" or "this is really another URL". None of them has
// any business reaching an API that is served directly over mutual TLS; one that does is either a misconfigured proxy
// or an attempt, and both are refused.
var deniedHeaders = map[string]bool{
	"x-forwarded-for": true, "x-forwarded-host": true, "x-forwarded-proto": true, "x-forwarded-port": true, "x-forwarded-server": true,
	"forwarded": true, "x-real-ip": true, "x-client-ip": true, "true-client-ip": true, "cf-connecting-ip": true, "x-cluster-client-ip": true,
	"x-original-url": true, "x-rewrite-url": true, "x-original-method": true,
	"x-http-method-override": true, "x-http-method": true, "x-method-override": true,
	"proxy-connection": true, "proxy-authorization": true, "te": true, "trailer": true, "upgrade": true, "content-encoding": true,
	"x-http-host-override": true, "x-forwarded-scheme": true, "x-host": true,
}

// Headers that carry meaning and so may appear only once.
var singleHeaders = map[string]bool{
	"authorization": true, "content-type": true, "content-length": true, "if-match": true, "idempotency-key": true,
	"carnical-acting-user": true, "carnical-stepup-at": true,
}

// checkHeaders refuses requests whose headers could be read two ways or are not meant for this API.
func (s *Server) checkHeaders(r *http.Request) *apiError {
	bad := func(msg string) *apiError { return errBadRequest(msg) }
	if r.ProtoMajor == 1 && r.ProtoMinor == 0 {
		return bad("HTTP/1.0 is not supported")
	}
	n, size := 0, 0
	for name, vals := range r.Header {
		lower := strings.ToLower(name)
		if strings.IndexByte(name, '_') >= 0 {
			return bad("a header name is not valid")
		}
		if deniedHeaders[lower] {
			return bad("a header is not accepted by this API")
		}
		if strings.HasPrefix(lower, "carnical-") && lower != "carnical-acting-user" && lower != "carnical-stepup-at" {
			return bad("a header is not accepted by this API")
		}
		if singleHeaders[lower] && len(vals) != 1 {
			return bad("a header must appear once")
		}
		for _, v := range vals {
			n++
			size += len(name) + len(v) + 4
			if len(v) > 4096 {
				return &apiError{status: http.StatusRequestHeaderFieldsTooLarge, code: "headers_too_large", msg: "a header is too large"}
			}
		}
	}
	if n > s.lim.MaxHeaders || size > s.lim.MaxHeaderBytes {
		return &apiError{status: http.StatusRequestHeaderFieldsTooLarge, code: "headers_too_large", msg: "the headers are too large"}
	}
	for _, te := range r.TransferEncoding {
		if te != "chunked" {
			return bad("this transfer encoding is not supported")
		}
	}
	return nil
}

func validUserID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 && !alnum {
			return false
		}
		if !alnum && c != '.' && c != '_' && c != '@' && c != ':' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

// validHostname is the rule for a hostname a customer may register: lower-case letters, digits and hyphens in labels
// of 1 to 63 characters, at least two labels, a last label that is letters (or an xn-- label), at most 253 characters
// in all, no address and no name that only means something inside a network.
func validHostname(h string) bool {
	if len(h) < 4 || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if strings.HasPrefix(tld, "xn--") {
		if len(tld) < 6 {
			return false
		}
	} else {
		if len(tld) < 2 {
			return false
		}
		for i := 0; i < len(tld); i++ {
			if tld[i] < 'a' || tld[i] > 'z' {
				return false
			}
		}
	}
	for _, sfx := range []string{".local", ".localhost", ".internal", ".lan", ".arpa", ".invalid", ".onion", ".corp", ".home"} {
		if strings.HasSuffix(h, sfx) {
			return false
		}
	}
	return h != "localhost"
}

// parseQuery reads the query of a request that has already passed checkTarget: only the named keys, each at most once,
// none empty.
func parseQuery(target string, allowed []string) (map[string]string, *apiError) {
	_, raw, has := strings.Cut(target, "?")
	if !has {
		return nil, nil
	}
	bad := errBadRequest("the query is not valid")
	out := map[string]string{}
	for _, kv := range strings.Split(raw, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || v == "" || k == "" {
			return nil, bad
		}
		known := false
		for _, a := range allowed {
			if a == k {
				known = true
			}
		}
		if !known {
			return nil, bad
		}
		if _, dup := out[k]; dup {
			return nil, bad
		}
		out[k] = v
	}
	return out, nil
}

// ------------------------------------------------------------------------------------------------ the table

func (s *Server) buildRoutes() []*route {
	rs := []*route{
		{method: "GET", pattern: "/healthz", public: true, handle: nil},

		{method: "GET", pattern: "/v1/tenants/{tenant}/policy", scope: ScopeRead, action: "policy.get", handle: s.getPolicy},
		{method: "PUT", pattern: "/v1/tenants/{tenant}/policy", scope: ScopeWrite, action: "policy.put", mutating: true, body: bodyDocument, stepUp: true, handle: s.putPolicy},
		{method: "POST", pattern: "/v1/tenants/{tenant}/policy:validate", scope: ScopeRead, action: "policy.validate", body: bodyDocument, handle: s.validatePolicy},
		{method: "GET", pattern: "/v1/tenants/{tenant}/policy/history", scope: ScopeRead, action: "policy.history", query: []string{"cursor", "limit"}, handle: s.policyHistory},
		{method: "POST", pattern: "/v1/tenants/{tenant}/policy:rollback", scope: ScopeWrite, action: "policy.rollback", mutating: true, body: bodyEnvelope, stepUp: true, handle: s.rollbackPolicy},
		{method: "POST", pattern: "/v1/tenants/{tenant}/publish", scope: ScopePublish, action: "policy.publish", mutating: true, body: bodyEnvelope, handle: s.publish},
		{method: "GET", pattern: "/v1/tenants/{tenant}/hosts", scope: ScopeRead, action: "hosts.list", handle: s.listHosts},
		{method: "POST", pattern: "/v1/tenants/{tenant}/hosts", scope: ScopeWrite, action: "hosts.add", mutating: true, body: bodyEnvelope, handle: s.addHost},
		{method: "POST", pattern: "/v1/tenants/{tenant}/hosts/{host}:verify", scope: ScopeWrite, action: "hosts.verify", mutating: true, handle: s.verifyHost},
		{method: "GET", pattern: "/v1/tenants/{tenant}/status", scope: ScopeRead, action: "status.get", handle: s.getStatus},
		{method: "GET", pattern: "/v1/tenants/{tenant}/events", scope: ScopeRead, action: "events.list", query: []string{"cursor", "limit"}, handle: s.listEvents},
		{method: "GET", pattern: "/v1/tenants/{tenant}/traffic", scope: ScopeRead, action: "traffic.list", query: []string{"cursor", "limit"}, handle: s.listTraffic},

		{method: "GET", pattern: "/v1/credentials", scope: ScopeAdmin, action: "credentials.list", allTenants: true, handle: s.listCredentials},
		{method: "POST", pattern: "/v1/credentials/{id}:revoke", scope: ScopeAdmin, action: "credentials.revoke", allTenants: true, mutating: true, handle: s.revokeCredential},
	}
	for _, r := range rs {
		compile(r)
	}
	return rs
}
