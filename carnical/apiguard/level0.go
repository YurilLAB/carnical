// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"net/http"
	"net/url"
	"strings"
)

// ---- is this an API request? ----

// apiNames are the first path segments that mark an API.
var apiNames = map[string]bool{"api": true, "rest": true, "graphql": true, "wp-json": true, "_api": true, "services": true, "odata": true}

// isAPIPath reports whether a path starts like an API: /api, /rest, /graphql, /wp-json, /_api, /services, /odata, /api-... or
// /v1 to /v99.
func isAPIPath(p string) bool {
	if len(p) < 2 || p[0] != '/' {
		return false
	}
	seg := p[1:]
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	if len(seg) > 16 {
		return false
	}
	seg = strings.ToLower(seg)
	if apiNames[seg] {
		return true
	}
	if strings.HasPrefix(seg, "api-") || strings.HasPrefix(seg, "api_") {
		return true
	}
	// v1 to v99
	if len(seg) >= 2 && len(seg) <= 3 && seg[0] == 'v' && seg[1] >= '1' && seg[1] <= '9' {
		return len(seg) == 2 || (seg[2] >= '0' && seg[2] <= '9')
	}
	return false
}

// isAPIContentType reports whether a media type is one that carries structured data for a program: JSON, XML or newline-delimited
// JSON.
func isAPIContentType(ct string) bool {
	switch ct {
	case "application/json", "application/xml", "text/xml", "text/json", "application/x-ndjson", "application/ndjson", "application/jsonl",
		"application/graphql", "application/json-seq":
		return true
	}
	return strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml")
}

// acceptsAPI reports whether an Accept header asks for structured data and not for a page. A browser's Accept lists
// application/xml among the page types, so a header that also asks for HTML is never taken as an API's.
func acceptsAPI(accept string) bool {
	if accept == "" {
		return false
	}
	found := false
	for rest := accept; rest != ""; {
		var tok string
		tok, rest, _ = strings.Cut(rest, ",")
		if i := strings.IndexByte(tok, ';'); i >= 0 {
			tok = tok[:i]
		}
		tok = strings.ToLower(strings.TrimSpace(tok))
		switch {
		case tok == "text/html" || tok == "application/xhtml+xml":
			return false
		case isAPIContentType(tok):
			found = true
		}
	}
	return found
}

// ---- authentication endpoints ----

// authExact are words that mark an authentication endpoint when they are a whole path segment (with the separators taken out).
var authExact = map[string]bool{"auth": true, "oauth": true, "oauth2": true, "otp": true, "2fa": true, "mfa": true,
	"authenticate": true, "authentication": true, "totp": true}

// authAffix are words that mark one when a segment starts or ends with them: resetpassword, forgot-password, refreshtoken, tokens.
var authAffix = []string{"login", "logon", "signin", "signup", "token", "password", "passwd", "reset", "forgot", "verify", "verification",
	"register", "registration"}

// isAuthPath reports whether a path looks like an authentication endpoint: login, signin, sign-in, token, oauth, auth, password,
// reset, forgot, otp, 2fa, mfa, verify, register or signup, as a path segment. "authors" is not "auth", and "presets" is not "reset".
func isAuthPath(p string) bool {
	for rest := p; rest != ""; {
		var seg string
		seg, rest, _ = strings.Cut(rest, "/")
		if seg == "" || len(seg) > 64 {
			continue
		}
		var buf [64]byte
		n := 0
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			switch {
			case c == '-' || c == '_' || c == '.':
				continue
			case c >= 'A' && c <= 'Z':
				c += 'a' - 'A'
			}
			buf[n] = c
			n++
		}
		s := string(buf[:n])
		if authExact[s] {
			return true
		}
		for _, w := range authAffix {
			if strings.HasPrefix(s, w) || strings.HasSuffix(s, w) {
				return true
			}
		}
	}
	return false
}

// ---- credentials ----

// credentialOf returns the credential a request presents, for the rate limiter to hash: Authorization, else X-API-Key, else an
// api_key or access_token parameter, else one the description names. It returns "" if there is none. The credential is never
// stored or logged: it is hashed with a key only this guard holds, and the hash is what the table keeps.
func credentialOf(h http.Header, query string, m *Model) string {
	if v := h.Get("Authorization"); v != "" {
		return v
	}
	if v := h.Get("X-Api-Key"); v != "" {
		return v
	}
	if m != nil {
		for _, name := range m.CredentialHeaders {
			if v := h.Get(name); v != "" {
				return v
			}
		}
	}
	if query != "" && (strings.Contains(query, "api_key") || strings.Contains(query, "apikey") || strings.Contains(query, "api-key") ||
		strings.Contains(query, "access_token") || (m != nil && len(m.CredentialQuery) > 0)) {
		var buf [16]qpair
		pairs, _ := parseQuery(query, buf[:0])
		for _, p := range pairs {
			switch strings.ToLower(p.name) {
			case "api_key", "apikey", "api-key", "access_token":
				if p.value != "" {
					return p.value
				}
			}
			if m != nil {
				for _, n := range m.CredentialQuery {
					if p.name == n && p.value != "" {
						return p.value
					}
				}
			}
		}
	}
	return ""
}

// hasCredential reports whether a request presents anything that could be a credential: the places credentialOf looks, and any
// cookie, since a session is a credential too.
func hasCredential(h http.Header, query string, m *Model) bool {
	if credentialOf(h, query, m) != "" || h.Get("Cookie") != "" {
		return true
	}
	return false
}

// ---- the query string ----

type qpair struct{ name, value string }

const maxQueryPairs = 256

// parseQuery splits a raw query string into decoded names and values, at most maxQueryPairs of them, and reports whether more
// were left unread. A piece that is not valid percent-encoding is kept as it was written.
func parseQuery(raw string, out []qpair) ([]qpair, bool) {
	for raw != "" && len(out) < maxQueryPairs {
		var part string
		part, raw, _ = strings.Cut(raw, "&")
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		out = append(out, qpair{queryUnescape(name), queryUnescape(value)})
	}
	return out, strings.Trim(raw, "&") != ""
}

func queryUnescape(s string) string {
	if strings.IndexByte(s, '%') < 0 && strings.IndexByte(s, '+') < 0 {
		return s
	}
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return s
}

// validMediaType reports whether s (lower case, no parameters) is type/subtype made of token characters.
func validMediaType(s string) bool {
	slash := strings.IndexByte(s, '/')
	if slash < 1 || slash == len(s)-1 || len(s) > 100 || strings.Count(s, "/") != 1 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '/', c == '-', c == '.', c == '+', c == '_', c == '*', c == '!', c == '#', c == '$',
			c == '&', c == '^', c == '%', c == '\'', c == '`', c == '|', c == '~':
		default:
			return false
		}
	}
	return true
}

// ---- mass assignment ----

// privileged are the property names that decide who a user is or what something costs. They are compared in lower case with "_",
// "-" and spaces taken out, so isAdmin, is_admin and is-admin are one name.
var privileged = map[string]string{
	"role": "role", "roles": "roles", "isadmin": "is_admin", "admin": "admin", "isstaff": "is_staff", "superuser": "superuser",
	"issuperuser": "is_superuser", "permissions": "permissions", "permission": "permission", "scope": "scope", "scopes": "scopes",
	"group": "group", "groups": "groups", "verified": "verified", "emailverified": "email_verified", "balance": "balance",
	"credit": "credit", "price": "price", "owner": "owner", "ownerid": "owner_id", "userid": "user_id", "tenantid": "tenant_id",
	"orgid": "org_id", "status": "status", "approved": "approved",
}

// privilegedName reports whether a property name is on the list, and the list's own spelling of it, which is what a message may
// repeat: the name in the request is the visitor's, and the spelling here is ours.
func privilegedName(k string) (string, bool) {
	if len(k) < 4 || len(k) > 24 {
		return "", false
	}
	var buf [24]byte
	n := 0
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c == '_' || c == '-' || c == ' ':
			continue
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		case c >= 0x80:
			return "", false
		}
		buf[n] = c
		n++
	}
	name, ok := privileged[string(buf[:n])]
	return name, ok
}

// privFinding is what a scan of a body for privileged properties found.
type privFinding struct {
	flagged string // the first privileged property that nothing says is never sent
	refused string // the first one the description or the learned model says clients never send
}

// scanPrivileged looks for privileged property names at any depth. s is the schema of the value, if one is known: where it
// describes the object's properties, a privileged name that is not among them is one the API says clients do not send, and one
// that is among them is a property the API lets a client set and is left alone.
func scanPrivileged(v any, s *Schema, depth int, out *privFinding) {
	if depth > bodyDepth+2 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		covered := s != nil && schemaCoversProps(s, 0)
		for k, child := range x {
			var cs *Schema
			if s != nil {
				cs = schemaProp(s, k, 0)
			}
			if name, ok := privilegedName(k); ok {
				switch {
				case cs != nil:
					// The description lets a client set it.
				case covered:
					// Of several, the one that sorts first is named, so that the same body always gives the same message.
					if out.refused == "" || name < out.refused {
						out.refused = name
					}
				default:
					if out.flagged == "" || name < out.flagged {
						out.flagged = name
					}
				}
			}
			scanPrivileged(child, cs, depth+1, out)
		}
	case []any:
		var is *Schema
		if s != nil {
			is = schemaItems(s, 0)
		}
		for _, e := range x {
			scanPrivileged(e, is, depth+1, out)
		}
	}
}

// schemaCoversProps reports whether a schema lists the properties of its objects (itself or through allOf), which is what makes a
// name that is missing from it meaningful.
func schemaCoversProps(s *Schema, depth int) bool {
	if s = s.target(); s == nil || depth > 8 {
		return false
	}
	if s.Properties != nil {
		return true
	}
	for _, sub := range s.AllOf {
		if schemaCoversProps(sub, depth+1) {
			return true
		}
	}
	return false
}

// schemaProp finds the schema of a property, in the schema or through allOf. It returns nil if the schema does not list it.
func schemaProp(s *Schema, name string, depth int) *Schema {
	if s = s.target(); s == nil || depth > 8 {
		return nil
	}
	if p, ok := s.Properties[name]; ok {
		return p
	}
	for _, sub := range s.AllOf {
		if p := schemaProp(sub, name, depth+1); p != nil {
			return p
		}
	}
	if s.AdditionalSchema != nil {
		return s.AdditionalSchema
	}
	return nil
}

func schemaItems(s *Schema, depth int) *Schema {
	if s = s.target(); s == nil || depth > 8 {
		return nil
	}
	if s.Items != nil {
		return s.Items
	}
	for _, sub := range s.AllOf {
		if it := schemaItems(sub, depth+1); it != nil {
			return it
		}
	}
	return nil
}
