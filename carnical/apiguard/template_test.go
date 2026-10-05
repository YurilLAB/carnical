// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"fmt"
	"strings"
	"testing"
)

func TestSegmentClasses(t *testing.T) {
	tests := []struct {
		seg  string
		want segClass
	}{
		{"42", scInt},
		{"0", scInt},
		{"1234567890123456789", scInt},
		{"12345678901234567890", scHex}, // more digits than an int64 holds
		{"550e8400-e29b-41d4-a716-446655440000", scUUID},
		{"550E8400-E29B-41D4-A716-446655440000", scUUID},
		{"2026-10-05", scDate},
		{"2026-10-05T12:00:00Z", scDate},
		{"5f4dcc3b5aa765d61d8327deb882cf99", scHex},
		{"deadbeef1", scHex},
		{"deadbeef", scLiteral}, // a word that happens to be made of hex letters
		{"abcdef", scLiteral},
		{"eyJhbGciOiJIUzI1NiJ9-abc_DEFghi12", scToken},
		{"aB3dE5gH7jK9mN1pQ3sT", scToken},
		{"product-123", scID},
		{"sku_9981", scID},
		{"abc123", scID},
		{"users", scLiteral},
		{"products", scLiteral},
		{"login", scLiteral},
		{"v1", scLiteral},
		{"v2.1", scLiteral},
		{"v10", scLiteral},
		{"oauth2", scLiteral},
		{"2fa", scLiteral},
		{"ipv6", scLiteral},
		{"how-to-configure-nginx-reverse-proxy", scLiteral},
		{"a1", scLiteral}, // too short to be told from a word
		{"", scLiteral},
	}
	for _, tt := range tests {
		t.Run(tt.seg, func(t *testing.T) {
			if got := classifySegment(tt.seg); got != tt.want {
				t.Fatalf("%q is %q, want %q", tt.seg, segClassName[got], segClassName[tt.want])
			}
		})
	}
}

func TestTemplates(t *testing.T) {
	collapsed := collapsedSet{"/api/catalogue": {}}
	tests := []struct {
		name   string
		method string
		path   string
		want   string
		ok     bool
	}{
		{"a literal path", "GET", "/api/users", "GET /api/users", true},
		{"an integer id", "GET", "/api/users/42", "GET /api/users/{int}", true},
		{"a uuid", "GET", "/api/orders/550e8400-e29b-41d4-a716-446655440000", "GET /api/orders/{uuid}", true},
		{"a hex id", "DELETE", "/files/5f4dcc3b5aa765d61d8327deb882cf99", "DELETE /files/{hex}", true},
		{"a date", "GET", "/reports/2026-10-05/summary", "GET /reports/{date}/summary", true},
		{"a token", "GET", "/share/aB3dE5gH7jK9mN1pQ3sT", "GET /share/{token}", true},
		{"a slug with digits", "GET", "/p/product-123", "GET /p/{id}", true},
		{"two ids", "GET", "/a/1/b/2", "GET /a/{int}/b/{int}", true},
		{"a version stays a literal", "GET", "/api/v1/users", "GET /api/v1/users", true},
		{"a trailing slash is the same route", "GET", "/api/users/", "GET /api/users", true},
		{"the root", "GET", "/", "GET /", true},
		{"a word at a collapsed position is a parameter", "GET", "/api/catalogue/shoes", "GET /api/catalogue/{id}", true},
		{"the same word elsewhere is not", "GET", "/api/shoes", "GET /api/shoes", true},
		{"a word that would make the template ambiguous", "GET", "/api/{x}", "GET /api/{id}", true},
		{"a segment with a space", "GET", "/api/a%20b", "GET /api/{id}", true},
		{"a very long word", "GET", "/api/" + strings.Repeat("a", 100), "GET /api/{id}", true},
		{"too many segments", "GET", "/a" + strings.Repeat("/x", MaxPathSegments), "", false},
		{"a bad escape", "GET", "/api/%zz", "", false},
		{"no leading slash", "GET", "api", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf [512]byte
			got, ok := templateOf(tt.method, tt.path, collapsed, buf[:0], nil)
			if ok != tt.ok || (ok && string(got) != tt.want) {
				t.Fatalf("template = %q ok=%v, want %q ok=%v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestTemplateReportsTheLiteralsItSees(t *testing.T) {
	var seen []string
	var buf [512]byte
	templateOf("GET", "/api/products/shoes/42/reviews", nil, buf[:0], func(prefix []byte, seg string) {
		seen = append(seen, string(prefix)+"|"+seg)
	})
	want := []string{"|api", "/api|products", "/api/products|shoes", "/api/products/shoes/{int}|reviews"}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("seen %q, want %q", seen, want)
	}
}

func TestAPIPaths(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/api", true}, {"/api/", true}, {"/api/v1/users", true}, {"/API/Users", true}, {"/v1/users", true}, {"/v9/x", true},
		{"/v12/x", true}, {"/v0/x", false}, {"/v100/x", false}, {"/rest/x", true}, {"/graphql", true}, {"/wp-json/wp/v2/posts", true},
		{"/_api/x", true}, {"/services/x", true}, {"/odata/x", true}, {"/api-v2/x", true}, {"/api_v2/x", true},
		{"/apple", false}, {"/apis", false}, {"/", false}, {"/index.html", false}, {"/blog/api/x", false}, {"/rests", false},
		{"/static/v1/app.js", false}, {"", false}, {"api", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isAPIPath(tt.path); got != tt.want {
				t.Fatalf("isAPIPath(%q) = %v", tt.path, got)
			}
		})
	}
}

func TestAcceptHeaders(t *testing.T) {
	tests := []struct {
		accept string
		want   bool
	}{
		{"application/json", true},
		{"application/json, text/plain, */*", true},
		{"application/vnd.api+json", true},
		{"application/xml", true},
		{"application/x-ndjson", true},
		{"*/*", false},
		{"", false},
		{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", false}, // a browser
		{"text/html, application/json", false},
		{"text/plain", false},
		{"image/png", false},
	}
	for _, tt := range tests {
		t.Run(tt.accept, func(t *testing.T) {
			if got := acceptsAPI(tt.accept); got != tt.want {
				t.Fatalf("acceptsAPI(%q) = %v", tt.accept, got)
			}
		})
	}
}

func TestAuthenticationPaths(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/api/v1/auth/login", true}, {"/login", true}, {"/signin", true}, {"/sign-in", true}, {"/api/sign_in", true},
		{"/oauth/token", true}, {"/oauth2/token", true}, {"/api/auth", true}, {"/user/password-reset", true}, {"/api/forgot-password", true},
		{"/api/forgotPassword", true}, {"/api/resetPassword", true}, {"/otp/verify", true}, {"/2fa", true}, {"/mfa/challenge", true},
		{"/api/verify-email", true}, {"/register", true}, {"/signup", true}, {"/api/tokens", true}, {"/api/refreshToken", true},
		{"/api/authenticate", true}, {"/api/users", false}, {"/api/authors", false}, {"/api/presets", false}, {"/api/authority", false},
		{"/api/products/42", false}, {"/api/loginhistory-report", true}, {"/", false}, {"/api/Login", true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isAuthPath(tt.path); got != tt.want {
				t.Fatalf("isAuthPath(%q) = %v", tt.path, got)
			}
		})
	}
}
