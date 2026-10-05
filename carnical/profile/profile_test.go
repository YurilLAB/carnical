package profile

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// site is an origin written out as data: path to answer. Anything not listed is a 404.
type site map[string]Response

func (s site) fetcher(count *atomic.Int32) Fetcher {
	return func(ctx context.Context, method, path string) (Response, error) {
		if count != nil {
			count.Add(1)
		}
		if err := ctx.Err(); err != nil {
			return Response{}, err
		}
		if method != http.MethodGet {
			return Response{}, errors.New("only GET is allowed")
		}
		if r, ok := s[path]; ok {
			return r, nil
		}
		return Response{Status: 404, Header: http.Header{}, Body: []byte("not found")}, nil
	}
}

func html(body string, headers ...string) Response {
	h := http.Header{}
	for i := 0; i+1 < len(headers); i += 2 {
		h.Add(headers[i], headers[i+1])
	}
	return Response{Status: 200, Header: h, Body: []byte(body)}
}

var wordpress = site{
	"/": html(`<html><head><meta name="generator" content="WordPress 6.5.2" />
<link rel='https://api.w.org/' href='https://shop.example.test/wp-json/' />
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.2" />
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.9.3"></script>
<script src="/wp-content/plugins/woocommerce/assets/js/frontend.js?ver=8.7.0"></script>
</head><body>hello</body></html>`, "X-Powered-By", "PHP/8.2.14", "Set-Cookie", "PHPSESSID=abc; path=/"),
	"/wp-login.php": html(`<form><input name="user_login"><input type="submit" id="wp-submit"></form>`),
	"/wp-json/":     html(`{"name":"Shop","namespaces":["oembed/1.0","wp/v2","contact-form-7/v1"]}`),
	"/xmlrpc.php":   {Status: 405, Header: http.Header{}, Body: []byte("XML-RPC server accepts POST requests only.")},
	"/readme.html":  html(`<h1>WordPress</h1><p>Version 6.5.2</p>`),
	"/robots.txt":   html("User-agent: *\nDisallow: /wp-admin/\n"),
}

func detect(t *testing.T, s site) Profile {
	t.Helper()
	p, err := Detect(context.Background(), s.fetcher(nil), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWordPressWithItsPluginsIsRecognisedAndScoped(t *testing.T) {
	p := detect(t, wordpress)
	if !p.Has("wordpress") || !p.Has("php") {
		t.Fatalf("software: %+v", p.Software)
	}
	var wp Found
	for _, f := range p.Software {
		if f.Name == "wordpress" {
			wp = f
		}
	}
	if wp.Version != "6.5.2" || wp.Confidence != "high" {
		t.Fatalf("wordpress: %+v", wp)
	}
	want := map[string]string{"plugin:contact-form-7": "5.9.3", "plugin:woocommerce": "8.7.0", "theme:twentytwentyfour": "1.2"}
	got := map[string]string{}
	for _, pl := range p.Plugins {
		got[pl.Kind+":"+pl.Slug] = pl.Version
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: version %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	scope := strings.Join(p.Scope, " ")
	for _, tag := range []string{"wordpress", "php", "wordpress:plugin:contact-form-7", "wordpress:plugin:woocommerce", "wordpress:theme:twentytwentyfour"} {
		if !strings.Contains(" "+scope+" ", " "+tag+" ") {
			t.Errorf("scope lacks %q: %v", tag, p.Scope)
		}
	}
	if len(p.API) != 1 || p.API[0] != (APIHint{"/wp-json/", "wp-rest"}) {
		t.Errorf("API hints: %+v", p.API)
	}
	s := Suggest(p)
	if !s.WordPress || s.AllowPathParams {
		t.Errorf("suggestions: %+v", s)
	}
	if !strings.Contains(strings.Join(p.Notes, "|"), "xmlrpc.php is reachable") || !strings.Contains(strings.Join(p.Notes, "|"), "readme.html is reachable") {
		t.Errorf("notes: %v", p.Notes)
	}
}

func TestOtherSoftwareIsRecognised(t *testing.T) {
	tests := []struct {
		name  string
		site  site
		must  []string
		never []string
		scope []string
	}{
		{"Next.js", site{"/": html(`<script id="__NEXT_DATA__" type="application/json">{}</script>`, "X-Powered-By", "Next.js")}, []string{"nextjs"}, []string{"wordpress", "php"}, []string{"nextjs", "node"}},
		{"Laravel", site{"/": html(`<html></html>`, "Set-Cookie", "laravel_session=abc; HttpOnly", "Set-Cookie", "XSRF-TOKEN=x")}, []string{"laravel"}, []string{"wordpress"}, []string{"laravel", "php"}},
		{"Spring Boot", site{"/actuator/health": html(`{"status":"UP"}`), "/carnical-probe-0b7e9d51": {Status: 404, Header: http.Header{}, Body: []byte("<h1>Whitelabel Error Page</h1>")}}, []string{"spring"}, []string{"php"}, []string{"java", "spring"}},
		{"Drupal", site{"/": html(`<html></html>`, "X-Generator", "Drupal 10 (https://www.drupal.org)")}, []string{"drupal"}, nil, []string{"drupal", "php"}},
		{"ASP.NET", site{"/": html(`<input type="hidden" name="__VIEWSTATE" value="x">`, "X-AspNet-Version", "4.0.30319")}, []string{"aspnet"}, nil, []string{"dotnet"}},
		{"a static site", site{"/": html(`<html><body>Opening hours</body></html>`)}, nil, []string{"wordpress", "php", "nextjs", "spring"}, nil},
		{"only a PHP banner (a medium-confidence banner still scopes php)", site{"/": html(`<html></html>`, "X-Powered-By", "PHP/8.1")}, []string{"php"}, nil, []string{"php"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := detect(t, tt.site)
			for _, n := range tt.must {
				if !p.Has(n) {
					t.Errorf("did not find %s: %+v", n, p.Software)
				}
			}
			for _, n := range tt.never {
				if p.Has(n) {
					t.Errorf("found %s on a site that is not: %+v", n, p.Software)
				}
			}
			if strings.Join(p.Scope, ",") != strings.Join(sorted(tt.scope), ",") {
				t.Errorf("scope %v, want %v", p.Scope, sorted(tt.scope))
			}
		})
	}
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestAPIDocumentsAreFound(t *testing.T) {
	s := site{
		"/":             html(`<html></html>`),
		"/openapi.json": html(`{"openapi":"3.0.1","info":{"title":"x"}}`),
		"/swagger.json": html(`{"swagger":"2.0"}`),
		"/api-docs":     html(`<html>an ordinary page</html>`),
		"/graphql":      {Status: 400, Header: http.Header{}, Body: []byte(`{"errors":[{"message":"Must provide query string."}]}`)},
	}
	p := detect(t, s)
	got := map[string]string{}
	for _, a := range p.API {
		got[a.Path] = a.Kind
	}
	if got["/openapi.json"] != "openapi" || got["/swagger.json"] != "swagger" || got["/graphql"] != "graphql" || len(got) != 3 {
		t.Fatalf("API hints: %v", got)
	}
}

// ---- the origin is hostile ----

func TestAHostileOriginCannotMakeTheProfileAnythingButTags(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`<meta name="generator" content="WordPress 6.0">`)
	for i := 0; i < 5000; i++ {
		sb.WriteString(`<script src="/wp-content/plugins/plug-` + strconv.Itoa(i) + `/a.js?ver=1.0"></script>`)
	}
	sb.WriteString(`<script src="/wp-content/plugins/Evil Plugin/a.js"></script>`)
	sb.WriteString(`<script src="/wp-content/plugins/ok-plugin/a.js?ver=1.0"><script>alert(1)</script>"></script>`)
	sb.WriteString(`<script src="/wp-content/plugins/ver-test/a.js?ver=1.0"></script>`)
	sb.WriteString(`<script src="/wp-content/plugins/bad-ver/a.js?ver=9"><b>"></script>`)
	sb.WriteString(strings.Repeat("A", 5<<20)) // far more than is read
	s := site{"/": html(sb.String())}
	p := detect(t, s)
	if len(p.Plugins) != maxPlugins {
		t.Fatalf("%d plugins kept, want exactly the limit of %d", len(p.Plugins), maxPlugins)
	}
	for _, pl := range p.Plugins {
		if !slug.MatchString(pl.Slug) || (pl.Version != "" && !version.MatchString(pl.Version)) {
			t.Fatalf("a plugin that is not a plugin name: %+v", pl)
		}
	}
	for _, tag := range p.Scope {
		if !scopeTag.MatchString(tag) {
			t.Fatalf("a scope tag outside the vocabulary: %q", tag)
		}
	}
	for _, f := range p.Software {
		for _, e := range f.Evidence {
			if strings.Contains(e, "<") || len(e) > 120 {
				t.Fatalf("evidence that quotes the page: %q", e)
			}
		}
	}
}

func TestTheNumberOfRequestsAndTheTimeAreBounded(t *testing.T) {
	var count atomic.Int32
	if _, err := Detect(context.Background(), site{}.fetcher(&count), Options{MaxRequests: 5}); err != nil {
		t.Fatal(err)
	}
	if n := count.Load(); n > 5 {
		t.Fatalf("%d requests with a limit of 5", n)
	}
	count.Store(0)
	Detect(context.Background(), site{}.fetcher(&count), Options{})
	if n := count.Load(); n > 24 {
		t.Fatalf("%d requests with the default limit", n)
	}

	slow := func(ctx context.Context, method, path string) (Response, error) {
		<-ctx.Done()
		return Response{}, ctx.Err()
	}
	began := time.Now()
	_, err := Detect(context.Background(), slow, Options{Timeout: 150 * time.Millisecond})
	if err == nil {
		t.Fatal("an origin that never answers produced a profile")
	}
	if took := time.Since(began); took > 3*time.Second {
		t.Fatalf("took %v", took)
	}
}

func TestAnOriginThatFailsIsNotAnErrorButANote(t *testing.T) {
	failing := func(ctx context.Context, method, path string) (Response, error) {
		return Response{}, errors.New("connection refused")
	}
	p, err := Detect(context.Background(), failing, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Software) != 0 || len(p.Scope) != 0 || !strings.Contains(strings.Join(p.Notes, "|"), "home page could not be fetched") {
		t.Fatalf("%+v", p)
	}
}

func TestSuggestionsForJava(t *testing.T) {
	p := detect(t, site{"/actuator/health": html(`{"status":"UP"}`)})
	if s := Suggest(p); !s.AllowPathParams || s.WordPress {
		t.Fatalf("%+v", s)
	}
}

// A guess from a banner alone must not decide which patches apply.
func TestALowConfidenceFindingDoesNotScope(t *testing.T) {
	d := &detector{found: map[string]*Found{}}
	d.add("django", "", "low", "a guess")
	d.add("laravel", "", "high", "a marker")
	p := d.result()
	if !p.Has("django") || strings.Contains(strings.Join(p.Scope, ","), "django") {
		t.Fatalf("a low-confidence finding was used for scope: %+v", p)
	}
	if !strings.Contains(strings.Join(p.Scope, ","), "laravel") {
		t.Fatalf("a high-confidence finding was not: %+v", p)
	}
}
