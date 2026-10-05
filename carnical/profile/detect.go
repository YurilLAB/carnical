package profile

import (
	"net/http"
	"regexp"
	"strings"
)

var (
	metaGenerator = regexp.MustCompile(`(?i)<meta[^>]{0,200}name=["']generator["'][^>]{0,200}content=["']([^"'<>]{1,80})["']`)
	metaGenAlt    = regexp.MustCompile(`(?i)<meta[^>]{0,200}content=["']([^"'<>]{1,80})["'][^>]{0,200}name=["']generator["']`)
	wpAsset       = regexp.MustCompile(`/wp-content/(plugins|themes)/([a-z0-9][a-z0-9_-]{0,63})/([^"'\s<>]{0,200})`)
	wpVer         = regexp.MustCompile(`[?&]ver=([0-9][0-9A-Za-z._+-]{0,31})`)
	wpRestLink    = regexp.MustCompile(`(?i)rel=["']?https://api\.w\.org/["']?`)
	numberedVer   = regexp.MustCompile(`([0-9]+(?:\.[0-9]+){0,3})`)
	readmeVersion = regexp.MustCompile(`(?i)Version\s+([0-9]+(?:\.[0-9]+){1,3})`)
)

const maxAssetMatches = 3000
const maxPlugins = 200

// fromHome reads the home page: its headers, its cookies and its markup.
func (d *detector) fromHome(r Response) {
	if r.Status == 0 {
		d.note("the home page could not be fetched")
		return
	}
	d.fromHeaders(r.Header)
	body := string(r.Body)
	lower := fold(body)

	// The generator tag names the software and often its version.
	for _, re := range []*regexp.Regexp{metaGenerator, metaGenAlt} {
		for _, m := range re.FindAllStringSubmatch(body, 5) {
			d.fromGenerator(m[1])
		}
	}
	if strings.Contains(lower, "/wp-content/") || strings.Contains(lower, "/wp-includes/") {
		d.add("wordpress", "", "high", "the page loads files from /wp-content/ or /wp-includes/")
	}
	if wpRestLink.MatchString(body) {
		d.add("wordpress", "", "high", "the page links to the WordPress REST API")
		d.hint("/wp-json/", "wp-rest")
	}
	d.plugins = map[string]Plugin{}
	n := 0
	for _, m := range wpAsset.FindAllStringSubmatch(body, maxAssetMatches) {
		n++
		kind := "plugin"
		if m[1] == "themes" {
			kind = "theme"
		}
		if !slug.MatchString(m[2]) || len(d.plugins) >= maxPlugins {
			continue
		}
		key := kind + ":" + m[2]
		pl := d.plugins[key]
		pl.Kind, pl.Slug = kind, m[2]
		if pl.Version == "" {
			if v := wpVer.FindStringSubmatch(m[3]); v != nil && version.MatchString(v[1]) {
				pl.Version = v[1]
			}
		}
		d.plugins[key] = pl
	}
	if len(d.plugins) > 0 {
		d.add("wordpress", "", "high", "the page loads WordPress plugin or theme files")
	}
	if n >= maxAssetMatches {
		d.note("the page names more WordPress files than were read")
	}

	switch {
	case strings.Contains(lower, "__next_data__") || strings.Contains(lower, "/_next/static/"):
		d.add("nextjs", "", "high", "the page carries Next.js markers")
	}
	if strings.Contains(lower, "__viewstate") {
		d.add("aspnet", "", "high", "the page has an ASP.NET view state field")
	}
	if strings.Contains(lower, "drupal.settings") || strings.Contains(lower, "/sites/default/files/") {
		d.add("drupal", "", "high", "the page carries Drupal markers")
	}
	if strings.Contains(lower, "/media/system/js/") || strings.Contains(lower, "/templates/") && strings.Contains(lower, "joomla") {
		d.add("joomla", "", "medium", "the page loads Joomla system scripts")
	}
	if strings.Contains(lower, "mage.cookies") || strings.Contains(lower, "/static/frontend/magento") {
		d.add("magento", "", "high", "the page carries Magento markers")
	}
	if strings.Contains(lower, "csrfmiddlewaretoken") {
		d.add("django", "", "medium", "a form carries a Django CSRF field")
	}
	if strings.Contains(lower, `name="csrf-param"`) && strings.Contains(lower, "authenticity_token") {
		d.add("rails", "", "medium", "the page carries Rails CSRF markers")
	}
}

func (d *detector) fromGenerator(g string) {
	lg := fold(g)
	ver := ""
	if m := numberedVer.FindString(g); m != "" {
		ver = m
	}
	switch {
	case strings.HasPrefix(lg, "wordpress"):
		d.add("wordpress", ver, "high", "the generator tag says WordPress")
	case strings.HasPrefix(lg, "drupal"):
		d.add("drupal", ver, "high", "the generator tag says Drupal")
	case strings.HasPrefix(lg, "joomla"):
		d.add("joomla", "", "high", "the generator tag says Joomla")
	case strings.Contains(lg, "magento"):
		d.add("magento", "", "high", "the generator tag says Magento")
	}
}

func (d *detector) fromHeaders(h http.Header) {
	if h == nil {
		return
	}
	pw := h.Get("X-Powered-By")
	switch lp := fold(pw); {
	case strings.HasPrefix(lp, "php"):
		d.add("php", numberedVer.FindString(pw), "medium", "X-Powered-By says PHP")
	case strings.HasPrefix(lp, "express"):
		d.add("express", "", "medium", "X-Powered-By says Express")
	case strings.HasPrefix(lp, "next.js"):
		d.add("nextjs", numberedVer.FindString(pw), "high", "X-Powered-By says Next.js")
	case strings.HasPrefix(lp, "asp.net"):
		d.add("aspnet", "", "medium", "X-Powered-By says ASP.NET")
	}
	if v := h.Get("X-AspNet-Version"); v != "" {
		d.add("aspnet", numberedVer.FindString(v), "high", "an ASP.NET version header is present")
	}
	if g := h.Get("X-Generator"); g != "" {
		d.fromGenerator(g)
	}
	if h.Get("X-Drupal-Cache") != "" || h.Get("X-Drupal-Dynamic-Cache") != "" {
		d.add("drupal", "", "high", "a Drupal cache header is present")
	}
	if h.Get("X-Magento-Tags") != "" || h.Get("X-Magento-Cache-Debug") != "" {
		d.add("magento", "", "high", "a Magento cache header is present")
	}
	if strings.Contains(fold(h.Get("X-Redirect-By")), "wordpress") {
		d.add("wordpress", "", "high", "X-Redirect-By says WordPress")
	}
	if strings.Contains(fold(h.Get("X-Pingback")), "xmlrpc.php") {
		d.add("wordpress", "", "medium", "an X-Pingback header points at xmlrpc.php")
	}
	for _, l := range h.Values("Link") {
		if wpRestLink.MatchString(l) {
			d.add("wordpress", "", "high", "a Link header names the WordPress REST API")
			d.hint("/wp-json/", "wp-rest")
		}
	}
	for _, c := range h.Values("Set-Cookie") {
		name := fold(c)
		if i := strings.IndexByte(name, '='); i > 0 {
			name = name[:i]
		}
		switch {
		case name == "phpsessid":
			d.add("php", "", "medium", "a PHPSESSID cookie is set")
		case name == "laravel_session":
			d.add("laravel", "", "high", "a laravel_session cookie is set")
		case name == "csrftoken":
			d.add("django", "", "medium", "a csrftoken cookie is set")
		case name == "asp.net_sessionid":
			d.add("aspnet", "", "medium", "an ASP.NET session cookie is set")
		case strings.HasPrefix(name, "wordpress_") || strings.HasPrefix(name, "wp-settings-") || name == "wp_woocommerce_session":
			d.add("wordpress", "", "high", "a WordPress cookie is set")
		}
	}
}

// probes asks for the handful of well-known places that tell software apart. Each is one GET; none can change anything.
func (d *detector) probes() {
	if r, err := d.get("/wp-login.php"); err == nil {
		b := fold(string(r.Body))
		switch {
		case (r.Status == 200 && (strings.Contains(b, "user_login") || strings.Contains(b, "wp-submit"))) || (r.Status == 302 && strings.Contains(fold(r.Header.Get("Location")), "wp-login")):
			d.add("wordpress", "", "high", "wp-login.php answers like the WordPress login")
		}
	}
	if r, err := d.get("/wp-json/"); err == nil && r.Status == 200 && strings.Contains(string(r.Body), `"namespaces"`) {
		d.add("wordpress", "", "high", "/wp-json/ answers like the WordPress REST index")
		d.hint("/wp-json/", "wp-rest")
	}
	if r, err := d.get("/xmlrpc.php"); err == nil && (r.Status == 405 || r.Status == 200) && strings.Contains(fold(string(r.Body)), "xml-rpc server accepts post requests only") {
		d.add("wordpress", "", "medium", "xmlrpc.php answers like the WordPress XML-RPC endpoint")
		d.note("xmlrpc.php is reachable on the origin")
	}
	if r, err := d.get("/readme.html"); err == nil && r.Status == 200 && strings.Contains(fold(string(r.Body)), "wordpress") {
		ver := ""
		if m := readmeVersion.FindStringSubmatch(string(r.Body)); m != nil {
			ver = m[1]
		}
		d.add("wordpress", ver, "high", "readme.html is the WordPress readme")
		d.note("the WordPress readme.html is reachable (it shows the version)")
	}
	if r, err := d.get("/administrator/"); err == nil && r.Status == 200 && strings.Contains(fold(string(r.Body)), "joomla") {
		d.add("joomla", "", "high", "/administrator/ is the Joomla login")
	}
	if r, err := d.get("/user/login"); err == nil && r.Status == 200 && strings.Contains(fold(string(r.Body)), "drupal") {
		d.add("drupal", "", "medium", "/user/login looks like Drupal")
	}
	if r, err := d.get("/actuator/health"); err == nil && r.Status == 200 && strings.Contains(string(r.Body), `"status"`) && strings.Contains(string(r.Body), "UP") {
		d.add("spring", "", "medium", "/actuator/health answers like Spring Boot")
		d.note("Spring Boot actuator endpoints are reachable on the origin")
	}
	if r, err := d.get("/carnical-probe-0b7e9d51"); err == nil {
		b := fold(string(r.Body))
		switch {
		case strings.Contains(b, "whitelabel error page"):
			d.add("spring", "", "high", "the not-found page is Spring's whitelabel page")
		case strings.Contains(b, "cannot get /carnical-probe"):
			d.add("express", "", "medium", "the not-found page is Express's")
		}
	}
	d.apiDocs()
	if r, err := d.get("/graphql"); err == nil && (r.Status == 200 || r.Status == 400 || r.Status == 405) {
		b := fold(string(r.Body))
		if strings.Contains(b, "graphql") || strings.Contains(b, "must provide query string") || strings.Contains(b, `"errors"`) {
			d.hint("/graphql", "graphql")
		}
	}
	if r, err := d.get("/robots.txt"); err == nil && r.Status == 200 {
		b := fold(string(r.Body))
		if strings.Contains(b, "/wp-admin/") {
			d.add("wordpress", "", "medium", "robots.txt names /wp-admin/")
		}
		if strings.Contains(b, "/administrator/") && strings.Contains(b, "/components/") {
			d.add("joomla", "", "medium", "robots.txt names Joomla directories")
		}
	}
}

// apiDocs looks for the places an API describes itself.
func (d *detector) apiDocs() {
	for _, p := range []string{"/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs"} {
		r, err := d.get(p)
		if err != nil || r.Status != 200 {
			continue
		}
		head := fold(string(r.Body[:min(len(r.Body), 2048)]))
		switch {
		case strings.Contains(head, `"openapi"`):
			d.hint(p, "openapi")
		case strings.Contains(head, `"swagger"`):
			d.hint(p, "swagger")
		}
	}
}

// Suggestions are protections to switch on for a site that looks like this. They are suggestions: the customer's settings win.
type Suggestions struct {
	// WordPress turns on the WordPress protections (no scripts from upload directories, xmlrpc off, login limits).
	WordPress bool
	// AllowPathParams is for Java applications, which carry a session id in the path (;jsessionid=).
	AllowPathParams bool
	// Scope is for the signature engine.
	Scope []string
	// APIPaths are where an API describes itself or lives, for the API guard's discovery.
	APIPaths []APIHint
	// Notes are things the owner or the customer should know about their site.
	Notes []string
}

// Suggest turns a profile into the protections it implies.
func Suggest(p Profile) Suggestions {
	s := Suggestions{Scope: p.Scope, APIPaths: p.API, Notes: p.Notes}
	if p.Has("wordpress") {
		s.WordPress = true
	}
	if p.Has("spring") {
		s.AllowPathParams = true
	}
	if p.Has("nextjs") {
		s.Notes = append(s.Notes, "Next.js: if the application has no server actions, refuse the Next-Action header (deny-headers)")
	}
	return s
}
