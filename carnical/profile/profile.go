// SPDX-License-Identifier: Apache-2.0

// Package profile works out what a protected site runs, so that a customer is protected correctly without configuring anything.
//
// A virtual patch for a WordPress plugin is useless on a site that does not have the plugin and noisy on one that has a page
// with the same path. The WordPress pack is wrong for a Java application. The framework-header checks matter for Next.js and not
// for a static site. So the first thing to know about a new customer is what their site is made of. The profile looks at the
// origin the way a visitor would (the home page, a handful of well-known paths), reads what it finds, and says: this is
// WordPress 6.5 with these plugins, this exposes a REST API and an OpenAPI document here, this is a Next.js application.
//
// Everything the origin answers is hostile input: the customer may be wrong about what is on their server, the site may have been
// taken over, and anyone who can edit a page can put anything in it. So the profile makes a small, fixed number of requests (never
// following one off the site), reads a bounded amount of each, extracts with linear-time patterns, and only ever produces tags
// from a validated vocabulary. Profiles and suggestions are advisory: the caller decides which changes are appropriate,
// including any compatibility setting that relaxes path checks.
package profile

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Response is what the origin answered to one request.
type Response struct {
	Status int
	Header http.Header
	// Body is limited by the Fetcher to at most MaxBody bytes.
	Body []byte
}

// Fetcher makes one request to the origin and returns the answer. The caller supplies it, so that every request goes through
// the proxy's guarded transport (public addresses only, no redirects off the site, the same timeouts). A redirect must not be
// followed by the Fetcher: a 3xx is returned as it is.
type Fetcher func(ctx context.Context, method, path string) (Response, error)

// MaxBody is how much of any one answer is read.
const MaxBody = 256 << 10

// Options bound the work.
type Options struct {
	// Timeout is the time allowed for the whole profile (default 20 seconds).
	Timeout time.Duration
	// MaxRequests is the most requests made (default 24).
	MaxRequests int
}

// Found is one piece of software and the evidence for it.
type Found struct {
	// Name is from a fixed vocabulary: wordpress, nextjs, laravel, drupal, joomla, magento, spring, aspnet, rails, django, express, php.
	Name    string
	Version string
	// Evidence says in words what was seen, never a copy of the page.
	Evidence []string
	// Confidence is high (a specific marker), medium or low (a guess from a banner).
	Confidence string
}

// Plugin is a WordPress plugin or theme seen in the page.
type Plugin struct {
	Kind    string // "plugin" or "theme"
	Slug    string
	Version string
}

// APIHint is a place that looks like an API.
type APIHint struct {
	Path string
	// Kind is openapi, swagger, wp-rest, graphql or json.
	Kind string
}

// Profile is what was found.
type Profile struct {
	Software []Found
	Plugins  []Plugin
	API      []APIHint
	// Scope is the list of tags to give the signature engine: "wordpress", "wordpress:plugin:contact-form-7", "php", "nextjs", and
	// so on. Every tag matches scopeTag.
	Scope []string
	// Requests is how many requests were made.
	Requests int
	// Notes say what could not be determined and why.
	Notes []string
}

// Has reports whether software of that name was found.
func (p Profile) Has(name string) bool {
	for _, f := range p.Software {
		if f.Name == name {
			return true
		}
	}
	return false
}

// scopeTag is what a tag in Scope must look like: lower-case letters, digits and . _ - : only, so that nothing an origin says can
// become anything else.
var scopeTag = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,95}$`)

// slug is a WordPress plugin or theme directory name.
var slug = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

var version = regexp.MustCompile(`^[0-9][0-9A-Za-z._+-]{0,31}$`)

// Detect profiles the site behind fetch. It never returns an error for a site that merely answers oddly: what could not be
// determined is in Notes. It returns an error only if the context ends before anything could be learned.
func Detect(ctx context.Context, fetch Fetcher, opt Options) (Profile, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 20 * time.Second
	}
	if opt.MaxRequests <= 0 {
		opt.MaxRequests = 24
	}
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	d := &detector{fetch: fetch, ctx: ctx, max: opt.MaxRequests, found: map[string]*Found{}}
	home, err := d.get("/")
	if err != nil && d.requests == 1 && errors.Is(err, ctx.Err()) {
		return Profile{}, err
	}
	d.fromHome(home)
	d.probes()

	p := d.result()
	return p, nil
}

type detector struct {
	fetch    Fetcher
	ctx      context.Context
	max      int
	requests int
	found    map[string]*Found
	plugins  map[string]Plugin
	api      map[string]APIHint
	notes    []string
}

func (d *detector) get(path string) (Response, error) {
	if d.requests >= d.max {
		d.note("the request limit was reached")
		return Response{}, errors.New("request limit")
	}
	d.requests++
	if err := d.ctx.Err(); err != nil {
		return Response{}, err
	}
	r, err := d.fetch(d.ctx, http.MethodGet, path)
	if err != nil {
		return Response{}, err
	}
	if len(r.Body) > MaxBody {
		r.Body = r.Body[:MaxBody]
	}
	return r, nil
}

func (d *detector) note(s string) {
	for _, n := range d.notes {
		if n == s {
			return
		}
	}
	if len(d.notes) < 20 {
		d.notes = append(d.notes, s)
	}
}

func (d *detector) add(name, ver, confidence, evidence string) {
	f := d.found[name]
	if f == nil {
		f = &Found{Name: name, Confidence: confidence}
		d.found[name] = f
	}
	if ver != "" && version.MatchString(ver) && f.Version == "" {
		f.Version = ver
	}
	if rank(confidence) > rank(f.Confidence) {
		f.Confidence = confidence
	}
	if len(f.Evidence) < 6 {
		f.Evidence = append(f.Evidence, evidence)
	}
}

func rank(c string) int {
	switch c {
	case "high":
		return 3
	case "medium":
		return 2
	}
	return 1
}

func (d *detector) hint(path, kind string) {
	if d.api == nil {
		d.api = map[string]APIHint{}
	}
	if len(d.api) < 20 {
		d.api[path] = APIHint{Path: path, Kind: kind}
	}
}

func (d *detector) result() Profile {
	p := Profile{Requests: d.requests, Notes: d.notes}
	names := make([]string, 0, len(d.found))
	for n := range d.found {
		names = append(names, n)
	}
	sort.Strings(names)
	scope := map[string]bool{}
	for _, n := range names {
		f := *d.found[n]
		p.Software = append(p.Software, f)
		if f.Confidence == "low" {
			continue // a banner alone does not decide which patches apply
		}
		for _, tag := range implied[n] {
			scope[tag] = true
		}
	}
	slugs := make([]string, 0, len(d.plugins))
	for k := range d.plugins {
		slugs = append(slugs, k)
	}
	sort.Strings(slugs)
	for _, k := range slugs {
		pl := d.plugins[k]
		p.Plugins = append(p.Plugins, pl)
		scope["wordpress:"+pl.Kind+":"+pl.Slug] = true
	}
	paths := make([]string, 0, len(d.api))
	for k := range d.api {
		paths = append(paths, k)
	}
	sort.Strings(paths)
	for _, k := range paths {
		p.API = append(p.API, d.api[k])
	}
	for tag := range scope {
		if scopeTag.MatchString(tag) {
			p.Scope = append(p.Scope, tag)
		}
	}
	sort.Strings(p.Scope)
	return p
}

// implied are the scope tags that software brings with it: a WordPress site is a PHP site.
var implied = map[string][]string{
	"wordpress": {"wordpress", "php"},
	"drupal":    {"drupal", "php"},
	"joomla":    {"joomla", "php"},
	"magento":   {"magento", "php"},
	"laravel":   {"laravel", "php"},
	"php":       {"php"},
	"nextjs":    {"nextjs", "node"},
	"express":   {"express", "node"},
	"spring":    {"spring", "java"},
	"aspnet":    {"dotnet"},
	"rails":     {"rails", "ruby"},
	"django":    {"django", "python"},
}

// fold lower-cases a header value for matching.
func fold(s string) string { return strings.ToLower(s) }
