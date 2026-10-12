// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"slices"
	"strings"
	"sync"
	"time"
)

// Fetcher asks the protected site's own server for one path and returns what it answered. The caller supplies it (the proxy's
// guarded transport, which refuses a private address and holds a time limit), so this package does no network I/O of its own.
// The body should be read to at most MaxDocumentBytes+1 bytes; anything longer is refused here without being read as a document.
type Fetcher func(ctx context.Context, path string) (status int, contentType string, body []byte, err error)

// ErrNoDescription is returned by Discover when no address gave an API description.
var ErrNoDescription = errors.New("no API description was found")

// ErrDiscoveryBusy is returned if a discovery is already running for this guard.
var ErrDiscoveryBusy = errors.New("a discovery is already running")

// WellKnown are the addresses discovery asks for, in order.
var WellKnown = []string{
	"/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml", "/v2/api-docs", "/v3/api-docs", "/api-docs",
	"/api/openapi.json", "/api/swagger.json", "/swagger/v1/swagger.json", "/docs/openapi.json", "/.well-known/openapi.json",
	"/api/v1/openapi.json", "/wp-json/",
}

const graphQLPath = "/graphql"

// maxDiscoveryBytes is how much of what a site answers one discovery will read as descriptions, in all. A document is read at
// about a megabyte a second in the worst case, so this is what a site that answers every address with a large document can cost.
const maxDiscoveryBytes = 16 << 20

// candidate is a description that was found and has not been trusted yet. It refuses nothing. Each request that is answered below
// 400 is held against it; when enough of them, from enough different clients, fit it, it is promoted.
type candidate struct {
	model *Model
	mu    sync.Mutex
	agree Evidence
	no    uint32
}

func (c *candidate) counts() (agree, disagree uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.agree.N, c.no
}

// shadow holds one answered request against the candidate and promotes it if it has earned that.
func (g *Guard) shadow(c *candidate, rv *reqView, client uint32, cfg *Config) {
	r := rv.r
	if r.Method == "OPTIONS" {
		return
	}
	var caps captures
	fits := false
	if node := c.model.idx.lookup(r.Path, &caps); node != nil {
		if rt := node.route(r.Method); rt != nil {
			fits = len(g.checkRoute(rt, rv, &caps, &declaredIDs, c.model, false)) == 0
		}
	}
	// #nosec G115 -- Observe supplies Guard's validated private config: agreement 1..1,000,000 and share 1..100 after defaults.
	rule := evRule{minObs: uint32(cfg.Discovery.AgreeMinimum), minClients: cfg.Learn.MinClients, maxShare: uint32(cfg.Learn.MaxClientShare)}
	c.mu.Lock()
	if fits {
		c.agree.add(client, 1, &rule)
	} else {
		c.no++
	}
	// It must agree with enough requests and disagree with few: a description that fits one request in four is not about this API.
	ready := c.agree.OK && uint64(c.no)*20 <= uint64(c.agree.N)
	c.mu.Unlock()
	if ready && !cfg.Discovery.ManualPromotion {
		g.promote(c)
	}
}

func (g *Guard) promote(c *candidate) bool {
	if !g.cand.CompareAndSwap(c, nil) {
		return false
	}
	m := *c.model
	m.State = ModelActive
	g.active.Store(&m)
	g.st.promotions.Add(1)
	return true
}

// Promote puts the candidate description in force: the owner's decision, without waiting for the guard to see enough requests
// agree with it.
func (g *Guard) Promote() error {
	c := g.cand.Load()
	if c == nil {
		return errors.New("there is no candidate description to promote")
	}
	if !g.promote(c) {
		return errors.New("the candidate changed while it was being promoted")
	}
	return nil
}

// Discover looks for the site's API description at the well-known addresses and, if it finds one, keeps it as a candidate (see
// candidate). What the site answers is untrusted: it is limited in size and time, its content type is checked and its shape
// sniffed before it is parsed, and a document that is hostile in size, nesting, YAML aliases or references is refused and
// reported without harm. The report says where each address got to.
//
// A description found while another is already known replaces it only if it has at least as many routes (see Refresh to force
// it). The error is ErrNoDescription if no address gave one.
func (g *Guard) Discover(ctx context.Context, fetch Fetcher) (Report, error) {
	return g.discover(ctx, fetch, false)
}

// Refresh runs discovery again. The description found replaces the one held only if it is not worse, meaning not fewer routes;
// force replaces it anyway. The replacement is a candidate: the description in force stays in force until the new one has been
// shown to agree with the traffic.
func (g *Guard) Refresh(ctx context.Context, fetch Fetcher, force bool) (Report, error) {
	return g.discover(ctx, fetch, force)
}

func (g *Guard) discover(ctx context.Context, fetch Fetcher, force bool) (Report, error) {
	rep := Report{Kind: "discovery", When: g.clock().UTC()}
	if fetch == nil {
		return rep, errors.New("no way to fetch was given")
	}
	if !g.disc.TryLock() {
		return rep, ErrDiscoveryBusy
	}
	defer g.disc.Unlock()
	cfg := g.config()
	ctx, cancel := context.WithTimeout(ctx, cfg.Discovery.Timeout)
	defer cancel()

	var found *Model
	var foundRep Report
	readable := maxDiscoveryBytes
	for _, path := range WellKnown {
		if err := ctx.Err(); err != nil {
			rep.Attempts = append(rep.Attempts, Attempt{Path: path, Result: "not tried: " + clean(err.Error(), 60)})
			break
		}
		m, r, status, result := g.fetchDescription(ctx, fetch, path, cfg, &readable)
		rep.Attempts = append(rep.Attempts, Attempt{Path: path, Status: status, Result: result})
		if m != nil {
			found, foundRep = m, r
			break
		}
	}

	// GraphQL: noted, never probed. An introspection query is a request that discovers the site's schema and it is not ours to
	// send; a plain request for the address tells whether something GraphQL-shaped answers.
	if gq := g.noteGraphQL(ctx, fetch); gq != "" {
		rep.GraphQL = true
		rep.warn(gq)
	}

	if found == nil {
		rep.Outcome = "no description found"
		return rep, ErrNoDescription
	}
	rep.Source, rep.Format, rep.Title, rep.Hash, rep.Routes = foundRep.Source, foundRep.Format, foundRep.Title, foundRep.Hash, foundRep.Routes
	rep.Warnings = append(rep.Warnings, foundRep.Warnings...)
	rep.WarningsDropped += foundRep.WarningsDropped
	rep.Kind = "discovery"

	current := g.cand.Load()
	var have *Model
	switch {
	case current != nil:
		have = current.model
	case g.active.Load() != nil:
		have = g.active.Load()
	}
	if have != nil && !force {
		switch {
		case have.Hash == found.Hash:
			rep.Outcome = "unchanged: the description found is the one already held"
			return rep, nil
		case len(found.Routes) < len(have.Routes):
			rep.Outcome = fmt.Sprintf("kept the description already held: the one found has fewer routes (%d, held %d)", len(found.Routes), len(have.Routes))
			return rep, nil
		}
	}
	if a := g.active.Load(); a != nil && a.Hash == found.Hash && current == nil {
		rep.Outcome = "unchanged: the description found is the one in force"
		return rep, nil
	}
	found.State = ModelCandidate
	g.cand.Store(&candidate{model: found})
	rep.Outcome = "candidate: refuses nothing until it agrees with observed requests or is promoted"
	return rep, nil
}

// descriptionTypes are the content types a description may be served as. A single-page application answers every unknown path
// with its home page as text/html, which is why that is not among them.
func descriptionTypeOK(ct string) bool {
	switch mediaType(ct) {
	case "", "application/json", "application/yaml", "application/x-yaml", "text/yaml", "text/x-yaml", "text/plain", "application/octet-stream",
		"application/vnd.oai.openapi", "application/vnd.oai.openapi+json", "application/vnd.oai.openapi+yaml", "application/openapi+json",
		"application/openapi+yaml", "application/swagger+json", "application/hal+json", "application/vnd.api+json":
		return true
	}
	return false
}

// fetchDescription asks for one address and tries to read what comes back as a description.
func (g *Guard) fetchDescription(ctx context.Context, fetch Fetcher, path string, cfg *Config, readable *int) (m *Model, rep Report, status int, result string) {
	fctx, cancel := context.WithTimeout(ctx, cfg.Discovery.FetchTimeout)
	defer cancel()
	status, ct, body, err := safeFetch(fctx, fetch, path)
	switch {
	case err != nil:
		return nil, rep, 0, "the fetch failed"
	case status != 200:
		return nil, rep, status, fmt.Sprintf("status %d", status)
	case len(body) > cfg.Discovery.MaxDocumentBytes:
		return nil, rep, status, fmt.Sprintf("refused: %d bytes is over the %d byte limit", len(body), cfg.Discovery.MaxDocumentBytes)
	case !descriptionTypeOK(ct):
		return nil, rep, status, "refused: the content type is not one a description has"
	case !looksLikeDescription(body, path):
		return nil, rep, status, "refused: it does not look like a description"
	case len(body) > *readable:
		return nil, rep, status, "skipped: this discovery has already read as much as it may"
	}
	*readable -= len(body)
	if path == "/wp-json/" {
		model, r, err := importWordPress(body)
		if err != nil {
			return nil, rep, status, "refused: " + clean(err.Error(), 100)
		}
		model.Source, model.Fetched = path, g.clock().UTC()
		r.Source = path
		return &model, r, status, fmt.Sprintf("imported %d routes", len(model.Routes))
	}
	model, r, err := ImportOpenAPI(body)
	if err != nil {
		return nil, rep, status, "refused: " + clean(err.Error(), 100)
	}
	model.Source, model.Fetched = path, g.clock().UTC()
	r.Source = path
	return &model, r, status, fmt.Sprintf("imported %d routes", len(model.Routes))
}

// safeFetch calls the fetcher, and turns a panic in it into an error: what it returns is the caller's, but a bug in it must not end
// the process that is protecting a site.
func safeFetch(ctx context.Context, fetch Fetcher, path string) (status int, ct string, body []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = errors.New("the fetcher failed")
		}
	}()
	return fetch(ctx, path)
}

// looksLikeDescription is the cheap test before a parse: a JSON object, or text that names openapi or swagger at the start of a
// line near the top. It is what stops a home page, an error page or a binary from being fed to the YAML parser.
func looksLikeDescription(body []byte, path string) bool {
	i := 0
	for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' || body[i] == '\n') {
		i++
	}
	if i >= len(body) {
		return false
	}
	if body[i] == '{' {
		return true
	}
	head := body[i:]
	if len(head) > 2048 {
		head = head[:2048]
	}
	for _, line := range strings.Split(string(head), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "---"))
		if strings.HasPrefix(line, "openapi:") || strings.HasPrefix(line, "swagger:") || strings.HasPrefix(line, `"openapi"`) || strings.HasPrefix(line, `"swagger"`) {
			return true
		}
	}
	return false
}

// noteGraphQL asks for the GraphQL address as an ordinary request and says whether something GraphQL answered.
func (g *Guard) noteGraphQL(ctx context.Context, fetch Fetcher) string {
	if ctx.Err() != nil {
		return ""
	}
	status, ct, body, err := safeFetch(ctx, fetch, graphQLPath)
	if err != nil || len(body) > 256<<10 {
		return ""
	}
	lower := strings.ToLower(string(body[:min(len(body), 4096)]))
	graphql := strings.Contains(lower, "graphql") || strings.Contains(lower, "must provide query") || strings.Contains(lower, "graphiql")
	if !graphql || (status != 200 && status != 400 && status != 405 && status != 401 && status != 403) {
		return ""
	}
	_ = ct
	g.gql.Store(true)
	return "a GraphQL endpoint answers at /graphql. Its schema is not read (no introspection query is sent); limit query depth, aliases and batching in the GraphQL server itself, which a proxy cannot do"
}

// ---- WordPress REST index ----

// wordPressIndex is the format of a model read from a WordPress REST index.
const wordPressIndex = "wordpress rest index"

// importWordPress reads the index the WordPress REST API gives at /wp-json/: the routes it has, with the methods of each. Its
// routes are written as patterns, with a regular expression for each parameter; a parameter that is plainly numeric becomes an
// integer, and every other becomes a string.
func importWordPress(body []byte) (Model, Report, error) {
	rep := Report{Kind: "wordpress", When: time.Now().UTC()}
	sum := sha256.Sum256(body)
	rep.Hash = hex.EncodeToString(sum[:])
	doc, _, err := parseJSON(body, jsonLimits{depth: 32, nodes: 500_000})
	if err != nil {
		return Model{}, rep, errors.New("not JSON")
	}
	root, _ := doc.(map[string]any)
	routes, _ := root["routes"].(map[string]any)
	if root == nil || routes == nil || root["namespaces"] == nil {
		return Model{}, rep, errors.New("not a WordPress REST index")
	}
	rep.Format = wordPressIndex
	rep.Title = clean(scalarText(root["name"]), 120)
	m := Model{Format: ModelFormat, Hash: rep.Hash, Title: rep.Title, SpecVersion: rep.Format}
	keys := make([]string, 0, len(routes))
	for k := range routes {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	skipped := 0
	for _, k := range keys {
		if len(m.Routes) >= MaxRoutes {
			return Model{}, rep, fmt.Errorf("more than %d routes", MaxRoutes)
		}
		tmpl, params, ok := wpTemplate(k)
		if !ok {
			skipped++
			continue
		}
		entry, _ := routes[k].(map[string]any)
		var methods []string
		if ms, ok := entry["methods"].([]any); ok {
			for _, e := range ms {
				if s, ok := e.(string); ok && validMethodToken(s) && len(methods) < 8 {
					methods = append(methods, s)
				}
			}
		}
		for _, method := range methods {
			switch method {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
			default:
				continue
			}
			m.Routes = append(m.Routes, Route{Method: method, Path: "/wp-json" + tmpl, State: StateDeclared, Params: append([]Param(nil), params...)})
		}
	}
	m.Routes = append(m.Routes, Route{Method: "GET", Path: "/wp-json", State: StateDeclared})
	if skipped > 0 {
		rep.warn(fmt.Sprintf("%d route(s) with patterns this importer cannot turn into a template were left out", skipped))
	}
	m.finish(rep.warn)
	rep.Routes = len(m.Routes)
	return m, rep, nil
}

// wpRestRoute reads the route a request names through WordPress's rest_route variable, which WordPress serves on any path and
// before the path itself, as PHP and WordPress read it: a form body's value before the query's, and the last one given. It returns
// the path that route has under /wp-json, or "" when PHP makes the variable an array, which names no route.
func wpRestRoute(rv *reqView) (path string, found bool) {
	v, arr, found := wpRestRouteIn(rv.r.RawQuery)
	var bv string
	var barr, bfound bool
	switch rv.ct {
	case "application/x-www-form-urlencoded":
		bv, barr, bfound = wpRestRouteIn(rv.body)
	case "multipart/form-data":
		bv, barr, bfound = wpRestRouteMultipart(rv)
	}
	if bfound {
		// No client names a route in both, and which one is served depends on the server's settings, so such a request names none.
		if found {
			return "", true
		}
		v, arr, found = bv, barr, true
	}
	switch {
	case !found:
		return "", false
	case arr:
		return "", true
	}
	// WordPress cuts trailing slashes and backslashes off the route. The value is decoded already, so a % in it is escaped
	// again for the lookup, which decodes the path once.
	if v = strings.TrimRight(v, `/\`); v == "" {
		return "/wp-json", true
	}
	return "/wp-json" + strings.ReplaceAll(v, "%", "%25"), true
}

// wpRestRouteIn finds the last rest_route in a query string or a form body, and whether PHP makes it an array.
func wpRestRouteIn[T ~string | ~[]byte](raw T) (value string, arr, found bool) {
	for start := 0; start < len(raw); {
		end, eq := start, -1
		for ; end < len(raw) && raw[end] != '&'; end++ {
			if eq < 0 && raw[end] == '=' {
				eq = end
			}
		}
		nameEnd, valStart := end, end
		if eq >= 0 {
			nameEnd, valStart = eq, eq+1
		}
		// Decoding a name never makes it longer, so a shorter one cannot be rest_route.
		if nameEnd-start >= len("rest_route") {
			if n, isArr := phpName(phpURLDecode(string(raw[start:nameEnd]))); n == "rest_route" {
				// PHP keeps the last one it reads, but it stops reading at max_input_vars, so a second one names no route.
				if found {
					return "", true, true
				}
				value, arr, found = phpURLDecode(string(raw[valStart:end])), isArr, true
			}
		}
		start = end + 1
	}
	return value, arr, found
}

// wpRestRouteMultipart finds rest_route among the fields of a multipart body, which PHP reads into $_POST as it does a form body.
// A body that cannot be read, and might name it, names no route.
func wpRestRouteMultipart(rv *reqView) (value string, arr, found bool) {
	unreadable := func() (string, bool, bool) {
		if bytes.Contains(rv.body, []byte("rest")) {
			return "", true, true
		}
		return "", false, false
	}
	_, params, err := mime.ParseMediaType(rv.r.Header.Get("Content-Type"))
	if err != nil || params["boundary"] == "" {
		return unreadable()
	}
	mr := multipart.NewReader(bytes.NewReader(rv.body), params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return value, arr, found
		}
		if err != nil {
			return unreadable()
		}
		if part.FileName() != "" {
			continue // a file goes to $_FILES
		}
		n, isArr := phpName(part.FormName())
		if n != "rest_route" {
			continue
		}
		if found {
			return "", true, true
		}
		b, err := io.ReadAll(part)
		if err != nil {
			return "", true, true
		}
		value, arr, found = string(b), isArr, true
	}
}

// wpIndexPath maps a path under /index.php/wp-json, which WordPress serves as the REST route after it, to that route.
func wpIndexPath(p string) (string, bool) {
	const index = "/index.php"
	if len(p) <= len(index) || !strings.EqualFold(p[:len(index)], index) {
		return "", false
	}
	if rest := p[len(index):]; rest == "/wp-json" || strings.HasPrefix(rest, "/wp-json/") {
		return rest, true
	}
	return "", false
}

// phpName returns the variable PHP makes of a decoded query or form name, and whether it is an array: the name ends at a NUL,
// leading spaces are dropped, a space or a dot becomes an underscore, and a [ starts an array if a ] follows it and otherwise
// becomes an underscore too.
func phpName(name string) (string, bool) {
	if i := strings.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimLeft(name, " ")
	if !strings.ContainsAny(name, " .[") {
		return name, false
	}
	b := []byte(name)
	for i, c := range b {
		switch c {
		case ' ', '.':
			b[i] = '_'
		case '[':
			if strings.IndexByte(name[i+1:], ']') >= 0 {
				return string(b[:i]), true
			}
			for j := i; j < len(b); j++ {
				if b[j] == ' ' || b[j] == '.' || b[j] == '[' {
					b[j] = '_'
				}
			}
			return string(b), false
		}
	}
	return string(b), false
}

// phpURLDecode decodes as PHP does: a + is a space, a % and two hex digits is that byte, and any other % is kept as it is.
func phpURLDecode(s string) string {
	if strings.IndexByte(s, '%') < 0 && strings.IndexByte(s, '+') < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			b = append(b, ' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b = append(b, hexDigit(s[i+1])<<4|hexDigit(s[i+2]))
			i += 2
		default:
			b = append(b, c)
		}
	}
	return string(b)
}

func hexDigit(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// wpTemplate turns a WordPress route pattern such as /wp/v2/posts/(?P<id>[\d]+) into a path template and its parameters.
func wpTemplate(pattern string) (tmpl string, params []Param, ok bool) {
	var b strings.Builder
	for i := 0; i < len(pattern); {
		if strings.HasPrefix(pattern[i:], "(?P<") {
			end := strings.IndexByte(pattern[i:], '>')
			if end < 0 {
				return "", nil, false
			}
			name := pattern[i+4 : i+end]
			depth, j := 1, i+end+1
			for j < len(pattern) && depth > 0 {
				switch pattern[j] {
				case '\\':
					j++
				case '(':
					depth++
				case ')':
					depth--
				}
				j++
			}
			if depth != 0 || name == "" || strings.ContainsAny(name, "{}/") {
				return "", nil, false
			}
			re := pattern[i+end+1 : j-1]
			p := Param{Name: name, In: "path", Required: true}
			switch re {
			case `[\d]+`, `\d+`, `[0-9]+`:
				p.Schema = &Schema{Type: []string{"integer"}}
			default:
				p.Schema = &Schema{Type: []string{"string"}}
			}
			params = append(params, p)
			b.WriteString("{" + name + "}")
			i = j
			continue
		}
		c := pattern[i]
		if strings.IndexByte(`()[]?*+\^$|`, c) >= 0 || c == '{' || c == '}' {
			return "", nil, false
		}
		b.WriteByte(c)
		i++
	}
	t := b.String()
	if !strings.HasPrefix(t, "/") || len(params) > maxPathParams {
		return "", nil, false
	}
	return t, params, true
}
