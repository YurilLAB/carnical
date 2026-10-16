// SPDX-License-Identifier: Apache-2.0

// Package apiguard protects an API without being told what the API is.
//
// A Guard is one site's protection. It is both an inspect.Inspector (it looks at each request before the rule set does and can
// refuse it) and an inspect.Observer (it is told what the application answered, and learns from the requests that passed). Nothing
// is shared between Guards.
//
// There are three levels, each on with no configuration and each better the more is known:
//
//	Level 0, the shield. Needs no description. For a request that looks like an API request: a method allow-list, a body-size
//	cap per method, a Content-Type that must be present and one the API has been seen to use, per-client rate limits with
//	stricter ones on login-like endpoints, and a warning (or a refusal, where the API is known not to take it) for a write
//	body that sets a privileged property.
//
//	Level 1, the API's own description. An OpenAPI 3.0/3.1 or Swagger 2.0 document, supplied or found by Discover, is turned
//	into a model, and a request that does not fit it is a finding: an unknown route, a method the route does not have, a
//	parameter of the wrong type or outside its bounds, a missing required parameter, a content type the route does not take, a
//	body that fails its schema, an unknown or read-only property.
//
//	Level 2, learning. The routes, parameters, content types and body shapes that real traffic shows are learned, and what has
//	enough support from enough different clients is enforced. See learntypes.go for the rule that keeps an attacker from
//	teaching the guard that an attack is normal.
//
// What no WAF can do is in docs/apiguard.md: it cannot know that user 7 may not read user 8's record (broken object-level
// authorisation) or that a discount may not be applied twice (business logic). The application has to decide those.
package apiguard

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// Guard is the protection of one site. Use New. It is safe for use by many requests at once.
type Guard struct {
	cfg    atomic.Pointer[Config]
	clock  func() time.Time
	lim    *limiter
	learn  *learner
	active atomic.Pointer[Model]
	cand   atomic.Pointer[candidate]
	disc   sync.Mutex
	gql    atomic.Bool
	st     counters
}

type counters struct {
	requests, api, refused, flagged, panics, observed, promotions atomic.Uint64
	byID                                                          [1000]atomic.Uint64
}

var (
	_ inspect.Inspector = (*Guard)(nil)
	_ inspect.Observer  = (*Guard)(nil)
)

// New makes a Guard. A zero Config is the default: see DefaultConfig and Modes for what that protects and how.
func New(cfg Config) (*Guard, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	cfg = cfg.withDefaults()
	g := &Guard{clock: clock}
	g.cfg.Store(&cfg)
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("no source of randomness: %w", err)
	}
	g.lim = newLimiter(cfg.Rate.MaxKeys, clock())
	g.learn = newLearner(g.config, clock, binary.LittleEndian.Uint64(seed[:]))
	return g, nil
}

// Name identifies the guard in the proxy's log.
func (g *Guard) Name() string { return "apiguard" }

func (g *Guard) config() *Config { return g.cfg.Load() }

// Config returns the configuration in force, with every default filled in.
func (g *Guard) Config() Config {
	c := *g.config()
	c.Methods = slices.Clone(c.Methods)
	bl := make(map[string]int64, len(c.BodyLimits))
	for k, v := range c.BodyLimits {
		bl[k] = v
	}
	c.BodyLimits = bl
	return c
}

// SetConfig replaces the configuration. The size of the rate table is fixed when the Guard is made; everything else takes effect
// on the next request. A Config that fails Validate is refused and nothing changes.
func (g *Guard) SetConfig(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	cfg.Clock = nil
	cfg = cfg.withDefaults()
	cfg.Rate.MaxKeys = g.config().Rate.MaxKeys
	g.cfg.Store(&cfg)
	return nil
}

// SetModes changes what each protection does, leaving the rest of the configuration as it is.
func (g *Guard) SetModes(m Modes) error {
	c := g.Config()
	c.Modes = m
	return g.SetConfig(c)
}

// SetMode changes the guard-wide mode: ModeOff, ModeLearn, ModeMonitor (nothing blocks) or ModeEnforce.
func (g *Guard) SetMode(m Mode) error {
	c := g.Config()
	c.Mode = m
	return g.SetConfig(c)
}

func (c *Config) methodAllowed(m string) bool {
	return slices.Contains(c.Methods, m)
}

func (c *Config) bodyLimit(m string) int64 {
	if n, ok := c.BodyLimits[m]; ok {
		return n
	}
	return c.DefaultBodyLimit
}

// inspection is one request being inspected.
type inspection struct {
	g        *Guard
	cfg      *Config
	r        *inspect.Request
	verdicts []inspect.Verdict
}

// emit reports a finding under the mode of the protection that found it and says whether the request must be refused (and so
// whether to stop looking). A protection that is off reports nothing.
func (in *inspection) emit(id int, detail string, own Mode) (stop bool) {
	m := effective(in.cfg.Mode, own)
	if m < ModeMonitor {
		return false
	}
	return in.report(finding{id: id, detail: detail}, m)
}

func (in *inspection) report(f finding, m Mode) bool {
	if len(in.verdicts) < 16 {
		in.verdicts = append(in.verdicts, f.verdict(m))
	}
	if i := f.id - 5003000; i >= 0 && i < len(in.g.st.byID) {
		in.g.st.byID[i].Add(1)
	}
	if m == ModeEnforce {
		in.g.st.refused.Add(1)
		return true
	}
	in.g.st.flagged.Add(1)
	return false
}

// emitF is emit for a finding a route check made.
func (in *inspection) emitF(f finding, own Mode) bool {
	m := effective(in.cfg.Mode, own)
	if m < ModeMonitor {
		return false
	}
	return in.report(f, m)
}

// Inspect looks at one request. It never panics: a failure inside the guard is the verdict IDInternalError, under the guard's own
// mode. In enforce it refuses the request (503), as the guard cannot say the request is one it would let through; in monitor it
// is reported and the request goes on, as any other finding would.
func (g *Guard) Inspect(r *inspect.Request) (res inspect.Result) {
	mode := ModeMonitor
	defer func() {
		if p := recover(); p != nil {
			g.st.panics.Add(1)
			in := &inspection{g: g}
			in.report(finding{id: IDInternalError, detail: "the request was not checked"}, mode)
			res = inspect.Result{Verdicts: in.verdicts}
		}
	}()
	if r == nil {
		return inspect.Result{}
	}
	cfg := g.config()
	mode = cfg.Mode
	if cfg.Mode < ModeMonitor {
		return inspect.Result{}
	}
	g.st.requests.Add(1)
	in := &inspection{g: g, cfg: cfg, r: r}
	in.run()
	return inspect.Result{Verdicts: in.verdicts}
}

func (in *inspection) run() {
	g, cfg, r := in.g, in.cfg, in.r
	method := r.Method
	var view reqView
	view.init(r)
	rv := &view

	// A CORS preflight (no body, and the method it asks about) is the one request a route need not list a method for, and only
	// for a method the route does take. It is held to that method's route as far as it goes: a browser sends it to the URL of the
	// request it asks about, with none of that request's credentials, header values, cookies or body. Any other OPTIONS request
	// reaches a handler that may not check the method.
	acrm := strings.ToUpper(strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")))
	preflight := method == "OPTIONS" && len(r.Body) == 0 && acrm != ""
	var asked, learnedAsked bool // the route found is the one a preflight asks about, not the request's own

	decl := g.active.Load()
	var caps captures
	var dnode *trieNode
	var drt *Route
	respelled := false
	// WordPress serves a REST route named by its rest_route variable on any path, and before the path, so such a request is held
	// to that route. A variable that names no route leaves path empty, and the request is refused as an unknown route.
	path, restRoute := r.Path, false
	if decl != nil && decl.SpecVersion == wordPressIndex {
		if p, found := wpRestRoute(rv); found {
			path, restRoute = p, true
		} else if p, ok := wpIndexPath(r.Path); ok {
			path, restRoute = p, true
		}
	}
	if decl != nil && path != "" {
		if dnode = decl.idx.lookup(path, &caps); dnode != nil {
			drt = dnode.route(method)
			if drt == nil && preflight {
				drt = dnode.route(acrm)
				asked = drt != nil
			}
		}
		// A path that names a described route only in another spelling (letter case, ';' parameters, empty segments), or names
		// another route that way than it does as written, is served by an operation that it would not be held to. It is not a
		// route the description has, so it is refused as an unknown one, whether or not it looks like an API.
		if decl.idx.respelled(path, dnode) {
			respelled, dnode, drt, asked = true, nil, nil, false
		}
	}
	learnedOn := effective(cfg.Mode, cfg.Modes.Learned) >= ModeMonitor
	var lk learnedLookup
	if learnedOn {
		lk = g.learn.lookup(method, r.Path)
		if lk.view == nil && preflight {
			if pk := g.learn.lookup(acrm, r.Path); pk.view != nil {
				lk, learnedAsked = pk, true
			}
		}
	}
	api := restRoute || dnode != nil || respelled || lk.view != nil || lk.otherMethod || isAPIPath(r.Path) || isAPIContentType(rv.ct) || acceptsAPI(r.Header.Get("Accept"))
	if !api {
		return
	}
	g.st.api.Add(1)

	// Level 0. The cheap refusals come first, so that a flood of requests that are refused anyway costs as little as it can.
	if !cfg.methodAllowed(method) && in.emit(IDMethodNotAllowed, "", cfg.Modes.Methods) {
		return
	}
	hasBody := len(r.Body) > 0
	if int64(len(r.Body)) > cfg.bodyLimit(method) && in.emit(IDBodyTooLarge, "", cfg.Modes.BodySize) {
		return
	}
	if in.rate(decl) {
		return
	}
	if hasBody {
		switch {
		case rv.ct == "":
			if in.emit(IDContentTypeMissing, "", cfg.Modes.Format) {
				return
			}
		case !validMediaType(rv.ct):
			if in.emit(IDContentTypeUnseen, "the Content-Type is not a media type", cfg.Modes.Format) {
				return
			}
		case drt == nil:
			if seen, mature := g.learn.contentTypeSeen(rv.ct); mature && !seen {
				if in.emit(IDContentTypeUnseen, "", cfg.Modes.Format) {
					return
				}
			}
		}
	}
	var body any
	bodyOK := false
	if rv.isJSON {
		val, dup, err := rv.json()
		switch {
		case err != nil:
			if in.emit(IDBodyMalformed, "", cfg.Modes.Format) {
				return
			}
		default:
			body, bodyOK = val, true
			if dup && in.emit(IDBodyDuplicateKey, "", cfg.Modes.Format) {
				return
			}
		}
	}

	// A write with no Content-Type is bound as JSON by many frameworks (Go's encoding/json, gin, FastAPI), so one that starts like
	// JSON is scanned for mass assignment too.
	untypedJSON := rv.ct == "" && startsLikeJSON(rv.body)
	if untypedJSON {
		if val, _, err := rv.json(); err == nil {
			body, bodyOK = val, true
		}
	}

	// Mass assignment: a privileged property in a write. It is looked for before the description and the learned model are
	// consulted, because it is the more specific finding (and 403 says more than 400 does), and a refusal here ends the check.
	if (rv.isJSON || untypedJSON) && (method == "POST" || method == "PUT" || method == "PATCH") && effective(cfg.Mode, cfg.Modes.MassAssign) >= ModeMonitor {
		var sch *Schema
		switch {
		case drt != nil:
			sch = drt.Body
		case lk.view != nil:
			sch = lk.view.Body
		}
		var pf privFinding
		switch {
		case bodyOK:
			scanPrivileged(body, sch, 0, &pf)
		case schemaCoversProps(sch, 0) || schemaCoversProps(schemaItems(sch, 0), 0):
			// A body the guard could not read may still be one the application's decoder reads, so where the schema says which
			// properties clients send, it is not cleared of the others.
			if in.emit(IDMassAssignRefused, "the body could not be read to look for a property this API's clients do not send", cfg.Modes.MassAssign) {
				return
			}
		}
		switch {
		case pf.refused != "":
			if in.emit(IDMassAssignRefused, "the body sets "+pf.refused+", which this API's clients do not send", cfg.Modes.MassAssign) {
				return
			}
		case pf.flagged != "":
			// Only a warning: nothing says this API's clients never send it, and many APIs do (a ticket's status, a product's price).
			in.emit(IDMassAssignFlagged, "the body sets "+pf.flagged+"; it is flagged, not refused, because it is not known that clients never send it", min(cfg.Modes.MassAssign, ModeMonitor))
		}
	}

	// Level 1: the API's own description.
	if decl != nil {
		switch {
		case respelled:
			if in.emit(IDSpecUnknownRoute, "the path spells a described route differently (letter case, ; parameters or empty segments)", cfg.Modes.Spec) {
				return
			}
		case dnode == nil:
			if lk.view == nil && in.emit(IDSpecUnknownRoute, "", cfg.Modes.Spec) {
				return
			}
		case drt == nil:
			if lk.view == nil && in.emit(IDSpecMethodNotAllowed, "the route takes "+strings.Join(dnode.methods, ", "), cfg.Modes.Spec) {
				return
			}
		default:
			for _, f := range g.checkRoute(drt, rv, &caps, &declaredIDs, decl, asked) {
				if in.emitF(f, cfg.Modes.Spec) {
					return
				}
			}
		}
	}

	// Level 2: what was learned. The description, where it covers the route, decides instead.
	if learnedOn && drt == nil {
		switch {
		case lk.view != nil:
			var none captures
			for _, f := range g.checkRoute(lk.view, rv, &none, &learnedIDs, nil, learnedAsked) {
				if in.emitF(f, cfg.Modes.Learned) {
					return
				}
			}
		case decl == nil && !preflight && g.learn.enforceable.Load() > 0:
			id, why := IDLearnedUnknownRoute, ""
			if lk.otherMethod {
				id = IDLearnedMethodNotSeen
			}
			if in.emit(id, why, cfg.Modes.Learned) {
				return
			}
		}
	}

}

// rate applies the per-client limits. It reports whether the request must be refused.
func (in *inspection) rate(decl *Model) (stop bool) {
	g, cfg, r := in.g, in.cfg, in.r
	rateMode, authMode := effective(cfg.Mode, cfg.Modes.Rate), effective(cfg.Mode, cfg.Modes.AuthRate)
	if rateMode < ModeMonitor && authMode < ModeMonitor {
		return false
	}
	if !r.Client.IsValid() {
		// Without a client address there is nobody to count.
		g.lim.noClient.Add(1)
		return false
	}
	now := g.clock()
	if authMode >= ModeMonitor && isAuthPath(r.Path) {
		if k, ok := addrKey(scopeAuth, r.Client); ok {
			if allowed, retry, _ := g.lim.allow(k, cfg.Rate.AuthSustained, cfg.Rate.AuthBurst, now); !allowed {
				if in.emit(IDAuthRateLimited, retryAfter(retry), cfg.Modes.AuthRate) {
					return true
				}
			}
		}
	}
	if rateMode < ModeMonitor {
		return false
	}
	cred := credentialOf(r.Header, r.RawQuery, decl)
	var k rlKey
	var ok bool
	if cred != "" {
		k, ok = g.lim.credKey(scopeClient, r.Client, cred)
	} else {
		k, ok = addrKey(scopeClient, r.Client)
	}
	if !ok {
		return false
	}
	if allowed, retry, _ := g.lim.allow(k, cfg.Rate.Sustained, cfg.Rate.Burst, now); !allowed {
		return in.emit(IDRateLimited, retryAfter(retry), cfg.Modes.Rate)
	}
	if cred != "" {
		// The address as a whole is counted too, so that changing the credential does not start a fresh count.
		f := cfg.Rate.AddrFactor
		ak, _ := addrKey(scopeAddr, r.Client)
		sus := Limit{Burst: cfg.Rate.Sustained.Burst * f, Per: cfg.Rate.Sustained.Per}
		bur := Limit{Burst: cfg.Rate.Burst.Burst * f, Per: cfg.Rate.Burst.Per}
		if allowed, retry, _ := g.lim.allow(ak, sus, bur, now); !allowed {
			return in.emit(IDRateLimited, retryAfter(retry), cfg.Modes.Rate)
		}
	}
	return false
}

// retryAfter words how long to wait, in the form an HTTP header has it.
func retryAfter(d time.Duration) string {
	secs := int(d / time.Second)
	if d%time.Second != 0 || secs == 0 {
		secs++
	}
	return "Retry-After: " + strconv.Itoa(secs)
}

// ---- observing ----

// Observe is told what the application answered for a request that was let through, and learns from it if it was a success. It
// never blocks and never panics.
func (g *Guard) Observe(r *inspect.Request, status int) {
	defer func() {
		if p := recover(); p != nil {
			g.st.panics.Add(1)
		}
	}()
	if r == nil || status < 200 || status >= 400 {
		return
	}
	cfg := g.config()
	if cfg.Mode == ModeOff || !cfg.methodAllowed(r.Method) {
		return
	}
	lm := effective(cfg.Mode, cfg.Modes.Learned)
	var view reqView
	view.init(r)
	rv := &view
	decl := g.active.Load()
	known := false
	if decl != nil {
		var caps captures
		known = decl.idx.lookup(r.Path, &caps) != nil
	}
	if !known && lm >= ModeLearn {
		lk := g.learn.lookup(r.Method, r.Path)
		known = lk.view != nil || lk.otherMethod
	}
	if !known && !isAPIPath(r.Path) && !isAPIContentType(rv.ct) && !acceptsAPI(r.Header.Get("Accept")) {
		return
	}
	// A body larger than a request to that method should ever carry is not evidence of what the API takes.
	if int64(len(r.Body)) > cfg.bodyLimit(r.Method) {
		return
	}
	g.st.observed.Add(1)
	client := g.learn.clientID(r)
	if lm >= ModeLearn {
		g.learn.observe(r, rv, client, false)
		if len(r.Body) > 0 {
			g.learn.observeContentType(rv.ct, client, false, cfg)
		}
	}
	if c := g.cand.Load(); c != nil {
		g.shadow(c, rv, client, cfg)
	}
}

// ---- owner actions ----

// Observation is a request and the status the application answered it with: what a recording holds.
type Observation struct {
	Request inspect.Request
	Status  int
	// ResponseType is the media type the application answered with, if the recording has it. A request that answered with JSON or
	// XML is an API request whatever its path looks like.
	ResponseType string
}

// Learn teaches the guard from observations an owner supplies (a recorded session, a collection): they count as full evidence, as
// if enough different clients had made them, because the owner is vouching for them. Do not feed it traffic captured from
// visitors. It returns how many were used.
func (g *Guard) Learn(obs []Observation) int {
	cfg := g.config()
	used := 0
	for i := range obs {
		o := &obs[i]
		if o.Status < 200 || o.Status >= 400 || !cfg.methodAllowed(o.Request.Method) || o.Request.Method == "OPTIONS" || !strings.HasPrefix(o.Request.Path, "/") {
			continue
		}
		if o.Request.Header == nil {
			o.Request.Header = map[string][]string{}
		}
		var view reqView
		view.init(&o.Request)
		rv := &view
		if !isAPIPath(o.Request.Path) && !isAPIContentType(rv.ct) && !isAPIContentType(o.ResponseType) && !acceptsAPI(o.Request.Header.Get("Accept")) {
			continue // a page or a script the browser loaded, not a call to the API
		}
		g.learn.observe(&o.Request, rv, 0, true)
		if len(o.Request.Body) > 0 {
			g.learn.observeContentType(rv.ct, 0, true, cfg)
		}
		used++
	}
	return used
}

// Approve teaches the guard that a route is real, on the owner's word. It is what to use for a new endpoint when the learned
// model is enforced: a refused request is never seen by the learner, so a route that has never been seen cannot teach itself.
func (g *Guard) Approve(method, path string) error {
	method = strings.ToUpper(method)
	if !g.config().methodAllowed(method) || method == "OPTIONS" {
		return errors.New("the method is not one the guard learns routes for")
	}
	if !strings.HasPrefix(path, "/") || len(path) > 2000 {
		return errors.New("the path must start with / and be at most 2000 bytes")
	}
	r := &inspect.Request{Method: method, Path: path, Header: map[string][]string{}}
	var view reqView
	view.init(r)
	g.learn.observe(r, &view, 0, true)
	return nil
}

// Flush brings every learned route's enforceable view up to date now. Views are kept up to date as requests are observed; this is
// for a caller that wants the answer without waiting for more traffic.
func (g *Guard) Flush() { g.learn.flush() }

// Sweep forgets learned routes and path positions that have not been seen for a long time. It runs by itself about once a
// minute while requests are observed; this runs it now.
func (g *Guard) Sweep() { g.learn.sweep(g.clock().Unix(), g.config()) }

// ResetLearned forgets everything that was learned.
func (g *Guard) ResetLearned() {
	var seed [8]byte
	rand.Read(seed[:])
	empty := Model{Format: ModelFormat, Seed: binary.LittleEndian.Uint64(seed[:])}
	_ = g.learn.load(&empty)
}

// SaveLearned returns what has been learned, in the saved form: versioned, and what LoadLearned reads.
func (g *Guard) SaveLearned() ([]byte, error) {
	m := g.learn.export()
	return m.MarshalJSON()
}

// LoadLearned replaces what has been learned with a saved model. The model is read strictly (see Model.UnmarshalJSON) and a
// model that does not fit this guard's learning limits is refused whole.
func (g *Guard) LoadLearned(data []byte) error {
	var m Model
	if err := m.UnmarshalJSON(data); err != nil {
		return err
	}
	return g.learn.load(&m)
}

// Snapshot returns the guard's current model: the active description's routes (declared), a candidate's (candidate), and what has
// been learned, each learned route with its state, learned-enforceable or learning.
func (g *Guard) Snapshot() Model {
	m := g.learn.export()
	m.Source = "snapshot"
	if a := g.active.Load(); a != nil {
		m.Title, m.SpecVersion, m.Hash, m.Fetched = a.Title, a.SpecVersion, a.Hash, a.Fetched
		m.CredentialHeaders, m.CredentialQuery, m.CredentialCookies = a.CredentialHeaders, a.CredentialQuery, a.CredentialCookies
		m.Source = a.Source
		for _, r := range a.Routes {
			r.State = StateDeclared
			m.Routes = append(m.Routes, r)
		}
	}
	if c := g.cand.Load(); c != nil {
		if m.Hash == "" {
			m.Title, m.SpecVersion, m.Hash, m.Fetched, m.Source = c.model.Title, c.model.SpecVersion, c.model.Hash, c.model.Fetched, c.model.Source
		}
		for _, r := range c.model.Routes {
			r.State = StateCandidate
			m.Routes = append(m.Routes, r)
		}
		m.State = ModelCandidate
	}
	if g.active.Load() != nil {
		m.State = ModelActive
	}
	slices.SortStableFunc(m.Routes, func(a, b Route) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return strings.Compare(a.Method, b.Method)
	})
	return m
}

// SetModel installs a described model as the one in force, on the owner's word (no candidate period).
func (g *Guard) SetModel(m Model) error {
	if len(m.Routes) > MaxRoutes {
		return errors.New("the model has too many routes")
	}
	if m.idx == nil {
		if err := m.validateLoaded(); err != nil {
			return err
		}
		m.finish(nil)
	}
	m.State = ModelActive
	g.active.Store(&m)
	g.cand.Store(nil)
	return nil
}

// ImportOpenAPI reads an OpenAPI or Swagger description the owner supplies and puts it in force.
func (g *Guard) ImportOpenAPI(data []byte) (Report, error) {
	m, rep, err := ImportOpenAPI(data)
	if err != nil {
		return rep, err
	}
	m.Source, m.Fetched = "supplied", rep.When
	if err := g.SetModel(m); err != nil {
		return rep, err
	}
	rep.Outcome = "in force"
	return rep, nil
}

// DropModel removes the described model (the active one and any candidate). What was learned is kept.
func (g *Guard) DropModel() {
	g.active.Store(nil)
	g.cand.Store(nil)
}

// Stats is a count of what the guard has done.
type Stats struct {
	Requests    uint64 // requests inspected
	APIRequests uint64 // of those, the ones taken to be API requests
	Refused     uint64 // findings that blocked
	Flagged     uint64 // findings that were only reported
	Panics      uint64 // failures inside the guard: refused under enforce, reported under monitor (5003990)
	Observed    uint64 // requests learned from
	ByVerdict   map[int]uint64

	RateKeys     int    // clients being counted
	RateEvicted  uint64 // idle clients forgotten to make room
	RateFailOpen uint64 // requests let through uncounted because the table was full of active clients
	RateNoClient uint64 // requests with no client address

	LearnedRoutes     int
	LearnedEnforce    int
	LearnNodes        int
	LearnDropped      uint64 // things not learned because a limit was reached
	CollapsedPlaces   int
	ModelState        string // none, candidate or active
	DeclaredRoutes    int
	CandidateRoutes   int
	CandidateAgree    uint32
	CandidateDisagree uint32
	Promotions        uint64
	GraphQLSeen       bool
}

// Stats returns the counts so far.
func (g *Guard) Stats() Stats {
	s := Stats{
		Requests: g.st.requests.Load(), APIRequests: g.st.api.Load(), Refused: g.st.refused.Load(), Flagged: g.st.flagged.Load(),
		Panics: g.st.panics.Load(), Observed: g.st.observed.Load(), ByVerdict: map[int]uint64{},
		RateKeys: g.lim.keys(), RateEvicted: g.lim.evicted.Load(), RateFailOpen: g.lim.failOpen.Load(), RateNoClient: g.lim.noClient.Load(),
		LearnDropped: g.learn.dropped.Load(), LearnNodes: int(g.learn.nodes.Load()), CollapsedPlaces: len(*g.learn.collapsed.Load()),
		Promotions: g.st.promotions.Load(), GraphQLSeen: g.gql.Load(), ModelState: "none",
	}
	for i := range g.st.byID {
		if n := g.st.byID[i].Load(); n > 0 {
			s.ByVerdict[5003000+i] = n
		}
	}
	s.LearnedRoutes, s.LearnedEnforce = g.learn.counts()
	if a := g.active.Load(); a != nil {
		s.ModelState, s.DeclaredRoutes = "active", len(a.Routes)
	}
	if c := g.cand.Load(); c != nil {
		s.CandidateRoutes = len(c.model.Routes)
		s.CandidateAgree, s.CandidateDisagree = c.counts()
		if s.ModelState == "none" {
			s.ModelState = "candidate"
		}
	}
	return s
}

// startsLikeJSON reports whether a body's first byte after white space opens a JSON object or array.
func startsLikeJSON(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		}
		return false
	}
	return false
}
