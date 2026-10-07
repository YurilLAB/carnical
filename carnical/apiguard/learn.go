// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

const (
	posShards = 16
	// maxPosValues is how many different words one path position follows.
	maxPosValues = 64
	// collapseMinTotal is how many sightings a path position needs before it can be read as a parameter. A position that has many
	// different words after only a few sightings may simply be an API that has many resources and has not been used much yet.
	collapseMinTotal = 50
	maxParamName     = 64
	maxArrayItems    = 16
	maxEnumLen       = 64
	maxPositions     = 1_000_000
)

type posVal struct {
	h uint64
	n uint32
}

type position struct {
	vals  []posVal
	total uint32
	last  int64
}

type posShard struct {
	mu sync.Mutex
	m  map[string]*position
}

// lroute is one route being learned. mu guards d and nodes; view is replaced whole, so a request being checked reads it with no
// lock.
type lroute struct {
	mu     sync.Mutex
	method string
	tmpl   string
	d      LearnedRoute
	nodes  int
	dirty  bool
	view   atomic.Pointer[Route]
}

// learner holds what the guard has learned from the traffic that was let through. It is safe for many requests at once: the route
// table is guarded by one read-write lock that is taken for writing only when a route appears or goes, each route has its own lock,
// and what a request is checked against is an immutable view swapped in whole.
type learner struct {
	cfg   func() *Config
	clock func() time.Time
	seed  atomic.Uint64

	mu     sync.RWMutex
	routes map[string]*lroute   // "METHOD template"
	byTmpl map[string][]*lroute // template -> its routes, one per method

	collapsed  atomic.Pointer[collapsedSet]
	collapseMu sync.Mutex
	pos        [posShards]posShard
	posCount   atomic.Int64

	nodes       atomic.Int64
	enforceable atomic.Int64

	ctMu   sync.Mutex
	ctypes map[string]*Evidence // content types seen on any API request, for the shield

	observed  atomic.Uint64
	dropped   atomic.Uint64 // things not learned because a limit was reached
	lastSweep atomic.Int64
}

func newLearner(cfg func() *Config, clock func() time.Time, seed uint64) *learner {
	l := &learner{cfg: cfg, clock: clock, routes: map[string]*lroute{}, byTmpl: map[string][]*lroute{}, ctypes: map[string]*Evidence{}}
	l.seed.Store(seed)
	empty := collapsedSet{}
	l.collapsed.Store(&empty)
	for i := range l.pos {
		l.pos[i].m = map[string]*position{}
	}
	return l
}

func (c *Config) rule() evRule {
	// #nosec G115 -- Guard.New/SetConfig validate before publishing this private config: observations <= 1,000,000, share <= 100; both positive after defaults.
	return evRule{minObs: uint32(c.Learn.MinObservations), minClients: c.Learn.MinClients, maxShare: uint32(c.Learn.MaxClientShare)}
}

// fnv-1a, seeded: the table of path words and the identifiers of clients are both keyed with a value that belongs to this guard, so
// a visitor cannot choose words or addresses that collide.
func hashOf[T ~string | ~[]byte](seed uint64, b T) uint64 {
	h := uint64(14695981039346656037) ^ seed
	for i := 0; i < len(b); i++ {
		h ^= uint64(b[i])
		h *= 1099511628211
	}
	h ^= h >> 29
	h *= 0xbf58476d1ce4e5b9
	return h ^ h>>32
}

// clientID identifies a client for the evidence rule. An IPv4 address is cut to its /24 and an IPv6 address to its /48, so a
// person with a block of addresses is one client, not hundreds.
func (l *learner) clientID(r *inspect.Request) uint32 {
	a := r.Client.Unmap()
	switch {
	case a.Is4():
		b := a.As4()
		return uint32(hashOf(l.seed.Load(), b[:3]) & 0xffffffff)
	case a.Is6():
		b := a.As16()
		return uint32(hashOf(l.seed.Load(), b[:6]) & 0xffffffff)
	}
	return 0
}

// ---- observing ----

func satAdd(a, b uint32) uint32 {
	if s := a + b; s >= a {
		return s
	}
	return ^uint32(0)
}

// observe learns from one request that was answered below 400. trusted means an owner vouches for it (a recording or an approval):
// it counts for as much as the evidence rule asks.
func (l *learner) observe(r *inspect.Request, rv *reqView, client uint32, trusted bool) {
	cfg := l.cfg()
	method := r.Method
	switch method {
	case "HEAD":
		method = "GET"
	case "OPTIONS":
		return // a preflight says nothing about the API, and an application answers it for any path
	}
	now := l.clock().Unix()
	var keybuf [512]byte
	cs := l.collapsed.Load()
	again := false
	key, ok := templateOf(method, r.Path, *cs, keybuf[:0], func(prefix []byte, seg string) {
		if l.track(prefix, seg, cfg, now) {
			again = true
		}
	})
	if !ok {
		return
	}
	if again {
		key, ok = templateOf(method, r.Path, *l.collapsed.Load(), keybuf[:0], nil)
		if !ok {
			return
		}
	}
	rt := l.route(key, method, cfg)
	if rt == nil {
		l.dropped.Add(1)
		return
	}
	rule := cfg.rule()
	w := uint32(1)
	if trusted {
		w = rule.minObs
	}
	rt.mu.Lock()
	l.update(rt, rv, client, w, trusted, &rule, cfg, now)
	rt.mu.Unlock()
	l.observed.Add(1)
	l.maybeSweep(now, cfg)
}

// route finds a route or makes it. nil means a limit was reached.
func (l *learner) route(key []byte, method string, cfg *Config) *lroute {
	l.mu.RLock()
	rt := l.routes[string(key)]
	l.mu.RUnlock()
	if rt != nil {
		return rt
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if rt = l.routes[string(key)]; rt != nil {
		return rt
	}
	if len(l.routes) >= cfg.Learn.MaxRoutes || l.nodes.Load() >= int64(cfg.Learn.MaxNodes) {
		return nil
	}
	tmpl := string(key[len(method)+1:])
	rt = &lroute{method: method, tmpl: tmpl, nodes: 1}
	l.routes[string(key)] = rt
	l.byTmpl[tmpl] = append(l.byTmpl[tmpl], rt)
	l.nodes.Add(1)
	return rt
}

func (rt *lroute) addNodes(l *learner, n int) {
	rt.nodes += n
	l.nodes.Add(int64(n))
}

func (rt *lroute) hit(e *Evidence, client, w uint32, trusted bool, rule *evRule) {
	var flipped bool
	if trusted {
		flipped = e.addTrusted(rule)
	} else {
		flipped = e.add(client, w, rule)
	}
	if flipped {
		rt.dirty = true
	}
}

// update folds one request into a route. rt.mu is held.
func (l *learner) update(rt *lroute, rv *reqView, client, w uint32, trusted bool, rule *evRule, cfg *Config, now int64) {
	d := &rt.d
	prev := d.Obs
	if d.First == 0 {
		d.First = now
	}
	d.Last = now
	d.Obs = satAdd(d.Obs, w)
	rt.hit(&d.Ev, client, w, trusted, rule)

	if len(rv.body) > 0 {
		rt.hit(&d.BodyEv, client, w, trusted, rule)
		if ct := rv.ct; ct != "" && validMediaType(ct) {
			ev := d.CTypes[ct]
			if ev == nil && len(d.CTypes) < maxCTypes {
				if d.CTypes == nil {
					d.CTypes = map[string]*Evidence{}
				}
				ev = &Evidence{}
				d.CTypes[ct] = ev
				rt.addNodes(l, 1)
			}
			if ev != nil {
				rt.hit(ev, client, w, trusted, rule)
			}
		}
		if rv.isJSON {
			if val, dup, err := rv.json(); err == nil && !dup {
				d.Bodies = satAdd(d.Bodies, w)
				if d.Body == nil {
					d.Body = &Shape{}
					rt.addNodes(l, 1)
				}
				l.shape(rt, d.Body, val, 0, client, w, trusted, rule, cfg)
			}
		}
	}

	var seen [maxQueryParams + 8]string
	nseen := 0
	for _, q := range rv.q() {
		name := q.name
		if name == "" || len(name) > maxParamName {
			continue
		}
		again := false
		for _, s := range seen[:nseen] {
			if s == name {
				again = true
				break
			}
		}
		if again {
			continue
		}
		if nseen < len(seen) {
			seen[nseen] = name
			nseen++
		}
		ps := d.Query[name]
		if ps == nil {
			if len(d.Query) >= maxQueryParams || l.nodes.Load() >= int64(cfg.Learn.MaxNodes) {
				l.dropped.Add(1)
				continue
			}
			if d.Query == nil {
				d.Query = map[string]*ParamStat{}
			}
			ps = &ParamStat{}
			d.Query[name] = ps
			rt.addNodes(l, 1)
		}
		rt.hit(&ps.Seen, client, w, trusted, rule)
		l.paramValue(rt, ps, q.value, client, w, trusted, rule, cfg)
	}
	if rt.dirty || prev/64 != d.Obs/64 {
		l.rebuild(rt, cfg)
	}
}

// classifyValue says what kind of value a query parameter held.
func classifyValue(v string) pclass {
	switch {
	case v == "":
		return pcEmpty
	case looksNumeric(v):
		if isPlainInt(v) {
			return pcInt
		}
		return pcNum
	case v == "true" || v == "false" || v == "True" || v == "False":
		return pcBool
	case len(v) == 36 && isUUID(v):
		return pcUUID
	case isDatePrefix(v) && len(v) <= 40:
		return pcDate
	}
	return pcStr
}

// isPlainInt reports whether v is -?digits that fit an int64.
func isPlainInt(v string) bool {
	_, err := strconv.ParseInt(v, 10, 64)
	return err == nil && !strings.HasPrefix(v, "+")
}

func (l *learner) paramValue(rt *lroute, ps *ParamStat, value string, client, w uint32, trusted bool, rule *evRule, cfg *Config) {
	cls := classifyValue(value)
	name := pclassNames[cls]
	ev := ps.Classes[name]
	if ev == nil {
		if ps.Classes == nil {
			ps.Classes = map[string]*Evidence{}
		}
		ev = &Evidence{}
		ps.Classes[name] = ev
		rt.addNodes(l, 1)
	}
	rt.hit(ev, client, w, trusted, rule)
	if cls == pcInt {
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			first := ev.N <= w
			if first || n < ps.IntMin {
				ps.IntMin = n
			}
			if first || n > ps.IntMax {
				ps.IntMax = n
			}
		}
	}
	ps.LenMax = max(ps.LenMax, len(value))
	if ps.Overflow || cls == pcEmpty {
		return
	}
	if len(value) > maxEnumLen {
		l.overflow(rt, ps)
		return
	}
	ve := ps.Values[value]
	if ve == nil {
		if len(ps.Values) >= cfg.Learn.DistinctValues || len(ps.Values) >= maxEnumValues {
			l.overflow(rt, ps)
			return
		}
		if ps.Values == nil {
			ps.Values = map[string]*Evidence{}
		}
		ve = &Evidence{}
		ps.Values[value] = ve
		rt.addNodes(l, 1)
	}
	rt.hit(ve, client, w, trusted, rule)
}

// overflow stops following a parameter's values: it takes too many to be an enumeration.
func (l *learner) overflow(rt *lroute, ps *ParamStat) {
	rt.addNodes(l, -len(ps.Values))
	ps.Values, ps.Overflow = nil, true
	rt.dirty = true
}

// shape folds a JSON value into the shape learned for its place in the body.
func (l *learner) shape(rt *lroute, sh *Shape, v any, depth int, client, w uint32, trusted bool, rule *evRule, cfg *Config) {
	rt.hit(&sh.Seen, client, w, trusted, rule)
	t := typeOf(v)
	te := sh.Types[t]
	if te == nil {
		te = &Evidence{}
		sh.Types[t] = te
		rt.addNodes(l, 1)
	}
	rt.hit(te, client, w, trusted, rule)
	switch x := v.(type) {
	case map[string]any:
		sh.ObjN = satAdd(sh.ObjN, w)
		if depth+1 > maxShapeDepth {
			sh.Open = true
			return
		}
		for k, child := range x {
			if len(k) > maxParamName {
				sh.Open = true
				continue
			}
			p := sh.Props[k]
			if p == nil {
				if len(sh.Props) >= maxShapeProps || l.nodes.Load() >= int64(cfg.Learn.MaxNodes) {
					sh.Open = true
					continue
				}
				if sh.Props == nil {
					sh.Props = map[string]*Shape{}
				}
				p = &Shape{}
				sh.Props[k] = p
				rt.addNodes(l, 1)
			}
			l.shape(rt, p, child, depth+1, client, w, trusted, rule, cfg)
		}
	case []any:
		if depth+1 > maxShapeDepth {
			return
		}
		if sh.Items == nil {
			sh.Items = &Shape{}
			rt.addNodes(l, 1)
		}
		for i, e := range x {
			if i >= maxArrayItems {
				break
			}
			l.shape(rt, sh.Items, e, depth+1, client, w, trusted, rule, cfg)
		}
	}
}

// ---- path positions ----

// track notes one more sighting of a word at a path position and reports whether that turned the position into a parameter.
//
// A position holds names (the resources of an API: users, orders, products) or identifiers that have no mark of one (slugs). The
// two differ in how often a word comes back: each name is used again and again, and most slugs are seen once or twice. So a
// position becomes a parameter when it has more than DistinctValues different words, has been seen at least collapseMinTotal
// times, and fewer than half of its words have been seen three times. An API with fifteen resources is therefore not read as
// /{id}, and a catalogue with thousands of slugs is.
func (l *learner) track(prefix []byte, seg string, cfg *Config, now int64) bool {
	seed := l.seed.Load()
	sh := &l.pos[hashOf(seed, prefix)%posShards]
	h := hashOf(seed, seg)
	sh.mu.Lock()
	p := sh.m[string(prefix)]
	if p == nil {
		if int(l.posCount.Load()) >= cfg.Learn.MaxPositions {
			sh.mu.Unlock()
			l.dropped.Add(1)
			return false
		}
		p = &position{}
		sh.m[string(prefix)] = p
		l.posCount.Add(1)
	}
	p.last = now
	p.total = satAdd(p.total, 1)
	found := false
	for i := range p.vals {
		if p.vals[i].h == h {
			p.vals[i].n = satAdd(p.vals[i].n, 1)
			found = true
			break
		}
	}
	if !found && len(p.vals) < maxPosValues {
		p.vals = append(p.vals, posVal{h, 1})
	}
	collapse := false
	if n := len(p.vals); n > cfg.Learn.DistinctValues && (p.total >= collapseMinTotal || n >= maxPosValues) {
		repeated := 0
		for _, v := range p.vals {
			if v.n >= 3 {
				repeated++
			}
		}
		collapse = repeated*2 < n
	}
	sh.mu.Unlock()
	if collapse {
		l.collapse(string(prefix))
		return true
	}
	return false
}

// collapse turns the position after prefix into a parameter. What was learned under its separate words is dropped (it is learned
// again under the parameter), which loses a little evidence and keeps the code that would merge two shapes out of the path that
// handles every request.
func (l *learner) collapse(prefix string) {
	l.collapseMu.Lock()
	defer l.collapseMu.Unlock()
	old := *l.collapsed.Load()
	if _, done := old[prefix]; done || len(old) >= int(l.cfg().Learn.MaxPositions) {
		return
	}
	next := make(collapsedSet, len(old)+1)
	for k := range old {
		next[k] = struct{}{}
	}
	next[prefix] = struct{}{}
	l.collapsed.Store(&next)

	under := prefix + "/"
	l.mu.Lock()
	for key, rt := range l.routes {
		rest, ok := strings.CutPrefix(rt.tmpl, under)
		if !ok || strings.HasPrefix(rest, "{") {
			continue
		}
		rt.mu.Lock()
		l.nodes.Add(-int64(rt.nodes))
		if rt.view.Load() != nil {
			l.enforceable.Add(-1)
		}
		rt.mu.Unlock()
		delete(l.routes, key)
		list := l.byTmpl[rt.tmpl]
		list = slices.DeleteFunc(list, func(x *lroute) bool { return x == rt })
		if len(list) == 0 {
			delete(l.byTmpl, rt.tmpl)
		} else {
			l.byTmpl[rt.tmpl] = list
		}
	}
	l.mu.Unlock()
	for i := range l.pos {
		s := &l.pos[i]
		s.mu.Lock()
		for k := range s.m {
			if k == prefix || strings.HasPrefix(k, under) {
				delete(s.m, k)
				l.posCount.Add(-1)
			}
		}
		s.mu.Unlock()
	}
}

// ---- views ----

// rebuild makes the enforceable view of a route from what has been learned. rt.mu is held.
func (l *learner) rebuild(rt *lroute, cfg *Config) {
	rt.dirty = false
	v := l.buildView(rt, cfg)
	old := rt.view.Swap(v)
	switch {
	case old == nil && v != nil:
		l.enforceable.Add(1)
	case old != nil && v == nil:
		l.enforceable.Add(-1)
	}
}

func (l *learner) buildView(rt *lroute, cfg *Config) *Route {
	d := &rt.d
	if !d.Ev.OK {
		return nil
	}
	// #nosec G115 -- Only Guard's validated private config reaches rebuild/buildView: required observations 1..1,000,000, percentage 50..100.
	reqMin, reqPct := uint32(cfg.Learn.RequiredMinObservations), uint32(cfg.Learn.RequiredPercent)
	r := &Route{Method: rt.method, Path: rt.tmpl, State: StateEnforceable, StrictQuery: true}
	names := make([]string, 0, len(d.Query))
	for n := range d.Query {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		ps := d.Query[n]
		if !ps.Seen.OK {
			continue
		}
		required := d.Obs >= reqMin && uint64(ps.Seen.N)*100 >= uint64(reqPct)*uint64(d.Obs)
		r.Params = append(r.Params, Param{Name: n, In: "query", Required: required, Schema: paramSchema(ps)})
	}
	cts := make([]string, 0, len(d.CTypes))
	for ct, e := range d.CTypes {
		if e.OK {
			cts = append(cts, ct)
		}
	}
	slices.Sort(cts)
	r.ContentTypes = cts
	if d.BodyEv.N == 0 {
		r.NoBody = true
	} else if d.BodyEv.OK && uint64(d.BodyEv.N)*100 >= uint64(reqPct)*uint64(d.Obs) && d.Obs >= reqMin {
		r.BodyRequired = true
	}
	if d.Bodies > 0 && d.Body != nil && d.Body.Seen.OK {
		r.Body = shapeSchema(d.Body, 0, reqMin, reqPct)
	}
	r.compile()
	dropped := 0
	seen := map[*Schema]bool{}
	patterns := map[string]*regexp.Regexp{}
	for i := range r.Params {
		r.Params[i].Schema.prepare(seen, patterns, &dropped)
	}
	r.Body.prepare(seen, patterns, &dropped)
	return r
}

// paramSchema makes the schema of a learned query parameter: the kinds of value that have enough support, and if it takes only a
// few values, which. An empty value is always allowed: it says nothing about the kind of the parameter.
func paramSchema(ps *ParamStat) *Schema {
	var branches []*Schema
	anyString := false
	for _, cls := range []pclass{pcInt, pcNum, pcBool, pcUUID, pcDate, pcStr} {
		if e := ps.Classes[pclassNames[cls]]; e == nil || !e.OK {
			continue
		}
		switch cls {
		case pcInt:
			branches = append(branches, &Schema{Type: []string{"integer"}})
		case pcNum:
			branches = append(branches, &Schema{Type: []string{"number"}})
		case pcBool:
			branches = append(branches, &Schema{Type: []string{"boolean"}})
		case pcUUID:
			branches = append(branches, &Schema{Type: []string{"string"}, Format: "uuid"})
		case pcDate:
			branches = append(branches, &Schema{Type: []string{"string"}, Pattern: `^\d{4}-\d{2}-\d{2}`})
		case pcStr:
			anyString = true
		}
	}
	if len(branches) == 0 && !anyString {
		return nil
	}
	s := &Schema{}
	if !anyString {
		branches = append(branches, &Schema{Type: []string{"string"}, MaxLength: intPtr(0)})
		s.AnyOf = branches
	}
	if anyString && !ps.Overflow && len(ps.Values) > 0 {
		// An enumeration is only made for words, and only when at least two of them are believed: a number is usually not one of a
		// closed set (a page size of 10 does not mean 25 is refused), and a parameter that always has the same value is not
		// shown to be an enumeration by that.
		var enum []JSONValue
		keys := make([]string, 0, len(ps.Values))
		for v := range ps.Values {
			keys = append(keys, v)
		}
		slices.Sort(keys)
		// Only the values that have enough support are in the enumeration. A value seen too seldom to be believed is refused,
		// which is what seldom costs.
		for _, v := range keys {
			if !ps.Values[v].OK {
				continue
			}
			switch classifyValue(v) {
			case pcInt, pcNum:
				enum = append(enum, JSONValue{Num(v)})
			case pcBool:
				enum = append(enum, JSONValue{v == "true" || v == "True"})
			default:
				enum = append(enum, JSONValue{v})
			}
		}
		if len(enum) >= 2 {
			// An empty value says nothing about which value was meant, so it is always let through.
			s.Enum = append(enum, JSONValue{""})
		}
	}
	return s
}

func intPtr(n int) *int { return &n }

// shapeSchema makes the schema of a learned JSON value.
func shapeSchema(sh *Shape, depth int, reqMin, reqPct uint32) *Schema {
	s := &Schema{}
	if sh == nil || !sh.Seen.OK || depth > maxShapeDepth {
		return s
	}
	var types []string
	has := func(t jtype) bool { e := sh.Types[t]; return e != nil && e.OK }
	switch {
	case has(tInt) && has(tNum), has(tNum):
		types = append(types, "number")
	case has(tInt):
		types = append(types, "integer")
	}
	if has(tBool) {
		types = append(types, "boolean")
	}
	if has(tStr) {
		types = append(types, "string")
	}
	if has(tArr) {
		types = append(types, "array")
	}
	if has(tObj) {
		types = append(types, "object")
	}
	if has(tNull) {
		s.Nullable = true
	}
	if len(types) == 0 {
		return s // supported as a value, but no kind of value is: say nothing about it
	}
	s.Type = types
	if has(tObj) {
		s.Properties = map[string]*Schema{}
		for name, p := range sh.Props {
			if !p.Seen.OK {
				continue
			}
			s.Properties[name] = shapeSchema(p, depth+1, reqMin, reqPct)
			if sh.ObjN >= reqMin && uint64(p.Seen.N)*100 >= uint64(reqPct)*uint64(sh.ObjN) {
				s.Required = append(s.Required, name)
			}
		}
		slices.Sort(s.Required)
		if !sh.Open {
			f := false
			s.AdditionalProperties = &f
		}
	}
	if has(tArr) && sh.Items != nil && sh.Items.Seen.OK {
		s.Items = shapeSchema(sh.Items, depth+1, reqMin, reqPct)
	}
	return s
}

// ---- looking up ----

// learnedLookup is what the learner knows about a request's route.
type learnedLookup struct {
	view *Route // the enforceable route for this method, or nil
	// otherMethod is true if the path is an enforceable route under another method.
	otherMethod bool
}

func (l *learner) lookup(method, path string) learnedLookup {
	if l.enforceable.Load() == 0 {
		return learnedLookup{}
	}
	if method == "HEAD" {
		method = "GET"
	}
	var buf [512]byte
	key, ok := templateOf(method, path, *l.collapsed.Load(), buf[:0], nil)
	if !ok {
		return learnedLookup{}
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if rt := l.routes[string(key)]; rt != nil {
		if v := rt.view.Load(); v != nil {
			return learnedLookup{view: v}
		}
	}
	for _, o := range l.byTmpl[string(key[len(method)+1:])] {
		if o.view.Load() != nil {
			return learnedLookup{otherMethod: true}
		}
	}
	return learnedLookup{}
}

// ---- the shield's own learning: content types ----

func (l *learner) observeContentType(ct string, client uint32, trusted bool, cfg *Config) {
	if ct == "" || !validMediaType(ct) {
		return
	}
	rule := cfg.rule()
	l.ctMu.Lock()
	defer l.ctMu.Unlock()
	e := l.ctypes[ct]
	if e == nil {
		if len(l.ctypes) >= 32 {
			l.dropped.Add(1)
			return
		}
		e = &Evidence{}
		l.ctypes[ct] = e
	}
	if trusted {
		e.addTrusted(&rule)
	} else {
		e.add(client, 1, &rule)
	}
}

// contentTypeSeen reports whether a media type has been seen enough to count as one this API uses, and whether the guard has
// seen enough to say anything: until at least one type has support, nothing is "unseen".
func (l *learner) contentTypeSeen(ct string) (seen, mature bool) {
	l.ctMu.Lock()
	defer l.ctMu.Unlock()
	for k, e := range l.ctypes {
		if e.OK {
			mature = true
			if k == ct {
				seen = true
			}
		}
	}
	return seen, mature
}

// ---- decay ----

func (l *learner) maybeSweep(now int64, cfg *Config) {
	last := l.lastSweep.Load()
	if now-last < 60 || !l.lastSweep.CompareAndSwap(last, now) {
		return
	}
	l.sweep(now, cfg)
}

// sweep forgets what has not been seen for a long time: a route that never became enforceable after LearningTTL, one that did
// after RouteTTL, and path positions that have not been used for LearningTTL. A route that is still in use is never forgotten.
func (l *learner) sweep(now int64, cfg *Config) {
	learning, enforce := int64(cfg.Learn.LearningTTL/time.Second), int64(cfg.Learn.RouteTTL/time.Second)
	l.mu.Lock()
	for key, rt := range l.routes {
		rt.mu.Lock()
		age := now - rt.d.Last
		ttl := learning
		if rt.view.Load() != nil {
			ttl = enforce
		}
		gone := age > ttl
		if gone {
			l.nodes.Add(-int64(rt.nodes))
			if rt.view.Load() != nil {
				l.enforceable.Add(-1)
			}
		}
		rt.mu.Unlock()
		if gone {
			delete(l.routes, key)
			list := slices.DeleteFunc(l.byTmpl[rt.tmpl], func(x *lroute) bool { return x == rt })
			if len(list) == 0 {
				delete(l.byTmpl, rt.tmpl)
			} else {
				l.byTmpl[rt.tmpl] = list
			}
		}
	}
	l.mu.Unlock()
	for i := range l.pos {
		s := &l.pos[i]
		s.mu.Lock()
		for k, p := range s.m {
			if now-p.last > learning {
				delete(s.m, k)
				l.posCount.Add(-1)
			}
		}
		s.mu.Unlock()
	}
}

// flush rebuilds every route's view now. The views are kept up to date as requests arrive; this is for a caller that has just
// loaded or changed something and wants the answer without waiting for the next request.
func (l *learner) flush() {
	cfg := l.cfg()
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, rt := range l.routes {
		rt.mu.Lock()
		l.rebuild(rt, cfg)
		rt.mu.Unlock()
	}
}

// ---- saving and loading ----

// export returns what has been learned as a model: every route with its state and its evidence.
func (l *learner) export() Model {
	m := Model{Format: ModelFormat, Source: "learned", Seed: l.seed.Load(), State: ModelActive}
	l.mu.RLock()
	keys := make([]string, 0, len(l.routes))
	for k := range l.routes {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		rt := l.routes[k]
		rt.mu.Lock()
		var r Route
		if v := rt.view.Load(); v != nil {
			r = *v
			r.State = StateEnforceable
		} else {
			r = Route{Method: rt.method, Path: rt.tmpl, State: StateLearning}
		}
		r.Learned = rt.d.clone()
		rt.mu.Unlock()
		m.Routes = append(m.Routes, r)
	}
	l.mu.RUnlock()
	for k := range *l.collapsed.Load() {
		m.Collapsed = append(m.Collapsed, k)
	}
	slices.Sort(m.Collapsed)
	l.ctMu.Lock()
	if len(l.ctypes) > 0 {
		m.SeenContentTypes = make(map[string]*Evidence, len(l.ctypes))
		for k, e := range l.ctypes {
			m.SeenContentTypes[k] = e.clone()
		}
	}
	l.ctMu.Unlock()
	return m
}

var errLearnLimit = errors.New("the saved model is larger than this guard's learning limits allow")

// load replaces what has been learned with a saved model. A route in it that has no learned data (a described route) is ignored.
func (l *learner) load(m *Model) error {
	cfg := l.cfg()
	fresh := newLearner(l.cfg, l.clock, m.Seed)
	cs := collapsedSet{}
	for _, p := range m.Collapsed {
		cs[p] = struct{}{}
	}
	fresh.collapsed.Store(&cs)
	for k, e := range m.SeenContentTypes {
		fresh.ctypes[k] = e.clone()
	}
	for i := range m.Routes {
		r := &m.Routes[i]
		if r.Learned == nil {
			continue
		}
		if len(fresh.routes) >= cfg.Learn.MaxRoutes {
			return errLearnLimit
		}
		key := r.Method + " " + r.Path
		if _, dup := fresh.routes[key]; dup {
			continue
		}
		rt := &lroute{method: r.Method, tmpl: r.Path, d: *r.Learned.clone()}
		rt.nodes = 1 + countLearned(&rt.d)
		fresh.routes[key] = rt
		fresh.byTmpl[rt.tmpl] = append(fresh.byTmpl[rt.tmpl], rt)
		fresh.nodes.Add(int64(rt.nodes))
		if fresh.nodes.Load() > int64(cfg.Learn.MaxNodes) {
			return errLearnLimit
		}
	}
	fresh.flush()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.routes, l.byTmpl = fresh.routes, fresh.byTmpl
	l.seed.Store(fresh.seed.Load())
	l.collapsed.Store(fresh.collapsed.Load())
	l.nodes.Store(fresh.nodes.Load())
	l.enforceable.Store(fresh.enforceable.Load())
	for i := range l.pos {
		l.pos[i].mu.Lock()
		l.pos[i].m = map[string]*position{}
		l.pos[i].mu.Unlock()
	}
	l.posCount.Store(0)
	l.ctMu.Lock()
	l.ctypes = fresh.ctypes
	l.ctMu.Unlock()
	return nil
}

func countLearned(d *LearnedRoute) int {
	n := len(d.CTypes) + d.Body.count()
	for _, p := range d.Query {
		n += 1 + len(p.Classes) + len(p.Values)
	}
	return n
}

// snapshot reports how many routes are being learned and how many are enforceable.
func (l *learner) counts() (routes int, enforceable int) {
	l.mu.RLock()
	routes = len(l.routes)
	l.mu.RUnlock()
	return routes, int(l.enforceable.Load())
}
