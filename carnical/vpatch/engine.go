// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"errors"
	"fmt"
	"hash/fnv"
	"hash/maphash"
	"math"
	"math/bits"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// Mode says what the engine does with a match.
type Mode string

const (
	// ModeMonitor records matches and never blocks. It is the default, because a new site starts by watching.
	ModeMonitor Mode = "monitor"
	// ModeBlock refuses a request that matches a signature whose action is block, subject to the tier rules.
	ModeBlock Mode = "block"
)

// Verdict identifiers. A signature's verdict is 5100000 plus a number derived from its ID, in 5101000 to 5199998; the first thousand
// are the engine's own.
const (
	// IDWorkLimit is the verdict for a request that used up its work allowance before every signature was checked.
	IDWorkLimit = 5100001
	// IDMoreMatches is the verdict that says further signatures matched than are listed.
	IDMoreMatches = 5100002

	idBase  = 5100000
	idFirst = idBase + 1000
	idSpan  = 98999
)

// Engine defaults.
const (
	// DefaultMaxWork is the default allowance of regular-expression input per request, in bytes charged by each
	// expression's cost. It is sized so that no request of the equivalence corpus, padded attack variants included, runs
	// out (8 MiB was not quite enough). It bounds what counted repeats can cost; DefaultMaxEvalTime bounds the rest.
	DefaultMaxWork = 12 << 20
	// DefaultMaxEvalTime is the default time one request may spend matching expressions, as the proxy gives each phase of
	// rule evaluation two seconds.
	DefaultMaxEvalTime = 2 * time.Second
	// DefaultMaxVerdicts is the default number of verdicts one request can produce.
	DefaultMaxVerdicts = 16
	// DefaultResultCache is the default size of the result table, in entries (256 KiB).
	DefaultResultCache = 1 << 15
	// MaxResultCache is the maximum size of the result table, in entries (8 MiB).
	MaxResultCache = 1 << 20
)

// Options configure an Engine. The zero value is a valid, cautious engine: verified signatures only, every unscoped signature,
// monitoring only.
type Options struct {
	// Tiers are the tiers that are loaded. Empty means verified only.
	Tiers []string
	// Scope is the software the site has declared ("wordpress", "wordpress:plugin:contact-form-7", "nextjs"). A signature with no
	// scope always applies. One with scope applies if any of its tags equals a site tag or starts with a site tag and a colon, so a
	// site that declares "wordpress" gets "wordpress:plugin:x". Tags compare without regard to case.
	Scope []string
	// Mode is ModeMonitor (the default) or ModeBlock.
	Mode Mode
	// MinSeverity drops signatures below it ("low", "medium", "high", "critical"). Empty keeps all.
	MinSeverity string
	// ExperimentalMayBlock lets an experimental-tier signature block. By default the experimental tier only ever records.
	ExperimentalMayBlock bool
	// MaxWork bounds the regular-expression work one request may cause, in bytes of text given to expressions, each charged
	// by the expression's cost (see repeatThreads). Zero means DefaultMaxWork. When it is used up the remaining signatures
	// are not checked and a verdict says so.
	MaxWork int
	// MaxEvalTime bounds the time one request may spend matching expressions, read from Now before each one runs; zero means
	// DefaultMaxEvalTime and a negative value no limit. MaxWork is the deterministic bound on counted repeats; this one is for
	// what no static count sees, an alternation whose branches a hostile value keeps alive together. When it runs out the
	// remaining signatures are not checked and the work-limit verdict says so.
	MaxEvalTime time.Duration
	// BlockOnWorkLimit makes a request that used up its allowance a blocking verdict (in ModeBlock), instead of a recorded one.
	BlockOnWorkLimit bool
	// MaxVerdicts bounds the verdicts one request produces. Zero means DefaultMaxVerdicts.
	MaxVerdicts int
	// Exclude lists signature ID prefixes that are not loaded. A site that runs the Core Rule Set next to this engine already has
	// what the "CRS-" signatures say, and they are the most expensive ones: Exclude: []string{"CRS-"}.
	Exclude []string
	// ResultCache is the number of entries of the table that remembers, for a regular expression and a value, whether it matched,
	// so that a value that comes again (the same User-Agent, the same page) is not matched again. Zero means DefaultResultCache;
	// negative switches the table off. Positive values are capped at MaxResultCache before rounding up to a power of two,
	// costing eight bytes an entry. Load reports a warning when the requested capacity exceeds the cap.
	ResultCache int
	// Now supplies the date used for Expires. Tests set it; nil means the clock.
	Now func() time.Time

	// mutateAnchors is a hook for the tests that break the index on purpose (the negative controls): it rewrites every condition's
	// required literals as they are indexed.
	mutateAnchors func([]string) []string
}

// Engine runs signatures. It is safe for use by many goroutines at once, including while Load replaces the signatures.
type Engine struct {
	opts  Options
	tiers map[string]bool
	scope []string
	minSv int

	cur    atomic.Pointer[snapshot]
	loadMu sync.Mutex
	// rxCache keeps the compiled expressions of the last Load, so that loading a feed that changed a little compiles only the
	// difference. Guarded by loadMu.
	rxCache map[string]*rxResult

	pool sync.Pool

	// cache is the table of remembered results (see Options.ResultCache): a hash of the expression and the value, with the result
	// in the lowest bit. A slot can be overwritten by another pair at any time, which only costs a repeat of the work; the
	// hash is keyed with a random per-snapshot seed, isolating replacement rules from older snapshots.
	cache     []atomic.Uint64
	cacheMask uint64

	requests, evaluated, hitsN, blocked, limited, truncated atomic.Uint64
}

type rxResult struct {
	prog *rxProg
	err  error
}

// New returns an Engine with no signatures; call Load.
func New(opts Options) *Engine {
	e := &Engine{opts: opts, tiers: map[string]bool{}, rxCache: map[string]*rxResult{}}
	if len(opts.Tiers) == 0 {
		e.tiers[TierVerified] = true
	}
	for _, t := range opts.Tiers {
		e.tiers[strings.ToLower(strings.TrimSpace(t))] = true
	}
	for _, s := range opts.Scope {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			e.scope = append(e.scope, s)
		}
	}
	e.minSv = severityRank[strings.ToLower(opts.MinSeverity)]
	if e.opts.Mode != ModeBlock {
		e.opts.Mode = ModeMonitor
	}
	if e.opts.MaxWork <= 0 {
		e.opts.MaxWork = DefaultMaxWork
	}
	if e.opts.MaxEvalTime == 0 {
		e.opts.MaxEvalTime = DefaultMaxEvalTime
	}
	if e.opts.MaxVerdicts <= 0 {
		e.opts.MaxVerdicts = DefaultMaxVerdicts
	}
	if e.opts.Now == nil {
		e.opts.Now = time.Now
	}
	if n := e.opts.ResultCache; n >= 0 {
		if n == 0 {
			n = DefaultResultCache
		}
		n = min(n, MaxResultCache)
		size := 1
		var mask uint64
		for size < n {
			size <<= 1
			mask = mask<<1 | 1
		}
		e.cache = make([]atomic.Uint64, size)
		e.cacheMask = mask
	}
	e.cur.Store(&snapshot{})
	return e
}

// Name implements inspect.Inspector.
func (e *Engine) Name() string { return "vpatch" }

// A Rejection is a signature that was not loaded because it is not valid, with the reason in plain words.
// An empty ID denotes a whole-batch indexing failure; the previous snapshot remains active.
type Rejection struct {
	ID     string
	Reason string
}

// LoadReport says what Load did.
type LoadReport struct {
	// Offered is the number of signatures given to Load.
	Offered int
	// Loaded counts the signatures now running, by tier; LoadedTotal is their sum.
	Loaded      map[string]int
	LoadedTotal int
	// Skipped counts signatures that were valid enough to read but not wanted, by reason: "tier not enabled", "scope", "expired",
	// "below the minimum severity".
	Skipped map[string]int
	// Rejected lists the signatures that are invalid or cannot be compiled, with the reason, in the order they were given.
	Rejected []Rejection
	// Indexed is the number of loaded signatures that are found through the literal index; Unindexed the number that are checked on
	// every request. Literals is the number of distinct strings in the index.
	Indexed, Unindexed, Literals int
	// Translated counts the regular expressions that had to be rewritten from PCRE, by construct.
	Translated map[string]int
	// Warnings are problems with the options rather than with a signature.
	Warnings []string
	// Elapsed is how long Load took.
	Elapsed time.Duration
}

// Stats are the engine's counters and the size of what is loaded.
type Stats struct {
	Signatures int
	ByTier     map[string]int
	Indexed    int
	Unindexed  int
	Literals   int
	// Requests is how many requests were matched, SignaturesEvaluated how many signatures were fully evaluated (the candidates
	// the index nominated plus the unindexed ones), Matches how many signature matches there were, Blocked how many requests
	// Inspect told the proxy to refuse, WorkLimited how many ran out of work allowance and Truncated how many had a value or
	// a count cut to the engine's bounds.
	Requests            uint64
	SignaturesEvaluated uint64
	Matches             uint64
	Blocked             uint64
	WorkLimited         uint64
	Truncated           uint64
	LoadedAt            time.Time
}

// snapshot is the compiled signature set a request is matched against. It is never modified after it is published.
type snapshot struct {
	// cacheSeed isolates regex results from older snapshots, including late in-flight writes.
	cacheSeed  maphash.Seed
	sigs       []sigC
	conds      []condC
	condDriver []int32 // per condition: the signature it nominates as a candidate, or -1
	chains     []chainC
	kinds      [numKinds]kindIndex
	unindexed  []int32

	needUploads bool
	byID        map[string]int32
	byTier      map[string]int
	literals    int
	loadedAt    time.Time
}

// chainC is one step of a transform chain: chain c is the chain parent followed by fn. Chain 0 is the empty chain.
type chainC struct {
	parent int32
	fn     transformFn
}

// kindIndex is the literal index for one kind of value: one automaton over every literal that some condition requires of values
// of this kind, and for each literal the conditions (and the transform chain they read the value through) that require it.
type kindIndex struct {
	auto *automaton
	// classes are the transform chains in use for this kind, one bit each in a text's mask.
	classes  []int32
	words    int
	patStart []int32
	pats     []entry
	nPat     int
}

type entry struct {
	class int32
	cond  int32
}

// scopeApplies reports whether a signature with these scope tags applies to a site with the engine's tags.
func (e *Engine) scopeApplies(tags []string) bool {
	if len(tags) == 0 {
		return true
	}
	for _, t := range tags {
		t = strings.ToLower(t)
		for _, s := range e.scope {
			if t == s || strings.HasPrefix(t, s+":") {
				return true
			}
		}
	}
	return false
}

func (e *Engine) excluded(id string) bool {
	for _, p := range e.opts.Exclude {
		if p != "" && strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

func verdictNumber(id string) int {
	h := fnv.New32a()
	h.Write([]byte(id)) // #nosec G104 -- hash.Hash.Write always consumes its input and never returns an error.
	return idFirst + int(h.Sum32()%idSpan)
}

// Load compiles the signatures and replaces what the engine runs with them, atomically: a request that is being matched finishes
// against the set it started with. A signature that is not valid is left out and listed in the report; the rest load.
// If the whole index cannot fit its representation, the previous snapshot is retained and the report includes a rejection with no ID.
func (e *Engine) Load(sigs []Signature) LoadReport {
	start := time.Now()
	e.loadMu.Lock()
	defer e.loadMu.Unlock()

	rep := LoadReport{
		Offered:    len(sigs),
		Loaded:     map[string]int{},
		Skipped:    map[string]int{},
		Translated: map[string]int{},
	}
	if e.opts.ResultCache > MaxResultCache {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("ResultCache exceeds the maximum; capped at %d entries", MaxResultCache))
	}
	for t := range e.tiers {
		switch t {
		case TierVerified, TierCommunity, TierExperimental:
		default:
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("the option Tiers names %q, which is not a tier", clip(t, 32)))
		}
	}
	today := e.opts.Now().UTC().Format("2006-01-02")

	type rej struct {
		idx    int
		id     string
		reason string
	}
	var rejects []rej
	var preps []*prepared
	var prepIdx []int
	seenID := make(map[string]struct{}, len(sigs))
	for i := range sigs {
		sig := &sigs[i]
		tier := sig.Tier
		if tier == "" {
			tier = TierVerified
		}
		switch {
		case e.excluded(sig.ID):
			rep.Skipped["excluded by option"]++
			continue
		case !e.tiers[tier]:
			switch tier {
			case TierVerified, TierCommunity, TierExperimental:
				rep.Skipped["tier not enabled"]++
			default:
				rejects = append(rejects, rej{i, sig.ID, fmt.Sprintf("unknown tier %q", clip(tier, 32))})
			}
			continue
		case sig.Expires != "" && sig.Expires < today && len(sig.Expires) == 10:
			rep.Skipped["expired"]++
			continue
		case !e.scopeApplies(sig.Scope):
			rep.Skipped["scope"]++
			continue
		case e.minSv > 0 && severityRank[sig.Severity] > 0 && severityRank[sig.Severity] < e.minSv:
			rep.Skipped["below the minimum severity"]++
			continue
		}
		p, err := validateSignature(sig)
		if err != nil {
			rejects = append(rejects, rej{i, sig.ID, err.Error()})
			continue
		}
		if _, dup := seenID[sig.ID]; dup {
			rejects = append(rejects, rej{i, sig.ID, "the ID is used by an earlier signature"})
			continue
		}
		seenID[sig.ID] = struct{}{}
		preps = append(preps, p)
		prepIdx = append(prepIdx, i)
	}

	// Compile every distinct regular expression once, in parallel, reusing the last load's where the pattern is unchanged.
	type rxKey struct{ pattern, flags string }
	keys := map[rxKey]int{}
	var order []rxKey
	for _, p := range preps {
		for ci := range p.conds {
			if c := &p.conds[ci]; c.op == opRx {
				k := rxKey{c.rxPattern, c.rxFlags}
				if _, ok := keys[k]; !ok {
					keys[k] = len(order)
					order = append(order, k)
				}
			}
		}
	}
	results := make([]*rxResult, len(order))
	var todo []int
	for i, k := range order {
		if r, ok := e.rxCache[k.flags+"\x00"+k.pattern]; ok {
			results[i] = r
		} else {
			todo = append(todo, i)
		}
	}
	workers := runtime.GOMAXPROCS(0)
	if workers > len(todo) {
		workers = len(todo)
	}
	var wg sync.WaitGroup
	var next atomic.Int64
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				j := int(next.Add(1)) - 1
				if j >= len(todo) {
					return
				}
				k := order[todo[j]]
				results[todo[j]] = safeCompileRx(k.pattern, k.flags)
			}
		}()
	}
	wg.Wait()
	newCache := make(map[string]*rxResult, len(order))
	noted := map[string]struct{}{}
	for i, k := range order {
		newCache[k.flags+"\x00"+k.pattern] = results[i]
		if results[i].err == nil {
			for _, n := range results[i].prog.notes {
				if _, ok := noted[k.flags+"\x00"+k.pattern+n]; !ok {
					noted[k.flags+"\x00"+k.pattern+n] = struct{}{}
					rep.Translated[n]++
				}
			}
		}
	}
	e.rxCache = newCache

	var good []*prepared
	for pi, p := range preps {
		ok := true
		for ci := range p.conds {
			c := &p.conds[ci]
			if c.op != opRx {
				continue
			}
			r := results[keys[rxKey{c.rxPattern, c.rxFlags}]]
			if r.err != nil {
				where := "the main condition"
				if ci > 0 {
					where = fmt.Sprintf("condition %d of Also", ci)
				}
				rejects = append(rejects, rej{prepIdx[pi], p.sig.ID, fmt.Sprintf("%s: %s", where, r.err.Error())})
				ok = false
				break
			}
			c.prog = r.prog
		}
		if ok {
			good = append(good, p)
		}
	}
	sort.SliceStable(rejects, func(a, b int) bool { return rejects[a].idx < rejects[b].idx })
	for _, r := range rejects {
		rep.Rejected = append(rep.Rejected, Rejection{ID: r.id, Reason: r.reason})
	}

	snap, err := buildSnapshot(good, e.opts.mutateAnchors)
	if err != nil {
		rep.Rejected = append(rep.Rejected, Rejection{Reason: err.Error()})
		snap = e.cur.Load()
	} else {
		snap.loadedAt = time.Now()
		e.cur.Store(snap)
	}
	for t, n := range snap.byTier {
		rep.Loaded[t] = n
		rep.LoadedTotal += n
	}
	rep.Unindexed = len(snap.unindexed)
	rep.Indexed = len(snap.sigs) - rep.Unindexed
	rep.Literals = snap.literals
	rep.Elapsed = time.Since(start)
	return rep
}

func safeCompileRx(pattern, flags string) (res *rxResult) {
	defer func() {
		if p := recover(); p != nil {
			res = &rxResult{err: fmt.Errorf("internal error compiling the expression")}
		}
	}()
	prog, err := compileRx(pattern, flags)
	return &rxResult{prog: prog, err: err}
}

var errIndexCapacity = errors.New("compiled signature index exceeds its representable capacity")

// index32 checks a nonnegative index or cumulative offset before narrowing it.
func index32(n int) (int32, error) {
	if n < 0 || n > math.MaxInt32 {
		return 0, errIndexCapacity
	}
	return int32(n), nil
}

// addIndex32 checks before addition too, so the arithmetic is safe on 32-bit hosts.
func addIndex32(total, count int) (int32, error) {
	if total < 0 || count < 0 || total > math.MaxInt32 || count > math.MaxInt32-total {
		return 0, errIndexCapacity
	}
	return index32(total + count)
}

// classMaskWords bounds the rectangular per-request mask, including its uint64 backing bytes, before publication.
func classMaskWords(classes int) (int, error) {
	if classes < 0 {
		return 0, errIndexCapacity
	}
	words := classes / 64
	if classes%64 != 0 {
		words++
	}
	// Divide before multiplying so neither classes*words nor its eight-byte elements can overflow native int.
	if words != 0 && classes > math.MaxInt/8/words {
		return 0, errIndexCapacity
	}
	return words, nil
}

// buildSnapshot indexes the compiled signatures without publishing a partially built index.
func buildSnapshot(preps []*prepared, mutate func([]string) []string) (*snapshot, error) {
	if _, err := index32(len(preps)); err != nil {
		return nil, err
	}
	s := &snapshot{cacheSeed: maphash.MakeSeed(), byTier: map[string]int{}, byID: make(map[string]int32, len(preps))}
	s.chains = []chainC{{parent: -1}}
	chainIDs := map[string]int32{"": 0}
	var intern func(names []string, fns []transformFn) (int32, error)
	intern = func(names []string, fns []transformFn) (int32, error) {
		if len(names) == 0 {
			return 0, nil
		}
		key := strings.Join(names, ",")
		if id, ok := chainIDs[key]; ok {
			return id, nil
		}
		parent, err := intern(names[:len(names)-1], fns[:len(fns)-1])
		if err != nil {
			return 0, err
		}
		// Request-local transformed values use a flattened kind*chain index stored in int32.
		if len(s.chains) >= math.MaxInt32/numKinds {
			return 0, errIndexCapacity
		}
		id, err := index32(len(s.chains))
		if err != nil {
			return 0, err
		}
		s.chains = append(s.chains, chainC{parent: parent, fn: fns[len(fns)-1]})
		chainIDs[key] = id
		return id, nil
	}

	// Flatten the conditions and compute each one's anchors.
	s.sigs = make([]sigC, 0, len(preps))
	for _, p := range preps {
		si, err := index32(len(s.sigs))
		if err != nil {
			return nil, err
		}
		sc := sigC{
			id: p.sig.ID, category: p.sig.Category, severity: p.sig.Severity, tier: p.tier,
			action: p.sig.Action, cves: p.sig.CVEs, idNum: verdictNumber(p.sig.ID), driver: -1,
			desc: sanitize(p.sig.Description, maxVerdictDesc),
		}
		if sc.action == "" {
			sc.action = "block"
		}
		for ci := range p.conds {
			c := p.conds[ci]
			c.sig = si
			c.chain, err = intern(c.tnames, c.fns)
			if err != nil {
				return nil, err
			}
			switch c.op {
			case opRx:
				if !c.neg && c.prog != nil {
					c.anchors = c.prog.anchors
				}
			default:
				c.anchors = stringAnchors(&c)
			}
			if mutate != nil && c.anchors != nil {
				c.anchors = mutate(c.anchors)
			}
			for _, tg := range c.targets {
				if tg.kind == kUploads {
					s.needUploads = true
				}
			}
			end, err := addIndex32(len(s.conds), 1)
			if err != nil {
				return nil, err
			}
			sc.conds = append(sc.conds, end-1)
			s.conds = append(s.conds, c)
		}
		sort.SliceStable(sc.conds, func(a, b int) bool { return s.conds[sc.conds[a]].cost < s.conds[sc.conds[b]].cost })
		s.sigs = append(s.sigs, sc)
		s.byID[sc.id] = si
		s.byTier[p.tier]++
	}
	s.condDriver = make([]int32, len(s.conds))
	for i := range s.condDriver {
		s.condDriver[i] = -1
	}

	// How many conditions offer each literal: a literal many signatures share is a poor way to pick one of them out.
	freq := map[string]int{}
	for i := range s.conds {
		for _, l := range s.conds[i].anchors {
			freq[l]++
		}
	}
	score := func(c *condC) int {
		q := clauseQuality(c.anchors)
		if q > 12 {
			q = 12
		}
		f := 0
		for _, l := range c.anchors {
			if freq[l] > f {
				f = freq[l]
			}
		}
		return q*8 - 5*bits.Len(uint(f))
	}
	for si := range s.sigs {
		best, bestScore := int32(-1), 0
		for _, ci := range s.sigs[si].conds {
			c := &s.conds[ci]
			if c.anchors == nil {
				continue
			}
			c.anchored = true
			s.sigs[si].gates = append(s.sigs[si].gates, ci)
			if sc := score(c); best < 0 || sc > bestScore {
				best, bestScore = ci, sc
			}
		}
		if best < 0 {
			s.unindexed = append(s.unindexed, int32(si))
			continue
		}
		s.sigs[si].driver = best
		s.condDriver[best] = int32(si)
	}

	// The per-kind literal tables.
	type regKey struct {
		kind  uint8
		class int32
		cond  int32
	}
	type litTable struct {
		ids     map[string]int32
		lits    []string
		entries [][]entry
		classes map[int32]int32
	}
	var tables [numKinds]*litTable
	registered := map[regKey]struct{}{}
	for ci := range s.conds {
		c := &s.conds[ci]
		if !c.anchored {
			continue
		}
		for _, tg := range c.targets {
			t := tables[tg.kind]
			if t == nil {
				t = &litTable{ids: map[string]int32{}, classes: map[int32]int32{}}
				tables[tg.kind] = t
			}
			cls, ok := t.classes[c.chain]
			if !ok {
				var err error
				cls, err = index32(len(t.classes))
				if err != nil {
					return nil, err
				}
				t.classes[c.chain] = cls
				s.kinds[tg.kind].classes = append(s.kinds[tg.kind].classes, c.chain)
			}
			rk := regKey{tg.kind, cls, int32(ci)}
			if _, dup := registered[rk]; dup {
				continue
			}
			registered[rk] = struct{}{}
			for _, l := range c.anchors {
				id, ok := t.ids[l]
				if !ok {
					var err error
					id, err = index32(len(t.lits))
					if err != nil {
						return nil, err
					}
					t.ids[l] = id
					t.lits = append(t.lits, l)
					t.entries = append(t.entries, nil)
				}
				t.entries[id] = append(t.entries[id], entry{class: cls, cond: int32(ci)})
			}
		}
	}
	for k, t := range tables {
		if t == nil {
			continue
		}
		ki := &s.kinds[k]
		words, err := classMaskWords(len(ki.classes))
		if err != nil {
			return nil, err
		}
		auto, err := newAutomaton(t.lits)
		if err != nil {
			return nil, err
		}
		ki.auto = auto
		ki.nPat = len(t.lits)
		ki.words = words
		ki.patStart = make([]int32, len(t.lits)+1)
		for i, es := range t.entries {
			end, err := addIndex32(int(ki.patStart[i]), len(es))
			if err != nil {
				return nil, err
			}
			ki.patStart[i+1] = end
			ki.pats = append(ki.pats, es...)
		}
		s.literals += len(t.lits)
	}
	return s, nil
}

// sanitize makes text safe to put in a log line: control characters become spaces and it is cut to n bytes.
func sanitize(s string, n int) string {
	if len(s) > n {
		s = s[:n]
		for len(s) > 0 {
			if r, size := utf8.DecodeLastRuneInString(s); r == utf8.RuneError && size <= 1 {
				s = s[:len(s)-1]
				continue
			}
			break
		}
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// Stats returns the engine's counters.
func (e *Engine) Stats() Stats {
	s := e.cur.Load()
	st := Stats{
		Signatures: len(s.sigs), ByTier: map[string]int{}, Unindexed: len(s.unindexed), Literals: s.literals, LoadedAt: s.loadedAt,
		Requests: e.requests.Load(), SignaturesEvaluated: e.evaluated.Load(), Matches: e.hitsN.Load(), Blocked: e.blocked.Load(),
		WorkLimited: e.limited.Load(), Truncated: e.truncated.Load(),
	}
	for t, n := range s.byTier {
		st.ByTier[t] = n
	}
	st.Indexed = st.Signatures - st.Unindexed
	return st
}

// Inspect implements inspect.Inspector: it matches the request and turns each match into a verdict. Whether a verdict blocks
// follows the signature's action, its tier and the engine's mode; the message names the signature, its CVEs and what it
// recognises, and never anything from the request.
func (e *Engine) Inspect(r *inspect.Request) inspect.Result {
	m := e.run(r, false)
	var res inspect.Result
	if len(m.hits) == 0 && !m.limited {
		return res
	}
	type vd struct {
		v   inspect.Verdict
		sev int
	}
	var vds []vd
	for _, hi := range m.hits {
		sg := &m.snap.sigs[hi]
		block := e.opts.Mode == ModeBlock && sg.action != "log" && (sg.tier != TierExperimental || e.opts.ExperimentalMayBlock)
		v := inspect.Verdict{ID: sg.idNum, Message: verdictMessage(sg), Block: block, Severity: sg.severity}
		if block {
			v.Status = 403
		}
		vds = append(vds, vd{v, severityRank[sg.severity]})
	}
	sort.SliceStable(vds, func(a, b int) bool {
		if vds[a].v.Block != vds[b].v.Block {
			return vds[a].v.Block
		}
		return vds[a].sev > vds[b].sev
	})
	extra := 0
	if len(vds) > e.opts.MaxVerdicts {
		extra = len(vds) - e.opts.MaxVerdicts
		vds = vds[:e.opts.MaxVerdicts]
	}
	blocked := false
	for _, x := range vds {
		res.Verdicts = append(res.Verdicts, x.v)
		blocked = blocked || x.v.Block
	}
	if extra > 0 {
		res.Verdicts = append(res.Verdicts, inspect.Verdict{
			ID: IDMoreMatches, Severity: "low", Message: fmt.Sprintf("virtual patch: %d more signatures matched than are listed", extra),
		})
	}
	if m.limited {
		block := e.opts.Mode == ModeBlock && e.opts.BlockOnWorkLimit
		res.Verdicts = append(res.Verdicts, inspect.Verdict{
			ID: IDWorkLimit, Severity: "medium", Block: block, Status: 403,
			Message: "virtual patch: the request used up its work allowance, so not every signature was checked",
		})
		blocked = blocked || block
	}
	if blocked {
		e.blocked.Add(1)
	}
	return res
}

func verdictMessage(sg *sigC) string {
	var b strings.Builder
	b.WriteString("virtual patch ")
	b.WriteString(sg.id)
	if len(sg.cves) > 0 {
		b.WriteString(" (")
		for i, c := range sg.cves {
			if i == 3 {
				b.WriteString(", ...")
				break
			}
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(sanitize(c, 40))
		}
		b.WriteString(")")
	}
	if sg.desc != "" {
		b.WriteString(": ")
		b.WriteString(sg.desc)
	}
	return b.String()
}

// Loaded reports whether a signature with this ID is part of what the engine runs.
func (e *Engine) Loaded(id string) bool {
	_, ok := e.cur.Load().byID[id]
	return ok
}

// Match returns the signatures that match the request, in the order they were loaded. It does not look at the engine's mode.
func (e *Engine) Match(r *inspect.Request) []Hit {
	m := e.run(r, false)
	return m.snap.hitsOf(m.hits)
}

// MatchBruteForce evaluates every loaded signature's conditions directly, with no index and no work limit. It is slow and exists so
// that the index can be checked against it, in tests and on a site's own traffic.
func (e *Engine) MatchBruteForce(r *inspect.Request) []Hit {
	m := e.run(r, true)
	return m.snap.hitsOf(m.hits)
}

func (s *snapshot) hitsOf(idx []int32) []Hit {
	if len(idx) == 0 {
		return nil
	}
	out := make([]Hit, len(idx))
	for i, hi := range idx {
		sg := &s.sigs[hi]
		out[i] = Hit{ID: sg.id, Category: sg.category, Severity: sg.severity, CVEs: sg.cves, Action: sg.action, Tier: sg.tier}
	}
	return out
}
