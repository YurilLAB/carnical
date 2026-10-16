// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"cmp"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A simulation of a small business site under distributed attacks, on a simulated clock, through the real Shield: every
// request is a real *http.Request through Admit, Write's decisions and Done. The site's application can serve
// originCapacity requests a second; beyond that, requests fail (503 from the origin), which is what a flood does to an
// unprotected site. Ordinary traffic is people: returning visitors (who become known before the attack) and new visitors,
// each visit a page and three assets, from a mix of browsers. Attacks come from tens of thousands of addresses spread
// over hundreds of networks and dozens of countries.

const defaultCapacity = 200

var browsers = [][]string{
	{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36", "Accept-Language", "en-AU,en;q=0.9", "Accept-Encoding", "gzip, deflate, br, zstd", "Sec-Ch-Ua", `"Chromium";v="141"`},
	{"User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1", "Accept-Language", "en-AU", "Accept-Encoding", "gzip, deflate, br"},
	{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0", "Accept-Language", "en-GB,en;q=0.5", "Accept-Encoding", "gzip, deflate, br, zstd"},
	{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15", "Accept-Language", "en-US", "Accept-Encoding", "gzip, deflate, br"},
	{"User-Agent", "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36", "Accept-Language", "en-AU,en;q=0.9", "Accept-Encoding", "gzip, deflate, br, zstd", "Sec-Ch-Ua", `"Chromium";v="141"`},
	{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36 Edg/141.0", "Accept-Language", "en-AU,en;q=0.9", "Accept-Encoding", "gzip, deflate, br, zstd", "Sec-Ch-Ua", `"Microsoft Edge";v="141"`},
}

var countries = strings.Fields("BR US ID VN IN CN RU TR MX AR CO PH TH EG ZA NG PK BD UA PL DE FR IT ES GB KR JP TW MY IR")

// fakeLabeler gives each /8 a country, the way a real table would give each allocation one.
type fakeLabeler struct{}

func (fakeLabeler) Label(a netip.Addr) string {
	b := a.As4()
	return countries[int(b[0])%len(countries)] + " AS" + strconv.Itoa(64500+int(b[0]))
}

type simVisitor struct {
	addr    netip.Addr
	browser int
	cookie  *http.Cookie
}

type sim struct {
	t        *testing.T
	s        *Shield
	clock    time.Time
	r        *rand.Rand
	served   int // requests the origin served this second
	known    []*simVisitor
	stats    map[string]*tally
	nextIP   uint32
	capacity int           // requests a second the application can serve
	kv, nv   int           // visits a second by returning and by new visitors
	shared   []netip.Addr  // addresses with many visitors behind them (a company, a mobile carrier)
	app      []string      // when set, every visit is the mobile app calling one API endpoint
	ua       [][]string    // when set, the browsers visitors use in place of browsers, index for index
	natShare float64       // the share of returning visits that come through them
	lat      time.Duration // how long the application takes to answer a visit
	queue    time.Duration // when set, the application queues what it cannot serve, and the clients hang up after this long
}

type tally struct{ sent, ok int }

func (t *tally) rate() float64 {
	if t.sent == 0 {
		return 1
	}
	return float64(t.ok) / float64(t.sent)
}

func newSim(t *testing.T, mod func(*Config)) *sim {
	m := &sim{t: t, clock: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), r: rand.New(rand.NewPCG(7, 11)), stats: map[string]*tally{}, nextIP: 1, capacity: defaultCapacity, kv: 4, nv: 4}
	cfg := Config{Now: func() time.Time { return m.clock }, ChallengeBits: 8, Labeler: fakeLabeler{}}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	m.s = s
	for i := 0; i < 400; i++ {
		m.known = append(m.known, &simVisitor{addr: m.legitAddr(), browser: i % len(browsers)})
	}
	return m
}

// underRace says whether the test binary was built with the race detector. The simulations run several times slower
// under it and on one goroutine, so what they find is in their values, not in how requests run concurrently: under it
// only some run, so that `go test -race ./shield` stays well within go test's ten minutes. The tests without -race run
// them all.
func underRace() bool {
	bi, ok := debug.ReadBuildInfo()
	return ok && slices.Contains(bi.Settings, debug.BuildSetting{Key: "-race", Value: "true"})
}

// strengths is names, the -ddos strengths a simulation runs under, but only normal under the race detector.
func strengths(names ...string) []string {
	if underRace() {
		return []string{"normal"}
	}
	return names
}

// notUnderRace skips a simulation under the race detector (see underRace).
func notUnderRace(t *testing.T) {
	if underRace() {
		t.Skip("a simulation on one goroutine; run without -race")
	}
}

// strength makes newSim start from the -ddos strength named (see Preset).
func strength(t *testing.T, name string) func(*Config) {
	return func(c *Config) {
		p, err := Preset(name)
		if err != nil {
			t.Fatal(err)
		}
		p.Now, p.ChallengeBits, p.Labeler = c.Now, c.ChallengeBits, c.Labeler
		*c = p
	}
}

// legitAddr is a fresh address for a person: the site's audience is mostly in a few countries' networks.
func (m *sim) legitAddr() netip.Addr {
	m.nextIP++
	n := m.nextIP
	return netip.AddrFrom4([4]byte{byte(100 + n%20), byte(n >> 16), byte(n >> 8), byte(n)})
}

func (m *sim) tally(name string) *tally {
	if m.stats[name] == nil {
		m.stats[name] = &tally{}
	}
	return m.stats[name]
}

// do sends one request and reports whether the visitor got what they asked for (from the origin, within its capacity).
// A browser that is shown the challenge answers it, as a real one does, and then asks again.
func (m *sim) do(class string, v *simVisitor, path string, nav bool, headers []string) bool {
	tl := m.tally(class)
	tl.sent++
	for attempt := 0; attempt < 2; attempt++ {
		r := simRequest(path)
		for i := 0; i+1 < len(headers); i += 2 {
			r.Header.Set(headers[i], headers[i+1])
		}
		if nav {
			r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
		} else if strings.HasPrefix(class, "legit") {
			r.Header.Set("Accept", "*/*")
			r.Header.Set("Sec-Fetch-Mode", "no-cors")
		}
		if v.cookie != nil {
			r.AddCookie(v.cookie)
		}
		d := m.s.Admit(r, v.addr)
		switch d.Action {
		case Allow:
			ok := m.served < m.capacity
			if ok {
				m.served++
				m.clock = m.clock.Add(m.lat)
				m.s.Done(d, 200, true)
				m.clock = m.clock.Add(-m.lat)
				tl.ok++
			} else if m.queue > 0 {
				d.start -= int64(m.queue)
				m.s.Done(d, StatusClientClosed, true)
			} else {
				m.s.Done(d, 503, true)
			}
			return ok
		case Challenge:
			if !strings.HasPrefix(class, "legit") || attempt > 0 {
				return false // bots do not run the page; a person who failed twice gives up
			}
			tok := m.s.token(SourceKey(v.addr), m.clock)
			vr := httptest.NewRequest(http.MethodGet, VerifyPath+"?t="+tok+"&n="+solve(tok, 8)+"&to=/", nil)
			vr.Header.Set("User-Agent", r.Header.Get("User-Agent"))
			vd := m.s.Admit(vr, v.addr)
			if vd.Action != Respond || vd.resp.cookie == nil {
				return false
			}
			v.cookie = vd.resp.cookie
			m.tally(class+" challenged").sent++
		default:
			return false
		}
	}
	return false
}

// simRequest is the request httptest.NewRequest makes for a GET of target, without parsing it from text through a new
// buffered reader each time, which was the largest part of what a simulation cost; the shield reads its method,
// protocol, target, headers and cookies.
func simRequest(target string) *http.Request {
	u, err := url.ParseRequestURI(target)
	if err != nil {
		panic(err)
	}
	return &http.Request{Method: http.MethodGet, URL: u, RequestURI: target, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{}, Body: http.NoBody, Host: "example.com", RemoteAddr: "192.0.2.1:1234"}
}

// visit is a person loading a page and its assets.
func (m *sim) visit(class string, v *simVisitor) {
	if m.app != nil {
		for i := 0; i < 4; i++ {
			m.do(class, v, "/api/v2/feed?cursor="+strconv.Itoa(m.r.IntN(1e6)), false, m.app)
		}
		return
	}
	h := browsers[v.browser]
	if m.ua != nil {
		h = m.ua[v.browser]
	}
	m.do(class, v, "/blog/post-"+strconv.Itoa(m.r.IntN(40)), true, h)
	for _, a := range []string{"/static/site.css", "/static/site.js", "/img/" + strconv.Itoa(m.r.IntN(60)) + ".jpg"} {
		m.do(class, v, a, false, h)
	}
}

// second runs one simulated second: visits from known and new people, and n attack requests from attack().
func (m *sim) second(visitsKnown, visitsNew, attackN int, attack func(i int)) {
	m.served = 0
	start := m.clock
	total := visitsKnown + visitsNew + attackN
	step := time.Second / time.Duration(max(total, 1)+1)
	order := m.r.Perm(total)
	for _, k := range order {
		m.clock = m.clock.Add(step)
		switch {
		case k < visitsKnown:
			v := m.known[m.r.IntN(len(m.known))]
			if len(m.shared) > 0 && m.r.Float64() < m.natShare {
				v = &simVisitor{addr: m.shared[m.r.IntN(len(m.shared))], browser: v.browser}
			}
			m.visit("legit known", v)
		case k < visitsKnown+visitsNew:
			m.visit("legit new", &simVisitor{addr: m.legitAddr(), browser: m.r.IntN(len(browsers))})
		default:
			attack(k - visitsKnown - visitsNew)
		}
	}
	m.clock = start.Add(time.Second)
	m.s.Tick()
}

// warm runs ordinary traffic long enough for the baseline to settle and the returning visitors to become known.
func (m *sim) warm(minutes int) {
	for i := 0; i < minutes*60; i++ {
		m.second(m.kv, m.nv, 0, nil)
	}
	if st := m.s.State(); st != Normal {
		m.t.Fatalf("after warm-up the state is %v", st)
	}
	m.stats = map[string]*tally{}
}

// botnet is n addresses spread over many /8s (countries) and /16s.
func botnet(n int, r *rand.Rand) []*simVisitor {
	out := make([]*simVisitor, n)
	for i := range out {
		out[i] = &simVisitor{addr: netip.AddrFrom4([4]byte{byte(1 + r.IntN(90)), byte(r.IntN(256)), byte(r.IntN(256)), byte(1 + r.IntN(254))})}
	}
	return out
}

// randomWord is a path segment of letters only, which a target's template keeps as it is.
func randomWord(r *rand.Rand) string {
	var b [8]byte
	for i := range b {
		b[i] = byte('a' + r.IntN(26))
	}
	return string(b[:])
}

type result struct {
	detectedAfter  int // seconds; -1 if never
	attackAdmitted float64
	known, new     float64
	inc            *Incident
	maxState       State
}

func (r result) String() string {
	return fmt.Sprintf("detected after %ds, attack admitted %.2f%%, returning visitors served %.1f%%, new visitors served %.1f%%",
		r.detectedAfter, 100*r.attackAdmitted, 100*r.known, 100*r.new)
}

// run sends ordinary traffic plus an attack of perSecond requests a second for seconds seconds.
func (m *sim) run(seconds, perSecond int, attack func(i int)) result {
	res := result{detectedAfter: -1}
	var admittedAfter, sentAfter int
	var knownAt, newAt tally // the visitors' tallies when the attack was detected
	for sec := 0; sec < seconds; sec++ {
		before := *m.tally("attack")
		m.second(m.kv, m.nv, perSecond, attack)
		st := m.s.State()
		if st > res.maxState {
			res.maxState = st
		}
		if st == Attack && res.detectedAfter < 0 {
			res.detectedAfter = sec + 1
			knownAt, newAt = *m.tally("legit known"), *m.tally("legit new")
		}
		if res.detectedAfter >= 0 && sec >= res.detectedAfter {
			after := m.tally("attack")
			admittedAfter += after.ok - before.ok
			sentAfter += after.sent - before.sent
		}
	}
	if sentAfter > 0 {
		res.attackAdmitted = float64(admittedAfter) / float64(sentAfter)
	}
	// Visitors are counted from the moment of detection: before it, the flood has the origin to itself, which is the
	// price of not acting on traffic until it is known to be an attack.
	k, n := m.tally("legit known"), m.tally("legit new")
	if res.detectedAfter < 0 {
		knownAt, newAt = tally{}, tally{}
	}
	res.known = (&tally{sent: k.sent - knownAt.sent, ok: k.ok - knownAt.ok}).rate()
	res.new = (&tally{sent: n.sent - newAt.sent, ok: n.ok - newAt.ok}).rate()
	if snap := m.s.Snapshot(); snap.Current != nil {
		res.inc = snap.Current
	}
	return res
}

func TestSimulatedAttacks(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	python := []string{"User-Agent", "python-requests/2.32.3", "Accept", "*/*", "Accept-Encoding", "gzip, deflate", "Connection", "keep-alive"}

	// Each strength of -ddos, from the most lenient, must hold off the botnets below.
	all := strengths("relaxed", "normal", "strict")

	t.Run("a botnet of 20,000 addresses in 30 countries, 5,000 requests a second, cache-busting the home page", func(t *testing.T) {
		for _, name := range all {
			t.Run(name, func(t *testing.T) {
				m := newSim(t, strength(t, name))
				m.warm(10)
				bots := botnet(20_000, m.r)
				res := m.run(90, 5000, func(i int) {
					m.do("attack", bots[m.r.IntN(len(bots))], "/?r="+strconv.Itoa(m.r.IntN(1e9)), false, python)
				})
				t.Log(res)
				t.Logf("incident: %d addresses, %d networks, %d countries/networks labelled; refused %d, banned %d; reasons: %q",
					res.inc.Sources, res.inc.Networks, res.inc.DistinctLabels, res.inc.Refused, res.inc.Banned, res.inc.Reasons)
				if res.detectedAfter < 0 || res.detectedAfter > 10 || res.attackAdmitted > 0.02 || res.known < 0.98 || res.new < 0.9 {
					t.Fatal("protection below the bar")
				}
				if res.inc.Sources < 17_000 || res.inc.Sources > 23_000 || res.inc.DistinctLabels < 25 {
					t.Fatalf("the record misjudges the attack's spread: %+v", res.inc)
				}
			})
		}
	})

	t.Run("the same botnet with the shield in monitor mode (control: the mitigation is what protects)", func(t *testing.T) {
		m := newSim(t, func(c *Config) { c.MonitorOnly = true })
		m.warm(10)
		bots := botnet(20_000, m.r)
		res := m.run(60, 5000, func(i int) {
			m.do("attack", bots[m.r.IntN(len(bots))], "/?r="+strconv.Itoa(m.r.IntN(1e9)), false, python)
		})
		t.Log(res)
		if res.detectedAfter < 0 || res.known > 0.2 {
			t.Fatal("monitor mode either missed the attack or the simulated origin is not overwhelmed (the test proves nothing)")
		}
	})

	t.Run("bots that copy a real browser exactly, loading a search page from 30,000 addresses", func(t *testing.T) {
		for _, name := range all {
			t.Run(name, func(t *testing.T) {
				m := newSim(t, strength(t, name))
				m.warm(10)
				bots := botnet(30_000, m.r)
				res := m.run(90, 3000, func(i int) {
					m.do("attack", bots[m.r.IntN(len(bots))], "/search?q="+strconv.Itoa(m.r.IntN(1e9)), true, browsers[0])
				})
				t.Log(res)
				t.Logf("reasons: %q", res.inc.Reasons)
				if res.detectedAfter < 0 || res.detectedAfter > 12 || res.attackAdmitted > 0.03 || res.known < 0.98 || res.new < 0.85 {
					t.Fatal("protection below the bar")
				}
			})
		}
	})

	t.Run("low and slow: 10,000 addresses, each one request every 20 seconds", func(t *testing.T) {
		m := newSim(t, nil)
		m.warm(10)
		bots := botnet(10_000, m.r)
		res := m.run(90, 500, func(i int) {
			m.do("attack", bots[m.r.IntN(len(bots))], "/wp-login.php", false, python)
		})
		t.Log(res)
		if res.detectedAfter < 0 || res.detectedAfter > 12 || res.attackAdmitted > 0.05 || res.known < 0.98 {
			t.Fatal("protection below the bar")
		}
	})

	// A patient botnet: 2,000 addresses that each loaded the home page every 100 seconds, like a person, for ten minutes before
	// the attack, and so earned standing. The control gives standing no budget of its own (as before the standing budget
	// existed): the bots then go straight through.
	patient := func(t *testing.T, mod func(*Config)) result {
		m := newSim(t, mod)
		bots := botnet(2_000, m.r)
		for i := range bots {
			bots[i].browser = 0
		}
		for sec := 0; sec < 10*60; sec++ {
			m.second(m.kv, m.nv, 20, func(i int) {
				b := bots[(sec*20+i)%len(bots)]
				m.do("bots earning standing", b, "/", true, browsers[0])
			})
		}
		if st := m.s.State(); st != Normal {
			t.Fatalf("after warm-up the state is %v", st)
		}
		m.stats = map[string]*tally{}
		return m.run(90, 3000, func(i int) {
			m.do("attack", bots[m.r.IntN(len(bots))], "/search?q="+strconv.Itoa(m.r.IntN(1e9)), true, browsers[0])
		})
	}
	t.Run("a botnet that earned standing before it attacks, copying a real browser", func(t *testing.T) {
		for _, name := range all {
			t.Run(name, func(t *testing.T) {
				res := patient(t, strength(t, name))
				t.Log(res)
				if res.detectedAfter < 0 || res.detectedAfter > 12 || res.attackAdmitted > 0.05 || res.known < 0.95 || res.new < 0.85 {
					t.Fatal("protection below the bar")
				}
			})
		}
	})
	t.Run("the same botnet with standing unbudgeted (control: the standing budget is what holds it)", func(t *testing.T) {
		res := patient(t, func(c *Config) { c.KnownFactor = 1e6 })
		t.Log(res)
		if res.detectedAfter < 0 || res.known > 0.2 {
			t.Fatal("with standing unbudgeted the attack was missed or visitors were still served: the simulation does not test the budget")
		}
	})

	// Under strict, as under normal, the crowd is taken for an attack; the people in it must still be served.
	t.Run("a newsletter sends a crowd to one article whose assets are on another host (taken for an attack, people still served)", func(t *testing.T) {
		for _, name := range strengths("normal", "strict") {
			t.Run(name, func(t *testing.T) {
				m := newSim(t, strength(t, name))
				m.warm(10)
				crowd := func(i int) {
					v := &simVisitor{addr: m.legitAddr(), browser: m.r.IntN(len(browsers))}
					m.do("legit new", v, "/blog/big-news", true, browsers[v.browser])
				}
				res := m.run(90, 150, crowd) // within what the origin can serve: the question is only what the shield does
				t.Logf("highest state %v; %s; reasons %q", res.maxState, res, m.s.Snapshot().Reasons)
				if all := m.tally("legit new").rate(); all < 0.95 {
					t.Fatalf("only %.1f%% of the crowd was served", 100*all)
				}
			})
		}
	})

	// strict is not held to this: it is meant to declare an attack on a smaller rise, and the people in a crowd it takes
	// for one are served through the challenge, as the newsletter case above shows.
	t.Run("a flash crowd of real people (negative control: not an attack)", func(t *testing.T) {
		for _, name := range strengths("relaxed", "normal") {
			t.Run(name, func(t *testing.T) {
				m := newSim(t, strength(t, name))
				m.warm(10)
				res := result{detectedAfter: -1}
				for sec := 0; sec < 120; sec++ {
					m.second(4, 40, 0, nil) // ten times the visits, almost all new, every browser, pages and assets
					if st := m.s.State(); st > res.maxState {
						res.maxState = st
					}
				}
				t.Logf("highest state %v; new visitors served %.1f%%", res.maxState, 100*m.tally("legit new").rate())
				if res.maxState == Attack {
					t.Fatalf("a crowd of people was taken for an attack: %q", m.s.Snapshot().Reasons)
				}
			})
		}
	})

	// A flood that grows by a fraction of a percent a second: slowly enough that a baseline that learnt every second would
	// follow it and never see four times its usual rate.
	grow := func(by float64, sec int) int { return int(min(10*math.Exp(by*float64(sec)), 3000)) }
	ramp := func(sec int) int { return grow(0.003, sec) }
	for _, tc := range []struct {
		name       string
		by         float64 // the flood's growth a second
		minutes    int
		known, new float64       // the least share of visitors to be served in the minute after detection
		queue      time.Duration // see sim.queue
	}{
		{"a botnet that ramps up slowly, doubling every four minutes, until the application fails", 0.003, 40, 0.95, 0.85, 0},
		// Its clients give up long before such an application would fail them: what it does not answer is told only by how
		// long they waited before they hung up.
		{"the same botnet against an application that queues what it cannot serve until its clients hang up", 0.003, 40, 0.95, 0.85, 5 * time.Second},
		// The application keeps up until the flood is about 170 a second, and by the time it fails about half the flood has
		// been learnt as the usual. The attack's budgets are sized from that usual and let about a third of the flood in: it
		// is declared, and held off only in part.
		{"a botnet that ramps up more slowly still, doubling every eight minutes, until the application fails", 0.0015, 80, 0.6, 0.6, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newSim(t, nil)
			m.queue = tc.queue
			m.warm(10)
			bots := botnet(20_000, m.r)
			detected := -1
			var known, fresh, attack tally
			for sec := 0; sec < tc.minutes*60 && (detected < 0 || sec < detected+60); sec++ {
				m.second(m.kv, m.nv, grow(tc.by, sec), func(int) {
					m.do("attack", bots[m.r.IntN(len(bots))], "/?r="+strconv.Itoa(m.r.IntN(1e9)), false, python)
				})
				if m.s.State() == Attack && detected < 0 {
					detected = sec
					t.Logf("detected after %ds at %d requests a second: %q", sec, grow(tc.by, sec), m.s.Snapshot().Reasons)
					known, fresh, attack = *m.tally("legit known"), *m.tally("legit new"), *m.tally("attack")
				}
			}
			if detected < 0 {
				t.Fatalf("a flood that reached %d requests a second on a site that serves 200 was never declared an attack", grow(tc.by, tc.minutes*60))
			}
			k, n, a := m.tally("legit known"), m.tally("legit new"), m.tally("attack")
			gotK, gotN := float64(k.ok-known.ok)/float64(k.sent-known.sent), float64(n.ok-fresh.ok)/float64(n.sent-fresh.sent)
			t.Logf("in the minute after detection returning visitors were served %.1f%%, new %.1f%%, and %.1f%% of the flood admitted",
				100*gotK, 100*gotN, 100*float64(a.ok-attack.ok)/float64(a.sent-attack.sent))
			if gotK < tc.known || gotN < tc.new {
				t.Fatal("protection below the bar")
			}
		})
	}
	for _, tc := range []struct {
		name    string
		slow    bool
		failing float64 // the share of requests the application fails whatever the load
	}{
		{"ordinary traffic that grows as fast, on an application that keeps up (negative control: not an attack)", false, 0},
		// Latency is measured until the response has been sent, so these make the application look slow when it is not.
		{"the same growth while four addresses download slowly, half a minute each (negative control: not an attack)", true, 0},
		// The application fails, but no more as more people come: what it answers grows with them, as a flood's does not.
		// Growth this fast is taken for an attack with the application failing whatever the baseline learns, so it is
		// sixfold over the twenty minutes, steadily.
		{"traffic that grows sixfold while a broken dependency fails three requests in ten (negative control: not an attack)", false, 0.3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newSim(t, nil)
			m.capacity, m.lat = 10_000, 50*time.Millisecond
			m.warm(10)
			slow := []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("198.51.100.3"), netip.MustParseAddr("198.51.100.4")}
			type download struct {
				d    Decision
				ends time.Time
			}
			var downloads []download
			worst := Normal
			for sec := 0; sec < 20*60; sec++ {
				v := max(4, ramp(sec)*4/10) // the visits of returning and of new visitors, each from 4 to 40 a second
				if tc.failing > 0 {
					v = 4 + 20*sec/(20*60)
					m.capacity = int((1 - tc.failing) * float64(8*v))
				}
				m.second(min(v, 40), min(v, 40), 0, nil)
				for i := 0; tc.slow && i < max(1, min(v, 40)*2/5); i++ { // one request in twenty
					if d := m.s.Admit(simRequest("/files/report.pdf"), slow[i%len(slow)]); d.Action == Allow {
						downloads = append(downloads, download{d, m.clock.Add(30 * time.Second)})
					}
				}
				for len(downloads) > 0 && !downloads[0].ends.After(m.clock) {
					m.s.Done(downloads[0].d, 200, true)
					downloads = downloads[1:]
				}
				if st := m.s.State(); st > worst {
					worst = st
				}
			}
			t.Logf("highest state %v; new visitors served %.1f%%", worst, 100*m.tally("legit new").rate())
			if worst == Attack {
				t.Fatalf("ordinary traffic growing over twenty minutes was taken for an attack: %q", m.s.Snapshot().Reasons)
			}
		})
	}

	t.Run("a new browser release that half the visitors take up, then a flash crowd (negative control: not an attack)", func(t *testing.T) {
		m := newSim(t, nil)
		m.warm(10)
		// Chrome 142 comes out after the baseline has warmed up, and half the visitors, returning and new, move to it.
		chrome := append([]string(nil), browsers[0]...)
		chrome[1] = strings.ReplaceAll(chrome[1], "Chrome/141.0", "Chrome/142.0")
		chrome[7] = `"Chromium";v="142"`
		m.ua = [][]string{chrome, chrome, chrome, browsers[1], browsers[2], browsers[3]}
		for sec := 0; sec < 30*60; sec++ {
			m.second(m.kv, m.nv, 0, nil)
		}
		fp, _ := fingerprint(func() *http.Request {
			r := simRequest("/")
			for i := 0; i+1 < len(chrome); i += 2 {
				r.Header.Set(chrome[i], chrome[i+1])
			}
			r.Header.Set("Accept", "*/*")
			r.Header.Set("Sec-Fetch-Mode", "no-cors")
			return r
		}())
		m.s.det.mu.Lock()
		learnt := m.s.det.base.fps[fp]
		m.s.det.mu.Unlock()
		if learnt < 0.2 {
			t.Errorf("after half an hour the new browser's assets are usually %.1f%% of requests, want about 37%%", 100*learnt)
		}
		worst := Normal
		for sec := 0; sec < 120; sec++ {
			m.second(4, 40, 0, nil)
			if st := m.s.State(); st > worst {
				worst = st
			}
		}
		t.Logf("highest state %v; new visitors served %.1f%%", worst, 100*m.tally("legit new").rate())
		if worst == Attack {
			t.Fatalf("a crowd of people with a browser released after the start was taken for an attack: %q", m.s.Snapshot().Reasons)
		}
	})

	t.Run("an app's users surge five minutes after a restart with the usual rate given (negative control: not an attack)", func(t *testing.T) {
		m := newSim(t, func(c *Config) { c.Detector.InitialRate = 120 })
		m.app = []string{"User-Agent", "ExampleApp/5.2 (iOS 18.6; iPhone16,2) Alamofire/5.9", "Accept", "application/json", "Accept-Encoding", "gzip, br"}
		m.capacity, m.kv, m.nv = 10_000, 15, 15 // 120 requests a second, the rate given, all of it one app calling one endpoint
		for sec := 0; sec < 5*60; sec++ {
			m.second(m.kv, m.nv, 0, nil)
		}
		worst := Normal
		for sec := 0; sec < 60; sec++ {
			m.second(5*m.kv, 5*m.nv, 0, nil)
			if st := m.s.State(); st > worst {
				worst = st
			}
		}
		t.Logf("highest state %v; served %.1f%% (returning) %.1f%% (new)", worst, 100*m.tally("legit known").rate(), 100*m.tally("legit new").rate())
		if worst == Attack {
			t.Fatalf("the app's own users were taken for an attack: %q", m.s.Snapshot().Reasons)
		}
	})

	t.Run("a restart into a flood of one target from many programs, with the usual rate given", func(t *testing.T) {
		m := newSim(t, func(c *Config) { c.Detector.InitialRate = 32 })
		m.capacity = 10_000 // the application keeps up: there is no harm to tell, only what the flood looks like
		bots := botnet(20_000, m.r)
		target := "/" + randomWord(m.r)
		res := m.run(60, 2000, func(i int) {
			// Sixty-four programs: nothing stands out but the volume, the target and new addresses that ask for nothing else.
			ua := []string{"User-Agent", "bot/" + strconv.Itoa(m.r.IntN(64)), "Accept", "*/*"}
			m.do("attack", bots[m.r.IntN(len(bots))], target, false, ua)
		})
		t.Log(res)
		if res.detectedAfter < 0 || res.detectedAfter > 12 || res.known < 0.95 || res.new < 0.9 {
			t.Fatal("protection below the bar")
		}
	})

	for _, tc := range []struct {
		name        string
		bots, rate  int
		minutes     int
		banFor      time.Duration
		programs    int     // 64 when 0
		pre         int     // seconds of the flood at 150 requests a second, which the site is not yet hurt by, first
		initialRate float64 // the -ddos-baseline-rate of a restart into the flood, with no warm-up
	}{
		{"a flood that rotates its look and shows only harm, going on longer than the evidence time-out", 200_000, 2000, 5, 0, 0, 0, 0},
		// One request a second from each address: each is banned within a minute, its ban's refusals are then most of the
		// flood, and when the bans run out the addresses are refused and banned again.
		{"the same flood from 1,000 addresses, banned and going on after their bans run out", 1_000, 1000, 6, 3 * time.Minute, 0, 0, 0},
		// Fifteen seconds over the threshold, with no evidence yet, must not teach the baseline the flood's programs: they
		// would then be the site's own, whose traffic does not hold an attack.
		{"the same flood from eight programs, after fifteen seconds that do not hurt", 200_000, 2000, 5, 0, 8, 15, 0},
		// The baseline knows no fingerprint, so nothing tells the site's own clients from the flood.
		{"the same flood after a restart into it with the usual rate given", 200_000, 2000, 5, 0, 0, 0, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newSim(t, func(c *Config) {
				c.Detector.EvidenceTimeout, c.BanFor, c.Detector.InitialRate = 2*time.Minute, tc.banFor, tc.initialRate
			})
			if tc.initialRate == 0 {
				m.warm(10)
			}
			bots := botnet(tc.bots, m.r)
			programs := cmp.Or(tc.programs, 64)
			flood := func(int) {
				ua := []string{"User-Agent", "bot/" + strconv.Itoa(m.r.IntN(programs)), "Accept", "*/*"}
				m.do("attack", bots[m.r.IntN(len(bots))], "/"+randomWord(m.r), false, ua)
			}
			if tc.pre > 0 {
				if res := m.run(tc.pre, 150, flood); res.maxState != Elevated {
					t.Fatalf("the first %d seconds put the site in state %v, not elevated, so the test proves nothing", tc.pre, res.maxState)
				}
			}
			// Once mitigated the application is well again, so the harm that declared the attack is gone while the flood is not.
			res := m.run(tc.minutes*60, tc.rate, flood)
			t.Log(res)
			if n := len(m.s.Snapshot().Recent); n > 0 || m.s.State() != Attack {
				t.Fatalf("the attack ended %d times while the flood went on, leaving the application to it each time", n)
			}
			if res.detectedAfter < 0 || res.detectedAfter > 12 || res.known < 0.95 || res.new < 0.9 {
				t.Fatal("protection below the bar")
			}
			// One address goes on at 400 requests a second: over the threshold, and mostly refused, but by its own limit and
			// then its ban, which hold it whether there is an attack or not, so it must not hold the attack.
			one := &simVisitor{addr: netip.MustParseAddr("203.0.113.1")}
			ended := -1
			for sec := 0; sec < 3*60 && ended < 0; sec++ {
				m.second(m.kv, m.nv, 400, func(int) { m.do("attack", one, "/", false, python) })
				if m.s.State() != Attack {
					ended = sec
				}
			}
			t.Logf("the attack ended %d seconds after the flood stopped", ended)
			if ended < 0 {
				t.Fatal("the attack did not end after the flood stopped, held by one address that its own limit holds")
			}
		})
	}

	// The flood is over and the frozen baseline is what the attack's budgets are sized from: when the app's own users then
	// grow past its threshold, the budgets refuse much of their traffic, which must not keep the attack for ever.
	t.Run("a flood that stops before the app's own users grow to eight times their usual (negative control: the attack ends)", func(t *testing.T) {
		m := newSim(t, func(c *Config) { c.Detector.EvidenceTimeout = 2 * time.Minute })
		m.app = []string{"User-Agent", "ExampleApp/5.2 (iOS 18.6; iPhone16,2) Alamofire/5.9", "Accept", "application/json", "Accept-Encoding", "gzip, br"}
		m.capacity = 10_000
		m.warm(10)
		bots := botnet(20_000, m.r)
		if res := m.run(60, 5000, func(int) {
			m.do("attack", bots[m.r.IntN(len(bots))], "/?r="+strconv.Itoa(m.r.IntN(1e9)), false, python)
		}); res.detectedAfter < 0 {
			t.Fatal("the flood was not declared an attack, so the test proves nothing")
		}
		ended := -1
		for sec := 0; sec < 6*60 && ended < 0; sec++ {
			m.second(8*m.kv, 8*m.nv, 0, nil)
			if m.s.State() != Attack {
				ended = sec
			}
		}
		t.Logf("the attack ended %d seconds after the flood stopped; returning users served %.1f%%, new %.1f%%",
			ended, 100*m.tally("legit known").rate(), 100*m.tally("legit new").rate())
		if ended < 0 {
			t.Fatalf("the app's own users, grown past the frozen threshold, held the attack: %q", m.s.Snapshot().Reasons)
		}
	})

	t.Run("one IPv6 host flooding from addresses all over its /64 (negative control: one client, which its own limit holds)", func(t *testing.T) {
		v6 := func(net, host int) netip.Addr { // 2001:db8:1:<net>::<host>
			return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, byte(net >> 8), byte(net), 12: byte(host >> 24), byte(host >> 16), byte(host >> 8), byte(host)})
		}
		// flood is ten seconds of 300 requests a second from one program, each from the address from gives it; it returns
		// the highest state the site was in and the reasons then.
		flood := func(from func(i int) netip.Addr) (State, []string) {
			m := newSim(t, func(c *Config) { c.Labeler = nil }) // the simulation's labeller knows IPv4 only
			m.warm(10)
			worst, reasons := Normal, []string(nil)
			for sec := 0; sec < 10; sec++ {
				m.second(m.kv, m.nv, 300, func(i int) {
					m.do("attack", &simVisitor{addr: from(sec*300 + i)}, "/?r="+strconv.Itoa(m.r.IntN(1e9)), false, python)
				})
				if st := m.s.State(); st > worst {
					worst, reasons = st, m.s.Snapshot().Reasons
				}
			}
			return worst, reasons
		}
		if st, reasons := flood(func(i int) netip.Addr { return v6(2, i) }); st == Attack {
			t.Fatalf("one host that changes the last 64 bits of its address was taken for an attack from many addresses: %q", reasons)
		}
		if st, _ := flood(func(i int) netip.Addr { return v6(i%40, 1) }); st != Attack {
			t.Fatalf("control: the same flood from 40 different /64s was not taken for an attack (state %v), so the test proves nothing", st)
		}
	})

	t.Run("one address opening connections as fast as it can, while visitors open their own (negative control: its own limit holds it)", func(t *testing.T) {
		// flood is ten minutes of ordinary traffic in which visitors open twenty connections a second, then a minute in
		// which 300 connections a second more, each sending nothing, come from the addresses given; it returns the highest
		// state the site was in and the reasons then.
		flood := func(from []netip.Addr) (State, []string) {
			m := newSim(t, nil)
			open := func(a netip.Addr) {
				mine, theirs := net.Pipe()
				defer theirs.Close()
				if c := m.s.admitConn(addrConn{mine, net.TCPAddrFromAddrPort(netip.AddrPortFrom(a, 40000))}); c != nil {
					c.Close()
				}
			}
			visitors := func(int) { open(m.known[m.r.IntN(len(m.known))].addr) }
			for i := 0; i < 10*60; i++ {
				m.second(m.kv, m.nv, 20, visitors)
			}
			if st := m.s.State(); st != Normal {
				t.Fatalf("after warm-up the state is %v", st)
			}
			worst, reasons := Normal, []string(nil)
			for i := 0; i < 60; i++ {
				m.second(m.kv, m.nv, 20+300, func(n int) {
					if n < 20 {
						visitors(n)
					} else {
						open(from[n%len(from)])
					}
				})
				if st := m.s.State(); st > worst {
					worst, reasons = st, m.s.Snapshot().Reasons
				}
			}
			return worst, reasons
		}
		if st, reasons := flood([]netip.Addr{netip.MustParseAddr("203.0.113.5")}); st == Attack {
			t.Fatalf("one address opening connections put the whole site into attack mode: %q", reasons)
		}
		var many []netip.Addr
		for _, b := range botnet(400, rand.New(rand.NewPCG(3, 5))) {
			many = append(many, b.addr)
		}
		if st, _ := flood(many); st != Attack {
			t.Fatalf("control: the same connections from 400 addresses were not taken for an attack (state %v), so the test proves nothing", st)
		}
	})
}

// busy builds a site with ten times the traffic of the one above, a share of whose returning visitors come through a few
// addresses that carry many people each (a company's gateway, a mobile carrier's), which any fixed per-address limit
// treats as attackers.
func busy(t *testing.T, mod func(*Config)) *sim {
	m := newSim(t, mod)
	m.capacity, m.kv, m.nv = 4000, 240, 60 // 1,200 requests a second of ordinary traffic
	m.natShare = 0.5
	for i := 1; i <= 4; i++ {
		m.shared = append(m.shared, netip.AddrFrom4([4]byte{100, 64, 0, byte(i)}))
	}
	for i := 0; i < 4000; i++ {
		m.known = append(m.known, &simVisitor{addr: m.legitAddr(), browser: i % len(browsers)})
	}
	return m
}

// busyWarm is how many seconds of ordinary traffic the shared addresses of busy need to earn the limits their visitors
// need: a second counts for at most twice an address's average and weighs a six-hundredth, so it takes about 25 minutes
// from a start.
const busyWarm = 25 * 60

func TestASiteWithMuchTrafficIsNotLimitedAsIfItWereSmall(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	python := []string{"User-Agent", "python-requests/2.32.3", "Accept", "*/*", "Accept-Encoding", "gzip, deflate", "Connection", "keep-alive"}

	// strict is not held to this: it is for a small site, and lowers the ceiling of the raise to 10.
	t.Run("visitors behind shared addresses are served, because each address's limit follows its own traffic", func(t *testing.T) {
		notUnderRace(t)
		for _, name := range strengths("relaxed", "normal") {
			t.Run(name, func(t *testing.T) {
				m := busy(t, strength(t, name))
				for i := 0; i < busyWarm; i++ {
					m.second(m.kv, m.nv, 0, nil)
				}
				snap := m.s.Snapshot()
				t.Logf("state %v, usual %.0f requests a second; per-address limit raised %.1fx, per-network %.1fx; legit served %.2f%%",
					snap.State, snap.BaselineRate, snap.RequestScale, snap.NetworkScale, 100*m.tally("legit known").rate())
				if snap.State == Attack {
					t.Fatalf("ordinary busy traffic was taken for an attack: %q", snap.Reasons)
				}
				m.stats = map[string]*tally{}
				for i := 0; i < 60; i++ {
					m.second(m.kv, m.nv, 0, nil)
				}
				if got := m.tally("legit known").rate(); got < 0.995 {
					t.Fatalf("only %.2f%% of returning visitors (half of them behind shared addresses) were served", 100*got)
				}
			})
		}
	})

	t.Run("an address that has sent nothing has only the limit it was given, however busy the others are", func(t *testing.T) {
		notUnderRace(t)
		m := busy(t, nil)
		for i := 0; i < busyWarm; i++ {
			m.second(m.kv, m.nv, 0, nil)
		}
		if snap := m.s.Snapshot(); snap.RequestScale < 2 {
			t.Fatalf("the busiest address's limit is raised %.1fx: no address has earned anything, so this proves nothing", snap.RequestScale)
		}
		m.stats = map[string]*tally{}
		stranger := &simVisitor{addr: netip.MustParseAddr("203.0.113.9")}
		const seconds = 5
		for i := 0; i < seconds; i++ {
			m.second(m.kv, m.nv, 600, func(int) { m.do("stranger", stranger, "/search?q="+strconv.Itoa(m.r.IntN(1e6)), false, python) })
		}
		got := m.tally("stranger")
		// The configured limit: bursts of 200, and 50 a second.
		if limit := 200 + 50*seconds; got.ok > limit {
			t.Fatalf("%d of the stranger's %d requests were served: its own limit allows %d", got.ok, got.sent, limit)
		}
		if served := m.tally("legit known").rate(); served < 0.995 {
			t.Fatalf("only %.2f%% of returning visitors were served meanwhile", 100*served)
		}
	})

	t.Run("control: with the limits fixed, the same visitors are refused", func(t *testing.T) {
		notUnderRace(t)
		m := busy(t, func(c *Config) { c.Detector.MaxScale = 1 })
		for i := 0; i < 8*60; i++ {
			m.second(m.kv, m.nv, 0, nil)
		}
		got := m.tally("legit known").rate()
		t.Logf("legit returning visitors served with fixed limits: %.1f%%", 100*got)
		if got > 0.9 {
			t.Fatalf("with fixed limits %.1f%% were served: the simulated site does not stress them, so the test above proves nothing", 100*got)
		}
	})

	t.Run("an attack of 8,000 requests a second from 25,000 addresses on a site that serves 1,200", func(t *testing.T) {
		m := busy(t, nil)
		for i := 0; i < busyWarm; i++ {
			m.second(m.kv, m.nv, 0, nil)
		}
		m.stats = map[string]*tally{}
		// What the shared addresses earned neither grows nor fades while the attack lasts.
		earnedBy := func() (avg float32) {
			m.s.sources.peek(m.shared[0], func(src *source) { avg = src.earned.avg })
			return avg
		}
		before := earnedBy()
		bots := botnet(25_000, m.r)
		res := m.run(60, 8000, func(i int) {
			m.do("attack", bots[m.r.IntN(len(bots))], "/?r="+strconv.Itoa(m.r.IntN(1e9)), false, python)
		})
		if after := earnedBy(); before < 50 || after < 0.95*before || after > 1.05*before {
			t.Fatalf("a shared address had earned %.1f requests a second before the attack and %.1f after a minute of it", before, after)
		}
		t.Log(res)
		if res.detectedAfter < 0 || res.detectedAfter > 12 || res.attackAdmitted > 0.02 || res.known < 0.98 || res.new < 0.9 {
			t.Fatal("protection below the bar")
		}
	})

	t.Run("a sudden tripling of real traffic is not an attack", func(t *testing.T) {
		notUnderRace(t)
		m := busy(t, nil)
		for i := 0; i < 8*60; i++ {
			m.second(m.kv, m.nv, 0, nil)
		}
		m.stats = map[string]*tally{}
		worst := Normal
		for i := 0; i < 120; i++ {
			m.second(3*m.kv, 3*m.nv, 0, nil)
			if st := m.s.State(); st > worst {
				worst = st
			}
		}
		t.Logf("highest state %v; returning %.1f%%, new %.1f%% served", worst, 100*m.tally("legit known").rate(), 100*m.tally("legit new").rate())
		if worst == Attack {
			t.Fatalf("a tripling of ordinary visits was taken for an attack: %q", m.s.Snapshot().Reasons)
		}
	})
}

// A steady site and a bursty one with the same average must not have the same threshold: the bursty one has to see more
// before it calls it an attack, because its own ordinary traffic already swings that far.
func TestTheRateThresholdFollowsTheSitesOwnVariation(t *testing.T) {
	drive := func(burst bool) (mean, threshold float64) {
		now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
		d := newDetector(DetectorConfig{Warmup: 2 * time.Minute, Tau: 5 * time.Minute})
		n := uint32(0)
		for sec := 0; sec < 40*60; sec++ {
			rate := 200
			if burst && sec%37 < 5 { // five seconds in thirty-seven at six times the rate
				rate = 1200
			}
			if burst && sec%37 >= 5 {
				rate = 120
			}
			for i := 0; i < rate; i++ {
				n++
				a := netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
				d.observe(now.Add(time.Duration(sec)*time.Second+time.Duration(i)*time.Millisecond).UnixNano(), a, 1, "x", 2, "/")
			}
			d.tick(now.Add(time.Duration(sec+1) * time.Second).UnixNano())
		}
		d.mu.Lock()
		mean = d.base.rate
		d.mu.Unlock()
		return mean, d.rateThreshold()
	}
	sMean, sThr := drive(false)
	bMean, bThr := drive(true)
	t.Logf("steady: mean %.0f/s, threshold %.0f/s (%.1fx); bursty: mean %.0f/s, threshold %.0f/s (%.1fx)", sMean, sThr, sThr/sMean, bMean, bThr, bThr/bMean)
	if sThr < 3.9*sMean || sThr > 4.4*sMean {
		t.Fatalf("a steady site's threshold is %.1fx its average, want about 4x", sThr/sMean)
	}
	if bThr/bMean < 1.25*sThr/sMean {
		t.Fatalf("a bursty site's threshold (%.1fx) is not clearly above a steady site's (%.1fx)", bThr/bMean, sThr/sMean)
	}
}

// A site that is already busy when the proxy starts (a first deployment, a restart) has no baseline: its first seconds
// must not be taken for an attack, and a state of "attack" must always be able to end.
func TestABusySiteIsNotAnAttackWhenTheProxyStarts(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	m := busy(t, nil)
	worst, attackSeconds := Normal, 0
	for i := 0; i < 10*60; i++ {
		m.second(m.kv, m.nv, 0, nil)
		st := m.s.State()
		if st > worst {
			worst = st
		}
		if st == Attack {
			attackSeconds++
		}
	}
	t.Logf("first ten minutes of a site serving 1,200 requests a second, no baseline: highest state %v, %d seconds in attack; new visitors served %.1f%%",
		worst, attackSeconds, 100*m.tally("legit new").rate())
	if attackSeconds > 0 {
		t.Fatalf("a busy site's first minutes were taken for an attack: %q", m.s.Snapshot().Reasons)
	}
	if got := m.tally("legit new").rate(); got < 0.99 {
		t.Fatalf("new visitors served %.1f%%", 100*got)
	}
}

func TestAnAttackThatShowsNoEvidenceForFiveMinutesEnds(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	d := newDetector(DetectorConfig{Warmup: 2 * time.Minute, Tau: 5 * time.Minute, MinAttack: 30 * time.Second, EvidenceTimeout: 3 * time.Minute})
	var kinds []string
	d.onEvent = func(e Event) {
		if e.Kind != "attack_update" {
			kinds = append(kinds, e.Kind)
		}
	}
	n := uint32(0)
	feed := func(sec, rate int, fp uint64, path uint64, variety uint32) {
		for i := 0; i < rate; i++ {
			n++
			a := netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
			d.observe(now.Add(time.Duration(sec)*time.Second).UnixNano(), a, fp+uint64(n%variety), "x", path+uint64(n%variety), "/")
			d.count(now.Add(time.Duration(sec)*time.Second).UnixNano(), func(w *window) { w.engaged++ })
		}
		d.tick(now.Add(time.Duration(sec+1) * time.Second).UnixNano())
	}
	sec := 0
	for ; sec < 300; sec++ {
		feed(sec, 100, 1, 100, 8) // eight fingerprints and eight targets, ordinary
	}
	if d.state == Attack || len(kinds) != 0 {
		t.Fatalf("ordinary traffic was reported: %q", kinds)
	}
	for ; sec < 330; sec++ {
		feed(sec, 1500, 500, 900, 1) // one program, one target: an attack
	}
	if d.state != Attack {
		t.Fatalf("the attack was not declared (state %v)", d.state)
	}
	// The rate stays high but the evidence is gone (the traffic is now as varied as ordinary traffic).
	ended := -1
	for ; sec < 330+600; sec++ {
		for i := 0; i < 1500; i++ {
			n++
			a := netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
			d.observe(now.Add(time.Duration(sec)*time.Second).UnixNano(), a, 1+uint64(n%8), "x", 100+uint64(n%8), "/")
			d.count(now.Add(time.Duration(sec)*time.Second).UnixNano(), func(w *window) { w.engaged++ })
		}
		d.tick(now.Add(time.Duration(sec+1) * time.Second).UnixNano())
		if d.state != Attack && ended < 0 {
			ended = sec - 330
		}
	}
	if ended < 0 {
		t.Fatal("the attack never ended although nothing shows it any more")
	}
	t.Logf("with traffic still at 15x but nothing to show an attack, the attack ended %d seconds later (timeout 180)", ended)
	if ended < 150 || ended > 260 {
		t.Fatalf("it ended after %d seconds, want about the 180-second timeout", ended)
	}
	// The traffic is still high after the attack, and then ordinary again: the owner is told both.
	for end := sec + 30; sec < end; sec++ {
		feed(sec, 100, 1, 100, 8)
	}
	if want := []string{"elevated", "attack_start", "attack_end", "elevated", "normal"}; !slices.Equal(kinds, want) {
		t.Fatalf("events %q, want %q", kinds, want)
	}
	// Short bursts that take the rate over the threshold and back are one rise, told once, until it has been calm.
	kinds = nil
	for burst := 0; burst < 4; burst++ {
		feed(sec, 30000, 1, 100, 8)
		sec++
		for end := sec + 14; sec < end; sec++ {
			feed(sec, 100, 1, 100, 8)
		}
	}
	for end := sec + 30; sec < end; sec++ {
		feed(sec, 100, 1, 100, 8)
	}
	if want := []string{"elevated", "normal"}; !slices.Equal(kinds, want) {
		t.Fatalf("events %q, want %q", kinds, want)
	}
}

// Traffic that is naturally concentrated (one mobile app calling one endpoint, which is most of what an API serves) has
// exactly the look of a flood to a detector that has not yet learnt it: one fingerprint, one target, all of the traffic.
// That must not be taken for an attack when the proxy starts, nor ever.
func TestAnAPIServedToOneAppIsNotAnAttackWhenTheProxyStarts(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	m := busy(t, nil)
	m.app = []string{"User-Agent", "ExampleApp/5.2 (iOS 18.6; iPhone16,2) Alamofire/5.9", "Accept", "application/json", "Accept-Encoding", "gzip, br"}
	attackSeconds := 0
	for i := 0; i < 10*60; i++ {
		m.second(m.kv, m.nv, 0, nil)
		if m.s.State() == Attack {
			attackSeconds++
		}
	}
	t.Logf("first ten minutes of an API serving 1,200 requests a second to one app, no baseline: %d seconds in attack; served %.2f%% (returning) %.2f%% (new)",
		attackSeconds, 100*m.tally("legit known").rate(), 100*m.tally("legit new").rate())
	if attackSeconds > 0 {
		t.Fatalf("the app's own traffic was taken for an attack: %q", m.s.Snapshot().Reasons)
	}
	if m.tally("legit new").rate() < 0.99 {
		t.Fatalf("new devices were refused")
	}
}

// Traffic that arrives in bursts from the moment the proxy starts: the first seconds look like a rise of several times
// "the usual", because nothing is usual yet. Nothing may be declared an attack until a baseline exists, and an attack
// declared on no baseline must not be able to stay.
func TestBurstyTrafficFromTheFirstSecondIsNotAnAttack(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	d := newDetector(DetectorConfig{Warmup: 2 * time.Minute, Tau: 5 * time.Minute})
	n := uint32(0)
	attackSeconds := 0
	for sec := 0; sec < 20*60; sec++ {
		rate := 120
		if sec%37 < 5 {
			rate = 1200 // five seconds in thirty-seven at ten times the rest
		}
		at := now.Add(time.Duration(sec) * time.Second).UnixNano()
		for i := 0; i < rate; i++ {
			n++
			a := netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
			d.observe(at, a, 1, "one program", 2, "/api/feed")
			d.count(at, func(w *window) { w.engaged++ })
		}
		d.tick(now.Add(time.Duration(sec+1) * time.Second).UnixNano())
		if d.state == Attack {
			attackSeconds++
		}
	}
	d.mu.Lock()
	mean := d.base.rate
	d.mu.Unlock()
	t.Logf("20 minutes of bursty traffic (mean %.0f requests a second) from a cold start: %d seconds in attack", mean, attackSeconds)
	if attackSeconds > 0 {
		t.Fatalf("%d seconds of ordinary bursty traffic were taken for an attack", attackSeconds)
	}
}
