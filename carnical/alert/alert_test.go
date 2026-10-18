// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// New package: each function below is the one home of its behaviour, and every behaviour is a row.

func TestClean(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"plain text is kept", "/search/item", 64, "/search/item"},
		{"exact fit is not cut", "abcdef", 6, "abcdef"},
		{"newline and carriage return are escaped", "a\r\nb", 64, `a\x0d\x0ab`},
		{"DEL and NUL are escaped", "a\x7f\x00", 64, `a\x7f\x00`},
		{"backslash is doubled so escapes cannot be forged", `a\x0ab`, 64, `a\\x0ab`},
		{"invalid UTF-8 is replaced", "a\xffb", 64, "a\uFFFDb"},
		{"line and paragraph separators are escaped", "a\u2028b\u2029", 64, `a\u2028b\u2029`},
		{"bidi overrides are escaped", "x\u202eexe.txt\u2066", 64, `x\u202eexe.txt\u2066`},
		{"C1 control NEL is escaped", "a\u0085b", 64, `a\u0085b`},
		{"printable non-ASCII is kept", "café", 64, "café"},
		{"long ASCII is cut with a marker", "abcdefgh", 6, "abc…"},
		{"cut never splits a rune", "éééé", 6, "é…"},
		{"non-ASCII that fits exactly is kept", "café", 5, "café"},
		{"escape that fits exactly with more after it is kept", "ab\nc", 7, `ab\x0ac`},
		{"escape one byte over is cut before it", "ab\nc", 6, "ab…"},
		{"cut never splits an escape", "a\nb", 5, "a…"},
		{"last escape that fits exactly is kept", "a\n", 5, `a\x0a`},
		{"too small for the marker gives nothing", "abcdef", 2, ""},
		{"zero max gives nothing", "abc", 0, ""},
		{"empty stays empty", "", 8, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Clean(tt.in, tt.max)
			if got != tt.want {
				t.Fatalf("Clean(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
			if len(got) > max(tt.max, 0) || !utf8.ValidString(got) {
				t.Fatalf("Clean(%q, %d) = %q: over the limit or not UTF-8", tt.in, tt.max, got)
			}
		})
	}
}

// crsCategory is the category the design gives each CRS file family (ADR-0084); none for the files that only set up,
// add up or exempt.
var crsCategory = map[int]Category{
	911: CatProtocol, 913: CatScanner, 920: CatProtocol, 921: CatProtocol, 922: CatProtocol, 930: CatLFI, 931: CatRFI,
	932: CatRCE, 933: CatPHP, 934: CatGeneric, 941: CatXSS, 942: CatSQLi, 943: CatSession, 944: CatJava,
	950: CatDataLeak, 951: CatDataLeak, 952: CatDataLeak, 953: CatDataLeak, 954: CatDataLeak, 955: CatDataLeak,
	956: CatDataLeak,
}

func TestCatalog(t *testing.T) {
	idRE := regexp.MustCompile(`"id:([0-9]+)`)
	files, err := filepath.Glob(filepath.Join("..", "crs", "owasp_crs", "*-9[0-9][0-9]-*.conf"))
	if err != nil || len(files) < 20 {
		t.Fatalf("CRS rule files: %v, %d found", err, len(files))
	}
	t.Run("every CRS family file", func(t *testing.T) {
		for _, f := range files {
			name := filepath.Base(f)
			t.Run(name, func(t *testing.T) {
				family, err := strconv.Atoi(strings.SplitN(name, "-", 3)[1])
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := crsFamilies[family]; !ok {
					t.Fatalf("family %d has no catalog name", family)
				}
				data, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range idRE.FindAllStringSubmatch(string(data), -1) {
					id, _ := strconv.Atoi(m[1])
					e, ok := Lookup(id)
					if !ok || e.Name == "" || e.Name == "OWASP CRS rule" || e.Risk == 0 {
						t.Fatalf("rule %d: %+v, %v", id, e, ok)
					}
					if want := Of(crsCategory[family]); id/1000 == family && e.Categories != want {
						t.Fatalf("rule %d: categories %v, want %v", id, e.Categories.Names(4), want.Names(4))
					}
					if sig := Signature(id); sig != "crs-"+m[1] || !ValidSignature(sig) {
						t.Fatalf("rule %d: signature %q", id, sig)
					}
				}
			})
		}
	})
	t.Run("every Coraza base rule", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("..", "crs", "base", "coraza.conf"))
		if err != nil {
			t.Fatal(err)
		}
		rules := regexp.MustCompile(`"id:'([0-9]+)'([^"]*)"`).FindAllStringSubmatch(string(data), -1)
		if len(rules) < 5 {
			t.Fatalf("%d base rules found", len(rules))
		}
		for _, m := range rules {
			id, _ := strconv.Atoi(m[1])
			e, ok := Lookup(id)
			if named, has := baseRules[id]; !ok || !has || e != named || e.Risk == 0 {
				t.Fatalf("base rule %d: %+v, %v", id, e, ok)
			}
			if strings.Contains(m[2], "deny") && (e.Risk < RiskMedium || e.Categories == 0) {
				t.Fatalf("refusing base rule %d: %+v", id, e)
			}
			if sig := Signature(id); sig != "crs-"+m[1] || !ValidSignature(sig) {
				t.Fatalf("base rule %d: signature %q", id, sig)
			}
		}
	})
	t.Run("local rules carry their own fixed message", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("..", "crs", "local", "REQUEST-499-CARNICAL.conf"))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, m := range regexp.MustCompile(`"id:(500[0-9]{4}),[^"]*msg:'([^']*)'`).FindAllStringSubmatch(string(data), -1) {
			id, _ := strconv.Atoi(m[1])
			if e, ok := localRules[id]; !ok || e.Name != m[2] || e.Categories == 0 {
				t.Errorf("local rule %d: catalog %+v, rule message %q", id, e, m[2])
			}
			n++
		}
		if n != len(localRules) {
			t.Fatalf("%d local rules with a message in the file, %d in the catalog", n, len(localRules))
		}
	})
	t.Run("every attack tag of the rules has a category", func(t *testing.T) {
		local, _ := filepath.Glob(filepath.Join("..", "crs", "local", "*.conf"))
		seen := map[string]bool{}
		for _, f := range append(files, local...) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range regexp.MustCompile(`tag:'(attack-[a-z-]+)'`).FindAllStringSubmatch(string(data), -1) {
				seen[m[1]] = true
			}
		}
		if len(seen) < 10 {
			t.Fatalf("%d attack tags found", len(seen))
		}
		for tag := range seen {
			if TagCategory(tag) == 0 {
				t.Errorf("tag %q has no category", tag)
			}
		}
		for tag, want := range map[string]Category{"attack-sqli": CatSQLi, "attack-reputation-scanner": CatScanner,
			"attack-fixation": CatSession, "paranoia-level/1": 0, "OWASP_CRS": 0, "attack-unknown": 0, "": 0} {
			if got := TagCategory(tag); got != want {
				t.Errorf("TagCategory(%q) = %v, want %v", tag, got, want)
			}
		}
	})

	rows := []struct {
		name string
		id   int
		ok   bool
		sig  string
		cat  Category
		risk Risk
	}{
		{"inbound verdict is high", 949110, true, "crs-949110", 0, RiskHigh},
		{"outbound verdict is high", 959100, true, "crs-959100", 0, RiskHigh},
		{"early inbound verdict is high", 949111, true, "crs-949111", 0, RiskHigh},
		{"early outbound verdict is high", 959101, true, "crs-959101", 0, RiskHigh},
		{"a rule that only reads the score is low", 949011, true, "crs-949011", 0, RiskLow},
		{"libinjection SQLi has its own name", 942100, true, "crs-942100", CatSQLi, RiskLow},
		{"another SQLi rule has the family name", 942190, true, "crs-942190", CatSQLi, RiskLow},
		{"local rule", 5006003, true, "crs-5006003", CatRCE, RiskLow},
		{"executable upload", 5000010, true, "carnical-5000010", CatUpload, RiskHigh},
		{"WordPress script", 5000020, true, "carnical-5000020", CatWordPress, RiskHigh},
		{"path canonicalisation", 5000002, true, "carnical-5000002", CatEvasion, RiskMedium},
		{"CrowdSec ban", 5000060, true, "carnical-5000060", CatReputation, RiskMedium},
		{"formats family", 5002103, true, "formats-5002103", CatFormat, RiskMedium},
		{"apiguard spec", 5003113, true, "apiguard-5003113", CatAPIContract, RiskLow},
		{"shield address rate", 5004001, true, "shield-5004001", CatFlood, RiskLow},
		{"policy block list", 1030002, true, "policy-1030002", CatReputation, RiskHigh},
		{"virtual patch signature", 5123456, true, "vpatch-5123456", CatVirtualPatch, RiskMedium},
		{"base body parse failure", 200002, true, "crs-200002", CatProtocol, RiskMedium},
		{"base multipart strict failure", 200003, true, "crs-200003", CatEvasion, RiskMedium},
		{"base argument limit", 200005, true, "crs-200005", CatProtocol, RiskMedium},
		{"above the base range", 201000, false, "", 0, 0},
		{"bot policy fake search engine", 5005011, true, "bots-5005011", CatBot, RiskMedium},
		{"bot policy AI crawler", 5005003, true, "bots-5005003", CatBot, RiskLow},
		{"unused carnical range", 5001000, false, "", 0, 0},
		{"below every range", 42, false, "", 0, 0},
	}
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			e, ok := Lookup(tt.id)
			if ok != tt.ok || e.Risk != tt.risk || tt.cat != 0 && !e.Categories.Has(tt.cat) || ok && e.Name == "" {
				t.Fatalf("Lookup(%d) = %+v, %v", tt.id, e, ok)
			}
			if strings.Contains(e.Name, "libinjection") != (tt.id == 942100) {
				t.Fatalf("Lookup(%d) name %q", tt.id, e.Name)
			}
			if s := Signature(tt.id); s != tt.sig {
				t.Fatalf("Signature(%d) = %q, want %q", tt.id, s, tt.sig)
			}
		})
	}

	sigs := []struct {
		sig  string
		want bool
	}{
		{"crs-942100", true},
		{"crs-5006001", true},
		{"carnical-5000070", true},
		{"formats-5002103", true},
		{"apiguard-5003113", true},
		{"shield-5004001", true},
		{"bots-5005003", true},
		{"bots-5004001", false}, // a shield id under the bots prefix
		{"policy-1050007", true},
		{"crs-200009", true},
		{"crs-199999", false},
		{"vpatch-CS-CVE-2024-4577-1", true},
		{"crs-5000010", false},     // a proxy id under the CRS prefix
		{"carnical-942100", false}, // and the other way round
		{"crs-0942100", false},
		{"crs-+942100", false},
		{"crs-", false},
		{"sqli", false},
		{"vpatch-", false},
		{"vpatch-a b", false},
		{"vpatch-" + strings.Repeat("a", MaxSig), false},
	}
	for _, tt := range sigs {
		t.Run("signature "+tt.sig, func(t *testing.T) {
			if got := ValidSignature(tt.sig); got != tt.want {
				t.Fatalf("ValidSignature(%q) = %v, want %v", tt.sig, got, tt.want)
			}
		})
	}
	t.Run("virtual patch signature is cut and cleaned", func(t *testing.T) {
		s := VPatchSignature("FW-XSS 1\n" + strings.Repeat("x", 100))
		if len(s) != MaxSig || !strings.HasPrefix(s, "vpatch-FW-XSS_1_x") || !ValidSignature(s) {
			t.Fatalf("VPatchSignature = %q", s)
		}
	})
}

// clock is a test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// collect is a sink that keeps what it is sent.
type collect struct {
	mu   sync.Mutex
	recs []Record
}

func (c *collect) Send(r Record) { c.mu.Lock(); c.recs = append(c.recs, r); c.mu.Unlock() }

func (c *collect) of(k Kind) []Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Record
	for _, r := range c.recs {
		if r.Kind == k {
			out = append(out, r)
		}
	}
	return out
}

func (c *collect) count(k Kind) uint64 {
	var n uint64
	for _, r := range c.of(k) {
		n += r.Alert.Count
	}
	return n
}

var (
	srcA = netip.MustParseAddr("192.0.2.10")
	srcB = netip.MustParseAddr("198.51.100.7")
)

// finding is a high-risk CRS block from src.
func finding(src netip.Addr, id int, cat Category, action Action, risk Risk) Alert {
	return Alert{ID: "0123456789abcdef", Layer: LayerCRS, RuleID: id, Sig: Signature(id), Categories: Of(cat),
		Risk: risk, Action: action, Mode: ModeBlock, Status: 403, Src: src, Method: "GET", Path: "/search",
		MatchPath: "/search"}
}

func TestAggregator(t *testing.T) {
	sqli := func(src netip.Addr) Alert { return finding(src, 942100, CatSQLi, Blocked, RiskHigh) }
	tests := []struct {
		name string
		cfg  Config
		run  func(t *testing.T, g *Aggregator, c *clock, out *collect)
	}{
		{"first alert at once, repeats counted and written when the window closes", Config{}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			for range 5 {
				g.Observe(sqli(srcA))
				c.add(time.Second)
			}
			if a := out.of(KindAlert); len(a) != 1 || a[0].Alert.Count != 1 || a[0].Alert.MatchPath != "" {
				t.Fatalf("first alerts: %+v", a)
			}
			g.Tick()
			if r := out.of(KindRepeated); len(r) != 0 {
				t.Fatalf("repeats written before the window closed: %+v", r)
			}
			c.add(DefaultWindow)
			g.Tick()
			r := out.of(KindRepeated)
			if len(r) != 1 || r[0].Alert.Count != 4 || !r[0].Alert.Last.After(r[0].Alert.First) {
				t.Fatalf("repeats: %+v", r)
			}
			g.Observe(sqli(srcA)) // a new window starts with a new first alert
			if a := out.of(KindAlert); len(a) != 2 {
				t.Fatalf("after the window: %d first alerts", len(a))
			}
		}},
		{"another source, signature or action is another alert", Config{}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			g.Observe(sqli(srcA))
			g.Observe(sqli(srcB))
			g.Observe(finding(srcA, 941100, CatXSS, Blocked, RiskHigh))
			g.Observe(finding(srcA, 942100, CatSQLi, WouldBlock, RiskHigh))
			g.Observe(sqli(srcA))
			if a := out.of(KindAlert); len(a) != 4 {
				t.Fatalf("%d first alerts, want 4", len(a))
			}
		}},
		{"with the source off, one alert per signature", Config{Source: SourceOff}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			g.Observe(sqli(srcA))
			g.Observe(sqli(srcB))
			if a := out.of(KindAlert); len(a) != 1 || a[0].Alert.Src.IsValid() {
				t.Fatalf("first alerts: %+v, want 1 without a source", a)
			}
		}},
		{"a window that closed before a tick is flushed by the next finding", Config{}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			for range 3 {
				g.Observe(sqli(srcA))
			}
			c.add(DefaultWindow)
			g.Observe(sqli(srcA))
			if r := out.of(KindRepeated); len(r) != 1 || r[0].Alert.Count != 2 {
				t.Fatalf("repeats: %+v", r)
			}
			if a := out.of(KindAlert); len(a) != 2 {
				t.Fatalf("%d first alerts, want 2", len(a))
			}
		}},
		{"eviction from a full table loses no repeat", Config{Table: MinTable, Rate: MaxRate, Window: MaxWindow}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			const sources = 5000
			for i := range sources {
				src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
				g.Observe(sqli(src))
				g.Observe(sqli(src))
				c.add(time.Millisecond) // the limiter refills: this row is about the table
			}
			if out.count(KindRepeated) == 0 {
				t.Fatal("no entry was evicted from a table smaller than the sources")
			}
			g.Close()
			if n := out.count(KindRepeated); n != sources {
				t.Fatalf("repeats written: %d, want %d", n, sources)
			}
		}},
		{"repeats the limiter refuses are still counted, by signature", Config{}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			const sources = 300
			for i := range sources {
				src := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
				g.Observe(sqli(src))
				g.Observe(sqli(src))
			}
			c.add(DefaultWindow) // every window closes at once: 300 repeat lines against a burst of 200
			g.Tick()
			var unwritten uint64
			for _, d := range out.of(KindDropped) {
				unwritten += d.Dropped.Repeats
				var bySig uint64
				for _, u := range d.Unwritten {
					if u.Sig != "crs-942100" || u.Action != Blocked {
						t.Fatalf("unwritten repeats of %+v", u)
					}
					bySig += u.N
				}
				if bySig != d.Dropped.Repeats {
					t.Fatalf("unwritten by signature %d, in all %d", bySig, d.Dropped.Repeats)
				}
			}
			if unwritten == 0 || out.count(KindRepeated)+unwritten != sources {
				t.Fatalf("repeats written %d and unwritten %d, want %d in all", out.count(KindRepeated), unwritten, sources)
			}
			if tot := g.Totals(); tot.Dropped.Repeats != unwritten {
				t.Fatalf("totals count %d unwritten repeats, want %d", tot.Dropped.Repeats, unwritten)
			}
		}},
		{"the final drops and totals get through a queue the open repeats overflow", Config{}, func(t *testing.T, _ *Aggregator, c *clock, _ *collect) {
			held := &gate{got: make(chan Record, 4096), open: make(chan struct{})}
			q := NewAsync(held, 64)
			g, err := NewAggregator(Config{Sink: q, Now: c.now, Rate: MaxRate, Window: MaxWindow})
			if err != nil {
				t.Fatal(err)
			}
			const sources = 500
			for i := range sources {
				src := netip.AddrFrom4([4]byte{10, 2, byte(i >> 8), byte(i)})
				g.Observe(sqli(src))
				g.Observe(sqli(src))
				c.add(time.Millisecond)
			}
			g.Close() // the sink holds the first record: the first alerts fill the queue, every repeat overflows it
			close(held.open)
			if !q.Close(5 * time.Second) {
				t.Fatal("the queue did not drain")
			}
			close(held.got)
			var repeated, unwritten, queue uint64
			totals := 0
			for r := range held.got {
				switch r.Kind {
				case KindRepeated:
					repeated += r.Alert.Count
				case KindDropped:
					unwritten += r.Dropped.Repeats
					queue += r.Dropped.Queue
				case KindTotals:
					totals++
				}
			}
			if totals != 1 || queue == 0 || repeated+unwritten != sources {
				t.Fatalf("final totals lines %d, queue drops reported %d, repeats written %d and unwritten %d of %d",
					totals, queue, repeated, unwritten, sources)
			}
		}},
		{"high risk is served before low when the limiter is short", Config{Rate: 1}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			// Rate 1: a burst of 10, 8 for high and medium, 2 shared. Low comes first and still cannot take the 8.
			for i := range 20 {
				g.Observe(finding(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 920350, CatProtocol, Detected, RiskLow))
			}
			for i := range 20 {
				g.Observe(sqli(netip.AddrFrom4([4]byte{10, 0, 1, byte(i)})))
			}
			high, low := 0, 0
			for _, r := range out.of(KindAlert) {
				if r.Alert.Risk == RiskHigh {
					high++
				} else {
					low++
				}
			}
			if high != 8 || low != 2 {
				t.Fatalf("written: %d high, %d low; want 8 and 2", high, low)
			}
			c.add(time.Second)
			g.Tick()
			d := out.of(KindDropped)
			if len(d) != 1 || d[0].Dropped.High != 12 || d[0].Dropped.Low != 18 {
				t.Fatalf("drops reported: %+v", d)
			}
			if tot := g.Totals(); tot.Get(LayerCRS, Blocked, RiskHigh) != 20 || tot.Get(LayerCRS, Detected, RiskLow) != 20 {
				t.Fatalf("totals are not exact: %+v", tot.Counts)
			}
			g.Tick()
			if d := out.of(KindDropped); len(d) != 1 {
				t.Fatalf("drops reported again with nothing new: %d", len(d))
			}
		}},
		{"high risk takes the shared tokens when it comes first", Config{Rate: 1}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			for i := range 20 {
				g.Observe(sqli(netip.AddrFrom4([4]byte{10, 0, 1, byte(i)})))
			}
			for i := range 20 {
				g.Observe(finding(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 920350, CatProtocol, Detected, RiskLow))
			}
			if a := out.of(KindAlert); len(a) != 10 || a[9].Alert.Risk != RiskHigh {
				t.Fatalf("written: %d, want the 10 high ones", len(a))
			}
		}},
		{"high risk uses its own tier before the shared one", Config{Rate: 1}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			for i := range 8 {
				g.Observe(sqli(netip.AddrFrom4([4]byte{10, 0, 1, byte(i)})))
			}
			for i := range 20 {
				g.Observe(finding(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 920350, CatProtocol, Detected, RiskLow))
			}
			if a := out.of(KindAlert); len(a) != 10 || a[9].Alert.Risk != RiskLow {
				t.Fatalf("written: %d, want 8 high and the 2 low ones the shared tier holds", len(a))
			}
		}},
		{"refused requests are counted by the kind of client, bots and people apart", Config{}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			by := func(src netip.Addr, client Client, action Action) Alert {
				a := finding(src, 942100, CatSQLi, action, RiskHigh)
				a.Client, a.Refusal = client, true
				return a
			}
			second := by(srcA, ClientAI, Blocked)
			second.Refusal = false
			g.Observe(second) // another alert of a request already counted
			g.Observe(by(srcA, ClientAI, Blocked))
			g.Observe(by(srcA, ClientAI, RateLimited))
			g.Observe(by(srcB, ClientTool, SourceBlocked))
			g.Observe(by(srcB, ClientFake, Blocked))
			g.Observe(by(netip.MustParseAddr("2001:db8:1:2::1"), ClientPerson, Blocked))
			g.Observe(by(netip.MustParseAddr("2001:db8:1:2::2"), ClientPerson, Blocked)) // the same /64: one source
			g.Observe(by(srcA, ClientPerson, WouldBlock))                                // let through: not refused
			g.Observe(by(srcA, ClientPerson, Detected))
			g.Observe(by(srcB, 0, Blocked)) // its client was not read
			tot := g.Totals()
			if tot.RefusedBots() != 4 || tot.RefusedPeople() != 2 || tot.BotSources != 2 || tot.PeopleSources != 1 {
				t.Fatalf("bots %d from %d, people %d from %d; want 4 from 2, 2 from 1", tot.RefusedBots(), tot.BotSources,
					tot.RefusedPeople(), tot.PeopleSources)
			}
			want := []ClientCount{{ClientPerson, 2}, {ClientAI, 2}, {ClientTool, 1}, {ClientFake, 1}}
			if !reflect.DeepEqual(tot.Refused, want) {
				t.Fatalf("refused by client %+v, want %+v", tot.Refused, want)
			}
			// Many sources are estimated, within a few percent.
			for i := range 5000 {
				g.Observe(by(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), ClientPerson, Blocked))
			}
			if n := g.Totals().PeopleSources; n < 4850 || n > 5150 {
				t.Fatalf("5001 people sources estimated as %d", n)
			}
		}},
		{"below the minimum risk is counted only", Config{MinRisk: RiskMedium}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			g.Observe(finding(srcA, 920350, CatProtocol, Detected, RiskLow))
			g.Observe(Alert{Layer: LayerCRS, Sig: "crs-942100", Risk: RiskHigh, Action: ClientClosed, Src: srcA})
			if len(out.of(KindAlert)) != 0 {
				t.Fatal("a finding below the minimum risk or a closed client was written")
			}
			tot := g.Totals()
			if tot.BelowMinRisk != 1 || tot.Get(LayerCRS, Detected, RiskLow) != 1 || tot.Get(LayerCRS, ClientClosed, RiskHigh) != 1 {
				t.Fatalf("totals: %+v", tot)
			}
			g.Observe(sqli(srcA))
			if len(out.of(KindAlert)) != 1 {
				t.Fatal("a finding at the minimum risk was not written")
			}
		}},
		{"suppression and excluded sources only silence", Config{
			Suppress: []Suppression{{Sig: "crs-942100", PathPrefix: "/search"}, {Sig: "crs-941100", Until: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}},
			Exclude:  []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			g.Observe(sqli(srcA)) // /search: suppressed
			sub := sqli(srcA)
			sub.MatchPath = "/search/deep"
			g.Observe(sub) // under it: suppressed
			other := sqli(srcA)
			other.MatchPath, other.Path = "/searchx", "/searchx"
			g.Observe(other)                                               // not under it by segment: written
			g.Observe(finding(srcA, 941100, CatXSS, Blocked, RiskHigh))    // expired: written
			g.Observe(finding(srcB, 932100, CatRCE, Blocked, RiskHigh))    // excluded source
			g.Observe(finding(srcA, 930100, CatLFI, WouldBlock, RiskHigh)) // not suppressed
			if a := out.of(KindAlert); len(a) != 3 {
				t.Fatalf("%d alerts written, want 3", len(a))
			}
			if tot := g.Totals(); tot.Suppressed != 3 || tot.Get(LayerCRS, Blocked, RiskHigh) != 5 {
				t.Fatalf("totals: suppressed %d, blocked %d", tot.Suppressed, tot.Get(LayerCRS, Blocked, RiskHigh))
			}
		}},
		{"a path-scoped suppression does not cover a path that is not in plain form", Config{
			Suppress: []Suppression{{Sig: "crs-942100", PathPrefix: "/search"}},
		}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			for i, p := range []string{"/search/../admin/login", "/search/..%2fadmin", "/search//../../admin", "/search/.",
				"/search\\..\\admin", "/search;/../admin", "/search/x"} {
				a := sqli(netip.AddrFrom4([4]byte{10, 3, 0, byte(i)}))
				a.MatchPath = p
				g.Observe(a)
			}
			if a := out.of(KindAlert); len(a) != 6 {
				t.Fatalf("%d alerts written, want the 6 not in plain form", len(a))
			}
			if tot := g.Totals(); tot.Suppressed != 1 {
				t.Fatalf("suppressed %d, want only /search/x", tot.Suppressed)
			}
		}},
		{"an alert repeated line names only what its repeats share", Config{}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			v6 := netip.MustParseAddr("2001:db8:1:2::10")
			first := finding(v6, 949110, CatSQLi, Blocked, RiskHigh)
			first.ID, first.Path, first.Host, first.Score, first.Threshold, first.Rules = "aaaaaaaaaaaaaaaa", "/login", "a.example", 5, 5, []int{942100}
			g.Observe(first)
			for i := range 4 {
				r := finding(netip.MustParseAddr("2001:db8:1:2::"+strconv.Itoa(20+i)), 949110, []Category{CatXSS, CatRCE}[i%2], Blocked, RiskHigh)
				r.ID, r.Path, r.Host, r.Status, r.Score, r.Threshold, r.Rules = "bbbbbbbbbbbbbbb"+strconv.Itoa(i), "/admin", "b.example", 400, 40, 5, []int{941100}
				g.Observe(r)
			}
			c.add(DefaultWindow)
			g.Tick()
			r := out.of(KindRepeated)
			if len(r) != 1 {
				t.Fatalf("repeats: %+v", r)
			}
			a := r[0].Alert
			if a.Count != 4 || a.Sig != "crs-949110" || a.Action != Blocked || a.Src != SourceKey(v6) || a.Categories != Of(CatXSS, CatRCE) {
				t.Fatalf("repeated: %+v", a)
			}
			if a.ID != "" || a.Path != "" || a.Host != "" || a.Method != "" || a.Status != 0 || a.Score != 0 || a.Threshold != 0 || a.Rules != nil {
				t.Fatalf("repeated carries one request's details: %+v", a)
			}
			if e, ok := FeedEvent(r[0]); !ok || e.ID != "" || e.Status != nil || e.Score != nil || e.IP != "2001:db8:1:2::" {
				t.Fatalf("feed of the repeats: %+v", e)
			}
			if a := out.of(KindAlert)[0].Alert; a.ID != "aaaaaaaaaaaaaaaa" || a.Path != "/login" || a.Score != 5 {
				t.Fatalf("first alert lost its own details: %+v", a)
			}
		}},
		{"a suspected intrusion the limiter refused is written on the next finding", Config{Rate: 1}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			// Rate 1: the limiter holds 10 lines. Thirty other sources, each suspected, take them all.
			for i := range 30 {
				src := netip.AddrFrom4([4]byte{10, 4, 0, byte(i)})
				g.Observe(finding(src, 913100, CatScanner, WouldBlock, RiskHigh))
				g.Observe(finding(src, 942100, CatSQLi, WouldBlock, RiskHigh))
			}
			mine := func() int {
				n := 0
				for _, s := range out.of(KindSuspected) {
					if s.Alert.Src == srcA {
						n++
					}
				}
				return n
			}
			g.Observe(finding(srcA, 913100, CatScanner, WouldBlock, RiskHigh))
			g.Observe(finding(srcA, 942100, CatSQLi, WouldBlock, RiskHigh))
			if mine() != 0 {
				t.Fatal("the limiter was not empty: this row is about a refused line")
			}
			c.add(time.Minute)
			g.Observe(finding(srcA, 932100, CatRCE, WouldBlock, RiskHigh))
			if mine() != 1 {
				t.Fatalf("suspected intrusion for srcA: %d lines, want 1", mine())
			}
			g.Observe(finding(srcA, 930100, CatLFI, WouldBlock, RiskHigh))
			if mine() != 1 {
				t.Fatal("suspected again within the hour once written")
			}
		}},
		{"three attack categories from one source are a suspected intrusion, once an hour", Config{}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			g.Observe(finding(srcA, 942100, CatSQLi, Detected, RiskLow))
			g.Observe(finding(srcA, 941100, CatXSS, Detected, RiskLow))
			g.Observe(finding(srcB, 930100, CatLFI, Detected, RiskLow)) // another source
			g.Observe(finding(srcA, 920350, CatProtocol, Detected, RiskLow))
			if s := out.of(KindSuspected); len(s) != 0 {
				t.Fatalf("suspected after two attack categories: %+v", s)
			}
			g.Observe(finding(srcA, 930100, CatLFI, Detected, RiskLow))
			g.Observe(finding(srcA, 932100, CatRCE, Detected, RiskLow))
			s := out.of(KindSuspected)
			if len(s) != 1 || s[0].Alert.Src != srcA || s[0].Alert.Risk != RiskHigh || s[0].Alert.Categories.Len() != 3 {
				t.Fatalf("suspected: %+v", s)
			}
			c.add(30 * time.Minute)
			for _, cat := range []Category{CatSQLi, CatXSS, CatLFI} {
				g.Observe(finding(srcA, 942100, cat, Detected, RiskLow))
			}
			if s := out.of(KindSuspected); len(s) != 1 {
				t.Fatalf("suspected again within the hour: %d", len(s))
			}
			c.add(time.Hour)
			for _, cat := range []Category{CatSQLi, CatXSS, CatLFI} {
				g.Observe(finding(srcA, 942100, cat, Detected, RiskLow))
			}
			if s := out.of(KindSuspected); len(s) != 2 {
				t.Fatalf("not suspected again after the hour: %d", len(s))
			}
		}},
		{"a scanner with an attack is a suspected intrusion", Config{}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			g.Observe(finding(srcA, 913100, CatScanner, Detected, RiskLow))
			g.Observe(finding(srcA, 920350, CatProtocol, Detected, RiskLow))
			if len(out.of(KindSuspected)) != 0 {
				t.Fatal("a scanner alone is suspected")
			}
			g.Observe(finding(srcA, 942100, CatSQLi, WouldBlock, RiskHigh))
			if len(out.of(KindSuspected)) != 1 {
				t.Fatal("a scanner with an attack is not suspected")
			}
		}},
		{"ten refused findings are a suspected intrusion, nine are not", Config{}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			for range 9 {
				g.Observe(sqli(srcA))
			}
			g.Observe(finding(srcA, 942100, CatSQLi, Detected, RiskLow))
			if len(out.of(KindSuspected)) != 0 {
				t.Fatal("suspected after nine refused findings")
			}
			c.add(11 * time.Minute) // a new correlation window starts from zero
			for range 9 {
				g.Observe(sqli(srcA))
			}
			if len(out.of(KindSuspected)) != 0 {
				t.Fatal("findings of an old window were counted")
			}
			g.Observe(sqli(srcA))
			if len(out.of(KindSuspected)) != 1 {
				t.Fatal("not suspected after ten refused findings")
			}
		}},
		{"an IPv6 source rotating /64s in one /48 is a suspected intrusion of the network", Config{SummaryInterval: 5 * time.Minute}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			one := netip.MustParseAddr("2001:db8:9:1::1") // three categories from one /64: that /64 alone is named
			for _, cat := range []Category{CatSQLi, CatXSS, CatRCE} {
				g.Observe(finding(one, 942100, cat, Detected, RiskLow))
			}
			if s := out.of(KindSuspected); len(s) != 1 || s[0].Alert.Net.IsValid() || s[0].Alert.Src != one {
				t.Fatalf("suspected from one /64: %+v", s)
			}
			cats := []Category{CatSQLi, CatXSS, CatRCE, CatLFI}
			for n := range 40 {
				src := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, byte(n), 15: 1})
				g.Observe(finding(src, 942100, cats[n%len(cats)], Blocked, RiskHigh))
			}
			s := out.of(KindSuspected)
			if len(s) != 2 || s[1].Alert.Net != netip.MustParsePrefix("2001:db8:1::/48") {
				t.Fatalf("suspected from one /48 rotating /64s: %+v", s)
			}
			c.add(5 * time.Minute)
			g.Tick()
			sum := out.of(KindSummary)
			if len(sum) != 1 || sum[0].Sources[0].Net != netip.MustParsePrefix("2001:db8:1::/48") || sum[0].Sources[0].Blocked != 40 {
				t.Fatalf("summary: %+v", sum)
			}
		}},
		{"a decoy hit is a suspected intrusion", Config{}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			g.Observe(finding(srcA, 5000080, CatDecoy, Blocked, RiskHigh))
			if s := out.of(KindSuspected); len(s) != 1 || s[0].Alert.Note == "" {
				t.Fatalf("suspected: %+v", s)
			}
		}},
		{"totals are exact, written when something changed and always at close", Config{TotalsInterval: time.Minute}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			a := sqli(srcA)
			a.RuleID, a.Sig, a.Rules = 949110, "crs-949110", []int{942100, 942190}
			for range 3 {
				g.Observe(a)
			}
			g.Observe(finding(srcB, 920350, CatProtocol, Detected, RiskInfo))
			c.add(time.Minute)
			g.Tick()
			tt := out.of(KindTotals)
			if len(tt) != 1 {
				t.Fatalf("%d totals lines, want 1", len(tt))
			}
			tot := tt[0].Totals
			if tot.Get(LayerCRS, Blocked, RiskHigh) != 3 || tot.Get(LayerCRS, Detected, RiskInfo) != 1 ||
				tot.Rule(949110) != 3 || tot.Rule(942190) != 3 || tot.Rule(920350) != 1 || tot.Rule(942100) != 3 {
				t.Fatalf("totals: %+v", tot)
			}
			c.add(time.Minute)
			g.Tick()
			if n := len(out.of(KindTotals)); n != 1 {
				t.Fatalf("totals written with nothing new: %d lines", n)
			}
			g.Close()
			if n := len(out.of(KindTotals)); n != 2 {
				t.Fatalf("no final totals at close: %d lines", n)
			}
		}},
		{"the summary lists the busiest sources first, and only those active", Config{SummaryInterval: 5 * time.Minute}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			g.Observe(sqli(srcA))
			for range 3 {
				g.Observe(finding(srcB, 941100, CatXSS, WouldBlock, RiskHigh))
			}
			g.Observe(finding(netip.MustParseAddr("203.0.113.5"), 920350, CatProtocol, Detected, RiskLow))
			c.add(5 * time.Minute)
			g.Tick()
			s := out.of(KindSummary)
			if len(s) != 1 || len(s[0].Sources) != 2 || s[0].Sources[0].Src != srcB || s[0].Sources[0].WouldBlock != 3 ||
				s[0].Sources[1].Src != srcA || s[0].Sources[1].Blocked != 1 {
				t.Fatalf("summary: %+v", s)
			}
			c.add(5 * time.Minute)
			g.Tick()
			if s := out.of(KindSummary); len(s) != 1 {
				t.Fatalf("a summary of a quiet period was written: %d", len(s))
			}
		}},
		{"with the source off, no record names a source", Config{Source: SourceOff, SummaryInterval: time.Minute}, func(t *testing.T, g *Aggregator, c *clock, out *collect) {
			for range 10 {
				g.Observe(sqli(srcA))
			}
			c.add(time.Minute)
			g.Tick()
			g.Close()
			out.mu.Lock()
			defer out.mu.Unlock()
			for _, r := range out.recs {
				if r.Alert.Src.IsValid() || len(r.Sources) > 0 {
					t.Fatalf("a record names the source: %+v", r)
				}
			}
			if len(out.recs) == 0 {
				t.Fatal("nothing written")
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &clock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
			out := &collect{}
			cfg := tt.cfg
			cfg.Sink, cfg.Now = out, c.now
			g, err := NewAggregator(cfg)
			if err != nil {
				t.Fatal(err)
			}
			tt.run(t, g, c, out)
		})
	}

	bad := []struct {
		name string
		cfg  Config
	}{
		{"no sink", Config{}},
		{"table too small", Config{Sink: &collect{}, Table: MinTable - 1}},
		{"rate too high", Config{Sink: &collect{}, Rate: MaxRate + 1}},
		{"window too short", Config{Sink: &collect{}, Window: time.Second}},
		{"negative interval", Config{Sink: &collect{}, TotalsInterval: -time.Second}},
	}
	for _, tt := range bad {
		t.Run("refused: "+tt.name, func(t *testing.T) {
			if _, err := NewAggregator(tt.cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestSuppressionParsing(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		in      []string
		want    []Suppression
		expired []bool
		err     string
	}{
		{"signature only", []string{"crs-920350"}, []Suppression{{Sig: "crs-920350"}}, []bool{false}, ""},
		{"path, date and note", []string{"crs-942100 /search until=2026-12-31 note=search box, reviewed"},
			[]Suppression{{Sig: "crs-942100", PathPrefix: "/search", Until: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), Note: "search box, reviewed"}},
			[]bool{false}, ""},
		{"several separated by semicolons", []string{"crs-920350; ;carnical-5000043 /api", "vpatch-CS-1"},
			[]Suppression{{Sig: "crs-920350"}, {Sig: "carnical-5000043", PathPrefix: "/api"}, {Sig: "vpatch-CS-1"}},
			[]bool{false, false, false}, ""},
		{"expired is kept and reported expired", []string{"crs-920350 until=2026-10-15"},
			[]Suppression{{Sig: "crs-920350", Until: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)}}, []bool{true}, ""},
		{"applies through its last day", []string{"crs-920350 until=2026-10-16"},
			[]Suppression{{Sig: "crs-920350", Until: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)}}, []bool{false}, ""},
		{"unknown signature form", []string{"sqli /x"}, nil, nil, "not one carnical writes"},
		{"id outside its prefix's range", []string{"crs-5000010"}, nil, nil, "not one carnical writes"},
		{"bad date", []string{"crs-920350 until=31/12/2026"}, nil, nil, "YYYY-MM-DD"},
		{"two paths", []string{"crs-920350 /a /b"}, nil, nil, "more than one path"},
		{"unknown key", []string{"crs-920350 for=1d"}, nil, nil, "expected a path"},
		{"empty note", []string{"crs-920350 note="}, nil, nil, "note= is empty"},
		{"control character in the note", []string{"crs-920350 note=a\x1bb"}, nil, nil, "printable"},
		{"non-ASCII note of exactly the limit", []string{"crs-920350 note=" + strings.Repeat("a", MaxNote-2) + "é"},
			[]Suppression{{Sig: "crs-920350", Note: strings.Repeat("a", MaxNote-2) + "é"}}, []bool{false}, ""},
		{"path prefix not in plain form", []string{"crs-920350 /search/../admin"}, nil, nil, "plain form"},
		{"path prefix with an escape", []string{"crs-920350 /search%2f"}, nil, nil, "plain form"},
		{"duplicate", []string{"crs-920350 /a; crs-920350 /a"}, nil, nil, "given twice"},
		{"too many", []string{strings.Repeat("crs-920350;", 1) + suppressMany(MaxSuppressions)}, nil, nil, "more than 256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSuppressions(tt.in)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("error %v, want one containing %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] || got[i].Expired(now) != tt.expired[i] {
					t.Fatalf("entry %d: %+v (expired %v), want %+v (expired %v)", i, got[i], got[i].Expired(now), tt.want[i], tt.expired[i])
				}
				if again, err := ParseSuppression(got[i].String()); err != nil || again != got[i] {
					t.Fatalf("entry %d does not read back from %q: %+v, %v", i, got[i].String(), again, err)
				}
			}
		})
	}

	sources := []struct {
		name string
		in   []string
		want []string
		err  string
	}{
		{"addresses and networks", []string{"192.0.2.1, 198.51.100.0/24", "2001:db8::/48 2001:db8:1::1"},
			[]string{"192.0.2.1/32", "198.51.100.0/24", "2001:db8::/48", "2001:db8:1::1/128"}, ""},
		{"masked", []string{"10.1.2.3/16"}, []string{"10.1.0.0/16"}, ""},
		{"IPv4-mapped read as IPv4", []string{"::ffff:192.0.2.0/120"}, []string{"192.0.2.0/24"}, ""},
		{"IPv4 wider than /16", []string{"10.0.0.0/15"}, nil, "wider than a /16"},
		{"everything", []string{"0.0.0.0/0"}, nil, "wider than a /16"},
		{"IPv6 wider than /32", []string{"2001:db8::/31"}, nil, "wider than a /32"},
		{"IPv4-mapped wider than /16", []string{"::ffff:10.0.0.0/104"}, nil, "wider than a /16"},
		{"not an address", []string{"example.com"}, nil, "CIDR"},
		{"zone", []string{"fe80::1%eth0"}, nil, "zone"},
		{"too many", []string{strings.Repeat("192.0.2.1,", MaxExcludeSources+1)}, nil, "more than 256"},
	}
	for _, tt := range sources {
		t.Run("exclude "+tt.name, func(t *testing.T) {
			got, err := ParseExcludeSources(tt.in)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("error %v, want one containing %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var s []string
			for _, p := range got {
				s = append(s, p.String())
			}
			if strings.Join(s, " ") != strings.Join(tt.want, " ") {
				t.Fatalf("got %v, want %v", s, tt.want)
			}
		})
	}
}

func suppressMany(n int) string {
	var b strings.Builder
	for i := range n {
		b.WriteString("crs-920350 /p" + strconv.Itoa(i) + ";")
	}
	return b.String()
}

// gate is a sink that holds every record until it is opened.
type gate struct {
	got  chan Record
	open chan struct{}
}

func (g *gate) Send(r Record) { g.got <- r; <-g.open }

func TestSinks(t *testing.T) {
	t.Run("async never blocks, counts drops and flushes at close", func(t *testing.T) {
		g := &gate{got: make(chan Record, 16), open: make(chan struct{})}
		q := NewAsync(g, 2)
		q.Send(Record{Kind: KindAlert})
		<-g.got // the drain goroutine holds the first; the queue is empty
		for range 3 {
			q.Send(Record{Kind: KindAlert}) // two fit, one is dropped
		}
		if q.Dropped() != 1 {
			t.Fatalf("dropped %d, want 1", q.Dropped())
		}
		close(g.open)
		if !q.Close(time.Second) {
			t.Fatal("close did not flush")
		}
		if len(g.got) != 2 {
			t.Fatalf("%d queued records delivered at close, want 2", len(g.got))
		}
		q.Send(Record{Kind: KindAlert})
		if q.Dropped() != 2 {
			t.Fatalf("a record sent after close was not counted: %d", q.Dropped())
		}
	})
	t.Run("async close is bounded by its timeout and counts what it left", func(t *testing.T) {
		g := &gate{got: make(chan Record, 16), open: make(chan struct{})}
		defer close(g.open)
		q := NewAsync(g, 4)
		q.Send(Record{Kind: KindAlert})
		<-g.got
		for range 3 {
			q.Send(Record{Kind: KindAlert})
		}
		start := time.Now()
		if q.Close(50*time.Millisecond) || time.Since(start) > time.Second {
			t.Fatal("close waited on a stuck sink")
		}
		if q.Dropped() != 3 {
			t.Fatalf("dropped %d, want the 3 left queued", q.Dropped())
		}
	})

	a := finding(netip.MustParseAddr("2001:db8:1:2:3::9"), 949110, CatSQLi, Blocked, RiskHigh)
	a.Rules, a.Score, a.Threshold, a.MatchPath, a.Count = []int{942100}, 10, 5, "/search?q=secret", 1
	a.First, a.Last = time.Unix(1, 0), time.Unix(2, 0)
	v4 := a
	v4.Src = srcA
	network := a
	network.Net = SourceNet(a.Src)
	withClient := a
	withClient.Client = ClientFake
	dropped := Record{Kind: KindDropped, Dropped: Drops{High: 2, Repeats: 7},
		Unwritten: []SigCount{{Sig: "crs-942100", Action: Blocked, N: 7}}}
	logs := []struct {
		name string
		mode SourceMode
		rec  Record
		want map[string]any
		not  []string
	}{
		{"full source", SourceFull, Record{Kind: KindAlert, Alert: a}, map[string]any{"msg": "intrusion blocked", "level": "WARN",
			"src": "2001:db8:1:2:3::9", "src_key": "2001:db8:1:2::", "sig": "crs-949110", "action": "blocked", "risk": "high",
			"score": 10.0}, []string{"secret"}},
		{"prefix source", SourcePrefix, Record{Kind: KindAlert, Alert: a}, map[string]any{"src": "2001:db8:1::/48"},
			[]string{"secret", "3::9", "2001:db8:1:2", "src_key"}},
		{"prefix source IPv4", SourcePrefix, Record{Kind: KindAlert, Alert: v4}, map[string]any{"src": "192.0.2.0/24"},
			[]string{"192.0.2.10", "src_key"}},
		{"no source", SourceOff, Record{Kind: KindAlert, Alert: a}, map[string]any{"sig": "crs-949110"}, []string{"secret", "src", "2001:db8"}},
		{"network", SourceFull, Record{Kind: KindSuspected, Alert: network}, map[string]any{"src_net": "2001:db8:1::/48"}, []string{"src_key"}},
		{"network with the source off", SourceOff, Record{Kind: KindSuspected, Alert: network}, map[string]any{"msg": "suspected intrusion"},
			[]string{"src", "2001:db8"}},
		{"repeats name no status", SourceFull, Record{Kind: KindRepeated, Alert: a}, map[string]any{"msg": "alert repeated"},
			[]string{`"status"`}},
		{"client", SourceFull, Record{Kind: KindAlert, Alert: withClient}, map[string]any{"client": "fake"}, nil},
		{"no client read", SourceFull, Record{Kind: KindAlert, Alert: a}, map[string]any{"sig": "crs-949110"}, []string{`"client"`}},
		{"totals count blocked bots and people", SourceFull, Record{Kind: KindTotals, Totals: &Totals{BotSources: 2, PeopleSources: 1,
			Refused: []ClientCount{{ClientPerson, 3}, {ClientAI, 4}, {ClientFake, 1}}}}, map[string]any{"blocked_bots": 5.0,
			"blocked_people": 3.0, "blocked_bot_sources": 2.0, "blocked_people_sources": 1.0,
			"blocked_by_client": map[string]any{"person": 3.0, "ai": 4.0, "fake": 1.0}}, nil},
		{"unwritten repeats", SourceFull, dropped, map[string]any{"msg": "alerts dropped", "count": 2.0, "repeats_unwritten": 7.0,
			"repeats_unwritten_by_sig": map[string]any{"crs-942100/blocked": 7.0}}, nil},
	}
	for _, tt := range logs {
		t.Run("log "+tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			NewLogSink(slog.New(slog.NewJSONHandler(&buf, nil)), tt.mode).Send(tt.rec)
			var got map[string]any
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("%v: %s", err, buf.String())
			}
			for k, v := range tt.want {
				if !reflect.DeepEqual(got[k], v) {
					t.Fatalf("%s = %v, want %v in %s", k, got[k], v, buf.String())
				}
			}
			for _, s := range tt.not {
				if strings.Contains(buf.String(), s) {
					t.Fatalf("%q in %s", s, buf.String())
				}
			}
		})
	}

	feeds := []struct {
		name string
		rec  Record
		kind string
		ok   bool
	}{
		{"block", Record{Kind: KindAlert, Alert: a}, "block", true},
		{"would block", Record{Kind: KindRepeated, Alert: Alert{Action: WouldBlock, Risk: RiskMedium, Sig: "formats-5002103", Count: 4}}, "would_block", true},
		{"suspected", Record{Kind: KindSuspected, Alert: Alert{Action: Detected, Risk: RiskHigh}}, "campaign", true},
		{"repeats have no incident id", Record{Kind: KindRepeated, Alert: a}, "block", true},
		{"client closed is not an event", Record{Kind: KindAlert, Alert: Alert{Action: ClientClosed}}, "", false},
		{"totals are not an event", Record{Kind: KindTotals, Totals: &Totals{}}, "", false},
	}
	for _, tt := range feeds {
		t.Run("feed "+tt.name, func(t *testing.T) {
			e, ok := FeedEvent(tt.rec)
			if ok != tt.ok || e.Kind != tt.kind {
				t.Fatalf("FeedEvent = %+v, %v", e, ok)
			}
			if tt.name == "block" && (e.ID != "0123456789AB" || len(e.Sigs) != 2 || e.Sigs[0].ID != "CRS-949110" ||
				e.Sigs[1].ID != "CRS-942100" || e.Sev != "high" || e.IP != "2001:db8:1:2:3::9" || *e.Score != 10) {
				t.Fatalf("FeedEvent = %+v", e)
			}
			if tt.name == "repeats have no incident id" && (e.ID != "" || e.N == nil) {
				t.Fatalf("FeedEvent = %+v", e)
			}
			if tt.name == "would block" && (e.N == nil || *e.N != 4 || e.Sev != "medium") {
				t.Fatalf("FeedEvent = %+v", e)
			}
		})
	}
}
