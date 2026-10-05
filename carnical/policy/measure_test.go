// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"

	"github.com/YurilLAB/coraza/carnical/crs"
)

// The cost of the largest policy a customer can write, measured and bounded, so that a change that makes compiling or loading it
// slow is noticed. The bounds are loose (a slow machine, the race detector); the numbers are in the log and in the documentation.
func TestTheLargestPolicyIsCheapToDecodeCompileAndLoad(t *testing.T) {
	p := largestPolicy()
	enc, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) > MaxPolicyBytes {
		t.Fatalf("the largest policy is %d bytes, over the %d the decoder reads", len(enc), MaxPolicyBytes)
	}
	start := time.Now()
	if _, err := Decode(enc); err != nil {
		t.Fatal(err)
	}
	decode := time.Since(start)
	start = time.Now()
	c, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	compile := time.Since(start)
	lines := strings.Count(c.CRS.Before, "\n") + 1
	longest := 0
	for _, l := range strings.Split(c.CRS.Before, "\n") {
		longest = max(longest, len(l))
	}
	if longest > MaxLineBytes {
		t.Fatalf("a line of %d bytes", longest)
	}
	// Reserved range and no duplicates.
	ids := map[int]bool{}
	for _, l := range strings.Split(c.CRS.Before, "\n") {
		var id int
		i := strings.Index(l, ` "id:`)
		if i < 0 {
			t.Fatalf("no id in %.60s", l)
		}
		fmt.Sscanf(l[i+5:], "%d", &id)
		if id < idBase || id > idLimit || ids[id] {
			t.Fatalf("rule id %d is outside %d-%d or used twice", id, idBase, idLimit)
		}
		ids[id] = true
	}
	directives, _ := c.CRS.Directives()
	start = time.Now()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS()).WithDirectives(directives))
	if err != nil {
		t.Fatal(err)
	}
	load := time.Since(start)
	n := waf.(experimental.WAFWithRules).RulesCount()
	waf.(experimental.WAFCloser).Close()
	base, _ := Compile(Default())
	bd, _ := base.CRS.Directives()
	start = time.Now()
	w2, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS()).WithDirectives(bd))
	if err != nil {
		t.Fatal(err)
	}
	baseLoad := time.Since(start)
	n2 := w2.(experimental.WAFWithRules).RulesCount()
	w2.(experimental.WAFCloser).Close()
	t.Logf("the largest policy: %d bytes of JSON, decoded in %s, compiled in %s to %d rules (%d lines of SecLang, %d bytes, longest line %d); the engine loads it with the Core Rule Set in %s (%d rules) against %s (%d rules) for Default",
		len(enc), decode, compile, len(ids), lines, len(c.CRS.Before), longest, load, n, baseLoad, n2)
	if decode > 2*time.Second || compile > 2*time.Second || load > 30*time.Second {
		t.Fatalf("too slow: decode %s, compile %s, load %s", decode, compile, load)
	}
}

// What the paranoia level costs, for the choice of the sensitivity presets: the time to evaluate ordinary requests at each level,
// and with the detection level one above the blocking level, which the presets leave off.
func TestWhatTheParanoiaLevelCosts(t *testing.T) {
	if testing.Short() {
		t.Skip("a measurement")
	}
	type variant struct {
		name      string
		pl, dpl   int
		threshold int
	}
	variants := []variant{{"paranoia 1", 1, 0, 5}, {"paranoia 2", 2, 0, 5}, {"paranoia 1, detection 2", 1, 2, 5}, {"paranoia 3", 3, 0, 5}}
	requests := []struct {
		method, uri, ct, body string
	}{
		{"GET", "/", "", ""},
		{"GET", "/search?q=blue+widgets+for+sale&page=2&sort=price", "", ""},
		{"POST", "/login", "application/x-www-form-urlencoded", "user=alice&pass=correct+horse+battery+staple&remember=1"},
		{"POST", "/api/items", "application/json", `{"name":"Alice","items":[1,2,3],"note":"hello world","address":{"street":"1 Main St","city":"Cairns"}}`},
		{"GET", "/assets/app.css?v=3", "", ""},
		{"GET", "/product/12345/reviews?lang=en&limit=20", "", ""},
	}
	const rounds = 150
	var base time.Duration
	for _, v := range variants {
		s := crs.DefaultSettings()
		s.ParanoiaLevel, s.DetectionParanoiaLevel, s.InboundThreshold = v.pl, v.dpl, v.threshold
		d, err := s.Directives()
		if err != nil {
			t.Fatal(err)
		}
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS()).WithDirectives(d))
		if err != nil {
			t.Fatal(err)
		}
		run := func() time.Duration {
			start := time.Now()
			for i := 0; i < rounds; i++ {
				for _, r := range requests {
					tx := waf.NewTransaction()
					tx.ProcessConnection("203.0.113.7", 1234, "", 0)
					tx.ProcessURI(r.uri, r.method, "HTTP/1.1")
					tx.AddRequestHeader("Host", "shop.example.test")
					tx.AddRequestHeader("User-Agent", browser)
					tx.AddRequestHeader("Accept", "text/html")
					if r.ct != "" {
						tx.AddRequestHeader("Content-Type", r.ct)
						tx.AddRequestHeader("Content-Length", fmt.Sprint(len(r.body)))
					}
					tx.ProcessRequestHeaders()
					if r.body != "" {
						tx.WriteRequestBody([]byte(r.body))
					}
					tx.ProcessRequestBody()
					tx.Close()
				}
			}
			return time.Since(start)
		}
		run() // warm up
		took := run()
		per := took / (rounds * time.Duration(len(requests)))
		if base == 0 {
			base = per
		}
		t.Logf("%-26s %8s per request (%.2fx paranoia 1)", v.name, per, float64(per)/float64(base))
		waf.(experimental.WAFCloser).Close()
	}
}
