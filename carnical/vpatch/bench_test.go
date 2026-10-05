// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"runtime"
	"testing"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// corpusRequests returns the requests of the replay corpus, or skips the test.
func corpusRequests(t testing.TB, name, kind string) []*inspect.Request {
	t.Helper()
	smp := readSamplesFile(t, corpusPath(t, name), kind)
	out := make([]*inspect.Request, len(smp))
	for i := range smp {
		out[i] = smp[i].Request
	}
	return out
}

func loadedEngine(t testing.TB, tiers []string) *Engine {
	t.Helper()
	e := New(Options{Tiers: tiers})
	e.Load(library(t))
	return e
}

func benchMatch(b *testing.B, tiers []string, corpus, kind string) {
	e := loadedEngine(b, tiers)
	reqs := corpusRequests(b, corpus, kind)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Match(reqs[i%len(reqs)])
	}
}

// The numbers in docs/vpatch.md come from these, with every tier (the whole library, 8,005 signatures) loaded.
func BenchmarkMatchBenignAllTiers(b *testing.B) { benchMatch(b, allTiers, "benign.jsonl", "benign") }
func BenchmarkMatchAttackAllTiers(b *testing.B) { benchMatch(b, allTiers, "attack.jsonl", "attack") }
func BenchmarkMatchBenignVerified(b *testing.B) {
	benchMatch(b, []string{TierVerified}, "benign.jsonl", "benign")
}
func BenchmarkMatchAttackVerified(b *testing.B) {
	benchMatch(b, []string{TierVerified}, "attack.jsonl", "attack")
}

func BenchmarkInspectBenignAllTiers(b *testing.B) {
	e := loadedEngine(b, allTiers)
	reqs := corpusRequests(b, "benign.jsonl", "benign")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Inspect(reqs[i%len(reqs)])
	}
}

func BenchmarkMatchParallelBenign(b *testing.B) {
	e := loadedEngine(b, allTiers)
	reqs := corpusRequests(b, "benign.jsonl", "benign")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = e.Match(reqs[i%len(reqs)])
			i++
		}
	})
}

// BenchmarkBruteForceBenign is what evaluating every signature costs, for the comparison with the index.
func BenchmarkBruteForceBenign(b *testing.B) {
	e := loadedEngine(b, allTiers)
	reqs := corpusRequests(b, "benign.jsonl", "benign")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.MatchBruteForce(reqs[i%len(reqs)])
	}
}

func BenchmarkLoadAllTiers(b *testing.B) {
	sigs := library(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := New(Options{Tiers: allTiers})
		e.Load(sigs)
	}
}

// TestMemoryOfLoadedLibrary measures the heap the loaded engine holds, after a collection, with all tiers and with the verified
// tier alone.
func TestMemoryOfLoadedLibrary(t *testing.T) {
	sigs := library(t)
	heap := func() uint64 {
		var m runtime.MemStats
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	for _, tc := range []struct {
		name  string
		tiers []string
	}{{"verified", []string{TierVerified}}, {"all tiers", allTiers}} {
		before := heap()
		e := New(Options{Tiers: tc.tiers})
		rep := e.Load(sigs)
		after := heap()
		t.Logf("%s: %d signatures, %d literals: heap %.1f MiB (load took %v)", tc.name, rep.LoadedTotal, rep.Literals, float64(after-before)/(1<<20), rep.Elapsed)
		runtime.KeepAlive(e)
	}
}
