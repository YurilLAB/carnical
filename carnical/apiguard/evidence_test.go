// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"slices"
	"testing"
)

var testRule = evRule{minObs: 30, minClients: 3, maxShare: 20}

// feed adds counts[i] sightings from client i+1 in an order that spreads each client evenly through the whole stream, as steady
// traffic does. (Evidence that is enough stays enough, so a client that only turns up after the crowd has been counted would not
// show what the rule says about a client that is heavy all along.)
func feed(counts ...int) *Evidence {
	type event struct {
		at     float64
		client uint32
	}
	var events []event
	for i, n := range counts {
		for k := 0; k < n; k++ {
			events = append(events, event{(float64(k) + 0.5) / float64(n), uint32(i + 1)})
		}
	}
	slices.SortStableFunc(events, func(a, b event) int {
		switch {
		case a.at < b.at:
			return -1
		case a.at > b.at:
			return 1
		}
		return int(a.client) - int(b.client)
	})
	e := &Evidence{}
	for _, ev := range events {
		e.add(ev.client, 1, &testRule)
	}
	return e
}

func TestTheEvidenceRule(t *testing.T) {
	rep := func(n, count int) []int {
		out := make([]int, n)
		for i := range out {
			out[i] = count
		}
		return out
	}
	tests := []struct {
		name   string
		counts []int
		want   bool
	}{
		{"one client, however often", []int{5000}, false},
		{"two clients", []int{500, 500}, false},
		{"three clients in equal shares is a third each", []int{10, 10, 10}, false},
		{"five clients in equal shares is exactly the limit", rep(5, 6), true},
		{"five clients, one a little over the share", []int{7, 6, 6, 6, 5}, false},
		{"one client over the share among many", append([]int{9}, rep(21, 1)...), false},
		{"twenty-nine sightings from many clients", rep(29, 1), false},
		{"thirty sightings from thirty clients", rep(30, 1), true},
		{"thirty sightings from ten clients", rep(10, 3), true},
		{"a client at a tenth among a crowd", append([]int{10}, rep(90, 1)...), true},
		{"a client at a third among a crowd", append([]int{33}, rep(67, 1)...), false},
		{"two clients at a tenth each and a crowd", append([]int{10, 10}, rep(80, 1)...), true},
		{"a hundred clients once each", rep(100, 1), true},
		{"four attackers sharing the evidence are four clients", rep(4, 100), false},
		{"five attackers sharing it equally are enough, which is the rule's limit", rep(5, 100), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := feed(tt.counts...)
			if e.OK != tt.want {
				t.Fatalf("OK = %v (N=%d, slots=%d), want %v", e.OK, e.N, len(e.Slots), tt.want)
			}
		})
	}
}

func TestEvidenceNeverUnderstatesAClientsShare(t *testing.T) {
	// More clients than slots: the Space-Saving counts may only be too high.
	e := &Evidence{}
	truth := map[uint32]uint32{}
	for round := 0; round < 40; round++ {
		for c := uint32(1); c <= 40; c++ {
			e.add(c, 1, &testRule)
			truth[c]++
		}
	}
	var sum uint32
	for _, s := range e.Slots {
		if s.N < truth[s.C] {
			t.Fatalf("client %d is counted %d times and was seen %d", s.C, s.N, truth[s.C])
		}
		sum += s.N
	}
	if len(e.Slots) != maxSlots || sum != e.N {
		t.Fatalf("slots %d, sum %d, N %d", len(e.Slots), sum, e.N)
	}
}

func TestEvidenceOnceEnoughStaysEnough(t *testing.T) {
	e := feed(rep30()...)
	if !e.OK {
		t.Fatal("not enough")
	}
	for i := 0; i < 10_000; i++ {
		e.add(1, 1, &testRule) // one client now dominates
	}
	if !e.OK {
		t.Fatal("evidence that was enough was taken back")
	}
}

func rep30() []int {
	out := make([]int, 30)
	for i := range out {
		out[i] = 1
	}
	return out
}

func TestOwnerSuppliedEvidenceCountsAtOnce(t *testing.T) {
	e := &Evidence{}
	if !e.addTrusted(&testRule) || !e.OK {
		t.Fatalf("a recording vouched for by the owner is not enough: %+v", e)
	}
	if e.N < testRule.minObs || len(e.Slots) < testRule.minClients {
		t.Fatalf("%+v", e)
	}
}

func TestEvidenceCountsDoNotOverflow(t *testing.T) {
	e := &Evidence{}
	for c := uint32(1); c <= 8; c++ {
		e.add(c, 1<<29, &testRule)
	}
	e.add(1, 1<<29, &testRule)
	e.add(2, 1<<29, &testRule)
	var sum uint32
	for _, s := range e.Slots {
		sum += s.N
	}
	if e.N > 1<<31 || sum != e.N {
		t.Fatalf("N %d, sum %d", e.N, sum)
	}
}
