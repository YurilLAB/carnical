// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"hash/maphash"
	"math"
	"math/bits"
	"net/netip"
	"sync/atomic"
)

// Client is what kind of client sent a request, as package bots reads it from what the request says about itself
// (ADR-0087). The totals count refused requests by it, so that an operator can tell how many bots and how many people
// were refused.
type Client uint8

// The kinds of client. Every kind from ClientSearch on is a bot.
const (
	// ClientPerson is a browser, or an app on a phone, that showed no sign of automation. It is the client software's
	// claim: a bot that copies a browser's headers exactly is counted here.
	ClientPerson Client = iota + 1
	// ClientSearch is a search engine's crawler, by its user agent; package bots can check its address by DNS.
	ClientSearch
	// ClientAI is a crawler or fetcher of an AI company: training data, AI search, or an assistant fetching for a user.
	ClientAI
	// ClientSEO is an SEO, marketing or data-mining crawler.
	ClientSEO
	// ClientTool is an HTTP library, command-line tool or scraping framework that kept its own user agent.
	ClientTool
	// ClientHeadless is a browser driven by a program: headless Chrome, PhantomJS and the like.
	ClientHeadless
	// ClientScanner is a vulnerability scanner or an internet-wide scanning service.
	ClientScanner
	// ClientPreview is a link-preview fetcher of a chat or social site.
	ClientPreview
	// ClientMonitor is an uptime or health check.
	ClientMonitor
	// ClientBot is a bot that names no known program: no user agent, a contact URL, a crawler word, or a browser's
	// user agent without the headers every browser sends.
	ClientBot
	// ClientFake is a client that claims to be a search engine's crawler from an address its DNS does not confirm.
	ClientFake

	numClients = int(ClientFake) + 1
)

var clientNames = [numClients]string{"", "person", "search", "ai", "seo", "tool", "headless", "scanner", "preview", "monitor", "bot", "fake"}

func (c Client) String() string {
	if int(c) < numClients {
		return clientNames[c]
	}
	return ""
}

// IsBot reports whether the client is a bot of any kind.
func (c Client) IsBot() bool { return c >= ClientSearch && int(c) < numClients }

// ParseClient reads a client kind's name.
func ParseClient(s string) (Client, bool) {
	for i := 1; i < numClients; i++ {
		if clientNames[i] == s {
			return Client(i), true
		}
	}
	return 0, false
}

// distinctBits sets the size of a distinct counter: 2^12 registers, a standard error of about 1.6%, and close to exact
// below a few hundred.
const distinctBits = 12

// distinct estimates how many different sources it was given (HyperLogLog, with linear counting for small numbers), in
// a fixed 16 KiB whatever the number. It is safe for concurrent use without a lock.
type distinct struct {
	reg [1 << distinctBits]atomic.Uint32
}

func (d *distinct) add(seed maphash.Seed, a netip.Addr) {
	b := SourceKey(a).As16()
	h := maphash.Bytes(seed, b[:])
	i := h >> (64 - distinctBits)
	rank := uint32(bits.LeadingZeros64(h<<distinctBits|1<<(distinctBits-1))) + 1 // #nosec G115 -- LeadingZeros64 is 0 to 64.
	r := &d.reg[i]
	for {
		old := r.Load()
		if rank <= old || r.CompareAndSwap(old, rank) {
			return
		}
	}
}

func (d *distinct) count() uint64 {
	const m = float64(len(d.reg))
	sum, zeros := 0.0, 0
	for i := range d.reg {
		v := d.reg[i].Load()
		if v == 0 {
			zeros++
		}
		sum += math.Ldexp(1, -int(v))
	}
	if zeros == len(d.reg) {
		return 0
	}
	e := 0.7213 / (1 + 1.079/m) * m * m / sum
	if e <= 2.5*m && zeros > 0 {
		e = m * math.Log(m/float64(zeros))
	}
	return uint64(math.Round(e))
}
