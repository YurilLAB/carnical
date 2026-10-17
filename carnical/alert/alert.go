// SPDX-License-Identifier: Apache-2.0

// Package alert turns what carnical's layers find in requests into intrusion alerts an operator can act on: one record
// per request and signature that states the final verdict, deduplicated per source and signature, rate limited with
// high risk first, correlated per source into "suspected intrusion", and summed into exact totals that are never
// sampled (ADR-0084).
//
// The package holds no request content. An Alert carries the verified source, a method, a bounded host and a path the
// producer already reduced to a template or to its path without the query; it never carries a query string, a body, a
// header, a cookie, matched data or an expanded rule message. Every string that came from a visitor goes through Clean.
//
// It uses the standard library only and imports neither the proxy nor the shield, so both can feed it.
package alert

import (
	"net/netip"
	"time"
)

// Action is the final outcome of a request for one signature.
type Action uint8

// The actions. Their names are those of the log and of docs/proxy-reference.md.
const (
	// Blocked: carnical refused the request because of this finding.
	Blocked Action = iota + 1
	// WouldBlock: a detect or monitor setting found something its enforcing setting refuses; the request was forwarded.
	WouldBlock
	// Detected: a finding that would not refuse the request in either mode.
	Detected
	// NotInspected: inspection could not finish and the request was forwarded.
	NotInspected
	// RateLimited: refused with 429 by a rate rule or the shield's bucket.
	RateLimited
	// SourceBlocked: refused because the source is banned.
	SourceBlocked
	// ClientClosed: the client went away before inspection finished. Counted only, never written as an alert.
	ClientClosed

	numActions = int(ClientClosed) + 1
)

var actionNames = [numActions]string{"", "blocked", "would_block", "detected", "not_inspected", "rate_limited", "source_blocked", "client_closed"}

func (a Action) String() string {
	if int(a) < numActions {
		return actionNames[a]
	}
	return ""
}

// Refused reports whether the request was refused (the actions an IPS takes).
func (a Action) Refused() bool { return a == Blocked || a == RateLimited || a == SourceBlocked }

// Risk is one scale for every layer, UniFi's: info, low, medium, high.
type Risk uint8

// The risks, lowest first, so that they compare.
const (
	RiskInfo Risk = iota + 1
	RiskLow
	RiskMedium
	RiskHigh

	numRisks = int(RiskHigh) + 1
)

var riskNames = [numRisks]string{"", "info", "low", "medium", "high"}

func (r Risk) String() string {
	if int(r) < numRisks {
		return riskNames[r]
	}
	return ""
}

// ParseRisk reads info, low, medium or high.
func ParseRisk(s string) (Risk, bool) {
	for i := 1; i < numRisks; i++ {
		if riskNames[i] == s {
			return Risk(i), true
		}
	}
	return 0, false
}

// Layer is the part of carnical that produced a finding.
type Layer uint8

// The layers.
const (
	LayerProxy Layer = iota + 1
	LayerCrowdSec
	LayerShield
	LayerFormats
	LayerVPatch
	LayerAPIGuard
	LayerUpload
	LayerCRS
	LayerRate
	LayerAutoBlock
	LayerBots

	numLayers = int(LayerBots) + 1
)

var layerNames = [numLayers]string{"", "proxy", "crowdsec", "shield", "formats", "vpatch", "apiguard", "upload", "crs", "rate", "auto-block", "bots"}

func (l Layer) String() string {
	if int(l) < numLayers {
		return layerNames[l]
	}
	return ""
}

// Mode is the mode of the layer that produced a finding.
type Mode uint8

// The modes.
const (
	ModeBlock Mode = iota + 1
	ModeDetect
	ModeMonitor
	ModeOn
	ModeOff

	numModes = int(ModeOff) + 1
)

var modeNames = [numModes]string{"", "block", "detect", "monitor", "on", "off"}

func (m Mode) String() string {
	if int(m) < numModes {
		return modeNames[m]
	}
	return ""
}

// Category is one value of the closed category vocabulary.
type Category uint8

// The categories (docs/proxy-reference.md). They are derived from rule ids and static tags, never from request data.
const (
	CatScanner      Category = iota + 1 // CRS 913, scanner and probe paths
	CatProtocol                         // CRS 911, 920, 921, 922
	CatLFI                              // CRS 930
	CatRFI                              // CRS 931
	CatRCE                              // CRS 932
	CatPHP                              // CRS 933
	CatGeneric                          // CRS 934
	CatXSS                              // CRS 941
	CatSQLi                             // CRS 942
	CatSession                          // CRS 943
	CatJava                             // CRS 944
	CatDataLeak                         // CRS 950 to 956
	CatUpload                           // executable or script uploads
	CatWordPress                        // WordPress write directories, xmlrpc
	CatFormat                           // body and query format checks
	CatVirtualPatch                     // virtual-patch signatures
	CatAPIContract                      // API contract checks
	CatRate                             // rate rules
	CatFlood                            // flood protection
	CatReputation                       // CrowdSec, block lists, bans
	CatPolicy                           // site policy: host, headers, custom rules
	CatDecoy                            // decoy paths
	CatEvasion                          // path canonicalisation, method override, encodings
	CatInspection                       // inspection that could not finish
	CatBot                              // the bot policy: a kind of client the site refuses

	numCategories = int(CatBot) + 1
)

var categoryNames = [numCategories]string{"", "scanner", "protocol", "lfi", "rfi", "rce", "php", "generic", "xss", "sqli",
	"session", "java", "data-leak", "upload", "wordpress", "format", "virtual-patch", "api-contract", "rate", "flood",
	"reputation", "policy", "decoy", "evasion", "inspection", "bot"}

func (c Category) String() string {
	if int(c) < numCategories {
		return categoryNames[c]
	}
	return ""
}

// Categories is a set of categories.
type Categories uint32

// Of returns the set of the given categories.
func Of(cs ...Category) Categories {
	var s Categories
	for _, c := range cs {
		s = s.With(c)
	}
	return s
}

// With returns the set with c added.
func (s Categories) With(c Category) Categories {
	if c == 0 || int(c) >= numCategories {
		return s
	}
	return s | 1<<c
}

// Has reports whether c is in the set.
func (s Categories) Has(c Category) bool { return c != 0 && int(c) < numCategories && s&(1<<c) != 0 }

// Len is the number of categories in the set.
func (s Categories) Len() int {
	n := 0
	for c := 1; c < numCategories; c++ {
		if s&(1<<c) != 0 {
			n++
		}
	}
	return n
}

// Names lists the names of up to max categories in the set, in vocabulary order.
func (s Categories) Names(max int) []string {
	var out []string
	for c := 1; c < numCategories && len(out) < max; c++ {
		if s&(1<<c) != 0 {
			out = append(out, categoryNames[c])
		}
	}
	return out
}

// attack is the set of categories that count as an attack for correlation: a finding about what a request tried to do
// to the application, not about its shape, its rate or the source's reputation.
const attack = Categories(1<<CatLFI | 1<<CatRFI | 1<<CatRCE | 1<<CatPHP | 1<<CatGeneric | 1<<CatXSS | 1<<CatSQLi |
	1<<CatSession | 1<<CatJava | 1<<CatDataLeak | 1<<CatUpload | 1<<CatWordPress | 1<<CatVirtualPatch | 1<<CatDecoy |
	1<<CatEvasion)

// Attacks returns the attack categories in the set.
func (s Categories) Attacks() Categories { return s & attack }

// Limits of an Alert's fields.
const (
	MaxRules      = 8   // contributing rule ids
	MaxCategories = 4   // category names written
	MaxSig        = 64  // bytes of a signature
	MaxSigName    = 96  // bytes of a signature name
	MaxMethod     = 16  // bytes of a method
	MaxHost       = 64  // bytes of a host
	MaxPath       = 256 // bytes of a path
	MaxNote       = 128 // bytes of a note
	MaxSeverity   = 16  // bytes of a raw severity
)

// Alert is one finding about one request, or (for the records the Aggregator writes) about one source. The producer
// fills it; the Aggregator dedupes, limits and counts it and hands it to a Sink. Strings that came from a visitor must
// already be cleaned and bounded (Clean); Rules is kept, so the producer must not change it after handing the Alert on.
type Alert struct {
	ID          string // the request id: 16 lower-case hex characters, equal to the Coraza transaction id
	Layer       Layer
	RuleID      int    // the primary rule id, counted in the totals
	Sig         string // a stable signature: Signature(RuleID), or VPatchSignature
	SigName     string // a static name from the catalog, never an expanded message
	Rules       []int  // up to MaxRules contributing rule ids
	Categories  Categories
	Risk        Risk
	SeverityRaw string // the producer's own severity word
	Action      Action
	Mode        Mode
	Status      int // the status sent; 0 when the request was forwarded
	Score       int // CRS anomaly score, 0 when not a CRS verdict
	Threshold   int
	Client      Client     // the kind of client that sent the request (package bots); 0 when it was not read
	Src         netip.Addr // the verified client, never a port and never an unverified forwarded address
	ViaProxy    bool       // the address came through a trusted proxy
	// Net is the network a "suspected intrusion" names when the findings came from several /64s of one IPv6 /48; zero
	// on every other record.
	Net    netip.Prefix
	Method string
	Host   string
	Path   string // a template or the path without its query, as the operator chose; empty to leave it out
	// MatchPath is the request path without its query, used only to match a suppression's path prefix. It is never
	// written. The producer passes the decoded, canonical path; one that is not in plain form (a "." or ".." segment,
	// "//", '%', a backslash or ';') is never under a suppression's path prefix.
	MatchPath string
	Count     uint64 // 1 on a first alert; the repeats on an "alert repeated" record
	First     time.Time
	Last      time.Time
	Note      string // static text
}

// SourceKey is the key a source is counted under: an IPv4 address, or the /64 of an IPv6 address. The zero Addr stays
// zero.
func SourceKey(a netip.Addr) netip.Addr {
	if !a.IsValid() {
		return a
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}

// SourceNet is the network an alert shows with -alert-source prefix: the /24 of an IPv4 address or the /48 of an
// IPv6 one.
func SourceNet(a netip.Addr) netip.Prefix {
	if !a.IsValid() {
		return netip.Prefix{}
	}
	a = a.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
}

// SourceMode is what an alert shows of its source.
type SourceMode uint8

// The source modes of -alert-source.
const (
	SourceFull   SourceMode = iota // the address
	SourcePrefix                   // its /24 or /48
	SourceOff                      // nothing: dedupe is then per signature only and no record names a source
)

// ParseSourceMode reads full, prefix or off.
func ParseSourceMode(s string) (SourceMode, bool) {
	switch s {
	case "full":
		return SourceFull, true
	case "prefix":
		return SourcePrefix, true
	case "off":
		return SourceOff, true
	}
	return 0, false
}

// PathMode is what an alert shows of the request's path.
type PathMode uint8

// The path modes of -alert-path.
const (
	PathTemplate PathMode = iota // the path with its identifiers replaced: digits by 9, long tokens by x, at most 6 segments
	PathFull                     // the path as sent, without the query, at most MaxPath bytes
	PathOff                      // no path
)

// ParsePathMode reads template, full or off.
func ParsePathMode(s string) (PathMode, bool) {
	switch s {
	case "template":
		return PathTemplate, true
	case "full":
		return PathFull, true
	case "off":
		return PathOff, true
	}
	return 0, false
}
