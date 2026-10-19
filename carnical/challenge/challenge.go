// SPDX-License-Identifier: Apache-2.0

// Package challenge is where a check that a visitor is a person plugs into the proxy: a page that asks for a tick, or
// some other proof, before a request goes on. Carnical has no such check of its own beyond the shield's work challenge
// (package shield); this package only says how one is called and what it is told.
//
// The proxy calls a Gate, when Config.Challenge names one, at two points of a request:
//
//   - Admission: the shield would show its own challenge, or refuse a stranger over an attack's budget. The request has
//     been read no further, and the request policy has not run. A ban, an address or network over its own rate, and a
//     kind of client the bot policy refuses are never offered to the gate.
//   - Request: the request passed the shield, the bot policy and the site's request policy, and is about to be read and
//     inspected. Every such request is offered; the gate decides which need the check.
//
// The gate either answers the request itself (shows its page, takes its answer), or lets it go on. When it decides
// about a visitor it says so first, through report, so that the proxy can alert on a refusal and admit a person past
// the shield.
package challenge

import (
	"net/http"
	"net/netip"

	"github.com/YurilLAB/coraza/carnical/alert"
)

// Point is where in a request the gate is called.
type Point uint8

// The points.
const (
	// Admission: the shield would show its challenge, or refuse a stranger over an attack's budget.
	Admission Point = iota + 1
	// Request: the request passed the shield, the bot policy and the request policy.
	Request
)

// Signals is what the proxy knows about the visitor when it calls the gate. None of it is request data the gate could
// not read itself; it is what the other layers concluded.
type Signals struct {
	// Point is where the gate is called.
	Point Point
	// Client is the visitor's address, as the proxy worked it out (through trusted proxies).
	Client netip.Addr
	// Kind is what kind of client the request says it is (package bots), and Watched says the bot policy reports that
	// kind as one it would refuse. At Admission the bot policy has not run: Kind is what the request's headers say,
	// without the policy's check of a search engine's address.
	Kind    alert.Client
	Watched bool
	// Attack says the shield is defending against an attack now. Known says the shield knows the visitor's address from
	// ordinary use before (a standing earned by requests the application answered well; the gate's own answers earn
	// none), and Strikes is how many refusals the address has had in the current attack. All three are false or 0
	// without a shield.
	Attack  bool
	Known   bool
	Strikes int
	// Relayed says a trusted proxy relayed the request, whose own address carries other visitors too.
	Relayed bool
}

// Verdict is what a gate decided about a visitor.
type Verdict uint8

// The verdicts.
const (
	// Shown: the check was put to the visitor, who has not answered yet.
	Shown Verdict = iota + 1
	// Passed: the visitor answered as a person. With a shield, the proxy admits the visitor's browser, from that
	// address, past an attack's budgets for a while, as the shield's own challenge does.
	Passed
	// Refused: the gate refused the visitor. The proxy alerts on it. At Admission the shield has already counted the
	// refusal it would have made, and nothing more is counted.
	Refused
)

// Outcome is a decision and why.
type Outcome struct {
	Verdict Verdict
	// Score is the gate's risk score, 0 to 100, for the alert.
	Score int
	// Reason is why, for the alert's message: a short fixed text of the gate's, never request data. The proxy keeps up
	// to 64 bytes of letters, digits, spaces and "-+:,." and drops the rest.
	Reason string
}

// Gate is a check that a visitor is a person.
type Gate interface {
	// Serve is offered a request and what the proxy knows about its visitor. It reports whether it answered the request
	// (the check's page, its answer), which then goes no further; false lets the request go on, and at Admission leaves
	// the shield's own answer to stand; a gate that wrote anything has answered, whatever it returns. Before it writes
	// an answer that carries a decision, it calls report with it, once: the proxy may set headers on w from it, and
	// ignores a second report or one made after Serve returned. The body of r is held to the site's body limit; read it
	// only for a request the gate answers. Serve runs on the request's goroutine, for every request that reaches its
	// point, so it must be quick for the requests it lets go on.
	Serve(w http.ResponseWriter, r *http.Request, s Signals, report func(Outcome)) bool
}

// Responder is a Gate that also sees the header of each response the application gives, before the proxy forwards it.
// A site can say in a header that a visitor proved to be a person (signed in with a second factor, paid), which a check
// can learn from; the check should remove such a header, which is not for the visitor. r is the request as the visitor
// sent it, after the proxy's checks; h is the response's header, which Respond may change. It runs on the request's
// goroutine and must be quick.
type Responder interface {
	Respond(r *http.Request, status int, h http.Header)
}
