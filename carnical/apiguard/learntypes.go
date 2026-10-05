// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"errors"
)

// What the guard learns, and the evidence it needs before it believes it.
//
// The rule is the one that keeps an attacker from teaching the model that an attack is normal. A route, a parameter, a property
// or a value is enforceable only when it has been seen at least MinObservations times, from at least MinClients different
// clients, and no one client accounts for more than MaxClientShare of the sightings. An attacker with one address cannot reach
// the third condition at all, and one with a few cannot reach the second: it takes MinClients and enough more that none of them is
// over the share, all of them getting an answer below 400 from the application.
//
// Evidence is kept in a fixed amount of space per item, by the Space-Saving method: a short list of clients with their counts,
// and when it is full a new client takes the place of the one with the fewest sightings and inherits its count. The counts are
// never below the truth, so the share that is computed is never below the truth either: every error makes the guard slower to
// trust, never quicker.

// maxSlots is how many clients one piece of evidence follows.
const maxSlots = 16

// ClientSlot is one client's count in an Evidence.
type ClientSlot struct {
	C uint32 `json:"c"` // an identifier made from the client's address prefix with a key that belongs to this guard
	N uint32 `json:"n"`
}

// Evidence is how often something was seen, and by whom.
type Evidence struct {
	N     uint32       `json:"n"`
	OK    bool         `json:"ok,omitempty"` // once true, stays true
	Slots []ClientSlot `json:"slots,omitempty"`
}

// evRule is the evidence a piece of learned knowledge needs.
type evRule struct {
	minObs     uint32
	minClients int
	maxShare   uint32 // percent
}

// trustedClients is how many separate clients an owner-supplied recording stands for. The owner is vouching for it, so it counts as
// full evidence, spread so that no one of them is over the share.
const trustedClients = 6

// add records weight sightings by a client and reports whether the evidence just became enough.
func (e *Evidence) add(client uint32, w uint32, r *evRule) (flipped bool) {
	if e.N > 1<<30 {
		// Halve everything so counts cannot overflow; the shares, which is what matters, stay the same.
		e.N = 0
		for i := range e.Slots {
			e.Slots[i].N >>= 1
			e.N += e.Slots[i].N
		}
	}
	e.N += w
	found := false
	for i := range e.Slots {
		if e.Slots[i].C == client {
			e.Slots[i].N += w
			found = true
			break
		}
	}
	if !found {
		if len(e.Slots) < maxSlots {
			e.Slots = append(e.Slots, ClientSlot{client, w})
		} else {
			lo := 0
			for i := range e.Slots {
				if e.Slots[i].N < e.Slots[lo].N {
					lo = i
				}
			}
			e.Slots[lo] = ClientSlot{client, e.Slots[lo].N + w}
		}
	}
	if !e.OK && e.supported(r) {
		e.OK = true
		return true
	}
	return false
}

// addTrusted records sightings that an owner vouches for: enough to be enforceable at once, as if from several clients.
func (e *Evidence) addTrusted(r *evRule) (flipped bool) {
	per := (r.minObs + trustedClients - 1) / trustedClients
	for k := uint32(0); k < trustedClients; k++ {
		if e.add(0xFFFF0000|k, per, r) {
			flipped = true
		}
	}
	return flipped
}

// supported reports whether the evidence is enough under the rule right now.
func (e *Evidence) supported(r *evRule) bool {
	if e.N < r.minObs || len(e.Slots) < r.minClients {
		return false
	}
	var top uint32
	for _, s := range e.Slots {
		top = max(top, s.N)
	}
	return uint64(top)*100 <= uint64(r.maxShare)*uint64(e.N)
}

func (e *Evidence) clone() *Evidence {
	if e == nil {
		return nil
	}
	c := *e
	c.Slots = append([]ClientSlot(nil), e.Slots...)
	return &c
}

func (e *Evidence) validate() error {
	if e == nil {
		return nil
	}
	if len(e.Slots) > maxSlots {
		return errors.New("the saved model has evidence with too many clients")
	}
	return nil
}

// pclass is the kind of value a text parameter held. Each is narrower than the one after it that includes it.
type pclass uint8

const (
	pcInt pclass = iota
	pcNum
	pcBool
	pcUUID
	pcDate
	pcStr
	pcEmpty
	nClasses
)

var pclassNames = [nClasses]string{"int", "number", "bool", "uuid", "date", "string", "empty"}

// maxEnumValues is how many distinct values of one parameter are followed to see whether it is an enumeration.
const maxEnumValues = 8

// ParamStat is what was seen of one query parameter of a route.
type ParamStat struct {
	Seen Evidence `json:"seen"`
	// Classes holds, for each kind of value, the evidence that this parameter takes values of that kind.
	Classes map[string]*Evidence `json:"classes,omitempty"`
	// Values holds the evidence for each value, while the parameter has taken at most maxEnumValues different ones. A parameter
	// that takes only a few values is an enumeration. After that Overflow is set and the values are forgotten.
	Values   map[string]*Evidence `json:"values,omitempty"`
	Overflow bool                 `json:"overflow,omitempty"`
	// IntMin and IntMax are the range of the integer values seen. They are recorded for the owner and not enforced: one client
	// can widen a range, and the evidence rule has nothing to say about a number.
	IntMin int64 `json:"intMin,omitempty"`
	IntMax int64 `json:"intMax,omitempty"`
	LenMax int   `json:"lenMax,omitempty"`
}

// Shape is what was seen at one place in a JSON body.
type Shape struct {
	Seen Evidence `json:"seen"`
	// Types holds, for each JSON type, the evidence that the value there had that type (indexed by jtype).
	Types [tNTypes]*Evidence `json:"types"`
	// ObjN is how many objects were seen here, which a property's count is compared with to say whether it is required.
	ObjN  uint32            `json:"objN,omitempty"`
	Props map[string]*Shape `json:"props,omitempty"`
	Items *Shape            `json:"items,omitempty"`
	// Open means more different property names were seen than are followed, so unknown properties are not refused here.
	Open bool `json:"open,omitempty"`
}

// LearnedRoute is everything learned about one route.
type LearnedRoute struct {
	Obs   uint32 `json:"obs"` // sightings; an owner-supplied recording counts as several
	First int64  `json:"first"`
	Last  int64  `json:"last"`
	// Ev is the evidence for the route itself.
	Ev Evidence `json:"ev"`
	// Bodies counts the sightings that had a JSON body, and BodyEv is the evidence for having any body at all.
	Bodies uint32                `json:"bodies,omitempty"`
	BodyEv Evidence              `json:"bodyEv"`
	Query  map[string]*ParamStat `json:"query,omitempty"`
	CTypes map[string]*Evidence  `json:"ctypes,omitempty"`
	Body   *Shape                `json:"body,omitempty"`
}

const (
	maxShapeDepth   = 8
	maxShapeProps   = 64
	maxQueryParams  = 32
	maxCTypes       = 8
	maxLearnedNodes = 20_000
)

func (l *LearnedRoute) validate(nodes *int) error {
	if err := l.Ev.validate(); err != nil {
		return err
	}
	if err := l.BodyEv.validate(); err != nil {
		return err
	}
	if len(l.Query) > maxQueryParams || len(l.CTypes) > maxCTypes {
		return errors.New("the saved model has a learned route with too many parameters")
	}
	for _, p := range l.Query {
		if p == nil {
			return errors.New("the saved model has an empty parameter record")
		}
		if err := p.Seen.validate(); err != nil {
			return err
		}
		if len(p.Classes) > int(nClasses) || len(p.Values) > maxEnumValues {
			return errors.New("the saved model has a parameter with too many classes or values")
		}
		for name, e := range p.Classes {
			if e == nil || !validClassName(name) {
				return errors.New("the saved model has an unknown parameter class")
			}
			if err := e.validate(); err != nil {
				return err
			}
		}
		for _, e := range p.Values {
			if e == nil {
				return errors.New("the saved model has an empty value record")
			}
			if err := e.validate(); err != nil {
				return err
			}
		}
	}
	for _, e := range l.CTypes {
		if e == nil {
			return errors.New("the saved model has an empty content-type record")
		}
		if err := e.validate(); err != nil {
			return err
		}
	}
	return l.Body.validate(0, nodes)
}

func validClassName(n string) bool {
	for _, c := range pclassNames {
		if c == n {
			return true
		}
	}
	return false
}

func (s *Shape) validate(depth int, nodes *int) error {
	if s == nil {
		return nil
	}
	if *nodes++; *nodes > maxSchemaNodes {
		return errors.New("the saved model is too large")
	}
	if depth > maxShapeDepth {
		return errors.New("the saved model has a learned body nested too deeply")
	}
	if len(s.Props) > maxShapeProps {
		return errors.New("the saved model has a learned object with too many properties")
	}
	if err := s.Seen.validate(); err != nil {
		return err
	}
	for _, e := range s.Types {
		if err := e.validate(); err != nil {
			return err
		}
	}
	for _, p := range s.Props {
		if p == nil {
			return errors.New("the saved model has an empty property record")
		}
		if err := p.validate(depth+1, nodes); err != nil {
			return err
		}
	}
	return s.Items.validate(depth+1, nodes)
}

// count returns how many nodes the shape holds, for the memory limit.
func (s *Shape) count() int {
	if s == nil {
		return 0
	}
	n := 1
	for _, p := range s.Props {
		n += p.count()
	}
	return n + s.Items.count()
}

func (s *Shape) clone() *Shape {
	if s == nil {
		return nil
	}
	c := &Shape{Seen: *s.Seen.clone(), ObjN: s.ObjN, Open: s.Open, Items: s.Items.clone()}
	for i, e := range s.Types {
		c.Types[i] = e.clone()
	}
	if s.Props != nil {
		c.Props = make(map[string]*Shape, len(s.Props))
		for k, p := range s.Props {
			c.Props[k] = p.clone()
		}
	}
	return c
}

func (p *ParamStat) clone() *ParamStat {
	c := &ParamStat{Seen: *p.Seen.clone(), Overflow: p.Overflow, IntMin: p.IntMin, IntMax: p.IntMax, LenMax: p.LenMax}
	if p.Classes != nil {
		c.Classes = make(map[string]*Evidence, len(p.Classes))
		for k, e := range p.Classes {
			c.Classes[k] = e.clone()
		}
	}
	if p.Values != nil {
		c.Values = make(map[string]*Evidence, len(p.Values))
		for k, e := range p.Values {
			c.Values[k] = e.clone()
		}
	}
	return c
}

func (l *LearnedRoute) clone() *LearnedRoute {
	c := &LearnedRoute{Obs: l.Obs, First: l.First, Last: l.Last, Ev: *l.Ev.clone(), Bodies: l.Bodies, BodyEv: *l.BodyEv.clone(), Body: l.Body.clone()}
	if l.Query != nil {
		c.Query = make(map[string]*ParamStat, len(l.Query))
		for k, p := range l.Query {
			c.Query[k] = p.clone()
		}
	}
	if l.CTypes != nil {
		c.CTypes = make(map[string]*Evidence, len(l.CTypes))
		for k, e := range l.CTypes {
			c.CTypes[k] = e.clone()
		}
	}
	return c
}
