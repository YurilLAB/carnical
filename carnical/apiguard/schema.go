// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"encoding/base64"
	"errors"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Schema is the part of JSON Schema that OpenAPI uses, held in a form that can be saved and loaded. The validator below is our own
// and bounded: it does not use any schema library for the decision, because a request is the input to be defended against and the
// schema may come from a server we do not control.
//
// Keywords that are not here (if/then/else, patternProperties, dependentRequired, unevaluated*, prefixItems) are ignored when a
// description is imported, which makes the schema more permissive, never stricter; the import report lists them.
type Schema struct {
	Type     []string `json:"type,omitempty"` // integer, number, string, boolean, object, array, null; empty means any
	Nullable bool     `json:"nullable,omitempty"`
	Format   string   `json:"format,omitempty"`

	Enum  []JSONValue `json:"enum,omitempty"`
	Const *JSONValue  `json:"const,omitempty"`

	Minimum          *float64 `json:"minimum,omitempty"`
	Maximum          *float64 `json:"maximum,omitempty"`
	ExclusiveMinimum *float64 `json:"exclusiveMinimum,omitempty"`
	ExclusiveMaximum *float64 `json:"exclusiveMaximum,omitempty"`
	MultipleOf       *float64 `json:"multipleOf,omitempty"`

	MinLength *int   `json:"minLength,omitempty"`
	MaxLength *int   `json:"maxLength,omitempty"`
	Pattern   string `json:"pattern,omitempty"` // RE2 only; anything the engine cannot run is dropped at import

	MinItems    *int `json:"minItems,omitempty"`
	MaxItems    *int `json:"maxItems,omitempty"`
	UniqueItems bool `json:"uniqueItems,omitempty"`

	MinProperties *int `json:"minProperties,omitempty"`
	MaxProperties *int `json:"maxProperties,omitempty"`

	Properties map[string]*Schema `json:"properties,omitempty"`
	Required   []string           `json:"required,omitempty"`
	// AdditionalProperties false means a property that is not listed is refused. AdditionalSchema constrains the value of one.
	AdditionalProperties *bool   `json:"additionalProperties,omitempty"`
	AdditionalSchema     *Schema `json:"additionalSchema,omitempty"`
	Items                *Schema `json:"items,omitempty"`

	OneOf []*Schema `json:"oneOf,omitempty"`
	AnyOf []*Schema `json:"anyOf,omitempty"`
	AllOf []*Schema `json:"allOf,omitempty"`
	Not   *Schema   `json:"not,omitempty"`

	// Ref names an entry of Model.Defs: a schema that refers back to itself (a tree, a thread of comments) is written once there and
	// pointed to from inside itself, so that it is checked to any depth the data has and can still be saved.
	Ref string `json:"$ref,omitempty"`

	// ReadOnly means the server sets the property: a client that sends it is trying to set what it must not (mass assignment).
	ReadOnly  bool `json:"readOnly,omitempty"`
	WriteOnly bool `json:"writeOnly,omitempty"`

	// Derived by prepare, never saved.
	ref       *Schema
	re        *regexp.Regexp
	enumV     []any
	constV    any
	propNames []string
	prepared  bool
}

// JSONValue holds a decoded JSON value inside a struct that is itself saved and loaded.
type JSONValue struct{ V any }

// MarshalJSON writes the value back the way it was read.
func (j JSONValue) MarshalJSON() ([]byte, error) { return appendJSON(nil, j.V, 0), nil }

// UnmarshalJSON reads one value with the same limits as a request body.
func (j *JSONValue) UnmarshalJSON(b []byte) error {
	v, _, err := parseJSON(b, jsonLimits{depth: 16, nodes: 10_000})
	if err != nil {
		return err
	}
	j.V = v
	return nil
}

// Limits on what a pattern may cost. A pattern is matched with Go's regexp package, which runs in time proportional to the
// subject times the size of the program, so the program is bounded here and the subject below.
const (
	maxPatternBytes   = 512
	maxPatternProgram = 1000
	maxPatternSubject = 4096
)

var errPattern = errors.New("the pattern is not one this engine can run within its limits")

// compilePattern compiles a pattern if it is RE2 syntax (no look-around, no back-references) and small enough.
func compilePattern(p string) (*regexp.Regexp, error) {
	if p == "" || len(p) > maxPatternBytes {
		return nil, errPattern
	}
	tree, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		return nil, errPattern
	}
	if estimateProgram(tree, 0) > maxPatternProgram {
		return nil, errPattern
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil, errPattern
	}
	return re, nil
}

// estimateProgram guesses how many instructions the pattern compiles to, multiplying out repeat counts, and stops counting once it
// is clearly over the limit so that a pattern like (a{1000}){1000} costs nothing to refuse.
func estimateProgram(re *syntax.Regexp, depth int) int {
	if depth > 100 {
		return maxPatternProgram + 1
	}
	sub := 0
	for _, s := range re.Sub {
		sub += estimateProgram(s, depth+1)
		if sub > maxPatternProgram {
			return sub
		}
	}
	switch re.Op {
	case syntax.OpRepeat:
		times := max(re.Max, re.Min, 1)
		if sub > 0 && times > (maxPatternProgram+1)/sub {
			return maxPatternProgram + 1
		}
		return sub * times
	case syntax.OpLiteral:
		return len(re.Rune)
	case syntax.OpCharClass:
		return 1 + len(re.Rune)/2
	case syntax.OpCapture:
		return sub + 2
	}
	return sub + 1
}

// prepare compiles what validation needs and cannot be saved: patterns, enum values, the sorted property names. It is called once
// on every schema reachable from a model before the model is used. Patterns that cannot run are dropped and counted in dropped,
// which makes the schema more permissive and is reported to the owner.
func (s *Schema) prepare(seen map[*Schema]bool, patterns map[string]*regexp.Regexp, dropped *int) {
	if s == nil || seen[s] {
		return
	}
	seen[s] = true
	if s.Pattern != "" {
		re, ok := patterns[s.Pattern]
		if !ok {
			var err error
			if re, err = compilePattern(s.Pattern); err != nil {
				re = nil
				*dropped++
			}
			patterns[s.Pattern] = re
		}
		s.re = re
	}
	s.enumV = s.enumV[:0]
	for _, e := range s.Enum {
		s.enumV = append(s.enumV, e.V)
	}
	if s.Const != nil {
		s.constV = s.Const.V
	}
	s.propNames = s.propNames[:0]
	for k := range s.Properties {
		s.propNames = append(s.propNames, k)
	}
	slices.Sort(s.propNames)
	s.prepared = true
	for _, p := range s.Properties {
		p.prepare(seen, patterns, dropped)
	}
	s.AdditionalSchema.prepare(seen, patterns, dropped)
	s.Items.prepare(seen, patterns, dropped)
	s.Not.prepare(seen, patterns, dropped)
	for _, list := range [][]*Schema{s.OneOf, s.AnyOf, s.AllOf} {
		for _, sub := range list {
			sub.prepare(seen, patterns, dropped)
		}
	}
}

// vkind says what a validation found wrong. It carries no part of the request.
type vkind uint8

const (
	vkNone vkind = iota
	vkType
	vkEnum
	vkBounds // a number outside its minimum, maximum or multiple
	vkLength // a string or an array or an object of the wrong size
	vkPattern
	vkFormat
	vkRequired
	vkUnknownProp
	vkReadOnly
	vkCombinator // oneOf, anyOf or not
	vkUnique
	vkTooComplex
	vkRepeated // a scalar parameter given more than once
)

var vkindText = [...]string{
	vkNone: "", vkType: "has the wrong type", vkEnum: "is not one of the allowed values", vkBounds: "is outside its allowed range",
	vkLength: "has the wrong length or size", vkPattern: "does not match its pattern", vkFormat: "does not have the declared format",
	vkRequired: "is missing a required property", vkUnknownProp: "has a property the description does not allow",
	vkReadOnly: "sets a read-only property", vkCombinator: "does not satisfy its alternatives", vkUnique: "repeats an item that must be unique",
	vkTooComplex: "is too complex to check", vkRepeated: "is given more than once",
}

func (k vkind) String() string { return vkindText[k] }

// violation is the first thing a validation found. where is built only from names in the schema (never from the request), so it
// is safe to put in a message.
type violation struct {
	kind  vkind
	where string
}

// vctx is the state of one validation: how much work is left, which direction the value travels, and the first violation.
type vctx struct {
	steps   int
	request bool // a request: read-only properties are forbidden and not required
	quiet   int  // inside oneOf, anyOf and not: failures are not recorded
	over    bool // the step budget ran out
	has     bool
	first   violation
	path    []string
}

const (
	maxSchemaDepth = 48
	// defaultSteps is how much work one validation may do, counted in values visited and branches tried. A body of 128 KiB has
	// at most about 64,000 values, so this allows a schema with a handful of alternatives and still ends a hostile pair of body
	// and schema in a few milliseconds.
	defaultSteps = 400_000
)

func (c *vctx) fail(k vkind) bool {
	if c.quiet == 0 && !c.has {
		c.has = true
		c.first = violation{k, strings.Join(c.path, ".")}
	}
	return false
}

// target follows a reference to the schema it names. A reference that does not resolve is nil, which accepts anything.
func (s *Schema) target() *Schema {
	for i := 0; s != nil && s.Ref != "" && i < 8; i++ {
		s = s.ref
	}
	return s
}

// validate reports whether v fits the schema. The schema must have been prepared.
func (s *Schema) validate(v any, c *vctx, depth int) bool {
	if s == nil || c.over {
		return true
	}
	if c.steps--; c.steps < 0 || depth > maxSchemaDepth {
		c.over = true
		return true
	}
	if s.Ref != "" {
		if v == nil && s.Nullable {
			return true
		}
		return s.ref.validate(v, c, depth+1)
	}
	t := typeOf(v)
	if !s.typeOK(t) {
		return c.fail(vkType)
	}
	if t == tNull {
		// A null that the type allowed has nothing more to be checked against, except an enum or const that must list it.
		if !s.Nullable && (len(s.enumV) > 0 || s.Const != nil) {
			if len(s.enumV) > 0 && !s.inEnum(v) {
				return c.fail(vkEnum)
			}
			if s.Const != nil && !equalValues(s.constV, v, 0) {
				return c.fail(vkEnum)
			}
		}
		return s.combinators(v, c, depth)
	}
	if len(s.enumV) > 0 && !s.inEnum(v) {
		return c.fail(vkEnum)
	}
	if s.Const != nil && !equalValues(s.constV, v, 0) {
		return c.fail(vkEnum)
	}
	switch t {
	case tInt, tNum:
		if !s.validNumber(v.(Num), t, c) {
			return false
		}
	case tStr:
		if !s.validString(v.(string), c) {
			return false
		}
	case tArr:
		if !s.validArray(v.([]any), c, depth) {
			return false
		}
	case tObj:
		if !s.validObject(v.(map[string]any), c, depth) {
			return false
		}
	}
	return s.combinators(v, c, depth)
}

func (s *Schema) typeOK(t jtype) bool {
	if t == tNull && s.Nullable {
		return true
	}
	if len(s.Type) == 0 {
		return true
	}
	for _, want := range s.Type {
		switch want {
		case "integer":
			if t == tInt {
				return true
			}
		case "number":
			if t == tInt || t == tNum {
				return true
			}
		case "string":
			if t == tStr {
				return true
			}
		case "boolean":
			if t == tBool {
				return true
			}
		case "object":
			if t == tObj {
				return true
			}
		case "array":
			if t == tArr {
				return true
			}
		case "null":
			if t == tNull {
				return true
			}
		}
	}
	return false
}

func (s *Schema) inEnum(v any) bool {
	for _, e := range s.enumV {
		if equalValues(e, v, 0) {
			return true
		}
	}
	return false
}

func (s *Schema) validNumber(n Num, t jtype, c *vctx) bool {
	f, ok := n.float()
	if !ok {
		return c.fail(vkType)
	}
	if s.Minimum != nil && f < *s.Minimum {
		return c.fail(vkBounds)
	}
	if s.Maximum != nil && f > *s.Maximum {
		return c.fail(vkBounds)
	}
	if s.ExclusiveMinimum != nil && f <= *s.ExclusiveMinimum {
		return c.fail(vkBounds)
	}
	if s.ExclusiveMaximum != nil && f >= *s.ExclusiveMaximum {
		return c.fail(vkBounds)
	}
	if m := s.MultipleOf; m != nil && *m > 0 {
		q := f / *m
		if math.Abs(q-math.Round(q)) > 1e-9*math.Max(1, math.Abs(q)) {
			return c.fail(vkBounds)
		}
	}
	switch s.Format {
	case "int32":
		if t != tInt {
			return c.fail(vkFormat)
		}
		if i, ok := n.int64(); !ok || i < math.MinInt32 || i > math.MaxInt32 {
			return c.fail(vkFormat)
		}
	case "int64":
		if t != tInt {
			return c.fail(vkFormat)
		}
		if _, ok := n.int64(); !ok {
			return c.fail(vkFormat)
		}
	}
	return true
}

func (s *Schema) validString(str string, c *vctx) bool {
	if s.MinLength != nil || s.MaxLength != nil {
		n := utf8.RuneCountInString(str)
		if s.MinLength != nil && n < *s.MinLength {
			return c.fail(vkLength)
		}
		if s.MaxLength != nil && n > *s.MaxLength {
			return c.fail(vkLength)
		}
	}
	if s.re != nil {
		if len(str) > maxPatternSubject {
			return c.fail(vkPattern)
		}
		c.steps -= len(str) / 16
		if !s.re.MatchString(str) {
			return c.fail(vkPattern)
		}
	}
	if s.Format != "" && !formatOK(s.Format, str) {
		return c.fail(vkFormat)
	}
	return true
}

func (s *Schema) validArray(a []any, c *vctx, depth int) bool {
	if s.MinItems != nil && len(a) < *s.MinItems {
		return c.fail(vkLength)
	}
	if s.MaxItems != nil && len(a) > *s.MaxItems {
		return c.fail(vkLength)
	}
	if s.UniqueItems && len(a) > 1 {
		seen := make(map[string]struct{}, len(a))
		for _, e := range a {
			key := string(appendJSON(nil, e, 0))
			if c.steps -= len(key)/32 + 1; c.steps < 0 {
				c.over = true
				return true
			}
			if _, dup := seen[key]; dup {
				return c.fail(vkUnique)
			}
			seen[key] = struct{}{}
		}
	}
	if s.Items != nil {
		c.path = append(c.path, "[]")
		for _, e := range a {
			if !s.Items.validate(e, c, depth+1) {
				c.path = c.path[:len(c.path)-1]
				return false
			}
		}
		c.path = c.path[:len(c.path)-1]
	}
	return true
}

func (s *Schema) validObject(o map[string]any, c *vctx, depth int) bool {
	if s.MinProperties != nil && len(o) < *s.MinProperties {
		return c.fail(vkLength)
	}
	if s.MaxProperties != nil && len(o) > *s.MaxProperties {
		return c.fail(vkLength)
	}
	for _, name := range s.Required {
		if _, present := o[name]; present {
			continue
		}
		// A required read-only property is only required in a response.
		if c.request {
			if ps := s.Properties[name]; ps != nil && ps.ReadOnly {
				continue
			}
		}
		c.path = append(c.path, name)
		ok := c.fail(vkRequired)
		c.path = c.path[:len(c.path)-1]
		return ok
	}
	for _, name := range s.propNames {
		val, present := o[name]
		if !present {
			continue
		}
		ps := s.Properties[name]
		c.path = append(c.path, name)
		if c.request && ps.ReadOnly {
			ok := c.fail(vkReadOnly)
			c.path = c.path[:len(c.path)-1]
			return ok
		}
		ok := ps.validate(val, c, depth+1)
		c.path = c.path[:len(c.path)-1]
		if !ok {
			return false
		}
	}
	closed := s.AdditionalProperties != nil && !*s.AdditionalProperties
	if (closed || s.AdditionalSchema != nil) && len(o) > 0 {
		for k, val := range o {
			if _, known := s.Properties[k]; known {
				continue
			}
			if closed {
				return c.fail(vkUnknownProp)
			}
			c.path = append(c.path, "*")
			ok := s.AdditionalSchema.validate(val, c, depth+1)
			c.path = c.path[:len(c.path)-1]
			if !ok {
				return false
			}
		}
	}
	return true
}

func (s *Schema) combinators(v any, c *vctx, depth int) bool {
	for _, sub := range s.AllOf {
		if !sub.validate(v, c, depth+1) {
			return false
		}
	}
	if len(s.AnyOf) > 0 {
		c.quiet++
		matched := false
		for _, sub := range s.AnyOf {
			if sub.validate(v, c, depth+1) {
				matched = true
				break
			}
		}
		c.quiet--
		if !matched && !c.over {
			return c.fail(vkCombinator)
		}
	}
	if len(s.OneOf) > 0 {
		c.quiet++
		n := 0
		for _, sub := range s.OneOf {
			if sub.validate(v, c, depth+1) {
				if n++; n > 1 {
					break
				}
			}
		}
		c.quiet--
		if n != 1 && !c.over {
			return c.fail(vkCombinator)
		}
	}
	if s.Not != nil {
		c.quiet++
		matched := s.Not.validate(v, c, depth+1)
		c.quiet--
		if matched && !c.over {
			return c.fail(vkCombinator)
		}
	}
	return true
}

// formatOK checks the string formats that matter for requests. A format it does not know is accepted, as the specification says
// an unknown format must be.
func formatOK(format, s string) bool {
	switch format {
	case "uuid":
		return isUUID(s)
	case "email":
		return isEmail(s)
	case "date":
		_, err := time.Parse(time.DateOnly, s)
		return err == nil && len(s) == 10
	case "date-time":
		_, err := time.Parse(time.RFC3339, s)
		return err == nil
	case "uri", "url":
		u, err := url.Parse(s)
		return err == nil && u.Scheme != "" && !strings.ContainsAny(s, " \t\r\n") && len(s) <= 2048
	case "ipv4":
		a, err := netip.ParseAddr(s)
		return err == nil && a.Is4()
	case "ipv6":
		a, err := netip.ParseAddr(s)
		return err == nil && a.Is6() && !a.Is4In6() && a.Zone() == ""
	case "hostname":
		return isHostname(s)
	case "byte":
		_, err := base64.StdEncoding.DecodeString(s)
		return err == nil
	}
	return true
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHex(c) {
				return false
			}
		}
	}
	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isEmail(s string) bool {
	if len(s) < 3 || len(s) > 254 || strings.ContainsAny(s, " \t\r\n,;<>()[]\\\"") {
		return false
	}
	at := strings.LastIndexByte(s, '@')
	if at < 1 || at > 64 || at == len(s)-1 || strings.Count(s, "@") != 1 {
		return false
	}
	return isHostname(s[at+1:]) && strings.Contains(s[at+1:], ".")
}

func isHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// validateBody validates a decoded request or response value against the schema and returns what was wrong with it. over reports
// that the work limit was reached before an answer was known.
func (s *Schema) validateBody(v any, request bool) (viol violation, ok, over bool) {
	c := &vctx{steps: defaultSteps, request: request}
	s.validate(v, c, 0)
	if c.over {
		return violation{kind: vkTooComplex}, true, true
	}
	return c.first, !c.has, false
}

// scalarVariants returns the typed values a text parameter could stand for under this schema, in the order to try them. A value in
// a URL is text; the schema says whether it is meant as a number or a boolean.
func scalarVariants(s *Schema, raw string) []any {
	want := ""
	if s != nil {
		for _, t := range s.Type {
			if t != "null" {
				want = t
				break
			}
		}
	}
	num := Num(raw)
	isNum := looksNumeric(raw)
	lower := strings.ToLower(raw)
	switch want {
	case "integer", "number":
		if isNum {
			return []any{num}
		}
		return []any{raw}
	case "boolean":
		switch lower {
		case "true":
			return []any{true}
		case "false":
			return []any{false}
		}
		return []any{raw}
	case "string":
		return []any{raw}
	case "":
		out := make([]any, 0, 3)
		if isNum {
			out = append(out, num)
		}
		if lower == "true" {
			out = append(out, true)
		} else if lower == "false" {
			out = append(out, false)
		}
		return append(out, raw)
	}
	return []any{raw}
}

// looksNumeric reports whether s is written as a number in decimal: an optional sign, digits, an optional fraction and exponent.
// Leading zeros are accepted (a form value of 007 is the integer 7 to most servers).
func looksNumeric(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	i := 0
	if s[0] == '-' || s[0] == '+' {
		i++
	}
	digits := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
		digits++
	}
	if i < len(s) && s[i] == '.' {
		i++
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
			digits++
		}
	}
	if digits == 0 {
		return false
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		j := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == j {
			return false
		}
	}
	if i != len(s) {
		return false
	}
	_, err := strconv.ParseFloat(strings.TrimPrefix(s, "+"), 64)
	return err == nil
}
