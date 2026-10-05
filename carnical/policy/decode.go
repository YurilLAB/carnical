// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// ErrInvalid is what errors.Is(err, ErrInvalid) says of an *Error.
var ErrInvalid = errors.New("policy: invalid")

// Problem is one thing wrong with a policy: where, and what, in a plain sentence that never repeats what the policy holds
// beyond a name from a fixed vocabulary.
type Problem struct {
	// Path locates it, such as "body.max_upload_bytes" or "custom_rules[3].value". "$" is the document itself.
	Path string `json:"path"`
	// Message says what is wrong.
	Message string `json:"message"`
}

// Error is every problem found in a policy (at most 50; the last says if there were more).
type Error struct {
	Problems []Problem
}

func (e *Error) Error() string {
	if len(e.Problems) == 0 {
		return ErrInvalid.Error()
	}
	first := e.Problems[0]
	more := ""
	if len(e.Problems) > 1 {
		more = fmt.Sprintf(" (and %d more)", len(e.Problems)-1)
	}
	return fmt.Sprintf("policy: %s: %s%s", first.Path, first.Message, more)
}

// Is makes errors.Is(err, ErrInvalid) true for an *Error.
func (e *Error) Is(target error) bool { return target == ErrInvalid }

const maxProblems = 50

// checker collects problems.
type checker struct {
	problems  []Problem
	truncated bool
}

func (c *checker) add(path, format string, args ...any) {
	if len(c.problems) >= maxProblems {
		c.truncated = true
		return
	}
	c.problems = append(c.problems, Problem{Path: path, Message: fmt.Sprintf(format, args...)})
}

func (c *checker) err() error {
	if len(c.problems) == 0 {
		return nil
	}
	if c.truncated {
		c.problems[len(c.problems)-1].Message += " (more problems were found and are not shown)"
	}
	return &Error{Problems: c.problems}
}

func invalid(path, format string, args ...any) error {
	var c checker
	c.add(path, format, args...)
	return c.err()
}

// Default is the policy of a new site: block mode, normal sensitivity, every rule group on, the standard methods, WordPress
// protections off (they are for a WordPress site, and the site's owner says so), nothing excluded, nothing allowed beyond
// the defaults, the verified virtual patches on, API protection off.
//
// Two protective settings are off because switching them on breaks sites that do not ask for them: Next-Action is not denied
// (a Next.js site that uses server actions needs it), and response inspection is off (it buffers responses, which costs latency).
func Default() Policy {
	return Policy{
		Schema:         SchemaVersion,
		Mode:           ModeBlock,
		Sensitivity:    SensitivityNormal,
		Body:           BodyLimits{MaxUploadBytes: DefaultUploadBytes, MaxFormBytes: DefaultFormBytes},
		AllowedMethods: []string{"GET", "HEAD", "OPTIONS", "POST"},
		AllowedHosts:   []string{},
		RuleGroups:     map[string]GroupState{},
		Exclusions:     []Exclusion{},
		CustomRules:    []CustomRule{},
		AllowIPs:       []string{},
		BlockIPs:       []string{},
		AllowPaths:     []string{},
		WordPress:      WordPressOptions{LoginPerMinute: 10},
		DenyHeaders:    []string{},
		VPatch:         VPatchOptions{Tiers: []string{"verified"}, Software: []string{}},
		APIMode:        APIOff,
	}
}

// Decode reads a policy document strictly and returns it normalised and validated. A field left out takes the value Default
// gives it, so a document only names what differs. It refuses (with an *Error that errors.Is ErrInvalid): a document over
// MaxPolicyBytes, text that is not valid UTF-8 or not a JSON object, nesting deeper than MaxDepth, a field the policy does
// not have, a field given twice, null where a value is needed (only "threshold" may be null), a value of the wrong kind,
// anything after the document, and then every problem Validate finds. It never panics, and its time and memory are in
// proportion to the document's size, which is at most 1 MiB.
func Decode(data []byte) (Policy, error) {
	if len(data) > MaxPolicyBytes {
		return Policy{}, invalid("$", "the policy is larger than %d KiB", MaxPolicyBytes>>10)
	}
	if err := scanJSON(data, scanLimits{maxDepth: MaxDepth, maxTokens: MaxTokens, maxString: MaxStringBytes, nullOK: policyNullOK}); err != nil {
		return Policy{}, invalid("$", "%s", err.Error())
	}
	if t := bytes.TrimSpace(data); len(t) == 0 || t[0] != '{' {
		return Policy{}, invalid("$", "the policy must be an object")
	}
	p := Default()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, decodeProblem(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Policy{}, invalid("$", "there is more than one document")
	}
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// policyNullOK says where null is allowed: for the threshold (it means "from the sensitivity"), and anywhere inside the two
// sections that belong to other packages.
func policyNullOK(path []string) bool {
	switch {
	case len(path) == 1 && path[0] == "threshold":
		return true
	case len(path) >= 1 && (path[0] == "api" || path[0] == "body_formats"):
		return true
	}
	return false
}

func decodeProblem(err error) error {
	var typeErr *json.UnmarshalTypeError
	var syntaxErr *json.SyntaxError
	switch {
	case errors.As(err, &typeErr):
		path := typeErr.Field
		if path == "" {
			path = "$"
		}
		return invalid(path, "must be %s", kindWords(typeErr.Type))
	case errors.As(err, &syntaxErr):
		return invalid("$", "not valid JSON")
	}
	if msg := err.Error(); strings.HasPrefix(msg, "json: unknown field ") {
		name := strings.Trim(strings.TrimPrefix(msg, "json: unknown field "), `"`)
		return invalid("$", "there is no field called %q", safeName(name))
	}
	return invalid("$", "not a policy document")
}

func kindWords(t reflect.Type) string {
	if t == nil {
		return "of another kind"
	}
	switch t.Kind() {
	case reflect.String:
		return "text"
	case reflect.Bool:
		return "true or false"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "a whole number"
	case reflect.Slice, reflect.Array:
		return "a list"
	case reflect.Map, reflect.Struct:
		return "an object"
	}
	return "of another kind"
}

// Encode returns the canonical JSON form of a policy: normalised (see Normalize), then written compactly with the fields in
// the order of the document's definition. The same policy always gives the same bytes. It refuses an invalid policy.
func Encode(p Policy) ([]byte, error) {
	q := p.Normalize()
	if err := q.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(q)
}

// Hash is the SHA-256, in lower-case hexadecimal, of the canonical encoding of the policy's content: the policy normalised
// and with its Revision set to zero, so two policies that say the same thing have the same hash whatever order their lists
// are in, and a change of revision alone is not a change. The control plane uses it as the identity of a revision and to
// see whether a save changed anything. It returns "" only for a policy that cannot be encoded at all (a section that is not
// JSON).
func (p Policy) Hash() string {
	q := p.Normalize()
	q.Revision = 0
	b, err := json.Marshal(q)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
