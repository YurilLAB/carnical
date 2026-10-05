// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// SectionValidator checks a section that belongs to another package. It is given the section as canonical JSON, after
// this package has checked it for size, depth, node count and the form of its field names, and returns an error that says,
// in a plain sentence, what is wrong with it, or nil. It must not keep or change raw, must be safe for concurrent use, and
// must bound its own work by the size of its input (at most MaxSectionBytes). If it panics, the section is refused.
type SectionValidator func(raw json.RawMessage) error

// The sections other packages own, with the name each is registered under.
const (
	SectionAPI         = "api"
	SectionBodyFormats = "body_formats"
)

var sections = struct {
	sync.RWMutex
	validators map[string]SectionValidator
}{validators: map[string]SectionValidator{}}

// RegisterSection makes v the validator of the named section, so that the package that owns the section can say what is
// valid in it without this package knowing. The names are SectionAPI ("api") and SectionBodyFormats ("body_formats"). A
// section with no validator registered is checked only for size, depth and the form of its names. It returns an error for
// another name, for a nil validator and for a name that already has one (registering twice is a mistake in the program
// that does it, and the first stays in place).
func RegisterSection(name string, v SectionValidator) error {
	if name != SectionAPI && name != SectionBodyFormats {
		return fmt.Errorf("policy: %q is not a section that another package owns", safeName(name))
	}
	if v == nil {
		return errors.New("policy: the validator is nil")
	}
	sections.Lock()
	defer sections.Unlock()
	if _, dup := sections.validators[name]; dup {
		return fmt.Errorf("policy: section %q already has a validator", name)
	}
	sections.validators[name] = v
	return nil
}

// unregisterSection is for tests.
func unregisterSection(name string) {
	sections.Lock()
	delete(sections.validators, name)
	sections.Unlock()
}

// runSection applies this package's checks and then the registered validator to a section, and returns what is wrong, if anything.
func runSection(name string, raw json.RawMessage) (problem string) {
	if len(raw) == 0 {
		return ""
	}
	if err := checkSection(raw); err != nil {
		return err.Error()
	}
	sections.RLock()
	v := sections.validators[name]
	sections.RUnlock()
	if v == nil {
		return ""
	}
	defer func() {
		if r := recover(); r != nil {
			problem = "the validator for this section failed, so the section is refused"
		}
	}()
	if err := v(append(json.RawMessage(nil), raw...)); err != nil {
		return shortMessage(err.Error())
	}
	return ""
}

// shortMessage keeps what another package's validator says to one line of printable text of at most 300 characters.
func shortMessage(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if len(out) >= 300 {
			out = append(out, '.', '.', '.')
			break
		}
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		out = append(out, r)
	}
	return string(out)
}
