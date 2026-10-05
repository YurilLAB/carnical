// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

func TestRegisteredSectionValidatorsAreCalledWithCanonicalJSON(t *testing.T) {
	defer unregisterSection(SectionAPI)
	defer unregisterSection(SectionBodyFormats)
	var got []string
	var mu sync.Mutex
	ok := func(name string) SectionValidator {
		return func(raw json.RawMessage) error {
			mu.Lock()
			got = append(got, name+" "+string(raw))
			mu.Unlock()
			if strings.Contains(string(raw), `"bad"`) {
				return errors.New("the \"bad\" key is not allowed here\nand this is a second line")
			}
			return nil
		}
	}
	if err := RegisterSection(SectionAPI, ok("api")); err != nil {
		t.Fatal(err)
	}
	if err := RegisterSection(SectionBodyFormats, ok("formats")); err != nil {
		t.Fatal(err)
	}

	p := Default()
	p.API = json.RawMessage(` { "b" : 1 , "a" : [ 2 ] } `)
	p.BodyFormats = json.RawMessage(`{"z":1}`)
	wantValid(t, p.Validate())
	if len(got) != 2 || got[0] != `api {"a":[2],"b":1}` || got[1] != `formats {"z":1}` {
		t.Fatalf("the validators were called with %v", got)
	}

	t.Run("a section that is empty is not given to its validator", func(t *testing.T) {
		got = nil
		wantValid(t, Default().Validate())
		if len(got) != 0 {
			t.Fatalf("called with %v", got)
		}
	})
	t.Run("what the validator says becomes a problem at the section, on one line", func(t *testing.T) {
		bad := Default()
		bad.API = json.RawMessage(`{"bad":1}`)
		err := bad.Validate()
		wantInvalid(t, err, "api")
		var e *Error
		errors.As(err, &e)
		if strings.Contains(e.Problems[0].Message, "\n") || !strings.Contains(e.Problems[0].Message, "not allowed here") {
			t.Fatalf("%q", e.Problems[0].Message)
		}
		if _, err := Compile(bad); err == nil {
			t.Fatal("Compile accepted a section its validator refused")
		}
		other := Default()
		other.BodyFormats = json.RawMessage(`{"bad":1}`)
		wantInvalid(t, other.Validate(), "body_formats")
	})
	t.Run("the generic checks come first", func(t *testing.T) {
		got = nil
		deep := Default()
		deep.API = json.RawMessage(strings.Repeat(`{"a":`, MaxSectionDepth+1) + `1` + strings.Repeat(`}`, MaxSectionDepth+1))
		wantInvalid(t, deep.Validate(), "api")
		if len(got) != 0 {
			t.Fatalf("the validator was given a section that failed the generic checks: %v", got)
		}
	})
	t.Run("a validator that panics refuses the section and does not take the caller down", func(t *testing.T) {
		unregisterSection(SectionAPI)
		if err := RegisterSection(SectionAPI, func(json.RawMessage) error { panic("boom") }); err != nil {
			t.Fatal(err)
		}
		p := Default()
		p.API = json.RawMessage(`{"a":1}`)
		wantInvalid(t, p.Validate(), "api")
	})
	t.Run("a validator cannot change what it is given", func(t *testing.T) {
		unregisterSection(SectionAPI)
		if err := RegisterSection(SectionAPI, func(raw json.RawMessage) error {
			for i := range raw {
				raw[i] = 'x'
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		p := Default()
		p.API = json.RawMessage(`{"a":1}`)
		wantValid(t, p.Validate())
		if string(p.API) != `{"a":1}` {
			t.Fatalf("the policy's section was changed by a validator: %s", p.API)
		}
		c, err := Compile(p)
		wantValid(t, err)
		if string(c.API) != `{"a":1}` {
			t.Fatalf("the compiled section was changed: %s", c.API)
		}
	})
}

func TestRegisterSectionRefusals(t *testing.T) {
	defer unregisterSection(SectionAPI)
	nop := func(json.RawMessage) error { return nil }
	for name, call := range map[string]func() error{
		"an unknown section":    func() error { return RegisterSection("vpatch", nop) },
		"an empty name":         func() error { return RegisterSection("", nop) },
		"a name in capitals":    func() error { return RegisterSection("API", nop) },
		"a long name":           func() error { return RegisterSection(strings.Repeat("x", 500), nop) },
		"a nil validator":       func() error { return RegisterSection(SectionAPI, nil) },
		"a name with a newline": func() error { return RegisterSection("api\nx", nop) },
	} {
		if err := call(); err == nil {
			t.Errorf("%s was accepted", name)
		} else if len(err.Error()) > 200 || strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: the error is not one short line: %q", name, err)
		}
	}
	if err := RegisterSection(SectionAPI, nop); err != nil {
		t.Fatal(err)
	}
	if err := RegisterSection(SectionAPI, nop); err == nil {
		t.Error("a second validator for one section was accepted")
	}
}

func TestSectionValidationIsSafeForConcurrentUse(t *testing.T) {
	defer unregisterSection(SectionAPI)
	var wg sync.WaitGroup
	p := Default()
	p.API = json.RawMessage(`{"a":1}`)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%8 == 0 {
				unregisterSection(SectionAPI)
				RegisterSection(SectionAPI, func(json.RawMessage) error { return nil })
			}
			for j := 0; j < 50; j++ {
				if err := p.Validate(); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
