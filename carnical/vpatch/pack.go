// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// PackFormat is the value of "format" in a pack.
const PackFormat = "carnical-vpatch-1"

// Limits on reading a pack.
const (
	maxPackBytes      = 64 << 20
	maxPackSignatures = 200000
	maxPackNodes      = 8 << 20
	maxPackMeta       = 256
)

// A Pack is Carnical's own file format for signatures: one YAML or JSON document that names and dates the set and carries the
// signatures, with a hash of their content so that a changed or truncated file is noticed.
//
//	format: carnical-vpatch-1
//	name: wordpress-plugins
//	version: "2026.10.05"
//	created: 2026-10-05T12:00:00Z
//	hash: <sha256 of the signatures, hex>
//	signatures:
//	  - id: CS-CVE-2024-4577-1
//	    ...
type Pack struct {
	Format  string `json:"format" yaml:"format"`
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
	Created string `json:"created" yaml:"created"`
	// Hash is the SHA-256 of the signatures (see ContentHash). WritePack fills it in; ReadPack checks it if it is present.
	Hash       string      `json:"hash,omitempty" yaml:"hash,omitempty"`
	Signatures []Signature `json:"signatures" yaml:"signatures"`
}

// ContentHash is the hex SHA-256 of the pack's signatures in their canonical JSON form, so the same signatures give the same hash
// whether the file is YAML or JSON and however it is laid out.
func (p *Pack) ContentHash() string {
	sigs := p.Signatures
	if sigs == nil {
		sigs = []Signature{} // no signatures hash the same whether the list was absent or empty
	}
	b, err := json.Marshal(sigs)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Validate checks a pack's shape: its format, its descriptive fields, the limits, that every signature is well formed (the same
// checks Load makes before it compiles anything) and that no ID is used twice.
func (p *Pack) Validate() error {
	if p.Format != PackFormat {
		return fmt.Errorf("format must be %q", PackFormat)
	}
	for name, v := range map[string]string{"name": p.Name, "version": p.Version, "created": p.Created} {
		if len(v) > maxPackMeta || !validText(v) {
			return fmt.Errorf("%s is too long or not plain text", name)
		}
	}
	if len(p.Signatures) > maxPackSignatures {
		return fmt.Errorf("more than %d signatures", maxPackSignatures)
	}
	seen := make(map[string]struct{}, len(p.Signatures))
	for i := range p.Signatures {
		s := &p.Signatures[i]
		if _, err := validateSignature(s); err != nil {
			return fmt.Errorf("signature %d (%s): %s", i+1, clip(s.ID, 40), err.Error())
		}
		if _, dup := seen[s.ID]; dup {
			return fmt.Errorf("signature ID %q appears twice", clip(s.ID, 40))
		}
		seen[s.ID] = struct{}{}
	}
	return nil
}

// ReadPack reads a pack, JSON or YAML (it looks at the first character). Decoding is strict: a field that is not part of the
// format is an error, so is a second document, and a YAML anchor, alias or merge key (which could make a small file expand
// into a very large one). The file is limited in size and signature count, the IDs must be unique, and if the pack carries a hash
// it must match the signatures.
func ReadPack(r io.Reader) (Pack, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxPackBytes+1))
	if err != nil {
		return Pack{}, err
	}
	if len(data) > maxPackBytes {
		return Pack{}, fmt.Errorf("the pack is larger than %d bytes", maxPackBytes)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var p Pack
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return Pack{}, fmt.Errorf("the pack is empty")
	}
	if trimmed[0] == '{' {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return Pack{}, fmt.Errorf("reading the pack: %w", err)
		}
		if _, err := dec.Token(); err != io.EOF {
			return Pack{}, fmt.Errorf("reading the pack: data after the document")
		}
	} else if err := decodeYAMLPack(trimmed, &p); err != nil {
		return Pack{}, err
	}
	if err := p.Validate(); err != nil {
		return Pack{}, err
	}
	want := p.ContentHash()
	if p.Hash != "" && !strings.EqualFold(p.Hash, want) {
		return Pack{}, fmt.Errorf("the content hash does not match the signatures (the file was changed or cut short)")
	}
	p.Hash = want
	return p, nil
}

type nodeCounter struct {
	n   int
	bad string
}

func (c *nodeCounter) Visit(n ast.Node) ast.Visitor {
	c.n++
	switch n.(type) {
	case *ast.AnchorNode, *ast.AliasNode, *ast.MergeKeyNode:
		c.bad = "YAML anchors, aliases and merge keys are not allowed in a pack"
	}
	if c.n > maxPackNodes || c.bad != "" {
		return nil
	}
	return c
}

// Limits on the shape of a YAML pack. A pack is a list of mappings, three levels deep; these are far above that. They exist because
// the YAML parser's time grows faster than the input's when brackets or sequences are nested (measured: 120 KB of "{a: " takes
// almost four seconds), and a pack is read from a file someone else wrote.
const (
	maxYAMLFlowDepth = 32
	maxYAMLDashRun   = 16
	maxYAMLIndent    = 128
)

// checkYAMLShape reads the text once, without building anything, and refuses nesting no pack has: flow brackets more than
// maxYAMLFlowDepth deep, more than maxYAMLDashRun "- " in a row at the start of a line, or indentation past maxYAMLIndent
// columns. Quoted strings and comments are skipped, and a bracket only counts where a token starts, so a regular expression
// full of brackets inside a quoted string, or in the middle of a plain one, does not count.
func checkYAMLShape(b []byte) error {
	depth, indent, lastOpen := 0, 0, -2
	inS, inD, lineStart := false, false, true
	tokenStart := func(i int) bool {
		if i == 0 {
			return true
		}
		switch b[i-1] {
		case ' ', '\t', '\n', '\r', ',':
			return true
		case '[', '{':
			return i-1 == lastOpen // directly after a bracket that was itself structural
		}
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == '\n' {
			lineStart, indent = true, 0
			continue
		}
		if lineStart && !inS && !inD {
			if c == ' ' {
				if indent++; indent > maxYAMLIndent {
					return fmt.Errorf("reading the pack: indentation deeper than %d columns", maxYAMLIndent)
				}
				continue
			}
			lineStart = false
			runs := 0
			for j := i; j+1 < len(b) && b[j] == '-' && (b[j+1] == ' ' || b[j+1] == '\t'); {
				runs++
				j += 2
				for j < len(b) && (b[j] == ' ' || b[j] == '\t') {
					j++
				}
			}
			if runs > maxYAMLDashRun {
				return fmt.Errorf("reading the pack: more than %d nested sequence markers on a line", maxYAMLDashRun)
			}
		}
		switch {
		case inD:
			if c == '\\' {
				i++
			} else if c == '"' {
				inD = false
			}
		case inS:
			if c == '\'' {
				if i+1 < len(b) && b[i+1] == '\'' {
					i++
				} else {
					inS = false
				}
			}
		case c == '#' && tokenStart(i):
			for i < len(b) && b[i] != '\n' {
				i++
			}
			i--
		case c == '"' && tokenStart(i):
			inD = true
		case c == '\'' && tokenStart(i):
			inS = true
		case (c == '[' || c == '{') && tokenStart(i):
			lastOpen = i
			if depth++; depth > maxYAMLFlowDepth {
				return fmt.Errorf("reading the pack: brackets nested deeper than %d", maxYAMLFlowDepth)
			}
		case (c == ']' || c == '}') && depth > 0:
			depth--
		}
		if lineStart {
			lineStart = false
		}
	}
	return nil
}

func decodeYAMLPack(data []byte, p *Pack) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("reading the pack: the YAML could not be parsed")
		}
	}()
	if err := checkYAMLShape(data); err != nil {
		return err
	}
	file, err := parser.ParseBytes(data, 0)
	if err != nil {
		return fmt.Errorf("reading the pack: %s", firstLine(err.Error()))
	}
	if len(file.Docs) != 1 {
		return fmt.Errorf("reading the pack: expected one YAML document, found %d", len(file.Docs))
	}
	var c nodeCounter
	ast.Walk(&c, file.Docs[0].Body)
	if c.bad != "" {
		return fmt.Errorf("reading the pack: %s", c.bad)
	}
	if c.n > maxPackNodes {
		return fmt.Errorf("reading the pack: the document is too complex")
	}
	if err := yaml.NodeToValue(file.Docs[0].Body, p, yaml.Strict()); err != nil {
		return fmt.Errorf("reading the pack: %s", firstLine(err.Error()))
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return clip(s, 200)
}

// WritePack writes a pack as YAML. It fills in the format and the content hash and refuses a pack that does not validate, so
// that what is written can be read back.
func WritePack(w io.Writer, p Pack) error {
	if err := preparePack(&p); err != nil {
		return err
	}
	b, err := yaml.MarshalWithOptions(p, yaml.IndentSequence(true))
	if err != nil {
		return fmt.Errorf("writing the pack: %w", err)
	}
	_, err = w.Write(b)
	return err
}

// WritePackJSON is WritePack in JSON, one signature per line group for readable diffs.
func WritePackJSON(w io.Writer, p Pack) error {
	if err := preparePack(&p); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("writing the pack: %w", err)
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

func preparePack(p *Pack) error {
	if p.Format == "" {
		p.Format = PackFormat
	}
	if err := p.Validate(); err != nil {
		return err
	}
	p.Hash = p.ContentHash()
	return nil
}
