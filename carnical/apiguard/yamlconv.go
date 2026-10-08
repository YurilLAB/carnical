// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// docLimits bound the parse of an API description, which comes from the customer's own server (or from the customer) and is
// treated as hostile: it may be enormous, nested to a depth that would exhaust a stack, or use YAML aliases to describe a tree
// that is billions of nodes when expanded.
type docLimits struct {
	bytes int // the most bytes read
	depth int // the deepest nesting
	nodes int // the most values, counting each use of an alias in full
}

// MaxDocumentBytes is the largest API description that is read at all.
const MaxDocumentBytes = 5 << 20

var defaultDocLimits = docLimits{bytes: MaxDocumentBytes, depth: 64, nodes: 500_000}

var errTooComplex = errors.New("the document is too complex (nesting or size beyond the limits)")

// parseDocument reads a JSON or YAML document into plain values. A document that starts with "{" is JSON and is read by the
// strict JSON parser; anything else is YAML.
func parseDocument(data []byte, lim docLimits) (v any, err error) {
	if lim.bytes <= 0 {
		lim = defaultDocLimits
	}
	if len(data) > lim.bytes {
		return nil, fmt.Errorf("the document is %d bytes; the limit is %d", len(data), lim.bytes)
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, errors.New("the document is empty")
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		v, _, err := parseJSON(data, jsonLimits{depth: lim.depth, nodes: lim.nodes})
		if err != nil {
			return nil, fmt.Errorf("the document is not valid JSON: %w", err)
		}
		return v, nil
	}
	return parseYAML(data, lim)
}

// yamlShapeOK refuses, before the YAML parser sees it, the shapes that would make its recursive descent exhaust the stack. A Go
// stack that grows past its maximum ends the whole process and cannot be recovered, so this has to be decided up front: bracket
// nesting, the indentation of a line, and the number of "- " entries that open on one line. Quoted text is not told apart, so a
// string holding a long run of brackets is refused too, which is the safe side.
func yamlShapeOK(data []byte, depth int) error {
	flow := 0
	lineStart := true
	indent := 0
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case c == '\n':
			lineStart, indent = true, 0
			continue
		case lineStart && c == ' ':
			indent++
			if indent > depth*4 {
				return errTooComplex
			}
			continue
		case c == '[' || c == '{':
			if flow++; flow > depth {
				return errTooComplex
			}
		case c == ']' || c == '}':
			if flow > 0 {
				flow--
			}
		}
		if lineStart {
			lineStart = false
			// A run of "- " (or "? ") at the start of a line opens one level each.
			n := 0
			for j := i; j+1 < len(data) && (data[j] == '-' || data[j] == '?') && data[j+1] == ' '; {
				if n++; n > depth {
					return errTooComplex
				}
				j += 2
				for j < len(data) && data[j] == ' ' {
					j++
				}
			}
		}
	}
	return nil
}

// Limits on how many keys one block mapping may have. The YAML library reads a block mapping in time that grows with the square of
// its keys (measured: 32,000 keys take 2.2 s, 300,000 keys in a 5 MiB document take almost eight minutes), so a hostile document
// could hold a CPU for that long. A real description has a few thousand keys in its largest mapping (its paths, its schemas).
const (
	maxSiblings    = 12_000
	maxSiblingCost = 400_000_000 // the sum of the squares of the sizes of all the mappings, about 1 s of work
)

// yamlSiblingsOK counts, line by line, the keys that follow each other at one indentation (a block mapping) and refuses a
// document whose mappings would be slow to read. It is an estimate made without parsing: a block of text that happens to have many
// lines of the form "word: text" is counted as keys, which refuses it, and that is the safe side.
func yamlSiblingsOK(data []byte, maxNodes int) error {
	type group struct{ indent, n int }
	var stack []group
	cost, nodes := 0, 0
	flush := func(g group) error {
		cost += g.n * g.n
		if g.n > maxSiblings || cost > maxSiblingCost {
			return errTooComplex
		}
		return nil
	}
	for rest := data; len(rest) > 0; {
		var line []byte
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			line, rest = rest, nil
		}
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		body := line[indent:]
		// "- key: value" starts a mapping two columns in.
		for len(body) >= 2 && body[0] == '-' && body[1] == ' ' {
			body = bytes.TrimLeft(body[2:], " ")
			indent += 2
		}
		if len(body) == 0 || body[0] == '#' {
			continue
		}
		// An estimate of how many values the document will have, made before it is read: a line is at least one, and a flow list or
		// mapping written on one line is one for each comma. A document over the limit would be refused after being read, which for
		// the library takes about a second for every 200,000 of them.
		nodes++
		value, isEntry := yamlEntry(body)
		flow := body
		if isEntry {
			flow = bytes.TrimLeft(body[value:], " ")
		}
		if len(flow) > 0 && (flow[0] == '[' || flow[0] == '{') {
			nodes += bytes.Count(flow, []byte{','})
		}
		if nodes > maxNodes {
			return errTooComplex
		}
		if !isEntry {
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].indent > indent {
			if err := flush(stack[len(stack)-1]); err != nil {
				return err
			}
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 && stack[len(stack)-1].indent == indent {
			stack[len(stack)-1].n++
		} else {
			stack = append(stack, group{indent, 1})
		}
	}
	for _, g := range stack {
		if err := flush(g); err != nil {
			return err
		}
	}
	return nil
}

// yamlEntry reports whether a line (without its indentation) starts a "key: value" entry: a key, then a colon that is followed by
// a space or the end of the line, not inside quotes. It also returns where the value starts.
func yamlEntry(b []byte) (value int, ok bool) {
	if b[0] == '[' || b[0] == '{' {
		return 0, false
	}
	i := 0
	if b[0] == '"' || b[0] == '\'' {
		q := b[0]
		for i = 1; i < len(b) && b[i] != q; i++ {
		}
		i++
	}
	for ; i < len(b); i++ {
		if b[i] == '#' && i > 0 && b[i-1] == ' ' {
			return 0, false
		}
		if b[i] == ':' && (i+1 == len(b) || b[i+1] == ' ' || b[i+1] == '\t' || b[i+1] == '\r') {
			return i + 1, true
		}
	}
	return 0, false
}

func parseYAML(data []byte, lim docLimits) (v any, err error) {
	if err := yamlShapeOK(data, lim.depth); err != nil {
		return nil, err
	}
	if err := yamlSiblingsOK(data, 2*lim.nodes); err != nil {
		return nil, err
	}
	defer func() {
		if p := recover(); p != nil {
			v, err = nil, errors.New("the YAML could not be read")
		}
	}()
	file, perr := parser.ParseBytes(data, 0)
	if perr != nil {
		return nil, errors.New("the document is not valid YAML")
	}
	if len(file.Docs) == 0 || file.Docs[0] == nil || file.Docs[0].Body == nil {
		return nil, errors.New("the document is empty")
	}
	c := &yamlConv{lim: lim, anchors: map[string]anchored{}}
	v, _, _, err = c.node(file.Docs[0].Body, 0)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// anchored is a converted anchor target and how large and how deep it is once expanded, so that each alias that uses it can be
// charged for all of it.
type anchored struct {
	v     any
	size  int
	depth int
}

type yamlConv struct {
	lim     docLimits
	nodes   int
	anchors map[string]anchored
}

func (c *yamlConv) charge(n int) error {
	c.nodes += n
	if c.nodes > c.lim.nodes {
		return errTooComplex
	}
	return nil
}

// node converts one YAML node. size is how many nodes the converted value holds once every alias is expanded, and height is its
// depth, both used to charge a later alias.
func (c *yamlConv) node(n ast.Node, depth int) (v any, size, height int, err error) {
	if depth > c.lim.depth {
		return nil, 0, 0, errTooComplex
	}
	if n == nil {
		return nil, 0, 0, nil
	}
	if err := c.charge(1); err != nil {
		return nil, 0, 0, err
	}
	switch x := n.(type) {
	case *ast.NullNode:
		return nil, 1, 0, nil
	case *ast.BoolNode:
		return x.Value, 1, 0, nil
	case *ast.IntegerNode:
		return Num(fmt.Sprint(x.Value)), 1, 0, nil
	case *ast.FloatNode:
		if x.Token != nil {
			if validNumberText(x.Token.Value) {
				return Num(x.Token.Value), 1, 0, nil
			}
		}
		return Num(strconv.FormatFloat(x.Value, 'g', -1, 64)), 1, 0, nil
	case *ast.InfinityNode, *ast.NanNode:
		return x.GetToken().Value, 1, 0, nil
	case *ast.StringNode:
		return x.Value, 1, 0, nil
	case *ast.LiteralNode:
		if x.Value == nil {
			return "", 1, 0, nil
		}
		return x.Value.Value, 1, 0, nil
	case *ast.TagNode:
		return c.node(x.Value, depth)
	case *ast.AnchorNode:
		v, size, height, err := c.node(x.Value, depth)
		if err != nil {
			return nil, 0, 0, err
		}
		if x.Name != nil {
			// Registered only after the value is converted, so an anchor cannot be used inside its own definition.
			c.anchors[x.Name.GetToken().Value] = anchored{v, size, height}
		}
		return v, size, height, nil
	case *ast.AliasNode:
		if x.Value == nil {
			return nil, 0, 0, errors.New("an alias without a name")
		}
		a, ok := c.anchors[x.Value.GetToken().Value]
		if !ok {
			return nil, 0, 0, errors.New("an alias refers to an anchor that is not defined")
		}
		if depth+a.depth > c.lim.depth {
			return nil, 0, 0, errTooComplex
		}
		if err := c.charge(a.size); err != nil {
			return nil, 0, 0, err
		}
		return a.v, a.size, a.depth, nil
	case *ast.SequenceNode:
		out := make([]any, 0, len(x.Values))
		size, height := 1, 1
		for _, e := range x.Values {
			ev, es, eh, err := c.node(e, depth+1)
			if err != nil {
				return nil, 0, 0, err
			}
			out = append(out, ev)
			size += es
			height = max(height, eh+1)
		}
		return out, size, height, nil
	case *ast.MappingNode:
		return c.mapping(x.Values, depth)
	case *ast.MappingValueNode:
		return c.mapping([]*ast.MappingValueNode{x}, depth)
	case *ast.MappingKeyNode:
		return c.node(x.Value, depth)
	case *ast.DocumentNode:
		return c.node(x.Body, depth)
	}
	return nil, 0, 0, fmt.Errorf("a YAML construct that is not supported (%T)", n)
}

func (c *yamlConv) mapping(entries []*ast.MappingValueNode, depth int) (any, int, int, error) {
	out := make(map[string]any, len(entries))
	size, height := 1, 1
	var merges []map[string]any
	for _, e := range entries {
		if e == nil {
			continue
		}
		if _, isMerge := e.Key.(*ast.MergeKeyNode); isMerge {
			mv, ms, mh, err := c.node(e.Value, depth+1)
			if err != nil {
				return nil, 0, 0, err
			}
			size += ms
			height = max(height, mh+1)
			switch m := mv.(type) {
			case map[string]any:
				merges = append(merges, m)
			case []any:
				for _, item := range m {
					if im, ok := item.(map[string]any); ok {
						merges = append(merges, im)
					}
				}
			}
			continue
		}
		key, err := c.key(e.Key, depth)
		if err != nil {
			return nil, 0, 0, err
		}
		if err := c.charge(1); err != nil {
			return nil, 0, 0, err
		}
		if _, dup := out[key]; dup {
			return nil, 0, 0, errors.New("a mapping repeats a key")
		}
		vv, vs, vh, err := c.node(e.Value, depth+1)
		if err != nil {
			return nil, 0, 0, err
		}
		out[key] = vv
		size += vs + 1
		height = max(height, vh+1)
	}
	// A merge key fills in what the mapping did not say itself, whatever order they were written in.
	for _, m := range merges {
		for k, v := range m {
			if _, have := out[k]; !have {
				out[k] = v
			}
		}
	}
	return out, size, height, nil
}

func (c *yamlConv) key(k ast.MapKeyNode, depth int) (string, error) {
	switch x := k.(type) {
	case *ast.StringNode:
		return x.Value, nil
	case *ast.AliasNode, *ast.MappingKeyNode:
		v, _, _, err := c.node(x, depth+1)
		if err != nil {
			return "", err
		}
		return keyText(v)
	}
	if t := k.GetToken(); t != nil {
		return t.Value, nil
	}
	return "", errors.New("a mapping key that is not supported")
}

func keyText(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case Num:
		return string(x), nil
	case bool:
		return strconv.FormatBool(x), nil
	case nil:
		return "null", nil
	}
	return "", errors.New("a mapping key that is not a scalar")
}

// validNumberText reports whether s is written the way JSON writes a number.
func validNumberText(s string) bool {
	v, _, err := parseJSON([]byte(s), jsonLimits{depth: 1, nodes: 1})
	n, number := v.(Num)
	return err == nil && number && string(n) == s
}
