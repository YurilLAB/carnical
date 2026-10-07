package formats

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
)

// YAML is refused unless the policy lists its media types, because a YAML document is a program for the loader of the application
// that reads it: tags (!!python/object, !ruby/object, !<tag:yaml.org,2002:java.util.PriorityQueue>) construct arbitrary objects, and
// anchors and aliases expand a few lines into billions of nodes. When it is allowed, this reads it with the goccy/go-yaml lexer and
// parser, which build a tree and never construct objects or expand aliases, and refuses any tag, more anchors or aliases than a
// request needs, deep or large documents and more than one document.
//
// Everything the library is given is bounded first: the body size cap, and a pass over the lexer's tokens that counts nesting, tags,
// anchors and aliases before the parser builds anything.

// checkYAML checks a YAML body. It returns false when the caller should stop.
func (in *Inspector) checkYAML(f *finder, ci ctInfo, body []byte) bool {
	lim := &in.pol.YAML
	if len(body) > lim.MaxBytes {
		f.hitLimit(rYAMLLimit, dBodyTooLong, lim.MaxBytes, -1)
		return false
	}
	if !in.utf8Charset(f, ci, body) {
		return false
	}
	start, ok := f.textStart(body)
	if !ok {
		return false
	}
	src := body[start:]
	if r, off := sourceProblem(src); r != nil {
		f.hit(r, start+off, dNone)
		return false
	}
	for i, c := range src {
		if c == 0x7f {
			f.hit(rControlChar, start+i, dNone)
			return false
		}
	}
	return in.yamlTree(f, string(src), lim)
}

func (in *Inspector) yamlTree(f *finder, src string, lim *YAMLLimits) (ok bool) {
	defer func() {
		// The library is not written for hostile input. If it panics the document is not one it can read, which is a refusal.
		if p := recover(); p != nil {
			f.hit(rYAMLSyntax, -1, dParserFailed)
			ok = false
		}
	}()
	tokens := lexer.Tokenize(src)
	if len(tokens) > lim.MaxNodes*4 {
		f.hitLimit(rYAMLLimit, dTooManyValues, lim.MaxNodes, -1)
		return false
	}
	anchors, aliases, flow, maxDepth, mappings, collectionWork := 0, 0, 0, 0, 0, 0
	var cols []int
	lastLine := -1
	// documents counts the documents in the stream from the tokens, because the parser merges empty ones: an explicit start marker
	// always begins one, and so does content that follows the end of one or comes before any marker.
	documents, inDocument := 0, false
	directiveLine := -1 // the line of a directive: the lexer gives its name and arguments as separate tokens
	for _, tk := range tokens {
		off := -1
		if tk.Position != nil {
			off = tk.Position.Offset
		}
		onDirective := tk.Position != nil && tk.Position.Line == directiveLine && tk.Type != token.DirectiveType
		if onDirective {
			// %TAG declares a handle for tags, which only has a use if tags are, and they are refused; refuse it too.
			if tk.Value == "TAG" && f.hit(rYAMLTag, off, dNone) {
				return false
			}
			continue
		}
		switch tk.Type {
		case token.DirectiveType:
			if tk.Position != nil {
				directiveLine = tk.Position.Line
			}
		case token.CommentType, token.SpaceType:
		case token.DocumentHeaderType:
			documents++
			inDocument = true
		case token.DocumentEndType:
			inDocument = false
		default:
			if !inDocument {
				documents++
				inDocument = true
			}
		}
		// These structural tokens bound block-map suffix copying and implicit
		// null insertion in block sequences and shorthand flow mappings. Count
		// conservatively, including valued entries, before constructing any AST.
		switch tk.Type {
		case token.MappingValueType, token.MappingKeyType, token.MappingStartType, token.CollectEntryType, token.SequenceEntryType:
			collectionWork++
			if collectionWork > lim.MaxCollectionWork {
				f.hitLimit(rYAMLLimit, dTooMuchCollectionWork, lim.MaxCollectionWork, off)
				return false
			}
		}
		switch tk.Type {
		case token.InvalidType:
			f.hit(rYAMLSyntax, off, dNone)
			return false
		case token.MappingValueType:
			// Each ':' needs at least a key and a value node, including implicit
			// nulls. Reject this lower bound before the parser recursively builds
			// and copies mappings; the tree walk still counts all remaining nodes.
			mappings++
			if mappings > lim.MaxNodes/2 {
				f.hitLimit(rYAMLLimit, dTooManyValues, lim.MaxNodes, off)
				return false
			}
		case token.TagType:
			if f.hit(rYAMLTag, off, dNone) {
				return false
			}
		case token.AnchorType:
			anchors++
			if anchors > lim.MaxAnchors {
				if f.hitLimit(rYAMLAnchor, dTooManyAnchors, lim.MaxAnchors, off) {
					return false
				}
			}
		case token.AliasType:
			aliases++
			if aliases > lim.MaxAliases {
				if f.hitLimit(rYAMLAnchor, dTooManyAliases, lim.MaxAliases, off) {
					return false
				}
			}
		case token.SequenceStartType, token.MappingStartType:
			flow++
		case token.SequenceEndType, token.MappingEndType:
			flow--
		}
		if tk.Position != nil && tk.Type != token.CommentType && tk.Type != token.SpaceType && tk.Position.Line != lastLine {
			// The first token on a line sits at its nesting level's column: a stack of columns is the nesting of block collections.
			lastLine = tk.Position.Line
			col := tk.Position.Column
			for len(cols) > 0 && col < cols[len(cols)-1] {
				cols = cols[:len(cols)-1]
			}
			if len(cols) == 0 || col > cols[len(cols)-1] {
				cols = append(cols, col)
			}
		}
		if d := len(cols) + flow; d > maxDepth {
			maxDepth = d
			if maxDepth > lim.MaxDepth+1 {
				f.hitLimit(rYAMLLimit, dTooDeep, lim.MaxDepth, off)
				return false
			}
		}
	}
	if documents > 1 && f.hit(rYAMLMulti, -1, dNone) {
		return false
	}
	file, err := parser.Parse(tokens, 0, parser.AllowDuplicateMapKey())
	if err != nil {
		f.hit(rYAMLSyntax, -1, dNone)
		return false
	}
	w := &yamlWalker{f: f, lim: lim, dup: f.active(rYAMLDup)}
	for _, doc := range file.Docs {
		if !w.node(doc.Body, 0) {
			return false
		}
	}
	return true
}

type yamlWalker struct {
	f     *finder
	lim   *YAMLLimits
	dup   bool
	nodes int
	fold  []byte
}

// node counts the nodes under n and checks depth and duplicate keys. Aliases are counted as one node and never followed.
func (w *yamlWalker) node(n ast.Node, depth int) bool {
	if n == nil {
		return true
	}
	w.nodes++
	if w.nodes > w.lim.MaxNodes {
		w.f.hitLimit(rYAMLLimit, dTooManyValues, w.lim.MaxNodes, -1)
		return false
	}
	switch x := n.(type) {
	case *ast.MappingNode:
		return w.mapping(x.Values, depth)
	case *ast.MappingValueNode:
		return w.mapping([]*ast.MappingValueNode{x}, depth)
	case *ast.SequenceNode:
		if depth+1 > w.lim.MaxDepth {
			w.f.hitLimit(rYAMLLimit, dTooDeep, w.lim.MaxDepth, -1)
			return false
		}
		for _, v := range x.Values {
			if !w.node(v, depth+1) {
				return false
			}
		}
	case *ast.AnchorNode:
		return w.node(x.Value, depth)
	case *ast.TagNode:
		return !w.f.hit(rYAMLTag, -1, dNone) && w.node(x.Value, depth)
	case *ast.MappingKeyNode:
		return w.node(x.Value, depth)
	}
	return true
}

func (w *yamlWalker) mapping(values []*ast.MappingValueNode, depth int) bool {
	if depth+1 > w.lim.MaxDepth {
		w.f.hitLimit(rYAMLLimit, dTooDeep, w.lim.MaxDepth, -1)
		return false
	}
	var seen map[string]struct{}
	if w.dup && len(values) > 1 {
		seen = make(map[string]struct{}, len(values))
	}
	for _, v := range values {
		if v == nil {
			continue
		}
		if seen != nil && v.Key != nil && v.Key.GetToken() != nil && !v.Key.IsMergeKey() {
			w.fold = appendFolded(w.fold[:0], []byte(v.Key.GetToken().Value), false)
			if _, dup := seen[string(w.fold)]; dup {
				if w.f.hit(rYAMLDup, -1, dNone) {
					return false
				}
			} else {
				seen[string(w.fold)] = struct{}{}
			}
		}
		if v.Key != nil && !w.node(v.Key, depth+1) {
			return false
		}
		if !w.node(v.Value, depth+1) {
			return false
		}
	}
	return true
}
