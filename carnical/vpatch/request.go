// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"sort"
	"strconv"
	"strings"
)

// Bounds on how much of a request is looked at. Every one of them keeps the cost of a request linear in its size, and none lets
// a request make the engine allocate more than a small multiple of what the proxy already holds for it.
const (
	// maxValue is the longest value matched whole. A longer one is matched as its first and its last maxValue bytes, so that a
	// payload placed after a long run of padding is still seen: the proxy limits a body that is not an upload to twice this.
	maxValue = 64 << 10
	// maxArgs is the most arguments (query, form, JSON and multipart together) that are kept.
	maxArgs = 1024
	// maxJSONDepth is how many levels of a JSON body make up an argument's name, and maxJSONKey how much of each key, so that a
	// name does not grow with the document; a value deeper than that is still an argument. maxJSONNest is how deep a JSON body
	// is followed at all (by default PHP reads 512 levels, Python and Jackson about 1,000, .NET 64), and maxJSONTokens how many
	// of its tokens are read: every token takes a byte, so no body the proxy lets through has more. Past either, the rest is
	// read for its strings.
	maxJSONDepth  = 24
	maxJSONKey    = 64
	maxJSONNest   = 1000
	maxJSONTokens = 2 * maxValue
	// maxMultipartBody is how much of a multipart body is walked, maxMultipartParts how many parts are read, and maxPartRead how
	// much of one part's content is kept.
	maxMultipartBody  = 8 << 20
	maxMultipartParts = 64
	maxPartRead       = 2 * maxValue
	// maxCookies and maxHeaderItems are how many cookies and header values are read. A request with more is reported
	// (matchCtx.overflow) rather than read in part without a word: browsers keep at most 180 cookies for a site, and PHP reads at
	// most 1,000.
	maxCookies     = 1024
	maxHeaderItems = 1024
)

// What a request has more of than is read, in matchCtx.overflow.
const (
	overflowCookies uint8 = 1 << iota
	overflowHeaders
)

// A view is one kind of value of the request, parsed once. vals are the values; for kinds that can be picked by name (arguments,
// cookies, headers) names is parallel to vals, and for arguments leaf is the last JSON key of a flattened path ("" for any other
// argument).
type view struct {
	ready uint32
	vals  []string
	names []string
	leaf  []string
	// hdr marks the header view, whose names compare with '_' and '-' alike (PHP and CGI make them one).
	hdr bool
	// php marks the views whose names PHP rewrites: arguments and cookies.
	php bool
}

func (v *view) reset() {
	clear(v.vals)
	clear(v.names)
	clear(v.leaf)
	v.vals, v.names, v.leaf = v.vals[:0], v.names[:0], v.leaf[:0]
}

// raw returns the view of kind k, building it on first use in this request.
func (c *matchCtx) raw(k int) *view {
	v := &c.views[k]
	if v.ready == c.epoch {
		return v
	}
	switch k {
	case kArgs, kArgNames, kFilenames, kUploads:
		c.buildArgs()
	case kCookies, kCookieNames:
		c.buildCookies()
	default:
		v.reset()
		v.ready = c.epoch
		c.buildSimple(k, v)
	}
	return v
}

func (c *matchCtx) buildSimple(k int, v *view) {
	req := c.req
	switch k {
	case kURI:
		s := req.Path
		if req.RawQuery != "" {
			s = req.Path + "?" + req.RawQuery
		}
		if s != "" {
			c.addCapped(v, "", s)
		}
	case kPath:
		if req.Path != "" {
			c.addCapped(v, "", req.Path)
		}
	case kQuery:
		if req.RawQuery != "" {
			c.addCapped(v, "", req.RawQuery)
		}
	case kMethod:
		c.buildMethod(v)
	case kBody:
		if c.multipartBody() {
			return
		}
		if s := c.bodyString(); s != "" {
			c.addCapped(v, "", s)
		}
	case kHeaders:
		c.buildHeaders(v)
	}
}

// buildMethod makes the method target: the method, and what a framework may use instead of it: the method-override headers and
// the _method argument. A request that says POST and means DELETE has both.
func (c *matchCtx) buildMethod(v *view) {
	req := c.req
	add := func(s string) {
		if len(s) > 64 {
			s = s[:64]
		}
		for _, x := range v.vals {
			if x == s {
				return
			}
		}
		v.vals = append(v.vals, s)
	}
	if req.Method != "" {
		add(req.Method)
	}
	for _, h := range [...]string{"X-Http-Method-Override", "X-Http-Method", "X-Method-Override"} {
		for _, val := range req.Header.Values(h) {
			add(val)
		}
	}
	args := c.raw(kArgs)
	for i, n := range args.names {
		if len(n) == 7 && strings.EqualFold(n, "_method") && len(v.vals) < 20 {
			add(args.vals[i])
		}
	}
}

// multipartBody reports whether the request's body is a multipart form that was read into its parts. Then the raw body is not
// offered as the body target: its fields are arguments, its file names are file names and its files are uploads, and matching
// the generic body signatures against the bytes of an uploaded photograph is how they come to block ordinary uploads. A
// multipart body that cannot be read (no boundary, no parts), or not all of it (a part Go's reader refuses, more parts than are
// read), is offered raw, so nothing hides behind a broken one.
func (c *matchCtx) multipartBody() bool {
	if len(c.req.Body) == 0 || !c.isMultipart() {
		return false
	}
	c.raw(kArgs)
	// Only the exact type is surely a multipart form to every parser; for one that only begins like it ("multipart/form-datax"),
	// PHP may read the body as raw input, so it is offered raw as well.
	return c.multipartOK && !c.multipartPartial && c.contentType() == "multipart/form-data"
}

// isMultipart reports whether the body is read as a multipart form. It goes by how the media type begins, as the rule set does:
// PHP cuts the type at a ',' or a space as well as at a ';', so "multipart/form-data, x" is a multipart form to it.
func (c *matchCtx) isMultipart() bool {
	return strings.HasPrefix(c.contentType(), "multipart/form-data")
}

func (v *view) add(name, val string) {
	v.vals = append(v.vals, val)
}

// addCapped adds a value, or its first and last maxValue bytes if it is longer.
func (c *matchCtx) addCapped(v *view, name, s string) {
	if len(s) <= maxValue {
		v.vals = append(v.vals, s)
		if v.names != nil || name != "" {
			v.names = append(v.names, name)
		}
		return
	}
	c.truncated = true
	tail := s[len(s)-maxValue:]
	if len(s) < 2*maxValue {
		tail = s[maxValue:]
	}
	for _, part := range [2]string{s[:maxValue], tail} {
		v.vals = append(v.vals, part)
		if v.names != nil || name != "" {
			v.names = append(v.names, name)
		}
	}
}

// contentType is the request's media type, worked out once.
func (c *matchCtx) contentType() string {
	if c.ctReady != c.epoch {
		c.ctReady = c.epoch
		c.ct = c.req.ContentType()
	}
	return c.ct
}

func (c *matchCtx) bodyString() string {
	if c.bodyReady != c.epoch {
		c.bodyReady = c.epoch
		c.bodyStr = string(c.req.Body)
	}
	return c.bodyStr
}

func (c *matchCtx) buildHeaders(v *view) {
	v.names = v.names[:0]
	v.hdr = true
	hdr := c.req.Header
	hostSeen := false
	n := 0
	for name, vals := range hdr {
		if len(name) == 4 && strings.EqualFold(name, "host") {
			hostSeen = true
		}
		n += len(vals)
	}
	if !hostSeen {
		// Go keeps Host out of the header map. It comes first, so that no number of other headers can leave it out. A request
		// with no Host has an empty one as far as the signatures are concerned: "Host is empty" is something they test.
		c.addCapped(v, "Host", c.req.Host)
	}
	if n <= maxHeaderItems {
		for name, vals := range hdr {
			for _, val := range vals {
				c.addCapped(v, name, val)
			}
		}
		return
	}
	// More values than are read: the request is reported, and the ones that are read do not depend on the map's order, so that
	// the same request is always matched the same way.
	c.truncated = true
	c.overflow |= overflowHeaders
	names := make([]string, 0, len(hdr))
	for name := range hdr {
		names = append(names, name)
	}
	sort.Strings(names)
	n = 0
	for _, name := range names {
		for _, val := range hdr[name] {
			if n++; n > maxHeaderItems {
				return
			}
			c.addCapped(v, name, val)
		}
	}
}

func (c *matchCtx) buildCookies() {
	vals, names := &c.views[kCookies], &c.views[kCookieNames]
	vals.php = true
	vals.reset()
	names.reset()
	vals.ready, names.ready = c.epoch, c.epoch
	n := 0
	for _, h := range c.req.Header.Values("Cookie") {
		for len(h) > 0 {
			var part string
			if i := strings.IndexByte(h, ';'); i >= 0 {
				part, h = h[:i], h[i+1:]
			} else {
				part, h = h, ""
			}
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if n++; n > maxCookies {
				c.truncated = true
				c.overflow |= overflowCookies
				return
			}
			name, val := part, ""
			if j := strings.IndexByte(part, '='); j >= 0 {
				name, val = strings.TrimSpace(part[:j]), part[j+1:]
			}
			// As the application reads them: a quoted value loses its quotes and a percent-escape is decoded, once.
			if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
				val = val[1 : len(val)-1]
			}
			name, val = formDecode(name), percentDecode(val, false)
			vals.vals = append(vals.vals, val)
			vals.names = append(vals.names, name)
			names.vals = append(names.vals, name)
		}
	}
}

// buildArgs parses the query string and the body into arguments, argument names, upload file names and upload contents. One
// pass fills all four, because they come from the same parse.
func (c *matchCtx) buildArgs() {
	for _, k := range [...]int{kArgs, kArgNames, kFilenames, kUploads} {
		v := &c.views[k]
		v.reset()
		v.ready = c.epoch
	}
	c.views[kArgs].php = true
	req := c.req
	c.multipartOK, c.multipartPartial = false, false
	if req.RawQuery != "" {
		q := req.RawQuery
		if len(q) <= maxValue {
			c.formPairs(q, false)
		} else {
			c.truncated = true
			c.formPairs(q[:maxValue], false)
			tail := q[len(q)-maxValue:]
			if len(q) < 2*maxValue {
				tail = q[maxValue:]
			}
			c.formPairs(tail, true)
		}
	}
	if len(req.Body) > 0 {
		c.bodyArgs()
	}
	c.joinRepeats()
}

// joinRepeats adds, for each argument name that was given more than once, its values joined by a comma and by a space: ASP.NET
// joins repeated parameters with commas, and a payload split across the repeats ("1/**/union/*" and "*/select 1") is whole
// again in the joined form.
func (c *matchCtx) joinRepeats() {
	args := &c.views[kArgs]
	n := len(args.vals)
	if n < 2 || n > 256 {
		return
	}
	var done [256]bool
	for i := 0; i < n; i++ {
		if done[i] || args.leaf[i] != "" {
			continue
		}
		var parts []string
		for j := i; j < n; j++ {
			if !done[j] && args.leaf[j] == "" && args.names[j] == args.names[i] {
				done[j] = true
				parts = append(parts, args.vals[j])
				if len(parts) == 20 {
					break
				}
			}
		}
		if len(parts) < 2 {
			continue
		}
		name := args.names[i]
		if !c.addArgOnly(name, clipValue(strings.Join(parts, ","))) || !c.addArgOnly(name, clipValue(strings.Join(parts, " "))) {
			return
		}
	}
}

func clipValue(s string) string {
	if len(s) > maxValue {
		return s[:maxValue]
	}
	return s
}

// addArg records one argument.
func (c *matchCtx) addArg(name, val, leaf string) bool {
	if len(val) > maxValue {
		head, tail := c.capped(val)
		return c.addArg(name, head, leaf) && c.addArg(name, tail, leaf)
	}
	args := &c.views[kArgs]
	if len(args.vals) >= maxArgs {
		c.truncated = true
		return false
	}
	args.vals = append(args.vals, val)
	args.names = append(args.names, name)
	args.leaf = append(args.leaf, leaf)
	names := &c.views[kArgNames]
	names.vals = append(names.vals, name)
	return true
}

// capped splits a value longer than maxValue into its first and last maxValue bytes (the rest of it, when it is under twice
// that), as addCapped does, so a payload after a long run of padding is still seen.
func (c *matchCtx) capped(s string) (head, tail string) {
	c.truncated = true
	if len(s) < 2*maxValue {
		return s[:maxValue], s[maxValue:]
	}
	return s[:maxValue], s[len(s)-maxValue:]
}

// formPairs reads name=value pairs separated by '&'. A ';' is part of the value, as it is for PHP, Java, ASP.NET, Go and Python's
// current parsers, so a command injected after one is not cut in half. Rack and some older stacks do split at ';', so a piece that
// has one is also offered split, as extra arguments. skipFirst drops the first pair, for text that begins part way through one.
func (c *matchCtx) formPairs(s string, skipFirst bool) {
	for len(s) > 0 {
		var pair string
		if i := strings.IndexByte(s, '&'); i >= 0 {
			pair, s = s[:i], s[i+1:]
		} else {
			pair, s = s, ""
		}
		if skipFirst {
			skipFirst = false
			continue
		}
		if pair == "" {
			continue
		}
		if !c.addPair(pair) {
			return
		}
		if strings.IndexByte(pair, ';') >= 0 {
			for rest := pair; rest != ""; {
				var sub string
				if i := strings.IndexByte(rest, ';'); i >= 0 {
					sub, rest = rest[:i], rest[i+1:]
				} else {
					sub, rest = rest, ""
				}
				if sub != "" && sub != pair && !c.addPair(sub) {
					return
				}
			}
		}
	}
}

func (c *matchCtx) addPair(pair string) bool {
	name, val := pair, ""
	if j := strings.IndexByte(pair, '='); j >= 0 {
		name, val = pair[:j], pair[j+1:]
	}
	return c.addArg(formDecode(name), formDecode(val), "")
}

// formDecode decodes a form component the way a framework does: '+' is a space and a valid %HH is a byte; anything else is left
// as it is. It returns its argument when there is nothing to decode.
func formDecode(s string) string {
	i := 0
	for i < len(s) && s[i] != '%' && s[i] != '+' {
		i++
	}
	if i == len(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(s[:i])
	for ; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			b.WriteByte(' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func (c *matchCtx) bodyArgs() {
	req := c.req
	ct := c.contentType()
	if c.isMultipart() {
		c.multipartArgs()
		if c.multipartOK && ct == "multipart/form-data" {
			return
		}
		// Not readable as multipart (no boundary, no parts): read it the way any other body is read, so that a payload is not
		// hidden by a content type that lies.
	}
	// A form by the same test as a multipart one: how the media type begins.
	if ct == "" || strings.HasPrefix(ct, "application/x-www-form-urlencoded") || looksLikeForm(req.Body) {
		c.formBody()
	}
	if strings.Contains(ct, "json") || looksLikeJSON(req.Body) {
		c.jsonArgs(req.Body)
	}
}

// looksLikeForm is the test for a body that is not declared as a form but may be read as one: text with an '=' near the start
// and no control characters. Plenty of applications read php://input or the body of a POST and split it themselves, whatever
// the Content-Type says, and an XML or text body with attributes is the usual way a payload is carried to one.
func looksLikeForm(b []byte) bool {
	head := b
	if len(head) > 512 {
		head = head[:512]
	}
	eq := false
	for _, x := range head {
		if x == '=' {
			eq = true
		}
		if x <= 8 || (x >= 0x0e && x <= 0x1f) {
			return false
		}
	}
	return eq
}

func looksLikeJSON(b []byte) bool {
	for _, x := range b {
		switch x {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		}
		return false
	}
	return false
}

// formBody reads the whole body: cutting it at a byte offset would leave the pair across the cut seen only in part. Splitting
// is linear, the number of arguments is bounded by maxArgs and a long value is capped as addArg caps it.
func (c *matchCtx) formBody() {
	c.formPairs(c.bodyString(), false)
}

// jsonArgs flattens a JSON document into arguments, with the names ModSecurity and Coraza give them (and the signature feeds
// are written for): "json" and then the object keys and array indices leading to the value, joined by dots, so that
// {"a":{"b":[7]}} is the argument json.a.b.0 with the value 7. Strings, numbers and booleans are the values; null is an empty
// string. Each argument's name is also an argument name. It does not recurse: the document is read as a stream of tokens, to
// its end, so that no padding (a long first value, deep nesting, thousands of empty arrays) puts a later key out of reach, and
// maxArgs bounds what is kept. A name is built only for a value that is kept (jsonName), so a level that holds none costs no
// string. A document that is malformed, or past maxJSONNest or maxJSONTokens, is read as far as it is good and the rest for its
// strings.
func (c *matchCtx) jsonArgs(body []byte) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var first [maxJSONDepth]jsonLevel
	levels := first[:0]
	curKey := ""
	// place says where the value that has just been read is, and counts it if it is an array element.
	place := func() (at jsonLevel) {
		if n := len(levels); n > 0 {
			if f := &levels[n-1]; f.obj {
				at.keyed, at.key, at.leaf = true, curKey, curKey
			} else {
				at.index, at.leaf = f.next, f.leaf
				f.next++
			}
		}
		return at
	}
	valueDone := func() {
		if n := len(levels); n > 0 && levels[n-1].obj {
			levels[n-1].wantKey = true
		}
	}
	// rest reads what follows the decoder's position for its strings, under the key the reading stopped at.
	rest := func() {
		leaf := ""
		if n := len(levels); n > 0 {
			leaf = levels[n-1].leaf
			if levels[n-1].obj {
				leaf = curKey
			}
		}
		c.looseStrings(body[min(int(dec.InputOffset()), len(body)):], leaf)
	}
	for tokens := 0; ; tokens++ {
		if tokens == maxJSONTokens {
			c.truncated = true
			rest()
			return
		}
		tok, err := dec.Token()
		if err != nil {
			if err != io.EOF {
				rest()
			}
			return
		}
		if n := len(levels); n > 0 && levels[n-1].obj && levels[n-1].wantKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				levels = levels[:n-1]
				valueDone()
				continue
			}
			key, ok := tok.(string)
			if !ok {
				return
			}
			curKey = key
			levels[n-1].wantKey = false
			continue
		}
		var leafVal string
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if len(levels) >= maxJSONNest {
					c.truncated = true
					rest()
					return
				}
				at := place()
				at.obj, at.wantKey = t == '{', t == '{'
				levels = append(levels, at)
			default:
				levels = levels[:len(levels)-1]
				valueDone()
			}
			continue
		case string:
			leafVal = t
		case json.Number:
			leafVal = t.String()
		case bool:
			leafVal = "false"
			if t {
				leafVal = "true"
			}
		}
		at := place()
		path, cut := jsonName(levels, &at)
		c.truncated = c.truncated || cut
		if !c.addJSONArg(path, leafVal, at.leaf) {
			return
		}
		valueDone()
	}
}

// jsonLevel is where a JSON value is, and for an object or array being read what it holds: it is under key in an object (keyed)
// or at index in an array, leaf is the last key on the way to it, and next is an array's next index.
type jsonLevel struct {
	obj, wantKey, keyed bool
	index, next         int
	key, leaf           string
}

// jsonName is the name of the value at in the innermost of levels: "json", the place of each of the levels below the document
// itself, and the value's own. Only the first maxJSONDepth levels are named, and a key only by its first maxJSONKey bytes, so
// that a name stays short however long the document's keys are; cut reports that something was left out. The value is still
// picked by its own key (its leaf), which is never cut.
func jsonName(levels []jsonLevel, at *jsonLevel) (name string, cut bool) {
	if len(levels) == 0 {
		return "json", false
	}
	var b strings.Builder
	b.WriteString("json")
	cut = len(levels) > maxJSONDepth
	for i := 1; i < len(levels) && i < maxJSONDepth; i++ {
		cut = writeJSONPlace(&b, &levels[i]) || cut
	}
	cut = writeJSONPlace(&b, at) || cut
	return b.String(), cut
}

func writeJSONPlace(b *strings.Builder, l *jsonLevel) (cut bool) {
	b.WriteByte('.')
	if !l.keyed {
		var digits [20]byte
		b.Write(strconv.AppendInt(digits[:0], int64(l.index), 10))
		return false
	}
	if len(l.key) > maxJSONKey {
		b.WriteString(l.key[:maxJSONKey])
		return true
	}
	b.WriteString(l.key)
	return false
}

// looseStrings reads what is left of a JSON document that stopped parsing: every string literal in it, as an argument named
// "json" and picked also by the key before it (leaf, to begin with), or, if a colon follows it, as an argument name. A request
// that is not valid JSON may still be read by an application with a more forgiving parser, so a payload after the first mistake
// is not left unexamined. It reads to the end, each byte about once, and decodes a literal only when it is kept.
func (c *matchCtx) looseStrings(b []byte, leaf string) {
	names := &c.views[kArgNames]
	keyAt, keyEnd := 0, 0 // the last key's literal, decoded when a value is kept under it
	pending := false
	for i := 0; i < len(b); i++ {
		if b[i] != '"' {
			continue
		}
		j := i + 1
		for j < len(b) && b[j] != '"' {
			if b[j] == '\\' {
				j++
			}
			j++
		}
		k := j + 1
		for k < len(b) && (b[k] == ' ' || b[k] == '\t' || b[k] == '\r' || b[k] == '\n') {
			k++
		}
		if k < len(b) && b[k] == ':' {
			keyAt, keyEnd, pending = i, j, true
			if len(names.vals) < maxArgs {
				leaf, pending = looseString(b, i, j), false
				names.vals = append(names.vals, leaf)
			}
		} else {
			if pending {
				leaf, pending = looseString(b, keyAt, keyEnd), false
			}
			if !c.addJSONArg("json", looseString(b, i, j), leaf) {
				return
			}
		}
		i = j
	}
}

// looseString is the text of the string literal that starts at b[i] and ends at b[j] (or runs off the end): decoded if it is
// valid JSON, and otherwise as it stands, without its quotes.
func looseString(b []byte, i, j int) string {
	var s string
	if json.Unmarshal(b[i:min(j+1, len(b))], &s) == nil {
		return s
	}
	return string(b[i+1 : min(j, len(b))])
}

// addJSONArg adds a flattened JSON value as an argument, and its name as an argument name.
func (c *matchCtx) addJSONArg(path, val, leaf string) bool {
	if len(val) > maxValue {
		head, tail := c.capped(val)
		return c.addJSONArg(path, head, leaf) && c.addJSONArg(path, tail, leaf)
	}
	args := &c.views[kArgs]
	if len(args.vals) >= maxArgs {
		c.truncated = true
		return false
	}
	args.vals = append(args.vals, val)
	args.names = append(args.names, path)
	args.leaf = append(args.leaf, leaf)
	c.views[kArgNames].vals = append(c.views[kArgNames].vals, path)
	return true
}

// multipartArgs reads a multipart/form-data body: ordinary fields are arguments, every part's field name is an argument name,
// and a part with a file name contributes the file name and, if some signature looks at uploads, its content. A part that only
// some parsers take for a file (filename* alone) is also a field.
func (c *matchCtx) multipartArgs() {
	req := c.req
	ct := req.Header.Get("Content-Type")
	_, params, err := mime.ParseMediaType(ct)
	if i := strings.IndexByte(ct, ';'); err != nil && i >= 0 {
		// A type Go refuses and PHP reads ("multipart/form-data, x; boundary=..."): the boundary is still in its parameters.
		_, params, err = mime.ParseMediaType("multipart/form-data" + ct[i:])
	}
	if err != nil || params["boundary"] == "" {
		return
	}
	body := req.Body
	if len(body) > maxMultipartBody {
		// The parts past the cut reach the application unread, so the raw body is offered too (multipartBody).
		c.truncated, c.multipartPartial = true, true
		body = body[:maxMultipartBody]
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	files, names := &c.views[kFilenames], &c.views[kArgNames]
	uploads := &c.views[kUploads]
	for n := 0; n < maxMultipartParts; n++ {
		part, err := mr.NextPart()
		if err != nil {
			// io.EOF is the closing boundary. Any other error after a part that was read is a part Go's reader cannot read (a
			// header line with no colon, a body that ends before its boundary), which a more forgiving parser still reads, as
			// it reads the parts after it: the raw body is offered too.
			if err != io.EOF && c.multipartOK {
				c.truncated, c.multipartPartial = true, true
			}
			return
		}
		c.multipartOK = true
		name := ""
		filename, hasFile, alsoField := "", false, false
		if cd := part.Header.Get("Content-Disposition"); cd != "" {
			if _, p, err := mime.ParseMediaType(cd); err == nil {
				// The filename parameter, not the word anywhere in the header: a part with note="filename" is a field to PHP and
				// Go, and its content is an argument. Go's mime also decodes filename* into it, which makes a file of a part
				// that PHP, reading filename alone, takes for a field: such a part is read as both.
				name = p["name"]
				filename, hasFile = p["filename"], p["filename"] != ""
				alsoField = hasFile && !plainParam(cd, "filename")
			} else {
				// A header Go refuses (a parameter given twice, a quote left open) is still read by PHP: the part is read as PHP
				// reads it, and the raw body is offered too, for a parser that reads it another way.
				name, filename = phpDisposition(cd)
				hasFile = filename != ""
				c.truncated, c.multipartPartial = true, true
			}
		}
		if len(names.vals) < maxArgs {
			names.vals = append(names.vals, name)
		}
		if hasFile {
			files.vals = append(files.vals, filename)
			if !c.snap.needUploads && !alsoField {
				continue
			}
			content := c.readEnds(part)
			if c.snap.needUploads && len(content) > 0 {
				c.addCapped(uploads, "", content)
			}
			if alsoField && !c.addArgOnly(name, content) {
				return
			}
			continue
		}
		if !c.addArgOnly(name, c.readEnds(part)) {
			return
		}
	}
	// As many parts as are read: if there is another, or one that cannot be read, the rest reach the application unread unless
	// the raw body is offered too.
	if _, err := mr.NextPart(); err != io.EOF {
		c.truncated, c.multipartPartial = true, true
	}
}

// plainParam reports whether a header value has the parameter key written plainly, outside quotes: the key right after a ';'
// (and any spaces) and the '=' right after the key. That is the one form every parser reads as that parameter; PHP, for one,
// reads filename and not filename*, wants nothing between the key and the '=', and takes ' as a quote as well as ".
func plainParam(h, key string) bool {
	var quote byte
	for i := 0; i < len(h); i++ {
		switch ch := h[i]; {
		case quote != 0:
			if ch == '\\' {
				i++
			} else if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == ';':
			j := i + 1
			for j < len(h) && (h[j] == ' ' || h[j] == '\t') {
				j++
			}
			if j+len(key) < len(h) && h[j+len(key)] == '=' && strings.EqualFold(h[j:j+len(key)], key) {
				return true
			}
		}
	}
	return false
}

// phpSpace is what C's isspace takes for white space.
const phpSpace = " \t\n\v\f\r"

// phpDisposition reads the name and filename parameters of a Content-Disposition as PHP does: the header splits at each ';'
// outside quotes, a key runs to its '=', and a value runs to its closing quote or, unquoted, to the next white space. The last of
// each wins.
func phpDisposition(cd string) (name, filename string) {
	for cd = strings.TrimLeft(cd, phpSpace); cd != ""; cd = strings.TrimLeft(cd, phpSpace) {
		var pair string
		pair, cd = phpWord(cd, ';')
		if strings.IndexByte(pair, '=') < 0 {
			continue
		}
		key, val := phpWord(pair, '=')
		switch {
		case strings.EqualFold(key, "name"):
			name = phpValue(val)
		case strings.EqualFold(key, "filename"):
			filename = phpValue(val)
		}
	}
	return name, filename
}

// phpWord splits s at the first stop byte outside quotes (" or '), and drops the stop bytes that follow it.
func phpWord(s string, stop byte) (word, rest string) {
	i := 0
	for i < len(s) && s[i] != stop {
		q := s[i]
		i++
		if q != '"' && q != '\'' {
			continue
		}
		for ; i < len(s) && s[i] != q; i++ {
			if s[i] == '\\' && i+1 < len(s) && s[i+1] == q {
				i++
			}
		}
		if i < len(s) {
			i++
		}
	}
	word, rest = s[:i], s[i:]
	for rest != "" && rest[0] == stop {
		rest = rest[1:]
	}
	return word, rest
}

// phpValue is a parameter value as PHP reads it: after any white space, quoted to the closing quote (or the end), where a
// backslash escapes the quote or itself, or unquoted to the next white space.
func phpValue(s string) string {
	s = strings.TrimLeft(s, phpSpace)
	quote := byte(0)
	if s != "" && (s[0] == '"' || s[0] == '\'') {
		quote, s = s[0], s[1:]
	} else if i := strings.IndexAny(s, phpSpace); i >= 0 {
		s = s[:i]
	}
	var b strings.Builder
	for i := 0; i < len(s) && (quote == 0 || s[i] != quote); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '\\' || quote != 0 && s[i+1] == quote) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// readEnds reads a part to its end and keeps its first and last maxValue bytes, so a payload after a long run of padding is
// seen without holding the whole part.
func (c *matchCtx) readEnds(r io.Reader) string {
	head, _ := io.ReadAll(io.LimitReader(r, maxPartRead)) // grows with the part: a small part costs a small buffer
	if len(head) < maxPartRead {
		return string(head)
	}
	// Longer than twice maxValue: keep the newest maxValue bytes in a ring while the rest is read.
	c.truncated = true
	ring := make([]byte, maxValue)
	pos, filled := 0, false
	buf := make([]byte, 32<<10)
	for {
		m, err := r.Read(buf)
		for data := buf[:m]; len(data) > 0; {
			k := copy(ring[pos:], data)
			data = data[k:]
			if pos += k; pos == len(ring) {
				pos, filled = 0, true
			}
		}
		if err != nil {
			break
		}
	}
	tail := head[maxValue:] // fewer than maxValue more bytes: the tail is the end of head plus what was read
	if filled {
		tail = append(append([]byte(nil), ring[pos:]...), ring[:pos]...)
	} else if pos > 0 {
		tail = append(append([]byte(nil), head[maxValue+pos:]...), ring[:pos]...)
	}
	return string(head[:maxValue]) + string(tail)
}

// addArgOnly adds an argument whose name is already in the argument names.
func (c *matchCtx) addArgOnly(name, val string) bool {
	if len(val) > maxValue {
		head, tail := c.capped(val)
		return c.addArgOnly(name, head) && c.addArgOnly(name, tail)
	}
	args := &c.views[kArgs]
	if len(args.vals) >= maxArgs {
		c.truncated = true
		return false
	}
	args.vals = append(args.vals, val)
	args.names = append(args.names, name)
	args.leaf = append(args.leaf, "")
	return true
}

// nameOK reports whether item i of v is the one a named target picks: the argument, cookie or header with that name, compared
// without regard to case, with '_' and '-' alike for a header, and for an argument or cookie also by the names PHP would give it
// ("a.b" is a_b, "a[b]" is a). A JSON value is picked by its full path or by its last key.
func nameOK(v *view, i int, want string) bool {
	if i < len(v.names) {
		n := v.names[i]
		if strings.EqualFold(n, want) {
			return true
		}
		if v.hdr && strings.IndexByte(n, '_') >= 0 && strings.EqualFold(strings.ReplaceAll(n, "_", "-"), want) {
			return true
		}
		if v.php && (i >= len(v.leaf) || v.leaf[i] == "") && phpNameMatches(n, want) {
			return true
		}
	}
	return i < len(v.leaf) && v.leaf[i] != "" && strings.EqualFold(v.leaf[i], want)
}

// phpNameMatches reports whether PHP would file a parameter called name under want: it turns the dots and spaces of a name into
// underscores and reads "a[b][c]" as the variable a holding an array. A signature for "a_b" or for "a" must see them.
func phpNameMatches(name, want string) bool {
	if strings.IndexAny(name, " .[") < 0 {
		return false
	}
	trim := strings.TrimLeft(name, " ")
	if open := strings.IndexByte(trim, '['); open > 0 && strings.IndexByte(trim[open:], ']') > 0 {
		base := trim[:open]
		if strings.EqualFold(base, want) || strings.EqualFold(underscores(base, " ."), want) {
			return true
		}
	}
	return strings.EqualFold(underscores(trim, " .["), want)
}

func underscores(s, set string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(set, r) {
			return '_'
		}
		return r
	}, s)
}
