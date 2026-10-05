// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
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
	// maxJSONDepth and maxJSONNodes bound the flattening of a JSON body.
	maxJSONDepth = 24
	maxJSONNodes = 16384
	// maxMultipartBody is how much of a multipart body is walked, maxMultipartParts how many parts are read, and maxPartRead how
	// much of one part's content is kept.
	maxMultipartBody  = 8 << 20
	maxMultipartParts = 64
	maxPartRead       = 2 * maxValue
	maxCookies        = 256
	maxHeaderItems    = 1024
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
// multipart body that cannot be read (no boundary, no parts) is offered raw, so nothing hides behind a broken one.
func (c *matchCtx) multipartBody() bool {
	if len(c.req.Body) == 0 || c.contentType() != "multipart/form-data" {
		return false
	}
	c.raw(kArgs)
	return c.multipartOK
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
	hostSeen := false
	n := 0
	for name, vals := range c.req.Header {
		if len(name) == 4 && strings.EqualFold(name, "host") {
			hostSeen = true
		}
		for _, val := range vals {
			if n++; n > maxHeaderItems {
				c.truncated = true
				return
			}
			c.addCapped(v, name, val)
		}
	}
	if !hostSeen {
		// A request with no Host has an empty one as far as the signatures are concerned: "Host is empty" is something they test.
		c.addCapped(v, "Host", c.req.Host)
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
	c.multipartOK = false
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
	if ct == "multipart/form-data" {
		c.multipartArgs()
		if c.multipartOK {
			return
		}
		// Not readable as multipart (no boundary, no parts): read it the way any other body is read, so that a payload is not
		// hidden by a content type that lies.
	}
	if ct == "" || ct == "application/x-www-form-urlencoded" || looksLikeForm(req.Body) {
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

func (c *matchCtx) formBody() {
	s := c.bodyString()
	if len(s) <= maxValue {
		c.formPairs(s, false)
		return
	}
	c.truncated = true
	c.formPairs(s[:maxValue], false)
	tail := s[len(s)-maxValue:]
	if len(s) < 2*maxValue {
		tail = s[maxValue:]
	}
	c.formPairs(tail, true)
}

// jsonArgs flattens a JSON document into arguments, with the names ModSecurity and Coraza give them (and the signature feeds
// are written for): "json" and then the object keys and array indices leading to the value, joined by dots, so that
// {"a":{"b":[7]}} is the argument json.a.b.0 with the value 7. Strings, numbers and booleans are the values; null is an empty
// string. Each argument's name is also an argument name. It does not recurse: the document is read as a stream of tokens, and a
// document that is malformed, too deep or too big is read as far as it is good.
func (c *matchCtx) jsonArgs(body []byte) {
	if len(body) > maxValue {
		c.truncated = true
		body = body[:maxValue]
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	type frame struct {
		obj     bool
		wantKey bool
		path    string
		leaf    string
		idx     int
	}
	var stack [maxJSONDepth]frame
	sp := 0
	curKey := ""
	// pathOf names the value that has just been read, and counts it if it is an array element.
	pathOf := func() (path, leaf string) {
		if sp == 0 {
			return "json", ""
		}
		f := &stack[sp-1]
		if f.obj {
			return f.path + "." + curKey, curKey
		}
		n := f.idx
		f.idx++
		return f.path + "." + strconv.Itoa(n), f.leaf
	}
	valueDone := func() {
		if sp > 0 && stack[sp-1].obj {
			stack[sp-1].wantKey = true
		}
	}
	for nodes := 0; ; nodes++ {
		if nodes > maxJSONNodes {
			c.truncated = true
			return
		}
		tok, err := dec.Token()
		if err != nil {
			if err != io.EOF {
				c.looseStrings(body[min(int(dec.InputOffset()), len(body)):])
			}
			return
		}
		if sp > 0 && stack[sp-1].obj && stack[sp-1].wantKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				sp--
				valueDone()
				continue
			}
			key, ok := tok.(string)
			if !ok {
				return
			}
			curKey = key
			stack[sp-1].wantKey = false
			continue
		}
		var leafVal string
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if sp >= maxJSONDepth {
					c.truncated = true
					return
				}
				path, leaf := pathOf()
				stack[sp] = frame{obj: t == '{', wantKey: t == '{', path: path, leaf: leaf}
				sp++
			default:
				sp--
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
		path, leaf := pathOf()
		if !c.addJSONArg(path, leafVal, leaf) {
			return
		}
		valueDone()
	}
}

// looseStrings reads what is left of a JSON document that stopped parsing: every string literal in it, as an argument named
// "json" (or, if a colon follows it, as an argument name). A request that is not valid JSON may still be read by an application
// with a more forgiving parser, so a payload after the first mistake is not left unexamined.
func (c *matchCtx) looseStrings(b []byte) {
	for i, n := 0, 0; i < len(b) && n < maxJSONNodes; i++ {
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
		end := min(j, len(b))
		val := string(b[i+1 : end])
		var un string
		if json.Unmarshal(b[i:min(j+1, len(b))], &un) == nil {
			val = un
		}
		k := j + 1
		for k < len(b) && (b[k] == ' ' || b[k] == '\t' || b[k] == '\r' || b[k] == '\n') {
			k++
		}
		if k < len(b) && b[k] == ':' {
			if names := &c.views[kArgNames]; len(names.vals) < maxArgs {
				names.vals = append(names.vals, val)
			}
		} else if !c.addJSONArg("json", val, "") {
			return
		}
		i = j
		n++
	}
}

// addJSONArg adds a flattened JSON value as an argument, and its name as an argument name.
func (c *matchCtx) addJSONArg(path, val, leaf string) bool {
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
// and a part with a file name contributes the file name and, if some signature looks at uploads, its content.
func (c *matchCtx) multipartArgs() {
	req := c.req
	_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || params["boundary"] == "" {
		return
	}
	body := req.Body
	if len(body) > maxMultipartBody {
		c.truncated = true
		body = body[:maxMultipartBody]
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	files, names := &c.views[kFilenames], &c.views[kArgNames]
	uploads := &c.views[kUploads]
	for n := 0; n < maxMultipartParts; n++ {
		part, err := mr.NextPart()
		if err != nil {
			return
		}
		c.multipartOK = true
		name := ""
		filename, hasFile := "", false
		if cd := part.Header.Get("Content-Disposition"); cd != "" {
			if _, p, err := mime.ParseMediaType(cd); err == nil {
				name = p["name"]
				filename, hasFile = p["filename"], p["filename"] != "" || strings.Contains(strings.ToLower(cd), "filename")
			}
		}
		if len(names.vals) < maxArgs {
			names.vals = append(names.vals, name)
		}
		if hasFile {
			files.vals = append(files.vals, filename)
			if c.snap.needUploads {
				content, _ := io.ReadAll(io.LimitReader(part, maxPartRead))
				if len(content) > 0 {
					c.addCapped(uploads, "", string(content))
				}
			}
			continue
		}
		content, _ := io.ReadAll(io.LimitReader(part, maxPartRead))
		val := string(content)
		if len(val) > maxValue {
			c.truncated = true
			val = val[:maxValue]
		}
		if !c.addArgOnly(name, val) {
			return
		}
	}
	c.truncated = true
}

// addArgOnly adds an argument whose name is already in the argument names.
func (c *matchCtx) addArgOnly(name, val string) bool {
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
