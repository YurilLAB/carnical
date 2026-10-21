package proxy

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// UploadPolicy is what is refused in a file upload before the rule set sees it. The rule set checks a file's name; it
// does not read what is inside it, and a web shell is a file whose content is a script. Most exploited WordPress
// plugins were hacked by uploading one.
type UploadPolicy struct {
	// AllowExecutableNames lets through names with a script extension anywhere in them (shell.php, shell.php.jpg,
	// shell.php. , shell.php;.jpg) and server configuration files (.htaccess, web.config).
	AllowExecutableNames bool
	// AllowScriptContent lets through a file whose content holds a PHP, ASP or JSP opening tag.
	AllowScriptContent bool
	// AllowUploadProgress lets through a multipart body with PHP's session upload progress field, which PHP2Shell goes
	// through (see php2shell.go).
	AllowUploadProgress bool
}

var (
	// Every filename=, filename*= and filename*N= in the body, wherever it is: if the proxy and the application
	// disagree about where one part ends and the next begins, a name that only one of them sees is still found. The
	// value is read as most parsers read it, double-quoted up to the next quote or bare up to a ';', a space or a
	// quote; executablePHPName reads it again as PHP does.
	filenameRe = regexp.MustCompile(`(?i)filename(\*[0-9]*\*?)?[ \t]*=[ \t]*(?:"([^"\r\n]*)"|([^;\s"]*))`)
	// Opening tags of server-side scripts. <?xml is not one.
	scriptRe = regexp.MustCompile(`(?i)<\?php|<\?=|<%@|<%=|<script\s+language\s*=\s*["']?php`)
	phpExt   = regexp.MustCompile(`^php[0-9]?$`)
	// A parameter whose name starts with filename*, extended (filename*=) or continued (filename*0=), which Go reads
	// and PHP does not; and any file name at all, without which no part is a file to anyone.
	extendedFilenameRe = regexp.MustCompile(`(?i)filename[ \t]*\*`)
	anyFilenameRe      = regexp.MustCompile(`(?i)filename`)
)

var executableExt = map[string]bool{
	"phtml": true, "pht": true, "phps": true, "phar": true, "pgif": true, "shtml": true, "shtm": true, "inc": false,
	"asp": true, "aspx": true, "ashx": true, "asmx": true, "asa": true, "cer": true, "cdx": true,
	"jsp": true, "jspx": true, "jspa": true, "jsw": true, "jsv": true, "jspf": true,
	"cgi": true, "pl": true, "py": true, "sh": true, "bash": true, "exe": true, "dll": true, "bat": true, "cmd": true,
}

var executableNames = map[string]bool{".htaccess": true, ".htpasswd": true, ".user.ini": true, "web.config": true, "php.ini": true}

// executableName reports whether an uploaded file's name would be run, or would change how the server runs files.
// extended says the name is the value of filename*=, which RFC 5987 encodes as charset'language'percent-encoded. strict
// says the name is in a part's headers, where one that does not parse is refused.
func executableName(raw string, extended, strict bool) bool {
	name := raw
	if extended {
		// filename*=UTF-8''%73hell.php. Browsers do not send it in a form, so one that does not parse is refused rather
		// than guessed at.
		_, rest, ok := strings.Cut(name, "'")
		if ok {
			_, name, ok = strings.Cut(rest, "'")
		}
		dec, err := url.PathUnescape(name)
		if !ok || err != nil {
			return strict
		}
		name = dec
	} else if dec, err := url.PathUnescape(name); err == nil {
		name = dec
	}
	name = strings.ToLower(name)
	if strings.IndexFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return true // a NUL or control character in a name is only ever there to end it early
	}
	// Quotes are dropped, as applications that clean a name drop them: x.php" is saved as x.php.
	name = strings.Map(func(r rune) rune {
		if r == '"' || r == '\'' {
			return -1
		}
		return r
	}, name)
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimRight(name, " .") // Windows ignores trailing dots and spaces
	name = strings.TrimSuffix(name, "::$data")
	if executableNames[name] {
		return true
	}
	// Any component counts, because Apache runs a file with a script extension anywhere in its name.
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return r == '.' || r == ';' }) {
		part = strings.TrimSpace(part)
		if phpExt.MatchString(part) || executableExt[part] {
			return true
		}
	}
	return false
}

// readAsMultipart says whether the rule set will read the body as multipart, by the same rule as readAsForm. A type
// that Go's parser refuses is still multipart to the rules and to PHP, so it is not passed on as something else.
func readAsMultipart(h http.Header) bool {
	v := h.Values("Content-Type")
	return len(v) > 0 && strings.HasPrefix(strings.TrimSpace(strings.ToLower(v[0])), "multipart/form-data")
}

// uploadBoundary returns the boundary of a multipart/form-data type, if every parser finds the same one. Go's parser
// refuses a type that does not follow the grammar, where PHP takes the first "boundary" anywhere in it, so the type
// must parse and PHP's reading must give the same value: "multipart/form-data, boundary=XX" and
// "multipart/form-data; xboundary=YY; boundary=XX" are both refused.
func uploadBoundary(contentType string) (string, bool) {
	mt, params, err := mime.ParseMediaType(contentType)
	boundary := params["boundary"]
	if err != nil || mt != "multipart/form-data" || boundary == "" {
		return "", false
	}
	return boundary, boundary == searchedBoundary(contentType)
}

// searchedBoundary is the boundary PHP finds in a Content-Type: after the first "boundary" (in lower case if there is
// one, in any case if not) and the next "=", the value up to its closing quote, or up to a ';' or ','.
func searchedBoundary(contentType string) string {
	i := strings.Index(contentType, "boundary")
	if i < 0 {
		lower := []byte(contentType) // ASCII only, so that it lines up byte for byte
		for k, c := range lower {
			if 'A' <= c && c <= 'Z' {
				lower[k] = c + 'a' - 'A'
			}
		}
		i = bytes.Index(lower, []byte("boundary"))
	}
	if i < 0 {
		return ""
	}
	_, value, ok := strings.Cut(contentType[i:], "=")
	if !ok {
		return ""
	}
	if quoted, ok := strings.CutPrefix(value, `"`); ok {
		value, _, _ = strings.Cut(quoted, `"`)
		return value
	}
	if end := strings.IndexAny(value, ";,"); end >= 0 {
		value = value[:end]
	}
	return value
}

// scanUpload looks through a multipart body. It returns what to report, or id 0 if nothing is wrong.
func scanUpload(body []byte, boundary string, p UploadPolicy) (id int, reason string) {
	if p.AllowExecutableNames && p.AllowScriptContent {
		return 0, ""
	}
	delim := []byte("--" + boundary)
	if nulInHeaders(body, delim) {
		// With script names allowed, the refusal still keeps PHP from finding a file's content where the proxy does not.
		if p.AllowExecutableNames {
			return idUploadScript, "an upload's part headers hold a NUL byte, which hides where a file's content starts from some parsers"
		}
		return idUploadName, "an upload's part headers hold a NUL byte, which hides a file's name from some parsers"
	}
	if !p.AllowExecutableNames {
		const why = "an uploaded file has the name of a script or a server configuration file"
		// A name that parsers could read differently is refused only where a parser reads headers: the same text in a
		// file's content, such as a saved mail or a log, is not a name to anyone.
		heads := inHeaders{blocks: newHeaderBlocks(body, delim)}
		for _, m := range filenameRe.FindAllSubmatchIndex(body, -1) {
			strict := heads.at(m[0])
			var key []byte // the '*' and what follows it, if there is one
			if m[2] >= 0 {
				key = body[m[2]:m[3]]
			}
			if bytes.ContainsAny(key, "0123456789") {
				if strict {
					return idUploadName, why // RFC 2231 splits a name over filename*0=, filename*1=: no browser sends it
				}
				continue
			}
			v := 6 // the bare value, or else the double-quoted one
			if m[4] >= 0 {
				v = 4
			}
			name := body[m[v]:m[v+1]]
			if executableName(string(name), len(key) > 0, strict) {
				return idUploadName, why
			}
		}
		if executablePHPName(body, delim) {
			return idUploadName, why
		}
	}
	if p.AllowScriptContent || boundary == "" {
		return 0, ""
	}
	if scriptInFile(body, delim) {
		return idUploadScript, "an uploaded file contains the opening tag of a server-side script"
	}
	return 0, ""
}

// multipartParts reads the parts of a multipart body as the rule set and PHP do, and returns what to refuse, or 0.
//
// A part is a file to Go's parser, and so to the rule set, when its Content-Disposition parses and names one as Go
// reads it, and to PHP only when it has a non-empty plain filename parameter as PHP reads it: PHP knows nothing of
// filename* (RFC 7578 forbids it in form data), matches "filename" only right before its '=', and reads parameters Go
// refuses to parse, such as a repeated one. Where they disagree the part's content is a file to one and a field to the
// other, so either the rules do not read as an argument what the application takes for one, or the rules read as an
// argument what the form limit does not count; it is refused (idAmbiguousType).
//
// Everything in the body but the content of its files (the fields the rules read as arguments, names, file names, part
// headers and boundaries) is held to the form body limit, as ModSecurity holds it to SecRequestBodyNoFilesLimit: only
// files may make a body larger (idMultipartFields). A body over the limit that cannot be read to its end as parts is
// over it: what was not read could be anything.
func multipartParts(body []byte, boundary string, limit int64) int {
	over := int64(len(body)) > limit // otherwise what is not a file is smaller than the whole body
	if !over && !anyFilenameRe.Match(body) {
		return 0
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var files int64 // the content of the parts that are files to all of them
	for {
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			if over {
				return idMultipartFields
			}
			return 0
		}
		cd := part.Header.Get("Content-Disposition")
		file := phpFileName(cd)
		if file != goFileName(part, cd) {
			return idAmbiguousType
		}
		n, err := io.Copy(io.Discard, part)
		if err != nil {
			if over {
				return idMultipartFields
			}
			return 0
		}
		if file {
			files += n
		}
	}
	if over && int64(len(body))-files > limit {
		return idMultipartFields
	}
	return 0
}

// goFileName reports whether Go and the rule set take a part for a file: its Content-Disposition parses, and names a
// file or has a filename* parameter, which the rule set decodes in charsets Go does not. Neither reads a file name in
// a Content-Disposition that does not parse.
func goFileName(part *multipart.Part, cd string) bool {
	if _, _, err := mime.ParseMediaType(cd); err != nil {
		return false
	}
	return part.FileName() != "" || extendedFilenameRe.MatchString(cd)
}

// phpFileName reports whether PHP finds a file name that is not empty in a Content-Disposition: the value of its last
// parameter named "filename", in any case. PHP splits the parameters at ';' and each at its first '=', outside quotes
// of either kind, skips the spaces before a parameter and not those after its name, and reads a value after any spaces,
// up to its closing quote if it is quoted. An empty name is an empty upload to PHP (UPLOAD_ERR_NO_FILE), whose content
// it discards, and a field to Go and the rules, so the part is counted as a field.
func phpFileName(cd string) bool {
	file := false
	for rest := cd; rest != ""; {
		var pair string
		pair, rest = phpWord(rest, ';')
		pair = strings.TrimLeft(pair, " \t\r\n\v\f")
		key, value := phpWord(pair, '=')
		if len(key) == len(pair) || !strings.EqualFold(key, "filename") {
			continue // no '=', or another parameter
		}
		value = strings.TrimLeft(value, " \t\r\n\v\f")
		if q := value; q != "" && (q[0] == '"' || q[0] == '\'') {
			value, _ = phpWord(q[1:], q[0])
		}
		file = value != ""
	}
	return file
}

// phpWord splits s at the first stop that is outside quotes, as PHP's php_ap_getword does: a quote of either kind runs
// to the same quote, and a backslash before that quote does not end it. It returns s and "" when there is no stop.
func phpWord(s string, stop byte) (word, rest string) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case stop:
			return s[:i], s[i+1:]
		case '"', '\'':
			for i++; i < len(s) && s[i] != c; i++ {
				if s[i] == '\\' && i+1 < len(s) && s[i+1] == c {
					i++
				}
			}
		}
	}
	return s, ""
}

// headerBlocks finds, in order, the places a multipart parser could read as a part's header block, since the
// application's parser may not find the parts where the proxy would. Parsers take a delimiter only at the start of a
// line and end a part's headers at the first blank line, CRLF or LF, and PHP reads a delimiter line among the headers
// as one more header line. So a block may start at the start of the body or after any delimiter, and runs to the
// first blank line after it, or on to the first CRLF blank line before the next delimiter (or, as before, LF blank
// line), as a parser that knows only one of them reads it.
type headerBlocks struct {
	body, delim        []byte
	crlfBlank, lfBlank seeker
	start              int // where the next block starts, or -1 after the last
}

func newHeaderBlocks(body, delim []byte) headerBlocks {
	return headerBlocks{
		body: body, delim: delim,
		crlfBlank: seeker{body: body, at: -1, find: func(b []byte) int { return bytes.Index(b, []byte("\n\r\n")) }},
		lfBlank:   seeker{body: body, at: -1, find: func(b []byte) int { return bytes.Index(b, []byte("\n\n")) }},
	}
}

// next returns the next block: it runs from start to head, and the content after it starts at content. A block whose
// headers do not end runs to the end of the body, with content -1, and is the last.
func (h *headerBlocks) next() (start, head, content int) {
	start, h.start = h.start, -1
	next := len(h.body)
	if i := bytes.Index(h.body[start:], h.delim); i >= 0 {
		next = start + i
		h.start = next + len(h.delim)
	}
	blank, sep := h.crlfBlank.next(start), 3
	if lf := h.lfBlank.next(start); lf < blank {
		blank, sep = lf, 2
	}
	if blank == len(h.body) {
		h.start = -1 // no header block ends after here
		return start, len(h.body), -1
	}
	head = blank
	if hd, _, ok := cutHeader(h.body[start:next]); ok {
		head = max(head, start+len(hd))
	}
	return start, head, blank + sep
}

// inHeaders says, for places asked about in increasing order, whether one is in a header block.
type inHeaders struct {
	blocks headerBlocks
	end    int // where the blocks taken in so far end
}

func (h *inHeaders) at(i int) bool {
	for h.blocks.start >= 0 && h.blocks.start <= i {
		_, head, _ := h.blocks.next()
		h.end = max(h.end, head)
	}
	return i < h.end
}

// nulInHeaders reports a NUL byte in a header block. PHP reads header lines as C strings, so a NUL ends a line early:
// the line after it can be joined to the one before, and a line that starts with one ends the headers. Where the
// proxy and PHP would then read a name or a part differently, the body is refused; no client sends a NUL there.
func nulInHeaders(body, delim []byte) bool {
	blocks := newHeaderBlocks(body, delim)
	checked := 0 // blocks overlap, so no byte is looked at twice
	for blocks.start >= 0 {
		start, head, content := blocks.next()
		if content >= 0 {
			head = min(head, content) // PHP's headers end at the first blank line, LF or CRLF
		}
		if from := max(start, checked); from < head && bytes.IndexByte(body[from:head], 0) >= 0 {
			return true
		}
		checked = max(checked, head)
	}
	return false
}

// scriptInFile reports a script opening tag in anything a multipart parser could take for a file's content: what
// follows the first blank line after the start of a header block (see headerBlocks) whose headers hold "filename". The
// content runs to the next delimiter every parser ends a part at: one after a CRLF and followed by a CRLF or "--".
// Stretches that overlap are matched as one, so no byte is matched twice.
func scriptInFile(body, delim []byte) bool {
	line := append([]byte("\r\n"), delim...)
	names := seeker{body: body, at: -1, find: indexFilename}
	ends := seeker{body: body, at: -1, find: func(b []byte) int {
		for i := 0; ; i++ {
			j := bytes.Index(b[i:], line)
			if j < 0 {
				return -1
			}
			i += j
			if rest := b[i+len(line):]; bytes.HasPrefix(rest, []byte("\r\n")) || bytes.HasPrefix(rest, []byte("--")) {
				return i
			}
		}
	}}
	blocks := newHeaderBlocks(body, delim)
	from, to := 0, 0 // file content found and not yet matched
	for blocks.start >= 0 {
		start, head, content := blocks.next()
		if content < 0 {
			break
		}
		if names.next(start) < head {
			end := len(body)
			if e := ends.next(content); e < len(body) {
				end = e + 2 // up to the delimiter itself
			}
			if content >= to {
				if scriptRe.Match(body[from:to]) {
					return true
				}
				from = content
			}
			to = max(to, end)
		}
	}
	return scriptRe.Match(body[from:to])
}

// seeker finds where a pattern next is, for places asked about in increasing order, so that the body is searched once
// however many parts ask.
type seeker struct {
	body []byte
	find func([]byte) int // the index of the pattern in a slice, or -1
	at   int              // where it was last found: len(body) if nowhere, -1 before the first search
}

func (s *seeker) next(from int) int {
	if s.at < from {
		s.at = len(s.body)
		if i := s.find(s.body[from:]); i >= 0 {
			s.at = from + i
		}
	}
	return s.at
}

// indexFilename finds "filename", in any case, also split over lines that PHP joins (see phpLine).
func indexFilename(b []byte) int {
	for i := range b {
		if b[i]|0x20 == 'f' { // only 'f' and 'F' give 'f'
			if l := (phpLine{body: b, at: i}); l.match("filename") {
				return i
			}
		}
	}
	return -1
}

// executablePHPName reports a filename that PHP's rfc1867 parser reads as executable, or one in a part's headers with a
// quote or backslash that does not parse cleanly, which another parser may read differently. PHP takes filename only
// as a whole key right before '=' and skips white space after it. A value in double or single quotes runs to the
// closing quote, and a backslash before a backslash or that quote stands for the character after it. A bare value
// runs to white space or a ';', and a backslash before a backslash stands for it. Values read here do not overlap, so
// the body is read once.
func executablePHPName(body, delim []byte) bool {
	heads := inHeaders{blocks: newHeaderBlocks(body, delim)}
	for i := 0; i < len(body); i++ {
		if body[i]|0x20 != 'f' {
			continue
		}
		l := phpLine{body: body, at: i}
		if !l.match("filename=") {
			continue
		}
		name, clean := l.value()
		if !clean && heads.at(i) || executableName(name, false, true) {
			return true
		}
		i = l.at - 1
	}
	return false
}

// phpLine reads a multipart header line as PHP does. PHP splits lines at LF, dropping a CR before it, and joins to a
// header line each line after it that is not empty and either starts with white space or holds no ':'.
type phpLine struct {
	body []byte
	at   int // the next byte to read
}

// next returns the line's next byte, or false at its end.
func (l *phpLine) next() (byte, bool) {
	for l.at < len(l.body) {
		c := l.body[l.at]
		if c == '\r' && l.at+1 < len(l.body) && l.body[l.at+1] == '\n' {
			l.at++
			continue
		}
		if c != '\n' {
			l.at++
			return c, true
		}
		line := l.body[l.at+1:]
		if end := bytes.IndexByte(line, '\n'); end >= 0 {
			line = bytes.TrimSuffix(line[:end], []byte("\r"))
		}
		if len(line) == 0 || !isCSpace(line[0]) && bytes.IndexByte(line, ':') >= 0 {
			return 0, false
		}
		l.at++
	}
	return 0, false
}

// match reads word, whose letters are lower case, in any case.
func (l *phpLine) match(word string) bool {
	for k := 0; k < len(word); k++ {
		c, ok := l.next()
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if !ok || c != word[k] {
			return false
		}
	}
	return true
}

// value reads a parameter's value after its '=' as PHP's php_ap_getword_conf does. It reports false when the value has
// a quote that is not closed, or a quote in a bare value: PHP and other parsers would end it in different places.
func (l *phpLine) value() (string, bool) {
	c, ok := l.next()
	for ok && isCSpace(c) {
		c, ok = l.next()
	}
	var name []byte
	if ok && (c == '"' || c == '\'') {
		quote := c
		for {
			if c, ok = l.next(); !ok {
				return "", false
			}
			if c == quote {
				return string(name), true
			}
			if c == '\\' {
				after := *l
				if d, ok := after.next(); ok && (d == '\\' || d == quote) {
					*l, c = after, d
				}
			}
			name = append(name, c)
		}
	}
	for ok && !isCSpace(c) && c != ';' {
		if c == '"' || c == '\'' {
			return "", false
		}
		if c == '\\' {
			after := *l
			if d, ok := after.next(); ok && d == '\\' {
				*l = after
			}
		}
		name = append(name, c)
		c, ok = l.next()
	}
	return string(name), true
}

// isCSpace is C's isspace.
func isCSpace(c byte) bool {
	return c == ' ' || '\t' <= c && c <= '\r'
}

// cutHeader splits a part into its header block and its content at the first blank line, accepting LF as well as CRLF.
func cutHeader(part []byte) (head, content []byte, ok bool) {
	for _, sep := range [][]byte{[]byte("\r\n\r\n"), []byte("\n\n")} {
		if i := bytes.Index(part, sep); i >= 0 {
			return part[:i], part[i+len(sep):], true
		}
	}
	return nil, nil, false
}
