package proxy

import (
	"bytes"
	"mime"
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
}

var (
	// Every filename= and filename*= in the body, wherever it is: if the proxy and the application disagree about where
	// one part ends and the next begins, a name that only one of them sees is still found.
	filenameRe = regexp.MustCompile(`(?i)filename\*?[ \t]*=[ \t]*(?:"([^"\r\n]*)"|([^;\s"]*))`)
	// Opening tags of server-side scripts. <?xml is not one.
	scriptRe = regexp.MustCompile(`(?i)<\?php|<\?=|<%@|<%=|<script\s+language\s*=\s*["']?php`)
	phpExt   = regexp.MustCompile(`^php[0-9]?$`)
)

var executableExt = map[string]bool{
	"phtml": true, "pht": true, "phps": true, "phar": true, "pgif": true, "shtml": true, "shtm": true, "inc": false,
	"asp": true, "aspx": true, "ashx": true, "asmx": true, "asa": true, "cer": true, "cdx": true,
	"jsp": true, "jspx": true, "jspa": true, "jsw": true, "jsv": true, "jspf": true,
	"cgi": true, "pl": true, "py": true, "sh": true, "bash": true, "exe": true, "dll": true, "bat": true, "cmd": true,
}

var executableNames = map[string]bool{".htaccess": true, ".htpasswd": true, ".user.ini": true, "web.config": true, "php.ini": true}

// executableName reports whether an uploaded file's name would be run, or would change how the server runs files.
func executableName(raw string) bool {
	name := raw
	// RFC 5987: filename*=UTF-8''%73hell.php
	if i := strings.Index(name, "''"); i >= 0 && i < 20 {
		name = name[i+2:]
	}
	if dec, err := url.PathUnescape(name); err == nil {
		name = dec
	}
	name = strings.ToLower(name)
	if strings.IndexFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return true // a NUL or control character in a name is only ever there to end it early
	}
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
	if !p.AllowExecutableNames {
		for _, m := range filenameRe.FindAllSubmatch(body, -1) {
			name := string(m[1])
			if len(m[1]) == 0 {
				name = string(m[2])
			}
			if executableName(name) {
				return idUploadName, "an uploaded file has the name of a script or a server configuration file"
			}
		}
	}
	if p.AllowScriptContent || boundary == "" {
		return 0, ""
	}
	if scriptInFile(body, []byte("--"+boundary)) {
		return idUploadScript, "an uploaded file contains the opening tag of a server-side script"
	}
	return 0, ""
}

// scriptInFile reports a script opening tag in anything a multipart parser could take for a file's content, since the
// application's parser may not find the parts where the proxy would. Parsers take a delimiter only at the start of a
// line and end a part's headers at the first blank line, CRLF or LF, and PHP reads a delimiter line among the headers
// as one more header line. So a part may start at any delimiter, its content starts after the first blank line that
// follows, and it is a file if "filename" is in its headers (or, as before, anywhere up to its first CRLF blank line
// before the next delimiter). The content runs to the next delimiter every parser ends a part at: one after a CRLF and
// followed by a CRLF or "--". Stretches that overlap are matched as one, so no byte is matched twice.
func scriptInFile(body, delim []byte) bool {
	line := append([]byte("\r\n"), delim...)
	crlfBlank := seeker{body: body, at: -1, find: func(b []byte) int { return bytes.Index(b, []byte("\n\r\n")) }}
	lfBlank := seeker{body: body, at: -1, find: func(b []byte) int { return bytes.Index(b, []byte("\n\n")) }}
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
	from, to := 0, 0 // file content found and not yet matched
	for start := 0; ; {
		next := len(body)
		if i := bytes.Index(body[start:], delim); i >= 0 {
			next = start + i
		}
		blank, sep := crlfBlank.next(start), 3
		if lf := lfBlank.next(start); lf < blank {
			blank, sep = lf, 2
		}
		if blank == len(body) {
			break // no header block ends after here
		}
		head := blank
		if h, _, ok := cutHeader(body[start:next]); ok {
			head = max(head, start+len(h))
		}
		if names.next(start) < head {
			content, end := blank+sep, len(body)
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
		if next == len(body) {
			break
		}
		start = next + len(delim)
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

// indexFilename finds "filename", in any case.
func indexFilename(b []byte) int {
	const word = "filename"
	for i := 0; i+len(word) <= len(b); i++ {
		k := 0
		for k < len(word) && b[i+k]|0x20 == word[k] { // every byte of word is a lower-case letter
			k++
		}
		if k == len(word) {
			return i
		}
	}
	return -1
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
