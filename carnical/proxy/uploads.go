package proxy

import (
	"bytes"
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
	delim := []byte("--" + boundary)
	for _, part := range bytes.Split(body, delim) {
		head, content, ok := cutHeader(part)
		if !ok || !bytes.Contains(bytes.ToLower(head), []byte("filename")) {
			continue
		}
		if scriptRe.Match(content) {
			return idUploadScript, "an uploaded file contains the opening tag of a server-side script"
		}
	}
	return 0, ""
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
