// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
)

// extendedCases adds named synthetic payloads for six families. The origin never
// interprets them. Multiple transports test parsing differences, not new exploits.
func extendedCases() []testCase {
	var out []testCase
	add := func(category, name, method, uri, contentType, body, note string, attack bool) {
		headers := map[string]string{"Accept": "application/json"}
		if contentType != "" {
			headers["Content-Type"] = contentType
		}
		out = append(out, testCase{Name: category + "/" + name, Attack: attack, Description: note, Request: request{Method: method, URI: uri, Headers: headers, Body: body}})
	}
	// LDAP, XPath and SSI payloads vary syntax as well as transport.
	for _, family := range []struct {
		category, endpoint string
		payloads           []string
	}{
		{"ldap", "/api/directory", []string{
			"*)(uid=*))(|(uid=*", "admin)(|(userPassword=*))", "*)(|(objectClass=*))", "*)(uid=*))(&(uid=*",
			"user)(!(uid=missing))", "user)(uid=*)(", "user)(|(cn=*)(sn=*))", "*)(|(memberOf=*))", "admin)(userPassword=*)", "*)(!(objectClass=missing))",
		}},
		{"xpath", "/api/xml-search", []string{
			"' or '1'='1", "\" or \"1\"=\"1", "' or true() or 'x'='y", "' or count(//user)>0 or 'x'='y",
			"' or contains(name(),'user') or 'x'='y", "' or string-length(name())>0 or 'x'='y", "' or position()=1 or 'x'='y",
			"' or substring(name(),1,1)='u' or 'x'='y", "'] | //user | //*['a'='a", "' or not(false()) or 'x'='y",
		}},
		{"ssi", "/api/render", []string{
			"<!--#exec cmd=\"echo LOADTEST\" -->", "<!--#exec cgi=\"/loadtest.cgi\" -->", "<!--#include virtual=\"/loadtest-marker.txt\" -->",
			"<!--#include file=\"../loadtest-marker.txt\" -->", "<!--#echo var=\"DOCUMENT_ROOT\" -->", "<!--#printenv -->",
			"<!--#config errmsg=\"LOADTEST\" -->", "<!--#set var=\"loadtest\" value=\"1\" -->", "<!--#if expr=\"1 = 1\" -->LOADTEST<!--#endif -->",
			"<!--#fsize file=\"loadtest-marker.txt\" -->",
		}},
	} {
		for i, payload := range family.payloads {
			note := fmt.Sprintf("%s syntax variant %d; requires an unsafe application sink", family.category, i+1)
			encoded := url.QueryEscape(payload)
			add(family.category, fmt.Sprintf("v%02d-query", i+1), "GET", family.endpoint+"?input="+encoded, "", "", note, true)
			add(family.category, fmt.Sprintf("v%02d-form", i+1), "POST", family.endpoint, "application/x-www-form-urlencoded", "input="+encoded, note, true)
			body, _ := json.Marshal(map[string]string{"input": payload})
			add(family.category, fmt.Sprintf("v%02d-json", i+1), "POST", family.endpoint, "application/json", string(body), note, true)
			x, _ := xml.Marshal(struct {
				XMLName xml.Name `xml:"input"`
				Value   string   `xml:",chardata"`
			}{Value: payload})
			add(family.category, fmt.Sprintf("v%02d-xml", i+1), "POST", family.endpoint, "application/xml", string(x), note, true)
		}
		for i, value := range []string{"alice", "support-team", "invoice 42", "normal text (sample)"} {
			body, _ := json.Marshal(map[string]string{"input": value})
			add(family.category, fmt.Sprintf("control-%02d", i+1), "POST", family.endpoint, "application/json", string(body), "benign scalar control", false)
		}
	}

	for i, body := range []string{
		`{"username":{"$ne":""},"password":{"$ne":""}}`, `{"username":{"$gt":""},"password":{"$gt":""}}`,
		`{"username":{"$regex":".*"},"password":{"$exists":true}}`, `{"filter":{"$where":"return true"}}`,
		`{"filter":{"$or":[{"role":"admin"},{"role":{"$ne":"guest"}}]}}`, `{"filter":{"$expr":{"$eq":[1,1]}}}`,
		`{"filter":{"$nin":[null]}}`, `{"filter":{"$not":{"$eq":"guest"}}}`, `{"filter":{"$in":["admin","root"]}}`,
		`{"filter":{"$function":{"body":"function(){return true}","args":[],"lang":"js"}}}`,
		`{"filter":{"$regex":"^admin"}}`, `{"filter":{"$elemMatch":{"role":{"$ne":"guest"}}}}`,
	} {
		name := fmt.Sprintf("v%02d", i+1)
		add("nosql", name+"-json", "POST", "/api/login", "application/json", body, "MongoDB operator object supplied where a scalar/filter contract is required", true)
		unicode := strings.ReplaceAll(body, "$", `\u0024`)
		add("nosql", name+"-unicode-json", "POST", "/api/login", "application/json", unicode, "same NoSQL operators with Unicode-escaped dollar keys", true)
	}
	for i, query := range []string{"username[$ne]=x&password[$ne]=x", "username[$regex]=.*", "filter[$where]=return+true", "filter[$gt]=0", "filter[$exists]=true", "filter[$in][]=admin"} {
		add("nosql", fmt.Sprintf("v%02d-query", i+1), "GET", "/api/login?"+query, "", "", "bracket-parsed query operators", true)
		add("nosql", fmt.Sprintf("v%02d-form", i+1), "POST", "/api/login", "application/x-www-form-urlencoded", query, "bracket-parsed form operators", true)
	}
	for i, body := range []string{`{"username":"alice","password":"test-value"}`, `{"search":"normal text"}`, `{"amount":"$25"}`, `{"filter":{"name":"alice"}}`} {
		add("nosql", fmt.Sprintf("control-%02d", i+1), "POST", "/api/login", "application/json", body, "benign scalar/object control without query operators", false)
	}

	for i, query := range []string{
		"role=user&role=admin", "role=user&%72ole=admin", "role=user&role[]=admin", "role[]=user&role=admin",
		"user.name=alice&user_name=admin", "user+name=alice&user_name=admin", "id=1&id=1%27+OR+%271%27=%271",
		"q=UNION&q=SELECT+password+FROM+users", "q=%3Cscript%3E&q=alert(1)%3C%2Fscript%3E", "role=user;role=admin",
		"enabled=false&enabled=true", "ids[0]=1&ids[0]=2",
	} {
		add("hpp", fmt.Sprintf("v%02d-query", i+1), "GET", "/api/update?"+query, "", "", "parameter duplication or normalization ambiguity; depends on origin parser contract", true)
		add("hpp", fmt.Sprintf("v%02d-form", i+1), "POST", "/api/update", "application/x-www-form-urlencoded", query, "form parameter duplication or normalization ambiguity", true)
	}
	for i, body := range []string{`{"role":"user","role":"admin"}`, `{"role":"user","\u0072ole":"admin"}`, `{"user":{"id":1,"id":2}}`, `{"enabled":false,"enabled":true}`} {
		add("hpp", fmt.Sprintf("v%02d-json", i+1), "POST", "/api/update", "application/json", body, "duplicate decoded JSON keys", true)
	}
	for i, query := range []string{"tag=blue&tag=green", "ids[]=1&ids[]=2", "id=1&role=user", "q=first%26second"} {
		add("hpp", fmt.Sprintf("control-%02d", i+1), "GET", "/api/search?"+query, "", "", "benign repeated multi-valued parameter or scalar control", false)
	}

	for i, query := range []string{
		"__proto__[loadtest]=1", "__proto__.loadtest=1", "%5f%5fproto%5f%5f[loadtest]=1", "constructor[prototype][loadtest]=1",
		"constructor.prototype.loadtest=1", "user[__proto__][loadtest]=1", "user.constructor.prototype.loadtest=1",
		"__PROTO__[loadtest]=1", "constructor[prototype].loadtest=1", "user[constructor][prototype][loadtest]=1",
	} {
		attack, note := true, "prototype-reaching path in bracket/dotted parsing"
		if strings.HasPrefix(query, "__PROTO__") {
			attack, note = false, "benign uppercase key in a case-sensitive JavaScript parser"
		}
		add("prototype", fmt.Sprintf("v%02d-query", i+1), "GET", "/api/settings?"+query, "", "", note, attack)
		add("prototype", fmt.Sprintf("v%02d-form", i+1), "POST", "/api/settings", "application/x-www-form-urlencoded", query, note, attack)
	}
	for i, body := range []string{
		`{"__proto__":{"loadtest":true}}`, `{"\u005f\u005fproto__":{"loadtest":true}}`, `{"user":{"__proto__":{"loadtest":true}}}`,
		`{"constructor":{"prototype":{"loadtest":true}}}`, `{"user":{"constructor":{"prototype":{"loadtest":true}}}}`,
		`{"__proto__.loadtest":true}`, `{"constructor.prototype.loadtest":true}`, `{"items":[{"__proto__":{"loadtest":true}}]}`,
		`{"__PROTO__":{"loadtest":true}}`, `{"constructor":{"\u0070rototype":{"loadtest":true}}}`,
	} {
		attack, note := true, "prototype-reaching object key; requires unsafe merging/path setting"
		if strings.Contains(body, "__PROTO__") {
			attack, note = false, "benign uppercase key in a case-sensitive JavaScript parser"
		}
		add("prototype", fmt.Sprintf("v%02d-json", i+1), "POST", "/api/settings", "application/json", body, note, attack)
	}
	for i, body := range []string{`{"name":"alice"}`, `{"message":"__proto__ is a word in this string"}`, `{"constructor":"label"}`, `{"product":{"prototype":"sample"}}`} {
		add("prototype", fmt.Sprintf("control-%02d", i+1), "POST", "/api/settings", "application/json", body, "benign object/text without a prototype-reaching write", false)
	}
	return out
}
