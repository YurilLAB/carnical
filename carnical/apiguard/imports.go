// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// A recorded session (a HAR file from a browser's developer tools) or a Postman collection is a way to teach the guard the API
// before any traffic has arrived. Both are turned into Observations, which Guard.Learn takes as the owner's word.
//
// Both files come from the owner but are read as hostile all the same: they are limited in size, in how many requests they may
// hold and in how deeply a collection may be nested, and a request that cannot be used is skipped and counted, not guessed at.

// MaxHARBytes is the largest HAR file that is read. A HAR holds the response bodies of everything the browser loaded, so it is
// far larger than the description of an API; the limit is higher than MaxDocumentBytes for that reason and the reader keeps only
// the few fields it needs.
const MaxHARBytes = 64 << 20

const (
	maxRecordedRequests = 20_000
	maxCollectionDepth  = 16
	maxRecordedBody     = 128 << 10
)

// ImportHAR reads a HAR 1.2 file and returns the requests in it that were answered below 400. The credentials in a request
// (Authorization, Cookie) are not kept.
func ImportHAR(data []byte) ([]Observation, Report, error) {
	rep := Report{Kind: "har", Source: "supplied", When: time.Now().UTC()}
	if len(data) > MaxHARBytes {
		return nil, rep, fmt.Errorf("the recording is %d bytes; the limit is %d", len(data), MaxHARBytes)
	}
	var f struct {
		Log struct {
			Entries []struct {
				Request struct {
					Method  string `json:"method"`
					URL     string `json:"url"`
					Headers []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
					PostData *struct {
						MimeType string `json:"mimeType"`
						Text     string `json:"text"`
					} `json:"postData"`
				} `json:"request"`
				Response struct {
					Status  int `json:"status"`
					Content struct {
						MimeType string `json:"mimeType"`
					} `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}))).Decode(&f); err != nil {
		return nil, rep, errors.New("the recording is not a readable HAR file")
	}
	if len(f.Log.Entries) == 0 {
		return nil, rep, errors.New("the recording has no entries")
	}
	rep.Format = "har"
	var out []Observation
	for _, e := range f.Log.Entries {
		if len(out) >= maxRecordedRequests {
			rep.warn(fmt.Sprintf("only the first %d entries were read", maxRecordedRequests))
			break
		}
		u, err := url.Parse(e.Request.URL)
		method := strings.ToUpper(e.Request.Method)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !validMethodToken(method) || e.Response.Status < 200 || e.Response.Status >= 400 {
			rep.Skipped++
			continue
		}
		o := Observation{Status: e.Response.Status, ResponseType: mediaType(e.Response.Content.MimeType)}
		o.Request = inspectRequest(method, u.Host, pathOf(u), u.RawQuery, u.Scheme == "https")
		for _, h := range e.Request.Headers {
			switch strings.ToLower(h.Name) {
			case "content-type", "accept":
				o.Request.Header.Set(h.Name, h.Value)
			}
		}
		if pd := e.Request.PostData; pd != nil {
			if o.Request.Header.Get("Content-Type") == "" && pd.MimeType != "" {
				o.Request.Header.Set("Content-Type", pd.MimeType)
			}
			if len(pd.Text) <= maxRecordedBody {
				o.Request.Body = []byte(pd.Text)
			}
		}
		out = append(out, o)
	}
	rep.Observations = len(out)
	return out, rep, nil
}

func pathOf(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

func inspectRequest(method, host, path, rawQuery string, tls bool) inspect.Request {
	return inspect.Request{Method: method, Host: host, Path: path, RawQuery: rawQuery, Header: http.Header{}, TLS: tls}
}

// ---- Postman ----

type pmCollection struct {
	Item     []pmItem `json:"item"`
	Variable []pmVar  `json:"variable"`
}

type pmVar struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

type pmItem struct {
	Item     []pmItem          `json:"item"`
	Request  json.RawMessage   `json:"request"`
	Response []json.RawMessage `json:"response"`
}

type pmRequest struct {
	Method string `json:"method"`
	Header []struct {
		Key      string `json:"key"`
		Value    string `json:"value"`
		Disabled bool   `json:"disabled"`
	} `json:"header"`
	URL  json.RawMessage `json:"url"`
	Body *struct {
		Mode       string `json:"mode"`
		Raw        string `json:"raw"`
		URLEncoded []struct {
			Key      string `json:"key"`
			Value    string `json:"value"`
			Disabled bool   `json:"disabled"`
		} `json:"urlencoded"`
	} `json:"body"`
}

type pmURL struct {
	Raw   string `json:"raw"`
	Host  any    `json:"host"`
	Path  any    `json:"path"`
	Query []struct {
		Key      string `json:"key"`
		Value    string `json:"value"`
		Disabled bool   `json:"disabled"`
	} `json:"query"`
	Variable []pmVar `json:"variable"`
}

// ImportPostman reads a Postman collection (v2.0 or v2.1) and returns one observation for each request in it. A collection holds
// requests and, if its author saved them, example responses; with no example the request is taken as answered 200. A variable in
// the path ({{id}} or :id) is replaced by its value if the collection gives one and by 1 if not, which the guard reads as an
// integer: a collection whose ids are not numbers should give them values.
func ImportPostman(data []byte) ([]Observation, Report, error) {
	rep := Report{Kind: "postman", Source: "supplied", When: time.Now().UTC()}
	if len(data) > MaxDocumentBytes {
		return nil, rep, fmt.Errorf("the collection is %d bytes; the limit is %d", len(data), MaxDocumentBytes)
	}
	var c pmCollection
	if err := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}))).Decode(&c); err != nil {
		return nil, rep, errors.New("the collection is not readable JSON")
	}
	if len(c.Item) == 0 {
		return nil, rep, errors.New("the collection has no items")
	}
	rep.Format = "postman collection"
	vars := map[string]string{}
	for _, v := range c.Variable {
		if s := scalarText(anyToValue(v.Value)); s != "" && v.Key != "" {
			vars[v.Key] = s
		}
	}
	var out []Observation
	var walk func(items []pmItem, depth int)
	walk = func(items []pmItem, depth int) {
		for _, it := range items {
			if len(out)+rep.Skipped >= maxRecordedRequests || depth > maxCollectionDepth {
				return
			}
			if len(it.Item) > 0 {
				walk(it.Item, depth+1)
			}
			if len(it.Request) == 0 {
				continue
			}
			o, ok := postmanObservation(it, vars)
			if !ok {
				rep.Skipped++
				continue
			}
			out = append(out, o)
		}
	}
	walk(c.Item, 0)
	rep.Observations = len(out)
	if len(out) == 0 {
		return nil, rep, errors.New("the collection has no usable requests")
	}
	return out, rep, nil
}

// anyToValue turns a decoded std JSON scalar into the package's value form, for scalarText.
func anyToValue(v any) any {
	switch x := v.(type) {
	case float64:
		return Num(fmt.Sprint(x))
	case string:
		return x
	}
	return nil
}

func postmanObservation(it pmItem, vars map[string]string) (Observation, bool) {
	var pr pmRequest
	// A request may be written as a bare URL string, which means GET.
	var asString string
	if err := json.Unmarshal(it.Request, &asString); err == nil {
		pr.Method, pr.URL = "GET", mustJSON(asString)
	} else if err := json.Unmarshal(it.Request, &pr); err != nil {
		return Observation{}, false
	}
	method := strings.ToUpper(pr.Method)
	if method == "" {
		method = "GET"
	}
	if !validMethodToken(method) {
		return Observation{}, false
	}
	host, path, rawQuery, ok := postmanURL(pr.URL, vars)
	if !ok {
		return Observation{}, false
	}
	o := Observation{Status: 200}
	if len(it.Response) > 0 {
		var resp struct {
			Code int `json:"code"`
		}
		if json.Unmarshal(it.Response[0], &resp) == nil && resp.Code != 0 {
			o.Status = resp.Code
		}
	}
	if o.Status < 200 || o.Status >= 400 {
		return Observation{}, false
	}
	o.Request = inspectRequest(method, host, path, rawQuery, true)
	for _, h := range pr.Header {
		if h.Disabled {
			continue
		}
		switch strings.ToLower(h.Key) {
		case "content-type", "accept":
			o.Request.Header.Set(h.Key, h.Value)
		}
	}
	if b := pr.Body; b != nil {
		switch b.Mode {
		case "raw":
			if len(b.Raw) <= maxRecordedBody {
				body := b.Raw
				if _, _, err := parseJSON([]byte(body), jsonLimits{}); err != nil {
					// An unquoted {{variable}} is not JSON; read it as null so the shape of the rest is kept.
					body = fillVars(body, func(string) string { return "null" })
				}
				if _, _, err := parseJSON([]byte(body), jsonLimits{}); err == nil {
					o.Request.Body = []byte(body)
					if o.Request.Header.Get("Content-Type") == "" {
						o.Request.Header.Set("Content-Type", "application/json")
					}
				}
			}
		case "urlencoded":
			var parts []string
			for _, kv := range b.URLEncoded {
				if !kv.Disabled && kv.Key != "" {
					parts = append(parts, url.QueryEscape(kv.Key)+"="+url.QueryEscape(fillVars(kv.Value, func(n string) string { return varOr(vars, n) })))
				}
			}
			o.Request.Body = []byte(strings.Join(parts, "&"))
			if o.Request.Header.Get("Content-Type") == "" {
				o.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		}
	}
	return o, true
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func varOr(vars map[string]string, name string) string {
	if v, ok := vars[name]; ok {
		return v
	}
	return "1"
}

// fillVars replaces each {{name}} in s with what f says.
func fillVars(s string, f func(name string) string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := strings.Index(s[i:], "}}")
		if j < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(f(strings.TrimSpace(s[i+2 : i+j])))
		s = s[i+j+2:]
	}
}

// postmanURL reads a request's URL, which Postman writes as a string or as an object of parts.
func postmanURL(raw json.RawMessage, vars map[string]string) (host, path, rawQuery string, ok bool) {
	var s string
	var pu pmURL
	if err := json.Unmarshal(raw, &s); err == nil {
		pu.Raw = s
	} else if err := json.Unmarshal(raw, &pu); err != nil {
		return "", "", "", false
	}
	local := map[string]string{}
	for _, v := range pu.Variable {
		if t := scalarText(anyToValue(v.Value)); t != "" && v.Key != "" {
			local[v.Key] = t
		}
	}
	resolve := func(name string) string {
		if v, ok := local[name]; ok {
			return v
		}
		return varOr(vars, name)
	}
	var segs []string
	switch p := pu.Path.(type) {
	case []any:
		for _, e := range p {
			switch x := e.(type) {
			case string:
				segs = append(segs, x)
			case map[string]any:
				if v, ok := x["value"].(string); ok {
					segs = append(segs, v)
				}
			}
		}
	case string:
		segs = strings.Split(strings.Trim(p, "/"), "/")
	}
	query := ""
	if len(pu.Query) > 0 {
		var parts []string
		for _, q := range pu.Query {
			if !q.Disabled && q.Key != "" {
				parts = append(parts, url.QueryEscape(q.Key)+"="+url.QueryEscape(fillVars(q.Value, resolve)))
			}
		}
		query = strings.Join(parts, "&")
	}
	if len(segs) == 0 && pu.Raw != "" {
		r := pu.Raw
		if i := strings.IndexByte(r, '#'); i >= 0 {
			r = r[:i]
		}
		if i := strings.IndexByte(r, '?'); i >= 0 {
			if query == "" {
				query = fillVars(r[i+1:], resolve)
			}
			r = r[:i]
		}
		if i := strings.Index(r, "://"); i >= 0 {
			r = r[i+3:]
			if j := strings.IndexByte(r, '/'); j >= 0 {
				host, r = r[:j], r[j:]
			} else {
				host, r = r, ""
			}
		} else if strings.HasPrefix(r, "{{") {
			// {{baseUrl}}/users: the variable is the origin.
			if j := strings.Index(r, "}}"); j >= 0 {
				r = r[j+2:]
			}
		}
		segs = strings.Split(strings.Trim(r, "/"), "/")
	}
	var clean []string
	for _, s := range segs {
		switch {
		case s == "":
			continue
		case strings.HasPrefix(s, ":"):
			s = resolve(s[1:])
		case strings.Contains(s, "{{"):
			s = fillVars(s, resolve)
		}
		clean = append(clean, (&url.URL{Path: s}).EscapedPath())
	}
	if len(clean) > MaxPathSegments {
		return "", "", "", false
	}
	return host, "/" + strings.Join(clean, "/"), query, true
}
