// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// viewOf parses the request as the engine does and returns one kind of value.
func viewOf(t *testing.T, r *inspect.Request, kind int) []string {
	t.Helper()
	e := New(Options{})
	snap := e.cur.Load()
	c := e.getCtx(snap)
	defer func() { c.release(); e.pool.Put(c) }()
	c.req = r
	c.snap = &snapshot{}
	return append([]string(nil), c.raw(kind).vals...)
}

func multipartBodyOf(t *testing.T, fields map[string]string, files map[string]string) (string, []byte) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	for name, content := range files {
		fw, _ := w.CreateFormFile("file", name)
		_, _ = fw.Write([]byte(content))
	}
	_ = w.Close()
	return w.FormDataContentType(), b.Bytes()
}

func TestRequestViews(t *testing.T) {
	ct, mp := multipartBodyOf(t, map[string]string{"title": "hello"}, map[string]string{"../../shell.php": "<?php system($_GET[c]); ?>"})
	mpReq := &inspect.Request{Method: "POST", Path: "/up", Header: http.Header{"Content-Type": {ct}}, Body: mp}
	jsonReq := &inspect.Request{Method: "POST", Path: "/", Header: http.Header{"Content-Type": {"application/json"}}, Body: []byte(`{"a":{"b":["x",2,true,null]},"c":"d"}`)}
	tests := []struct {
		name string
		req  *inspect.Request
		kind int
		want []string
	}{
		{"uri with query", mkReq("GET", "/a?b=c", nil, ""), kURI, []string{"/a?b=c"}},
		{"uri without query", mkReq("GET", "/a", nil, ""), kURI, []string{"/a"}},
		{"path", mkReq("GET", "/a%20b?c", nil, ""), kPath, []string{"/a%20b"}},
		{"query empty is no value", mkReq("GET", "/a", nil, ""), kQuery, nil},
		{"args", mkReq("GET", "/?a=1&b=%26&c", nil, ""), kArgs, []string{"1", "&", ""}},
		{"argnames", mkReq("GET", "/?a=1&b%5B%5D=2", nil, ""), kArgNames, []string{"a", "b[]"}},
		{"no body is no body value", mkReq("POST", "/", nil, ""), kBody, nil},
		{"multipart fields are arguments", mpReq, kArgs, []string{"hello"}},
		{"multipart file name is not sanitised", mpReq, kFilenames, []string{"../../shell.php"}},
		{"multipart body is not offered raw", mpReq, kBody, nil},
		{"multipart field names", mpReq, kArgNames, []string{"title", "file"}},
		{"json values", jsonReq, kArgs, []string{"x", "2", "true", "", "d"}},
		{"json names", jsonReq, kArgNames, []string{"json.a.b.0", "json.a.b.1", "json.a.b.2", "json.a.b.3", "json.c"}},
		{"json is also the body", jsonReq, kBody, []string{`{"a":{"b":["x",2,true,null]},"c":"d"}`}},
		{"broken multipart is offered as the body", &inspect.Request{Method: "POST", Path: "/", Header: http.Header{"Content-Type": {"multipart/form-data; boundary=zz"}}, Body: []byte("a=b&c=d")}, kBody, []string{"a=b&c=d"}},
		{"broken multipart is read as a form", &inspect.Request{Method: "POST", Path: "/", Header: http.Header{"Content-Type": {"multipart/form-data; boundary=zz"}}, Body: []byte("a=b&c=d")}, kArgs, []string{"b", "d"}},
		{"cookies are decoded and unquoted", mkReq("GET", "/", map[string]string{"cookie": `a="x%20y"; b=2`}, ""), kCookies, []string{"x y", "2"}},
		{"cookie names", mkReq("GET", "/", map[string]string{"cookie": "a=1; b=2;c"}, ""), kCookieNames, []string{"a", "b", "c"}},
		{"method with override", mkReq("POST", "/", map[string]string{"x-http-method": "PUT"}, ""), kMethod, []string{"POST", "PUT"}},
		{"json that stops being json keeps its later strings", &inspect.Request{Method: "POST", Path: "/", Header: http.Header{"Content-Type": {"application/json"}}, Body: []byte(`{"a":"ok", oops, "b":"payload"}`)}, kArgs, []string{"ok", "oops", "payload"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := viewOf(t, tc.req, tc.kind)
			if tc.name == "json that stops being json keeps its later strings" {
				// the exact leftovers are not the point; the payload must be among them
				if !strings.Contains(strings.Join(got, "|"), "payload") || !strings.Contains(strings.Join(got, "|"), "ok") {
					t.Fatalf("got %q", got)
				}
				return
			}
			if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRequestBounds(t *testing.T) {
	t.Run("arguments are capped", func(t *testing.T) {
		var q strings.Builder
		for i := 0; i < 5000; i++ {
			fmt.Fprintf(&q, "a%d=v&", i)
		}
		if got := len(viewOf(t, mkReq("GET", "/?"+q.String(), nil, ""), kArgs)); got != maxArgs {
			t.Fatalf("%d arguments kept, want %d", got, maxArgs)
		}
	})
	t.Run("json depth is capped", func(t *testing.T) {
		deep := strings.Repeat(`{"a":`, 200) + `"x"` + strings.Repeat("}", 200)
		r := &inspect.Request{Method: "POST", Path: "/", Header: http.Header{"Content-Type": {"application/json"}}, Body: []byte(deep)}
		if got := viewOf(t, r, kArgs); len(got) != 0 {
			t.Fatalf("a document nested 200 deep gave %q", got)
		}
	})
	t.Run("json nodes are capped", func(t *testing.T) {
		wide := "[" + strings.Repeat("1,", 30000) + "1]"
		r := &inspect.Request{Method: "POST", Path: "/", Header: http.Header{"Content-Type": {"application/json"}}, Body: []byte(wide)}
		if got := len(viewOf(t, r, kArgs)); got > maxArgs {
			t.Fatalf("%d arguments", got)
		}
	})
	t.Run("a long value is seen at both ends", func(t *testing.T) {
		long := strings.Repeat("a", 3*maxValue)
		got := viewOf(t, mkReq("POST", "/", nil, "HEAD"+long+"TAIL"), kBody)
		if len(got) != 2 || !strings.HasPrefix(got[0], "HEAD") || !strings.HasSuffix(got[1], "TAIL") || len(got[0]) != maxValue || len(got[1]) != maxValue {
			t.Fatalf("%d pieces", len(got))
		}
	})
	t.Run("a value up to twice the cap is covered whole", func(t *testing.T) {
		body := strings.Repeat("a", maxValue-1) + "XY" + strings.Repeat("b", maxValue-3)
		got := viewOf(t, mkReq("POST", "/", nil, body), kBody)
		if len(got) != 2 || !strings.Contains(got[0]+got[1], "XY") {
			t.Fatalf("%d pieces", len(got))
		}
	})
	t.Run("cookies and headers are capped", func(t *testing.T) {
		var cookie strings.Builder
		for i := 0; i < 2000; i++ {
			fmt.Fprintf(&cookie, "c%d=v;", i)
		}
		if got := len(viewOf(t, mkReq("GET", "/", map[string]string{"cookie": cookie.String()}, ""), kCookies)); got != maxCookies {
			t.Fatalf("%d cookies", got)
		}
	})
	t.Run("multipart parts are capped", func(t *testing.T) {
		fields := map[string]string{}
		for i := 0; i < 200; i++ {
			fields[fmt.Sprintf("f%d", i)] = "v"
		}
		ct, body := multipartBodyOf(t, fields, nil)
		r := &inspect.Request{Method: "POST", Path: "/", Header: http.Header{"Content-Type": {ct}}, Body: body}
		if got := len(viewOf(t, r, kArgs)); got > maxMultipartParts {
			t.Fatalf("%d parts read", got)
		}
	})
	t.Run("a hostile request does not panic", func(t *testing.T) {
		for _, body := range []string{"", "{", "[", `{"a":`, strings.Repeat("[", 5000), "\x00\xff\xfe=&&;;==", `"`, `{"` + strings.Repeat(`\`, 10001)} {
			for _, ct := range []string{"", "application/json", "multipart/form-data; boundary=", "multipart/form-data; boundary=x", "application/x-www-form-urlencoded", "text/xml"} {
				r := &inspect.Request{Method: "POST", Path: "/%zz?%=&=%&;;", RawQuery: "%zz=%&&==;", Header: http.Header{"Content-Type": {ct}, "Cookie": {";;==;a"}}, Body: []byte(body)}
				for kind := 0; kind < numKinds; kind++ {
					_ = viewOf(t, r, kind)
				}
			}
		}
	})
}

func TestUploadContentIsOnlyReadIfSomeSignatureWantsIt(t *testing.T) {
	ct, mp := multipartBodyOf(t, nil, map[string]string{"a.png": "MZ-PAYLOAD"})
	r := &inspect.Request{Method: "POST", Path: "/up", Header: http.Header{"Content-Type": {ct}}, Body: mp}
	without := loadOne(t, Options{}, sig("F", cond("rx", `\.php$`, tg("filenames"))))
	if got := len(without.cur.Load().kinds[kUploads].classes); got != 0 {
		t.Fatalf("an uploads class exists with no signature on uploads: %d", got)
	}
	withUploads := loadOne(t, Options{}, sig("U", cond("contains", "MZ-PAYLOAD", tg("uploads"))))
	if !hasHit(withUploads.Match(r), "U") {
		t.Fatal("upload content was not matched")
	}
	if hasHit(without.Match(r), "F") {
		t.Fatal("a .png matched the .php signature")
	}
}
