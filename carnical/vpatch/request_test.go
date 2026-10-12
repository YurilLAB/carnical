// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"runtime"
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
		{"multipart typed as PHP reads it and Go does not", &inspect.Request{Method: "POST", Path: "/up", Header: http.Header{"Content-Type": {strings.Replace(ct, ";", ", x;", 1)}}, Body: mp}, kFilenames, []string{"../../shell.php"}},
		{"a type that only begins like multipart is offered raw too", &inspect.Request{Method: "POST", Path: "/", Header: http.Header{"Content-Type": {"multipart/form-datax; boundary=zz"}}, Body: []byte("id=1\r\n--zz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n--zz--\r\n")}, kBody, []string{"id=1\r\n--zz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n--zz--\r\n"}},
		{"a form typed as PHP reads it and Go does not", &inspect.Request{Method: "POST", Path: "/", Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded, text/plain"}}, Body: []byte("z=\x01&id=1")}, kArgs, []string{"\x01", "1"}},
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
	t.Run("json names are capped, and so is what they cost", func(t *testing.T) {
		// A long key above thousands of containers and a value nested 60 deep: a name is built only for a value that is kept,
		// from maxJSONDepth levels of keys cut to maxJSONKey bytes. Naming every container as it was opened made 126 KiB cost
		// 500 MiB.
		key := strings.Repeat("k", 5000)
		body := `{"` + key + `":[` + strings.Repeat("[],", 20000) + `{"` + key + `":` + strings.Repeat(`{"a":`, 60) + `"x"` + strings.Repeat("}", 61) + `]}`
		r := &inspect.Request{Method: "POST", Path: "/", Header: http.Header{"Content-Type": {"application/json"}}, Body: []byte(body)}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		got := viewOf(t, r, kArgNames)
		runtime.ReadMemStats(&after)
		if longest := 4 + maxJSONDepth*(maxJSONKey+1); len(got) != 1 || len(got[0]) > longest {
			t.Fatalf("%d names, want one of at most %d bytes: %.80q", len(got), longest, got)
		}
		if spent := after.TotalAlloc - before.TotalAlloc; spent > 64*uint64(len(body)) {
			t.Fatalf("a %d byte document cost %d bytes", len(body), spent)
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
	// What a cap leaves out must still be seen by some signature: an application reads all of the request.
	const marker = "zqxmarkerzqx"
	multipartOf := func(fillers int, cd, value string) *inspect.Request {
		var b strings.Builder
		for i := 0; i < fillers; i++ {
			fmt.Fprintf(&b, "--B\r\nContent-Disposition: form-data; name=\"f%d\"\r\n\r\nv\r\n", i)
		}
		fmt.Fprintf(&b, "--B\r\nContent-Disposition: %s\r\n\r\n%s\r\n--B--\r\n", cd, value)
		return &inspect.Request{Method: "POST", Path: "/", Header: http.Header{"Content-Type": {"multipart/form-data; boundary=B"}}, Body: []byte(b.String())}
	}
	withType := func(ct, body string) *inspect.Request {
		return &inspect.Request{Method: "POST", Path: "/", Header: http.Header{"Content-Type": {ct}}, Body: []byte(body)}
	}
	straddle := "pad=" + strings.Repeat("p", maxValue-len("pad=")-len("&target=")-len(marker)/2) + "&target=" + marker + "&z=1"
	cookies := func(fillers int) map[string]string {
		var b strings.Builder
		for i := 0; i < fillers; i++ {
			fmt.Fprintf(&b, "c%d=v; ", i)
		}
		return map[string]string{"cookie": b.String() + "target=" + marker}
	}
	headers := map[string]string{"host": marker}
	for i := 0; i < maxHeaderItems+100; i++ {
		headers[fmt.Sprintf("x-pad-%d", i)] = "v"
	}
	for _, tc := range []struct {
		name    string
		targets []string
		req     *inspect.Request
		// past is set when the marker is past a count the engine reads, and limited when the request has more of something
		// than is read: it is then reported, and refused with BlockOnWorkLimit, as a request that was not checked in full.
		past, limited bool
	}{
		{"a part after the parts that are read", tg("args", "body"), multipartOf(200, `form-data; name="target"`, marker), false, false},
		{"a part after one Go's reader cannot read", tg("args", "body"), multipartOf(1, "form-data; name=\"target\"\r\nno colon", marker), false, false},
		{"a field whose header merely mentions filename", tg("args"), multipartOf(0, `form-data; name="target"; note="filename"`, marker), false, false},
		{"a field with filename* and no filename", tg("args"), multipartOf(0, `form-data; name="target"; filename*=UTF-8''a.txt`, marker), false, false},
		{"the end of a long multipart field", tg("args"), multipartOf(0, `form-data; name="target"`, strings.Repeat("p", 3*maxValue)+marker), false, false},
		{"a form value across the 64 KiB mark", tg("arg:target"), withType("application/x-www-form-urlencoded", straddle), false, false},
		{"a JSON argument after the first 64 KiB", tg("arg:target"), withType("application/json", `{"pad":"`+strings.Repeat("p", maxValue)+`","target":"`+marker+`"}`), false, false},
		{"a JSON argument after a value nested past the depth that names it", tg("arg:target"), withType("application/json", `{"pad":`+strings.Repeat("[", 30)+strings.Repeat("]", 30)+`,"target":"`+marker+`"}`), false, false},
		{"a JSON argument after thousands of empty arrays", tg("arg:target"), withType("application/json", `{"pad":[`+strings.Repeat("[],", 9000)+`[]],"target":"`+marker+`"}`), false, false},
		{"a cookie after the cookies that are read", tg("cookie:target"), mkReq("GET", "/", cookies(maxCookies+100), ""), true, true},
		{"the Host after more header values than are read", tg("header:host"), mkReq("GET", "/", headers, ""), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := loadOne(t, Options{Mode: ModeBlock, BlockOnWorkLimit: true}, sig("CAP", cond("contains", marker, tc.targets)))
			if seen := len(e.Match(tc.req)) == 1; seen == tc.past {
				t.Fatalf("the signature saw the marker: %v", seen)
			}
			limited := false
			for _, v := range e.Inspect(tc.req).Verdicts {
				limited = limited || (v.ID == IDInputLimit && v.Block)
			}
			if limited != tc.limited {
				t.Fatalf("reported as not checked in full: %v, want %v", limited, tc.limited)
			}
		})
	}
	t.Run("the raw body is offered only when parts were left unread", func(t *testing.T) {
		for _, tc := range []struct {
			parts   int
			wantRaw bool
		}{{maxMultipartParts, false}, {maxMultipartParts + 1, true}} {
			r := multipartOf(tc.parts-1, `form-data; name="last"`, "v")
			if got := len(viewOf(t, r, kBody)) > 0; got != tc.wantRaw {
				t.Fatalf("%d parts: raw body offered %v, want %v", tc.parts, got, tc.wantRaw)
			}
		}
	})
	t.Run("a part is read to its end, keeping both ends", func(t *testing.T) {
		for _, n := range []int{0, 5, 2*maxValue - 1, 2 * maxValue, 2*maxValue + 10, 3*maxValue - 1, 3 * maxValue, 3*maxValue + 7, 5*maxValue + 3} {
			s := make([]byte, n)
			for i := range s {
				s[i] = byte('a' + i%23)
			}
			want := string(s)
			if n > 2*maxValue {
				want = string(s[:maxValue]) + string(s[n-maxValue:])
			}
			c := &matchCtx{}
			if got := c.readEnds(bytes.NewReader(s)); got != want {
				t.Fatalf("length %d: kept %d bytes, not the first and last %d", n, len(got), maxValue)
			}
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
