package proxy

import (
	"compress/flate"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A database error page: the Core Rule Set's response rules (951xxx) block it when response inspection is on.
const sqlErrorPage = "<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1</body></html>"

func TestResponseInspectionSeesTheRealResponse(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/early" {
			w.Header().Add("Link", "</style.css>; rel=preload; as=style")
			w.WriteHeader(http.StatusEarlyHints) // 103: the real response follows
		}
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.URL.Path == "/file": // a static file, served in ranges when asked for them
			http.ServeContent(w, r, "page.html", time.Time{}, strings.NewReader(sqlErrorPage))
		case r.URL.Path == "/deflate": // compressed whatever the request asked for
			w.Header().Set("Content-Encoding", "deflate")
			zw, _ := flate.NewWriter(w, flate.BestSpeed)
			zw.Write([]byte(sqlErrorPage))
			zw.Close()
		case strings.Contains(r.Header.Get("Accept-Encoding"), "gzip"):
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			zw.Write([]byte(sqlErrorPage))
			zw.Close()
		default:
			w.Write([]byte(sqlErrorPage))
		}
	}))
	defer app.Close()
	inspect := func(c *Config) {
		c.CRS.InspectResponses = true
		c.Upstream = mustURL(app.URL)
	}
	for _, tt := range []struct {
		name, path, header string
		want               int
	}{
		{"a plain response", "/plain", "", 403},
		{"the response after an interim one", "/early", "", 403},
		{"a client that accepts compression", "/plain", "Accept-Encoding: gzip, deflate, br\r\n", 403},
		{"an application that compresses unasked", "/deflate", "", 502},
		{"a static file", "/file", "", 403},
		{"a static file asked for in two ranges (multipart/byteranges)", "/file", "Range: bytes=0-9,10-\r\n", 403},
		{"a static file asked for in one range", "/file", "Range: bytes=0-40\r\n", 403},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := start(t, inspect)
			status, reply := s.raw(t, get(tt.path, tt.header))
			if status != tt.want {
				t.Fatalf("status %d, want %d:\n%.400s", status, tt.want, reply)
			}
			if strings.Contains(reply, "error in your SQL syntax") {
				t.Fatalf("the error page reached the visitor:\n%.400s", reply)
			}
		})
	}
}

func TestAnExpectHeaderIsNotPassedToTheApplication(t *testing.T) {
	s := start(t, ruleSetOff)
	body := "a=1"
	status, _ := s.raw(t, "POST /submit HTTP/1.1\r\n"+preamble+"Expect: 100-continue\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\nConnection: close\r\n\r\n"+body)
	got := s.up.requests()
	if status != 200 && status != 100 {
		t.Fatalf("status %d", status)
	}
	if len(got) != 1 {
		t.Fatalf("%d requests reached the application", len(got))
	}
	if v := got[0].Header.Get("Expect"); v != "" {
		t.Fatalf("Expect: %s reached the application", v)
	}
}
