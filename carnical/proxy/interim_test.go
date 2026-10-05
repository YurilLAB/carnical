package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A database error page: the Core Rule Set's response rules (951xxx) block it when response inspection is on.
const sqlErrorPage = "<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1</body></html>"

func TestResponseInspectionSeesTheRealResponseAfterAnInterimOne(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/early" {
			w.Header().Add("Link", "</style.css>; rel=preload; as=style")
			w.WriteHeader(http.StatusEarlyHints) // 103: the real response follows
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(sqlErrorPage))
	}))
	defer app.Close()
	inspect := func(c *Config) {
		c.CRS.InspectResponses = true
		c.Upstream = mustURL(app.URL)
	}
	for _, path := range []string{"/plain", "/early"} {
		t.Run(path, func(t *testing.T) {
			s := start(t, inspect)
			_, reply := s.raw(t, get(path))
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
