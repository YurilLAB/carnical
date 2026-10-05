package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/YurilLAB/coraza/carnical/crs"
)

// Everything here that says so runs with the rule set OFF. These protections must hold without it: they are the part
// that does not depend on a rule recognising an attack.
func ruleSetOff(c *Config) { c.CRS.Mode = crs.ModeOff }

type refusals struct {
	mu  sync.Mutex
	ids []int
}

func (r *refusals) record(m Match) { r.mu.Lock(); r.ids = append(r.ids, m.RuleID); r.mu.Unlock() }
func (r *refusals) last() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.ids) == 0 {
		return 0
	}
	return r.ids[len(r.ids)-1]
}

func TestPathPolicy(t *testing.T) {
	strict := PathPolicy{}
	tests := []struct {
		name, path string
		policy     PathPolicy
		ok         bool
	}{
		{"root", "/", strict, true},
		{"nested", "/a/b/c", strict, true},
		{"a file", "/index.php", strict, true},
		{"unreserved characters", "/a.b-c_d~e", strict, true},
		{"a segment of dots that is not a dot segment", "/a/.../b", strict, true},
		{"dots inside a name", "/a/b..c", strict, true},
		{"an escaped multibyte character", "/caf%C3%A9", strict, true},
		{"an escaped space", "/a%20b", strict, true},
		{"an escaped tilde", "/a%7Eb", strict, true},
		{"an encoded slash", "/a%2fb", strict, false},
		{"an encoded slash in capitals", "/a%2Fb", strict, false},
		{"an encoded backslash", "/a%5cb", strict, false},
		{"an encoded question mark", "/a%3fb", strict, false},
		{"an encoded hash", "/a%23b", strict, false},
		{"an encoded NUL", "/a%00b", strict, false},
		{"an encoded percent (double decoding)", "/a%25b", strict, false},
		{"an encoded newline", "/a%0ab", strict, false},
		{"an encoded DEL", "/a%7fb", strict, false},
		{"an escaped letter", "/%77p-admin/", strict, false},
		{"an escaped dot", "/a%2Eb", strict, false},
		{"encoded dot segments", "/%2e%2e/etc/passwd", strict, false},
		{"a dot segment", "/a/./b", strict, false},
		{"a parent segment", "/a/../b", strict, false},
		{"a trailing parent segment", "/a/..", strict, false},
		{"a path parameter", "/a;jsessionid=1", strict, false},
		{"a backslash", "/a" + string(rune(92)) + "b", strict, false},
		{"a truncated escape", "/a%", strict, false},
		{"a half escape", "/a%2", strict, false},
		{"a malformed escape", "/a%zz", strict, false},
		{"a space", "/a b", strict, false},
		{"a non-ASCII byte", "/é", strict, false},
		{"an encoded slash, allowed", "/a%2fb", PathPolicy{AllowEncodedSlash: true}, true},
		{"an encoded backslash, allowed", "/a%5Cb", PathPolicy{AllowEncodedSlash: true}, true},
		{"an encoded NUL stays refused when slashes are allowed", "/a%00b", PathPolicy{AllowEncodedSlash: true}, false},
		{"a path parameter, allowed", "/a;x=1", PathPolicy{AllowPathParams: true}, true},
		{"dot segments stay refused when parameters are allowed", "/a/../b", PathPolicy{AllowPathParams: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.policy.check(tt.path); (err == nil) != tt.ok {
				t.Fatalf("check(%q) = %v, want ok=%v", tt.path, err, tt.ok)
			}
		})
	}
}

func TestRefusalsHoldWithTheRuleSetOffAndAreRecorded(t *testing.T) {
	tests := []struct {
		name    string
		request string
		change  func(*Config)
		want    int
		id      int
	}{
		{"an ordinary request", get("/page"), nil, 200, 0},
		{"an encoded slash", get("/a%2fb"), nil, 400, idPathNotCanon},
		{"a dot segment", get("/a/../admin"), nil, 400, idPathNotCanon},
		{"a name the site does not answer to", get("/page"), func(c *Config) { c.AllowedHosts = []string{"www.other.test"} }, 421, idHostNotAllowed},
		{"a name it does answer to", get("/page"), func(c *Config) { c.AllowedHosts = []string{"SHOP.example.test."} }, 200, 0},
		{"a name with a port", "GET /page HTTP/1.1\r\nHost: shop.example.test:8443\r\nConnection: close\r\n\r\n", func(c *Config) { c.AllowedHosts = []string{"shop.example.test"} }, 200, 0},
		{"a gzip request body", get("/page", "Content-Encoding: gzip\r\n"), nil, 415, idRequestEncoding},
		{"an identity request encoding", get("/page", "Content-Encoding: identity\r\n"), nil, 200, 0},
		{"two Content-Type headers", get("/page", "Content-Type: text/plain\r\n", "Content-Type: application/json\r\n"), nil, 400, idAmbiguousType},
		{"a header the site does not accept", get("/page", "Next-Action: abc\r\n"), func(c *Config) { c.DenyHeaders = []string{"next-action"} }, 400, idInternalHeader},
		{"the same header with underscores", get("/page", "Next_Action: abc\r\n"), func(c *Config) { c.DenyHeaders = []string{"Next-Action"} }, 400, idInternalHeader},
		{"that header on a site that did not ask", get("/page", "Next-Action: abc\r\n"), nil, 200, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen refusals
			s := start(t, func(c *Config) {
				ruleSetOff(c)
				c.OnMatch = seen.record
				if tt.change != nil {
					tt.change(c)
				}
			})
			status, _ := s.raw(t, tt.request)
			if status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
			if got := len(s.up.requests()) > 0; got != (tt.want == 200) {
				t.Fatalf("reached the application: %v", got)
			}
			if seen.last() != tt.id {
				t.Fatalf("recorded id %d, want %d", seen.last(), tt.id)
			}
		})
	}
}

func TestFrameworkControlHeadersNeverReachTheApplication(t *testing.T) {
	names := []string{"X-Middleware-Subrequest", "X_Middleware_Subrequest", "X-Middleware-Prefetch", "X-Invoke-Path", "X-Invoke-Status",
		"X-Matched-Path", "X-Now-Route-Matches", "X-HTTP-Method-Override", "X-Method-Override", "X-Nextjs-Data"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			s := start(t, ruleSetOff)
			status, _ := s.raw(t, get("/page", name+": middleware:middleware:middleware\r\n", "X-Application-Token: keep\r\n"))
			got := s.up.requests()
			if status != 200 || len(got) != 1 {
				t.Fatalf("status %d, %d requests", status, len(got))
			}
			dashed := strings.ReplaceAll(strings.ToLower(name), "_", "-")
			for header := range got[0].Header {
				if strings.ReplaceAll(strings.ToLower(header), "_", "-") == dashed {
					t.Fatalf("%s reached the application", header)
				}
			}
			if got[0].Header.Get("X-Application-Token") == "" {
				t.Fatal("an ordinary header was dropped with them")
			}
		})
	}
}

func TestAHeaderNamedInConnectionCannotRemoveTheProxysOwn(t *testing.T) {
	s := start(t, ruleSetOff)
	status, _ := s.raw(t, get("/page", "Connection: close, X-Forwarded-For, X-Real-IP, X-Forwarded-Proto\r\n"))
	got := s.up.requests()
	if status != 200 || len(got) != 1 {
		t.Fatalf("status %d, %d requests", status, len(got))
	}
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip", "X-Forwarded-Proto"} {
		if got[0].Header.Get(h) == "" {
			t.Errorf("%s was removed because the client listed it in Connection", h)
		}
	}
}

// The classic smuggling shapes. The proxy re-serialises every request it forwards and the engine inspects each one it
// parses, so whatever is hidden in a body either stays inert body text or is parsed as a request of its own and
// inspected like any other. What must never happen is an attack reaching the application as a request without having
// been looked at. Here the hidden request is an attack the rule set blocks, in blocking mode.
func TestSmuggledAttacksAreStillInspected(t *testing.T) {
	hidden := "GET /x?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\n\r\n"
	post := func(headers string, body string) string {
		return "POST /submit HTTP/1.1\r\n" + preamble + "Content-Type: text/plain\r\n" + headers + "\r\n" + body
	}
	chunkedHidden := "0\r\n\r\n" + hidden
	tests := map[string]string{
		"CL.TE":                     post("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", "5c\r\n"+hidden+"\r\n0\r\n\r\n"),
		"TE.CL":                     post("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", chunkedHidden),
		"TE.TE obfuscated":          post("Content-Length: 4\r\nTransfer-Encoding: xchunked\r\n", chunkedHidden),
		"TE with a space before :":  post("Content-Length: 4\r\nTransfer-Encoding : chunked\r\n", chunkedHidden),
		"TE tab after :":            post("Content-Length: 4\r\nTransfer-Encoding:\tchunked\r\n", chunkedHidden),
		"two Content-Length":        post("Content-Length: 4\r\nContent-Length: 60\r\n", "a=1&"+hidden),
		"Content-Length with plus":  post("Content-Length: +4\r\n", "a=1&"+hidden),
		"CL.0":                      post("Content-Length: "+strconv.Itoa(len(hidden))+"\r\n", hidden),
		"bare LF in a chunk header": post("Transfer-Encoding: chunked\r\n", "0\n\r\n"+hidden),
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			s := start(t, nil) // the rule set on, blocking
			s.raw(t, request)
			for _, got := range s.up.requests() {
				uri := strings.ToLower(got.RequestURI)
				if strings.Contains(uri, "script") || strings.Contains(uri, "%3c") {
					t.Fatalf("an attack hidden in a body reached the application as a request: %q", got.RequestURI)
				}
			}
		})
	}
}

func TestARequestWithABodyDoesNotShareItsApplicationConnection(t *testing.T) {
	var opened, closed atomic.Int32
	app := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	app.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			opened.Add(1)
		case http.StateClosed:
			closed.Add(1)
		}
	}
	app.Start()
	defer app.Close()
	s := start(t, func(c *Config) {
		ruleSetOff(c)
		c.Upstream = mustURL(app.URL)
	})
	for i := 0; i < 3; i++ {
		s.raw(t, get("/page"))
	}
	if opened.Load() != 1 || closed.Load() != 0 {
		t.Fatalf("three requests without a body: %d connections opened, %d closed; want 1 and 0 (the control: the connection is reused)", opened.Load(), closed.Load())
	}
	for i := 0; i < 3; i++ {
		s.raw(t, post("a=1"))
	}
	deadline := time.Now().Add(3 * time.Second)
	for closed.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if closed.Load() != 3 {
		t.Fatalf("three requests with a body closed %d application connections, want 3 (each one's own, so nothing is left on a reused connection)", closed.Load())
	}
}

func TestResponsePolicy(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		policy ResponsePolicy
		check  func(t *testing.T, h http.Header)
	}{
		{"nosniff is added", "/page", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("X-Content-Type-Options = %q", h.Get("X-Content-Type-Options"))
			}
		}},
		{"banners are removed", "/banner", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("X-Powered-By") != "" || h.Get("Server") != "" {
				t.Fatalf("banners remain: %q %q", h.Get("X-Powered-By"), h.Get("Server"))
			}
		}},
		{"banners are kept when asked", "/banner", ResponsePolicy{KeepBanners: true}, func(t *testing.T, h http.Header) {
			if h.Get("X-Powered-By") == "" {
				t.Fatal("the banner was removed although asked to keep it")
			}
		}},
		{"a cookie makes a response private", "/set-cookie", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("Cache-Control") != "private, no-store" {
				t.Fatalf("Cache-Control = %q", h.Get("Cache-Control"))
			}
		}},
		{"a cookie leaves caching alone when asked", "/set-cookie", ResponsePolicy{KeepCaching: true}, func(t *testing.T, h http.Header) {
			if h.Get("Cache-Control") != "" {
				t.Fatalf("Cache-Control = %q", h.Get("Cache-Control"))
			}
		}},
		{"HTML at a stylesheet's address is not cached", "/account/profile.css", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("Cache-Control") != "private, no-store" {
				t.Fatalf("Cache-Control = %q", h.Get("Cache-Control"))
			}
		}},
		{"an ordinary page is left to the application", "/page", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("Cache-Control") != "" {
				t.Fatalf("Cache-Control = %q on an ordinary page", h.Get("Cache-Control"))
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := start(t, func(c *Config) { ruleSetOff(c); c.Responses = tt.policy })
			_, reply := s.raw(t, get(tt.path))
			resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(reply)), nil)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, resp.Header)
		})
	}
}

func multipartBody(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--XX\r\n" + p + "\r\n")
	}
	b.WriteString("--XX--\r\n")
	return b.String()
}

func filePart(name, content string) string {
	return "Content-Disposition: form-data; name=\"f\"; filename=\"" + name + "\"\r\nContent-Type: application/octet-stream\r\n\r\n" + content
}

func uploadRequest(body string) string {
	return "POST /upload HTTP/1.1\r\n" + preamble + "Content-Type: multipart/form-data; boundary=XX\r\nContent-Length: " + strconv.Itoa(len(body)) +
		"\r\nConnection: close\r\n\r\n" + body
}

func TestUploadPolicy(t *testing.T) {
	jpeg := "\xff\xd8\xff\xe0\x00\x10JFIF\x00 an ordinary picture \xff\xd9"
	shell := "GIF89a<?php system($_GET['c']); ?>"
	tests := []struct {
		name    string
		body    string
		policy  UploadPolicy
		refused int // the id, or 0
	}{
		{"a picture", multipartBody(filePart("photo.jpg", jpeg)), UploadPolicy{}, 0},
		{"a document with a long name", multipartBody(filePart("Quarterly report - final (2).pdf", "%PDF-1.7 text")), UploadPolicy{}, 0},
		{"a text field mentioning php", multipartBody("Content-Disposition: form-data; name=\"comment\"\r\n\r\nuse <?php echo 1; ?> in your template"), UploadPolicy{}, 0},
		{"an XML file", multipartBody(filePart("data.xml", "<?xml version=\"1.0\"?><a/>")), UploadPolicy{}, 0},
		{"a script name", multipartBody(filePart("shell.php", "x")), UploadPolicy{}, idUploadName},
		{"a script name in capitals", multipartBody(filePart("SHELL.PHP", "x")), UploadPolicy{}, idUploadName},
		{"a double extension", multipartBody(filePart("shell.php.jpg", jpeg)), UploadPolicy{}, idUploadName},
		{"a trailing dot", multipartBody(filePart("shell.php.", "x")), UploadPolicy{}, idUploadName},
		{"a trailing space", multipartBody(filePart("shell.php ", "x")), UploadPolicy{}, idUploadName},
		{"a semicolon trick", multipartBody(filePart("shell.asp;.jpg", "x")), UploadPolicy{}, idUploadName},
		{"phtml", multipartBody(filePart("a.phtml", "x")), UploadPolicy{}, idUploadName},
		{"php5", multipartBody(filePart("a.php5", "x")), UploadPolicy{}, idUploadName},
		{"jsp", multipartBody(filePart("a.jsp", "x")), UploadPolicy{}, idUploadName},
		{"a NUL in the name, percent-encoded", multipartBody(filePart("shell.php%00.jpg", jpeg)), UploadPolicy{}, idUploadName},
		{"an NTFS stream", multipartBody(filePart("shell.php::$DATA", "x")), UploadPolicy{}, idUploadName},
		{"htaccess", multipartBody(filePart(".htaccess", "AddType application/x-httpd-php .jpg")), UploadPolicy{}, idUploadName},
		{"web.config", multipartBody(filePart("web.config", "<configuration/>")), UploadPolicy{}, idUploadName},
		{"a path in the name", multipartBody(filePart("..\\..\\shell.php", "x")), UploadPolicy{}, idUploadName},
		{"an RFC 5987 name", multipartBody("Content-Disposition: form-data; name=\"f\"; filename*=UTF-8''%73hell.php\r\n\r\nx"), UploadPolicy{}, idUploadName},
		{"an unquoted name", multipartBody("Content-Disposition: form-data; name=f; filename=shell.php\r\n\r\nx"), UploadPolicy{}, idUploadName},
		{"a picture with a script in it", multipartBody(filePart("photo.jpg", shell)), UploadPolicy{}, idUploadScript},
		{"a script far into a large file", multipartBody(filePart("photo.jpg", jpeg+strings.Repeat("A", 50000)+"<?= `id` ?>")), UploadPolicy{}, idUploadScript},
		{"an asp tag", multipartBody(filePart("photo.jpg", "x<%@ Page Language=\"C#\" %>")), UploadPolicy{}, idUploadScript},
		{"script names allowed", multipartBody(filePart("shell.php", "x")), UploadPolicy{AllowExecutableNames: true}, 0},
		{"script content allowed", multipartBody(filePart("photo.jpg", shell)), UploadPolicy{AllowScriptContent: true}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen refusals
			s := start(t, func(c *Config) {
				ruleSetOff(c)
				c.OnMatch = seen.record
				c.Uploads = tt.policy
				c.CRS.RequestBodyLimit = 1 << 20
			})
			status, _ := s.raw(t, uploadRequest(tt.body))
			if tt.refused == 0 {
				if status != 200 || len(s.up.requests()) != 1 {
					t.Fatalf("a harmless upload: status %d, %d requests", status, len(s.up.requests()))
				}
				return
			}
			if status != 403 || len(s.up.requests()) != 0 || seen.last() != tt.refused {
				t.Fatalf("status %d, %d requests, id %d; want 403, none, %d", status, len(s.up.requests()), seen.last(), tt.refused)
			}
		})
	}
}

func TestWordPressPolicy(t *testing.T) {
	on := func(c *Config) { ruleSetOff(c); c.WordPress = WordPressPolicy{Enabled: true, LoginPerMinute: 3} }
	tests := []struct {
		name, path string
		change     func(*Config)
		want       int
	}{
		{"a picture in uploads", "/wp-content/uploads/2026/10/photo.jpg", on, 200},
		{"a script in uploads", "/wp-content/uploads/2026/10/shell.php", on, 403},
		{"a script in uploads, in capitals", "/wp-content/UPLOADS/shell.PHP", on, 403},
		{"a script with a path after it", "/wp-content/uploads/shell.php/x.jpg", on, 403},
		{"phtml in a cache directory", "/wp-content/cache/a.phtml", on, 403},
		{"a script in a backup directory", "/wp-content/backup-db/x.php", on, 403},
		{"a plugin's own script", "/wp-content/plugins/contact-form/handler.php", on, 200},
		{"admin-ajax", "/wp-admin/admin-ajax.php", on, 200},
		{"xmlrpc is off by default", "/xmlrpc.php", on, 403},
		{"xmlrpc allowed", "/xmlrpc.php", func(c *Config) { on(c); c.WordPress.AllowXMLRPC = true }, 200},
		{"a script in uploads on a site not marked as WordPress", "/wp-content/uploads/shell.php", ruleSetOff, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := start(t, tt.change)
			if status, _ := s.raw(t, get(tt.path)); status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
		})
	}

	t.Run("login attempts are limited per address", func(t *testing.T) {
		s := start(t, on)
		login := "POST /wp-login.php HTTP/1.1\r\n" + preamble + "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\nConnection: close\r\n\r\nlog=a&pwd=b"
		var statuses []int
		for i := 0; i < 5; i++ {
			status, _ := s.raw(t, login)
			statuses = append(statuses, status)
		}
		if want := []int{200, 200, 200, 429, 429}; !equalInts(statuses, want) {
			t.Fatalf("statuses %v, want %v", statuses, want)
		}
		if status, _ := s.raw(t, get("/wp-login.php")); status != 200 {
			t.Fatalf("reading the login page was limited: %d", status)
		}
	})
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestOneAddressCannotHoldManyConnectionsOpen(t *testing.T) {
	s := start(t, func(c *Config) { ruleSetOff(c); c.MaxConnsPerIP = 3 })
	var held []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.DialTimeout("tcp", s.addr, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond) // let the server see all three

	extra, err := net.DialTimeout("tcp", s.addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetDeadline(time.Now().Add(3 * time.Second))
	extra.Write([]byte(get("/page")))
	if _, err := bufio.NewReader(extra).ReadString('\n'); err == nil {
		t.Fatal("a fourth connection from the same address was served")
	}

	held[0].Close() // a place comes free
	time.Sleep(100 * time.Millisecond)
	if status, _ := s.raw(t, get("/page")); status != 200 {
		t.Fatalf("after one was closed, a new connection got %d", status)
	}
}

func TestHTTP2LimitsAreAdvertisedToClients(t *testing.T) {
	s := start(t, ruleSetOff)
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = s.edge.Server("")
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "example.com", NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated %q, want h2", conn.ConnectionState().NegotiatedProtocol)
	}
	conn.Write([]byte(http2.ClientPreface))
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("no SETTINGS frame from the server: %v", err)
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			streams, ok := sf.Value(http2.SettingMaxConcurrentStreams)
			if !ok || streams != 100 {
				t.Fatalf("MAX_CONCURRENT_STREAMS = %d (set: %v), want 100", streams, ok)
			}
			if size, ok := sf.Value(http2.SettingMaxFrameSize); ok && size > 16<<10 {
				t.Fatalf("MAX_FRAME_SIZE = %d, want 16384 or less", size)
			}
			return
		}
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
