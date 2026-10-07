// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/formats"
	"github.com/YurilLAB/coraza/carnical/inspect"
	"github.com/YurilLAB/coraza/carnical/proxy"
)

// This is executable startup and TCP forwarding behavior, which cannot be expressed as an engine profile.
func TestRequestFormatsAtCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "carnical")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	t.Run("site configuration parser", func(t *testing.T) {
		tests := []struct {
			name, data string
			bad        bool
		}{
			{name: "empty settings", data: "{\"version\":1,\"flags\":{}}", bad: false},
			{name: "boolean string option", data: "{\"version\":1,\"flags\":{\"upstream\":true}}", bad: true},
			{name: "all flag kinds", data: "{\"version\":1,\"flags\":{\"upstream\":\"http://example.test\",\"local-rules\":false,\"max-body\":2048,\"max-upstream\":2,\"ddos-rate\":0.5,\"eval-budget\":\"500ms\"}}", bad: false},
			{name: "unknown field", data: "{\"version\":1,\"flags\":{},\"other\":1}", bad: true},
			{name: "wrong version", data: "{\"version\":2,\"flags\":{}}", bad: true},
			{name: "null root", data: "null", bad: true},
			{name: "array root", data: "[]", bad: true},
			{name: "null flags", data: "{\"version\":1,\"flags\":null}", bad: true},
			{name: "missing version", data: "{\"flags\":{}}", bad: true},
			{name: "missing flags", data: "{\"version\":1}", bad: true},
			{name: "duplicate root field", data: "{\"version\":1,\"version\":1,\"flags\":{}}", bad: true},
			{name: "escaped duplicate flag", data: "{\"version\":1,\"flags\":{\"mode\":\"block\",\"\\u006dode\":\"off\"}}", bad: true},
			{name: "duplicate flags object", data: "{\"version\":1,\"flags\":{},\"flags\":{}}", bad: true},
			{name: "null flag", data: "{\"version\":1,\"flags\":{\"mode\":null}}", bad: true},
			{name: "unknown flag", data: "{\"version\":1,\"flags\":{\"mod\":\"block\"}}", bad: true},
			{name: "case alias", data: "{\"version\":1,\"flags\":{\"MODE\":\"block\"}}", bad: true},
			{name: "nested string", data: "{\"version\":1,\"flags\":{\"mode\":{\"value\":\"block\"}}}", bad: true},
			{name: "string boolean", data: "{\"version\":1,\"flags\":{\"local-rules\":\"false\"}}", bad: true},
			{name: "number boolean", data: "{\"version\":1,\"flags\":{\"local-rules\":0}}", bad: true},
			{name: "string integer", data: "{\"version\":1,\"flags\":{\"max-body\":\"2048\"}}", bad: true},
			{name: "fractional integer", data: "{\"version\":1,\"flags\":{\"max-body\":1.5}}", bad: true},
			{name: "integer overflow", data: "{\"version\":1,\"flags\":{\"max-body\":9223372036854775808}}", bad: true},
			{name: "float overflow", data: "{\"version\":1,\"flags\":{\"ddos-rate\":1e999}}", bad: true},
			{name: "invalid duration", data: "{\"version\":1,\"flags\":{\"eval-budget\":\"later\"}}", bad: true},
			{name: "numeric duration", data: "{\"version\":1,\"flags\":{\"eval-budget\":2}}", bad: true},
			{name: "recursive config", data: "{\"version\":1,\"flags\":{\"config\":\"next.json\"}}", bad: true},
			{name: "file check action", data: "{\"version\":1,\"flags\":{\"check\":true}}", bad: true},
			{name: "file network action", data: "{\"version\":1,\"flags\":{\"check-origin\":true}}", bad: true},
			{name: "file HTTP action", data: `{"version":1,"flags":{"check-origin-http":true}}`, bad: true},
			{name: "file version action", data: "{\"version\":1,\"flags\":{\"version\":true}}", bad: true},
			{name: "trailing document", data: "{\"version\":1,\"flags\":{}} {}", bad: true},
			{name: "truncated document", data: "{\"version\":1,\"flags\":{\"mode\":\"block\"}", bad: true},
			{name: "invalid UTF8", data: "{\"version\":1,\"flags\":{\"mode\":\"" + string([]byte{0xff}) + "\"}}", bad: true},
			{name: "over size limit", data: "{\"version\":1,\"flags\":{}}" + strings.Repeat(" ", maxSiteConfigBytes), bad: true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				flags := flag.NewFlagSet("site", flag.ContinueOnError)
				upstream := flags.String("upstream", "", "")
				flags.String("mode", "detect", "")
				localRules := flags.Bool("local-rules", true, "")
				flags.Int64("max-body", 1<<20, "")
				flags.Int("max-upstream", 256, "")
				flags.Float64("ddos-rate", 50, "")
				flags.Duration("eval-budget", time.Second, "")
				flags.String("config", "", "")
				flags.Bool("check", false, "")
				flags.Bool("check-origin", false, "")
				flags.Bool("check-origin-http", false, "")
				flags.Bool("version", false, "")
				if err := flags.Parse([]string{"-upstream", "http://override.test", "-local-rules=false"}); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "site.json")
				if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
					t.Fatal(err)
				}
				err := loadSiteConfig(path, flags)
				if (err != nil) != tc.bad {
					t.Fatalf("error %v, want invalid=%v", err, tc.bad)
				}
				if !tc.bad && (*upstream != "http://override.test" || *localRules) {
					t.Fatal("file replaced explicit CLI settings")
				}
			})
		}
		t.Run("symlink file", func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "site.json")
			if err := os.WriteFile(path, []byte(`{"version":1,"flags":{}}`), 0600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "link.json")
			if err := os.Symlink(path, link); err != nil {
				if runtime.GOOS == "windows" {
					t.Skip("Windows symlink creation requires host privilege")
				}
				t.Fatal(err)
			}
			if err := loadSiteConfig(link, flag.NewFlagSet("site", flag.ContinueOnError)); err == nil {
				t.Fatal("symlink accepted as configuration")
			}
		})
		t.Run("nonregular file", func(t *testing.T) {
			if err := loadSiteConfig(t.TempDir(), flag.NewFlagSet("site", flag.ContinueOnError)); err == nil {
				t.Fatal("directory accepted as config")
			}
		})
	})

	type received struct {
		body, encoding string
		length         int64
		target         string
	}
	requests := make(chan received, 64)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__cli_test_ready" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad body", 400)
				return
			}
			requests <- received{string(body), r.Header.Get("Content-Encoding"), r.ContentLength, r.RequestURI}
		}
		w.WriteHeader(200)
	}))
	defer app.Close()
	tlsApp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests <- received{target: r.RequestURI} }))
	defer tlsApp.Close()

	// The authenticated origin uses a dedicated CA plus an exact certificate
	// identity allowlist. A different identity signed by that CA is still denied.
	type originCredential struct {
		cert            *x509.Certificate
		pair            tls.Certificate
		certPEM, keyPEM []byte
	}
	issue := func(template *x509.Certificate, issuer *originCredential) originCredential {
		_, key, err := ed25519.GenerateKey(cryptorand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		parent, signingKey := template, key
		if issuer != nil {
			parent, signingKey = issuer.cert, issuer.pair.PrivateKey.(ed25519.PrivateKey)
		}
		der, err := x509.CreateCertificate(cryptorand.Reader, template, parent, key.Public(), signingKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return originCredential{parsed, pair, certPEM, keyPEM}
	}
	now := time.Now()
	ca := issue(&x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	foreignCA := issue(&x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	serverIdentity := issue(&x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, &ca)
	identities := map[string]originCredential{}
	for _, tc := range []struct {
		name          string
		serial        int64
		ca            *originCredential
		usage         x509.ExtKeyUsage
		before, after time.Time
	}{
		{"good", 4, &ca, x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(time.Hour)},
		{"wrong-site", 5, &ca, x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(time.Hour)},
		{"foreign", 4, &foreignCA, x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(time.Hour)},
		{"expired", 6, &ca, x509.ExtKeyUsageClientAuth, now.Add(-2 * time.Hour), now.Add(-time.Hour)},
		{"future", 7, &ca, x509.ExtKeyUsageClientAuth, now.Add(time.Hour), now.Add(2 * time.Hour)},
		{"server-only", 8, &ca, x509.ExtKeyUsageServerAuth, now.Add(-time.Hour), now.Add(time.Hour)},
	} {
		t.Run("origin credential fixture "+tc.name, func(t *testing.T) {
			identities[tc.name] = issue(&x509.Certificate{SerialNumber: big.NewInt(tc.serial), NotBefore: tc.before, NotAfter: tc.after, ExtKeyUsage: []x509.ExtKeyUsage{tc.usage}}, tc.ca)
		})
	}

	t.Run("origin file protections", func(t *testing.T) {
		for _, tc := range []struct {
			name                               string
			mode                               os.FileMode
			symlink, directory, oversized, bad bool
		}{
			{name: "private key", mode: 0600},
			{name: "read-only service group", mode: 0640},
			{name: "world-readable key", mode: 0644, bad: true},
			{name: "group-writable key", mode: 0660, bad: true},
			{name: "symlink key", mode: 0600, symlink: true, bad: true},
			{name: "directory key", directory: true, bad: true},
			{name: "oversized key", mode: 0600, oversized: true, bad: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if runtime.GOOS == "windows" && (tc.mode == 0644 || tc.mode == 0660) {
					t.Skip("Unix permissions do not describe Windows ACLs")
				}
				dir := t.TempDir()
				path := filepath.Join(dir, "edge.key")
				data := identities["good"].keyPEM
				if tc.oversized {
					data = bytes.Repeat([]byte(" "), (64<<10)+1)
				}
				if tc.directory {
					path = dir
				} else {
					if err := os.WriteFile(path, data, tc.mode); err != nil {
						t.Fatal(err)
					}
					if runtime.GOOS != "windows" {
						if err := os.Chmod(path, tc.mode); err != nil {
							t.Fatal(err)
						}
					}
				}
				if tc.symlink {
					link := filepath.Join(dir, "link.key")
					if err := os.Symlink(path, link); err != nil {
						if runtime.GOOS == "windows" {
							t.Skip("Windows symlink creation requires host privilege")
						}
						t.Fatal(err)
					}
					path = link
				}
				got, err := readOriginFile(path, 64<<10, true)
				if (err != nil) != tc.bad {
					t.Fatalf("key acceptance: error=%v want refused=%v", err, tc.bad)
				}
				if !tc.bad && !bytes.Equal(got, data) {
					t.Fatal("key bytes changed")
				}
			})
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	originCalls := make(chan received, 64)
	authOrigin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.VerifiedChains) == 0 || r.TLS.PeerCertificates[0].SerialNumber.Cmp(big.NewInt(4)) != 0 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/__cli_test_ready" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad body", 400)
				return
			}
			originCalls <- received{string(body), r.Header.Get("Content-Encoding"), r.ContentLength, r.RequestURI}
		}
		w.WriteHeader(200)
	}))
	authOrigin.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverIdentity.pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true}
	authOrigin.StartTLS()
	defer authOrigin.Close()

	t.Run("origin certificate snapshot survives input mutation", func(t *testing.T) {
		identity := identities["good"].pair
		identity.Certificate = [][]byte{bytes.Clone(identity.Certificate[0])}
		// A supplied Leaf is not authority; parse the actual certificate bytes.
		identity.Leaf = identities["foreign"].cert
		target, err := url.Parse(authOrigin.URL)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := (proxy.OriginTLS{Roots: roots, Certificate: &identity}).ClientConfig(target)
		if err != nil {
			t.Fatal(err)
		}
		clear(identity.Certificate[0])
		transport := &http.Transport{TLSClientConfig: cfg}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		request, err := http.NewRequest(http.MethodHead, authOrigin.URL+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("input mutation changed the TLS identity: %v", err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("authenticated origin returned %d", response.StatusCode)
		}
		select {
		case <-originCalls:
		default:
			t.Fatal("authenticated request did not reach the origin")
		}
	})

	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	const good = `{"note":"SECRET_TOKEN_CLI_TEST","a":1}`
	var packed bytes.Buffer
	gz := gzip.NewWriter(&packed)
	if _, err := gz.Write([]byte(good)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	compress := func(body string) string {
		var out bytes.Buffer
		w := gzip.NewWriter(&out)
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	// Compress below the wire limit without tripping the ratio limit, then expand above the default non-upload cap.
	random := make([]byte, 30000)
	_, _ = rand.New(rand.NewSource(1)).Read(random)
	largeJSON := `{"data":"` + strings.Repeat(base64.StdEncoding.EncodeToString(random), 4) + `"}`
	upload := func(name, content string) string {
		return "--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + name + "\"\r\nContent-Type: text/plain\r\n\r\n" + content + "\r\n--B--\r\n"
	}
	tests := []struct {
		site                                                                        string
		preflight                                                                   bool
		trustOrigin                                                                 bool
		originAuth                                                                  string
		probeHTTP                                                                   bool
		apiSpec                                                                     string
		headers                                                                     map[string]string
		alsoRules                                                                   []int
		statsRule                                                                   int
		statsBlocked, statsMonitored                                                uint64
		repeat                                                                      int
		apiRate                                                                     int
		apiPaths                                                                    string
		statuses                                                                    []int
		targets, forwarding, extraArgs                                              []string
		name, mode, policy, method, target, ct, body, encoding, logRule, originBody string
		allowEncoding, fails, policyDir                                             bool
		status                                                                      int
	}{
		{name: "origin authentication forwards good traffic", originAuth: "good", method: "GET", target: "/page", status: 200, repeat: 4},
		{name: "origin identity does not skip inspection", originAuth: "good", method: "GET", target: "/page?q=%3Cscript%3Ealert(1)%3C/script%3E", extraArgs: []string{"-mode", "block"}, mode: "block", status: 403},
		{name: "origin certificate preflight confirms HTTP acceptance", originAuth: "good", extraArgs: []string{"-check", "-check-origin", "-check-origin-http"}, preflight: true, probeHTTP: true},
		{name: "origin refuses missing certificate", originAuth: "none", extraArgs: []string{"-check", "-check-origin", "-check-origin-http"}, fails: true},
		{name: "origin refuses foreign CA certificate", originAuth: "foreign", extraArgs: []string{"-check", "-check-origin", "-check-origin-http"}, fails: true},
		{name: "origin refuses different identity from its CA", originAuth: "wrong-site", extraArgs: []string{"-check", "-check-origin", "-check-origin-http"}, fails: true},
		{name: "origin expired certificate refuses startup", originAuth: "expired", extraArgs: []string{"-check"}, fails: true},
		{name: "origin future certificate refuses startup", originAuth: "future", extraArgs: []string{"-check"}, fails: true},
		{name: "origin server certificate cannot serve as client identity", originAuth: "server-only", extraArgs: []string{"-check"}, fails: true},
		{name: "origin key mismatch refuses startup", originAuth: "mismatch", extraArgs: []string{"-check"}, fails: true},
		{name: "origin certificate needs paired key", extraArgs: []string{"-origin-client-cert", "missing.pem", "-check"}, fails: true},
		{name: "origin TLS settings refuse plaintext upstream", extraArgs: []string{"-origin-ca-file", "missing.pem", "-check"}, fails: true},
		{name: "HTTP preflight requires explicit actions", extraArgs: []string{"-check-origin-http"}, fails: true},
		{name: "site check accepts trusted origin certificate", site: `{"version":1,"flags":{"upstream":"$TLSORIGIN","origin-allow":"127.0.0.1/32"}}`, extraArgs: []string{"-check", "-check-origin"}, preflight: true, trustOrigin: true},
		{name: "site check rejects untrusted origin certificate", site: `{"version":1,"flags":{"upstream":"$TLSORIGIN","origin-allow":"127.0.0.1/32"}}`, extraArgs: []string{"-check", "-check-origin"}, fails: true},
		{name: "site check rejects private DNS without allowance", site: `{"version":1,"flags":{"upstream":"$DNSORIGIN"}}`, extraArgs: []string{"-check", "-check-origin"}, fails: true},
		{name: "site shipped local example", site: "local-example", method: "GET", target: "/page", status: 200},
		{name: "site config serves good request", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"block\",\"formats-mode\":\"block\",\"local-rules\":true,\"max-body\":1048576,\"ddos-rate\":50.5,\"eval-budget\":\"2s\"}}", method: "GET", target: "/page", status: 200},
		{name: "site config blocks injection", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"block\",\"formats-mode\":\"block\"}}", method: "GET", target: "/page?q=%3Cscript%3Ealert(1)%3C/script%3E", status: 403},
		{name: "site config format enforcement", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"block\",\"formats-mode\":\"block\"}}", ct: "application/json", body: "{\"a\":1,\"a\":2}", status: 400},
		{name: "explicit false overrides file true", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"off\",\"allow-request-encoding\":true}}", mode: "off", extraArgs: []string{"-allow-request-encoding=false"}, status: 200},
		{name: "explicit enforcement overrides file monitor", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"off\",\"formats-mode\":\"monitor\"}}", mode: "block", ct: "application/json", body: "{\"a\":1,\"a\":2}", status: 400},
		{name: "site config private origin needs allowance", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\"}}", fails: true},
		{name: "site check does not listen or require inherited socket", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"systemd-socket\":true}}", preflight: true, extraArgs: []string{"-check"}},
		{name: "site check verifies origin connectivity without HTTP", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\"}}", preflight: true, extraArgs: []string{"-check", "-check-origin"}},
		{name: "site check validates confine port list", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"confine\":true,\"confine-connect\":\"invalid\"}}", fails: true, extraArgs: []string{"-check"}},
		{name: "site check permits named listening port", extraArgs: []string{"-check", "-listen", "127.0.0.1:http"}, preflight: true},
		{name: "check validates listen syntax", extraArgs: []string{"-check", "-listen", "invalid"}, fails: true},
		{name: "check validates upstream port", extraArgs: []string{"-check", "-upstream", "http://127.0.0.1:0"}, fails: true},
		{name: "check origin requires check", extraArgs: []string{"-check-origin"}, fails: true},
		{name: "contract correct URL query", mode: "block", apiSpec: "example", method: "GET", target: "/api/import?src=https%3A%2F%2Fassets.example.test%2Fpublic%2Fphoto.png", status: 200},
		{name: "contract correct JSON URL", mode: "block", apiSpec: "example", target: "/api/import", ct: "application/json", body: `{"src":"https://assets.example.test/public/photo.png"}`, status: 200},
		{name: "contract attacker host", mode: "block", apiSpec: "example", method: "GET", target: "/api/import?src=https%3A%2F%2Fevil.example%2Fpublic%2Fphoto.png", status: 400, logRule: `"rule":5003103`},
		{name: "contract private IP", mode: "block", apiSpec: "example", method: "GET", target: "/api/import?src=http%3A%2F%2F127.0.0.1%2F", status: 400, logRule: `"rule":5003103`},
		{name: "contract userinfo bypass", mode: "block", apiSpec: "example", target: "/api/import", ct: "application/json", body: `{"src":"https://assets.example.test@evil.example/public/photo.png"}`, status: 400, logRule: `"rule":5003108`},
		{name: "contract escaped JSON host bypass", mode: "block", apiSpec: "example", target: "/api/import", ct: "application/json", body: `{"src":"https://\u0065vil.example/public/photo.png"}`, status: 400, logRule: `"rule":5003108`},
		{name: "contract missing URL", mode: "block", apiSpec: "example", target: "/api/import", ct: "application/json", body: `{}`, status: 400, logRule: `"rule":5003108`},
		{name: "contract independently detects duplicate JSON", mode: "block", apiSpec: "example", policy: `{"rules":{"json-duplicate-key":"off"}}`, target: "/api/import", ct: "application/json", body: `{"src":"https://assets.example.test/public/photo.png","src":"https://evil.example/x"}`, status: 400, logRule: `"rule":5003006`},
		{name: "contract refuses JSON relabeled text", mode: "block", apiSpec: "example", target: "/api/import", ct: "text/plain", body: `{"src":"https://evil.example/x"}`, status: 415, logRule: `"rule":5002040`},
		{name: "contract unknown privileged JSON field", mode: "block", apiSpec: "example", target: "/api/import", ct: "application/json", body: `{"src":"https://assets.example.test/public/photo.png","role":"admin"}`, status: 400, logRule: `"rule":5003109`},
		{name: "contract JSON array shape bypass", mode: "block", apiSpec: "example", target: "/api/import", ct: "application/json", body: `[{"src":"https://assets.example.test/public/photo.png"}]`, status: 400, logRule: `"rule":5003108`},
		{name: "contract duplicate scalar", mode: "block", apiSpec: "example", method: "GET", target: "/api/search?user_id=1&user_id=2", status: 400, logRule: `"rule":5003103`},
		{name: "contract scalar bracket alias", mode: "block", apiSpec: "example", method: "GET", target: "/api/search?user_id=1&user_id_extra[]=2", status: 400, logRule: `"rule":5003113`},
		{name: "contract optional array bracket alias", mode: "block", apiSpec: "example", method: "GET", target: "/api/search?user_id=1&tags[]=red", status: 400, logRule: `"rule":5003113`},
		{name: "contract declared repeated array", mode: "block", apiSpec: "example", method: "GET", target: "/api/search?user_id=1&tags=red&tags=blue", status: 200},
		{name: "contract typed XPath protection", mode: "block", apiSpec: "example", method: "GET", target: "/api/search?user_id=0%20or%20true%28%29", status: 400, logRule: `"rule":5003103`},
		{name: "contract monitor URL", mode: "monitor", apiSpec: "example", method: "GET", target: "/api/import?src=https%3A%2F%2Fevil.example%2Fx", extraArgs: []string{"-api-spec-mode", "monitor"}, status: 200, logRule: `"rule":5003103`},
		{name: "contract block needs strict formats", mode: "monitor", apiSpec: "example", fails: true},
		{name: "contract invalid mode", mode: "block", extraArgs: []string{"-api-spec-mode", "ignored"}, fails: true},
		{name: "contract malformed specification", mode: "block", apiSpec: `{`, fails: true},
		{name: "contract empty specification", mode: "block", apiSpec: `{"openapi":"3.0.3","paths":{}}`, fails: true},
		{name: "contract empty required body media", mode: "block", apiSpec: `{"openapi":"3.0.3","paths":{"/api/x":{"post":{"requestBody":{"required":true,"content":{}}}}}}`, fails: true},
		{name: "contract unsupported constraints", mode: "block", apiSpec: `{"openapi":"3.0.3","paths":{"/api/x":{"get":{"parameters":[{"name":"x","in":"query","schema":{"type":"string","pattern":"(?=a)"}}]}}}}`, fails: true},
		{name: "contract object parameter", mode: "block", apiSpec: `{"openapi":"3.0.3","paths":{"/api/x":{"get":{"parameters":[{"name":"x","in":"query","style":"deepObject","schema":{"type":"object"}}]}}}}`, fails: true},
		{name: "contract non JSON body", mode: "block", apiSpec: `{"openapi":"3.0.3","paths":{"/api/x":{"post":{"requestBody":{"content":{"application/x-www-form-urlencoded":{"schema":{"type":"object","properties":{"x":{"type":"string"}}}}}}}}}}`, fails: true},
		{name: "live supplemental XPath", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/api?q=%27%20or%20true%28%29%20or%20%27a%27%3D%27b", status: 403, logRule: `"rule":5006001`},
		{name: "live heldout XPath comments", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/api?q=%27%20or%20%28%3Acomment%3A%29%20true%28%29", status: 403, logRule: `"rule":5006009`},
		{name: "live heldout deep traversal", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/api?q=%2525252e%2525252e%2525252fetc%2525252fpasswd", status: 403, logRule: `"rule":5006006`},
		{name: "live local rules detect mode", mode: "block", extraArgs: []string{"-mode", "detect"}, method: "GET", target: "/api?q=%27%20or%20true%28%29", status: 200, logRule: `"rule":5006001`},
		{name: "live local rules opt out", mode: "block", extraArgs: []string{"-mode", "block", "-local-rules=false"}, method: "GET", target: "/api?q=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH", status: 200},
		{name: "live supplemental quoted shell", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/api?q=%3Bi%27%27d", status: 403, logRule: `"rule":5006003`},
		{name: "live parameter collision", mode: "block", ct: "application/x-www-form-urlencoded", body: "user.name=a&user_name=b", status: 400, logRule: `"rule":5002608`},
		{name: "live XML attribute bypass", mode: "block", extraArgs: []string{"-mode", "block"}, ct: "application/xml", body: `<input value="' or true() or 'a'='b"/>`, status: 403, logRule: `"rule":5006001`},
		{name: "default monitor logs a GET mutation", method: "GET", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 200, logRule: `"rule":5002310`},
		{name: "block GET mutation with CRS off", mode: "block", method: "GET", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 403, logRule: `"rule":5002310`},
		{name: "block HEAD mutation with CRS off", mode: "block", method: "HEAD", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002314"},
		{name: "HEAD protocol name case alias", mode: "block", method: "HEAD", target: "/graphql?%51uery=mutation%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002314"},
		{name: "HEAD protocol alias independent transport guard", mode: "block", policy: "{\"rules\":{\"graphql-safe-method-mutation\":\"off\"}}", method: "HEAD", target: "/api/gql?QUERY=mutation%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002315"},
		{name: "POST JSON protocol name case alias", mode: "block", target: "/graphql", ct: "application/json", body: "{\"Query\":\"mutation{deleteUser}\"}", status: 400, logRule: "\"rule\":5002308"},
		{name: "independent transport guard with mutation rule off", mode: "block", policy: "{\"rules\":{\"graphql-safe-method-mutation\":\"off\"}}", method: "HEAD", target: "/api/gql?query=mutation%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002315", repeat: 3,
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002315, statsBlocked: 3},
		{name: "protocol alias method override multiple detection totals", mode: "monitor", method: "HEAD", target: "/api/gql?%51uery=mutation%7BSECRET_TOKEN_CLI_TEST%7D&_method=POST", status: 200,
			logRule: "\"rule\":5002314", alsoRules: []int{5002315, 5002308, 5002317}, repeat: 2,
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002315, statsMonitored: 2},
		{name: "discovered GraphQL through PUT form", mode: "block", method: "PUT", target: "/api/gql", ct: "application/x-www-form-urlencoded", body: "query=mutation%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002315"},
		{name: "discovered GraphQL after an empty batch prefix", mode: "block", method: "PUT", target: "/api/gql", ct: "application/json", body: "[{}, {\"query\":\"mutation{deleteUser}\"}]", status: 403, logRule: "\"rule\":5002315"},
		{name: "GraphQL discovery beyond retained batch elements", mode: "block", target: "/api/gql", ct: "application/json", body: "[" + strings.Repeat("{},", 12) + "{\"query\":\"mutation{deleteUser}\"}]", status: 400, logRule: "\"rule\":5002305"},
		{name: "conflicting URL and body selection", mode: "block", method: "POST", target: "/graphql?operationName=Read", ct: "application/json", body: "{\"query\":\"query Read{a} mutation Write{b}\",\"operationName\":\"Write\"}", status: 400, logRule: "\"rule\":5002316"},
		{name: "discovered URL operation with body-only selection", mode: "block", target: "/api/gql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read", ct: "application/json", body: "{\"operationName\":\"Write\"}", status: 400, logRule: "\"rule\":5002316"},
		{name: "discovered URL operation with body-only form selection", mode: "block", target: "/api/gql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read", ct: "application/x-www-form-urlencoded", body: "operationName=Write", status: 400, logRule: "\"rule\":5002316"},
		{name: "discovered URL operation with body-only variables", mode: "block", target: "/api/gql?query=%7Ba%7D", ct: "application/json", body: "{\"variables\":{\"admin\":true}}", status: 400, logRule: "\"rule\":5002316"},
		{name: "noncanonical HEAD token", mode: "off", method: "head", target: "/api/gql?query=mutation%7BdeleteUser%7D", status: 400, logRule: "\"rule\":5000043"},
		{name: "GraphQL method override URL metadata", mode: "block", target: "/graphql?%5Fmethod=HEAD", ct: "application/json", body: "{\"query\":\"mutation{deleteUser}\"}", status: 400, logRule: "\"rule\":5002317"},
		{name: "GraphQL method override form metadata", mode: "block", target: "/api/gql", ct: "application/x-www-form-urlencoded", body: "_method=GET&query=mutation%7BdeleteUser%7D", status: 400, logRule: "\"rule\":5002317"},
		{name: "GraphQL method override JSON metadata", mode: "block", target: "/graphql", ct: "application/json", body: "{\"_method\":\"HEAD\",\"query\":\"mutation{deleteUser}\"}", status: 400, logRule: "\"rule\":5002317"},
		{name: "GraphQL variables method field remains valid", mode: "block", target: "/graphql", ct: "application/json", body: "{\"query\":\"mutation($x:Input){update(x:$x)}\",\"variables\":{\"x\":{\"_method\":\"GET\"}}}", status: 200},
		{name: "method override metadata monitoring totals", mode: "monitor", target: "/graphql?%5Fmethod=GET", ct: "application/json", body: "{\"query\":\"mutation{deleteUser}\"}", status: 200, logRule: "\"rule\":5002317", repeat: 2,
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002317, statsMonitored: 2},
		{name: "method override header hard refusal", mode: "off", method: "POST", ct: "application/json", body: good, headers: map[string]string{"X-HTTP-Method-Override": "GET"}, status: 400, logRule: "\"rule\":5000044"},
		{name: "underscore method override hard refusal", mode: "off", headers: map[string]string{"X_HTTP_METHOD_OVERRIDE": "GET"}, status: 400, logRule: "\"rule\":5000044"},
		{name: "method override connection token hard refusal", mode: "off", headers: map[string]string{"X-Method-Override": "GET", "Connection": "close, X-Method-Override"}, status: 400, logRule: "\"rule\":5000044"},
		{name: "mixed variables and form transport", mode: "block", target: "/graphql?variables=%7B%7D", ct: "application/x-www-form-urlencoded", body: "%71uery=mutation%7BdeleteUser%7D", status: 400, logRule: "\"rule\":5002316"},
		{name: "mixed raw GraphQL and URL transport", mode: "block", target: "/api/gql?%65xtensions=%7B%7D", ct: "application/graphql", body: "mutation{deleteUser}", status: 400, logRule: "\"rule\":5002316"},
		{name: "mixed transport monitor logs both layers", mode: "monitor", method: "HEAD", target: "/graphql?operationName=Write", ct: "application/json", body: "{\"query\":\"mutation Write{deleteUser}\"}", status: 200,
			logRule: "\"rule\":5002316", alsoRules: []int{5002009, 5002314, 5002315},
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002316, statsMonitored: 1},
		{name: "ordinary metadata with POST mutation", mode: "block", target: "/graphql?locale=en", ct: "application/json", body: "{\"query\":\"mutation{deleteUser}\"}", status: 200},
		{name: "HEAD extension-only request transport refused", mode: "block", method: "HEAD", target: "/graphql?extensions=%7B%22persistedQuery%22%3A%7B%22sha256Hash%22%3A%22abc%22%7D%7D", status: 403, logRule: "\"rule\":5002315"},
		{name: "blocked bypass totals", mode: "block", method: "HEAD", target: "/api/gql?%71uery=%6d%75%74%61%74%69%6f%6e%7BSECRET_TOKEN_CLI_TEST%7D", repeat: 3, status: 403, logRule: "\"rule\":5002314",
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002314, statsBlocked: 3},
		{name: "multiple independent bypass detections", mode: "monitor", method: "HEAD", target: "/graphql", ct: "application/json",
			body: "{\"query\":\"{a}\",\"query\":\"mutation{SECRET_TOKEN_CLI_TEST}\"}", status: 200, logRule: "\"rule\":5002314", alsoRules: []int{5002009, 5002103, 5002315},
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002314, statsMonitored: 1},
		{name: "monitored related bypass totals", mode: "monitor", method: "OPTIONS", target: "/graphql", ct: "application/x-www-form-urlencoded", body: "%71uery=mutation%7BSECRET_TOKEN_CLI_TEST%7D", repeat: 2, status: 200, logRule: "\"rule\":5002314",
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002314, statsMonitored: 2},
		{name: "invalid negative stats interval", extraArgs: []string{"-formats-stats-interval", "-1s"}, fails: true},
		{name: "invalid excessive stats frequency", extraArgs: []string{"-formats-stats-interval", "50ms"}, fails: true},
		{name: "invalid long stats interval", extraArgs: []string{"-formats-stats-interval", "25h"}, fails: true},
		{name: "block discovered HEAD mutation", mode: "block", method: "HEAD", target: "/api/gql?query=mutation%7BdeleteUser%7D", status: 403},
		{name: "block OPTIONS mutation with CRS off", mode: "block", method: "OPTIONS", target: "/api/gql?query=mutation%7BdeleteUser%7D", status: 403},
		{name: "block TRACE mutation with CRS off", mode: "block", method: "TRACE", target: "/api/gql?query=mutation%7BdeleteUser%7D", status: 403},
		{name: "monitor HEAD mutation", mode: "monitor", method: "HEAD", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 200, logRule: "\"rule\":5002314"},
		{name: "ordinary OPTIONS preflight", mode: "block", method: "OPTIONS", target: "/graphql?version=1", status: 200},
		{name: "selected HEAD query transport refused", mode: "block", method: "HEAD", target: "/graphql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read", status: 403, logRule: "\"rule\":5002315"},
		{name: "HEAD escaped protocol name and operation", mode: "block", method: "HEAD", target: "/api/gql?%71uery=%6d%75%74%61%74%69%6f%6e%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002314"},
		{name: "HEAD selected mutation via fragment", mode: "block", method: "HEAD", target: "/api/gql?query=fragment+F+on+User%7Bid%7D+mutation+Write%7BdeleteUser%7B...F%7D%7D&operationName=Write", status: 403, logRule: "\"rule\":5002314"},
		{name: "HEAD batch mutation in permitted body", mode: "block", policy: "{\"rules\":{\"body-on-get\":\"off\",\"graphql-http-method\":\"off\"}}", method: "HEAD", target: "/graphql", ct: "application/json", body: "[{\"query\":\"{a}\"},{\"query\":\"mutation{deleteUser}\"}]", status: 403, logRule: "\"rule\":5002314"},
		{name: "monitor related OPTIONS form mutation", mode: "monitor", method: "OPTIONS", target: "/graphql", ct: "application/x-www-form-urlencoded", body: "%71uery=mutation%7BdeleteUser%7D", status: 200, logRule: "\"rule\":5002314"},
		{name: "HEAD duplicate operationName", mode: "block", method: "HEAD", target: "/api/gql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read&%6fperationName=Write", status: 400, logRule: "\"rule\":5002308"},
		{name: "selected GET query beside mutation", mode: "block", method: "GET", target: "/graphql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read", status: 200},
		{name: "valid JSON", mode: "block", ct: "application/json", body: good, status: 200},
		{name: "query malformed escape", mode: "block", method: "GET", target: "/api?x=%zz", status: 400},
		{name: "query raw semicolon", mode: "block", method: "GET", target: "/api?x=1;y=2", status: 400},
		{name: "query escaped NUL", mode: "block", ct: "application/json", body: good, target: "/api?x=%00", status: 400},
		{name: "query invalid UTF-8", mode: "block", method: "GET", target: "/api?x=%ff", status: 400},
		{name: "query prototype key", mode: "block", method: "GET", target: "/api?user%5B__proto__%5D%5Badmin%5D=1", status: 400},
		{name: "valid query preserves target", mode: "block", method: "GET", target: "/api?q=a%3Bb%26c&tag%5B%5D=red&tag%5B%5D=blue", status: 200},
		{name: "query duplicate monitor", mode: "block", method: "GET", target: "/api?id=1&%69D=2", status: 200, logRule: `"rule":5002802`},
		{name: "query duplicate opt-in block", mode: "block", policy: `{"rules":{"query-duplicate-param":"block"}}`, method: "GET", target: "/api?id=1&id=2", status: 400},
		{name: "query semicolon monitor forwards unchanged", mode: "monitor", method: "GET", target: "/api?x=1;y=2", status: 200, logRule: `"rule":5002805`},
		{name: "query byte cap", mode: "block", policy: `{"max_query_bytes":4}`, method: "GET", target: "/api?a=123", status: 414},
		{name: "query count policy", mode: "block", policy: `{"query":{"max_params":1}}`, method: "GET", target: "/api?a=1&b=2", status: 400},
		{name: "query monitor cap still checks body", mode: "block", policy: `{"max_query_bytes":4,"rules":{"query-too-large":"monitor"}}`, target: "/api?a=123", ct: "application/json", body: `{"a":1,"a":2}`, status: 400, logRule: `"rule":5002103`},
		{name: "duplicate JSON key", mode: "block", ct: "application/json", body: `{"a":1,"a":2}`, status: 400, logRule: `"rule":5002103`},
		{name: "XML external entity", mode: "block", ct: "text/xml", body: `<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>`, status: 400},
		{name: "custom GraphQL depth", mode: "block", policy: `{"graphql":{"max_depth":2}}`, target: "/graphql", ct: "application/json", body: `{"query":"{a{b{c}}}"}`, status: 400},
		{name: "aggregate GraphQL budget blocks a batch", mode: "block", policy: `{"graphql":{"max_request_fields":3}}`, target: "/graphql", ct: "application/json", body: `[{"query":"{a b}"},{"query":"{c d}"}]`, status: 400, logRule: `"rule":5002311`},
		{name: "aggregate budget is local to each request", mode: "block", policy: `{"graphql":{"max_request_fields":4}}`, target: "/graphql", ct: "application/json", body: `[{"query":"{a b}"},{"query":"{c d}"}]`, status: 200, repeat: 3},
		{name: "aggregate budget monitoring", mode: "monitor", policy: `{"graphql":{"max_request_fields":3}}`, target: "/graphql", ct: "application/json", body: `[{"query":"{a b}"},{"query":"{c d}"}]`, status: 200, logRule: `"rule":5002311`},
		{name: "explicit monitor overrides policy", mode: "monitor", policy: `{"monitor":false}`, ct: "application/json", body: `{"a":1,"a":2}`, status: 200, logRule: `"rule":5002103`},
		{name: "explicit block overrides policy monitor", mode: "block", policy: `{"monitor":true}`, ct: "application/json", body: `{"a":1,"a":2}`, status: 400},
		{name: "off forwards uninspected JSON", mode: "off", ct: "application/json", body: `{"a":1,"a":2}`, status: 200},
		{name: "bounded gzip decompressed", mode: "block", ct: "application/json", body: packed.String(), originBody: good, encoding: "gzip", allowEncoding: true, status: 200},
		{name: "decompressed body respects proxy limit", mode: "block", ct: "application/json", body: compress(largeJSON), encoding: "gzip", allowEncoding: true, status: 413},
		{name: "decompressed body limit survives monitor mode", mode: "monitor", ct: "application/json", body: compress(largeJSON), encoding: "gzip", allowEncoding: true, status: 413},
		{name: "compressed executable upload refused", mode: "block", ct: "multipart/form-data; boundary=B", body: compress(upload("shell.php", "ordinary text")), encoding: "gzip", allowEncoding: true, status: 403},
		{name: "compressed script content refused", mode: "block", ct: "multipart/form-data; boundary=B", body: compress(upload("photo.txt", "<?php echo 1; ?>")), encoding: "gzip", allowEncoding: true, status: 403},
		{name: "compressed ordinary upload", mode: "block", ct: "multipart/form-data; boundary=B", body: compress(upload("photo.txt", "ordinary text")), originBody: upload("photo.txt", "ordinary text"), encoding: "gzip", allowEncoding: true, status: 200},
		{name: "gzip opt-in required", mode: "block", ct: "application/json", body: packed.String(), encoding: "gzip", status: 415},
		{name: "corrupt gzip refused", mode: "block", ct: "application/json", body: "bad-gzip", encoding: "gzip", allowEncoding: true, status: 400},
		{name: "API quota holds with CRS and formats off", mode: "off", apiRate: 2, target: "/api/orders", statuses: []int{200, 200, 429}, logRule: `"rule":5000042`},
		{name: "API prefixes share a budget", mode: "off", apiRate: 2, targets: []string{"/api/orders", "/graphql", "/api/users"}, statuses: []int{200, 200, 429}},
		{name: "API forwarding spoof cannot rotate identity", mode: "off", apiRate: 1, target: "/api", forwarding: []string{"198.51.100.1", "198.51.100.2"}, statuses: []int{200, 429}},
		{name: "trusted clients have separate quotas", mode: "off", apiRate: 1, target: "/api", extraArgs: []string{"-trusted-proxies", "127.0.0.0/8"}, forwarding: []string{"198.51.100.1", "198.51.100.1", "198.51.100.2"}, statuses: []int{200, 429, 200}},
		{name: "custom API prefix", mode: "off", apiRate: 1, apiPaths: "/internal", target: "/internal/orders", statuses: []int{200, 429}},
		{name: "API prefix requires a segment boundary", mode: "off", apiRate: 1, target: "/apiary", statuses: []int{200, 200}},
		{name: "API and login budgets are separate", mode: "off", apiRate: 1, extraArgs: []string{"-wordpress", "-login-per-minute", "1"}, targets: []string{"/wp-login.php", "/api", "/wp-login.php", "/api"}, statuses: []int{200, 200, 429, 429}},
		{name: "negative API limit refuses startup", mode: "off", apiRate: -1, fails: true},
		{name: "excess API limit refuses startup", mode: "off", apiRate: 100001, fails: true},
		{name: "invalid API prefix refuses startup", mode: "off", apiRate: 1, apiPaths: "/api?x=1", fails: true},
		{name: "unknown mode refuses startup", mode: "enforce", fails: true},
		{name: "off with encoding refuses startup", mode: "off", allowEncoding: true, fails: true},
		{name: "off with policy refuses startup", mode: "off", policy: `{}`, fails: true},
		{name: "malformed policy refuses startup", mode: "block", policy: `{`, fails: true},
		{name: "unknown policy field refuses startup", mode: "block", policy: `{"graphql":{"max_dept":2}}`, fails: true},
		{name: "invalid policy limit refuses startup", mode: "block", policy: `{"graphql":{"max_depth":-1}}`, fails: true},
		{name: "null policy refuses startup", mode: "block", policy: `null`, fails: true},
		{name: "null limit refuses startup", mode: "block", policy: `{"graphql":{"max_depth":null}}`, fails: true},
		{name: "duplicate limit refuses startup", mode: "block", policy: `{"graphql":{"max_depth":2,"max_depth":12}}`, fails: true},
		{name: "duplicate rule refuses startup", mode: "block", policy: `{"rules":{"json-duplicate-key":"block","json-duplicate-key":"off"}}`, fails: true},
		{name: "case alias refuses startup", mode: "block", policy: `{"graphql":{"MAX_DEPTH":2}}`, fails: true},
		{name: "policy directory refuses startup", mode: "block", policyDir: true, fails: true},
		{name: "policy over file cap refuses startup", mode: "block", policy: `{}` + strings.Repeat(" ", maxFormatsPolicyBytes), fails: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.trustOrigin && runtime.GOOS != "linux" {
				t.Skip("Linux SSL_CERT_FILE tests system-root overrides; Windows uses the native certificate store")
			}
			for len(originCalls) > 0 {
				<-originCalls
			}
			for len(requests) > 0 {
				<-requests // a failing previous subtest must not contaminate this one's origin evidence
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			if err := ln.Close(); err != nil {
				t.Fatal(err)
			}
			args := []string{"-listen", addr, "-upstream", app.URL, "-origin-allow", "127.0.0.0/8", "-mode", "off"}
			if tc.site == "local-example" {
				data, err := os.ReadFile("../../docs/examples/site-local.json")
				if err != nil {
					t.Fatal(err)
				}
				tc.site = strings.ReplaceAll(string(data), "http://127.0.0.1:8081", app.URL)
			}
			if tc.site != "" {
				path := filepath.Join(t.TempDir(), "site.json")
				if err := os.WriteFile(path, []byte(strings.NewReplacer("$ORIGIN", app.URL, "$TLSORIGIN", tlsApp.URL, "$DNSORIGIN", strings.ReplaceAll(app.URL, "127.0.0.1", "localhost")).Replace(tc.site)), 0600); err != nil {
					t.Fatal(err)
				}
				args = []string{"-listen", addr, "-config", path}
			}
			args = append(args, tc.extraArgs...)

			if tc.originAuth != "" {
				dir := t.TempDir()
				caPath := filepath.Join(dir, "origin-ca.pem")
				if err := os.WriteFile(caPath, ca.certPEM, 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-upstream", authOrigin.URL, "-origin-ca-file", caPath)
				if tc.originAuth != "none" {
					name := tc.originAuth
					if name == "mismatch" {
						name = "good"
					}
					identity := identities[name]
					certPath, keyPath := filepath.Join(dir, "edge.pem"), filepath.Join(dir, "edge.key")
					key := identity.keyPEM
					if tc.originAuth == "mismatch" {
						key = identities["wrong-site"].keyPEM
					}
					if err := os.WriteFile(certPath, identity.certPEM, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(keyPath, key, 0600); err != nil {
						t.Fatal(err)
					}
					args = append(args, "-origin-client-cert", certPath, "-origin-client-key", keyPath)
				}
			}

			if tc.apiSpec != "" {
				data := []byte(tc.apiSpec)
				if tc.apiSpec == "example" {
					data, err = os.ReadFile("../../docs/examples/api-contract.json")
					if err != nil {
						t.Fatal(err)
					}
				}
				path := filepath.Join(t.TempDir(), "api.json")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-api-spec", path)
			}
			if tc.apiRate != 0 {
				args = append(args, "-api-per-minute", fmt.Sprint(tc.apiRate))
			}
			if tc.apiPaths != "" {
				args = append(args, "-api-rate-paths", tc.apiPaths)
			}
			if tc.mode != "" {
				args = append(args, "-formats-mode", tc.mode)
			}
			if tc.allowEncoding {
				args = append(args, "-allow-request-encoding")
			}
			if tc.policy != "" || tc.policyDir {
				path := t.TempDir()
				if !tc.policyDir {
					path = filepath.Join(path, "formats.json")
					if err := os.WriteFile(path, []byte(tc.policy), 0600); err != nil {
						t.Fatal(err)
					}
				}
				args = append(args, "-formats-policy", path)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, args...)
			if tc.trustOrigin {
				path := filepath.Join(t.TempDir(), "ca.pem")
				data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsApp.Certificate().Raw})
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+path)
			}
			logPath := filepath.Join(t.TempDir(), "proxy.log")
			logs, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			defer logs.Close()
			cmd.Stdout, cmd.Stderr = logs, logs
			if tc.preflight {
				if err := cmd.Run(); err != nil {
					data, _ := os.ReadFile(logPath)
					t.Fatalf("preflight failed: %v\n%s", err, data)
				}
				data, _ := os.ReadFile(logPath)
				if !bytes.Contains(data, []byte(`"msg":"configuration checked"`)) {
					t.Fatal("missing preflight result")
				}
				if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
					conn.Close()
					t.Fatal("preflight opened a listener")
				}
				if tc.probeHTTP {
					select {
					case got := <-originCalls:
						if got.target != "/" || got.body != "" {
							t.Fatal("HTTP probe changed target or sent a body")
						}
					default:
						t.Fatal("HTTP probe did not reach authenticated origin")
					}
				} else if len(originCalls) != 0 {
					t.Fatal("local preflight sent HTTP")
				}
				if len(requests) != 0 {
					t.Fatal("preflight sent an HTTP request")
				}
				return
			}
			if tc.fails {
				if err := cmd.Run(); err == nil || ctx.Err() != nil {
					t.Fatalf("invalid configuration did not fail promptly: %v", err)
				}
				if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
					conn.Close()
					t.Fatal("invalid configuration opened a listener")
				}
				if len(originCalls) != 0 {
					t.Fatal("refused origin identity reached the application")
				}
				return
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				cancel()
				if !waited {
					_ = cmd.Wait()
				}
			}()
			url := "http://" + addr
			for {
				resp, err := client.Get(url + "/__cli_test_ready")
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						break
					}
				}
				if ctx.Err() != nil {
					t.Fatal("firewall did not become ready")
				}
				time.Sleep(25 * time.Millisecond)
			}
			method, target := tc.method, tc.target
			if method == "" {
				method = "POST"
			}
			if target == "" {
				target = "/api/save"
			}
			for i := range max(tc.repeat, len(tc.statuses), 1) {
				want, requestTarget := tc.status, target
				if len(tc.statuses) > 0 {
					want = tc.statuses[i]
				}
				if len(tc.targets) > 0 {
					requestTarget = tc.targets[i]
				}
				req, err := http.NewRequest(method, url+requestTarget, strings.NewReader(tc.body))
				if err != nil {
					t.Fatal(err)
				}
				if tc.ct != "" {
					req.Header.Set("Content-Type", tc.ct)
				}
				for name, value := range tc.headers {
					req.Header.Set(name, value)
				}
				if len(tc.forwarding) > 0 {
					req.Header.Set("X-Forwarded-For", tc.forwarding[i])
				}
				if tc.encoding != "" {
					req.Header.Set("Content-Encoding", tc.encoding)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != want {
					data, _ := os.ReadFile(logPath)
					t.Fatalf("status %d, want %d\n%s", resp.StatusCode, want, data)
				}
				if want == 429 && (resp.Header.Get("Retry-After") != "60" || resp.Header.Get("Cache-Control") != "no-store") {
					t.Fatal("rate refusal lacks retry or cache policy")
				}
				originRequests := requests
				if tc.originAuth != "" {
					originRequests = originCalls
				}
				select {
				case got := <-originRequests:
					if want != 200 {
						t.Fatal("refused request reached the origin")
					}
					want := tc.body
					if tc.originBody != "" {
						want = tc.originBody
					}
					if got.body != want || got.encoding != "" || got.length != int64(len(want)) {
						t.Fatalf("origin received %d body bytes, encoding %q, length %d", len(got.body), got.encoding, got.length)
					}
					if got.target != requestTarget {
						t.Fatal("origin request target changed")
					}
				default:
					if want == 200 {
						t.Fatal("accepted request did not reach the origin")
					}
				}
			}
			if tc.statsRule != 0 {
				deadline := time.Now().Add(2 * time.Second)
				for {
					data, err := os.ReadFile(logPath)
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, line := range bytes.Split(data, []byte("\n")) {
						var event struct {
							Msg   string
							Rules []struct {
								Rule               int
								Blocked, Monitored uint64
							}
						}
						if json.Unmarshal(line, &event) != nil || event.Msg != "format protection totals" {
							continue
						}
						for _, r := range event.Rules {
							found = found || r.Rule == tc.statsRule && r.Blocked == tc.statsBlocked && r.Monitored == tc.statsMonitored
						}
					}
					if found {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("compiled firewall did not report expected bypass totals")
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			cancel()
			_ = cmd.Wait()
			waited = true
			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if tc.logRule != "" && !bytes.Contains(data, []byte(tc.logRule)) {
				t.Fatalf("expected finding %s absent from logs", tc.logRule)
			}
			if tc.logRule != "" {
				var wanted struct{ Rule int }
				if err := json.Unmarshal([]byte("{"+tc.logRule+"}"), &wanted); err != nil {
					t.Fatal(err)
				}
				blocked := tc.status >= 400
				if len(tc.statuses) > 0 {
					blocked = tc.statuses[len(tc.statuses)-1] >= 400
				}
				for _, id := range append([]int{wanted.Rule}, tc.alsoRules...) {
					matches := 0
					for _, line := range bytes.Split(data, []byte("\n")) {
						var event struct {
							Msg        string
							Rule       int
							Disruptive bool
						}
						if json.Unmarshal(line, &event) == nil && event.Msg == "rule matched" && event.Rule == id {
							matches++
							if event.Disruptive != blocked {
								t.Fatal("finding logged with incorrect enforcement outcome")
							}
						}
					}
					if matches < max(tc.repeat, 1) {
						t.Fatalf("not every attempt produced detection %d", id)
					}
				}
			}
			if bytes.Contains(data, []byte("SECRET_TOKEN_CLI_TEST")) {
				t.Fatal("default log disclosed request content")
			}
		})
	}
}

type statsWriter struct {
	bytes.Buffer
	emitted chan struct{}
}

func (w *statsWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	select {
	case w.emitted <- struct{}{}:
	default:
	}
	return n, err
}

func TestFormatStatsLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval time.Duration
		periodic bool
		off      bool
		want     int
	}{
		{"graceful final snapshot", time.Hour, false, false, 1},
		{"unchanged final snapshot suppressed", 100 * time.Millisecond, true, false, 1},
		{"statistics disabled", 0, false, false, 0},
		{"formats disabled", 100 * time.Millisecond, false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := formats.New(formats.Policy{Monitor: true})
			in.Inspect(&inspect.Request{Method: "HEAD", Path: "/graphql", RawQuery: "query=mutation%7BSECRET_TOKEN_CLI_TEST%7D"})
			if tc.off {
				in = nil
			}
			out := &statsWriter{emitted: make(chan struct{}, 1)}
			stop := startFormatStats(slog.New(slog.NewJSONHandler(out, nil)), in, tc.interval)
			defer stop()
			if tc.periodic {
				select {
				case <-out.emitted:
				case <-time.After(2 * time.Second):
					t.Fatal("periodic statistics were not emitted")
				}
			}
			stop() // joins the writer before reading the buffer
			if got := bytes.Count(out.Bytes(), []byte("format protection totals")); got != tc.want {
				t.Fatalf("%d snapshots, want %d", got, tc.want)
			}
			if bytes.Contains(out.Bytes(), []byte("SECRET_TOKEN_CLI_TEST")) {
				t.Fatal("statistics expose request content")
			}
			if tc.want != 0 && !bytes.Contains(out.Bytes(), []byte("\"monitored\":1")) {
				t.Fatal("final snapshot lost the finding")
			}
		})
	}
}
