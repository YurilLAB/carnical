// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
	type received struct {
		body, encoding string
		length         int64
	}
	requests := make(chan received, 64)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__cli_test_ready" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad body", 400)
				return
			}
			requests <- received{string(body), r.Header.Get("Content-Encoding"), r.ContentLength}
		}
		w.WriteHeader(200)
	}))
	defer app.Close()
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
		repeat                                                                      int
		name, mode, policy, method, target, ct, body, encoding, logRule, originBody string
		allowEncoding, fails, policyDir                                             bool
		status                                                                      int
	}{
		{name: "default monitor logs a GET mutation", method: "GET", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 200, logRule: `"rule":5002310`},
		{name: "block GET mutation with CRS off", mode: "block", method: "GET", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 403, logRule: `"rule":5002310`},
		{name: "selected GET query beside mutation", mode: "block", method: "GET", target: "/graphql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read", status: 200},
		{name: "valid JSON", mode: "block", ct: "application/json", body: good, status: 200},
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
		{name: "unknown mode refuses startup", mode: "enforce", fails: true},
		{name: "off with encoding refuses startup", mode: "off", allowEncoding: true, fails: true},
		{name: "off with policy refuses startup", mode: "off", policy: `{}`, fails: true},
		{name: "malformed policy refuses startup", mode: "block", policy: `{`, fails: true},
		{name: "unknown policy field refuses startup", mode: "block", policy: `{"graphql":{"max_dept":2}}`, fails: true},
		{name: "invalid policy limit refuses startup", mode: "block", policy: `{"graphql":{"max_depth":-1}}`, fails: true},
		{name: "policy directory refuses startup", mode: "block", policyDir: true, fails: true},
		{name: "policy over file cap refuses startup", mode: "block", policy: `{}` + strings.Repeat(" ", maxFormatsPolicyBytes), fails: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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
			logPath := filepath.Join(t.TempDir(), "proxy.log")
			logs, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			defer logs.Close()
			cmd.Stdout, cmd.Stderr = logs, logs
			if tc.fails {
				if err := cmd.Run(); err == nil || ctx.Err() != nil {
					t.Fatalf("invalid configuration did not fail promptly: %v", err)
				}
				if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
					conn.Close()
					t.Fatal("invalid configuration opened a listener")
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
			for range max(tc.repeat, 1) {
				req, err := http.NewRequest(method, url+target, strings.NewReader(tc.body))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", tc.ct)
				if tc.encoding != "" {
					req.Header.Set("Content-Encoding", tc.encoding)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != tc.status {
					t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
				}
				select {
				case got := <-requests:
					if tc.status != 200 {
						t.Fatal("refused request reached the origin")
					}
					want := tc.body
					if tc.originBody != "" {
						want = tc.originBody
					}
					if got.body != want || got.encoding != "" || got.length != int64(len(want)) {
						t.Fatalf("origin received %d body bytes, encoding %q, length %d", len(got.body), got.encoding, got.length)
					}
				default:
					if tc.status == 200 {
						t.Fatal("accepted request did not reach the origin")
					}
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
			if bytes.Contains(data, []byte("SECRET_TOKEN_CLI_TEST")) {
				t.Fatal("default log disclosed request content")
			}
		})
	}
}
