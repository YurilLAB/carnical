// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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

	"github.com/YurilLAB/coraza/carnical/formats"
	"github.com/YurilLAB/coraza/carnical/inspect"
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
		{name: "default monitor logs a GET mutation", method: "GET", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 200, logRule: `"rule":5002310`},
		{name: "block GET mutation with CRS off", mode: "block", method: "GET", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 403, logRule: `"rule":5002310`},
		{name: "block HEAD mutation with CRS off", mode: "block", method: "HEAD", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002314"},
		{name: "blocked bypass totals", mode: "block", method: "HEAD", target: "/api/gql?%71uery=%6d%75%74%61%74%69%6f%6e%7BSECRET_TOKEN_CLI_TEST%7D", repeat: 3, status: 403, logRule: "\"rule\":5002314",
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002314, statsBlocked: 3},
		{name: "multiple independent bypass detections", mode: "monitor", method: "HEAD", target: "/graphql", ct: "application/json",
			body: "{\"query\":\"{a}\",\"query\":\"mutation{SECRET_TOKEN_CLI_TEST}\"}", status: 200, logRule: "\"rule\":5002314", alsoRules: []int{5002009, 5002103},
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
		{name: "selected HEAD query beside mutation", mode: "block", method: "HEAD", target: "/graphql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read", status: 200},
		{name: "HEAD escaped protocol name and operation", mode: "block", method: "HEAD", target: "/api/gql?%71uery=%6d%75%74%61%74%69%6f%6e%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002314"},
		{name: "HEAD selected mutation via fragment", mode: "block", method: "HEAD", target: "/api/gql?query=fragment+F+on+User%7Bid%7D+mutation+Write%7BdeleteUser%7B...F%7D%7D&operationName=Write", status: 403, logRule: "\"rule\":5002314"},
		{name: "HEAD batch mutation in permitted body", mode: "block", policy: "{\"rules\":{\"body-on-get\":\"off\"}}", method: "HEAD", target: "/graphql", ct: "application/json", body: "[{\"query\":\"{a}\"},{\"query\":\"mutation{deleteUser}\"}]", status: 403, logRule: "\"rule\":5002314"},
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
			args = append(args, tc.extraArgs...)
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
				req.Header.Set("Content-Type", tc.ct)
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
					t.Fatalf("status %d, want %d", resp.StatusCode, want)
				}
				if want == 429 && (resp.Header.Get("Retry-After") != "60" || resp.Header.Get("Cache-Control") != "no-store") {
					t.Fatal("rate refusal lacks retry or cache policy")
				}
				select {
				case got := <-requests:
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
