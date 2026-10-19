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
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/YurilLAB/coraza/carnical/alert"
	"github.com/YurilLAB/coraza/carnical/apiguard"
	"github.com/YurilLAB/coraza/carnical/bots"
	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/formats"
	"github.com/YurilLAB/coraza/carnical/inspect"
	"github.com/YurilLAB/coraza/carnical/netwatch"
	"github.com/YurilLAB/coraza/carnical/notify"
	"github.com/YurilLAB/coraza/carnical/policy"
	"github.com/YurilLAB/coraza/carnical/proxy"
	"github.com/YurilLAB/coraza/carnical/shield"
	"github.com/YurilLAB/coraza/carnical/vpatch"
)

type setupOutputFault struct{ io.Writer }

func (w setupOutputFault) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("No account configuration directory is available.")) {
		return 0, io.ErrClosedPipe
	}
	return w.Writer.Write(p)
}

// refusingFlag is a string flag that refuses every value, quoting it, as a flag that checks its value may.
type refusingFlag struct{}

func (refusingFlag) Set(s string) error { return fmt.Errorf("refused %q", s) }
func (refusingFlag) String() string     { return "" }
func (refusingFlag) Get() any           { return "" }

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

	t.Run("local policy and virtual patch", func(t *testing.T) { testSiteProtectionCLI(t, bin) })
	t.Run("site configuration parser", func(t *testing.T) {
		tests := []struct {
			name, data string
			bad        bool
			says       string // what the error must say
			hides      string // what it must not
		}{
			{name: "empty settings", data: "{\"version\":1,\"flags\":{}}", bad: false},
			{name: "a refused value with the reason", data: `{"version":1,"flags":{"limit":"9/x"}}`, bad: true, says: `invalid site configuration flag "limit": refused "9/x"`},
			{name: "a refused private value without it", data: `{"version":1,"flags":{"trusted-proxies":"10.9.8.7/33"}}`, bad: true,
				says: `invalid site configuration flag "trusted-proxies"`, hides: "10.9.8.7"},
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
			{name: "file probe action", data: `{"version":1,"flags":{"probe":"ready"}}`, bad: true},
			{name: "file version action", data: "{\"version\":1,\"flags\":{\"version\":true}}", bad: true},
			{name: "key bootstrap in site file", data: `{"version":1,"flags":{"config-key-file":"other.key"}}`, bad: true},
			{name: "null private section", data: `{"version":1,"flags":{},"private":null}`, bad: true},
			{name: "duplicate encrypted field", data: `{"version":1,"flags":{},"private":{"key-id":"abc","key-id":"abc","sealed":"abc"}}`, bad: true},
			{name: "unknown encrypted field", data: `{"version":1,"flags":{},"private":{"key-id":"abc","sealed":"abc","extra":1}}`, bad: true},
			{name: "missing encrypted payload", data: `{"version":1,"flags":{},"private":{"key-id":"abc"}}`, bad: true},
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
				flags.String("probe", "", "")
				flags.Var(refusingFlag{}, "limit", "")
				flags.Var(refusingFlag{}, "trusted-proxies", "")
				if err := flags.Parse([]string{"-upstream", "http://override.test", "-local-rules=false"}); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "site.json")
				if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
					t.Fatal(err)
				}
				_, _, err := loadSiteConfig(path, flags)
				if (err != nil) != tc.bad {
					t.Fatalf("error %v, want invalid=%v", err, tc.bad)
				}
				if err != nil && (!strings.Contains(err.Error(), tc.says) || tc.hides != "" && strings.Contains(err.Error(), tc.hides)) {
					t.Fatalf("error %q, want it to say %q and not %q", err, tc.says, tc.hides)
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
			if _, _, err := loadSiteConfig(link, flag.NewFlagSet("site", flag.ContinueOnError)); err == nil {
				t.Fatal("symlink accepted as configuration")
			}
		})
		t.Run("nonregular file", func(t *testing.T) {
			if _, _, err := loadSiteConfig(t.TempDir(), flag.NewFlagSet("site", flag.ContinueOnError)); err == nil {
				t.Fatal("directory accepted as config")
			}
		})
	})

	t.Run("setup wizard and encrypted runtime", func(t *testing.T) {
		var reached atomic.Int64
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached.Add(1)
			if r.Host != "example.test" {
				t.Errorf("unexpected origin Host %q", r.Host)
			}
			w.WriteHeader(200)
		}))
		defer origin.Close()
		listen := "127.0.0.1:" + quietPort(t, "tcp", "127.0.0.1")
		for _, tc := range []struct {
			name, prefix                                                                            string
			save, bad, exists, defaultKey, defaultSite, sameKey, noProfile, missingKey, outputError bool
			endpoint                                                                                []string // answers to the alert endpoint's questions; none is no endpoint
			secretAnswer                                                                            string   // the answer to where a new signing secret goes
			newSecret                                                                               bool     // a new secret file is expected next to the key
		}{
			{name: "declined save"},
			{name: "encrypted saved site", save: true},
			{name: "default account key store", save: true, defaultKey: true},
			{name: "saved where check and start find it", save: true, defaultKey: true, defaultSite: true},
			{name: "explicit key without account directory", save: true, noProfile: true},
			{name: "missing account directory needs a key path", save: true, bad: true, noProfile: true, missingKey: true},
			{name: "key fallback output failure saves nothing", save: true, bad: true, noProfile: true, outputError: true},
			{name: "EOF before consent", prefix: "example.test\n", bad: true},
			{name: "control character", prefix: "example.test\x1b\n", bad: true},
			{name: "oversized input", prefix: strings.Repeat("x", 4097) + "\n", bad: true},
			{name: "credentials refused", prefix: "example.test\nhttp://admin:password@127.0.0.1\n", bad: true},
			{name: "public plaintext listener refused", prefix: "example.test\n" + origin.URL + "\ny\n\nlocal\n0.0.0.0:8080\n", bad: true},
			{name: "existing config preserved", save: true, exists: true, bad: true},
			{name: "key and config need separate files", save: true, sameKey: true, bad: true},
			// A public http URL is refused and asked again; a private address must be allowed; blank makes a new secret.
			{name: "alert endpoint with a new signing secret", save: true, newSecret: true,
				endpoint: []string{"http://alerts.example.com/hook", "https://127.0.0.1:9443/hook", "y", ""}},
			{name: "alert endpoint refused without an allowance", save: true, bad: true,
				endpoint: []string{"https://127.0.0.1:9443/hook", "n"}},
			{name: "alert signing secret needs a file of its own", save: true, bad: true,
				endpoint: []string{"https://127.0.0.1:9443/hook", "y", ""}, secretAnswer: "SAMEKEY"},
			{name: "an existing file is never replaced by a new signing secret", save: true, bad: true,
				endpoint: []string{"https://127.0.0.1:9443/hook", "y", ""}, secretAnswer: "EXISTING"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				configPath, keyPath := filepath.Join(dir, "site.json"), filepath.Join(dir, "key.bin")
				keyAnswer := keyPath
				if tc.sameKey {
					keyAnswer = configPath
				}
				switch tc.secretAnswer {
				case "SAMEKEY":
					tc.secretAnswer = keyPath
				case "EXISTING":
					tc.secretAnswer = filepath.Join(dir, "taken.secret")
					if err := os.WriteFile(tc.secretAnswer, []byte("not to be replaced"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if tc.defaultKey {
					t.Setenv("APPDATA", filepath.Join(dir, "appdata"))
					t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))
					keyAnswer = ""
				}
				configAnswer, siteType := configPath, ""
				if tc.defaultSite {
					saved, err := defaultSitePath()
					if err != nil {
						t.Fatal(err)
					}
					configPath, configAnswer, siteType = saved, "", "?\n" // and the help of a question on the way
				}
				if tc.noProfile {
					t.Setenv("APPDATA", "")
					t.Setenv("XDG_CONFIG_HOME", "")
					t.Setenv("HOME", "")
				}
				if tc.missingKey {
					keyAnswer = ""
				}
				if tc.exists {
					if err := os.WriteFile(configPath, []byte("original"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				answer := "n"
				if tc.save {
					answer = "YES"
				}
				input := tc.prefix
				if input == "" {
					endpoint := tc.endpoint
					if len(endpoint) == 0 {
						endpoint = []string{""} // no endpoint
					}
					answers := append([]string{"example.test", origin.URL, "y", "", "local", listen, siteType, "", "block", "", "", "", "", ""}, endpoint...)
					input = strings.Join(append(answers, "n", answer, configAnswer, keyAnswer, tc.secretAnswer, ""), "\n")
				}
				var output bytes.Buffer
				var err error
				if tc.save && !tc.bad {
					setupCmd := exec.Command(bin, "setup")
					setupCmd.Stdin = strings.NewReader(input)
					setupCmd.Stdout, setupCmd.Stderr = &output, &output
					err = setupCmd.Run()
				} else {
					var sink io.Writer = &output
					if tc.outputError {
						sink = setupOutputFault{Writer: &output}
					}
					err = runSetup(strings.NewReader(input), sink, runArgs)
				}
				if tc.outputError && !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("fallback output failure was not returned: %v", err)
				}
				if (err != nil) != tc.bad {
					t.Fatalf("wizard error=%v, want bad=%v; %s", err, tc.bad, &output)
				}
				if !tc.save || tc.bad {
					if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
						t.Fatal("key written without successful save")
					}
					if matches, _ := filepath.Glob(filepath.Join(dir, "alert-*.secret")); len(matches) != 0 {
						t.Fatalf("a secret file was left by a failed setup: %v", matches)
					}
					if tc.secretAnswer != "" && tc.secretAnswer != keyPath {
						if data, err := os.ReadFile(tc.secretAnswer); err != nil || string(data) != "not to be replaced" {
							t.Fatalf("an existing file was changed: %q %v", data, err)
						}
					}
					data, err := os.ReadFile(configPath)
					if tc.exists {
						if err != nil || string(data) != "original" {
							t.Fatal("existing config changed")
						}
					} else if !os.IsNotExist(err) {
						t.Fatal("config written without consent")
					}
					return
				}
				data, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(data, []byte(origin.URL)) || bytes.Contains(data, []byte("127.0.0.1/32")) || bytes.Contains(data, []byte(keyPath)) ||
					bytes.Contains(data, []byte("9443")) || bytes.Contains(data, []byte(".secret")) {
					t.Fatal("private origin or alert endpoint details, or a key path, stored in clear")
				}
				var document siteDocument
				if err := json.Unmarshal(data, &document); err != nil {
					t.Fatal(err)
				}
				if document.Private == nil || document.Flags["mode"] != "block" {
					t.Fatal("missing ciphertext or reviewable policy")
				}
				if tc.newSecret {
					secretPath := filepath.Join(filepath.Dir(keyPath), "alert-"+document.Private.KeyID+".secret")
					secret, err := readCrowdSecFile(secretPath, 4096, true)
					if err != nil {
						t.Fatalf("the new signing secret is not a protected file: %v", err)
					}
					if _, err := notify.ParseSecret(secret); err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(output.String(), "The alert signing secret is in "+secretPath) || strings.Contains(output.String(), strings.TrimSpace(string(secret))) {
						t.Fatalf("setup did not say where the secret is, or showed it:\n%s", &output)
					}
					if !strings.Contains(output.String(), "endpoint   on, port 9443") {
						t.Errorf("the summary does not show the endpoint:\n%s", &output)
					}
				} else if matches, _ := filepath.Glob(filepath.Join(dir, "*.secret")); len(matches) != 0 {
					t.Fatalf("a secret file was made without an endpoint: %v", matches)
				}
				if tc.defaultKey {
					keyPath, err = siteKeyPath(document.Private.KeyID)
					if err != nil {
						t.Fatal(err)
					}
				}
				key, err := readSiteFile(keyPath, 32, true)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(key)
				baseArgs := []string{"-config", configPath}
				if !tc.defaultKey {
					baseArgs = append(baseArgs, "-config-key-file", keyPath)
				}
				if err := runArgs(append(append([]string{}, baseArgs...), "-check")); err != nil {
					t.Fatal(err)
				}
				// The commands setup prints are what check and start need: nothing at all for a site saved in its place.
				next := "carnical check " + setupQuote(configPath)
				if tc.defaultSite {
					next, baseArgs = "carnical check\n", []string{"start"}
					if !strings.Contains(output.String(), "wordpress: no scripts from uploads") {
						t.Error("? did not explain the question")
					}
					if err := runCommand([]string{"check"}, nil, io.Discard); err != nil {
						t.Fatalf("carnical check: %v", err)
					}
				}
				if !strings.Contains(output.String(), next) {
					t.Errorf("setup did not say %q:\n%s", next, &output)
				}
				flags := flag.NewFlagSet("encrypted override", flag.ContinueOnError)
				for _, name := range []string{"hosts", "listen", "mode", "formats-mode", "ddos", "auto-block", "bots", "bots-monitor", "alerts", "upstream", "upstream-host", "origin-allow", "config-key-file",
					"alert-endpoint", "alert-endpoint-allow", "alert-endpoint-secret-file"} {
					flags.String(name, "", "")
				}
				flags.Bool("wordpress", false, "")
				if err := flags.Parse([]string{"-upstream=http://override.test", "-config-key-file=" + keyPath}); err != nil {
					t.Fatal(err)
				}
				if _, _, err := loadSiteConfig(configPath, flags); err != nil {
					t.Fatal(err)
				}
				if flags.Lookup("upstream").Value.String() != "http://override.test" {
					t.Fatal("encrypted file replaced explicit CLI origin")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, bin, baseArgs...)
				var log bytes.Buffer
				cmd.Stderr = &log
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := cmd.Process.Kill(); err != nil && ctx.Err() == nil {
						t.Error(err)
					}
					_ = cmd.Wait() // deliberate test teardown of the live child
					if strings.Contains(log.String(), origin.URL) {
						t.Error("private origin URL disclosed in default startup log")
					}
				}()
				client := &http.Client{Timeout: time.Second}
				send := func(method, path, body string) (int, error) {
					request, err := http.NewRequest(method, "http://"+listen+path, strings.NewReader(body))
					if err != nil {
						return 0, err
					}
					request.Host = "example.test"
					if body != "" {
						request.Header.Set("Content-Type", "application/json")
					}
					response, err := client.Do(request)
					if err != nil {
						return 0, err
					}
					_, readErr := io.Copy(io.Discard, response.Body)
					closeErr := response.Body.Close()
					if readErr != nil {
						return 0, readErr
					}
					return response.StatusCode, closeErr
				}
				ready := false
				for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
					if status, err := send("GET", "/", ""); err == nil && status == 200 {
						ready = true
						break
					}
					time.Sleep(30 * time.Millisecond)
				}
				if !ready {
					t.Fatal("encrypted WAF did not become ready")
				}
				before := reached.Load()
				for _, attack := range []struct {
					method, path, body string
					status             int
				}{
					{"POST", "/api", `{"id":1,"id":2}`, 400},
					{"GET", "/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", "", 403},
				} {
					status, err := send(attack.method, attack.path, attack.body)
					if err != nil || status != attack.status {
						t.Fatalf("live refusal: status=%d err=%v", status, err)
					}
				}
				if reached.Load() != before {
					t.Fatal("refused request reached origin")
				}
				for _, mutation := range []struct {
					name   string
					mutate func(*siteDocument)
				}{
					{"ciphertext tamper", func(d *siteDocument) {
						sealed, _ := base64.StdEncoding.DecodeString(d.Private.Sealed)
						sealed[len(sealed)-1] ^= 1
						d.Private.Sealed = base64.StdEncoding.EncodeToString(sealed)
					}},
					{"key ID binding", func(d *siteDocument) { d.Private.KeyID = strings.Repeat("0", 32) }},
					{"path traversal key ID", func(d *siteDocument) { d.Private.KeyID = "../../key" }},
					{"duplicate across sections", func(d *siteDocument) { d.Flags["upstream"] = origin.URL }},
					{"encrypted action", func(d *siteDocument) {
						d.Private, err = sealSiteSettings(map[string]any{"check": true}, d.Private.KeyID, key)
						if err != nil {
							t.Fatal(err)
						}
					}},
				} {
					t.Run(mutation.name, func(t *testing.T) {
						var changed siteDocument
						if err := json.Unmarshal(data, &changed); err != nil {
							t.Fatal(err)
						}
						mutation.mutate(&changed)
						encoded, err := json.Marshal(changed)
						if err != nil {
							t.Fatal(err)
						}
						badPath := filepath.Join(t.TempDir(), "bad.json")
						if err := os.WriteFile(badPath, encoded, 0600); err != nil {
							t.Fatal(err)
						}
						if err := runArgs([]string{"-config", badPath, "-config-key-file", keyPath, "-check"}); err == nil {
							t.Fatal("invalid encrypted config accepted")
						}
					})
				}
				t.Run("wrong key", func(t *testing.T) {
					wrongPath := filepath.Join(t.TempDir(), "wrong.key")
					wrong := make([]byte, 32)
					if _, err := cryptorand.Read(wrong); err != nil {
						t.Fatal(err)
					}
					if err := writeNewSiteFile(wrongPath, wrong); err != nil {
						t.Fatal(err)
					}
					if err := runArgs([]string{"-config", configPath, "-config-key-file", wrongPath, "-check"}); err == nil {
						t.Fatal("wrong key accepted")
					}
				})
				t.Run("key permissions", func(t *testing.T) {
					if runtime.GOOS == "windows" {
						if out, err := exec.Command("icacls", keyPath, "/grant", "*S-1-1-0:(R)").CombinedOutput(); err != nil {
							t.Fatalf("ACL fixture: %v %s", err, out)
						}
					} else if err := os.Chmod(keyPath, 0644); err != nil {
						t.Fatal(err)
					}
					if err := runArgs(append(append([]string{}, baseArgs...), "-check")); err == nil {
						t.Fatal("shared-readable key accepted")
					}
				})
			})
		}
	})

	t.Run("new site file starts private", func(t *testing.T) {
		fixture := t.TempDir()
		dir := filepath.Join(fixture, "root")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" {
			if out, err := exec.Command("icacls", dir, "/grant", "*S-1-1-0:(OI)(CI)(R)").CombinedOutput(); err != nil {
				t.Fatalf("shared-directory fixture: %v %s", err, out)
			}
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		file, err := createSiteFile(root, "key.bin")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		// Check immediately after creation, before any later ACL change or write.
		if err := checkPrivateSiteFile(file); err != nil {
			t.Fatalf("new file permits inherited access before protection: %v", err)
		}
		if runtime.GOOS == "windows" {
			for _, name := range []string{"../escape.key", "nested/key.bin", "nested\\key.bin", "key.bin:stream", "key\x00.bin", "NUL", "key.bin.", "."} {
				t.Run(name, func(t *testing.T) {
					if f, err := createSiteFile(root, name); err == nil {
						f.Close()
						t.Fatal("unsafe filename accepted")
					}
				})
			}
		}
		if _, err := file.WriteString("original"); err != nil {
			t.Fatal(err)
		}
		if f, err := createSiteFile(root, "key.bin"); err == nil || !os.IsExist(err) {
			if f != nil {
				f.Close()
			}
			t.Fatalf("existing file accepted: %v", err)
		}
		if data, err := os.ReadFile(filepath.Join(dir, "key.bin")); err != nil || string(data) != "original" {
			t.Fatalf("existing contents changed: %v", err)
		}
		// Windows roots hold a directory handle that prevents this rename.
		if runtime.GOOS != "windows" {
			moved := filepath.Join(fixture, "moved")
			if err := os.Rename(dir, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			pinned, err := createSiteFile(root, "pinned.key")
			if err != nil {
				t.Fatal(err)
			}
			defer pinned.Close()
			if err := checkPrivateSiteFile(pinned); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, "pinned.key")); !os.IsNotExist(err) {
				t.Fatal("creation followed a replacement directory")
			}
			if _, err := os.Stat(filepath.Join(moved, "pinned.key")); err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("setup commands quote paths for the host shell", func(t *testing.T) {
		// Printed commands are for PowerShell on Windows, which also ends a
		// single-quoted string at a typographic quote, and for sh elsewhere.
		var quotes string
		for _, r := range []rune{0x2018, 0x2019, 0x201a, 0x201b} {
			quotes += string(r)
		}
		values := []string{
			filepath.Join(t.TempDir(), "site.json"),
			`C:\Site Files\it's "here" $HOME $(id) ` + "`date`;&|",
			"a" + quotes + "b",
			"x" + string(rune(0x2019)) + "; Write-Output injected; " + string(rune(0x2019)) + "y",
		}
		var script strings.Builder
		var shell *exec.Cmd
		if runtime.GOOS == "windows" {
			script.WriteString("\xef\xbb\xbf") // UTF-8 BOM for Windows PowerShell 5.1
			for _, value := range values {
				fmt.Fprintf(&script, "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(%s))\n", setupQuote(value))
			}
			path := filepath.Join(t.TempDir(), "quote.ps1")
			if err := os.WriteFile(path, []byte(script.String()), 0600); err != nil {
				t.Fatal(err)
			}
			shell = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
		} else {
			script.WriteString(`printf '%s\n'`)
			for _, value := range values {
				script.WriteString(" " + setupQuote(value))
			}
			shell = exec.Command("sh", "-c", script.String())
		}
		out, err := shell.Output()
		if err != nil {
			t.Fatalf("host shell rejected the printed quoting: %v", err)
		}
		lines := strings.Split(strings.TrimRight(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n"), "\n")
		if len(lines) != len(values) {
			t.Fatalf("host shell read %d values, want %d: %q", len(lines), len(values), out)
		}
		for i, value := range values {
			got := lines[i]
			if runtime.GOOS == "windows" {
				decoded, err := base64.StdEncoding.DecodeString(got)
				if err != nil {
					t.Fatal(err)
				}
				got = string(decoded)
			}
			if got != value {
				t.Errorf("host shell read %q, want %q", got, value)
			}
		}
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
		if r.URL.Path == "/__cli_test_slow" { // an application that answers after the shortest write or upstream timeout a test sets
			time.Sleep(2 * time.Second)
		}
		// One that starts its answer at once and ends it after that timeout. Its length is announced, so the proxy holds what
		// has come of it until the rest does, rather than passing each part on as it arrives.
		if r.URL.Path == "/__cli_test_slow_body" {
			w.Header().Set("Content-Length", "16")
			_, _ = w.Write([]byte("part of "))
			w.(http.Flusher).Flush()
			time.Sleep(2 * time.Second)
			_, _ = w.Write([]byte("the rest"))
			return
		}
		if r.URL.Path == "/__cli_test_cut" { // an application that dies part way through the body it announced
			w.Header().Set("Content-Length", "1000")
			w.Write([]byte("part of a body"))
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
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
	t.Run("setup visitor certificate", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := filepath.Join(dir, "visitor.crt"), filepath.Join(dir, "visitor.key")
		if err := os.WriteFile(certPath, serverIdentity.certPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, serverIdentity.keyPEM, 0600); err != nil {
			t.Fatal(err)
		}
		keyMode(t, keyPath, 0o600)
		for _, tc := range []struct {
			name  string
			hosts []string
			bad   bool
		}{
			{"covered DNS and IP", []string{"localhost", "127.0.0.1"}, false},
			{"one uncovered name", []string{"localhost", "other.test"}, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := checkSetupCertificate(certPath, keyPath, tc.hosts); (err != nil) != tc.bad {
					t.Fatalf("certificate validation=%v", err)
				}
			})
		}
		for _, flow := range []struct {
			name  string
			extra []string
		}{
			{"HTTPS visitor setup", []string{"https", "127.0.0.1:8443", certPath, keyPath}},
			{"TLS gateway setup", []string{"proxy", "127.0.0.1:8080", "127.0.0.1/32"}},
		} {
			t.Run(flow.name, func(t *testing.T) {
				answers := append([]string{"localhost", app.URL, "yes", ""}, flow.extra...)
				answers = append(answers, "", "", "detect", "", "", "", "", "", "", "no", "no")
				var transcript bytes.Buffer
				if err := runSetup(strings.NewReader(strings.Join(answers, "\n")), &transcript, runArgs); err != nil {
					t.Fatalf("setup=%v %s", err, &transcript)
				}
			})
		}

		brokenPath := filepath.Join(dir, "broken.key")
		if err := os.WriteFile(brokenPath, []byte("not a private key"), 0600); err != nil {
			t.Fatal(err)
		}
		keyMode(t, brokenPath, 0o600)
		if err := checkSetupCertificate(certPath, brokenPath, []string{"localhost"}); err == nil {
			t.Fatal("invalid visitor private key accepted")
		}
		// Setup refuses what start-up would refuse: the right key, but one everyone can read.
		openPath := filepath.Join(dir, "open.key")
		if err := os.WriteFile(openPath, serverIdentity.keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		keyMode(t, openPath, 0o644)
		if err := checkSetupCertificate(certPath, openPath, []string{"localhost"}); err == nil {
			t.Fatal("a visitor key everyone can read was accepted")
		}
	})

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
					keyMode(t, path, tc.mode)
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

	t.Run("listener failures close both endpoints", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			brokenTLS  bool
			lostHealth bool
		}{
			{"health listener closed before serving", false, true},
			{"visitor TLS fails before accept", true, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				visitor, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer visitor.Close()
				address := visitor.Addr().String()
				healthListener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer healthListener.Close()
				healthAddress := healthListener.Addr().String()
				if tc.lostHealth {
					if err := healthListener.Close(); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				done := make(chan error, 1)
				server := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
				if tc.brokenTLS {
					server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
				}
				defer server.Close()
				go func() {
					done <- serveRuntime(ctx, server, visitor, healthListener, &runtimeHealth{},
						lifecycleOptions{shutdown: time.Second}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
				}()
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("lost listener was reported as a clean stop")
					}
				case <-ctx.Done():
					t.Fatal("listener failure did not stop the serving goroutines")
				}
				for _, endpoint := range []string{address, healthAddress} {
					if connection, err := net.DialTimeout("tcp", endpoint, 100*time.Millisecond); err == nil {
						connection.Close()
						t.Fatal("listener remained open after serving failed")
					}
				}
			})
		}
	})

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

	client := &http.Client{Timeout: 3 * time.Second}
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
	unix := runtime.GOOS != "windows" // file modes mean nothing on Windows, so a check of them passes there
	onUnix := func(s string) string {
		if unix {
			return s
		}
		return ""
	}
	tests := []struct {
		site                                                                        string
		health                                                                      bool
		healthAlias                                                                 string
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
		says                                                                        string // what the log of a failure or a preflight must say
		allowEncoding, fails, policyDir                                             bool
		status                                                                      int
	}{
		{name: "expanded IPv6 health address works", health: true, healthAlias: "ipv6-expanded", method: "GET", target: "/page", status: 200},
		{name: "mapped IPv4 health address works", health: true, healthAlias: "ipv4-mapped", method: "GET", target: "/page", status: 200},
		{name: "version cannot bypass health action", extraArgs: []string{"-probe", "ready", "-version"}, fails: true},
		{name: "private health probes preserve forwarding", health: true, method: "GET", target: "/page", status: 200},
		{name: "visitor readiness path still inspected", health: true, mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/readyz?q=%3Cscript%3Ealert(1)%3C/script%3E", status: 403},
		{name: "public health binding refused", extraArgs: []string{"-health-listen", "0.0.0.0:8082"}, fails: true},
		{name: "wildcard health binding refused", extraArgs: []string{"-health-listen", ":8082"}, fails: true},
		{name: "health hostname refused", extraArgs: []string{"-health-listen", "localhost:8082"}, fails: true},
		{name: "health ephemeral port refused", extraArgs: []string{"-health-listen", "127.0.0.1:0"}, fails: true},
		{name: "negative drain delay refused", extraArgs: []string{"-drain-delay", "-1s"}, fails: true},
		{name: "negative form body limit refused", extraArgs: []string{"-max-form-body", "-1", "-check"}, fails: true, says: "-max-form-body must not be negative"},
		{name: "drain must fit shutdown budget", extraArgs: []string{"-drain-delay", "1s", "-shutdown-timeout", "1s"}, fails: true},
		{name: "unbounded shutdown refused", extraArgs: []string{"-shutdown-timeout", "0"}, fails: true},
		{name: "excess shutdown refused", extraArgs: []string{"-shutdown-timeout", "11m"}, fails: true},
		{name: "probe kind refused", extraArgs: []string{"-probe", "drain", "-health-listen", "127.0.0.1:8082"}, fails: true},
		{name: "probe needs private listener", extraArgs: []string{"-probe", "live"}, fails: true},
		{name: "probe cannot run deployment check", extraArgs: []string{"-probe", "live", "-health-listen", "127.0.0.1:8082", "-check"}, fails: true},
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
		{name: "site config switches a local rule off", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"block\",\"local-rules-off\":\"5006012\"}}", method: "GET", target: "/actuator/env", status: 200},
		{name: "site config leaves other local rules on", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"block\",\"local-rules-off\":\"5006012\"}}", method: "GET", target: "/wp-admin/install.php", status: 403},
		{name: "site config names no local rule", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"local-rules-off\":\"942100\"}}", fails: true},
		{name: "site config switches a stricter rule on", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"block\",\"local-rules-on\":\"5006101\"}}", method: "GET", target: "/console", status: 403},
		{name: "site config blocks injection", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"block\",\"formats-mode\":\"block\"}}", method: "GET", target: "/page?q=%3Cscript%3Ealert(1)%3C/script%3E", status: 403},
		{name: "site config format enforcement", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"block\",\"formats-mode\":\"block\"}}", ct: "application/json", body: "{\"a\":1,\"a\":2}", status: 400},
		{name: "explicit false overrides file true", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"off\",\"allow-request-encoding\":true}}", mode: "off", extraArgs: []string{"-allow-request-encoding=false"}, status: 200},
		{name: "explicit enforcement overrides file monitor", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"off\",\"formats-mode\":\"monitor\"}}", mode: "block", ct: "application/json", body: "{\"a\":1,\"a\":2}", status: 400},
		{name: "site config private origin needs allowance", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\"}}", fails: true},
		{name: "site check does not listen or require inherited socket", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"systemd-socket\":true}}", preflight: true, extraArgs: []string{"-check"}},
		{name: "site check verifies origin connectivity without HTTP", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\"}}", preflight: true, extraArgs: []string{"-check", "-check-origin"}},
		{name: "site check validates confine port list", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"confine\":true,\"confine-connect\":\"invalid\"}}", fails: true, extraArgs: []string{"-check"}, says: "-confine-connect:"},
		// A confined proxy can connect only to the listed ports: without the origin's it would pass the check and then refuse
		// every request, and without its own upload directory it would refuse every upload.
		{name: "confine refuses an origin port it may not connect to", extraArgs: []string{"-check", "-confine", "-upload-dir", "$UPLOADS"}, fails: true, says: "must be listed in -confine-connect"},
		{name: "confine without an upload directory warns that uploads will be refused", extraArgs: []string{"-check", "-confine", "-confine-connect", "$ORIGINPORT,53"}, preflight: true, says: "uploads with file parts will be refused"},
		{name: "confine refuses an upload directory its group may write", extraArgs: []string{"-check", "-confine", "-confine-connect", "$ORIGINPORT,53", "-upload-dir", "$SHAREDUPLOADS"}, fails: unix, preflight: !unix, says: onUnix("-upload-dir: mode 0770")},
		{name: "confine check passes with the origin port and an upload directory", extraArgs: []string{"-check", "-confine", "-confine-connect", "$ORIGINPORT,53", "-upload-dir", "$UPLOADS"}, preflight: true},
		// The reverse proxy's own line about a body the application cut short is JSON, named, without the addresses.
		{name: "an application that cuts its body short is logged as the origin's error", mode: "block", method: "GET", target: "/__cli_test_cut", status: 0, says: `"server":"origin"`},
		// The client gives up after three seconds, and the application ends its answer after two: only a write timeout of 1.5
		// cuts it. The upstream timeout must be shorter than the write timeout.
		{name: "a response longer than -write-timeout is cut", extraArgs: []string{"-read-timeout", "1s", "-write-timeout", "1500ms", "-upstream-timeout", "1s"}, method: "GET", target: "/__cli_test_slow_body", status: 0},
		{name: "a response within -write-timeout is answered", extraArgs: []string{"-read-timeout", "1s", "-write-timeout", "5s", "-upstream-timeout", "3s"}, method: "GET", target: "/__cli_test_slow", status: 200},
		// The application starts its answer after two seconds: past an -upstream-timeout of one, the visitor gets a 502.
		{name: "an answer slower than -upstream-timeout is a 502", extraArgs: []string{"-upstream-timeout", "1s"}, method: "GET", target: "/__cli_test_slow", status: 502,
			logRule: `"rule":5000050`},
		{name: "an upstream timeout over a day refuses startup", extraArgs: []string{"-check", "-upstream-timeout", "25h"}, fails: true, says: "-upstream-timeout must be 0 (30s) or from 1s to 24h"},
		{name: "an upstream timeout under a second refuses startup", extraArgs: []string{"-check", "-upstream-timeout", "1ns"}, fails: true, says: "-upstream-timeout must be 0 (30s) or from 1s to 24h"},
		{name: "an upstream timeout within the default write timeout refuses startup", extraArgs: []string{"-check", "-upstream-timeout", "5m"}, fails: true,
			says: "-upstream-timeout (5m0s) must be shorter than -write-timeout (2m0s)"},
		{name: "an upstream timeout within the write timeout refuses startup", extraArgs: []string{"-check", "-upstream-timeout", "5m", "-write-timeout", "5m"}, fails: true,
			says: "-upstream-timeout (5m0s) must be shorter than -write-timeout (5m0s)"},
		{name: "a read timeout over a day refuses startup", extraArgs: []string{"-check", "-read-timeout", "25h"}, fails: true, says: "-read-timeout must be 0 (30s) or from 1s to 23h"},
		// No -write-timeout could be both longer than a read timeout of a day and within its own day.
		{name: "a read timeout of a day refuses startup", extraArgs: []string{"-check", "-read-timeout", "24h"}, fails: true, says: "-read-timeout must be 0 (30s) or from 1s to 23h"},
		{name: "a read timeout under a second refuses startup", extraArgs: []string{"-check", "-read-timeout", "1ms"}, fails: true, says: "-read-timeout must be 0 (30s) or from 1s to 23h"},
		{name: "the longest read and write timeouts", extraArgs: []string{"-check", "-read-timeout", "23h", "-write-timeout", "24h"}, preflight: true},
		{name: "a detected attack is one intrusion alert", extraArgs: []string{"-mode", "detect"}, method: "GET", target: "/page?id=1%27%20UNION%20SELECT%20password%20FROM%20users--", status: 200, says: `"msg":"intrusion detected"`},
		{name: "a blocked attack is one intrusion alert", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/page?id=1%27%20UNION%20SELECT%20password%20FROM%20users--", status: 403,
			says: `"msg":"intrusion blocked"`},
		{name: "alerts and auto-block settings pass the check", extraArgs: []string{"-check", "-alert-source", "prefix", "-alert-path", "full", "-alert-min-risk", "medium",
			"-alert-suppress", "crs-920350 note=numeric host; crs-942100 /search until=2099-12-31", "-alert-exclude-sources", "192.0.2.0/24",
			"-auto-block", "on", "-auto-block-exempt", "198.51.100.7", "-eval-budget-detect", "refuse"}, preflight: true},
		{name: "alerts off pass the check", extraArgs: []string{"-check", "-alerts", "off"}, preflight: true},
		{name: "an unknown alerts value refuses startup", extraArgs: []string{"-check", "-alerts", "maybe"}, fails: true, says: "-alerts must be on or off"},
		{name: "an unknown alert source refuses startup", extraArgs: []string{"-check", "-alert-source", "everyone"}, fails: true, says: "-alert-source must be full, prefix or off"},
		{name: "an unknown alert path refuses startup", extraArgs: []string{"-check", "-alert-path", "query"}, fails: true, says: "-alert-path must be template, full or off"},
		{name: "an unknown minimum risk refuses startup", extraArgs: []string{"-check", "-alert-min-risk", "severe"}, fails: true, says: "-alert-min-risk must be info, low, medium or high"},
		{name: "an alert rate of zero refuses startup", extraArgs: []string{"-check", "-alert-rate", "0"}, fails: true, says: "-alert-rate must be from 1 to 10000"},
		{name: "a short repeat window refuses startup", extraArgs: []string{"-check", "-alert-repeat-window", "1s"}, fails: true, says: "-alert-repeat-window must be from 10s to 1h0m0s"},
		{name: "a short totals interval refuses startup", extraArgs: []string{"-check", "-alert-totals-interval", "1s"}, fails: true, says: "-alert-totals-interval must be 0 or from 10s to 24h"},
		{name: "an excluded source wider than a /16 refuses startup", extraArgs: []string{"-check", "-alert-exclude-sources", "10.0.0.0/8"}, fails: true, says: "-alert-exclude-sources:"},
		{name: "an unknown suppression signature refuses startup", extraArgs: []string{"-check", "-alert-suppress", "not a signature"}, fails: true, says: "-alert-suppress:"},
		{name: "an unknown detection budget choice refuses startup", extraArgs: []string{"-check", "-eval-budget-detect", "skip"}, fails: true, says: "-eval-budget-detect must be forward or refuse"},
		{name: "flood protection off leaves the default auto-block quietly off", extraArgs: []string{"-check", "-ddos", "off"}, preflight: true},
		{name: "auto-block asked for without flood protection refuses startup", extraArgs: []string{"-check", "-ddos", "off", "-auto-block", "on"}, fails: true,
			says: "-auto-block on needs -ddos on or monitor"},
		{name: "an unknown auto-block mode refuses startup", extraArgs: []string{"-check", "-auto-block", "always"}, fails: true, says: "-auto-block must be off, monitor or on"},
		{name: "too few auto-block points refuse startup", extraArgs: []string{"-check", "-auto-block-points", "3"}, fails: true, says: "-auto-block-points must be from 4 to 1000"},
		{name: "a longest ban shorter than the first refuses startup", extraArgs: []string{"-check", "-auto-block-for", "30m", "-auto-block-max-for", "20m"}, fails: true,
			says: "-auto-block-max-for (20m0s) must be at least -auto-block-for (30m0s)"},
		{name: "an auto-block exemption wider than a /16 refuses startup", extraArgs: []string{"-check", "-auto-block-exempt", "10.0.0.0/8"}, fails: true, says: "-auto-block-exempt:"},
		{name: "a negative write timeout refuses startup", extraArgs: []string{"-check", "-write-timeout", "-1s"}, fails: true, says: "-write-timeout must be 0 (-read-timeout plus 90s) or from 1s to 24h"},
		{name: "a write timeout within the read timeout refuses startup", extraArgs: []string{"-check", "-read-timeout", "2m", "-write-timeout", "1m"}, fails: true,
			says: "-write-timeout (1m0s) must be longer than -read-timeout (2m0s)"},
		{name: "a write timeout within the default read timeout refuses startup", extraArgs: []string{"-check", "-write-timeout", "30s"}, fails: true,
			says: "-write-timeout (30s) must be longer than -read-timeout (30s)"},
		{name: "a write timeout within the default upstream timeout refuses startup", extraArgs: []string{"-check", "-read-timeout", "10s", "-write-timeout", "20s"}, fails: true,
			says: "-write-timeout (20s) must be longer than -upstream-timeout (30s, its default)"},
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
		{name: "live exploit path", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/wp-content/uploads/2024/x.php.jpg", status: 403, logRule: `"rule":5006011,"severity":"critical","rule_msg":"Exploit or web shell path"`,
			says: `"disruptive":false,"category":"scanner","risk":"low"`},
		{name: "live debug interface", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/actuator/env", status: 403, logRule: `"rule":5006012,"severity":"critical","rule_msg":"Debug or diagnostic interface"`},
		{name: "live remote include", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/index.php?page=http%3A%2F%2Fevil.example%2Fx", status: 403, logRule: `"rule":5006015,"severity":"critical","rule_msg":"Remote file reference in an include parameter"`},
		{name: "live local rules switched off", mode: "block", extraArgs: []string{"-mode", "block", "-local-rules-off", "5006012, 5006013"}, method: "GET", target: "/actuator/env", status: 200},
		{name: "live local rule off keeps the others", mode: "block", extraArgs: []string{"-mode", "block", "-local-rules-off", "5006012"}, method: "GET", target: "/wp-admin/install.php", status: 403, logRule: `"rule":5006013`},
		{name: "known visitor budget flags", mode: "block", extraArgs: []string{"-ddos", "on", "-ddos-known-factor", "4", "-ddos-known-rate", "100"}, method: "GET", target: "/page", status: 200},
		{name: "negative known visitor budget", mode: "block", extraArgs: []string{"-ddos", "on", "-ddos-known-rate", "-1"}, fails: true, says: "-ddos-known-rate must be a number from 0.01 to 1000000"},
		{name: "negative known visitor factor", mode: "block", extraArgs: []string{"-ddos", "on", "-ddos-known-factor", "-1"}, fails: true, says: "-ddos-known-factor must be a number from 0.01 to 1000"},
		{name: "site config names a protection strength", site: `{"version":1,"flags":{"upstream":"$ORIGIN","origin-allow":"127.0.0.1/32","ddos":"strict","ddos-rate":60}}`, extraArgs: []string{"-check"}, preflight: true,
			says: `"ddos":"on","ddos_strength":"strict","ddos_overrides":["-ddos-rate"]`},
		{name: "flood flags with protection off are reported", extraArgs: []string{"-check", "-ddos", "off", "-ddos-rate", "10"}, preflight: true,
			says: `"msg":"flood protection flags have no effect with -ddos off","flags":["-ddos-rate"]`},
		{name: "a flood flag out of range is refused with protection off too", extraArgs: []string{"-check", "-ddos", "off", "-ddos-rate", "-5"}, fails: true,
			says: "-ddos-rate must be a number from 0.01 to 1000000 requests a second"},
		{name: "address limits kept fixed", mode: "block", extraArgs: []string{"-ddos", "on", "-ddos-max-raise", "1"}, method: "GET", target: "/page", status: 200},
		{name: "address limit raise below one", mode: "block", extraArgs: []string{"-ddos", "on", "-ddos-max-raise", "0.5"}, fails: true},
		{name: "address limit raise of zero", mode: "block", extraArgs: []string{"-ddos", "on", "-ddos-max-raise", "0"}, fails: true},
		{name: "address limit raise too high", mode: "block", extraArgs: []string{"-ddos", "on", "-ddos-max-raise", "101"}, fails: true},
		{name: "address limit raise not a number", mode: "block", extraArgs: []string{"-ddos", "on", "-ddos-max-raise", "NaN"}, fails: true},
		{name: "local rules off names a CRS rule", mode: "block", extraArgs: []string{"-local-rules-off", "942100"}, fails: true},
		{name: "local rules off names no rule", mode: "block", extraArgs: []string{"-local-rules-off", "actuator"}, fails: true},
		{name: "live stricter rule is off by default", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/console", status: 200},
		{name: "live stricter rule switched on", mode: "block", extraArgs: []string{"-mode", "block", "-local-rules-on", "5006101"}, method: "GET", target: "/console", status: 403, logRule: `"rule":5006101,"severity":"critical","rule_msg":"Console path"`},
		{name: "live stricter rule on keeps the other off", mode: "block", extraArgs: []string{"-mode", "block", "-local-rules-on", "5006101"}, ct: "application/x-www-form-urlencoded", body: "input_3=http%3A%2F%2Fevil.example%2Fa.php", status: 200},
		{name: "live script in a form field, switched on", mode: "block", extraArgs: []string{"-mode", "block", "-local-rules-on", "5006101, 5006102"}, ct: "application/x-www-form-urlencoded", body: "input_3=http%3A%2F%2Fevil.example%2Fa.php", status: 403, logRule: `"rule":5006102`},
		{name: "live database tool", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/phpmyadmin/index.php", status: 403, logRule: `"rule":5006018,"severity":"critical","rule_msg":"Database administration tool"`},
		{name: "live script on another host", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/x?view=http%3A%2F%2Fevil.example%2Fa.php", status: 403, logRule: `"rule":5006021`},
		{name: "local rules on names a default rule", mode: "block", extraArgs: []string{"-local-rules-on", "5006012"}, fails: true},
		{name: "local rules on names no rule", mode: "block", extraArgs: []string{"-local-rules-on", "console"}, fails: true},
		{name: "a local rule both on and off", mode: "block", extraArgs: []string{"-local-rules-on", "5006101", "-local-rules-off", "5006101"}, fails: true},
		{name: "live parameter collision", mode: "block", ct: "application/x-www-form-urlencoded", body: "user.name=a&user_name=b", status: 400, logRule: `"rule":5002608`},
		{name: "live parameter name spelt two ways", mode: "block", ct: "application/x-www-form-urlencoded", body: "role=user&%72ole=admin", status: 400, logRule: `"rule":5002609`},
		{name: "live query name spelt two ways", mode: "block", method: "GET", target: "/x?role=user&Role=admin", status: 400, logRule: `"rule":5002810`},
		{name: "live injection split over a repeated parameter", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/api/update?q=UNION&q=SELECT+password+FROM+users", status: 403, logRule: `"rule":949110`},
		{name: "live repeated parameter, joining switched off", mode: "block", extraArgs: []string{"-mode", "block", "-join-repeated-params=false"}, method: "GET", target: "/api/update?q=UNION&q=SELECT+password+FROM+users", status: 200},
		{name: "live repeated choices", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/shop?color=red&color=blue&size=m&size=l", status: 200},
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
		{name: "HEAD duplicate operationName", mode: "block", method: "HEAD", target: "/api/gql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read&operationName=Write", status: 400, logRule: "\"rule\":5002308"},
		{name: "HEAD operationName spelt two ways", mode: "block", method: "HEAD", target: "/api/gql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read&%6fperationName=Write", status: 400, logRule: `"rule":5002810`},
		{name: "selected GET query beside mutation", mode: "block", method: "GET", target: "/graphql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read", status: 200},
		{name: "valid JSON", mode: "block", ct: "application/json", body: good, status: 200},
		{name: "query malformed escape", mode: "block", method: "GET", target: "/api?x=%zz", status: 400},
		{name: "query raw semicolon", mode: "block", method: "GET", target: "/api?x=1;y=2", status: 400},
		{name: "query escaped NUL", mode: "block", ct: "application/json", body: good, target: "/api?x=%00", status: 400},
		{name: "query invalid UTF-8", mode: "block", method: "GET", target: "/api?x=%ff", status: 400},
		{name: "query prototype key", mode: "block", method: "GET", target: "/api?user%5B__proto__%5D%5Badmin%5D=1", status: 400},
		{name: "valid query preserves target", mode: "block", method: "GET", target: "/api?q=a%3Bb%26c&tag%5B%5D=red&tag%5B%5D=blue", status: 200},
		{name: "query duplicate monitor", mode: "block", method: "GET", target: "/api?id=1&id=2", status: 200, logRule: `"rule":5002802`},
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
		{name: "a -limit rule refuses past its count", mode: "off", extraArgs: []string{"-limit", "POST /api 1/m"}, statuses: []int{200, 429}, logRule: `"rule":5000047`,
			says: `"rate_limits":["POST /api 1/1m (flag)"]`},
		{name: "a site configuration limit", mode: "off", site: `{"version":1,"flags":{"upstream":"$ORIGIN","origin-allow":"127.0.0.1/32","limit":"POST /api 1/m"}}`,
			statuses: []int{200, 429}, logRule: `"rule":5000047`, says: `"rate_limits":["POST /api 1/1m (site configuration)"]`},
		{name: "a -limit replaces the site configuration's", mode: "off", site: `{"version":1,"flags":{"upstream":"$ORIGIN","origin-allow":"127.0.0.1/32","limit":"POST /api 1/m"}}`,
			extraArgs: []string{"-limit", "GET /api 1/m"}, statuses: []int{200, 200}, says: `"msg":"site configuration limit replaced by the command line"`},
		{name: "an invalid site configuration limit is refused with the reason", site: `{"version":1,"flags":{"upstream":"$ORIGIN","origin-allow":"127.0.0.1/32","limit":"POST /api 5/x"}}`,
			extraArgs: []string{"-check"}, fails: true,
			says: `invalid site configuration flag "limit": -limit rule 1 ("POST /api 5/x"): "5/x": unknown window unit "x"; use s, m or h, such as 5/m, 100/10s or 1k/h`},
		// These are checked after the file is read, together with the other flags; the refusal still names the file's flag.
		{name: "a site configuration strength that does not read is refused as the site's", site: `{"version":1,"flags":{"upstream":"$ORIGIN","origin-allow":"127.0.0.1/32","ddos":"strcit"}}`,
			extraArgs: []string{"-check"}, fails: true,
			says: `invalid site configuration flag "ddos": -ddos: "strcit" is not one of on, monitor, off, relaxed, normal, strict (did you mean strict?)`},
		{name: "a site configuration login limit out of range is refused as the site's", site: `{"version":1,"flags":{"upstream":"$ORIGIN","origin-allow":"127.0.0.1/32","login-per-minute":0}}`,
			extraArgs: []string{"-check"}, fails: true, says: `invalid site configuration flag "login-per-minute": -login-per-minute must be from 1 to 100000`},
		{name: "a site configuration trusted proxy that does not read is refused as the site's", site: `{"version":1,"flags":{"upstream":"$ORIGIN","origin-allow":"127.0.0.1/32","trusted-proxies":"bogus"}}`,
			extraArgs: []string{"-check"}, fails: true, says: `invalid site configuration flag "trusted-proxies"`},
		{name: "a site configuration timeout out of range is refused as the site's", site: `{"version":1,"flags":{"upstream":"$ORIGIN","origin-allow":"127.0.0.1/32","read-timeout":"25h"}}`,
			extraArgs: []string{"-check"}, fails: true, says: `invalid site configuration flag "read-timeout": -read-timeout must be 0 (30s) or from 1s to 23h`},
		{name: "rate limits are listed with where they come from", extraArgs: []string{"-check", "-wordpress", "-api-per-minute", "60", "-api-rate-paths", "/API,/v1",
			"-limit", "POST /login,/register 5/m", "-limit", "get /search 30/10s monitor"}, preflight: true,
			says: `"rate_limits":["POST */wp-login.php 10/1m (-wordpress)","/api,/v1 60/1m (-api-per-minute)","POST /login,/register 5/1m (flag)","GET /search 30/10s monitor (flag)"]`},
		{name: "a login limit a local policy switches on is listed", extraArgs: []string{"-check", "-policy", protectionFixture(t, "policy.json", `{"wordpress":{"enabled":true,"login_per_minute":5}}`)},
			preflight: true, says: `"rate_limits":["POST */wp-login.php 5/1m (-policy)"]`},
		{name: "a -limit rule that does not read refuses startup", extraArgs: []string{"-check", "-limit", "/api 600/m; PSOT /login 5/m"}, fails: true,
			says: `-limit rule 2 ("PSOT /login 5/m"): "PSOT" is not an HTTP method (did you mean POST?)`},
		{name: "repeated -limit flags are numbered together", extraArgs: []string{"-check", "-limit", "/api 600/m", "-limit", "/api 600/m"}, fails: true,
			says: `-limit rule 2 ("/api 600/m"): repeats rule 1`},
		{name: "negative API limit refuses startup", mode: "off", apiRate: -1, fails: true, says: "-api-per-minute must be 0 (off) or from 1 to 100000"},
		{name: "excess API limit refuses startup", mode: "off", apiRate: 100001, fails: true, says: "-api-per-minute must be 0 (off) or from 1 to 100000"},
		{name: "invalid API prefix refuses startup", mode: "off", apiRate: 1, apiPaths: "/api?x=1", fails: true,
			says: `-api-rate-paths: path "/api?x=1" must be a plain absolute path`},
		{name: "an API prefix with a trailing slash is named", mode: "off", apiRate: 1, apiPaths: "/api,/v1/,/graphql", fails: true,
			says: `-api-rate-paths: "/v1/" has a trailing slash; write /v1`},
		{name: "API prefixes that are all empty refuse startup", mode: "off", apiRate: 1, apiPaths: " , ", fails: true, says: "-api-rate-paths has no path"},
		{name: "API prefixes without an API limit are reported", extraArgs: []string{"-check", "-api-rate-paths", "/v1"}, preflight: true,
			says: `"msg":"-api-rate-paths has no effect with -api-per-minute 0"`},
		{name: "a login limit without WordPress is reported", extraArgs: []string{"-check", "-login-per-minute", "50"}, preflight: true,
			says: `"msg":"-login-per-minute has no effect without -wordpress"`},
		{name: "a login limit of zero refuses startup", extraArgs: []string{"-check", "-wordpress", "-login-per-minute", "0"}, fails: true,
			says: "-login-per-minute must be from 1 to 100000"},
		{name: "a trusted proxy that does not parse is named", extraArgs: []string{"-check", "-trusted-proxies", "127.0.0.1,proxy"}, fails: true,
			says: `-trusted-proxies: trusted proxy "proxy"`},
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
			addr := "127.0.0.1:" + quietPort(t, "tcp", "127.0.0.1")
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
			if strings.Contains(strings.Join(tc.extraArgs, " "), "$") {
				_, originPort, _ := net.SplitHostPort(strings.TrimPrefix(app.URL, "http://"))
				uploads, err := os.MkdirTemp("", "carnical-uploads") // plain characters, which the upload directory must have
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(uploads) })
				// A Windows temp directory can be named by its 8.3 short name (C:\Users\RUNNER~1\...), whose ~ the setting
				// refuses; the long name is the same directory in plain characters.
				long, err := filepath.EvalSymlinks(uploads)
				if err != nil {
					t.Fatal(err)
				}
				uploads = long
				shared := filepath.Join(uploads, "shared")
				if err := os.Mkdir(shared, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(shared, 0o770); err != nil {
					t.Fatal(err)
				}
				for i := range args {
					args[i] = strings.NewReplacer("$ORIGINPORT", originPort, "$SHAREDUPLOADS", shared, "$UPLOADS", uploads).Replace(args[i])
				}
			}

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
					keyMode(t, keyPath, 0o600)
					args = append(args, "-origin-client-cert", certPath, "-origin-client-key", keyPath)
				}
			}

			if tc.apiSpec != "" {
				data := []byte(tc.apiSpec)
				if tc.apiSpec == "example" {
					var err error
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
			healthAddress := ""
			if tc.health {
				// The health listener must be given a port (it refuses port 0), so the test names one.
				network, host := "tcp", "127.0.0.1"
				if tc.healthAlias == "ipv6-expanded" {
					network, host = "tcp6", "::1"
				}
				port := quietPort(t, network, host)
				healthAddress = net.JoinHostPort(host, port)
				switch tc.healthAlias {
				case "ipv6-expanded":
					healthAddress = "[0:0:0:0:0:0:0:1]:" + port
				case "ipv4-mapped":
					healthAddress = "[::ffff:127.0.0.1]:" + port
				}
				args = append(args, "-health-listen", healthAddress)
			}
			if !tc.preflight && !tc.fails {
				// The proxy picks its own port and says which. A port picked here is free only until something else takes
				// it, and another test's server that did would answer in the proxy's place.
				args[1] = "127.0.0.1:0"
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
				if !bytes.Contains(data, []byte(tc.says)) {
					t.Fatalf("the preflight did not say %q:\n%s", tc.says, data)
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
				if data, _ := os.ReadFile(logPath); !bytes.Contains(data, []byte(tc.says)) {
					t.Fatalf("failed, but not saying %q:\n%s", tc.says, data)
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
			url := "http://" + listeningAddress(ctx, t, logPath)
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
			if tc.health {
				for _, kind := range []string{"live", "ready"} {
					probe := exec.CommandContext(ctx, bin, "-health-listen", healthAddress, "-probe", kind)
					probe.Env = append(os.Environ(), "HTTP_PROXY=http://127.0.0.1:1", "NO_PROXY=")
					if out, err := probe.CombinedOutput(); err != nil {
						t.Fatalf("private %s probe: %v %s", kind, err, out)
					}
				}
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
				if want == 0 { // the connection is closed without an answer: the application died part way through it
					if err == nil {
						resp.Body.Close()
						t.Fatalf("status %d, want the connection closed without an answer", resp.StatusCode)
					}
					select {
					case <-requests:
					default:
						t.Fatal("the request did not reach the application")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != want {
					data, _ := os.ReadFile(logPath)
					t.Fatalf("status %d, want %d\n%s", resp.StatusCode, want, data)
				}
				// Requests a few seconds apart under a per-minute limit: the window clears 50 to 66 seconds after the first.
				if retry, err := strconv.Atoi(resp.Header.Get("Retry-After")); want == 429 && (err != nil || retry < 50 || retry > 66 || resp.Header.Get("Cache-Control") != "no-store") {
					t.Fatalf("rate refusal with Retry-After %q, Cache-Control %q", resp.Header.Get("Retry-After"), resp.Header.Get("Cache-Control"))
				}
				originRequests := requests
				if tc.originAuth != "" {
					originRequests = originCalls
				}
				// A 502 is the application failing to answer a request it was given.
				reached := want == 200 || want == 502
				select {
				case got := <-originRequests:
					if !reached {
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
					if reached {
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
			// Alerts and rule matches are written through queues, and cancel kills the process: wait for the lines first.
			for deadline := time.Now().Add(2 * time.Second); (tc.says != "" || tc.logRule != "") && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
				if data, err := os.ReadFile(logPath); err == nil && bytes.Contains(data, []byte(tc.says)) &&
					(tc.logRule == "" || bytes.Count(data, []byte(tc.logRule)) >= max(tc.repeat, 1)) {
					break
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
			if tc.says != "" && !bytes.Contains(data, []byte(tc.says)) {
				t.Fatalf("the log does not say %q:\n%s", tc.says, data)
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
					// A rule set rule that only adds to the anomaly score is never the one that refused: 949110 is.
					scores := id >= 5006000 && id <= 5006999 || id >= 900000 && id <= 999999 && id != 949110 && id != 959100
					matches := 0
					for _, line := range bytes.Split(data, []byte("\n")) {
						var event struct {
							Msg        string
							Rule       int
							Disruptive bool
						}
						if json.Unmarshal(line, &event) == nil && event.Msg == "rule matched" && event.Rule == id {
							matches++
							if event.Disruptive != (blocked && !scores) {
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

// The visitor's key and the CrowdSec bouncer key are read like the origin's: a key others can read is refused, and a FIFO
// put where the file was expected does not hold start-up.
// The settings a site file stores encrypted stay out of the errors the proxy prints. Given as flags, the same mistakes name
// them: that control shows each row would see a leak.
func TestEncryptedSiteSettingsStayOutOfErrors(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "site.key")
	key := make([]byte, 32)
	if _, err := cryptorand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := writeNewSiteFile(keyPath, key); err != nil {
		t.Fatal(err)
	}
	id, err := newSiteKeyID()
	if err != nil {
		t.Fatal(err)
	}
	hidden := filepath.Join(dir, "hidden-place")
	for _, tc := range []struct {
		name     string
		settings map[string]string
		extra    []string
		secrets  []string
	}{
		{name: "an upstream that does not parse", settings: map[string]string{"upstream": "http://secret-origin.test:8080/%zz"},
			secrets: []string{"secret-origin"}},
		{name: "an origin range that does not parse", settings: map[string]string{"upstream": "http://192.0.2.80:8080", "origin-allow": "192.0.2.0/24,10.99.88.0/33"},
			secrets: []string{"10.99.88", "192.0.2"}},
		{name: "a certificate that is not there", settings: map[string]string{"upstream": "http://192.0.2.80:8080", "origin-allow": "192.0.2.0/24",
			"tls-cert": filepath.Join(hidden, "site-cert.pem"), "tls-key": filepath.Join(hidden, "site-key.pem")}, secrets: []string{"hidden-place", "192.0.2"}},
		{name: "a trusted proxy that does not parse", settings: map[string]string{"upstream": "http://192.0.2.80:8080", "trusted-proxies": "10.99.88.7/33"},
			secrets: []string{"10.99.88"}},
		{name: "an origin that refuses the check", settings: map[string]string{"upstream": "http://127.0.0.1:1", "origin-allow": "127.0.0.0/8"},
			extra: []string{"-check-origin"}, secrets: []string{"127.0.0.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := map[string]any{}
			var asFlags []string
			for name, value := range tc.settings {
				settings[name] = value
				asFlags = append(asFlags, "-"+name, value)
			}
			sealed, err := sealSiteSettings(settings, id, key)
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(siteDocument{Version: 1, Flags: map[string]any{}, Private: sealed})
			if err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(t.TempDir(), "site.json")
			if err := os.WriteFile(config, data, 0600); err != nil {
				t.Fatal(err)
			}
			named := func(err error) bool {
				for _, secret := range tc.secrets {
					if strings.Contains(err.Error(), secret) {
						return true
					}
				}
				return false
			}
			err = runArgs(append([]string{"-config", config, "-config-key-file", keyPath, "-check"}, tc.extra...))
			if err == nil {
				t.Fatal("the mistake was not reported")
			}
			if named(err) {
				t.Errorf("the error names an encrypted setting: %v", err)
			}
			if err = runArgs(append(append(asFlags, "-check"), tc.extra...)); err == nil || !named(err) {
				t.Errorf("control: given as flags, the error does not name the setting: %v", err)
			}
		})
	}
}

func TestPrivateSettingsAreLeftOutOfErrorText(t *testing.T) {
	private := map[string]string{"upstream": "http://origin:8080/x", "origin-allow": "10.0.0.0/8,10.99.88.0/33",
		"tls-key": `C:\keys\site.key`, "upstream-host": "shop.example.test"}
	for _, tc := range []struct{ name, in, want string }{
		{"a URL in a parse error", `parse "http://origin:8080/x": invalid URL escape "%zz"`, `parse "[private setting]": invalid URL escape "%zz"`},
		{"one entry of a list", `invalid origin range "10.99.88.0/33"`, `invalid origin range "[private setting]"`},
		{"a path", `open C:\keys\site.key: not found`, `open [private setting]: not found`},
		{"an address the origin resolved to", `dial tcp 10.1.2.3:8080: refused`, `dial tcp [address]: refused`},
		{"a one-word host is replaced only where it can be nothing else", `origin preflight: lookup origin: no such host`,
			`origin preflight: lookup [private setting]: no such host`},
		{"a one-word host the origin check could not resolve", `origin preflight: resolving origin: lookup origin on 10.0.0.53:53: no such host`,
			`origin preflight: resolving [private setting]: lookup [private setting] on [address]: no such host`},
		{"a one-word host with no address", `origin preflight: origin has no address`, `origin preflight: [private setting] has no address`},
		{"a one-word host at an address that is not allowed", `origin preflight: origin: 10.0.0.5 is not a public address (10.0.0.0/8)`,
			`origin preflight: [private setting]: [address] is not a public address ([private setting])`},
		{"a one-word host a certificate does not name", `origin preflight: tls: failed to verify certificate: x509: certificate is valid for www.example.com, not origin`,
			`origin preflight: tls: failed to verify certificate: x509: certificate is valid for www.example.com, not [private setting]`},
		{"a one-word host a certificate with no names does not name", `x509: certificate is not valid for any names, but wanted to match origin`,
			`x509: certificate is not valid for any names, but wanted to match [private setting]`},
		{"a longer name is left alone", `shop.example.testing and shop.example.test.`, `shop.example.testing and [private setting].`},
		{"nothing private", `-listen must have a valid TCP port`, `-listen must have a valid TCP port`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := redactPrivate(errors.New(tc.in), private)
			if err.Error() != tc.want {
				t.Fatalf("%q, want %q", err.Error(), tc.want)
			}
		})
	}
	if err := redactPrivate(fmt.Errorf("at http://origin:8080/x: %w", flag.ErrHelp), private); !errors.Is(err, flag.ErrHelp) ||
		strings.Contains(err.Error(), "origin:8080") {
		t.Fatalf("a redacted error no longer unwraps to what it was, or kept the setting: %v", err)
	}
}

func TestPrivateFilesAreReadWithCare(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("-----BEGIN PRIVATE KEY-----\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		keyMode(t, path, mode)
		return path
	}
	private, open := write("private.key", 0o600), write("open.key", 0o644)
	groupRead, groupWrite := write("group.key", 0o640), write("groupwrite.key", 0o620)
	readers := map[string]func(string, bool) error{
		"visitor TLS": func(p string, priv bool) error { _, err := readTLSFile(p, 64<<10, priv); return err },
		"CrowdSec":    func(p string, priv bool) error { _, err := readCrowdSecFile(p, 4096, priv); return err },
		"origin":      func(p string, priv bool) error { _, err := readOriginFile(p, 64<<10, priv); return err },
	}
	for name, read := range readers {
		t.Run(name, func(t *testing.T) {
			if err := read(private, true); err != nil {
				t.Fatalf("a private key: %v", err)
			}
			if err := read(groupRead, true); err != nil {
				t.Fatalf("a key its group may read: %v", err)
			}
			if err := read(open, false); err != nil {
				t.Fatalf("a public file: %v", err)
			}
			if err := read(open, true); err == nil {
				t.Fatal("a key everyone can read was accepted")
			}
			if err := read(groupWrite, true); err == nil {
				t.Fatal("a key its group may write was accepted")
			}
			if err := read(dir, false); err == nil {
				t.Fatal("a directory was read")
			}
			if runtime.GOOS == "windows" {
				// What an access list can say that a mode cannot. Each file starts with a list of its own, for this
				// account and SYSTEM, as keyMode makes it.
				for _, tt := range []struct {
					name   string
					args   []string // for icacls; or one argument that is the whole access list, as SDDL
					public bool     // too widely readable or writable for a key
				}{
					{"only this account and SYSTEM", nil, false},
					{"Users may read", []string{"/grant", "*S-1-5-32-545:(R)"}, true},
					{"Authenticated Users may read", []string{"/grant", "*S-1-5-11:(R)"}, true},
					{"Guests may read", []string{"/grant", "*S-1-5-32-546:(R)"}, true},
					{"interactive logons may read", []string{"/grant", "*S-1-5-4:(R)"}, true},
					{"every service may read", []string{"/grant", "*S-1-5-6:(R)"}, true},
					{"all application packages may read", []string{"/grant", "*S-1-15-2-1:(R)"}, true},
					{"Everyone may only read its attributes", []string{"/grant", "*S-1-1-0:(RA)"}, true},
					{"Everyone has full access", []string{"/grant", "*S-1-1-0:(F)"}, true},
					{"Everyone is denied writing", []string{"/deny", "*S-1-1-0:(WD)"}, false},
					{"another account may read and run", []string{"/grant", "*S-1-5-20:(RX)"}, false},
					{"another account may change the access list", []string{"/grant", "*S-1-5-20:(R,WDAC)"}, true},
					{"another account may take ownership", []string{"/grant", "*S-1-5-20:(R,WO)"}, true},
					{"another account may append", []string{"/grant", "*S-1-5-20:(R,AD)"}, true},
					{"another account may write data", []string{"/grant", "*S-1-5-20:(R,WD)"}, true},
					{"no access list at all", []string{"D:NO_ACCESS_CONTROL"}, true},
					{"another account has full access", []string{"/grant", "*S-1-5-19:(F)"}, true},
					{"Administrators have full access", []string{"/grant", "*S-1-5-32-544:(F)"}, false},
				} {
					t.Run(tt.name, func(t *testing.T) {
						path := write("acl.key", 0o600)
						defer os.Remove(path)
						switch {
						case len(tt.args) == 1:
							setSDDL(t, path, tt.args[0])
						case tt.args != nil:
							icacls(t, path, tt.args...)
						}
						if err := read(path, true); (err != nil) != tt.public {
							t.Fatalf("read as a private key: %v", err)
						}
						if err := read(path, false); err != nil {
							t.Fatalf("read as a public file: %v", err)
						}
					})
				}
				return
			}
			fifo := filepath.Join(t.TempDir(), "fifo.key")
			if err := exec.Command("mkfifo", "-m", "0600", fifo).Run(); err != nil {
				t.Skipf("no FIFO here: %v", err)
			}
			for _, priv := range []bool{false, true} { // a mode the key check accepts, so only the file type can refuse it
				done := make(chan error, 1)
				go func() { done <- read(fifo, priv) }()
				select {
				case err := <-done:
					if err == nil {
						t.Fatalf("a FIFO was read (private %v)", priv)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("reading a FIFO blocked")
				}
			}
		})
	}
	t.Run("other operator files from a FIFO", func(t *testing.T) {
		// These are not keys, so they hold no rows above; a FIFO must not hold start-up for them either.
		if runtime.GOOS == "windows" {
			t.Skip("no FIFO on Windows")
		}
		fifo := filepath.Join(t.TempDir(), "operator.fifo")
		if err := exec.Command("mkfifo", "-m", "0600", fifo).Run(); err != nil {
			t.Skipf("no FIFO here: %v", err)
		}
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		for _, tc := range []struct {
			name string
			read func() error
		}{
			{"-api-spec", func() error { _, _, err := configureAPI(fifo, "monitor", "monitor"); return err }},
			{"-formats-policy", func() error { _, err := configureFormats("monitor", fifo, false); return err }},
			{"-ddos-ranges", func() error {
				_, err := configureShield(log, shieldFlags{mode: "monitor", ranges: fifo}, nil, nil)
				return err
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				done := make(chan error, 1)
				go func() { done <- tc.read() }()
				select {
				case err := <-done:
					if err == nil || !strings.Contains(err.Error(), "regular file") {
						t.Fatalf("a FIFO was not refused as not a regular file: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("reading a FIFO blocked")
				}
			})
		}
	})
	t.Run("visitor TLS through a link", func(t *testing.T) {
		// certbot's live/ directory holds links into archive/; the visitor's pair is read through them.
		link := filepath.Join(t.TempDir(), "privkey.pem")
		if err := os.Symlink(private, link); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
		if _, err := readTLSFile(link, 64<<10, true); err != nil {
			t.Fatalf("a key through a link: %v", err)
		}
	})
}

// TestUploadDirIsCheckedBeforeConfinement: the confined proxy can write only its upload directory, which Landlock can grant
// only if it exists, and which must not be open to other users.
func TestUploadDirIsCheckedBeforeConfinement(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	unix := runtime.GOOS != "windows" // Windows has no such mode bits
	for _, tt := range []struct {
		name string
		path string
		ok   bool
	}{
		{"its own directory", mk("own", 0o700), true},
		{"readable by others", mk("readable", 0o755), true},
		{"not there", filepath.Join(dir, "missing"), false},
		{"a file", file, false},
		{"writable by its group", mk("group", 0o770), !unix},
		{"writable by everyone", mk("everyone", 0o777), !unix},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkUploadDir(tt.path); (err == nil) != tt.ok {
				t.Fatalf("accepted %v, want %v: %v", err == nil, tt.ok, err)
			}
		})
	}
}

// net/http's own lines about connections reach the JSON log without the client's address, unless details are on, and at most
// one a second.
func TestServerErrorsAreLoggedWithoutAddresses(t *testing.T) {
	type entry struct {
		Msg, Kind, Error string
		Dropped          int
		CutBytes         int `json:"cut_bytes"`
	}
	logged := func(t *testing.T, out *bytes.Buffer) []entry {
		t.Helper()
		var got []entry
		for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			var e entry
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				t.Fatalf("not JSON (%v): %s", err, line)
			}
			got = append(got, e)
		}
		return got
	}
	write := func(t *testing.T, s *serverErrors, line string) {
		t.Helper()
		if n, err := s.Write([]byte(line)); err != nil || n != len(line) {
			t.Fatalf("Write took %d of %d bytes: %v", n, len(line), err)
		}
	}
	at := func(out *bytes.Buffer, details bool, now func() time.Time) *serverErrors {
		return &serverErrors{log: slog.New(slog.NewJSONHandler(out, nil)), details: details, now: now}
	}
	for _, tt := range []struct {
		name    string
		details bool
		line    string
		want    string
	}{
		{"IPv4 handshake", false, "http: TLS handshake error from 192.0.2.7:51234: EOF\n", "http: TLS handshake error from [address]: EOF"},
		// What the client sent is quoted in the line; it is left out, and it cannot pass the line off as a panic.
		{"protocols the client asked for", false, "http: TLS handshake error from 192.0.2.7:51234: tls: client requested unsupported application protocols ([\"panic serving\" \"x\\\"y\"])\n",
			"http: TLS handshake error from [address]: tls: client requested unsupported application protocols ([\"[client data]\" \"[client data]\"])"},
		{"a greeting that was not HTTP/2", false, "http2: server: error reading preface from client 192.0.2.7:51234: bogus greeting \"Accept error: 1.2.3.4:56\"\n",
			"http2: server: error reading preface from client [address]: bogus greeting \"[client data]\""},
		{"IPv6 preface", false, "http2: server: error reading preface from client [2001:db8::7]:443: bogus greeting\n", "http2: server: error reading preface from client [address]: bogus greeting"},
		{"both ends of a timed-out connection", false, "http: TLS handshake error from 127.0.0.1:61492: read tcp 127.0.0.1:61491->127.0.0.1:61492: i/o timeout\n",
			"http: TLS handshake error from [address]: read tcp [address]->[address]: i/o timeout"},
		{"both ends with IPv6 zones", false, "http2: server: error reading preface from client [fe80::1%eth0]:51234: read tcp [fe80::2%eth0]:443->[fe80::1%eth0]:51234: read: connection reset by peer\n",
			"http2: server: error reading preface from client [address]: read tcp [address]->[address]: read: connection reset by peer"},
		{"an address without a port", false, "http: TLS handshake error from 192.0.2.7:51234: lookup example.com on 2001:db8::53: no such host\n",
			"http: TLS handshake error from [address]: lookup example.com on [address]: no such host"},
		{"an IPv6 address that ends in a colon", false, "httputil: ReverseProxy read error during body copy: dial 2001:db8:: refused\n",
			"httputil: ReverseProxy read error during body copy: dial [address] refused"},
		{"an IPv6 address that ends a clause", false, "lookup example.com on 2001:db8::: no such host\n", "lookup example.com on [address]: no such host"},
		{"a line with no address", false, "http: superfluous response.WriteHeader call from main.handler (main.go:12)\n", "http: superfluous response.WriteHeader call from main.handler (main.go:12)"},
		{"details keep it", true, "http: TLS handshake error from 127.0.0.1:61492: read tcp 127.0.0.1:61491->127.0.0.1:61492: i/o timeout\n",
			"http: TLS handshake error from 127.0.0.1:61492: read tcp 127.0.0.1:61491->127.0.0.1:61492: i/o timeout"},
		{"details keep what the client sent", true, "http2: server: error reading preface from client 192.0.2.7:51234: bogus greeting \"PRI\"\n",
			"http2: server: error reading preface from client 192.0.2.7:51234: bogus greeting \"PRI\""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			now := time.Unix(1000, 0)
			s := at(&out, tt.details, func() time.Time { return now })
			write(t, s, tt.line)
			write(t, s, tt.line) // the same second: counted, not logged
			now = now.Add(time.Second)
			write(t, s, tt.line)
			got := logged(t, &out)
			if len(got) != 2 || got[0].Error != tt.want || got[1].Error != tt.want || got[0].Kind != "connection" {
				t.Fatalf("logged %+v, want twice %q", got, tt.want)
			}
			if got[0].Dropped != 0 || got[1].Dropped != 1 {
				t.Fatalf("the line dropped in the first second was not counted: %+v", got)
			}
		})
	}
	t.Run("each kind of line has its own second", func(t *testing.T) {
		// A flood of handshake errors must not hide a handler's panic or a failing accept, even one that names them.
		var out bytes.Buffer
		s := at(&out, false, func() time.Time { return time.Unix(1000, 0) })
		const handshake = "http: TLS handshake error from 192.0.2.7:51234: EOF\n"
		const named = "http: TLS handshake error from 192.0.2.7:51234: tls: client requested unsupported application protocols ([\"panic serving\"])\n"
		for _, line := range []string{handshake, named, "http: panic serving 192.0.2.7:51234: boom\ngoroutine 7 [running]:\n",
			"http: Accept error: accept tcp [::]:443: accept4: too many open files; retrying in 5ms\n", named, handshake} {
			write(t, s, line)
		}
		s.flush() // as the server stops: what was counted is reported
		got := logged(t, &out)
		want := []entry{
			{"server error", "connection", "http: TLS handshake error from [address]: EOF", 0, 0},
			{"server error", "panic", "http: panic serving [address]: boom\ngoroutine 7 [running]:", 0, 0},
			{"server error", "accept", "http: Accept error: accept tcp [address]: accept4: too many open files; retrying in 5ms", 0, 0},
			{"server errors not logged", "connection", "", 3, 0},
		}
		if !slices.Equal(got, want) {
			t.Fatalf("logged %+v\nwant   %+v", got, want)
		}
	})
	t.Run("a long line is cut after its addresses are hidden", func(t *testing.T) {
		for _, tt := range []struct {
			line, start string
			limit       int
		}{
			// The cut falls inside a two-byte character, so it must move back to where the character starts.
			{"http: TLS handshake error from 192.0.2.7:51234: x" + strings.Repeat("é", 2000) + "\n", "http: TLS handshake error from [address]: xé", maxErrorLine - 1},
			{"http: panic serving 192.0.2.7:51234: boom\n" + strings.Repeat("main.handler(...)\n", 2000), "http: panic serving [address]: boom\nmain.handler", maxPanicLine},
		} {
			var out bytes.Buffer
			write(t, at(&out, false, time.Now), tt.line)
			got := logged(t, &out)
			if len(got) != 1 || len(got[0].Error) != tt.limit || !strings.HasPrefix(got[0].Error, tt.start) || !utf8.ValidString(got[0].Error) ||
				strings.ContainsRune(got[0].Error, utf8.RuneError) || got[0].CutBytes == 0 {
				t.Fatalf("logged %d bytes (cut %d), want %d starting %q", len(got[0].Error), got[0].CutBytes, tt.limit, tt.start)
			}
		}
	})
}

// TestBothServersLogTheirOwnErrorsAsJSON: what net/http says about the visitor and health servers (here an accept that
// failed for a while, as when descriptors run out) reaches the JSON log, not standard error.
func TestBothServersLogTheirOwnErrorsAsJSON(t *testing.T) {
	for _, failing := range []string{"visitor", "health"} {
		t.Run(failing, func(t *testing.T) {
			var out syncBuffer
			listen := func() net.Listener {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				return ln
			}
			visitor, health := listen(), listen()
			flaky := &failingListener{fails: 2, retried: make(chan struct{})}
			if failing == "visitor" {
				flaky.Listener, visitor = visitor, flaky
			} else {
				flaky.Listener, health = health, flaky
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
			done := make(chan error, 1)
			go func() {
				done <- serveRuntime(ctx, server, visitor, health, &runtimeHealth{}, lifecycleOptions{shutdown: time.Second},
					slog.New(slog.NewJSONHandler(&out, nil)))
			}()
			select {
			case <-flaky.retried: // net/http logs the failure before it tries again
			case <-time.After(10 * time.Second):
				t.Fatal("the server never tried again")
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			// Each failure is in the log: as a line of its own, or counted by a later line or when the server stopped (the
			// second comes 5ms after the first, so it is nearly always held back to be reported then).
			logged, accounted := 0, 0
			for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
				var e struct {
					Msg, Server, Kind, Error string
					Dropped                  int
				}
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					t.Fatalf("not JSON (%v): %s", err, line)
				}
				switch {
				case e.Server != failing || e.Kind != "accept":
				case e.Msg == "server error" && strings.HasPrefix(e.Error, "http: Accept error: accept failed for a while; retrying"):
					logged++
					accounted += 1 + e.Dropped
				case e.Msg == "server errors not logged":
					accounted += e.Dropped
				}
			}
			if logged == 0 || accounted != flaky.fails {
				t.Fatalf("the %s server's %d failures: %d logged, %d accounted for:\n%s", failing, flaky.fails, logged, accounted, out.String())
			}
		})
	}
}

// failingListener fails its first Accepts with an error net/http logs and retries, and says when it is asked again.
type failingListener struct {
	net.Listener
	fails   int
	calls   atomic.Int32
	retried chan struct{}
}

func (l *failingListener) Accept() (net.Conn, error) {
	switch n := int(l.calls.Add(1)); {
	case n <= l.fails:
		return nil, temporaryAcceptError{}
	case n == l.fails+1:
		close(l.retried)
	}
	return l.Listener.Accept()
}

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "accept failed for a while" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

// syncBuffer is a bytes.Buffer two servers can write at once.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The flood protection's settings are those of the strength -ddos names, with the -ddos-* flags given on the command line
// or in the site configuration put over them, the command line's first; a value a flag cannot take is refused with the
// flag's name and range. (Not rows of the table above: those start the program and see one request through, which cannot
// show a limit that takes minutes of traffic to move.)
func TestFloodFlagsBecomeShieldSettings(t *testing.T) {
	preset := func(name string, change func(*shield.Config)) shield.Config {
		c, err := shield.Preset(name)
		if err != nil {
			t.Fatal(err)
		}
		if change != nil {
			change(&c)
		}
		return c
	}
	// What the flags gave before there were strengths, with no flag set.
	today := func(change func(*shield.Config)) shield.Config {
		c := shield.Config{RequestRate: 50, RequestBurst: 200, SubnetRate: 500, MaxConns: 20000, KnownFactor: 2, MinKnownRate: 50,
			Detector: shield.DetectorConfig{MaxScale: 20}}
		if change != nil {
			change(&c)
		}
		return c
	}
	monitor := func(c *shield.Config) { c.MonitorOnly = true }
	rangeErr := func(flag, from, to, unit, zero string) string {
		msg := "-" + flag + " must be a number from " + from + " to " + to + unit
		if zero != "" {
			msg += " (0 = " + zero + ")"
		}
		return msg
	}
	rateErr := rangeErr("ddos-rate", "0.01", "1000000", " requests a second", "the strength's value")
	burstErr := rangeErr("ddos-burst", "1", "10000000", " requests", "the strength's value")
	connsErr := rangeErr("ddos-max-conns", "16", "10000000", " connections", "the strength's value")
	knownFactorErr := rangeErr("ddos-known-factor", "0.01", "1000", "", "the strength's value")
	knownRateErr := rangeErr("ddos-known-rate", "0.01", "1000000", " requests a second", "the strength's value")
	baselineErr := rangeErr("ddos-baseline-rate", "0.01", "10000000", " requests a second", "learn it")
	raiseErr := rangeErr("ddos-max-raise", "1", "100", "", "")
	for _, tt := range []struct {
		name string
		args []string
		site string // the flags of a site configuration, if any
		want shield.Config
		err  string // the whole error, if the flags are refused
	}{
		{name: "the default is today's", want: today(nil)},
		{name: "on is normal", args: []string{"-ddos", "on"}, want: today(nil)},
		{name: "normal", args: []string{"-ddos", "normal"}, want: today(nil)},
		{name: "monitor alone is normal", args: []string{"-ddos", "monitor"}, want: today(monitor)},
		{name: "today's defaults given as flags", args: []string{"-ddos-rate", "50", "-ddos-burst", "200", "-ddos-max-conns", "20000",
			"-ddos-known-factor", "2", "-ddos-known-rate", "50", "-ddos-max-raise", "20", "-ddos-challenge=true"}, want: today(nil)},
		{name: "strict", args: []string{"-ddos", "strict"}, want: preset("strict", nil)},
		{name: "relaxed", args: []string{"-ddos", "relaxed"}, want: preset("relaxed", nil)},
		{name: "monitor with a strength", args: []string{"-ddos", "monitor,strict"}, want: preset("strict", monitor)},
		{name: "a strength before its mode", args: []string{"-ddos", " strict , monitor "}, want: preset("strict", monitor)},
		{name: "a rate over the strength's", args: []string{"-ddos", "strict", "-ddos-rate", "60"},
			want: preset("strict", func(c *shield.Config) { c.RequestRate, c.SubnetRate = 60, 600 })},
		{name: "a site's rate over the strength's", site: `{"ddos":"strict","ddos-rate":60}`,
			want: preset("strict", func(c *shield.Config) { c.RequestRate, c.SubnetRate = 60, 600 })},
		{name: "the command line's rate over the site's", args: []string{"-ddos-rate", "30"}, site: `{"ddos":"strict","ddos-rate":60}`,
			want: preset("strict", func(c *shield.Config) { c.RequestRate, c.SubnetRate = 30, 500 })},
		{name: "the command line's -ddos replaces the site's", args: []string{"-ddos", "monitor"}, site: `{"ddos":"strict"}`, want: today(monitor)},
		{name: "zero is the strength's value", args: []string{"-ddos", "strict", "-ddos-rate", "0", "-ddos-burst", "0", "-ddos-max-conns", "0",
			"-ddos-known-factor", "0", "-ddos-known-rate", "0", "-ddos-baseline-rate", "0"}, want: preset("strict", nil)},
		{name: "a rate given alone brings its burst", args: []string{"-ddos-rate", "5000"},
			want: today(func(c *shield.Config) {
				c.RequestRate, c.SubnetRate, c.RequestBurst, c.SubnetBurst = 5000, 50000, 500, 5000
			})},
		{name: "a burst raises its network's", args: []string{"-ddos-burst", "5000"},
			want: today(func(c *shield.Config) { c.RequestBurst, c.SubnetBurst = 5000, 50000 })},
		{name: "a burst below its network's leaves it", args: []string{"-ddos-burst", "100"},
			want: today(func(c *shield.Config) { c.RequestBurst = 100 })},
		{name: "connections above the ceiling raise it", args: []string{"-ddos-max-conns", "300000"},
			want: today(func(c *shield.Config) { c.MaxConns, c.MaxConnsCeiling = 300000, 300000 })},
		{name: "the fewest connections", args: []string{"-ddos-max-conns", "16"}, want: today(func(c *shield.Config) { c.MaxConns = 16 })},
		{name: "known visitors' budget", args: []string{"-ddos-known-factor", "4", "-ddos-known-rate", "100"},
			want: today(func(c *shield.Config) { c.KnownFactor, c.MinKnownRate = 4, 100 })},
		{name: "fixed limits", args: []string{"-ddos-max-raise", "1"}, want: today(func(c *shield.Config) { c.Detector.MaxScale = 1 })},
		{name: "the highest raise", args: []string{"-ddos-max-raise", "100"}, want: today(func(c *shield.Config) { c.Detector.MaxScale = 100 })},
		{name: "a raise between whole numbers", args: []string{"-ddos-max-raise", "2.5"}, want: today(func(c *shield.Config) { c.Detector.MaxScale = 2.5 })},
		{name: "a raise over the strength's", args: []string{"-ddos", "strict", "-ddos-max-raise", "30"},
			want: preset("strict", func(c *shield.Config) { c.Detector.MaxScale = 30 })},
		{name: "no challenge", args: []string{"-ddos-challenge=false"}, want: today(func(c *shield.Config) { c.NoChallenge = true })},
		{name: "a baseline", args: []string{"-ddos-baseline-rate", "120"}, want: today(func(c *shield.Config) { c.Detector.InitialRate = 120 })},

		{name: "a misspelt strength", args: []string{"-ddos", "stict"},
			err: `-ddos: "stict" is not one of on, monitor, off, relaxed, normal, strict (did you mean strict?)`},
		{name: "a misspelt strength in the site's", site: `{"ddos":"stict"}`,
			err: `-ddos: "stict" is not one of on, monitor, off, relaxed, normal, strict (did you mean strict?)`},
		{name: "a strength in capitals", args: []string{"-ddos", "MONITOR,STRICT"},
			err: `-ddos: "MONITOR" is not one of on, monitor, off, relaxed, normal, strict (did you mean monitor?)`},
		{name: "a word that is near none", args: []string{"-ddos", "loud"}, err: `-ddos: "loud" is not one of on, monitor, off, relaxed, normal, strict`},
		{name: "two modes", args: []string{"-ddos", "on,monitor"}, err: `-ddos: "on,monitor" names two modes`},
		{name: "two strengths", args: []string{"-ddos", "strict,relaxed"}, err: `-ddos: "strict,relaxed" names two strengths`},
		{name: "a strength with off", args: []string{"-ddos", "off,strict"}, err: "-ddos off,strict: a strength needs -ddos on or monitor"},
		{name: "no value", args: []string{"-ddos", ""},
			err: "-ddos needs on, monitor or off, a strength relaxed, normal or strict, or one of each, as in -ddos monitor,strict"},
		{name: "a word twice", args: []string{"-ddos", "strict,strict"}, err: `-ddos: "strict,strict" names strict twice`},
		{name: "an empty word", args: []string{"-ddos", "on,"}, err: `-ddos: "on," has an empty part`},
		{name: "a negative rate", args: []string{"-ddos-rate", "-1"}, err: rateErr},
		{name: "a rate below the least", args: []string{"-ddos-rate", "0.001"}, err: rateErr},
		{name: "a rate above the most", args: []string{"-ddos-rate", "1e308"}, err: rateErr},
		{name: "a rate that is not a number", args: []string{"-ddos-rate", "NaN"}, err: rateErr},
		{name: "a site's rate that is negative", site: `{"ddos-rate":-1}`, err: rateErr},
		{name: "a burst below one", args: []string{"-ddos-burst", "0.5"}, err: burstErr},
		{name: "a burst above the most", args: []string{"-ddos-burst", "10000001"}, err: burstErr},
		{name: "a burst under a tenth of the rate", args: []string{"-ddos-rate", "5000", "-ddos-burst", "200"},
			err: "-ddos-burst (200) must be at least a tenth of -ddos-rate (5000): use -ddos-burst 500 or more"},
		{name: "a burst under a tenth of the strength's rate", args: []string{"-ddos", "relaxed", "-ddos-burst", "5"},
			err: "-ddos-burst (5) must be at least a tenth of the request rate of -ddos relaxed (100): use -ddos-burst 10 or more"},
		{name: "too few connections", args: []string{"-ddos-max-conns", "10"}, err: connsErr},
		{name: "too many connections", args: []string{"-ddos-max-conns", "10000001"}, err: connsErr},
		{name: "negative connections", args: []string{"-ddos-max-conns", "-1"}, err: connsErr},
		{name: "a negative known factor", args: []string{"-ddos-known-factor", "-1"}, err: knownFactorErr},
		{name: "a known factor above the most", args: []string{"-ddos-known-factor", "1000.5"}, err: knownFactorErr},
		{name: "a negative known rate", args: []string{"-ddos-known-rate", "-3"}, err: knownRateErr},
		{name: "a known rate above the most", args: []string{"-ddos-known-rate", "1000001"}, err: knownRateErr},
		{name: "a negative baseline", args: []string{"-ddos-baseline-rate", "-5"}, err: baselineErr},
		{name: "a baseline above the most", args: []string{"-ddos-baseline-rate", "1e308"}, err: baselineErr},
		{name: "a baseline that is not a number", args: []string{"-ddos-baseline-rate", "NaN"}, err: baselineErr},
		{name: "a raise below one", args: []string{"-ddos-max-raise", "0.99"}, err: raiseErr},
		{name: "a raise of zero, which would be none", args: []string{"-ddos-max-raise", "0"}, err: raiseErr},
		{name: "a negative raise", args: []string{"-ddos-max-raise", "-3"}, err: raiseErr},
		{name: "a raise above the highest", args: []string{"-ddos-max-raise", "100.5"}, err: raiseErr},
		{name: "a raise that is not a number", args: []string{"-ddos-max-raise", "NaN"}, err: raiseErr},
		{name: "an infinite raise", args: []string{"-ddos-max-raise", "+Inf"}, err: raiseErr},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("carnical", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			f := declareShieldFlags(fs)
			if err := fs.Parse(tt.args); err != nil {
				t.Fatal(err)
			}
			if tt.site != "" {
				path := filepath.Join(t.TempDir(), "site.json")
				if err := os.WriteFile(path, []byte(`{"version":1,"flags":`+tt.site+`}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if _, _, err := loadSiteConfig(path, fs); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := shieldSettings(*f, setFlags(fs), nil)
			if tt.err != "" {
				if err == nil || err.Error() != tt.err {
					t.Fatalf("got error %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, want := withDefaults(cfg), withDefaults(tt.want); !reflect.DeepEqual(got, want) {
				t.Fatalf("settings\n%+v\nwant\n%+v", got, want)
			}
			s, err := shield.New(cfg)
			if err != nil {
				t.Fatalf("the shield refuses these settings: %v", err)
			}
			s.Close()
		})
	}
}

// withDefaults is c with each zero number replaced by the default it stands for, so that two configurations the shield
// takes for the same compare equal.
func withDefaults(c shield.Config) shield.Config {
	var fill func(v, def reflect.Value)
	fill = func(v, def reflect.Value) {
		for i := range v.NumField() {
			switch field := v.Field(i); field.Kind() {
			case reflect.Struct:
				fill(field, def.Field(i))
			case reflect.Float64, reflect.Int, reflect.Int64:
				if field.CanSet() && field.IsZero() {
					field.Set(def.Field(i))
				}
			}
		}
	}
	fill(reflect.ValueOf(&c).Elem(), reflect.ValueOf(shield.DefaultConfig()))
	return c
}

// quietPort finds a port on a loopback address that is free now and that the system gives to nobody who asks for "any
// port": it lies below the range such ports are drawn from on Linux, Windows and macOS. A port found free by asking
// for any port can go to another test's server, or to a connection another test opens, the moment it is let go, and
// the proxy under test then fails to take it or is not what answers there.
func quietPort(t *testing.T, network, host string) string {
	t.Helper()
	for range 200 {
		port := fmt.Sprint(20000 + rand.Intn(12000))
		ln, err := net.Listen(network, net.JoinHostPort(host, port))
		if err != nil {
			continue
		}
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		return port
	}
	t.Fatal("found no free port below the range the system gives out")
	return ""
}

// listeningAddress waits for a proxy that was started on port 0 to say in its log which address it took.
func listeningAddress(ctx context.Context, t *testing.T, logPath string) string {
	t.Helper()
	for {
		data, _ := os.ReadFile(logPath)
		if _, rest, ok := bytes.Cut(data, []byte(`"msg":"listening","addr":"`)); ok {
			if addr, _, ok := bytes.Cut(rest, []byte(`"`)); ok {
				return string(addr)
			}
		}
		if ctx.Err() != nil {
			t.Fatalf("the firewall did not start listening\n%s", data)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// keyMode gives a key file a mode on every system. Windows has none, and a file there takes its access list from its
// directory, which on some machines lets other accounts write; so the list is replaced by one that says the same as
// the mode: this account and SYSTEM, Everyone for "others", and the network service account, which is neither this
// account nor an administrator, for "the group".
func keyMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return
	}
	args := []string{"/inheritance:r", "/grant:r", me(t) + ":(F)", "*S-1-5-18:(F)"}
	for _, grant := range []struct {
		bit   os.FileMode
		entry string
	}{{0o004, "*S-1-1-0:(R)"}, {0o040, "*S-1-5-20:(R)"}, {0o020, "*S-1-5-20:(W)"}} {
		if mode&grant.bit != 0 {
			args = append(args, grant.entry)
		}
	}
	icacls(t, path, args...)
}

// icacls changes a file's access list on Windows.
func icacls(t *testing.T, path string, args ...string) {
	t.Helper()
	if out, err := exec.Command("icacls", append([]string{path}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("icacls %v: %v %s", args, err, out)
	}
}

// setSDDL replaces a file's access list on Windows with one written as SDDL, for the lists icacls cannot make.
func setSDDL(t *testing.T, path, sddl string) {
	t.Helper()
	script := "$a = New-Object System.Security.AccessControl.FileSecurity; $a.SetSecurityDescriptorSddlForm($env:KEYSDDL, 'Access'); [System.IO.File]::SetAccessControl($env:KEYFILE, $a)"
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "KEYFILE="+path, "KEYSDDL="+sddl)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("setting the access list %s: %v %s", sddl, err, out)
	}
}

// me is the account the tests run as, as icacls takes it.
func me(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("whoami").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// A function of its own: no other test reads the lines the shield's events are logged as. Each kind has its own
// message and level, and the IDS fields are written.
func TestShieldEventsAreLoggedByKind(t *testing.T) {
	offence := func(kind string) shield.Event {
		return shield.Event{Kind: kind, Mode: "on", Source: netip.MustParsePrefix("203.0.113.7/32"), Client: netip.MustParseAddr("203.0.113.7"),
			Points: 12, Sigs: []string{"crs-949110"}, TTL: 20 * time.Minute, Level: 2}
	}
	tests := []struct {
		name    string
		ev      shield.Event
		monitor bool
		source  alert.SourceMode
		says    []string
		not     []string
	}{
		{name: "an IDS signal names its codes and mode", ev: shield.Event{Kind: "ids_signal", Mode: "monitor", Codes: []string{"held"}},
			says: []string{`"level":"WARN"`, `"msg":"network or HTTP intrusion signal detected"`, `"mode":"monitor"`, `"codes":["held"]`}},
		{name: "signals cleared", ev: shield.Event{Kind: "ids_clear", Mode: "on", Codes: []string{"held", "rejections"}},
			says: []string{`"level":"INFO"`, `"msg":"intrusion signals cleared"`, `"codes":["held","rejections"]`}},
		{name: "back to normal", ev: shield.Event{Kind: "normal", Mode: "on"},
			says: []string{`"level":"INFO"`, `"msg":"traffic is back to normal"`, `"mode":"on"`}, not: []string{`"codes"`}},
		{name: "an attack in monitor mode is not called mitigated", ev: shield.Event{Kind: "attack_start", Mode: "monitor"}, monitor: true,
			says: []string{`"level":"WARN"`, `"msg":"denial-of-service attack detected; monitor mode, not mitigated"`}, not: []string{"mitigation on"}},
		{name: "a kind this binary does not know is still a warning", ev: shield.Event{Kind: "later_kind"},
			says: []string{`"level":"WARN"`, `"msg":"flood protection event"`, `"kind":"later_kind"`}},
		{name: "a repeat offender's ban names the source once and its own level apart", ev: offence("source_blocked"),
			says: []string{`"level":"WARN"`, `"msg":"source blocked"`, `"src":"203.0.113.7"`, `"src_key":"203.0.113.7/32"`, `"ban_level":2`,
				`"sigs":["crs-949110"]`, `"ttl":"20m0s"`, "-auto-block-exempt"}, not: []string{`"level":2`}},
		{name: "a would-be ban in monitor mode", ev: offence("source_would_block"),
			says: []string{`"msg":"source would be blocked"`, `"points":12`}, not: []string{"exempt it"}},
		{name: "a ban shows only the network with -alert-source prefix", ev: offence("source_blocked"), source: alert.SourcePrefix,
			says: []string{`"src":"203.0.113.0/24"`}, not: []string{"203.0.113.7", "src_key"}},
		{name: "a ban shows no address with -alert-source off", ev: offence("source_blocked"), source: alert.SourceOff,
			says: []string{`"msg":"source blocked"`}, not: []string{"203.0.113", `"src`}},
		{name: "a ban that ended is information", ev: shield.Event{Kind: "source_block_ended", Mode: "on", Source: netip.MustParsePrefix("203.0.113.7/32")},
			says: []string{`"level":"INFO"`, `"msg":"source block ended"`}},
		{name: "a full ban table is a warning with its count", ev: shield.Event{Kind: "auto_block_full", Mode: "on", Count: 3},
			says: []string{`"level":"WARN"`, `"msg":"auto-block table full; sources not blocked"`, `"count":3`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			shieldEventLogger(slog.New(slog.NewJSONHandler(&buf, nil)), tt.monitor, tt.source)(tt.ev)
			line := buf.String()
			for _, want := range tt.says {
				if !strings.Contains(line, want) {
					t.Errorf("log %s lacks %s", line, want)
				}
			}
			for _, unwanted := range tt.not {
				if strings.Contains(line, unwanted) {
					t.Errorf("log %s has %s", line, unwanted)
				}
			}
		})
	}
}

// A Windows access list is read from its text form, and what is not understood is refused, on every system the tests
// run on (the reading is plain text; who an entry names is resolved on Windows only).
func TestWindowsAccessListsAreReadStrictly(t *testing.T) {
	for _, tt := range []struct {
		name string
		sddl string
		want []daclEntry
		err  error // nil: none
	}{
		{"two full entries", "D:P(A;;FA;;;SY)(A;;FA;;;BA)", []daclEntry{{"SY", 0x1f01ff}, {"BA", 0x1f01ff}}, nil},
		{"handed down, rights as a number", "D:PAI(A;ID;0x1200a9;;;BU)", []daclEntry{{"BU", 0x1200a9}}, nil},
		{"an account by its SID", "D:(A;;FR;;;S-1-5-21-1-2-3-1001)", []daclEntry{{"S-1-5-21-1-2-3-1001", 0x120089}}, nil},
		{"rights named one after another", "D:AI(A;;FRFW;;;AU)", []daclEntry{{"AU", 0x120089 | 0x120116}}, nil},
		{"single rights", "D:(A;;RCWDWO;;;NS)", []daclEntry{{"NS", 0x20000 | 0x40000 | 0x80000}}, nil},
		{"generic rights", "D:(A;;GAGR;;;WD)", []daclEntry{{"WD", 0x10000000 | 0x80000000}}, nil},
		{"a denial allows nothing", "D:(D;;FA;;;WD)(A;;FR;;;SY)", []daclEntry{{"SY", 0x120089}}, nil},
		{"an entry for children only", "D:(A;OICIIO;FA;;;WD)(A;OICI;FR;;;SY)", []daclEntry{{"SY", 0x120089}}, nil},
		{"an entry that allows nothing", "D:(A;;;;;WD)(A;;0x0;;;AU)", nil, nil},
		{"an empty list", "D:", nil, nil},
		{"an empty protected list", "D:PAI", nil, nil},
		{"no list at all", "D:NO_ACCESS_CONTROL", nil, errNoDACL},
		{"no list at all, with flags", "D:PNO_ACCESS_CONTROL", nil, errNoDACL},
		{"not an access list", "O:BAG:SY", nil, errDACLUnread},
		{"an audit list", "S:(AU;SA;FA;;;WD)", nil, errDACLUnread},
		{"an owner before the list", "O:BAD:(A;;FA;;;SY)", nil, errDACLUnread},
		{"unknown flags before the entries", "D:X(A;;FA;;;SY)", nil, errDACLUnread},
		{"an entry with a condition", "D:(XA;;FA;;;WD;(Title==1))", nil, errDACLUnread},
		{"an allow entry with a seventh field", "D:(A;;FA;;;WD;x)", nil, errDACLUnread},
		{"an entry for an object type", "D:(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)", nil, errDACLUnread},
		{"an allow entry that names an object type", "D:(A;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)", nil, errDACLUnread},
		{"an entry of an unknown kind", "D:(ZZ;;FA;;;WD)", nil, errDACLUnread},
		{"an unknown right", "D:(A;;FAZZ;;;WD)", nil, errDACLUnread},
		{"a registry right", "D:(A;;KA;;;WD)", nil, errDACLUnread},
		{"half a right", "D:(A;;FAF;;;WD)", nil, errDACLUnread},
		{"a number that is none", "D:(A;;0x;;;WD)", nil, errDACLUnread},
		{"a number too large", "D:(A;;0x100000000;;;WD)", nil, errDACLUnread},
		{"an unknown flag", "D:(A;ZZ;FA;;;WD)", nil, errDACLUnread},
		{"half a flag", "D:(A;I;FA;;;WD)", nil, errDACLUnread},
		{"no account", "D:(A;;FA;;;)", nil, errDACLUnread},
		{"too few fields", "D:(A;;FA;;WD)", nil, errDACLUnread},
		{"an entry that does not end", "D:(A;;FA;;;SY", nil, errDACLUnread},
		{"text between entries", "D:(A;;FA;;;SY)x(A;;FA;;;BA)", nil, errDACLUnread},
		{"an entry that does not begin", "D:(A;;FA;;;SY)xA;;FR;;;WD)", nil, errDACLUnread},
		{"text after the entries", "D:(A;;FA;;;SY)S:", nil, errDACLUnread},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDACL(tt.sddl)
			if !errors.Is(err, tt.err) || (tt.err == nil && err != nil) {
				t.Fatalf("error %v, want %v", err, tt.err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("entries %+v, want %+v", got, tt.want)
			}
		})
	}
}

// The rule for a private key's access list: nothing for a principal that stands for everyone, and no writing for an
// account that is neither trusted nor the owner. What an account is comes from the system (see accountKind on
// Windows); here it is given.
func TestWhoMayHaveAPrivateKey(t *testing.T) {
	who := func(account string) (principal, string, error) {
		switch account {
		case "ME", "SY", "OWNER":
			return principalTrusted, "", nil
		case "WD":
			return principalEveryone, "Everyone", nil
		case "BU":
			return principalEveryone, "Users", nil
		case "??":
			return principalOther, "", errors.New("no such account")
		}
		return principalOther, "", nil
	}
	const read, readRun, full = 0x120089, 0x1200a9, 0x1f01ff
	for _, tt := range []struct {
		name    string
		entries []daclEntry
		refused string // part of the reason; "" if the key is accepted
	}{
		{"nobody at all", nil, ""},
		{"this account and SYSTEM in full", []daclEntry{{"ME", full}, {"SY", full}}, ""},
		{"the owner in full", []daclEntry{{"OWNER", full}, {"ME", read}}, ""},
		{"another account may read", []daclEntry{{"ME", full}, {"NS", read}}, ""},
		{"another account may read and run", []daclEntry{{"ME", full}, {"NS", readRun}}, ""},
		{"another account may delete it", []daclEntry{{"ME", full}, {"NS", read | 0x10000}}, ""},
		{"Everyone may read", []daclEntry{{"ME", full}, {"WD", read}}, "accessible to Everyone"},
		{"Everyone may read its attributes", []daclEntry{{"ME", full}, {"WD", 0x80}}, "accessible to Everyone"},
		{"Users in full, after the trusted ones", []daclEntry{{"ME", full}, {"SY", full}, {"BU", full}}, "accessible to Users"},
		{"another account may write data", []daclEntry{{"ME", full}, {"NS", read | 0x2}}, "writable by NS"},
		{"another account may append", []daclEntry{{"NS", read | 0x4}}, "writable by NS"},
		{"another account may change the list", []daclEntry{{"NS", read | 0x40000}}, "writable by NS"},
		{"another account may take ownership", []daclEntry{{"NS", read | 0x80000}}, "writable by NS"},
		{"another account has every generic right", []daclEntry{{"NS", 0x10000000}}, "writable by NS"},
		{"another account may write, generically", []daclEntry{{"NS", 0x40000000}}, "writable by NS"},
		{"another account in full", []daclEntry{{"ME", full}, {"NS", full}}, "writable by NS"},
		{"an account that cannot be told", []daclEntry{{"ME", full}, {"??", read}}, "access list cannot be read"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := keyAccessProblem(tt.entries, who)
			if tt.refused == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.refused) {
				t.Fatalf("%v, want one about %q", err, tt.refused)
			}
		})
	}
}

// A site policy cannot raise the machine's body ceilings, including defaults.
func TestRecoveredPolicyBodyCeilings(t *testing.T) {
	for _, set := range []map[string]bool{{}, {"max-body": true, "max-form-body": true}} {
		flags := proxy.Config{CRS: crs.DefaultSettings(), MaxFormBody: 128 << 10}
		flags.CRS.RequestBodyLimit = 1 << 20
		for _, limits := range [][2]int64{{4 << 20, 4 << 20}, {1024, 2048}} {
			cfg := flags
			sp := &sitePolicy{compiled: policy.Compiled{CRS: crs.Settings{RequestBodyLimit: limits[0]}, MaxFormBody: limits[1]}}
			applyPolicy(&cfg, flags, set, sp)
			if cfg.CRS.RequestBodyLimit != min(flags.CRS.RequestBodyLimit, limits[0]) || cfg.MaxFormBody != min(flags.MaxFormBody, limits[1]) {
				t.Fatalf("raised ceilings: body=%d form=%d", cfg.CRS.RequestBodyLimit, cfg.MaxFormBody)
			}
		}
	}
}

func protectionFixture(t *testing.T, name, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func protectionPack(t *testing.T, sigs ...vpatch.Signature) string {
	t.Helper()
	var b bytes.Buffer
	if err := vpatch.WritePackJSON(&b, vpatch.Pack{Name: "test", Version: "1", Signatures: sigs}); err != nil {
		t.Fatal(err)
	}
	return protectionFixture(t, "pack.json", b.String())
}

func TestRecoveredProtectionConfiguration(t *testing.T) {
	sig := vpatch.Signature{ID: "TEST-PATH", Tier: vpatch.TierVerified, Category: "protocol", Severity: "high", Condition: vpatch.Condition{Operator: vpatch.OpContains, Pattern: "/protected", Targets: []string{vpatch.TargetPath}}}
	pack := protectionPack(t, sig)
	scoped := sig
	scoped.Scope = []string{"wordpress"}
	scopedPack := protectionPack(t, scoped)
	invalidRegex := sig
	invalidRegex.Operator = vpatch.OpRegex
	invalidRegex.Pattern = "["
	invalidPack := protectionPack(t, invalidRegex)
	expired := sig
	expired.Expires = "2000-01-01"
	expiredPack := protectionPack(t, expired)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		name    string
		args    []string
		policy  string
		bad     bool
		mode    string
		patches bool
	}{
		{name: "unchanged defaults", mode: "monitor"},
		{name: "policy enables format blocking", policy: `{"body_formats":{"monitor":false}}`, mode: "block"},
		{name: "explicit mode wins", args: []string{"-formats-mode", "monitor"}, policy: `{"body_formats":{"monitor":false}}`, mode: "monitor"},
		{name: "policy format off", args: []string{"-formats-mode", "off"}, policy: `{"body_formats":{"monitor":false}}`, mode: "off"},
		{name: "decoded request with formats off", args: []string{"-formats-mode", "off", "-allow-request-encoding"}, policy: `{"body_formats":{"monitor":false}}`, bad: true},
		{name: "invalid format action", args: []string{"-formats-mode", "x"}, policy: `{"body_formats":{}}`, bad: true},
		{name: "pack monitor", args: []string{"-vpatch-pack", pack}, mode: "monitor", patches: true},
		{name: "pack block", args: []string{"-vpatch-pack", pack, "-vpatch-mode", "block"}, mode: "monitor", patches: true},
		{name: "pack disabled", args: []string{"-vpatch-pack", "absent.json", "-vpatch-mode", "off"}, mode: "monitor"},
		{name: "bad pack", args: []string{"-vpatch-pack", protectionFixture(t, "bad.json", "{bad}")}, bad: true},
		{name: "empty pack", args: []string{"-vpatch-pack", protectionPack(t)}, bad: true},
		{name: "invalid compiled regex", args: []string{"-vpatch-pack", invalidPack}, bad: true},
		{name: "expired-only pack", args: []string{"-vpatch-pack", expiredPack}, bad: true},
		{name: "unmatched scope", args: []string{"-vpatch-pack", scopedPack}, bad: true},
		{name: "declared scope", args: []string{"-vpatch-pack", scopedPack}, policy: `{"vpatch":{"software":["wordpress"]}}`, mode: "monitor", patches: true},
		{name: "explicit scope", args: []string{"-vpatch-pack", scopedPack, "-vpatch-scope", "wordpress"}, mode: "monitor", patches: true},
		{name: "scope none", args: []string{"-vpatch-pack", scopedPack, "-vpatch-scope", "none"}, policy: `{"vpatch":{"software":["wordpress"]}}`, bad: true},
		{name: "explicit community tier excludes verified", args: []string{"-vpatch-pack", pack, "-vpatch-tiers", "community"}, bad: true},
		{name: "exclude all", args: []string{"-vpatch-pack", pack, "-vpatch-exclude", "TEST-"}, bad: true},
		{name: "invalid exclusion", args: []string{"-vpatch-pack", pack, "-vpatch-exclude", "*"}, bad: true},
		{name: "invalid mode", args: []string{"-vpatch-mode", "x"}, bad: true},
		{name: "invalid tier", args: []string{"-vpatch-tiers", "x"}, bad: true},
		{name: "invalid scope", args: []string{"-vpatch-scope", "bad tag"}, bad: true},
		{name: "mode requires pack", args: []string{"-vpatch-mode", "block"}, bad: true},
		{name: "policy requires pack", policy: `{"vpatch":{"software":["wordpress"]}}`, bad: true},
		{name: "invalid stats interval", args: []string{"-vpatch-stats-interval", "1ns"}, bad: true},
		{name: "api enabled", args: []string{"-api-guard", "enforce"}, mode: "monitor"},
		{name: "api from policy", policy: `{"api_mode":"monitor"}`, mode: "monitor"},
		{name: "api section", policy: `{"api":{"methods":["GET"]}}`, mode: "monitor"},
		{name: "api flag wins", args: []string{"-api-guard", "off"}, policy: `{"api_mode":"enforce"}`, mode: "monitor"},
		{name: "bad api mode", args: []string{"-api-guard", "x"}, bad: true},
		{name: "no auto learning", args: []string{"-api-guard", "learn"}, bad: true},
		{name: "no learned enforcement", policy: `{"api":{"modes":{"learned":"enforce"}}}`, bad: true},
		{name: "no discovered spec enforcement", policy: `{"api":{"modes":{"spec":"enforce"}}}`, bad: true},
		{name: "no discovery configuration", policy: `{"api":{"discovery":{"manualPromotion":true}}}`, bad: true},
		{name: "no learning configuration", policy: `{"api":{"learn":{"minObservations":10}}}`, bad: true},
		{name: "conflicting api actions", policy: `{"api_mode":"monitor","api":{"mode":"enforce"}}`, bad: true},
		{name: "duplicate policy field", policy: `{"mode":"off","mode":"block"}`, bad: true},
		{name: "unknown policy field", policy: `{"unknown":true}`, bad: true},
		{name: "trailing policy garbage", policy: `{}X`, bad: true},
		{name: "invalid API section", policy: `{"api":{"unknown":true}}`, bad: true},
		{name: "invalid format section", policy: `{"body_formats":{"unknown":true}}`, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("site", flag.ContinueOnError)
			f := declareSiteFlags(fs)
			fm := fs.String("formats-mode", "monitor", "")
			enc := fs.Bool("allow-request-encoding", false, "")
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			if tc.policy != "" {
				f.policy = protectionFixture(t, "policy.json", tc.policy)
			}
			cfg := proxy.Config{CRS: crs.DefaultSettings(), MaxFormBody: 128 << 10}
			_, mode, vp, err := configureSite(f, setFlags(fs), &cfg, log, *fm, "", *enc)
			if (err != nil) != tc.bad {
				t.Fatalf("error %v; want bad=%v", err, tc.bad)
			}
			if tc.bad {
				return
			}
			if mode != tc.mode || (vp != nil) != tc.patches {
				t.Fatalf("mode=%s patches=%v", mode, vp != nil)
			}
			for _, in := range cfg.Inspectors {
				if api, ok := in.(*apiguard.Guard); ok {
					ac := api.Config()
					if ac.Modes.Learned != apiguard.ModeOff || ac.Modes.Spec != apiguard.ModeOff || !ac.Discovery.ManualPromotion {
						t.Fatal("unreviewed API model enabled")
					}
				}
			}
		})
	}
}

func TestRecoveredProtectionFileBounds(t *testing.T) {
	path := protectionFixture(t, "input.json", "1234")
	for _, limit := range []int64{-1, 0, 3, 4, 5, maxPackFileBytes + 1, math.MaxInt64} {
		_, err := readProtectionFile(path, limit)
		bad := limit < 4 || limit > maxPackFileBytes
		if (err != nil) != bad {
			t.Fatalf("limit=%d error=%v", limit, err)
		}
	}
	if _, err := readProtectionFile(t.TempDir(), 10); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := readProtectionFile(filepath.Join(t.TempDir(), "missing"), 10); err == nil {
		t.Fatal("missing accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err == nil {
		if _, err := readProtectionFile(link, 10); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}

func testSiteProtectionCLI(t *testing.T, bin string) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer origin.Close()
	pathSig := vpatch.Signature{ID: "TEST-PATH", Tier: vpatch.TierVerified, Category: "protocol", Severity: "high", Condition: vpatch.Condition{Operator: vpatch.OpContains, Pattern: "/protected", Targets: []string{vpatch.TargetPath}}}
	bodySig := pathSig
	bodySig.ID = "TEST-BODY"
	bodySig.Pattern = "blocked-canary"
	bodySig.Targets = []string{vpatch.TargetBody}
	pack := protectionPack(t, pathSig, bodySig)
	for _, tc := range []struct {
		name                       string
		args                       []string
		method, target, body, host string
		want                       int
		encoding                   bool
	}{
		{name: "ordinary default", target: "/ordinary", want: 200},
		{name: "monitor reports", args: []string{"-vpatch-pack", pack}, target: "/protected", want: 200},
		{name: "pack blocks", args: []string{"-vpatch-pack", pack, "-vpatch-mode", "block"}, target: "/protected", want: 403},
		{name: "pack allows ordinary", args: []string{"-vpatch-pack", pack, "-vpatch-mode", "block"}, target: "/ordinary", want: 200},
		{name: "gzip is decoded before patches", args: []string{"-vpatch-pack", pack, "-vpatch-mode", "block", "-formats-mode", "block", "-allow-request-encoding"}, method: "POST", target: "/ordinary", body: "blocked-canary", want: 403, encoding: true},
		{name: "policy host denied", args: []string{"-policy", protectionFixture(t, "site.json", `{"allowed_hosts":["shop.example"]}`)}, host: "other.example", target: "/ordinary", want: 421},
		{name: "flag host wins", args: []string{"-policy", protectionFixture(t, "site.json", `{"allowed_hosts":["shop.example"]}`), "-hosts", "other.example"}, host: "other.example", target: "/ordinary", want: 200},
		{name: "policy header denied", args: []string{"-policy", protectionFixture(t, "site.json", `{"deny_headers":["x-test-header"]}`), "-deny-headers", "x-other"}, target: "/ordinary", want: 400},
		{name: "default form ceiling holds", args: []string{"-formats-mode", "off", "-policy", protectionFixture(t, "site.json", `{"body":{"max_form_bytes":262144}}`)}, method: "POST", target: "/ordinary", body: "x=" + strings.Repeat("a", 129<<10), want: 413},
		{name: "default upload ceiling holds", args: []string{"-formats-mode", "off", "-policy", protectionFixture(t, "site.json", `{"body":{"max_upload_bytes":4194304}}`)}, method: "POST", target: "/ordinary", body: "x=" + strings.Repeat("a", (1<<20)+1), want: 413},
		{name: "api method blocks", args: []string{"-api-guard", "enforce"}, method: "PROPFIND", target: "/api/items", want: 405},
		{name: "api monitor allows", args: []string{"-api-guard", "monitor"}, method: "PROPFIND", target: "/api/items", want: 200},
		{name: "format policy blocks ambiguity", args: []string{"-policy", protectionFixture(t, "site.json", `{"body_formats":{"monitor":false}}`)}, method: "POST", target: "/ordinary", body: `{"x":1,"x":2}`, want: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			args := append([]string{"-listen", "127.0.0.1:0", "-upstream", origin.URL, "-origin-allow", "127.0.0.1/32", "-mode", "off", "-ddos", "off", "-formats-stats-interval", "0", "-vpatch-stats-interval", "0"}, tc.args...)
			logPath := filepath.Join(t.TempDir(), "proxy.log")
			logs, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			defer logs.Close()
			startupCalls := calls.Load()
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Stdout = logs
			cmd.Stderr = logs
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = cmd.Wait() }()
			address := listeningAddress(ctx, t, logPath)
			before := calls.Load()
			if before != startupCalls {
				t.Fatal("startup sent unexpected origin traffic")
			}
			body := []byte(tc.body)
			if tc.encoding {
				var b bytes.Buffer
				gz := gzip.NewWriter(&b)
				_, _ = gz.Write(body)
				if err := gz.Close(); err != nil {
					t.Fatal(err)
				}
				body = b.Bytes()
			}
			method := tc.method
			if method == "" {
				method = "GET"
			}
			req, err := http.NewRequestWithContext(ctx, method, "http://"+address+tc.target, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Host = tc.host
			if req.Host == "" {
				req.Host = "shop.example"
			}
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
				if strings.HasPrefix(tc.body, "x=") {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
			}
			if tc.encoding {
				req.Header.Set("Content-Encoding", "gzip")
				req.Header.Set("Content-Type", "text/plain")
			}
			if tc.name == "policy header denied" {
				req.Header.Set("X-Test-Header", "1")
			}
			transport := &http.Transport{}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				data, _ := os.ReadFile(logPath)
				t.Fatalf("status=%d want=%d logs=%s", resp.StatusCode, tc.want, data)
			}
			after := calls.Load()
			if tc.want == 200 && after != before+1 || tc.want != 200 && after != before {
				t.Fatalf("origin calls before=%d after=%d status=%d", before, after, tc.want)
			}
			if tc.name == "monitor reports" || tc.name == "pack blocks" {
				// Rule matches are written through a queue: wait for the line.
				var data []byte
				for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
					if data, _ = os.ReadFile(logPath); bytes.Contains(data, []byte("TEST-PATH")) {
						break
					}
				}
				if !bytes.Contains(data, []byte("TEST-PATH")) || bytes.Contains(data, []byte("blocked-canary")) {
					t.Fatalf("missing safe match log: %s", data)
				}
			}
		})
	}
}

func TestRecoveredSummaryShutdown(t *testing.T) {
	var out bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&out, nil))
	var n atomic.Uint64
	stop := startSnapshotLog(log, "totals", time.Hour, n.Load, func(v uint64) []any { return []any{"requests", v} })
	n.Store(7)
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(stop)
	}
	wg.Wait()
	if strings.Count(out.String(), `"requests":7`) != 1 {
		t.Fatalf("final totals: %s", out.String())
	}
	quiet := startSnapshotLog(log, "quiet", 0, n.Load, func(v uint64) []any { return nil })
	quiet()
}

func FuzzRecoveredSiteFlagLists(f *testing.F) {
	for _, s := range []string{"", "auto", "none", "wordpress,php", " verified , community ", "bad tag", strings.Repeat("x", 100)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		_, _, _ = parseVPatchMode(s)
		_, _, _ = parseVPatchScope(s)
		_, _ = parseVPatchTiers("tiers", splitList(s))
		_ = softwareTags(splitList(s))
		_ = unionTags(splitList(s))
		_ = clipText(s, 40)
	})
}

func TestRecoveredZeroFormCeiling(t *testing.T) {
	flags := proxy.Config{CRS: crs.DefaultSettings()}
	cfg := flags
	sp := &sitePolicy{compiled: policy.Compiled{CRS: crs.DefaultSettings(), MaxFormBody: 1024}}
	applyPolicy(&cfg, flags, map[string]bool{"max-form-body": true}, sp)
	if cfg.MaxFormBody != 1024 {
		t.Fatalf("zero flag undid policy limit: %d", cfg.MaxFormBody)
	}
}

func TestRecoveredSelectionBounds(t *testing.T) {
	tags := make([]string, 129)
	for i := range tags {
		tags[i] = fmt.Sprintf("tag%d", i)
	}
	if _, _, err := parseVPatchScope(strings.Join(tags[:128], ",")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseVPatchScope(strings.Join(tags, ",")); err == nil {
		t.Fatal("unbounded scope list accepted")
	}
	if _, _, err := parseVPatchScope(strings.Repeat(" ", 16385) + "auto"); err == nil {
		t.Fatal("oversized scope accepted")
	}
	if _, err := parseVPatchTiers("tiers", strings.Split(strings.Repeat("verified,", 16)+"verified", ",")); err == nil {
		t.Fatal("unbounded tier list accepted")
	}
}

func TestRecoveredPolicyKeepsOperatorSettings(t *testing.T) {
	flags := proxy.Config{CRS: crs.DefaultSettings(), MaxFormBody: 4096, AllowedHosts: []string{"flag.example"}, Paths: proxy.PathPolicy{AllowEncodedSlash: true, AllowPathParams: true}, DenyHeaders: []string{"X_Flag"}, WordPress: proxy.WordPressPolicy{Enabled: true, AllowXMLRPC: true, LoginPerMinute: 7}, Uploads: proxy.UploadPolicy{AllowExecutableNames: true, AllowScriptContent: true}, Responses: proxy.ResponsePolicy{KeepBanners: true, KeepCaching: true}, MaxUpstreamInFlight: 3, MaxConnsPerIP: 5, NoJoinedParams: true}
	flags.CRS.Mode = crs.ModeOff
	flags.CRS.ParanoiaLevel = 2
	flags.CRS.DetectionParanoiaLevel = 3
	flags.CRS.InboundThreshold = 8
	flags.CRS.OutboundThreshold = 9
	flags.CRS.InspectResponses = true
	flags.CRS.AllowedMethods = []string{"GET"}
	flags.CRS.AllowedContentTypes = []string{"application/x-flag"}
	flags.CRS.AllowedExtensions = []string{".sh"}
	flags.CRS.UploadDir = "private-uploads"
	flags.CRS.LocalRulesOff = []int{5006001}
	set := map[string]bool{}
	for _, name := range strings.Fields("hosts allow-encoded-slash allow-path-params deny-headers wordpress allow-xmlrpc login-per-minute allow-script-names allow-script-content keep-banners keep-caching max-form-body max-body mode paranoia detection-paranoia inbound-threshold outbound-threshold inspect-responses allowed-methods allowed-content-types allowed-extensions") {
		set[name] = true
	}
	sp := &sitePolicy{compiled: policy.Compiled{CRS: crs.DefaultSettings(), MaxFormBody: 8192, DenyHeaders: []string{"x-policy"}}}
	cfg := flags
	applyPolicy(&cfg, flags, set, sp)
	expected := flags
	expected.DenyHeaders = []string{"x-policy", "x-flag"}
	slices.Sort(expected.DenyHeaders)
	if !reflect.DeepEqual(cfg, expected) {
		t.Fatalf("operator settings changed: got=%+v want=%+v", cfg, expected)
	}
}

func TestRecoveredProtectionDiagnostics(t *testing.T) {
	if _, err := loadPolicy(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing policy accepted")
	}
	if _, err := readPackFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing pack accepted")
	}
	var buffer bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buffer, nil))
	logVPatchLoad(log, "test", "1", "hash", vpatch.ModeMonitor, nil, nil, nil, vpatch.LoadReport{Rejected: []vpatch.Rejection{{ID: "X", Reason: "invalid"}}, Warnings: []string{"warning"}})
	if !strings.Contains(buffer.String(), "warning") {
		t.Fatal("warning not reported")
	}
	if clipText("abcdef\n", 3) != "abc..." || clipText("a\nb", 10) != "a b" {
		t.Fatal("log clipping failed")
	}
	if len(vpatchStatsAttrs(vpatch.Stats{})) != 12 {
		t.Fatal("summary shape changed")
	}
	if _, err := parseVPatchTiers("tiers", nil); err == nil {
		t.Fatal("empty tiers accepted")
	}
	for _, s := range []string{"{bad}", "null"} {
		if len(namedFields([]byte(s))) != 0 {
			t.Fatal("malformed policy fields")
		}
	}
}

// The short commands only choose flags: what each turns into, and what it refuses before anything runs.
func TestShortCommands(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", filepath.Join(dir, "appdata"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))
	saved, err := defaultSitePath()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		args    []string
		haveDef bool // a site is saved in the default place
		want    []string
		says    string // the error, if refused
	}{
		{"start uses the saved site", []string{"start"}, true, []string{"-config", saved}, ""},
		{"check also checks the origin", []string{"check"}, true, []string{"-config", saved, "-check", "-check-origin"}, ""},
		{"flags after the command are kept", []string{"start", "-mode", "block"}, true, []string{"-config", saved, "-mode", "block"}, ""},
		{"a named file", []string{"start", "site.json", "-config-key-file", "k"}, false, []string{"-config", "site.json", "-config-key-file", "k"}, ""},
		{"-config instead of a file", []string{"check", "--config=site.json"}, false, []string{"-check", "-check-origin", "--config=site.json"}, ""},
		{"no saved site", []string{"start"}, false, nil, "run carnical setup first"},
		{"the file given twice", []string{"start", "a.json", "-config", "b.json"}, true, nil, "give the site file once"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.RemoveAll(filepath.Dir(saved))
			if tc.haveDef {
				if err := os.MkdirAll(filepath.Dir(saved), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(saved, []byte(`{"version":1,"flags":{}}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := commandArgs(tc.args[0], tc.args[1:])
			if tc.says != "" {
				if err == nil || !strings.Contains(err.Error(), tc.says) {
					t.Fatalf("error %v, want one saying %q", err, tc.says)
				}
				return
			}
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		args []string
		says string // in the output, or in the error when bad
		bad  bool
	}{
		{"no arguments is the guide", nil, "carnical setup", false},
		{"help", []string{"help"}, "carnical start [FILE]", false},
		{"-h is the guide too", []string{"-h"}, "Commands:", false},
		{"a help topic", []string{"help", "profiles"}, "wordpress", false},
		{"the bots topic", []string{"help", "bots"}, "blocked_people", false},
		{"every flag", []string{"help", "flags"}, "-auto-block", false},
		{"an unknown topic", []string{"help", "nope"}, "topics: setup", true},
		{"an unknown command", []string{"launch"}, `unknown command "launch"`, true},
		{"setup takes no arguments", []string{"setup", "x"}, "without extra arguments", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runCommand(tc.args, strings.NewReader(""), &out)
			if errors.Is(err, flag.ErrHelp) {
				err = nil
			}
			text := out.String()
			if err != nil {
				text = err.Error()
			}
			if (err != nil) != tc.bad || !strings.Contains(text, tc.says) {
				t.Fatalf("error %v, output %q; want bad=%v saying %q", err, out.String(), tc.bad, tc.says)
			}
		})
	}
}

// Each setup answer becomes flags; a level or site type writes only what differs from the defaults.
func TestSetupProfilesChooseFlags(t *testing.T) {
	base := setupProtection{site: "general", level: "normal", mode: "detect", flood: "normal", autoBlock: "monitor", alerts: "on"}
	common := map[string]any{"mode": "detect", "formats-mode": "monitor", "ddos": "normal", "auto-block": "monitor", "alerts": "on"}
	with := func(extra map[string]any) map[string]any {
		out := maps.Clone(common)
		maps.Copy(out, extra)
		return out
	}
	for _, tc := range []struct {
		name   string
		change func(*setupProtection)
		want   map[string]any
	}{
		{"recommended answers add nothing", func(*setupProtection) {}, common},
		{"block enforces the formats too", func(s *setupProtection) { s.mode = "block" }, with(map[string]any{"mode": "block", "formats-mode": "block"})},
		{"wordpress", func(s *setupProtection) { s.site = "wordpress" }, with(map[string]any{"wordpress": true})},
		{"api", func(s *setupProtection) { s.site = "api" }, with(map[string]any{"api-guard": "monitor"})},
		{"java", func(s *setupProtection) { s.site = "java" }, with(map[string]any{"allow-path-params": true})},
		{"relaxed blocks at 8", func(s *setupProtection) { s.level = "relaxed" }, with(map[string]any{"inbound-threshold": 8, "outbound-threshold": 8})},
		{"strict is level 2", func(s *setupProtection) { s.level = "strict" }, with(map[string]any{"paranoia": 2})},
		{"a login page", func(s *setupProtection) { s.login = "/account/login" }, with(map[string]any{"limit": "POST /account/login 10/m"})},
		{"the other answers are written as given", func(s *setupProtection) { s.flood, s.autoBlock, s.alerts = "strict", "on", "off" },
			with(map[string]any{"ddos": "strict", "auto-block": "on", "alerts": "off"})},
		{"in detect only scanners are blocked, and the bots chosen logged", func(s *setupProtection) { s.bots = "fake" },
			with(map[string]any{"bots": "scanner", "bots-monitor": "fake,scanner"})},
		{"strict bots are blocked in block", func(s *setupProtection) { s.mode, s.bots = "block", "strict" },
			with(map[string]any{"mode": "block", "formats-mode": "block", "bots": "fake,scanner,ai,seo,tool,headless,disguised,bot"})},
		{"no bots blocked turns the default off", func(s *setupProtection) { s.bots = "none" }, with(map[string]any{"bots": "none"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			tc.change(&s)
			got := s.flags()
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("flags %v, want %v", got, tc.want)
			}
			// Every value is one the proxy takes as it is.
			if err := runArgsTo(io.Discard, io.Discard, append(setupValidationArgs(got), "-upstream=http://192.0.2.1", "-origin-allow=192.0.2.1/32")); err != nil {
				t.Fatalf("the flags are refused: %v", err)
			}
		})
	}
}

// gatedWriter holds every write until open is closed, as a log that has fallen behind does.
type gatedWriter struct {
	open chan struct{}
	mu   sync.Mutex
	buf  bytes.Buffer
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	<-w.open
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// Not a profile: this is the command's own log path. Under attack every matched rule is a line, so a log that cannot
// keep up must cost lines, which are counted, and never hold up the requests.
func TestRuleMatchLinesNeverWaitOnTheLog(t *testing.T) {
	w := &gatedWriter{open: make(chan struct{})}
	l := newMatchLog(slog.NewJSONHandler(w, nil))
	log := slog.New(l)
	const sent = 20000
	start := time.Now()
	for i := range sent {
		log.Warn("rule matched", "rule", 942100, "tx", i)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("%d lines took %v while the log was stalled", sent, took)
	}
	close(w.open)
	l.close(5 * time.Second)
	log.Warn("rule matched", "rule", 942100) // after close: dropped, not a panic
	written, dropped := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(w.buf.String()), "\n") {
		var rec struct {
			Msg   string
			Count int
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		switch rec.Msg {
		case "rule matched":
			written++
		case "rule matched lines dropped":
			dropped += rec.Count
		}
	}
	if written == 0 || dropped == 0 || written+dropped != sent {
		t.Fatalf("%d written and %d counted as dropped, want both, adding up to %d", written, dropped, sent)
	}
}

// noDNS answers every lookup with "no such host", so that an address outside the lists is refused without the network.
type noDNS struct{}

func (noDNS) LookupAddr(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

func (noDNS) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

// The crawler lists are read again when a new copy is put in place, a copy that cannot be used leaves them as they were,
// and a list not refreshed for a week is reported once a day. Not a profile: it is the command line's files and clock.
func TestCrawlerListsStayCurrent(t *testing.T) {
	const listA = `{"creationTime": "2026-10-01T00:00:00", "prefixes": [{"ipv4Prefix": "66.249.64.0/27"}]}`
	const listB = "192.0.2.0/24\n"
	inA, inB := netip.MustParseAddr("66.249.64.1"), netip.MustParseAddr("192.0.2.1")
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	type step struct {
		change func(t *testing.T, dir, path string) // what happens to the files
		after  time.Duration                        // when, after start, the files are looked at
		logs   []string                             // what that look logs, in order; nil for nothing
		in     []netip.Addr                         // verified as Google's crawlers afterwards
		out    []netip.Addr                         // not verified
	}
	replace := func(data string, mtime time.Time) func(*testing.T, string, string) {
		return func(t *testing.T, dir, path string) {
			tmp := filepath.Join(dir, ".new")
			if err := os.WriteFile(tmp, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(tmp, mtime, mtime); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, path); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tt := range []struct {
		name    string
		written time.Time // the first copy's time
		first   []string  // what reading it at start logs, in order; nil to not look
		steps   []step
	}{
		{name: "an unchanged list is not read again", written: start, first: []string{`"msg":"crawler ranges","engine":"google"`},
			steps: []step{{after: time.Minute, in: []netip.Addr{inA}, out: []netip.Addr{inB}}}},
		{name: "the start-up line says what was read", written: start.Add(-50 * time.Hour),
			first: []string{`"msg":"crawler ranges","engine":"google","file":`, `"ranges":1,"fetched":"2026-10-16T10:00:00Z","age_days":2,"published":"2026-10-01T00:00:00Z"`}},
		{name: "a new copy moved into place replaces the list", written: start, steps: []step{{
			change: replace(listB, start.Add(time.Minute)), after: 2 * time.Minute,
			logs: []string{`"msg":"crawler ranges reloaded","engine":"google"`}, in: []netip.Addr{inB}, out: []netip.Addr{inA}}}},
		{name: "a copy that does not parse leaves the list as it was, and is reported once", written: start, steps: []step{
			{change: replace(`{"prefixes": [{"ipv4Prefix": "10.0.0.0/8"}]}`, start.Add(time.Minute)), after: 2 * time.Minute,
				logs: []string{`"msg":"crawler ranges not reloaded","error":"google: prefix 1: 10.0.0.0/8 is wider than a /16"`},
				in:   []netip.Addr{inA}},
			{after: 3 * time.Minute, in: []netip.Addr{inA}},
			{change: replace(listB, start.Add(4*time.Minute)), after: 5 * time.Minute,
				logs: []string{`"msg":"crawler ranges reloaded"`}, in: []netip.Addr{inB}, out: []netip.Addr{inA}}}},
		{name: "a removed list leaves the list as it was", written: start, steps: []step{{
			change: func(t *testing.T, _, path string) { os.Remove(path) }, after: 2 * time.Minute,
			logs: []string{`"msg":"crawler ranges not reloaded","error":"google: `, `common-crawlers.json`}, in: []netip.Addr{inA}}}},
		{name: "a symbolic link put in its place is refused", written: start, steps: []step{{
			change: func(t *testing.T, dir, path string) {
				target := filepath.Join(dir, "elsewhere.txt")
				if err := os.WriteFile(target, []byte(listB), 0o600); err != nil {
					t.Fatal(err)
				}
				os.Remove(path)
				if err := os.Symlink(target, path); err != nil {
					t.Skip("no symbolic links here:", err)
				}
			}, after: 2 * time.Minute,
			logs: []string{`"msg":"crawler ranges not reloaded","error":"google: must be a regular file`}, in: []netip.Addr{inA}, out: []netip.Addr{inB}}}},
		{name: "a list a week old is reported at start, then once a day", written: start.Add(-8 * 24 * time.Hour),
			first: []string{`"msg":"crawler ranges"`, `"msg":"crawler ranges not refreshed","engine":"google"`, `"age_days":8`},
			steps: []step{
				{after: time.Hour, in: []netip.Addr{inA}},
				{after: 25 * time.Hour, logs: []string{`"msg":"crawler ranges not refreshed"`, `"age_days":9`}},
				{change: replace(listB, start.Add(26*time.Hour)), after: 26 * time.Hour,
					logs: []string{`"msg":"crawler ranges reloaded"`}, in: []netip.Addr{inB}}}},
		{name: "a list six days old is reported only once it is a week old", written: start.Add(-6 * 24 * time.Hour), first: []string{`"msg":"crawler ranges"`},
			steps: []step{{after: 23 * time.Hour}, {after: 25 * time.Hour, logs: []string{`"msg":"crawler ranges not refreshed"`, `"age_days":7`}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "common-crawlers.json")
			replace(listA, tt.written)(t, dir, path)
			v := bots.NewVerifier(noDNS{}, 0, 0)
			lists, err := readCrawlerLists("google="+path, v)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&out, nil))
			expect := func(when string, want []string) {
				t.Helper()
				got := out.String()
				out.Reset()
				rest := got
				for _, w := range want {
					i := strings.Index(rest, w)
					if i < 0 {
						t.Fatalf("%s: the log lacks %q (in order):\n%s", when, w, got)
					}
					rest = rest[i+len(w):]
				}
				if want == nil && got != "" {
					t.Fatalf("%s: logged %s, want nothing", when, got)
				}
				if lines := strings.Count(got, "\n"); len(want) > 0 && lines > len(want) {
					t.Fatalf("%s: %d lines, want at most %d:\n%s", when, lines, len(want), got)
				}
			}
			lists.logRead(log, "crawler ranges", start)
			if tt.first != nil {
				expect("at start", tt.first)
			}
			out.Reset()
			for i, s := range tt.steps {
				if s.change != nil {
					s.change(t, dir, path)
				}
				lists.refresh(log, start.Add(s.after))
				expect(fmt.Sprintf("step %d", i+1), s.logs)
				for _, a := range s.in {
					if !v.Verify(context.Background(), a, bots.EngineGoogle) {
						t.Fatalf("step %d: %v is not verified", i+1, a)
					}
				}
				for _, a := range s.out {
					if v.Verify(context.Background(), a, bots.EngineGoogle) {
						t.Fatalf("step %d: %v is verified", i+1, a)
					}
				}
			}
		})
	}
}

// The alert endpoint's settings are checked at start-up as the proxy's own are, and a refusal names the setting, never
// the endpoint's URL, its token or the secret.
func TestAlertEndpointSettings(t *testing.T) {
	dir := t.TempDir()
	secretPath, shortPath, openPath := filepath.Join(dir, "alert.secret"), filepath.Join(dir, "short.secret"), filepath.Join(dir, "open.secret")
	secret := strings.Repeat("s", 40)
	for _, f := range []struct{ path, data string }{{secretPath, secret + "\n"}, {shortPath, "too-short\n"}} {
		if err := writeNewSiteFile(f.path, []byte(f.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(openPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyMode(t, openPath, 0o644)
	const url = "-alert-endpoint=https://alerts.example.com/hook?token=zz9tok"
	withSecret := "-alert-endpoint-secret-file=" + secretPath
	for _, tc := range []struct {
		name string
		args []string
		says string // empty: accepted
	}{
		{"no endpoint", nil, ""},
		{"a public https endpoint", []string{url, withSecret}, ""},
		{"a private endpoint that is allowed", []string{"-alert-endpoint=https://10.0.0.7/hook", "-alert-endpoint-allow=10.0.0.7/32", withSecret}, ""},
		{"a relay on this machine over http", []string{"-alert-endpoint=http://127.0.0.1:9000/hook", "-alert-endpoint-allow=127.0.0.1/32", withSecret}, ""},
		{"a private endpoint that is not allowed", []string{"-alert-endpoint=https://10.0.0.7/hook", withSecret}, "not public"},
		{"the metadata address", []string{"-alert-endpoint=https://169.254.169.254/latest", withSecret}, "not public"},
		{"plain http to a public endpoint", []string{"-alert-endpoint=http://alerts.example.com/hook", withSecret}, "must use https"},
		{"credentials in the URL", []string{"-alert-endpoint=https://user:pw@alerts.example.com/hook", withSecret}, "user name or password"},
		{"no secret", []string{url}, "needs -alert-endpoint-secret-file"},
		{"a short secret", []string{url, "-alert-endpoint-secret-file=" + shortPath}, "32 to 1024"},
		{"a secret everyone can read", []string{url, "-alert-endpoint-secret-file=" + openPath}, "cannot read the alert endpoint's secret file"},
		{"a missing secret file", []string{url, "-alert-endpoint-secret-file=" + filepath.Join(dir, "none")}, "cannot read the alert endpoint's secret file"},
		{"a secret without an endpoint", []string{withSecret}, "-alert-endpoint-secret-file needs -alert-endpoint"},
		{"an allowance without an endpoint", []string{"-alert-endpoint-allow=10.0.0.7/32"}, "-alert-endpoint-allow needs -alert-endpoint"},
		{"an allow-all range", []string{url, withSecret, "-alert-endpoint-allow=0.0.0.0/0"}, "-alert-endpoint-allow"},
		{"a CA file with no certificate", []string{url, withSecret, "-alert-endpoint-ca-file=" + shortPath}, "contains no certificates"},
		{"confined with the endpoint's port", []string{"-confine", "-confine-connect=80,443,53", url, withSecret}, ""},
		{"confined without the endpoint's port", []string{"-confine", "-confine-connect=80,443,53", "-alert-endpoint=https://alerts.example.com:8443/hook", withSecret}, "port 8443 must be listed in -confine-connect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			args := append([]string{"-check", "-upstream=http://192.0.2.1", "-origin-allow=192.0.2.1/32"}, tc.args...)
			err := runArgsTo(io.Discard, &logs, args)
			if tc.says == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("error %v, want one that says %q", err, tc.says)
			}
			for _, leak := range []string{"zz9tok", "alerts.example.com", secret, "user:pw"} {
				if err != nil && strings.Contains(err.Error(), leak) || strings.Contains(logs.String(), leak) {
					t.Fatalf("%q leaked: error %v, log %s", leak, err, &logs)
				}
			}
		})
	}
}

// The endpoint sends an attack's start, its end, and at most one update a minute of the shield's ten-second updates,
// signed, to a real TLS receiver through the guarded dialer.
// alertReceiver is a started endpoint for the site example.com, its log, and what its receiver was sent with a valid
// signature, which is complete once the endpoint is closed.
func alertReceiver(t *testing.T) (*endpoint, *slog.Logger, *bytes.Buffer, *[]notify.Message) {
	t.Helper()
	dir := t.TempDir()
	secret := strings.Repeat("k", 48)
	secretPath := filepath.Join(dir, "alert.secret")
	if err := writeNewSiteFile(secretPath, []byte(secret+"\n")); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	got := new([]notify.Message)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, notify.MaxBody))
		var m notify.Message
		if notify.Verify([]byte(secret), r.Header.Get("X-Carnical-Timestamp"), r.Header.Get("X-Carnical-Signature"), body, time.Now(), time.Minute) &&
			json.Unmarshal(body, &m) == nil {
			mu.Lock()
			*got = append(*got, m)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := new(bytes.Buffer)
	log := slog.New(slog.NewJSONHandler(logs, nil))
	str := func(s string) *string { return &s }
	ep, err := configureEndpoint(log, endpointFlags{url: str(srv.URL + "/hook"), secretFile: str(secretPath), allow: str("127.0.0.1/32"), caFile: str(caPath)}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := ep.start(log); err != nil {
		t.Fatal(err)
	}
	return ep, log, logs, got
}

func TestAlertEndpointSendsAttacks(t *testing.T) {
	ep, log, logs, sent := alertReceiver(t)
	start := time.Date(2026, 10, 19, 1, 0, 0, 0, time.UTC)
	inc := shield.Incident{Start: start, Kinds: []string{"request_flood"}, Ports: []shield.PortCount{{Port: 443, Requests: 900}},
		Sources: 700, Networks: 90, PeakRate: 3000, BaselineRate: 20, TLS: 900, HTTP2: 900, Requests: 900, Window: true,
		Clusters: []shield.Cluster{{Kind: "target", Label: "/search?\x1b[31m<script>" + strings.Repeat("x", 300), Share: 0.9, Sources: 600}}}
	ep.shieldEvent(shield.Event{Kind: "elevated", At: start}) // not an attack: not sent
	ep.shieldEvent(shield.Event{Kind: "attack_start", Mode: "on", At: start, Rate: 3000, Incident: inc})
	for s := 10; s <= 120; s += 10 { // the shield's ten-second updates: one a minute goes
		inc.Window = false
		ep.shieldEvent(shield.Event{Kind: "attack_update", Mode: "on", At: start.Add(time.Duration(s) * time.Second), Rate: 2000, Incident: inc})
	}
	inc.End = start.Add(130 * time.Second)
	ep.shieldEvent(shield.Event{Kind: "attack_end", Mode: "on", At: inc.End, Incident: inc})
	ep.close(log)
	ep.shieldEvent(shield.Event{Kind: "attack_start", Mode: "on", At: inc.End, Incident: inc}) // after close: dropped quietly
	got := *sent

	// The updates of 60s and 120s go; one still waiting when the next comes is replaced by it (the endpoint needs the
	// latest), so the last update sent is always that of 120s.
	var events []notify.Event
	var last *notify.Message
	for i, m := range got {
		events = append(events, m.Event)
		if m.Event == notify.AttackUpdate {
			last = &got[i]
		}
	}
	updates := len(events) - 2
	if len(events) < 3 || events[0] != notify.AttackStart || events[len(events)-1] != notify.AttackEnd || updates < 1 || updates > 2 ||
		last == nil || !last.At.Equal(start.Add(120*time.Second)) || last.Attack.Window {
		t.Fatalf("events %v (last update %+v), want the start, the updates of 60s and 120s or only the latest, the end", events, last)
	}
	if !strings.Contains(logs.String(), `"queued":4`) {
		t.Fatalf("want the start, the updates of 60s and 120s and the end queued: %s", logs)
	}
	got = append(got[:1], got[len(got)-1]) // the start and the end
	first := got[0]
	if first.Site != "example.com" || first.Attack.Ports[0].Port != 443 || !first.Attack.Window || first.Attack.Addresses != 700 ||
		!strings.Contains(first.Text, "tcp/443") || !strings.Contains(first.Text, "mitigation on") {
		t.Fatalf("start %+v", first)
	}
	label := first.Attack.Clusters[0].Label
	if len(label) > 96 || strings.ContainsAny(label, "\x1b<>") {
		t.Fatalf("a client-made label went out unbounded or uncleaned: %q", label)
	}
	if got[1].Attack.Ended == nil || got[1].Severity != "info" || strings.Contains(got[1].Text, "mitigation on") {
		t.Fatalf("end %+v", got[1])
	}
	if strings.Contains(logs.String(), "/hook") || strings.Contains(logs.String(), strings.Repeat("k", 48)) || !strings.Contains(logs.String(), `"sent":`+strconv.Itoa(len(events))) {
		t.Fatalf("the log names neither the URL nor the secret, and counts what was sent: %s", logs)
	}
}

// The network watch's events are read from its state file once each, logged, and sent as the shield's are: every start
// and end, one update a minute. A file that is not one the watch writes is refused, and an old event found at startup
// is not told again.
func TestNetwatchStateIsToldOnce(t *testing.T) {
	ep, log, logs, sent := alertReceiver(t)
	path := filepath.Join(t.TempDir(), "state.json")
	start := time.Date(2026, 10, 19, 2, 0, 0, 0, time.UTC)
	clock := start
	n := newNetwatchReader(path, log, ep, "example.com")
	n.now, n.owner = func() time.Time { return clock }, os.Getuid()
	rec := netwatch.Record{Started: start, Kinds: []netwatch.KindCount{{Kind: netwatch.KindReflection, Packets: 90000, Bytes: 9e6}},
		Ports: []netwatch.Port{}, SourcePorts: []netwatch.Port{{Protocol: "udp", Port: 123, Packets: 90000, Bytes: 9e6}},
		PacketRate: 30000, PeakRate: 30000, Baseline: 4, Packets: 90000, Bytes: 9e6}
	seq := uint64(0)
	write := func(ev netwatch.Event, at time.Time, r netwatch.Record) {
		t.Helper()
		seq++
		if err := netwatch.WriteState(path, netwatch.State{Version: 1, Seq: seq, Event: ev, At: at, Attack: &r}); err != nil {
			t.Fatal(err)
		}
	}
	n.poll() // no file yet: nothing reported, and what comes is new
	write(netwatch.Start, start, rec)
	n.poll()
	n.poll() // the same file: not told again
	seq--
	write(netwatch.Start, start, rec) // the same event in a new file: not told again either
	n.poll()
	for s := 10; s <= 120; s += 10 {
		clock = start.Add(time.Duration(s) * time.Second)
		write(netwatch.Update, clock, rec)
		n.poll()
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"seq":99,"event":"network_attack_start","at":"2026-10-19T02:03:00Z","attack":{"kinds":[{"kind":"made_up"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	n.poll()
	n.poll() // refused once a minute in the log, never sent
	end := start.Add(150 * time.Second)
	clock = end
	r := rec
	r.Ended = &end
	write(netwatch.End, end, r)
	n.poll()

	// A restart: an event 20 seconds old is not told; a newer one is.
	clock = end.Add(20 * time.Second)
	restarted := newNetwatchReader(path, log, ep, "example.com")
	restarted.now, restarted.owner = func() time.Time { return clock }, os.Getuid()
	restarted.poll()
	write(netwatch.Start, clock, rec)
	restarted.poll()
	ep.close(log)

	var events []notify.Event
	for _, m := range *sent {
		events = append(events, m.Event)
		// A minute after the start, then a minute after that: the updates of 60 and 120 seconds.
		if at := m.At.Sub(start); m.Event == notify.NetworkUpdate && at != time.Minute && at != 2*time.Minute {
			t.Fatalf("an update of %s was sent", at)
		}
		if m.Network == nil || m.Attack != nil || m.Site != "example.com" || len(m.Network.SourcePorts) != 1 || m.Network.SourcePorts[0].Port != 123 {
			t.Fatalf("message %+v", m)
		}
	}
	want := []notify.Event{notify.NetworkStart, notify.NetworkUpdate, notify.NetworkUpdate, notify.NetworkEnd, notify.NetworkStart}
	if !slices.Equal(events, want) && !slices.Equal(events, slices.Delete(slices.Clone(want), 1, 2)) {
		t.Fatalf("sent %v, want %v (or one update: one waiting is replaced by the next)", events, want)
	}
	first := (*sent)[0]
	if first.Severity != "critical" || !strings.Contains(first.Text, "reflected from udp/123") || !strings.Contains(first.Text, "on example.com") {
		t.Fatalf("start %+v", first)
	}
	out := logs.String()
	// The start, the updates of 60 and 120 seconds, the end, and the start after the restart.
	if !strings.Contains(out, `"queued":5`) {
		t.Fatalf("want five messages queued:\n%s", out)
	}
	if c := strings.Count(out, `"msg":"network flood detected"`); c != 2 {
		t.Fatalf("%d start lines, want 2:\n%s", c, out)
	}
	if strings.Count(out, `"msg":"network flood continues"`) != 12 || strings.Count(out, `"msg":"network flood over"`) != 1 {
		t.Fatalf("every update and the end are logged:\n%s", out)
	}
	if strings.Count(out, "the network watch's state cannot be read") != 1 || strings.Contains(out, "made_up") {
		t.Fatalf("a forged file is refused once, without its content:\n%s", out)
	}
}

// A state file that someone other than its owner could have written, or that belongs to another user, is refused.
func TestNetwatchStateMustBeTheWatchs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("carnical-netwatch runs on Linux")
	}
	path := filepath.Join(t.TempDir(), "state.json")
	end := time.Now().UTC()
	st := netwatch.State{Version: 1, Seq: 1, Event: netwatch.Start, At: end, Attack: &netwatch.Record{Started: end,
		Kinds: []netwatch.KindCount{{Kind: netwatch.KindUDPFlood, Packets: 1}}, Ports: []netwatch.Port{}}}
	for _, tc := range []struct {
		name  string
		mode  os.FileMode
		owner int
		want  string
	}{
		{"the watch's, readable by all", 0o644, os.Getuid(), ""},
		{"writable by its group", 0o664, os.Getuid(), "can be written by others"},
		{"writable by everyone", 0o646, os.Getuid(), "can be written by others"},
		{"another user's", 0o644, os.Getuid() + 1, "belongs to uid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := netwatch.WriteState(path, st); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			n := newNetwatchReader(path, slog.New(slog.NewJSONHandler(&logs, nil)), nil, "")
			n.owner, n.started = tc.owner, true
			n.poll()
			told := strings.Contains(logs.String(), "network flood detected")
			if tc.want == "" && !told || tc.want != "" && (told || !strings.Contains(logs.String(), tc.want)) {
				t.Fatalf("log %s", &logs)
			}
		})
	}
}

func TestNetwatchStateSetting(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name, path, want string
	}{
		{"relative", "state.json", "must be an absolute path"},
		{"no directory", filepath.Join(dir, "missing", "state.json"), "must exist"},
		{"a directory that is there", filepath.Join(dir, "state.json"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkNetwatchState(tt.path)
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("%v, want %q", err, tt.want)
			}
		})
	}
}

// The guard is applied where it cannot be fooled, at each connection: a name that passes start-up (it is not an
// address) but resolves to a private one gets nothing, and the endpoint there is never reached.
func TestAlertEndpointNamesAreCheckedWhenConnecting(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "alert.secret")
	if err := writeNewSiteFile(secretPath, []byte(strings.Repeat("k", 48)+"\n")); err != nil {
		t.Fatal(err)
	}
	var reached atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	// A certificate for the name localhost, which httptest's does not cover.
	pub, key, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	str := func(s string) *string { return &s }
	for _, tc := range []struct {
		name, allow string
		reaches     bool
	}{
		{"not allowed", "", false},
		{"allowed (control: the endpoint is reachable, so the refusal is the guard's)", "127.0.0.1/32,::1/128", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := reached.Load()
			ep, err := configureEndpoint(log, endpointFlags{url: str("https://localhost:" + port + "/hook"), secretFile: str(secretPath),
				allow: str(tc.allow), caFile: str("")}, "example.com")
			if err != nil {
				t.Fatal(err)
			}
			pool := x509.NewCertPool()
			pool.AddCert(cert)
			ep.cfg.RootCAs = pool
			if err := ep.start(log); err != nil {
				t.Fatal(err)
			}
			ep.shieldEvent(shield.Event{Kind: "attack_start", At: time.Now(), Incident: shield.Incident{Start: time.Now()}})
			ep.close(log)
			if got := reached.Load() > before; got != tc.reaches {
				t.Fatalf("endpoint reached %v, want %v; log %s", got, tc.reaches, &logs)
			}
			if !tc.reaches && !strings.Contains(logs.String(), "the address is not allowed") {
				t.Fatalf("the refusal was not logged: %s", &logs)
			}
		})
	}
}
