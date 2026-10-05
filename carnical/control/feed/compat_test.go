// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The tests in this file run the owner console's real Python reader (newsletter/brief/waf/feed.py and fleet.py)
// against this handler. They are skipped when Python or the reader is not there. Set CARNICAL_READER_DIR to the
// newsletter folder and CARNICAL_PYTHON to the interpreter to point them elsewhere.

func pythonAndReader(t *testing.T) (python, reader, script string) {
	t.Helper()
	reader = os.Getenv("CARNICAL_READER_DIR")
	if reader == "" {
		reader = filepath.Join("..", "..", "..", "..", "5Weeks1k", "newsletter")
	}
	if _, err := os.Stat(filepath.Join(reader, "brief", "waf", "feed.py")); err != nil {
		t.Skipf("the owner console's reader is not at %s (set CARNICAL_READER_DIR)", reader)
	}
	reader, _ = filepath.Abs(reader)
	python = os.Getenv("CARNICAL_PYTHON")
	if python == "" {
		for _, name := range []string{"python3", "python"} {
			if p, err := exec.LookPath(name); err == nil {
				python = p
				break
			}
		}
	}
	if python == "" {
		t.Skip("python is not installed")
	}
	script, _ = filepath.Abs(filepath.Join("testdata", "reader_compat.py"))
	// does the reader import here? (it needs PyYAML for the register)
	if out, err := runPython(python, reader, script, "vector"); err != nil {
		t.Skipf("the reader cannot be imported with %s: %v: %s", python, err, out)
	}
	return python, reader, script
}

func runPython(python, reader, script string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, append([]string{"-B", script}, args...)...)
	cmd.Env = append(os.Environ(), "CARNICAL_READER_DIR="+reader, "PYTHONDONTWRITEBYTECODE=1", "PYTHONIOENCODING=utf-8")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return append(stdout.Bytes(), stderr.Bytes()...), err
	}
	return stdout.Bytes(), nil
}

func py(t *testing.T, args ...string) map[string]any {
	t.Helper()
	python, reader, script := pythonAndReader(t)
	out, err := runPython(python, reader, script, args...)
	if err != nil {
		t.Fatalf("python %v: %v\n%s", args, err, out)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("python output is not JSON: %v\n%s", err, out)
	}
	return m
}

// kinds is every kind of event in docs/backend-compat.md section 2, with the severity the reports expect.
var kinds = []struct{ kind, sev string }{
	{"block", "high"}, {"would_block", "medium"}, {"match", "low"}, {"budget", "low"}, {"listed", "low"}, {"reputation", "low"},
	{"error", "high"}, {"log_full", "high"}, {"ip_ban", "high"}, {"campaign", "high"}, {"leak", "high"}, {"health", "high"},
	{"flood", "high"}, {"spraying", "high"}, {"scan", "medium"}, {"enumeration", "medium"}, {"would_ban", "medium"},
	{"sig_error", "medium"}, {"ip_unban", "info"}, {"policy", "info"}, {"update_ok", "info"}, {"update_failed", "critical"},
}

// richRig fills a rig with data that uses every field the reader knows.
func richRig(t *testing.T, n int, mutate ...func(*Config, *Key)) *rig {
	t.Helper()
	r := newRig(t, mutate...)
	for i := 0; i < n; i++ {
		k := kinds[i%len(kinds)]
		score, thr, status, errs, cnt := 12+i, 5, 403, 2, 7
		ms := 0.25
		until := int64(1791014400 + i)
		e := Event{Time: nowAt().Add(-time.Duration(n-i) * time.Minute), Kind: k.kind, Sev: k.sev, Channel: "fw", ID: fmt.Sprintf("%012X", 0xABC000000000+i),
			Mode: "block", IP: []string{"198.51.100.77", "2001:db8:abcd:1234::1", "203.0.113.9", ""}[i%4], Method: "POST", Path: "/wp-login.php?x=1",
			Status: &status, Score: &score, Threshold: &thr, MS: &ms, UA: "Mozilla/5.0 (X11; Linux x86_64) é中", Code: "code" + strconv.Itoa(i),
			Msg: "matched 942100", Detail: "from 203.0.113.9 via 2001:db8:1:2::3", Engine: "carnical-1", Host: "alpha.example", Why: "3 blocked from 198.51.100.77",
			User: "sam", What: "changed the threshold", Errs: &errs, N: &cnt, Trunc: bp(i%2 == 0), Budget: bp(false), Ver: "1.0",
			Sigs: []SigMatch{{ID: "CRS-942100", Score: i2p(5), Action: "block", Target: "args", Name: "q"}, {ID: "CRS-941100", Action: "log"}}}
		if i%3 == 0 {
			e.UntilUnix = &until
		} else if i%3 == 1 {
			e.UntilText = "midnight"
		}
		if k.kind == "update_ok" || k.kind == "update_failed" {
			e.Channel = "update"
		}
		r.src.events = append(r.src.events, e)
	}
	for d := 0; d < 3; d++ {
		day := nowAt().AddDate(0, 0, -d-1).Format("2006-01-02")
		r.src.traffic = append(r.src.traffic, TrafficDay{Day: day, TZ: "Australia/Brisbane", Requests: 812, Pages: 301, Visitors: 120, Attacks: 14, Bots: i64(260),
			API: i64(9), Static: i64(100), Proxied: i64(0), Lines: i64(900), BadLines: i64(0), VisitorsCapped: bp(false), Partial: bp(d == 0),
			Outcomes: map[string]int64{"c": 790, "m": 8, "b": 12, "B": 2}, Status: map[string]int64{"2xx": 700, "4xx": 100, "5xx": 12},
			Hours: make([]Hour, 24), MS: &MS{P50: 0.21, P95: 0.9, Max: 3}, TopPages: []TopEntry{{"/", 120}, {"/about", 30}},
			Top404: []TopEntry{{"/wp-admin", 4}}, TopBlocked: []TopEntry{{"/wp-login.php", 12}}})
	}
	r.src.traffic = append(r.src.traffic, TrafficDay{Day: nowAt().AddDate(0, 0, -9).Format("2006-01-02"), Requests: 1, Outcomes: map[string]int64{}, Status: map[string]int64{}})
	r.src.ips = IPs{Bans: []Ban{{IP: "198.51.100.77", At: 1791010000, Until: 1791010900, Why: "3 blocked", By: "auto", N: 1, Active: true}},
		Offenders: []Offender{{IP: "203.0.113.9", Points: 12, Counts: map[string]int64{"not_found": 12}, Last: 1791013000}, {IP: "2001:db8:5::1", Points: 3}}}
	r.src.marks = []Mark{{ID: "0123456789abcdef", Time: nowAt(), Kind: "real_visitor", Note: "an order form", User: "sam",
		Event: &MarkEvent{Time: ptrTime(nowAt()), Kind: "would_block", Sev: "medium", Path: "/order", Method: "POST", IP: "198.51.100.77", ID: "ABCDEF012345",
			Sigs: []SigMatch{{ID: "CRS-942100", Score: i2p(5), Action: "log"}}}}, {ID: "fedcba9876543210", Time: nowAt(), Kind: "look_at"}}
	r.src.health = Health{Engine: "carnical-1", Mode: "block", Inspecting: bp(true), Bundle: &Bundle{Version: "crs-4.30.0", Signatures: 4000, Activated: ptrTime(nowAt()), Verified: bp(true)},
		Updates: Updates{LastCheck: ptrTime(nowAt()), LastOK: ptrTime(nowAt()), NextCheck: ptrTime(nowAt().Add(6 * time.Hour)), Failures: 0},
		Errors:  []string{"a segmentation check failed: zone-reach"}, Notes: []string{"all edges acknowledged revision 3"}}
	return r
}

func i2p(v int) *int { return &v }

// answerBytes asks the handler once, signing with the vector's secret, and returns the body.
func answerBytes(t *testing.T, r *rig, target string) []byte {
	t.Helper()
	w := r.do(r.signed(target))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	return w.Body.Bytes()
}

func writeTemp(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "answer.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTheReadersOwnCodeSignsTheVectorAsWeDo(t *testing.T) {
	m := py(t, "vector")
	if m["signature"] != vectorSig || m["signed"] != vectorSigned {
		t.Fatalf("the reader's vector differs: %v", m)
	}
	if Sign(vectorSecret(), vectorTarget, vectorTS, vectorNonce) != m["signature"] {
		t.Fatal("our signature differs from the reader's")
	}
}

func TestReaderParseAcceptsEverythingWeSend(t *testing.T) {
	r := richRig(t, 44)
	body := answerBytes(t, r, "/feed?days=7")
	m := py(t, "parse", writeTemp(t, body))
	if why, bad := m["not_a_feed"]; bad {
		t.Fatalf("the reader refused the answer: %v", why)
	}
	if lo, _ := m["left_out"].(map[string]any); len(lo) != 0 {
		t.Fatalf("the reader left things out: %v (%v)", lo, m["reasons"])
	}
	want := map[string]float64{"events": 44, "traffic": 4, "bans": 1, "offenders": 2, "marks": 2}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("%s: reader kept %v, we sent %v", k, m[k], v)
		}
	}
	if m["more"] != false || m["addresses"] != "cut" || m["site"].(map[string]any)["id"] != testSite {
		t.Fatalf("frame: %v", m)
	}
	h := m["health"].(map[string]any)
	if len(h["errors"].([]any)) != 1 || h["updates"].(map[string]any)["failures"] != float64(0) {
		t.Fatalf("health: %v", h)
	}
	// every address the reader saw was cut
	for _, k := range []string{"event_ips", "ban_ips", "offender_ips"} {
		for _, ip := range m[k].([]any) {
			if ip == nil {
				continue
			}
			s := ip.(string)
			if s != "198.51.100.0" && s != "203.0.113.0" && s != "2001:db8:abcd::" && s != "2001:db8:5::" {
				t.Fatalf("%s holds %q: not a cut address", k, s)
			}
		}
	}
	// a repeat is byte-identical in the reader's canonical form, so it is recognised and not stored twice
	body2 := answerBytes(t, r, "/feed?days=7")
	m2 := py(t, "parse", writeTemp(t, body2))
	if fmt.Sprint(m["canonical"]) != fmt.Sprint(m2["canonical"]) {
		t.Fatal("two answers for the same events differ in the reader's canonical form")
	}
	// the reader's own text for the event kinds we send
	if n := len(m["event_ids"].([]any)); n != 44 {
		t.Fatalf("%d event ids", n)
	}
}

func TestReaderParseAcceptsAKeyWithoutTheEventsScope(t *testing.T) {
	// The PHP console leaves cursor and more out in this case and the reader refuses it; ours always sends them.
	r := richRig(t, 5, func(c *Config, k *Key) { k.Scopes = []string{"traffic", "health"} })
	body := answerBytes(t, r, "/feed")
	m := py(t, "parse", writeTemp(t, body))
	if why, bad := m["not_a_feed"]; bad {
		t.Fatalf("the reader refused an answer without events: %v", why)
	}
	if m["cursor"] != "0" || m["more"] != false || m["events"] != float64(0) {
		t.Fatalf("%v", m)
	}
}

// The negative control for the test above: the reader does notice each of these faults, so "left_out is empty" means
// something.
func TestReaderParseNoticesFaults(t *testing.T) {
	r := richRig(t, 6)
	good := answerBytes(t, r, "/feed")
	clone := func() map[string]any {
		var c map[string]any
		_ = json.Unmarshal(good, &c)
		return c
	}
	rows := []struct {
		name     string
		change   func(m map[string]any)
		notAFeed bool
		leftOut  string
	}{
		{"no cursor", func(m map[string]any) { delete(m, "cursor") }, true, ""},
		{"no more", func(m map[string]any) { delete(m, "more") }, true, ""},
		{"an empty ip as a string", func(m map[string]any) { m["events"].([]any)[0].(map[string]any)["ip"] = "" }, false, "events"},
		{"an empty map as a list", func(m map[string]any) { m["traffic"].([]any)[0].(map[string]any)["outcomes"] = []any{} }, false, "traffic"},
		{"a severity it does not know", func(m map[string]any) { m["events"].([]any)[0].(map[string]any)["sev"] = "urgent" }, false, "events"},
		{"a time with fractions", func(m map[string]any) { m["events"].([]any)[0].(map[string]any)["t"] = "2026-10-03T07:00:00.5Z" }, false, "events"},
		{"feed version 2", func(m map[string]any) { m["feed"] = 2 }, true, ""},
		{"a site id that is not 32 hex", func(m map[string]any) { m["site"].(map[string]any)["id"] = "ABC" }, true, ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			m := clone()
			row.change(m)
			b, _ := json.Marshal(m)
			got := py(t, "parse", writeTemp(t, b))
			_, notAFeed := got["not_a_feed"]
			if notAFeed != row.notAFeed {
				t.Fatalf("not_a_feed = %v, want %v: %v", notAFeed, row.notAFeed, got)
			}
			if row.leftOut != "" {
				lo, _ := got["left_out"].(map[string]any)
				if lo[row.leftOut] == nil {
					t.Fatalf("the reader should have left out a %s: %v", row.leftOut, got)
				}
			}
		})
	}
}

func TestOurHandlerAcceptsTheRequestsTheReaderMakes(t *testing.T) {
	python, reader, script := pythonAndReader(t)
	rows := []struct{ name, cursor, days string }{
		{"first read", "-", "7"},
		{"a cursor of ours", "p3", "30"},
		{"a cursor of the PHP kind", "eyJ2IjoxLCJmdyI6WyIyMDI2MTAwMyIsMTIzNF19", "1"},
		{"a cursor with characters that need encoding", "a b/c+d&e=", "90"},
		{"days over the maximum", "p1", "500"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := richRig(t, 4)
			out, err := runPython(python, reader, script, "request", "/feed", row.cursor, row.days, testKeyID, vectorSecretText, strconv.FormatInt(vectorTS, 10), freshNonce())
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			var raw map[string]string
			if err := json.Unmarshal(out, &raw); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			srv := httptest.NewServer(r.h)
			defer srv.Close()
			hreq, _ := http.NewRequest("GET", srv.URL+raw["path"], nil)
			hreq.Header.Set("Authorization", raw["authorization"])
			resp, err := http.DefaultClient.Do(hreq)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("status %d for %s", resp.StatusCode, raw["path"])
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("content type %q", ct)
			}
			// the reader's expectation of the path the server sees: exactly as it signed it
			if u, err := url.Parse(raw["path"]); err != nil || u.RawQuery == "" {
				t.Fatalf("path %q", raw["path"])
			}
		})
	}
}

func TestTheRealReaderPullsFromUsAndFollowsMore(t *testing.T) {
	python, reader, script := pythonAndReader(t)
	r := richRig(t, 25)
	r.src.maxPage = 10
	srv := httptest.NewServer(r.h)
	defer srv.Close()
	// a key the reader will accept: its id and the secret as 43 characters
	out, err := runPython(python, reader, script, "pull", srv.URL, testKeyID, vectorSecretText, strconv.FormatInt(vectorTS, 10), t.TempDir(), "2")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var reads []struct {
		State     string
		Note      string
		Pages     int
		Events    int
		Days      int
		Marks     int
		More      bool
		Counts    map[string]int
		SiteID    string `json:"site_id"`
		Cursor    string
		Addresses string
	}
	if err := json.Unmarshal(out, &reads); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(reads) != 2 {
		t.Fatalf("%d reads", len(reads))
	}
	first, second := reads[0], reads[1]
	if first.State != "ok" || first.Events != 25 || first.Pages != 3 || first.Days != 4 || first.Marks != 2 {
		t.Fatalf("first read: %+v", first)
	}
	if first.SiteID != testSite || first.Addresses != "cut" || first.Cursor != "p25" {
		t.Fatalf("what the reader pinned: %+v", first)
	}
	if first.Counts["events"] != 25 || first.Counts["traffic"] != 4 || first.Counts["bans"] != 1 || first.Counts["offenders"] != 2 || first.Counts["health"] != 1 {
		t.Fatalf("what the reader stored: %v", first.Counts)
	}
	if second.State != "ok" || second.Events != 0 || second.Counts["events"] != 25 || second.Pages != 1 {
		t.Fatalf("second read should find nothing new: %+v", second)
	}
	if len(r.told) != 0 {
		t.Fatalf("refusals during a good read: %v", r.told)
	}
}

func TestTheReaderUnderstandsOurRefusals(t *testing.T) {
	rows := []struct {
		name  string
		make  func(r *rig) *httptest.ResponseRecorder
		state string
		words string
	}{
		{"bad signature", func(r *rig) *httptest.ResponseRecorder {
			return r.do(signedAt("/feed", []byte("00000000000000000000000000000000"), testKeyID, r.now.Unix(), freshNonce()))
		}, "refused", "the signature is wrong"},
		{"unknown key", func(r *rig) *httptest.ResponseRecorder {
			return r.do(signedAt("/feed", vectorSecret(), "ffffffffffffffff", r.now.Unix(), freshNonce()))
		}, "refused", "unknown key"},
		{"scope", func(r *rig) *httptest.ResponseRecorder { return r.do(r.signed("/feed?scopes=nope")) }, "forbidden", "may not read"},
		{"switched off", func(r *rig) *httptest.ResponseRecorder {
			r.h.cfg.Enabled = func(string) bool { return false }
			return r.do(r.signed("/feed"))
		}, "missing", ""},
		{"rate", func(r *rig) *httptest.ResponseRecorder {
			var w *httptest.ResponseRecorder
			for i := 0; i <= PerHour; i++ {
				w = r.do(r.signed("/feed?scopes=health"))
			}
			return w
		}, "busy", "60 requests"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := richRig(t, 2)
			w := row.make(r)
			args := []string{"refusal", strconv.Itoa(w.Code), writeTemp(t, w.Body.Bytes())}
			if ra := w.Header().Get("Retry-After"); ra != "" {
				args = append(args, ra)
			}
			m := py(t, args...)
			if m["state"] != row.state {
				t.Fatalf("state %v (%v), want %s", m["state"], m["sentence"], row.state)
			}
			if !strings.Contains(fmt.Sprint(m["sentence"]), row.words) {
				t.Fatalf("sentence %q does not say %q", m["sentence"], row.words)
			}
		})
	}
}
