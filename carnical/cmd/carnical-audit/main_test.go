// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/audit"
	"github.com/YurilLAB/coraza/carnical/proxy"
)

// A unit copied from -print-schedule must write where the shipped unit does, inside the directories it may write.
func TestPrintedScheduleMatchesTheShippedUnit(t *testing.T) {
	printed, ok := scheduleText("systemd")
	if !ok {
		t.Fatal("no systemd schedule")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "carnical-audit.service"))
	if err != nil {
		t.Fatal(err)
	}
	shipped := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, re := range []*regexp.Regexp{regexp.MustCompile(`-status (\S+)`), regexp.MustCompile(`-log (\S+)`), regexp.MustCompile(`(?m)^ExecStart=.* -origin-allow (\S+)`),
		regexp.MustCompile(`(?m)^ReadWritePaths=(.*)$`)} {
		p, s := re.FindStringSubmatch(printed), re.FindStringSubmatch(shipped)
		if p == nil || s == nil || p[1] != s[1] {
			t.Errorf("%s: printed %q, shipped %q", re, p, s)
		}
	}
}

// The documented `carnical-audit -write-baseline` is about this machine, so it does not ask for a zone map.
func TestWriteBaselineNeedsNoZoneMap(t *testing.T) {
	if os.Getenv("CARNICAL_AUDIT_TEST_RUN") == "1" {
		os.Args = append([]string{"carnical-audit"}, strings.Split(os.Getenv("CARNICAL_AUDIT_TEST_ARGS"), "\n")...)
		os.Exit(run())
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestWriteBaselineNeedsNoZoneMap$")
	cmd.Env = append(os.Environ(), "CARNICAL_AUDIT_TEST_RUN=1", "CARNICAL_AUDIT_TEST_ARGS=-write-baseline\n-baseline-dir\n"+t.TempDir())
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err != nil && !errors.As(err, &exit):
		t.Fatalf("the command did not run: %v", err)
	case exit != nil && exit.ExitCode() == 2, strings.Contains(output.String(), "-zones is required"):
		t.Fatalf("-write-baseline was refused as a usage error: %v\n%s", err, output.String())
	case !strings.Contains(output.String(), "carnical-audit:") && !strings.Contains(output.String(), "recorded the baselines"):
		t.Fatalf("the command did not get as far as the baselines (%v):\n%s", err, output.String())
	}
}

// Command-owned evidence I/O is outside the audit runner; real files exercise its failure reporting.
func TestReportOutput(t *testing.T) {
	tests := []struct {
		name                  string
		status                audit.Status
		allowSkips            bool
		log, statusPath       string
		invalidTime, keepTemp bool
		alias                 string
		fullConsole           bool
		wantCode              int
		wantOK                bool
	}{
		{name: "passing check without evidence files", status: audit.Pass},
		{name: "full console device", status: audit.Pass, fullConsole: true, statusPath: "good", wantCode: 1},
		{name: "identical log and status paths", status: audit.Pass, log: "good", alias: "same", wantCode: 1},
		{name: "alternate spelling of the log path", status: audit.Pass, log: "good", alias: "dot", wantCode: 1},
		{name: "Windows case alias of the log path", status: audit.Pass, log: "good", alias: "case", wantCode: 1},
		{name: "log symlink to the status file", status: audit.Pass, log: "good", alias: "symlink", wantCode: 1},
		{name: "log and status share a file", status: audit.Pass, log: "good", alias: "hardlink", wantCode: 1},
		{name: "passing check with both files", status: audit.Pass, log: "good", statusPath: "good", wantOK: true},
		{name: "failed check stays failed", status: audit.Fail, log: "good", statusPath: "good", wantCode: 1},
		{name: "unexpected skip stays skipped", status: audit.Skip, statusPath: "good", wantCode: 3},
		{name: "expected skip remains allowed", status: audit.Skip, allowSkips: true, statusPath: "good", wantOK: true},
		{name: "missing log parent makes status unhealthy", status: audit.Pass, log: "missing", statusPath: "good", wantCode: 1},
		{name: "log destination is a directory", status: audit.Pass, log: "directory", statusPath: "good", wantCode: 1},
		{name: "full log device", status: audit.Pass, log: "full", statusPath: "good", wantCode: 1},
		{name: "missing status parent", status: audit.Pass, statusPath: "missing", wantCode: 1},
		{name: "status destination is a directory", status: audit.Pass, statusPath: "directory", wantCode: 1},
		{name: "log serialization failure", status: audit.Pass, log: "good", invalidTime: true, wantCode: 1},
		{name: "status serialization failure", status: audit.Pass, statusPath: "good", invalidTime: true, wantCode: 1},
		{name: "another writer's temporary file is untouched", status: audit.Pass, statusPath: "good", keepTemp: true, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if (tt.log == "full" || tt.fullConsole) && runtime.GOOS != "linux" {
				t.Skip("/dev/full is a Linux write-failure control")
			}
			dir := t.TempDir()
			output := func(kind, name string) string {
				switch kind {
				case "":
					return ""
				case "missing":
					return filepath.Join(dir, "missing", name)
				case "directory":
					return dir
				case "full":
					return "/dev/full"
				default:
					return filepath.Join(dir, name)
				}
			}
			logPath, statusPath := output(tt.log, "audit.jsonl"), output(tt.statusPath, "status.json")
			if tt.alias == "case" && runtime.GOOS != "windows" {
				t.Skip("Windows case-insensitive path control")
			}
			if tt.alias != "" {
				seed := audit.Report{Started: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), Results: []audit.Result{{Check: "previous-check", Status: audit.Pass, Checked: 1}}}
				b, err := json.Marshal(seed)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(logPath, append(b, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
				switch tt.alias {
				case "same":
					statusPath = logPath
				case "dot":
					statusPath = dir + string(os.PathSeparator) + "." + string(os.PathSeparator) + "audit.jsonl"
				case "case":
					statusPath = filepath.Join(dir, "AUDIT.JSONL")
					if _, err := os.Stat(statusPath); os.IsNotExist(err) {
						t.Skip("case-sensitive filesystem")
					} else if err != nil {
						t.Fatal(err)
					}
				case "symlink":
					statusPath = logPath
					logPath = filepath.Join(dir, "log-link.jsonl")
					if err := os.Symlink(statusPath, logPath); err != nil {
						t.Skipf("symlink unavailable: %v", err)
					}
				case "hardlink":
					statusPath = filepath.Join(dir, "status.json")
					if err := os.Link(logPath, statusPath); err != nil {
						t.Fatal(err)
					}
				}
			}
			marker := filepath.Join(dir, ".status.json.tmp")
			if tt.keepTemp {
				if err := os.WriteFile(marker, []byte("belongs to another writer"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			started := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
			if tt.invalidTime {
				started = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			}
			rep := audit.Report{Started: started, Results: []audit.Result{{Check: "test-check", Status: tt.status, Checked: 1}}}
			var code int
			if tt.fullConsole {
				f, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				stdout := os.Stdout
				os.Stdout = f
				code = report(rep, logPath, statusPath, tt.allowSkips)
				os.Stdout = stdout
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				code = report(rep, logPath, statusPath, tt.allowSkips)
			}
			if got := code; got != tt.wantCode {
				t.Fatalf("report exit = %d, want %d", got, tt.wantCode)
			}
			if tt.statusPath == "good" && !tt.invalidTime {
				raw, err := os.ReadFile(statusPath)
				if err != nil {
					t.Fatal(err)
				}
				var status struct {
					OK       bool
					Counts   map[audit.Status]int
					Problems []string
				}
				if err := json.Unmarshal(raw, &status); err != nil {
					t.Fatal(err)
				}
				if status.OK != tt.wantOK || status.Counts[tt.status] != 1 || status.Problems == nil {
					t.Fatalf("status: %s", raw)
				}
			}
			if tt.log == "good" && !tt.invalidTime {
				raw, err := os.ReadFile(logPath)
				if err != nil {
					t.Fatal(err)
				}
				var got audit.Report
				if tt.alias != "" {
					lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
					if len(lines) != 2 || !strings.Contains(lines[0], "previous-check") {
						t.Fatalf("log history was lost: %s", raw)
					}
					raw = []byte(lines[1])
				}
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatal(err)
				}
				if len(got.Results) != 1 || got.Results[0].Status != tt.status {
					t.Fatalf("log: %s", raw)
				}
			}
			if tt.keepTemp {
				raw, err := os.ReadFile(marker)
				if err != nil || string(raw) != "belongs to another writer" {
					t.Fatalf("another writer's temporary file changed: %q, %v", raw, err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name()[0] == '.' && !(tt.keepTemp && entry.Name() == ".status.json.tmp") {
					t.Fatalf("temporary output left behind: %s", entry.Name())
				}
			}
		})
	}
}

// Not a row of TestReportOutput: a stop is decided around the run, before any report is built.
func TestAStoppedRun(t *testing.T) {
	failing := audit.Check{Name: "failing-check", Run: func(context.Context) audit.Outcome {
		return audit.Outcome{Checked: 1, Problems: []string{"the wall is open"}}
	}}
	passing := audit.Check{Name: "passing-check", Run: func(context.Context) audit.Outcome { return audit.Outcome{Checked: 1} }}
	tests := []struct {
		name     string
		first    audit.Check // finishes before the stop
		code     int
		recorded bool
	}{
		{"records nothing when nothing was found", passing, 0, false},
		{"reports what a finished check found", failing, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			logPath, statusPath := filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "status.json")
			previous := map[string]string{logPath: `{"started":"2026-10-06T00:00:00Z","results":[]}` + "\n", statusPath: `{"ok": true}`}
			for path, content := range previous {
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			interrupted := audit.Check{Name: "interrupted-check", Run: func(ctx context.Context) audit.Outcome {
				cancel() // the stop request arrives while the check runs, long before its time limit
				<-ctx.Done()
				return audit.Outcome{Checked: 1}
			}}
			code, stopped := audited(ctx, []audit.Check{tt.first, interrupted}, time.Hour, logPath, statusPath, false)
			if !stopped || code != tt.code {
				t.Fatalf("exit %d, stopped %v; want exit %d, stopped", code, stopped, tt.code)
			}
			status, err := os.ReadFile(statusPath)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.recorded {
				for path, want := range previous {
					if got, err := os.ReadFile(path); err != nil || string(got) != want {
						t.Errorf("%s changed: %q, %v", filepath.Base(path), got, err)
					}
				}
				return
			}
			if !strings.Contains(string(status), `"ok": false`) || !strings.Contains(string(status), "the wall is open") ||
				!strings.Contains(string(status), audit.StoppedNote) {
				t.Errorf("status does not report the finding and the stop: %s", status)
			}
			if got, _ := os.ReadFile(logPath); !strings.Contains(string(got), "failing-check") {
				t.Errorf("log does not carry the run: %s", got)
			}
		})
	}
}

// Without the edge's allow list origin-guard would check an empty one and pass whatever the edge allows, so it is skipped;
// given "" (the edge has none) it runs. Not a table of the audit package: it is what this command makes of its flags.
func TestOriginGuardNeedsTheEdgesAllowList(t *testing.T) {
	zm := audit.Map{Here: "edge", Zones: []audit.Zone{{Name: "edge"}}}
	for _, given := range []bool{false, true} {
		var guard *audit.Check
		checks := catalogue(zm, proxy.OriginPolicy{}, given)
		for i := range checks {
			if checks[i].Name == "origin-guard" {
				guard = &checks[i]
			}
		}
		if guard == nil {
			t.Fatal("no origin-guard from the edge")
		}
		r := audit.Run(context.Background(), []audit.Check{*guard}, time.Second).Results[0]
		if want := map[bool]audit.Status{false: audit.Skip, true: audit.Pass}[given]; r.Status != want {
			t.Fatalf("allow list given %v: %+v, want %s", given, r, want)
		}
	}
}
