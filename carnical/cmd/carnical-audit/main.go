// Command carnical-audit runs the segmentation checks: the walls between Carnical's zones and between its customers.
//
// It is meant to run a few times a day from each place that matters (the edge, and an outside vantage point that acts
// as a customer would), and to be loud when something is wrong:
//
//	carnical-audit -zones /etc/carnical/zones.json -origin-allow 10.7.0.0/24 -log audit.jsonl -status audit-status.json
//
// Exit status: 0 everything passed, 1 something failed or broke, 3 nothing failed but a check could not run (a
// skipped check is not a pass), 2 a usage error. It installs nothing: -print-schedule only prints what to install.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/YurilLAB/coraza/carnical/audit"
	"github.com/YurilLAB/coraza/carnical/proxy"
)

func main() {
	os.Exit(run())
}

func run() int {
	zonesFile := flag.String("zones", "", "the zone map (JSON); required")
	originAllow := flag.String("origin-allow", "", "the edge's -origin-allow value, so the check sees the policy the edge really runs with")
	logFile := flag.String("log", "", "append each report to this file, one JSON line per run")
	statusFile := flag.String("status", "", "write a short status file here after each run (for the owner's health view)")
	allowSkips := flag.Bool("allow-skips", false, "do not treat a check that could not run as a problem")
	perCheck := flag.Duration("timeout", 2*time.Minute, "time limit for each check")
	watch := flag.Bool("watch", false, "keep running instead of once")
	every := flag.Duration("every", 6*time.Hour, "with -watch, how long between runs")
	jitter := flag.Duration("jitter", 0, "wait a random time up to this long before each run, so the runs are not predictable")
	list := flag.Bool("list", false, "list the checks and exit")
	schedule := flag.String("print-schedule", "", "print how to run this on a schedule (systemd or schtasks) and exit; nothing is installed")
	flag.Parse()

	if *schedule != "" {
		text, ok := scheduleText(*schedule)
		if !ok {
			fmt.Fprintln(os.Stderr, "carnical-audit: -print-schedule takes systemd or schtasks")
			return 2
		}
		fmt.Print(text)
		return 0
	}
	if *zonesFile == "" {
		fmt.Fprintln(os.Stderr, "carnical-audit: -zones is required")
		return 2
	}
	f, err := os.Open(*zonesFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "carnical-audit:", err)
		return 2
	}
	zm, err := audit.LoadMap(f)
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "carnical-audit:", err)
		return 2
	}
	allow, err := proxy.ParseOriginAllow(*originAllow)
	if err != nil {
		fmt.Fprintln(os.Stderr, "carnical-audit:", err)
		return 2
	}
	checks := catalogue(zm, proxy.OriginPolicy{Allow: allow})
	if *list {
		for _, c := range checks {
			fmt.Printf("%-26s from %-8s %s\n", c.Name, c.Zone, c.What)
		}
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := 0
	for {
		if *jitter > 0 {
			select {
			case <-time.After(rand.N(*jitter)):
			case <-ctx.Done():
				return code
			}
		}
		rep := audit.Run(ctx, checks, *perCheck)
		code = report(rep, *logFile, *statusFile, *allowSkips)
		if !*watch {
			return code
		}
		select {
		case <-time.After(*every):
		case <-ctx.Done():
			return code
		}
	}
}

// catalogue is every check that makes sense from the zone this machine is in.
func catalogue(zm audit.Map, policy proxy.OriginPolicy) []audit.Check {
	var d net.Dialer
	all := []audit.Check{audit.OriginGuard(zm, policy), audit.ZoneReach(zm, d.DialContext)}
	// The tenant checks need a deployment with canary tenants to act against. None is connected yet, so they report
	// that they could not run, which is a visible gap and not a pass.
	all = append(all, audit.TenantChecks(nil)...)
	var mine []audit.Check
	for _, c := range all {
		if c.Zone == "" || c.Zone == zm.Here {
			mine = append(mine, c)
		}
	}
	return mine
}

func report(rep audit.Report, logFile, statusFile string, allowSkips bool) int {
	counts := rep.Counts()
	for _, r := range rep.Results {
		line := fmt.Sprintf("%-5s %-26s %d cases", r.Status, r.Check, r.Checked)
		if r.Note != "" {
			line += " (" + r.Note + ")"
		}
		fmt.Println(line)
		for _, p := range r.Problems {
			fmt.Println("        -", p)
		}
	}
	if logFile != "" {
		if b, err := json.Marshal(rep); err == nil {
			if f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
				f.Write(append(b, '\n'))
				f.Close()
			} else {
				fmt.Fprintln(os.Stderr, "carnical-audit: the log:", err)
			}
		}
	}
	ok := rep.OK(allowSkips)
	if statusFile != "" {
		writeStatus(statusFile, rep, ok)
	}
	switch {
	case counts[audit.Fail]+counts[audit.Error] > 0 || len(rep.Results) == 0:
		return 1
	case !ok:
		return 3
	}
	return 0
}

// writeStatus replaces the status file in one step, so a reader never sees half of it.
func writeStatus(path string, rep audit.Report, ok bool) {
	problems := rep.Problems()
	if problems == nil {
		problems = []string{} // "[]" and not "null", for whatever reads the file
	}
	b, _ := json.MarshalIndent(struct {
		When     time.Time `json:"when"`
		OK       bool      `json:"ok"`
		Counts   any       `json:"counts"`
		Problems []string  `json:"problems"`
	}{rep.Started, ok, rep.Counts(), problems}, "", "  ")
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "carnical-audit: the status file:", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		fmt.Fprintln(os.Stderr, "carnical-audit: the status file:", err)
	}
}

func scheduleText(kind string) (string, bool) {
	switch kind {
	case "systemd":
		return `# /etc/systemd/system/carnical-audit.service
[Unit]
Description=Carnical segmentation audit

[Service]
Type=oneshot
User=carnical-audit
ExecStart=/usr/local/bin/carnical-audit -zones /etc/carnical/zones.json -origin-allow "" -log /var/log/carnical/audit.jsonl -status /var/lib/carnical/audit-status.json
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/carnical /var/lib/carnical

# /etc/systemd/system/carnical-audit.timer   (four runs a day, each a random time up to 45 minutes late)
[Unit]
Description=Run the Carnical segmentation audit four times a day

[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
RandomizedDelaySec=45min
Persistent=true

[Install]
WantedBy=timers.target

# then: systemctl daemon-reload && systemctl enable --now carnical-audit.timer
`, true
	case "schtasks":
		return `rem Four runs a day, each a random time up to 45 minutes late. Edit the paths, then run this once, by hand.
schtasks /Create /TN "Carnical\Audit" /SC HOURLY /MO 6 /ST 00:15 /RL LIMITED /TR "\"C:\Carnical\carnical-audit.exe\" -jitter 45m -zones C:\Carnical\zones.json -log C:\Carnical\audit.jsonl -status C:\Carnical\audit-status.json"
`, true
	}
	return "", false
}
