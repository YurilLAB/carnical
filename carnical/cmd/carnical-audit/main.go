// SPDX-License-Identifier: Apache-2.0

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
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/YurilLAB/coraza/carnical/audit"
	"github.com/YurilLAB/coraza/carnical/audit/host"
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
	hostChecks := flag.Bool("host", false, "also check this machine: kernel settings, mounts, the services' sandboxes, network and audit rules, who is listening, what is running, whether anything that should not change has changed (Linux; needs root to see other users' processes)")
	baselineDir := flag.String("baseline-dir", "/var/lib/carnical/host-audit", "where the integrity and setuid baselines are kept: a directory only the user running the host checks (root) owns and can write")
	writeBaseline := flag.Bool("write-baseline", false, "record the current integrity and setuid state as the baseline, and exit (run it once, when the machine is known to be good)")
	force := flag.Bool("force", false, "with -write-baseline, replace a baseline that exists (a baseline rewritten by whoever changed the machine proves nothing)")
	schedule := flag.String("print-schedule", "", "print how to run this on a schedule (systemd or schtasks) and exit; nothing is installed")
	flag.Parse()

	if *jitter < 0 || (*watch && *every <= 0) {
		fmt.Fprintln(os.Stderr, "carnical-audit: jitter must not be negative and a watch interval must be positive")
		return 2
	}

	if *schedule != "" {
		text, ok := scheduleText(*schedule)
		if !ok {
			fmt.Fprintln(os.Stderr, "carnical-audit: -print-schedule takes systemd or schtasks")
			return 2
		}
		fmt.Print(text)
		return 0
	}
	if *writeBaseline {
		return writeBaselines(*baselineDir, *force) // the baselines are of this machine, not of the zones
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
	err = errors.Join(err, f.Close())
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
	if *hostChecks {
		checks = append(checks, hostCatalogue(zm, *baselineDir)...)
	}
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
			delay, err := rand.Int(rand.Reader, big.NewInt(int64(*jitter)))
			if err != nil {
				fmt.Fprintln(os.Stderr, "carnical-audit: jitter:", err)
				return 1
			}
			select {
			case <-time.After(time.Duration(delay.Int64())):
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

// hostCatalogue is the checks of the machine itself. They are not tied to a zone: the machine is one place.
func hostCatalogue(zm audit.Map, baselineDir string) []audit.Check {
	var src host.OS
	var declared []audit.Service
	for _, z := range zm.Zones {
		declared = append(declared, z.Services...)
	}
	return []audit.Check{
		host.Sysctl(src, host.Sysctls),
		host.Mount(src, host.Mounts),
		host.Unit(src, host.EdgeUnit),
		host.NFT(src),
		host.Auditd(src),
		host.Ownership(src, host.Files),
		host.Listeners(src, declared),
		host.Running(src, host.DefaultProcs),
		host.Confined(src, host.DefaultEdge),
		host.Integrity(src, filepath.Join(baselineDir, "integrity.json")),
		host.SUID(src, filepath.Join(baselineDir, "suid.json")),
	}
}

func writeBaselines(dir string, replace bool) int {
	var src host.OS
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "carnical-audit:", err)
		return 1
	}
	ctx := context.Background()
	if err := host.WriteIntegrity(src, filepath.Join(dir, "integrity.json"), host.IntegrityFiles, replace); err != nil {
		fmt.Fprintln(os.Stderr, "carnical-audit:", err)
		return 1
	}
	if err := host.WriteSUID(ctx, src, filepath.Join(dir, "suid.json"), replace); err != nil {
		fmt.Fprintln(os.Stderr, "carnical-audit:", err)
		return 1
	}
	fmt.Println("recorded the baselines in", dir, "- copy them somewhere an attacker on this machine cannot reach")
	return 0
}

func report(rep audit.Report, logFile, statusFile string, allowSkips bool) int {
	counts := rep.Counts()
	outputFailed := false
	for _, r := range rep.Results {
		line := fmt.Sprintf("%-5s %-26s %d cases", r.Status, r.Check, r.Checked)
		if r.Note != "" {
			line += " (" + r.Note + ")"
		}
		if _, err := fmt.Println(line); err != nil {
			fmt.Fprintln(os.Stderr, "carnical-audit: the console:", err)
			outputFailed = true
		}
		for _, p := range r.Problems {
			if _, err := fmt.Println("        -", p); err != nil {
				fmt.Fprintln(os.Stderr, "carnical-audit: the console:", err)
				outputFailed = true
			}
		}
	}
	if logFile != "" {
		if err := writeLog(logFile, rep); err != nil {
			fmt.Fprintln(os.Stderr, "carnical-audit: the log:", err)
			outputFailed = true
		}
	}
	statusSafe := true
	if logFile != "" && statusFile != "" {
		same, err := sameOutputFile(logFile, statusFile)
		if err != nil || same {
			if same {
				err = errors.New("log and status outputs must be different files")
			}
			fmt.Fprintln(os.Stderr, "carnical-audit: the output paths:", err)
			outputFailed = true
			statusSafe = false // Do not replace the requested log history.
		}
	}
	ok := rep.OK(allowSkips) && !outputFailed
	if statusFile != "" && statusSafe {
		if err := writeStatus(statusFile, rep, ok); err != nil {
			fmt.Fprintln(os.Stderr, "carnical-audit: the status file:", err)
			outputFailed = true
		}
	}

	switch {
	case outputFailed || counts[audit.Fail]+counts[audit.Error] > 0 || len(rep.Results) == 0:
		return 1
	case !ok:
		return 3
	}
	return 0
}

// sameOutputFile checks after log creation, including filesystem case and symlink aliases.
// Output directories are operator-owned; concurrent changes to those directories are not supported.
func sameOutputFile(logPath, statusPath string) (bool, error) {
	logAbs, err := filepath.Abs(logPath)
	if err != nil {
		return false, err
	}
	statusAbs, err := filepath.Abs(statusPath)
	if err != nil {
		return false, err
	}
	if logAbs == statusAbs {
		return true, nil
	}
	logInfo, err := os.Stat(logAbs)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	statusInfo, err := os.Stat(statusAbs)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(logInfo, statusInfo), nil
}

// writeLog appends a complete report and surfaces write, sync and close failures.
func writeLog(path string, rep audit.Report) error {
	b, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	// #nosec G304 -- path is an operator-supplied CLI output; no request or tenant input selects it.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

// writeStatus writes a complete temporary file before replacing the destination.
func writeStatus(path string, rep audit.Report, ok bool) (err error) {
	problems := rep.Problems()
	if problems == nil {
		problems = []string{} // "[]" and not "null", for whatever reads the file
	}
	b, err := json.MarshalIndent(struct {
		When     time.Time `json:"when"`
		OK       bool      `json:"ok"`
		Counts   any       `json:"counts"`
		Problems []string  `json:"problems"`
	}{rep.Started, ok, rep.Counts(), problems}, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(tmp))
		}
	}()
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
ExecStart=/usr/local/bin/carnical-audit -zones /etc/carnical/zones.json -origin-allow "" -log /var/log/carnical/audit.jsonl -status /var/lib/carnical/audit/audit-status.json
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/carnical /var/lib/carnical/audit

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
