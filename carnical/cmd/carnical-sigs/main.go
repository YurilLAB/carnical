// SPDX-License-Identifier: Apache-2.0

// Command carnical-sigs converts rules published in other formats into Carnical signatures (vpatch.Signature, one JSON object per line).
//
//	carnical-sigs convert -format crowdsec|suricata|nuclei|seclang -in PATH -out signatures.jsonl [-report report.json] [-tier community]
//	carnical-sigs legacy  -format crowdsec|suricata|nuclei -sigs signatures.jsonl -legacy legacy.jsonl [-out comparison.json]
//
// convert reads one rule file or every matching file under a directory, and writes the signatures and a report of what was read,
// converted and skipped, and why. legacy compares converted signatures with the signature library that was built from the same
// sources earlier, rule by rule, and says where they agree and where they do not.
//
// The input is untrusted rule text: it is read with size limits, never executed, and a rule that cannot be converted exactly is
// skipped with a reason, not approximated silently.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers/crowdsec"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers/legacy"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers/nuclei"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers/seclang"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers/suricata"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

var formats = map[string]importers.Format{
	"crowdsec": crowdsec.Format,
	"suricata": suricata.Format,
	"nuclei":   nuclei.Format,
	"seclang":  seclang.Format,
}

func formatNames() string {
	names := importers.SortedKeys(formats)
	return strings.Join(names, "|")
}

const usage = `usage:
  carnical-sigs convert -format %s -in PATH -out signatures.jsonl [-report report.json] [-tier community] [-revision REV]
  carnical-sigs legacy  -format crowdsec|suricata|nuclei -sigs signatures.jsonl -legacy legacy.jsonl [-out comparison.json]
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, formatNames())
		return 2
	}
	switch args[0] {
	case "convert":
		return runConvert(args[1:], stdout, stderr)
	case "legacy":
		return runLegacy(args[1:], stdout, stderr)
	case "-h", "-help", "--help", "help":
		fmt.Fprintf(stdout, usage, formatNames())
		return 0
	}
	fmt.Fprintf(stderr, "carnical-sigs: unknown command %q\n", args[0])
	fmt.Fprintf(stderr, usage, formatNames())
	return 2
}

func runConvert(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("convert", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "", "input format: "+formatNames())
	in := fs.String("in", "", "a rule file, or a directory of them")
	out := fs.String("out", "", "where to write the signatures, one JSON object per line (- for standard output)")
	report := fs.String("report", "", "where to write the report (JSON); a short summary is always printed to standard error")
	tier := fs.String("tier", vpatch.TierCommunity, "the tier a signature converted without loss gets: verified, community or experimental")
	revision := fs.String("revision", "", "the revision written after @ in Sources; default the rule's own revision, the checkout's commit, or a hash of the file")
	copyleft := fs.Bool("allow-copyleft", false, "suricata: also convert rules whose licence is not BSD (the GPLv2 sids of the Emerging Threats files)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, ok := formats[*format]
	if !ok {
		fmt.Fprintf(stderr, "carnical-sigs convert: -format must be one of %s\n", formatNames())
		return 2
	}
	if *in == "" || *out == "" {
		fmt.Fprintln(stderr, "carnical-sigs convert: -in and -out are required")
		return 2
	}
	switch *tier {
	case vpatch.TierVerified, vpatch.TierCommunity, vpatch.TierExperimental:
	default:
		fmt.Fprintf(stderr, "carnical-sigs convert: -tier must be %s, %s or %s\n", vpatch.TierVerified, vpatch.TierCommunity, vpatch.TierExperimental)
		return 2
	}
	rev := *revision
	if rev == "" && (*format == "crowdsec" || *format == "nuclei") {
		rev = importers.DiscoverRevision(*in)
	}
	res, err := importers.Run(f, *in, importers.Options{Tier: *tier, Revision: rev, AllowCopyleft: *copyleft})
	if err != nil {
		fmt.Fprintf(stderr, "carnical-sigs convert: %v\n", err)
		return 1
	}
	var buf bytes.Buffer
	if err := importers.WriteJSONL(&buf, res.Signatures); err != nil {
		fmt.Fprintf(stderr, "carnical-sigs convert: %v\n", err)
		return 1
	}
	if *out == "-" {
		stdout.Write(buf.Bytes())
	} else if err := writeFile(*out, buf.Bytes()); err != nil {
		fmt.Fprintf(stderr, "carnical-sigs convert: %v\n", err)
		return 1
	}
	if *report != "" {
		var rb bytes.Buffer
		if err := res.Report.WriteJSON(&rb); err != nil {
			fmt.Fprintf(stderr, "carnical-sigs convert: %v\n", err)
			return 1
		}
		if err := writeFile(*report, rb.Bytes()); err != nil {
			fmt.Fprintf(stderr, "carnical-sigs convert: %v\n", err)
			return 1
		}
	}
	summary(stderr, res.Report)
	if res.Report.Signatures == 0 {
		fmt.Fprintln(stderr, "carnical-sigs convert: nothing was converted")
		return 1
	}
	return 0
}

// summary prints what the report says that a person wants to see first.
func summary(w io.Writer, r importers.Report) {
	fmt.Fprintf(w, "%s: %d files read, %d rules read, %d converted, %d signatures, %d skipped\n",
		r.Format, r.FilesRead, r.UnitsRead, r.UnitsConverted, r.Signatures, r.SkippedTotal())
	for _, rc := range r.TopSkips(10) {
		fmt.Fprintf(w, "  skipped %6d  %s\n", rc.Count, rc.Reason)
	}
	if len(r.Dropped) > 0 {
		fmt.Fprintf(w, "  lost a constraint (one tier lower): %s\n", countsLine(r.Dropped))
	}
	if len(r.Approximations) > 0 {
		fmt.Fprintf(w, "  approximations: %s\n", countsLine(r.Approximations))
	}
	fmt.Fprintf(w, "  tiers: %s\n", countsLine(r.Tiers))
	fmt.Fprintf(w, "  regular expressions: %d seen, %d compile as written, %d after an exact translation, %d refused\n",
		r.Regex.Seen, r.Regex.Compiled, r.Regex.Translated, r.Regex.Failed)
	for _, e := range r.Errors {
		fmt.Fprintf(w, "  problem: %s\n", e)
	}
}

func countsLine(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// writeFile writes through a temporary file in the same directory and renames it, so an interrupted run never leaves half a file.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".carnical-sigs-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func runLegacy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("legacy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "", "which sources to compare: crowdsec, suricata or nuclei")
	sigs := fs.String("sigs", "", "signatures written by convert")
	lib := fs.String("legacy", "", "the earlier signature library (JSON lines with _origin and _status)")
	out := fs.String("out", "", "where to write the comparison (JSON); default standard output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *format != "crowdsec" && *format != "suricata" && *format != "nuclei" {
		fmt.Fprintln(stderr, "carnical-sigs legacy: -format must be crowdsec, suricata or nuclei")
		return 2
	}
	if *sigs == "" || *lib == "" {
		fmt.Fprintln(stderr, "carnical-sigs legacy: -sigs and -legacy are required")
		return 2
	}
	mine, err := readSigs(*sigs)
	if err != nil {
		fmt.Fprintf(stderr, "carnical-sigs legacy: %v\n", err)
		return 1
	}
	fh, err := os.Open(*lib)
	if err != nil {
		fmt.Fprintf(stderr, "carnical-sigs legacy: %v\n", err)
		return 1
	}
	defer fh.Close()
	recs, err := legacy.ReadLibrary(fh)
	if err != nil {
		fmt.Fprintf(stderr, "carnical-sigs legacy: %v\n", err)
		return 1
	}
	cmp := legacy.Compare(*format, mine, recs)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cmp); err != nil {
		fmt.Fprintf(stderr, "carnical-sigs legacy: %v\n", err)
		return 1
	}
	if *out == "" {
		stdout.Write(buf.Bytes())
	} else if err := writeFile(*out, buf.Bytes()); err != nil {
		fmt.Fprintf(stderr, "carnical-sigs legacy: %v\n", err)
		return 1
	}
	cmp.WriteSummary(stderr)
	return 0
}

func readSigs(path string) ([]vpatch.Signature, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return importers.ReadJSONL(fh, 0)
}
