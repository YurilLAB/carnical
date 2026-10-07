// SPDX-License-Identifier: Apache-2.0

// Command carnical-vpatch loads, checks and converts virtual-patch signature libraries, and measures what a library does to real
// and ordinary requests, with the same engine the proxy runs.
//
//	carnical-vpatch load     -in FILE [-tiers verified,community,experimental] [-scope wordpress,php] [-exclude CRS-] [-v]
//	carnical-vpatch validate -sigs legacy.jsonl -samples samples.jsonl [-tiers ...] [-v]
//	carnical-vpatch replay   -sigs legacy.jsonl -benign benign.jsonl -attack attack.jsonl [-tiers ...] [-verify-index] [-v]
//	carnical-vpatch convert  -in legacy.jsonl -out pack.yaml [-tiers ...] [-name N] [-version V]
//
// Files named *.jsonl are read as the signature library's JSON lines; anything else as a pack (YAML or JSON), unless -format says
// otherwise. Exit status: 0 on success, 1 if something could not be read or checked, 2 for a usage error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/YurilLAB/coraza/carnical/vpatch"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usage = `usage: carnical-vpatch <command> [flags]

commands:
  load      read a signature file and print what the engine loads from it, and what it refuses and why
  validate  run every signature's own samples: each attack sample must match it, each benign sample must not
  replay    run the engine over a corpus of benign and attack requests and report false positives and detection
  convert   write a legacy JSON-lines library as a Carnical pack

Run "carnical-vpatch <command> -h" for a command's flags.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "help" {
		fmt.Fprint(stderr, usage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	var err error
	switch args[0] {
	case "load":
		err = cmdLoad(args[1:], stdout, stderr)
	case "validate":
		err = cmdValidate(args[1:], stdout, stderr)
	case "replay":
		err = cmdReplay(args[1:], stdout, stderr)
	case "convert":
		err = cmdConvert(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "carnical-vpatch: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err == nil {
		return 0
	}
	if _, ok := err.(usageError); ok {
		fmt.Fprintln(stderr, "carnical-vpatch:", err)
		return 2
	}
	fmt.Fprintln(stderr, "carnical-vpatch:", err)
	return 1
}

type usageError string

func (e usageError) Error() string { return string(e) }

// parse parses a command's flags; -h is not an error.
func parse(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return errHelp
		}
		return usageError(err.Error())
	}
	return nil
}

var errHelp = fmt.Errorf("help shown")

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseTiers(s string) ([]string, error) {
	tiers := splitList(s)
	if len(tiers) == 0 {
		return []string{vpatch.TierVerified}, nil
	}
	for _, t := range tiers {
		switch t {
		case vpatch.TierVerified, vpatch.TierCommunity, vpatch.TierExperimental:
		default:
			return nil, usageError(fmt.Sprintf("-tiers: %q is not a tier (verified, community, experimental)", t))
		}
	}
	return tiers, nil
}

func readSignatures(path, format string) ([]vpatch.Signature, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if format == "auto" || format == "" {
		switch {
		case strings.HasSuffix(path, ".jsonl") || strings.HasSuffix(path, ".ndjson"):
			format = "legacy"
		default:
			format = "pack"
		}
	}
	switch format {
	case "legacy":
		return vpatch.ReadLegacy(f)
	case "pack":
		p, err := vpatch.ReadPack(f)
		return p.Signatures, err
	}
	return nil, usageError(fmt.Sprintf("-format: %q is not legacy, pack or auto", format))
}

func tierOf(s vpatch.Signature) string {
	if s.Tier == "" {
		return vpatch.TierVerified
	}
	return s.Tier
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func printReport(w io.Writer, rep vpatch.LoadReport, verbose bool) {
	fmt.Fprintf(w, "offered %d signatures; loaded %d in %v\n", rep.Offered, rep.LoadedTotal, rep.Elapsed.Round(time.Millisecond))
	for _, t := range []string{vpatch.TierVerified, vpatch.TierCommunity, vpatch.TierExperimental} {
		if n, ok := rep.Loaded[t]; ok {
			fmt.Fprintf(w, "  %-13s %6d\n", t, n)
		}
	}
	if len(rep.Skipped) > 0 {
		fmt.Fprintf(w, "not wanted (left out on purpose):")
		for _, k := range sortedKeys(rep.Skipped) {
			fmt.Fprintf(w, " %s %d;", k, rep.Skipped[k])
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "index: %d signatures found through %d literals, %d checked on every request\n", rep.Indexed, rep.Literals, rep.Unindexed)
	if len(rep.Translated) > 0 {
		fmt.Fprintln(w, "regular expressions rewritten from PCRE to RE2 (each is exact, or matches a little more, never less):")
		for _, k := range sortedKeys(rep.Translated) {
			fmt.Fprintf(w, "  %6d  %s\n", rep.Translated[k], k)
		}
	}
	for _, warn := range rep.Warnings {
		fmt.Fprintln(w, "warning:", warn)
	}
	fmt.Fprintf(w, "rejected: %d\n", len(rep.Rejected))
	if len(rep.Rejected) == 0 {
		return
	}
	if verbose {
		for _, r := range rep.Rejected {
			fmt.Fprintf(w, "  %s: %s\n", r.ID, r.Reason)
		}
		return
	}
	groups := map[string][]string{}
	for _, r := range rep.Rejected {
		groups[stripWhere(r.Reason)] = append(groups[stripWhere(r.Reason)], r.ID)
	}
	reasons := make([]string, 0, len(groups))
	for k := range groups {
		reasons = append(reasons, k)
	}
	sort.Slice(reasons, func(a, b int) bool {
		if len(groups[reasons[a]]) != len(groups[reasons[b]]) {
			return len(groups[reasons[a]]) > len(groups[reasons[b]])
		}
		return reasons[a] < reasons[b]
	})
	for _, k := range reasons {
		ids := groups[k]
		shown := ids
		if len(shown) > 3 {
			shown = shown[:3]
		}
		fmt.Fprintf(w, "  %5d  %s  (%s%s)\n", len(ids), k, strings.Join(shown, ", "), map[bool]string{true: ", ...", false: ""}[len(ids) > 3])
	}
	fmt.Fprintln(w, "  (-v lists every one)")
}

// stripWhere drops the "condition 2 of Also:" prefix so that the same fault in different places groups together.
func stripWhere(reason string) string {
	if i := strings.Index(reason, ": "); i >= 0 && (strings.HasPrefix(reason, "condition ") || strings.HasPrefix(reason, "the main condition")) {
		return reason[i+2:]
	}
	return reason
}

func newEngine(tiers, scope, exclude []string, block bool) *vpatch.Engine {
	mode := vpatch.ModeMonitor
	if block {
		mode = vpatch.ModeBlock
	}
	return vpatch.New(vpatch.Options{Tiers: tiers, Scope: scope, Exclude: exclude, Mode: mode})
}

func cmdLoad(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	in := fs.String("in", "", "the signature file (required)")
	format := fs.String("format", "auto", "legacy (JSON lines), pack, or auto (by file name)")
	tiers := fs.String("tiers", "verified", "comma-separated tiers to load")
	scope := fs.String("scope", "", "comma-separated software tags the site declares (a signature with a scope loads only if it matches)")
	exclude := fs.String("exclude", "", "comma-separated signature ID prefixes to leave out, such as CRS-")
	verbose := fs.Bool("v", false, "list every rejected signature and every signature that is checked on every request")
	if err := parse(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}
	if *in == "" {
		return usageError("-in is required")
	}
	tl, err := parseTiers(*tiers)
	if err != nil {
		return err
	}
	sigs, err := readSignatures(*in, *format)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "read %d signatures from %s\n", len(sigs), *in)
	e := newEngine(tl, splitList(*scope), splitList(*exclude), false)
	rep := e.Load(sigs)
	printReport(stdout, rep, *verbose)
	st := e.Stats()
	fmt.Fprintf(stdout, "tiers loaded: %v\n", tl)
	_ = st
	return nil
}

func cmdValidate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	sigsPath := fs.String("sigs", "", "the signature library (required)")
	samplesPath := fs.String("samples", "", "the samples file (required)")
	format := fs.String("format", "auto", "legacy, pack or auto")
	tiers := fs.String("tiers", "verified", "comma-separated tiers to check")
	verbose := fs.Bool("v", false, "one line per signature")
	if err := parse(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}
	if *sigsPath == "" || *samplesPath == "" {
		return usageError("-sigs and -samples are required")
	}
	tl, err := parseTiers(*tiers)
	if err != nil {
		return err
	}
	sigs, err := readSignatures(*sigsPath, *format)
	if err != nil {
		return err
	}
	sf, err := os.Open(*samplesPath)
	if err != nil {
		return err
	}
	samples, err := vpatch.ReadSamples(sf)
	sf.Close()
	if err != nil {
		return err
	}
	e := newEngine(tl, nil, nil, false)
	rep := e.Load(sigs)
	fmt.Fprintf(stdout, "loaded %d signatures (%d rejected); %d samples\n", rep.LoadedTotal, len(rep.Rejected), len(samples))
	results := vpatch.ValidateSamples(e, sigs, samples)
	type tot struct {
		loaded, withAttacks, allCaught, most, benignTripped, none, fullPass int
		attacks, caught, benign, tripped                                    int
	}
	totals := map[string]*tot{}
	var failing []string
	for _, r := range results {
		if !r.Loaded {
			continue
		}
		t := totals[r.Tier]
		if t == nil {
			t = &tot{}
			totals[r.Tier] = t
		}
		t.loaded++
		t.attacks += r.Attacks
		t.caught += r.AttacksCaught
		t.benign += r.Benign
		t.tripped += r.BenignTripped
		switch {
		case r.Attacks == 0:
			t.none++
		case r.AttacksCaught == r.Attacks:
			t.allCaught++
			t.withAttacks++
			t.most++
		default:
			t.withAttacks++
			if float64(r.AttacksCaught) >= 0.8*float64(r.Attacks) {
				t.most++
			}
		}
		if r.BenignTripped > 0 {
			t.benignTripped++
		}
		if r.Passes() {
			t.fullPass++
		} else {
			failing = append(failing, r.ID)
		}
		if *verbose {
			status := "ok"
			if !r.Passes() {
				status = "FAIL"
			}
			fmt.Fprintf(stdout, "%-4s %-28s %-12s attacks %d/%d  benign tripped %d/%d\n", status, r.ID, r.Tier, r.AttacksCaught, r.Attacks, r.BenignTripped, r.Benign)
		}
	}
	for _, name := range []string{vpatch.TierVerified, vpatch.TierCommunity, vpatch.TierExperimental} {
		t := totals[name]
		if t == nil {
			continue
		}
		fmt.Fprintf(stdout, "%s: %d signatures loaded\n", name, t.loaded)
		fmt.Fprintf(stdout, "  catch all of their own attack samples:      %d  (%d of %d signatures that have attack samples; %d have none)\n", t.allCaught, t.allCaught, t.withAttacks, t.none)
		fmt.Fprintf(stdout, "  catch at least 80%% of them:                 %d\n", t.most)
		fmt.Fprintf(stdout, "  trip one of their own benign samples:       %d\n", t.benignTripped)
		fmt.Fprintf(stdout, "  pass completely (all attacks, no benign):   %d\n", t.fullPass)
		fmt.Fprintf(stdout, "  attack samples caught %d of %d; benign samples tripped %d of %d\n", t.caught, t.attacks, t.tripped, t.benign)
	}
	if !*verbose && len(failing) > 0 {
		sort.Strings(failing)
		shown := failing
		if len(shown) > 40 {
			shown = shown[:40]
		}
		fmt.Fprintf(stdout, "not passing completely (%d): %s", len(failing), strings.Join(shown, " "))
		if len(failing) > len(shown) {
			fmt.Fprint(stdout, " ...")
		}
		fmt.Fprintln(stdout, "\n(-v lists every signature)")
	}
	return nil
}

func cmdReplay(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	sigsPath := fs.String("sigs", "", "the signature library (required)")
	benignPath := fs.String("benign", "", "the benign corpus (JSON lines of requests)")
	attackPath := fs.String("attack", "", "the attack corpus")
	samplesPath := fs.String("samples", "", "a samples file: its benign samples are replayed as benign requests and its attack samples as attacks")
	format := fs.String("format", "auto", "legacy, pack or auto")
	tiers := fs.String("tiers", "verified", "comma-separated tiers to load")
	scope := fs.String("scope", "", "comma-separated software tags the site declares")
	exclude := fs.String("exclude", "", "comma-separated signature ID prefixes to leave out")
	verify := fs.Bool("verify-index", false, "also evaluate every signature on every request and report any request where the index and the full evaluation differ")
	verbose := fs.Bool("v", false, "list every false positive and every missed attack")
	if err := parse(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}
	if *sigsPath == "" || (*benignPath == "" && *attackPath == "" && *samplesPath == "") {
		return usageError("-sigs and at least one of -benign, -attack and -samples are required")
	}
	tl, err := parseTiers(*tiers)
	if err != nil {
		return err
	}
	sigs, err := readSignatures(*sigsPath, *format)
	if err != nil {
		return err
	}
	read := func(path, kind string) ([]vpatch.Sample, error) {
		if path == "" {
			return nil, nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return vpatch.ReadCorpus(f, kind)
	}
	benign, err := read(*benignPath, "benign")
	if err != nil {
		return err
	}
	attack, err := read(*attackPath, "attack")
	if err != nil {
		return err
	}
	if *samplesPath != "" {
		extra, err := read(*samplesPath, "")
		if err != nil {
			return err
		}
		for _, s := range extra {
			if s.Kind == "attack" {
				attack = append(attack, s)
			} else {
				benign = append(benign, s)
			}
		}
	}
	e := newEngine(tl, splitList(*scope), splitList(*exclude), false)
	rep := e.Load(sigs)
	if rep.LoadedTotal == 0 {
		return fmt.Errorf("no signatures loaded; check -tiers, -scope and -exclude")
	}
	fmt.Fprintf(stdout, "loaded %d signatures (tiers %v); %d benign and %d attack requests\n", rep.LoadedTotal, tl, len(benign), len(attack))

	run := func(set []vpatch.Sample) (hits [][]vpatch.Hit, perReq time.Duration) {
		hits = make([][]vpatch.Hit, len(set))
		start := time.Now()
		for i, s := range set {
			hits[i] = s.MatchAny(e)
		}
		if len(set) > 0 {
			perReq = time.Since(start) / time.Duration(len(set))
		}
		return
	}
	if len(benign) > 0 {
		hits, per := run(benign)
		tripped := 0
		bySig := map[string]int{}
		for i, h := range hits {
			if len(h) == 0 {
				continue
			}
			tripped++
			for _, x := range h {
				bySig[x.ID]++
			}
			if *verbose {
				fmt.Fprintf(stdout, "  false positive: %s %s?%.60s [%s] -> %s\n", benign[i].Request.Method, benign[i].Request.Path, benign[i].Request.RawQuery, benign[i].Group, ids(h))
			}
		}
		fmt.Fprintf(stdout, "benign: %d of %d requests matched a signature (%.1f%%); %v per request\n", tripped, len(benign), 100*float64(tripped)/float64(len(benign)), per)
		if len(bySig) > 0 {
			fmt.Fprintf(stdout, "  signatures that matched benign requests (%d): %s\n", len(bySig), topIDs(bySig, 12))
		}
	}
	if len(attack) > 0 {
		hits, per := run(attack)
		caught := 0
		byGroup, totalByGroup := map[string]int{}, map[string]int{}
		for i, h := range hits {
			g := attack[i].Group
			totalByGroup[g]++
			if len(h) > 0 {
				caught++
				byGroup[g]++
			} else if *verbose {
				fmt.Fprintf(stdout, "  missed: %s %s?%.60s [%s]\n", attack[i].Request.Method, attack[i].Request.Path, attack[i].Request.RawQuery, g)
			}
		}
		fmt.Fprintf(stdout, "attack: %d of %d requests matched a signature (%.1f%%); %v per request\n", caught, len(attack), 100*float64(caught)/float64(len(attack)), per)
		var groups []string
		for g := range totalByGroup {
			groups = append(groups, g)
		}
		sort.Strings(groups)
		for _, g := range groups {
			fmt.Fprintf(stdout, "  %-10s %3d of %3d\n", g, byGroup[g], totalByGroup[g])
		}
	}
	if *verify {
		bad := 0
		for _, set := range [][]vpatch.Sample{benign, attack} {
			for _, s := range set {
				if !sameHits(e.Match(s.Request), e.MatchBruteForce(s.Request)) {
					bad++
					fmt.Fprintf(stdout, "  index differs from full evaluation on %s %s\n", s.Request.Method, s.Request.Path)
				}
			}
		}
		fmt.Fprintf(stdout, "index check: %d requests where the index and the full evaluation differ\n", bad)
		if bad > 0 {
			return fmt.Errorf("the index differs from the full evaluation on %d requests", bad)
		}
	}
	return nil
}

func sameHits(a, b []vpatch.Hit) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}

func ids(h []vpatch.Hit) string {
	var s []string
	for _, x := range h {
		s = append(s, x.ID)
	}
	return strings.Join(s, " ")
}

func topIDs(m map[string]int, n int) string {
	type kv struct {
		k string
		n int
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(a, b int) bool {
		if l[a].n != l[b].n {
			return l[a].n > l[b].n
		}
		return l[a].k < l[b].k
	})
	var out []string
	for i, x := range l {
		if i >= n {
			out = append(out, "...")
			break
		}
		out = append(out, fmt.Sprintf("%s x%d", x.k, x.n))
	}
	return strings.Join(out, ", ")
}

func cmdConvert(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("convert", flag.ContinueOnError)
	in := fs.String("in", "", "the signature library to read (required)")
	out := fs.String("out", "", "the pack to write: .json writes JSON, anything else YAML (required)")
	format := fs.String("format", "auto", "legacy, pack or auto")
	tiers := fs.String("tiers", "verified", "comma-separated tiers to keep")
	name := fs.String("name", "", "the pack's name (default: the input file's name)")
	version := fs.String("version", "", "the pack's version (default: today's date)")
	if err := parse(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}
	if *in == "" || *out == "" {
		return usageError("-in and -out are required")
	}
	tl, err := parseTiers(*tiers)
	if err != nil {
		return err
	}
	sigs, err := readSignatures(*in, *format)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, t := range tl {
		keep[t] = true
	}
	var kept []vpatch.Signature
	for _, s := range sigs {
		if keep[tierOf(s)] {
			kept = append(kept, s)
		}
	}
	p := vpatch.Pack{Name: *name, Version: *version, Created: time.Now().UTC().Format(time.RFC3339), Signatures: kept}
	if p.Name == "" {
		p.Name = baseName(*in)
	}
	if p.Version == "" {
		p.Version = time.Now().UTC().Format("2006.01.02")
	}
	// Create a private, exclusive temporary file in the output directory.
	// The directory must be operator-controlled, as for any published pack.
	f, err := os.CreateTemp(filepath.Dir(*out), ".carnical-vpatch-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if strings.HasSuffix(*out, ".json") {
		err = vpatch.WritePackJSON(f, p)
	} else {
		err = vpatch.WritePack(f, p)
	}
	var chk vpatch.Pack
	if err == nil {
		// Validate the exact file we wrote before it replaces a working pack.
		// Keep the handle open so validation cannot resolve a different path.
		if _, err = f.Seek(0, io.SeekStart); err == nil {
			chk, err = vpatch.ReadPack(f)
		}
		if err != nil {
			err = fmt.Errorf("converted pack failed validation: %w", err)
		}
	}
	if err := errors.Join(err, f.Close()); err != nil {
		return errors.Join(err, os.Remove(tmp))
	}
	if err := os.Rename(tmp, *out); err != nil {
		return errors.Join(err, os.Remove(tmp))
	}
	_, err = fmt.Fprintf(stdout, "wrote %s: %d of %d signatures (tiers %v), hash %s\n", *out, len(chk.Signatures), len(sigs), tl, chk.Hash)
	return err
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.IndexByte(p, '.'); i > 0 {
		p = p[:i]
	}
	return p
}
