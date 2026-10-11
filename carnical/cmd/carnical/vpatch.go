// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
)

func attrsOf(in []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(in))
	for _, a := range in {
		if at, ok := a.(slog.Attr); ok {
			out = append(out, at)
		}
	}
	return out
}

// maxPackFileBytes is the largest pack file the executable will open. vpatch.ReadPack has its own limit; this one makes the
// error name the file and costs nothing to check before reading.
const maxPackFileBytes = 64 << 20

// readPackFile reads a signature pack. A missing, unreadable, corrupt or oversized pack is an error that names the file: the
// operator asked for these patches, and running without them would leave the site less protected than they believe.
func readPackFile(path string) (vpatch.Pack, error) {
	fail := func(err error) (vpatch.Pack, error) {
		return vpatch.Pack{}, fmt.Errorf("-vpatch-pack %s: %w", path, err)
	}
	data, err := readProtectionFile(path, maxPackFileBytes)
	if err != nil {
		return fail(err)
	}
	p, err := vpatch.ReadPack(bytes.NewReader(data))
	if err != nil {
		return fail(err)
	}
	if len(p.Signatures) == 0 {
		return fail(errors.New("the pack holds no signatures"))
	}
	return p, nil
}

// parseVPatchMode reads -vpatch-mode.
func parseVPatchMode(s string) (mode vpatch.Mode, off bool, err error) {
	switch s {
	case "off":
		return vpatch.ModeMonitor, true, nil
	case "monitor":
		return vpatch.ModeMonitor, false, nil
	case "block":
		return vpatch.ModeBlock, false, nil
	}
	return "", false, errors.New("-vpatch-mode must be off, monitor or block")
}

// parseVPatchTiers reads a list of tiers: verified, community, experimental.
func parseVPatchTiers(what string, list []string) ([]string, error) {
	if len(list) > 16 {
		return nil, fmt.Errorf("%s: too many tier entries", what)
	}
	var out []string
	for _, t := range list {
		t = strings.ToLower(strings.TrimSpace(t))
		switch t {
		case vpatch.TierVerified, vpatch.TierCommunity, vpatch.TierExperimental:
		default:
			return nil, fmt.Errorf("%s: %q is not a tier (verified, community, experimental)", what, clipText(t, 24))
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: name at least one tier (verified, community, experimental)", what)
	}
	return out, nil
}

// scopeTag is what a software tag looks like: the same shape the site profile produces and the engine compares.
var scopeTag = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,95}$`)

// parseVPatchScope reads -vpatch-scope: "auto" (the software the policy declares), "none" (only the
// signatures that name no software), or a list of tags.
func parseVPatchScope(s string) (auto bool, tags []string, err error) {
	if len(s) > 16384 {
		return false, nil, errors.New("-vpatch-scope is too long")
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto":
		return true, nil, nil
	case "none", "":
		return false, nil, nil
	}
	list := splitList(strings.ToLower(s))
	if len(list) > 128 {
		return false, nil, errors.New("-vpatch-scope has more than 128 entries")
	}
	for _, t := range list {
		if !scopeTag.MatchString(t) {
			return false, nil, fmt.Errorf("-vpatch-scope: %q is not a software tag (lower-case letters, digits and . _ : -)", clipText(t, 40))
		}
		if !slices.Contains(tags, t) {
			tags = append(tags, t)
		}
	}
	slices.Sort(tags)
	return false, tags, nil
}

// softwareTags turns the policy's declared software ("wordpress", "woocommerce@9.3") into scope tags: the name, without a version.
func softwareTags(software []string) []string {
	var out []string
	for _, s := range software {
		name, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(s)), "@")
		if scopeTag.MatchString(name) && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// unionTags is the sorted union of tag lists.
func unionTags(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range lists {
		for _, tag := range list {
			if !seen[tag] {
				seen[tag] = true
				out = append(out, tag)
			}
		}
	}
	slices.Sort(out)
	return out
}

// clipText cuts text from the operator's own files to a length that is safe to put in one log line or error.
func clipText(s string, n int) string {
	if len(s) > n {
		s = s[:n] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// logVPatchLoad says in the log what was loaded from the pack, what was left out on purpose and what was rejected, so an owner
// can see at a glance that the patches they asked for are running (and which are not).
func logVPatchLoad(log *slog.Logger, packName, packVersion, packHash string, mode vpatch.Mode, tiers, scope, exclude []string, rep vpatch.LoadReport) {
	loaded := []any{}
	for _, t := range []string{vpatch.TierVerified, vpatch.TierCommunity, vpatch.TierExperimental} {
		if n, ok := rep.Loaded[t]; ok {
			loaded = append(loaded, slog.Int(t, n))
		}
	}
	skipped := []any{}
	reasons := make([]string, 0, len(rep.Skipped))
	for k := range rep.Skipped {
		reasons = append(reasons, k)
	}
	sort.Strings(reasons)
	for _, k := range reasons {
		skipped = append(skipped, slog.Int(k, rep.Skipped[k]))
	}
	if len(packHash) > 16 {
		packHash = packHash[:16]
	}
	log.Info("virtual patches loaded", "pack", clipText(packName, 80), "version", clipText(packVersion, 40), "content_hash", packHash,
		"mode", string(mode), "tiers", tiers, "scope", scope, "excluded_prefixes", exclude, "offered", rep.Offered, "loaded_total", rep.LoadedTotal,
		"loaded", slog.GroupValue(attrsOf(loaded)...), "left_out_on_purpose", slog.GroupValue(attrsOf(skipped)...),
		"rejected", len(rep.Rejected), "indexed", rep.Indexed, "unindexed", rep.Unindexed, "load_ms", rep.Elapsed.Milliseconds())
	if len(rep.Rejected) > 0 {
		first := make([]string, 0, 5)
		for i, r := range rep.Rejected {
			if i == 5 {
				break
			}
			first = append(first, clipText(r.ID, 40)+": "+clipText(r.Reason, 120))
		}
		log.Warn("virtual patches rejected: these signatures are not running", "count", len(rep.Rejected), "first", first)
	}
	for _, w := range rep.Warnings {
		log.Warn("virtual patches", "warning", clipText(w, 200))
	}
	if rep.LoadedTotal == 0 {
		log.Warn("virtual patches: no signature is running for this site; check -vpatch-tiers and -vpatch-scope (a signature that names software loads only when the site has declared to run it)")
	}
}
