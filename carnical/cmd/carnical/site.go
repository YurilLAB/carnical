// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/YurilLAB/coraza/carnical/apiguard"
	"github.com/YurilLAB/coraza/carnical/formats"
	"github.com/YurilLAB/coraza/carnical/inspect"
	"github.com/YurilLAB/coraza/carnical/proxy"
	"github.com/YurilLAB/coraza/carnical/vpatch"
)

type siteFlags struct {
	policy, vpatchPack, vpatchMode, vpatchTiers, vpatchScope, vpatchExcl, apiGuard string
	vpatchStats                                                                    time.Duration
}

func declareSiteFlags(fs *flag.FlagSet) *siteFlags {
	f := &siteFlags{}
	fs.StringVar(&f.policy, "policy", "", "local site policy JSON (maximum 1 MiB; explicit flags override settings, body ceilings always apply)")
	fs.StringVar(&f.vpatchPack, "vpatch-pack", "", "local virtual-patch pack built with carnical-vpatch (maximum 64 MiB)")
	fs.StringVar(&f.vpatchMode, "vpatch-mode", "monitor", "virtual patches: off, monitor, or block")
	fs.StringVar(&f.vpatchTiers, "vpatch-tiers", "verified", "comma-separated tiers: verified, community, experimental")
	fs.StringVar(&f.vpatchScope, "vpatch-scope", "auto", "software tags to protect; auto uses policy declarations, none selects unscoped signatures")
	fs.StringVar(&f.vpatchExcl, "vpatch-exclude", "none", "comma-separated signature ID prefixes to exclude; none excludes nothing")
	fs.DurationVar(&f.vpatchStats, "vpatch-stats-interval", time.Minute, "log changed virtual-patch counts (0 = off; 100ms to 24h)")
	fs.StringVar(&f.apiGuard, "api-guard", "off", "additional API checks: off, monitor, enforce; independent of the local OpenAPI contract")
	return f
}

func setFlags(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

// readProtectionFile pins the directory and verifies the file opened is the one
// checked. Nonblocking opens reject a raced FIFO instead of hanging startup.
func readProtectionFile(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > maxPackFileBytes {
		return nil, errors.New("invalid protection-file limit")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("protection file must be regular, within the size limit, and not a symlink")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("protection file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("protection file exceeds the size limit")
	}
	return data, nil
}

// configureSite validates all requested protections before a listener is opened.
// The existing explicit OpenAPI contract is installed separately after this step.
func configureSite(f *siteFlags, set map[string]bool, cfg *proxy.Config, log *slog.Logger, formatsMode, formatsPath string, encoding bool) (*formats.Inspector, string, *vpatch.Engine, error) {
	fail := func(err error) (*formats.Inspector, string, *vpatch.Engine, error) { return nil, "", nil, err }
	if err := checkStatsInterval("-vpatch-stats-interval", f.vpatchStats); err != nil {
		return fail(err)
	}
	var sp *sitePolicy
	if f.policy != "" {
		var err error
		sp, err = loadPolicy(f.policy)
		if err != nil {
			return fail(err)
		}
		applyPolicy(cfg, *cfg, set, sp)
		sp.log(log)
	}
	var fi *formats.Inspector
	raw, namesMonitor := sp.formatsSection()
	if formatsPath != "" || len(raw) == 0 {
		var err error
		fi, err = configureFormats(formatsMode, formatsPath, encoding)
		if err != nil {
			return fail(err)
		}
	} else {
		if formatsMode != "off" && formatsMode != "block" && formatsMode != "monitor" {
			return fail(errors.New("-formats-mode must be off, monitor or block"))
		}
		p, err := formats.ParsePolicy(raw)
		if err != nil {
			return fail(err)
		}
		if !set["formats-mode"] && namesMonitor {
			formatsMode = "block"
			if p.Monitor {
				formatsMode = "monitor"
			}
		}
		if formatsMode == "off" {
			fi, err = configureFormats("off", "", encoding)
			if err != nil {
				return fail(err)
			}
		} else {
			p.Monitor = formatsMode == "monitor"
			fi = formats.New(p)
			if err := fi.Err(); err != nil {
				return fail(err)
			}
		}
	}
	var pipeline []inspect.Inspector
	if fi != nil {
		pipeline = append(pipeline, fi)
	}
	mode, off, err := parseVPatchMode(f.vpatchMode)
	if err != nil {
		return fail(err)
	}
	tiers, err := parseVPatchTiers("-vpatch-tiers", splitList(f.vpatchTiers))
	if err != nil {
		return fail(err)
	}
	if sp != nil && !set["vpatch-tiers"] {
		tiers, err = parseVPatchTiers("policy vpatch.tiers", sp.compiled.VPatch.Tiers)
		if err != nil {
			return fail(err)
		}
	}
	auto, scope, err := parseVPatchScope(f.vpatchScope)
	if err != nil {
		return fail(err)
	}
	if auto && sp != nil {
		scope = softwareTags(sp.compiled.VPatch.Software)
	}
	var vp *vpatch.Engine
	if f.vpatchPack == "" {
		if (set["vpatch-mode"] && !off) || set["vpatch-tiers"] || set["vpatch-scope"] || set["vpatch-exclude"] || (sp != nil && (sp.named["vpatch.tiers"] || sp.named["vpatch.software"])) {
			return fail(errors.New("virtual-patch settings require -vpatch-pack"))
		}
	} else if !off {
		pack, err := readPackFile(f.vpatchPack)
		if err != nil {
			return fail(err)
		}
		var exclude []string
		if f.vpatchExcl != "none" && f.vpatchExcl != "" {
			if len(f.vpatchExcl) > 16384 {
				return fail(errors.New("-vpatch-exclude is too long"))
			}
			exclude = splitList(f.vpatchExcl)
			if len(exclude) > 128 {
				return fail(errors.New("-vpatch-exclude has more than 128 entries"))
			}
			for _, prefix := range exclude {
				if !scopeTag.MatchString(strings.ToLower(prefix)) {
					return fail(errors.New("invalid -vpatch-exclude prefix"))
				}
			}
		}
		vp = vpatch.New(vpatch.Options{Mode: mode, Tiers: tiers, Scope: scope, Exclude: exclude, BlockOnWorkLimit: true})
		rep := vp.Load(pack.Signatures)
		logVPatchLoad(log, pack.Name, pack.Version, pack.Hash, mode, tiers, scope, exclude, rep)
		if len(rep.Rejected) > 0 || len(rep.Warnings) > 0 || rep.LoadedTotal == 0 {
			return fail(errors.New("virtual-patch pack did not load completely for the selected scope and tiers"))
		}
		pipeline = append(pipeline, vp)
	}
	apiMode, err := parseAPIMode(f.apiGuard, "-api-guard")
	if err != nil {
		return fail(err)
	}
	if sp != nil && !set["api-guard"] {
		if m, named, err := sp.apiMode(); err != nil {
			return fail(err)
		} else if named {
			apiMode = m
		} else if len(sp.compiled.API) > 0 {
			apiMode = apiguard.ModeEnforce
		}
	}
	apiCfg, err := sp.apiConfig()
	if err != nil {
		return fail(err)
	}
	if apiMode == apiguard.ModeLearn || (apiCfg.Modes.Spec != apiguard.ModeDefault && apiCfg.Modes.Spec != apiguard.ModeOff) || (apiCfg.Modes.Learned != apiguard.ModeDefault && apiCfg.Modes.Learned != apiguard.ModeOff) || (sp != nil && (sp.named["api.learn"] || sp.named["api.discovery"])) {
		return fail(errors.New("API learning and discovery are unsupported by this command; use a reviewed local -api-spec"))
	}
	if apiMode != apiguard.ModeOff {
		apiCfg.Mode = apiMode
		apiCfg.Discovery.ManualPromotion = true
		apiCfg.Modes.Learned = apiguard.ModeOff
		apiCfg.Modes.Spec = apiguard.ModeOff
		api, err := apiguard.New(apiCfg)
		if err != nil {
			return fail(err)
		}
		pipeline = append(pipeline, api)
	}
	cfg.Inspectors = append(cfg.Inspectors, pipeline...)
	return fi, formatsMode, vp, nil
}

func vpatchStatsAttrs(s vpatch.Stats) []any {
	return []any{"signatures", s.Signatures, "requests", s.Requests, "matches", s.Matches, "refused", s.Blocked, "work_limited", s.WorkLimited, "truncated", s.Truncated}
}
