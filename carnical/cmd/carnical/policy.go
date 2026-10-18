// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/YurilLAB/coraza/carnical/apiguard"
	"github.com/YurilLAB/coraza/carnical/formats"
	"github.com/YurilLAB/coraza/carnical/policy"
	"github.com/YurilLAB/coraza/carnical/proxy"
)

// sitePolicy is the customer's policy file (package policy), decoded strictly, compiled, and ready to be applied to the proxy's
// configuration with applyPolicy. See docs/config-and-policy.md for precedence.
type sitePolicy struct {
	path     string
	compiled policy.Compiled
	// named is the set of fields the document itself names, as lower-case dotted paths ("wordpress.enabled", "api_mode"). A policy
	// that leaves a field out takes the policy package's default. Section-specific CLI overrides use these names.
	named map[string]bool
}

var registerSections sync.Once

// registerPolicySections lets the two packages that own a section of the policy say what is valid in it, so that a policy with a
// bad "api" or "body_formats" section is refused when it is read and not when it is used.
func registerPolicySections() {
	registerSections.Do(func() {
		_ = policy.RegisterSection(policy.SectionAPI, func(raw json.RawMessage) error {
			_, err := apiguard.ParseConfig(raw)
			return err
		})
		_ = policy.RegisterSection(policy.SectionBodyFormats, func(raw json.RawMessage) error {
			_, err := formats.ParsePolicy(raw)
			return err
		})
	})
}

// readBoundedFile reads a regular file of at most max bytes. The error names the flag and the file.
func readBoundedFile(flagName, path string, max int64) ([]byte, error) {
	data, err := readProtectionFile(path, max)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	return data, nil
}

// loadPolicy reads, strictly decodes and compiles the customer's policy file. Anything the policy package refuses is a startup
// error that names the file and the first problem: a policy that cannot be read is never a reason to run without it.
func loadPolicy(path string) (*sitePolicy, error) {
	registerPolicySections()
	data, err := readBoundedFile("-policy", path, policy.MaxPolicyBytes)
	if err != nil {
		return nil, err
	}
	p, err := policy.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("-policy %s: %w", path, err)
	}
	c, err := policy.Compile(p)
	if err != nil {
		return nil, fmt.Errorf("-policy %s: %w", path, err)
	}
	sp := &sitePolicy{path: path, compiled: c, named: namedFields(data)}
	// The guard-wide mode can be given in two places, "api_mode" and "api.mode". Two answers that differ are a mistake in the file.
	if sp.named["api_mode"] && len(c.API) > 0 {
		inner, err := apiguard.ParseConfig(c.API)
		if err != nil {
			return nil, fmt.Errorf("-policy %s: api: %w", path, err)
		}
		if inner.Mode != apiguard.ModeDefault && inner.Mode.String() != string(c.APIMode) {
			return nil, fmt.Errorf("-policy %s: api_mode (%s) and api.mode (%s) disagree", path, c.APIMode, inner.Mode)
		}
	}
	return sp, nil
}

// namedFields lists the fields a policy document names, to one level inside the sections that are objects of settings. The
// document has already passed policy.Decode, which refuses repeated names and anything that is not a JSON object, so reading it
// again into maps is exact. Names are lower-cased so that a spelling the decoder accepts is still recognised.
func namedFields(data []byte) map[string]bool {
	named := map[string]bool{}
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		return named
	}
	for k, v := range top {
		k = strings.ToLower(k)
		named[k] = true
		switch k {
		case "wordpress", "paths", "uploads", "responses", "body", "vpatch", "framework", "api", "body_formats":
			var inner map[string]json.RawMessage
			if json.Unmarshal(v, &inner) == nil {
				for ik := range inner {
					named[k+"."+strings.ToLower(ik)] = true
				}
			}
		}
	}
	return named
}

// applyPolicy sets what the policy decides on the proxy configuration, then puts back what the operator said on the command line.
//
// flagsCfg is the configuration as the flags alone made it, and set is the names of the flags the operator actually gave. The
// rules, in the order they are applied:
//
//  1. The policy decides everything in policy.Compiled (hosts, path rules, denied headers, WordPress, uploads, responses, the
//     rule set's mode, sensitivity, body limits, methods, exclusions, custom rules and lists). A setting it does not name takes the
//     policy package's default.
//  2. A flag the operator gave wins over the policy for the same setting.
//  3. Two kinds of setting are not simply replaced:
//     - the byte limits -max-body and -max-form-body are ceilings: the policy may make them smaller, never larger, because they
//     protect the machine's memory and the customer does not own the machine;
//     - -deny-headers adds to the policy's list instead of replacing it, because a header that either side asked to be refused
//     should stay refused.
func applyPolicy(cfg *proxy.Config, flagsCfg proxy.Config, set map[string]bool, sp *sitePolicy) {
	sp.compiled.ApplyTo(cfg)

	if set["hosts"] {
		cfg.AllowedHosts = slices.Clone(flagsCfg.AllowedHosts)
	}
	if set["allow-encoded-slash"] {
		cfg.Paths.AllowEncodedSlash = flagsCfg.Paths.AllowEncodedSlash
	}
	if set["allow-path-params"] {
		cfg.Paths.AllowPathParams = flagsCfg.Paths.AllowPathParams
	}
	if set["deny-headers"] {
		cfg.DenyHeaders = unionTags(cfg.DenyHeaders, normalizeHeaderNames(flagsCfg.DenyHeaders))
	}
	if set["wordpress"] {
		cfg.WordPress.Enabled = flagsCfg.WordPress.Enabled
	}
	if set["allow-xmlrpc"] {
		cfg.WordPress.AllowXMLRPC = flagsCfg.WordPress.AllowXMLRPC
	}
	if set["login-per-minute"] {
		cfg.WordPress.LoginPerMinute = flagsCfg.WordPress.LoginPerMinute
	}
	if set["allow-script-names"] {
		cfg.Uploads.AllowExecutableNames = flagsCfg.Uploads.AllowExecutableNames
	}
	if set["allow-script-content"] {
		cfg.Uploads.AllowScriptContent = flagsCfg.Uploads.AllowScriptContent
	}
	if set["keep-banners"] {
		cfg.Responses.KeepBanners = flagsCfg.Responses.KeepBanners
	}
	if set["keep-caching"] {
		cfg.Responses.KeepCaching = flagsCfg.Responses.KeepCaching
	}
	formCeiling := flagsCfg.MaxFormBody
	if formCeiling == 0 {
		formCeiling = 128 << 10
	} // proxy.New interprets zero as its default.
	cfg.MaxFormBody = min(cfg.MaxFormBody, formCeiling)
	cfg.CRS.RequestBodyLimit = min(cfg.CRS.RequestBodyLimit, flagsCfg.CRS.RequestBodyLimit)
	if set["mode"] {
		cfg.CRS.Mode = flagsCfg.CRS.Mode
	}
	if set["paranoia"] {
		cfg.CRS.ParanoiaLevel = flagsCfg.CRS.ParanoiaLevel
	}
	if set["detection-paranoia"] {
		cfg.CRS.DetectionParanoiaLevel = flagsCfg.CRS.DetectionParanoiaLevel
	}
	if set["inbound-threshold"] {
		cfg.CRS.InboundThreshold = flagsCfg.CRS.InboundThreshold
	}
	if set["outbound-threshold"] {
		cfg.CRS.OutboundThreshold = flagsCfg.CRS.OutboundThreshold
	}
	if set["inspect-responses"] {
		cfg.CRS.InspectResponses = flagsCfg.CRS.InspectResponses
	}
	if set["allowed-methods"] {
		cfg.CRS.AllowedMethods = slices.Clone(flagsCfg.CRS.AllowedMethods)
	}
	if set["allowed-content-types"] {
		cfg.CRS.AllowedContentTypes = slices.Clone(flagsCfg.CRS.AllowedContentTypes)
	}
	if set["allowed-extensions"] {
		cfg.CRS.AllowedExtensions = slices.Clone(flagsCfg.CRS.AllowedExtensions)
	}
}

// normalizeHeaderNames writes header names the way the policy does (lower case, "-" for "_"), so that the union of the two lists
// has no duplicates that differ only in spelling.
func normalizeHeaderNames(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		out = append(out, strings.ReplaceAll(strings.ToLower(strings.TrimSpace(h)), "_", "-"))
	}
	return out
}

// apiMode is the guard-wide API mode the customer's policy asks for, and whether it asks at all: "api_mode" if the document
// names it, else "api.mode" inside the api section.
func (sp *sitePolicy) apiMode() (apiguard.Mode, bool, error) {
	if sp == nil {
		return apiguard.ModeDefault, false, nil
	}
	if sp.named["api_mode"] {
		m, err := parseAPIMode(string(sp.compiled.APIMode), "policy api_mode")
		return m, true, err
	}
	if len(sp.compiled.API) > 0 {
		cfg, err := apiguard.ParseConfig(sp.compiled.API)
		if err != nil {
			return apiguard.ModeDefault, false, fmt.Errorf("policy api: %w", err)
		}
		if cfg.Mode != apiguard.ModeDefault {
			return cfg.Mode, true, nil
		}
	}
	return apiguard.ModeDefault, false, nil
}

// apiConfig is the API guard configuration the policy's "api" section holds (the zero Config, which means the guard's defaults, if
// there is none).
func (sp *sitePolicy) apiConfig() (apiguard.Config, error) {
	if sp == nil || len(sp.compiled.API) == 0 {
		return apiguard.Config{}, nil
	}
	cfg, err := apiguard.ParseConfig(sp.compiled.API)
	if err != nil {
		return apiguard.Config{}, fmt.Errorf("policy api: %w", err)
	}
	return cfg, nil
}

// formatsSection is the policy's "body_formats" section, and whether the customer named "monitor" in it.
func (sp *sitePolicy) formatsSection() (raw json.RawMessage, namesMonitor bool) {
	if sp == nil || len(sp.compiled.BodyFormats) == 0 {
		return nil, false
	}
	return sp.compiled.BodyFormats, sp.named["body_formats.monitor"]
}

// log says which policy is in force, so that an owner can tell which revision an edge is running.
func (sp *sitePolicy) log(log *slog.Logger) {
	hash := sp.compiled.Hash
	if len(hash) > 16 {
		hash = hash[:16]
	}
	log.Info("customer policy loaded", "file", clipText(sp.path, 200), "revision", sp.compiled.Revision, "hash", hash,
		"mode", string(sp.compiled.CRS.Mode), "paranoia", sp.compiled.CRS.ParanoiaLevel, "inbound_threshold", sp.compiled.CRS.InboundThreshold)
	for _, n := range sp.compiled.Notes {
		log.Info("customer policy note", "note", clipText(n, 300))
	}
}

func parseAPIMode(s, what string) (apiguard.Mode, error) {
	switch s {
	case "off":
		return apiguard.ModeOff, nil
	case "learn":
		return apiguard.ModeLearn, nil
	case "monitor":
		return apiguard.ModeMonitor, nil
	case "enforce":
		return apiguard.ModeEnforce, nil
	}
	return apiguard.ModeDefault, errors.New(what + " must be off, learn, monitor or enforce")
}
