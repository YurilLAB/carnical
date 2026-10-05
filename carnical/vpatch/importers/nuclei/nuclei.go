// SPDX-License-Identifier: Apache-2.0

// Package nuclei converts ProjectDiscovery nuclei templates (MIT licence) to vpatch signatures.
//
// A nuclei template describes the request an exploit sends and the response that shows it worked. A WAF sees the request only, so
// this converts the shape of the request: the path (variables become character classes, the {{BaseURL}} prefix is dropped), the
// method, and what makes the request an exploit and not a visit: an argument that carries a payload, a routing argument such as
// "action" that picks the vulnerable function, a script file in an upload, a framework control header.
//
// A payload in a template is one example, so an argument that carries one gets the pattern for its whole class of attack (cross-site
// scripting, SQL injection, path traversal, command injection, template injection, XML entities, JNDI lookups, object
// deserialisation, server-side request forgery), on that argument of that path only.
//
// It is deliberately conservative. Templates that only detect software, panels, exposures or default logins, that need a sequence of
// requests (a "flow"), or whose only request is an ordinary fetch of a static file are skipped. A template that is only a request to
// an exploit endpoint, with no payload, becomes a signature with low confidence. docs/signature-formats.md has the whole table.
package nuclei

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// Format is the nuclei template format, for importers.Run.
var Format = importers.Format{Name: "nuclei", Extensions: []string{".yaml", ".yml"}, Convert: convertFile}

// Convert converts a template, or every template under a directory.
func Convert(root string, opts importers.Options) (importers.Result, error) {
	return importers.Run(Format, root, opts)
}

// ConvertBytes converts the contents of one template.
func ConvertBytes(name string, data []byte, opts importers.Options) importers.Result {
	return importers.ConvertBytes(Format, name, data, opts)
}

type skipError struct{ reason string }

func (e *skipError) Error() string { return e.reason }

func skip(format string, args ...any) error { return &skipError{reason: fmt.Sprintf(format, args...)} }

func reasonOf(err error) string {
	var se *skipError
	if errors.As(err, &se) {
		return se.reason
	}
	return "invalid-template"
}

func yamlReason(err error) string {
	switch {
	case errors.Is(err, importers.ErrYAMLTooLarge):
		return "yaml-too-large"
	case errors.Is(err, importers.ErrYAMLUnsafe):
		return "yaml-unsafe"
	case errors.Is(err, importers.ErrYAMLSlow):
		return "yaml-too-slow"
	case errors.Is(err, importers.ErrYAMLEmpty):
		return "yaml-empty"
	case errors.Is(err, importers.ErrYAMLMultiple):
		return "yaml-multiple-documents"
	case errors.Is(err, importers.ErrYAMLNotUTF8):
		return "yaml-not-utf8"
	case errors.Is(err, importers.ErrYAMLInternal):
		return "internal-error"
	}
	return "yaml-invalid"
}

// skipTags mark templates that find software, not exploits.
var skipTags = map[string]bool{"tech": true, "detect": true, "detection": true, "panel": true, "exposure": true, "exposures": true,
	"misconfig": true, "misconfiguration": true, "default-login": true, "default-logins": true, "osint": true, "token": true,
	"fingerprint": true}

func convertFile(name string, data []byte, opts importers.Options, rep *importers.Report) []vpatch.Signature {
	rep.UnitsRead++
	lim := opts.Limits.Normalize()
	doc, err := importers.DecodeYAML(data, lim)
	if err != nil {
		rep.Skip(yamlReason(err), name)
		return nil
	}
	root, ok := importers.AsMap(doc)
	if !ok {
		rep.Skip("not-a-template", name)
		return nil
	}
	id, _ := importers.AsString(root["id"])
	id = strings.TrimSpace(id)
	if id == "" {
		rep.Skip("no-id", name)
		return nil
	}
	safeID := importers.SafeToken(id, 80)
	if safeID == "" {
		rep.Skip("no-id", name)
		return nil
	}
	info, _ := importers.AsMap(root["info"])
	title, _ := importers.AsString(info["name"])
	desc, _ := importers.AsString(info["description"])
	sev, _ := importers.AsString(info["severity"])
	sev = strings.ToLower(strings.TrimSpace(sev))
	tags := tagList(info["tags"])
	for _, t := range tags {
		if skipTags[t] {
			rep.Skip("tag:"+t, safeID)
			return nil
		}
	}
	switch sev {
	case "critical", "high", "medium", "low":
	case "info":
		rep.Skip("severity-info", safeID)
		return nil
	default:
		rep.Skip("no-severity", safeID)
		return nil
	}
	if _, ok := root["flow"]; ok {
		rep.Skip("flow", safeID)
		return nil
	}
	blocksV, ok := root["http"]
	if !ok {
		blocksV, ok = root["requests"]
	}
	blocks, isList := importers.AsList(blocksV)
	if !ok || !isList || len(blocks) == 0 {
		rep.Skip("no-http-requests", safeID)
		return nil
	}

	x := &extractor{res: resolver{vars: templateVars(root["variables"])}}
	var reqs []request
	var partial []string
	for _, bv := range blocks {
		bm, ok := importers.AsMap(bv)
		if !ok {
			partial = append(partial, "request-not-a-mapping")
			continue
		}
		got, unsupported := x.fromBlock(bm)
		partial = append(partial, unsupported...)
		for i := range got {
			got[i].payloads = x.payloads
		}
		reqs = append(reqs, got...)
	}
	if len(reqs) == 0 {
		reason := "no-requests"
		if len(partial) > 0 {
			reason = partial[0]
		}
		rep.Skip(reason, safeID)
		return nil
	}
	if len(reqs) > maxRequestsPerTemplate {
		partial = append(partial, "too-many-requests")
		reqs = reqs[:maxRequestsPerTemplate]
	}

	cve := importers.CVEs(append(cveIDs(info), id, title)...)
	b := &builder{lim: lim, rep: rep, multi: len(reqs) > 1}
	var out []vpatch.Signature
	seen := map[string]bool{}
	var firstReason string
	for _, r := range reqs {
		b.payloads = r.payloads
		bt, err := b.request(r)
		if err != nil {
			partial = append(partial, reasonOf(err))
			if firstReason == "" {
				firstReason = reasonOf(err)
			}
			continue
		}
		s := b.signature(bt, opts, data, safeID, title, desc, sev, tags, info, cve)
		key := fmt.Sprintf("%+v|%+v", s.Condition, s.Also)
		if seen[key] {
			continue
		}
		seen[key] = true
		s.ID = "NU-" + importers.IDPart(id) + "-" + strconv.Itoa(len(out)+1)
		out = append(out, s)
	}
	if len(out) == 0 {
		if firstReason == "" && len(partial) > 0 {
			firstReason = partial[0]
		}
		if firstReason == "" {
			firstReason = "no-exploit-shape"
		}
		rep.Skip(firstReason, safeID)
		return nil
	}
	for _, r := range partial {
		rep.PartialSkip(r)
	}
	rep.UnitsConverted++
	return out
}

func (b *builder) signature(bt *built, opts importers.Options, data []byte, safeID, title, desc, sev string, tags []string, info map[string]any, cve []string) vpatch.Signature {
	main, also := importers.Assemble(dedupe(bt.conds))
	category := ""
	switch {
	case bt.upload:
		category = "upload"
	case bt.cl != nil:
		category = bt.cl.category
	}
	if category == "" {
		category = importers.ClassifyText(title, strings.Join(tags, " "))
	}
	if category == "" {
		for _, c := range classificationCWEs(info) {
			if category = importers.CategoryFromCWE(c); category != "" {
				break
			}
		}
	}
	if category == "" {
		if len(cve) > 0 {
			category = "cve"
		} else {
			category = "other"
		}
	}
	conf := "low"
	if bt.payload {
		conf = "medium"
	}
	// The scope is only software a site can be expected to know it runs (a framework, a WordPress plugin). A vendor's product name from
	// the template's metadata is not used: no site declares it, so a signature scoped to it would never be switched on.
	scope := importers.InferScope(bt.paths, []string{title, desc}, tags)
	return vpatch.Signature{
		Rev:         1,
		Description: importers.Describe(title, 300),
		Category:    category,
		Severity:    sev,
		Confidence:  conf,
		Action:      importers.ActionFor(conf),
		Score:       importers.ScoreFor(conf),
		CVEs:        cve,
		Sources:     []string{"nuclei:" + safeID + "@" + opts.RevisionOr(data)},
		Scope:       scope,
		Tier:        opts.StartTier(),
		Condition:   main,
		Also:        also,
	}
}

func dedupe(cs []vpatch.Condition) []vpatch.Condition {
	seen := map[string]bool{}
	var out []vpatch.Condition
	for _, c := range cs {
		k := fmt.Sprintf("%+v", c)
		if !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	return out
}

func tagList(v any) []string {
	var out []string
	if s, ok := importers.AsString(v); ok {
		for _, t := range strings.Split(s, ",") {
			if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
				out = append(out, t)
			}
		}
		return out
	}
	l, _ := importers.AsStrings(v)
	for _, t := range l {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func cveIDs(info map[string]any) []string {
	cl, _ := importers.AsMap(info["classification"])
	s, _ := importers.AsStrings(cl["cve-id"])
	return s
}

func classificationCWEs(info map[string]any) []string {
	cl, _ := importers.AsMap(info["classification"])
	s, _ := importers.AsStrings(cl["cwe-id"])
	var out []string
	for _, x := range s {
		out = append(out, strings.Split(x, ",")...)
	}
	return out
}
