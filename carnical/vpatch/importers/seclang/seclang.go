// SPDX-License-Identifier: Apache-2.0

// Package seclang converts a subset of ModSecurity and Coraza SecLang to vpatch signatures, for people who bring their own rules.
//
// Only SecRule is read. A rule may name the variables REQUEST_URI, REQUEST_FILENAME, QUERY_STRING, ARGS, ARGS_NAMES,
// REQUEST_HEADERS (with a header name), REQUEST_COOKIES, REQUEST_BODY, REQUEST_METHOD and FILES (and a few more that map the same
// way), the operators @rx, @contains, @pm, @beginsWith, @endsWith, @streq and @within, the transformations the model has, and the
// actions id, phase, msg, severity, tag, rev and the disruptive ones. A chain becomes the main condition and Also. Anything else is
// skipped with a reason: it is never approximated without the report counting it. docs/signature-formats.md has the whole table.
package seclang

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// Format is the SecLang format, for importers.Run.
var Format = importers.Format{Name: "seclang", Extensions: []string{".conf", ".rules", ".seclang"}, Convert: convertFile}

// Convert converts a SecLang file, or every .conf, .rules or .seclang file under a directory.
func Convert(root string, opts importers.Options) (importers.Result, error) {
	return importers.Run(Format, root, opts)
}

// ConvertBytes converts the contents of one SecLang file.
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
	var re *importers.RegexError
	if errors.As(err, &re) {
		return "regex:" + re.Reason
	}
	switch {
	case errors.Is(err, errBadQuote):
		return "unterminated-quote"
	case errors.Is(err, errBadArgs):
		return "malformed-rule"
	case errors.Is(err, importers.ErrTooManyAlternatives):
		return "or-expands-too-far"
	case errors.Is(err, importers.ErrTooManyConditions):
		return "too-many-conditions"
	}
	return "invalid-rule"
}

// secRule is one SecRule line.
type secRule struct {
	vars    []variable
	op      operator
	actions []action
	line    int
}

func (r secRule) has(key string) bool {
	for _, a := range r.actions {
		if a.key == key {
			return true
		}
	}
	return false
}

func (r secRule) get(key string) (string, bool) {
	for _, a := range r.actions {
		if a.key == key {
			return a.val, true
		}
	}
	return "", false
}

const maxChain = 8

type converter struct {
	opts importers.Options
	lim  importers.Limits
	rep  *importers.Report
	// approx names the approximations a chain used, counted for the signatures made from it.
	approx map[string]bool
}

func convertFile(name string, data []byte, opts importers.Options, rep *importers.Report) []vpatch.Signature {
	lim := opts.Limits.Normalize()
	var out []vpatch.Signature
	var chain []secRule
	open := false // the last rule had "chain": the next SecRule belongs to it

	flush := func() {
		if len(chain) == 0 {
			return
		}
		c := &converter{opts: opts, lim: lim, rep: rep, approx: map[string]bool{}}
		sigs, err := c.convertChain(chain, data)
		if err != nil {
			rep.Skip(reasonOf(err), unitName(chain[0]))
		} else {
			rep.UnitsConverted++
			out = append(out, sigs...)
		}
		chain, open = nil, false
	}

	for _, d := range logicalLines(string(data), lim.MaxDocBytes) {
		if !strings.EqualFold(d.name, "SecRule") {
			if open {
				rep.Skip("chain-unterminated", unitName(chain[0]))
				chain, open = nil, false
			}
			rep.Ignore(directiveName(d.name))
			continue
		}
		head := !open
		if head {
			rep.UnitsRead++
		}
		if len(d.rest) > lim.MaxDocBytes {
			rep.Skip("rule-too-long", "line:"+strconv.Itoa(d.line))
			chain, open = nil, false
			continue
		}
		r, err := parseSecRule(d)
		if err != nil {
			if head {
				rep.Skip(reasonOf(err), "line:"+strconv.Itoa(d.line))
			} else {
				rep.Skip(reasonOf(err), unitName(chain[0]))
				chain, open = nil, false
			}
			continue
		}
		if head {
			chain = []secRule{r}
		} else {
			chain = append(chain, r)
			if len(chain) > maxChain {
				rep.Skip("chain-too-long", unitName(chain[0]))
				chain, open = nil, false
				continue
			}
		}
		if r.has("chain") {
			open = true
			continue
		}
		open = false
		flush()
	}
	if open {
		rep.Skip("chain-unterminated", unitName(chain[0]))
	}
	return out
}

func directiveName(n string) string {
	return importers.SafeName(n)
}

func unitName(r secRule) string {
	if id, ok := r.get("id"); ok {
		return "id:" + importers.SafeToken(id, 20)
	}
	return "line:" + strconv.Itoa(r.line)
}

func parseSecRule(d directive) (secRule, error) {
	words, err := splitWords(d.rest)
	if err != nil {
		return secRule{}, err
	}
	if len(words) < 2 || len(words) > 3 {
		return secRule{}, errBadArgs
	}
	r := secRule{vars: splitVariables(words[0]), op: parseOperator(words[1]), line: d.line}
	if len(words) == 3 {
		r.actions = splitActions(words[2])
	}
	if len(r.vars) == 0 || len(r.vars) > 32 {
		return secRule{}, errBadArgs
	}
	return r, nil
}

// convertChain converts one rule or one chain.
func (c *converter) convertChain(chain []secRule, data []byte) ([]vpatch.Signature, error) {
	head := chain[0]
	idStr, ok := head.get("id")
	if !ok || strings.TrimSpace(idStr) == "" {
		return nil, skip("no-id")
	}
	id, err := strconv.Atoi(strings.TrimSpace(idStr))
	if err != nil || id <= 0 {
		return nil, skip("bad-id")
	}
	// Actions of the head say what the whole chain is.
	if err := c.checkActions(head); err != nil {
		return nil, err
	}
	var kids []importers.Expr
	for _, r := range chain {
		e, err := c.ruleExpr(r)
		if err != nil {
			return nil, err
		}
		kids = append(kids, e)
	}
	alts, err := importers.And(kids...).Expand(c.lim.MaxAlternatives, c.lim.MaxConditions)
	if err != nil {
		return nil, err
	}

	msg, _ := head.get("msg")
	var tags []string
	for _, a := range head.actions {
		if a.key == "tag" {
			tags = append(tags, a.val)
		}
	}
	rev, _ := head.get("rev")
	category := categoryFrom(tags, msg)
	sev := severityFrom(head)
	if sev == "" {
		sev = importers.SeverityFor(category)
	}
	conf := "medium"
	act := "block"
	if head.has("pass") {
		act = "log"
	}
	rv := rev
	if c.opts.Revision != "" {
		rv = importers.SafeRevision(c.opts.Revision)
	}
	if rv == "" {
		rv = importers.ContentRevision(data)
	}
	revNum, _ := strconv.Atoi(rev)
	var out []vpatch.Signature
	for i, conds := range alts {
		main, also := importers.Assemble(conds)
		sid := "SL-" + strconv.Itoa(id)
		if len(alts) > 1 {
			sid += "-" + strconv.Itoa(i+1)
		}
		s := vpatch.Signature{
			ID:          sid,
			Rev:         revNum,
			Description: importers.Describe(msg, 300),
			Category:    category,
			Severity:    sev,
			Confidence:  conf,
			Action:      act,
			Score:       importers.ScoreFor(conf),
			CVEs:        importers.CVEs(append([]string{msg}, tags...)...),
			Sources:     []string{"seclang:" + strconv.Itoa(id) + "@" + rv},
			Scope:       importers.InferScope(pathsOf(conds), append([]string{msg}, tags...), nil),
			Tier:        c.opts.StartTier(),
			Condition:   main,
			Also:        also,
		}
		out = append(out, s)
	}
	for k := range c.approx {
		for range out {
			c.rep.Approximate(k)
		}
	}
	return out, nil
}

func pathsOf(conds []vpatch.Condition) []string {
	var out []string
	for _, c := range conds {
		for _, t := range c.Targets {
			if t == vpatch.TargetPath || t == vpatch.TargetURI {
				out = append(out, c.Pattern)
			}
		}
	}
	return out
}

// checkActions refuses a rule whose actions change what the rule means in a way the model cannot say.
func (c *converter) checkActions(r secRule) error {
	for _, a := range r.actions {
		switch a.key {
		case "id", "msg", "severity", "tag", "rev", "ver", "maturity", "accuracy", "logdata", "capture", "log", "nolog", "auditlog",
			"noauditlog", "setvar", "t", "chain", "status", "deny", "drop", "block", "pass", "sanitisearg", "sanitisematched",
			"sanitisematchedbytes", "sanitiserequestheader", "sanitiseresponseheader", "xmlns":
		case "phase":
			p := strings.ToLower(strings.TrimSpace(a.val))
			switch p {
			case "1", "2", "request":
			case "3", "4", "5", "response", "logging":
				return skip("response-phase")
			default:
				return skip("bad-phase")
			}
		case "multimatch":
			return skip("multimatch")
		case "allow":
			return skip("allow-action")
		case "redirect", "proxy":
			return skip("redirect-action")
		case "ctl", "skip", "skipafter":
			return skip("flow-control:%s", a.key)
		case "setenv", "setsid", "setuid", "initcol", "expirevar", "deprecatevar", "exec", "prepend", "append":
			return skip("action-unsupported:%s", a.key)
		default:
			return skip("action-unsupported:%s", importers.SafeName(a.key))
		}
	}
	return nil
}

func severityFrom(r secRule) string {
	v, ok := r.get("severity")
	if !ok {
		return ""
	}
	switch strings.ToUpper(strings.Trim(strings.TrimSpace(v), "'")) {
	case "EMERGENCY", "ALERT", "CRITICAL", "0", "1", "2":
		return "critical"
	case "ERROR", "3":
		return "high"
	case "WARNING", "4":
		return "medium"
	case "NOTICE", "INFO", "DEBUG", "5", "6", "7":
		return "low"
	}
	return ""
}

var tagCategories = map[string]string{
	"attack-sqli": "sqli", "attack-xss": "xss", "attack-rce": "rce", "attack-lfi": "lfi", "attack-rfi": "rfi",
	"attack-injection-php": "php", "attack-protocol": "protocol", "attack-reputation-scanner": "scanner", "attack-scanner": "scanner",
	"attack-injection-java": "java", "attack-ssrf": "ssrf", "attack-xxe": "xxe", "attack-ssti": "ssti", "attack-disclosure": "probe",
	"attack-generic": "other", "attack-injection-generic": "other", "attack-fixation": "other", "attack-multipart": "protocol",
}

func categoryFrom(tags []string, msg string) string {
	for _, t := range tags {
		if c, ok := tagCategories[strings.ToLower(strings.TrimSpace(t))]; ok {
			return c
		}
	}
	if c := importers.ClassifyText(msg); c != "" {
		return c
	}
	return "other"
}
