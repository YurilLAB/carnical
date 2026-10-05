// SPDX-License-Identifier: Apache-2.0

// Package suricata converts Suricata and Snort HTTP rules, such as the Emerging Threats Open rule set (BSD licence), to vpatch signatures.
//
// A rule is "alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg; flow; http.uri; content; pcre; ...)". Only what says something about
// a request is used: the HTTP buffers (http.uri, http.method, http.header, http.cookie, http.request_body, http.user_agent and the
// others, in the sticky form and in the older http_uri / uricontent form), the contents and pcre in them, and what orders and sizes
// them. Contents that follow one another with distance or within become one regular expression that keeps their order; what cannot
// be said (a pcre relative to the match before it, a rate limit) is dropped, counted in the report, and the signature goes one tier
// down. Rules about responses, files, other protocols, binary data or state kept between requests are skipped with a reason.
// docs/signature-formats.md has the whole table.
package suricata

import (
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// Format is the Suricata and Snort rule format, for importers.Run.
var Format = importers.Format{Name: "suricata", Extensions: []string{".rules"}, Convert: convertFile}

// Convert converts a rules file, or every .rules file under a directory.
func Convert(root string, opts importers.Options) (importers.Result, error) {
	return importers.Run(Format, root, opts)
}

// ConvertBytes converts the contents of one rules file.
func ConvertBytes(name string, data []byte, opts importers.Options) importers.Result {
	return importers.ConvertBytes(Format, name, data, opts)
}

// maxRuleBytes bounds one rule, however it is spread over lines.
const maxRuleBytes = 64 << 10

// The Emerging Threats files say rules with sids 2000000 to 2799999 are BSD and sids 1 to 3464 and 100000000 to 100000908 are GPLv2.
func permissiveSID(sid int) bool { return sid >= 2000000 && sid <= 2799999 }

func convertFile(name string, data []byte, opts importers.Options, rep *importers.Report) []vpatch.Signature {
	lim := opts.Limits.Normalize()
	var out []vpatch.Signature
	text := string(data)
	for len(text) > 0 {
		var line string
		line, text = nextRule(text)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			// Emerging Threats keeps rules it has switched off as comments; they are rules, and they were not wanted.
			body := strings.TrimLeft(trimmed, "# \t")
			if looksLikeRule(body) {
				rep.UnitsRead++
				rep.Skip("disabled-in-source", unitName(body))
			}
			continue
		}
		rep.UnitsRead++
		if len(line) > maxRuleBytes {
			rep.Skip("rule-too-long", unitName(trimmed))
			continue
		}
		r, err := parseRule(trimmed)
		if err != nil {
			rep.Skip(reasonOf(err), unitName(trimmed))
			continue
		}
		if r.action != "alert" {
			rep.Skip("action-not-alert", unitName(trimmed))
			continue
		}
		if sid, ok := sidOf(r); ok && !permissiveSID(sid) && !opts.AllowCopyleft {
			rep.Skip("licence-not-bsd", "sid:"+strconv.Itoa(sid))
			continue
		}
		c := &cvt{opts: opts, lim: lim, rep: rep, drops: map[string]bool{}}
		sig, err := c.convertRule(r)
		if err != nil {
			rep.Skip(reasonOf(err), unitName(trimmed))
			continue
		}
		for _, k := range importers.SortedKeys(c.drops) {
			rep.Drop(k)
		}
		rep.UnitsConverted++
		out = append(out, *sig)
	}
	return out
}

// nextRule returns the next rule and the text after it. A line that ends in a backslash continues on the next one.
func nextRule(text string) (rule, rest string) {
	var b strings.Builder
	for len(text) > 0 {
		var line string
		i := strings.IndexByte(text, '\n')
		if i < 0 {
			line, text = text, ""
		} else {
			line, text = text[:i], text[i+1:]
		}
		line = strings.TrimSuffix(line, "\r")
		if b.Len() <= maxRuleBytes+1024 {
			if strings.HasSuffix(line, `\`) && !strings.HasSuffix(line, `\\`) {
				b.WriteString(strings.TrimSuffix(line, `\`))
				continue
			}
			b.WriteString(line)
		}
		return b.String(), text
	}
	return b.String(), ""
}

func looksLikeRule(s string) bool {
	w, _, _ := strings.Cut(s, " ")
	return actions[w] && strings.HasSuffix(strings.TrimSpace(s), ")") && strings.Contains(s, "(")
}

// unitName is a short name for a rule in the report: its sid.
func unitName(line string) string {
	if i := strings.Index(line, "sid:"); i >= 0 {
		rest := line[i+4:]
		j := 0
		for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
			j++
		}
		if j > 0 {
			return "sid:" + rest[:j]
		}
	}
	return "rule"
}

func sidOf(r *rule) (int, bool) {
	for _, o := range r.opts {
		if o.key == "sid" {
			n, err := strconv.Atoi(strings.TrimSpace(o.val))
			return n, err == nil
		}
	}
	return 0, false
}
