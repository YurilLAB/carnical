// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/YurilLAB/coraza/carnical/crs"
)

// A rule group set to "log" has to keep its rules running (so their matches are recorded) and stop them adding to the score
// that decides a block. The Core Rule Set cannot do this from outside: every rule adds its own score to
// tx.inbound_anomaly_score_plN with its own setvar, and the blocking rule (949110) reads the sum. So for each rule in the group,
// the generated SecLang adds a second setvar to the rule that takes away what its own setvar added:
//
//	SecRuleUpdateActionById 942100 "setvar:'tx.inbound_anomaly_score_pl1=-%{tx.critical_anomaly_score}'"
//
// The two run one after the other, so the score ends where it began and the match is still recorded.
//
// That works for a rule that is one condition. A rule that needs several (a chain: 920180, "a POST with neither a Content-Length
// nor a Transfer-Encoding header", is one) keeps its score in its last link, and the engine runs a rule's own actions when the
// rule's first link matches, so an action added to the rule would take the score back even when the later links do not match, and
// lower the score of a request that deserved it. Those rules cannot be given a log-only score, so in a group set to log they are
// switched off instead (no match, no score, no record). Which they are is listed in the policy's Compiled.Notes and in
// docs/config-and-policy.md; of the 570 or so scoring rules in the ten groups, 45 are such chains.
//
// Which rule adds what, and which are chains, is read from the embedded rule set itself, once, the first time it is needed, so the
// table cannot drift from the rules it describes: when the rule set is updated the table is the new one. A test checks that every
// scoring setvar of every rule in every group is accounted for (so that a change in how the rule set scores is noticed there, not in
// production) and, for each group, that an attack it detects passes and is recorded when the group is set to log.

type scoreEntry struct {
	level int    // 1 to 4: which tx.inbound_anomaly_score_plN the rule adds to
	macro string // the amount, as the rule wrote it: %{tx.critical_anomaly_score}
}

// scoreTable is what the embedded rule set says about scoring.
type scoreTable struct {
	// own holds the rules (by id) that add to the score in their own first condition.
	own map[int][]scoreEntry
	// chained holds the rules (by id) that add to the score in a later link of a chain.
	chained map[int]bool
}

var (
	scoreOnce sync.Once
	scores    scoreTable
	scoreErr  error
)

var (
	idRe     = regexp.MustCompile(`\bid:(\d+)\b`)
	chainRe  = regexp.MustCompile(`(?:^|[,"\s])chain(?:[,"\s]|$)`)
	setvarRe = regexp.MustCompile(`setvar:'tx\.inbound_anomaly_score_pl([1-4])=\+(%\{tx\.[a-z_]+\})'`)
	// anyScoreRe finds every mention of the variable, so that a form of scoring the setvar pattern does not recognise is found
	// and refused instead of being left out.
	anyScoreRe = regexp.MustCompile(`tx\.inbound_anomaly_score_pl[1-4]`)
)

// scoring reads the embedded request rules once.
func scoring() (scoreTable, error) {
	scoreOnce.Do(func() {
		scores = scoreTable{own: map[int][]scoreEntry{}, chained: map[int]bool{}}
		files, err := fs.Glob(crs.FS(), "owasp_crs/REQUEST-9??-*.conf")
		if err != nil || len(files) == 0 {
			scoreErr = fmt.Errorf("the embedded rule set has no request rules to read")
			return
		}
		for _, name := range files {
			data, err := fs.ReadFile(crs.FS(), name)
			if err != nil {
				scoreErr = fmt.Errorf("reading the embedded rule set: %v", err)
				return
			}
			curID, inChain := 0, false
			for _, d := range directives(string(data)) {
				if !strings.HasPrefix(d, "SecRule ") && !strings.HasPrefix(d, "SecAction") {
					continue
				}
				hasChain := chainRe.MatchString(d)
				m := idRe.FindStringSubmatch(d)
				if m == nil && !inChain {
					continue // a rule with no id that is not part of a chain: nothing the groups use
				}
				isLink := m == nil
				if m != nil {
					curID, _ = strconv.Atoi(m[1])
					inChain = hasChain
				} else {
					inChain = hasChain
				}
				if curID == 0 || !anyScoreRe.MatchString(d) {
					continue
				}
				found := setvarRe.FindAllStringSubmatch(d, -1)
				if len(found) != len(anyScoreRe.FindAllString(d, -1)) {
					// A directive that mentions the score in a way other than adding to it (the initialisation sets it to 0, the
					// blocking evaluation reads it) is not a scoring rule. Only the ranges of rule groups are used, and none of
					// those rules is one of those.
					if curID >= 913000 && curID <= 944999 {
						scoreErr = fmt.Errorf("rule %d scores in a form this package does not know; the rule set was updated and the table of scoring rules needs the new form", curID)
						return
					}
					continue
				}
				if isLink {
					scores.chained[curID] = true
					continue
				}
				for _, f := range found {
					lvl, _ := strconv.Atoi(f[1])
					scores.own[curID] = append(scores.own[curID], scoreEntry{level: lvl, macro: f[2]})
				}
			}
		}
	})
	return scores, scoreErr
}

// directives splits SecLang text into its directives: a line that ends in a backslash continues on the next, and a line that
// starts with # is a comment, as the engine reads them.
func directives(text string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if cur.Len() == 0 && (line == "" || strings.HasPrefix(line, "#")) {
			continue
		}
		if strings.HasSuffix(line, `\`) {
			cur.WriteString(strings.TrimSuffix(line, `\`))
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// logGroup returns what makes a group's rules add nothing to the blocking score: the directives that take back the score of each rule
// that is one condition, and the ids of the chained rules that have to be switched off instead.
func logGroup(g GroupInfo) (lines []string, switchedOff []int, err error) {
	t, err := scoring()
	if err != nil {
		return nil, nil, err
	}
	var ids []int
	for id := range t.chained {
		if id >= g.First && id <= g.Last {
			switchedOff = append(switchedOff, id)
		}
	}
	for id := range t.own {
		if id >= g.First && id <= g.Last && !t.chained[id] {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	sort.Ints(switchedOff)
	for _, id := range ids {
		parts := make([]string, 0, len(t.own[id]))
		for _, e := range t.own[id] {
			parts = append(parts, fmt.Sprintf("setvar:'tx.inbound_anomaly_score_pl%d=-%s'", e.level, e.macro))
		}
		lines = append(lines, fmt.Sprintf(`SecRuleUpdateActionById %d "%s"`, id, strings.Join(parts, ",")))
	}
	return lines, switchedOff, nil
}
