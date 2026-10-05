// Package audit runs the checks that look for a break in the walls between Carnical's zones and between its
// customers. They are meant to run several times a day, unattended, and to say so loudly when something is wrong.
//
// Three rules keep a checker honest, because a checker that cannot fail is worse than none:
//
//   - A check that could not run is reported as skipped, never as passed, and a skip is a failing exit status
//     unless the operator has said it is expected.
//   - A check that exercised nothing has failed: "no problems" over zero cases is not a result.
//   - Every check is tested against a deliberately broken setup that it must catch.
//
// What a check reports names the tenant, the kind of record and the way it was tried. It never carries the marker
// values or the content that came back, so the report itself cannot leak what it is looking for.
package audit

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"time"
)

// Status is how one check ended.
type Status string

const (
	Pass  Status = "pass"
	Fail  Status = "fail"  // a wall is broken, or the check found nothing to test
	Skip  Status = "skip"  // the check could not run here; see Note
	Error Status = "error" // the check itself broke (it panicked or ran out of time)
)

// Outcome is what a check's Run returns.
type Outcome struct {
	// Checked is how many cases were really exercised.
	Checked int
	// Problems lists what is wrong, one line each, with no secret content.
	Problems []string
	// SkipReason is set when the check could not run in this place.
	SkipReason string
}

// Check is one segmentation check.
type Check struct {
	Name string
	// Zone is where the check has to run from to mean anything. The tenant checks run from "outside": they act as a
	// customer would, with no access to anything internal, because that is the position they are testing.
	Zone string
	// What says in a sentence which wall it watches.
	What string
	Run  func(ctx context.Context) Outcome
}

// Result is the recorded outcome of one check.
type Result struct {
	Check    string   `json:"check"`
	Zone     string   `json:"zone,omitempty"`
	Status   Status   `json:"status"`
	Checked  int      `json:"checked"`
	Problems []string `json:"problems,omitempty"`
	Note     string   `json:"note,omitempty"`
	Millis   int64    `json:"millis"`
}

// Report is one run of the whole catalogue.
type Report struct {
	Started time.Time `json:"started"`
	Host    string    `json:"host"`
	Results []Result  `json:"results"`
}

// Counts returns how many results ended each way.
func (r Report) Counts() map[Status]int {
	c := map[Status]int{}
	for _, res := range r.Results {
		c[res.Status]++
	}
	return c
}

// OK is true when every check passed. Skips count against it unless allowSkips is set.
func (r Report) OK(allowSkips bool) bool {
	for _, res := range r.Results {
		switch res.Status {
		case Pass:
		case Skip:
			if !allowSkips {
				return false
			}
		default:
			return false
		}
	}
	return len(r.Results) > 0
}

// Problems lists every failing line, for an alert.
func (r Report) Problems() []string {
	var out []string
	for _, res := range r.Results {
		switch res.Status {
		case Fail, Error:
			if len(res.Problems) == 0 {
				out = append(out, res.Check+": "+res.Note)
			}
			for _, p := range res.Problems {
				out = append(out, res.Check+": "+p)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Run runs every check once, each with its own time limit, and never lets one check's failure or panic stop the rest.
func Run(ctx context.Context, checks []Check, perCheck time.Duration) Report {
	host, _ := os.Hostname()
	rep := Report{Started: time.Now().UTC(), Host: host}
	if perCheck <= 0 {
		perCheck = 2 * time.Minute
	}
	for _, c := range checks {
		rep.Results = append(rep.Results, runOne(ctx, c, perCheck))
	}
	return rep
}

func runOne(ctx context.Context, c Check, limit time.Duration) (res Result) {
	start := time.Now()
	res = Result{Check: c.Name, Zone: c.Zone}
	defer func() {
		res.Millis = time.Since(start).Milliseconds()
		if p := recover(); p != nil {
			res.Status, res.Note = Error, fmt.Sprintf("the check panicked: %v", p)
			_ = debug.Stack() // kept out of the report: a stack can carry values
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	out := c.Run(ctx)
	res.Checked, res.Problems = out.Checked, out.Problems
	switch {
	case ctx.Err() != nil:
		res.Status, res.Note = Error, "the check ran out of time"
	case out.SkipReason != "":
		res.Status, res.Note = Skip, out.SkipReason
	case len(out.Problems) > 0:
		res.Status = Fail
	case out.Checked == 0:
		res.Status, res.Note = Fail, "the check exercised no cases, so it proves nothing"
	default:
		res.Status = Pass
	}
	return res
}
