package host

import (
	"fmt"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/audit"
)

func edgeMachine(statuses map[string]string) *fake {
	f := &fake{
		files: map[string]string{"/etc/passwd": "root:x:0:0::/root:/bin/sh\ncarnical-edge:x:990:990::/:/bin/false\n"},
		links: map[string]string{"/proc/100/exe": "/usr/local/bin/carnical"},
		globs: map[string][]string{"/proc/[0-9]*": {"/proc/100"}},
	}
	f.files["/proc/100/status"] = "Name:\tcarnical\nUid:\t990\t990\t990\t990\n"
	for tid, s := range statuses {
		f.globs["/proc/100/task/[0-9]*"] = append(f.globs["/proc/100/task/[0-9]*"], "/proc/100/task/"+tid)
		f.files["/proc/100/task/"+tid+"/status"] = s
	}
	return f
}

func status(uid int, nnp, seccomp, capEff, capBnd string) string {
	return fmt.Sprintf("Name:\tcarnical\nUid:\t%d\t%d\t%d\t%d\nNoNewPrivs:\t%s\nSeccomp:\t%s\nCapEff:\t%s\nCapBnd:\t%s\n", uid, uid, uid, uid, nnp, seccomp, capEff, capBnd)
}

func TestConfined(t *testing.T) {
	needLinux(t)
	zero := "0000000000000000"
	good := status(990, "1", "2", zero, zero)
	tests := []struct {
		name     string
		threads  map[string]string
		want     audit.Status
		contains string
	}{
		{"every thread confined", map[string]string{"100": good, "101": good, "102": good}, audit.Pass, ""},
		{"one thread without the filter", map[string]string{"100": good, "101": status(990, "1", "0", zero, zero)}, audit.Fail, "thread 101 has no seccomp filter"},
		{"one thread that can gain privileges", map[string]string{"100": good, "101": status(990, "0", "2", zero, zero)}, audit.Fail, "thread 101 can gain new privileges"},
		{"a capability left in the bounding set", map[string]string{"100": status(990, "1", "2", zero, "0000000000000400")}, audit.Fail, "holds capabilities"},
		{"running as root", map[string]string{"100": status(0, "1", "2", zero, zero)}, audit.Fail, "runs as uid 0, not carnical-edge"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(Confined(edgeMachine(tt.threads), DefaultEdge))
			if r.Status != tt.want || (tt.contains != "" && !strings.Contains(strings.Join(r.Problems, "\n"), tt.contains)) {
				t.Fatalf("%+v", r)
			}
			if tt.want == audit.Pass && r.Checked != 3 {
				t.Fatalf("only %d threads were read", r.Checked)
			}
		})
	}
	// No edge running is a skip, which fails the run: an edge that is down is not an edge that is confined.
	none := &fake{files: map[string]string{"/etc/passwd": ""}, links: map[string]string{}, globs: map[string][]string{}}
	if r := run(Confined(none, DefaultEdge)); r.Status != audit.Skip {
		t.Fatalf("%+v", r)
	}
}
