package host

import (
	"fmt"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/audit"
)

// asRoot makes the checks believe they run as root, as the host audit does, for the length of a test.
func asRoot(t *testing.T) {
	t.Helper()
	prev := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = prev })
}

// edgeCmdline is how /proc shows the command line of the edge that deploy/systemd/carnical-edge.service starts.
const edgeCmdline = "/usr/local/bin/carnical\x00-systemd-socket\x00-confine\x00-upload-dir\x00/var/lib/carnical/edge/uploads\x00-config\x00/etc/carnical/site.json\x00"

func edgeMachine(statuses map[string]string) *fake {
	f := &fake{
		files: map[string]string{"/etc/passwd": "root:x:0:0::/root:/bin/sh\ncarnical-edge:x:990:990::/:/bin/false\n"},
		links: map[string]string{"/proc/100/exe": "/usr/local/bin/carnical"},
		globs: map[string][]string{"/proc/[0-9]*": {"/proc/100"}},
	}
	f.files["/proc/100/status"] = "Name:\tcarnical\nUid:\t990\t990\t990\t990\n"
	f.files["/proc/100/cmdline"] = edgeCmdline
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
	asRoot(t)
	zero := "0000000000000000"
	good := status(990, "1", "2", zero, zero)
	all := map[string]string{"100": good, "101": good, "102": good}
	cmdline := func(c string) func(*fake) { return func(f *fake) { f.files["/proc/100/cmdline"] = c } }
	tests := []struct {
		name     string
		threads  map[string]string
		change   func(*fake)
		want     audit.Status
		contains string
	}{
		{"every thread confined", all, nil, audit.Pass, ""},
		{"one thread without the filter", map[string]string{"100": good, "101": status(990, "1", "0", zero, zero)}, nil, audit.Fail, "thread 101 has no seccomp filter"},
		{"one thread that can gain privileges", map[string]string{"100": good, "101": status(990, "0", "2", zero, zero)}, nil, audit.Fail, "thread 101 can gain new privileges"},
		{"a capability left in the bounding set", map[string]string{"100": status(990, "1", "2", zero, "0000000000000400")}, nil, audit.Fail, "holds capabilities"},
		{"running as root", map[string]string{"100": status(0, "1", "2", zero, zero)}, nil, audit.Fail, "runs as uid 0, not carnical-edge"},
		// The unit's NoNewPrivileges and system call filter mark every thread whether or not the edge confined itself.
		{"started without -confine", all, cmdline("/usr/local/bin/carnical\x00-systemd-socket\x00"), audit.Fail, "pid 100 was started without -confine"},
		{"-confine turned off by a later flag", all, cmdline(edgeCmdline + "-confine=false\x00"), audit.Fail, "started without -confine"},
		{"the command line cannot be read", all, func(f *fake) { delete(f.files, "/proc/100/cmdline") }, audit.Fail, "its command line cannot be read"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := edgeMachine(tt.threads)
			if tt.change != nil {
				tt.change(m)
			}
			r := run(Confined(m, DefaultEdge))
			if r.Status != tt.want || (tt.contains != "" && !strings.Contains(strings.Join(r.Problems, "\n"), tt.contains)) {
				t.Fatalf("%+v", r)
			}
			if tt.want == audit.Pass && r.Checked != 4 {
				t.Fatalf("%d cases, want the command line and three threads", r.Checked)
			}
		})
	}
	// No edge running is a skip, which fails the run: an edge that is down is not an edge that is confined.
	none := &fake{files: map[string]string{"/etc/passwd": ""}, links: map[string]string{}, globs: map[string][]string{}}
	if r := run(Confined(none, DefaultEdge)); r.Status != audit.Skip {
		t.Fatalf("%+v", r)
	}
	// Not as root, /proc may hide the edge altogether (hidepid): that is said, not "not running". An edge that can be seen is
	// still checked.
	geteuid = func() int { return 1000 }
	if r := run(Confined(none, DefaultEdge)); r.Status != audit.Skip || !strings.Contains(r.Note, "needs root") {
		t.Fatalf("not as root, no edge seen: %+v", r)
	}
	if r := run(Confined(edgeMachine(all), DefaultEdge)); r.Status != audit.Pass {
		t.Fatalf("not as root, the edge seen: %+v", r)
	}
}

func TestAsksToConfine(t *testing.T) {
	for _, tt := range []struct {
		args string
		want bool
	}{
		{"carnical\x00-confine\x00", true},
		{"carnical\x00--confine\x00", true},
		{"carnical\x00-confine=true\x00", true},
		{"carnical\x00-confine=1\x00", true},
		{"carnical\x00-confine\x00-confine=false\x00", false},
		{"carnical\x00-confine=false\x00-confine\x00", true},
		{"carnical\x00-confine=nonsense\x00", false},
		{"carnical\x00-confine-best-effort\x00", false},
		{"carnical\x00-confine-connect\x0080,443\x00", false},
		{"carnical\x00confine\x00", false},
		{"", false},
	} {
		t.Run(strings.ReplaceAll(tt.args, "\x00", " "), func(t *testing.T) {
			if got := asksToConfine([]byte(tt.args)); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
