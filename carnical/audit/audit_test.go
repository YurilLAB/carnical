package audit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/proxy"
)

func statusOf(t *testing.T, rep Report, name string) Result {
	t.Helper()
	for _, r := range rep.Results {
		if r.Check == name {
			return r
		}
	}
	t.Fatalf("no result for %s", name)
	return Result{}
}

func TestRunnerStatuses(t *testing.T) {
	boom := func(context.Context) Outcome { panic("boom") }
	slow := func(ctx context.Context) Outcome { <-ctx.Done(); return Outcome{Checked: 1} }
	tests := []struct {
		name string
		run  func(context.Context) Outcome
		want Status
	}{
		{"cases and no problems", func(context.Context) Outcome { return Outcome{Checked: 3} }, Pass},
		{"a problem", func(context.Context) Outcome { return Outcome{Checked: 3, Problems: []string{"x"}} }, Fail},
		{"nothing exercised is not a pass", func(context.Context) Outcome { return Outcome{} }, Fail},
		{"could not run", func(context.Context) Outcome { return Outcome{SkipReason: "no network"} }, Skip},
		{"a panic", boom, Error},
		{"out of time", slow, Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := Run(context.Background(), []Check{{Name: "c", Run: tt.run}}, 100*time.Millisecond)
			if got := rep.Results[0].Status; got != tt.want {
				t.Fatalf("status %s, want %s (%+v)", got, tt.want, rep.Results[0])
			}
		})
	}
}

func TestReportOKCountsSkipsAgainstItself(t *testing.T) {
	mk := func(s ...Status) Report {
		var r Report
		for _, st := range s {
			r.Results = append(r.Results, Result{Status: st})
		}
		return r
	}
	tests := []struct {
		name  string
		rep   Report
		allow bool
		ok    bool
	}{
		{"all pass", mk(Pass, Pass), false, true},
		{"a skip", mk(Pass, Skip), false, false},
		{"a skip, said to be expected", mk(Pass, Skip), true, true},
		{"a failure is never excused", mk(Pass, Fail), true, false},
		{"an error is never excused", mk(Pass, Error), true, false},
		{"an empty run is not ok", Report{}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rep.OK(tt.allow); got != tt.ok {
				t.Fatalf("OK = %v, want %v", got, tt.ok)
			}
		})
	}
}

func TestOneBrokenCheckDoesNotStopTheRest(t *testing.T) {
	rep := Run(context.Background(), []Check{
		{Name: "a", Run: func(context.Context) Outcome { panic("x") }},
		{Name: "b", Run: func(context.Context) Outcome { return Outcome{Checked: 1} }},
	}, time.Second)
	if statusOf(t, rep, "b").Status != Pass {
		t.Fatal("the check after a panicking one did not run")
	}
}

const sampleMap = `{
  "here": "edge",
  "zones": [
    {"name": "edge", "prefixes": ["203.0.113.0/24"]},
    {"name": "control", "internal": true, "prefixes": ["10.20.0.0/24"], "services": [{"name": "config", "addr": "10.20.0.5:8443"}]},
    {"name": "owner", "internal": true, "prefixes": ["10.99.0.0/28"]}
  ],
  "flows": [{"from": "edge", "to": "control"}]
}`

func TestZoneMapIsValidated(t *testing.T) {
	tests := []struct {
		name, in string
		ok       bool
	}{
		{"valid", sampleMap, true},
		{"a misspelt key", strings.Replace(sampleMap, `"internal"`, `"intrnal"`, 1), false},
		{"duplicate zone", strings.Replace(sampleMap, `{"name": "owner"`, `{"name": "edge"`, 1), false},
		{"unknown zone in a flow", strings.Replace(sampleMap, `"to": "control"`, `"to": "nowhere"`, 1), false},
		{"a zone to itself", strings.Replace(sampleMap, `"to": "control"`, `"to": "edge"`, 1), false},
		{"here is not a zone", strings.Replace(sampleMap, `"here": "edge"`, `"here": "moon"`, 1), false},
		{"bad prefix", strings.Replace(sampleMap, `10.20.0.0/24`, `10.20.0.0/99`, 1), false},
		{"service without a port", strings.Replace(sampleMap, `10.20.0.5:8443`, `10.20.0.5`, 1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadMap(strings.NewReader(tt.in))
			if (err == nil) != tt.ok {
				t.Fatalf("LoadMap = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestLastAddr(t *testing.T) {
	tests := []struct{ prefix, want string }{
		{"10.20.0.0/24", "10.20.0.255"},
		{"10.99.0.0/28", "10.99.0.15"},
		{"10.0.0.0/8", "10.255.255.255"},
		{"10.1.2.3/32", "10.1.2.3"},
		{"fd00::/8", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"2001:db8::/33", "2001:db8:7fff:ffff:ffff:ffff:ffff:ffff"},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			if got := lastAddr(netip.MustParsePrefix(tt.prefix)); got != netip.MustParseAddr(tt.want) {
				t.Fatalf("lastAddr(%s) = %s, want %s", tt.prefix, got, tt.want)
			}
		})
	}
}

func TestOriginGuardCatchesAnAllowListThatCoversTheBackend(t *testing.T) {
	zm, err := LoadMap(strings.NewReader(sampleMap))
	if err != nil {
		t.Fatal(err)
	}
	allow := func(cidr string) proxy.OriginPolicy {
		return proxy.OriginPolicy{Allow: []netip.Prefix{netip.MustParsePrefix(cidr)}}
	}
	tests := []struct {
		name   string
		policy proxy.OriginPolicy
		bad    string // an address that must be named in the problems, or "" for a clean result
	}{
		{"the default policy", proxy.OriginPolicy{}, ""},
		{"a range beside the backend but touching none of it", allow("10.50.0.0/16"), ""},
		{"a range that covers the control plane", allow("10.0.0.0/8"), "10.20.0.5"},
		{"a range that covers only the owner zone", allow("10.99.0.0/24"), "10.99.0.0"},
		{"the metadata range", allow("169.254.0.0/16"), "169.254.169.254"},
		{"loopback", allow("127.0.0.0/8"), "127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := Run(context.Background(), []Check{OriginGuard(zm, tt.policy)}, time.Second).Results[0]
			if tt.bad == "" {
				if o.Status != Pass || o.Checked < 10 {
					t.Fatalf("a safe policy was flagged, or too little was tried: %+v", o)
				}
				return
			}
			if o.Status != Fail || !strings.Contains(strings.Join(o.Problems, "; "), tt.bad) {
				t.Fatalf("not caught: %+v", o)
			}
		})
	}
}

func listen(t *testing.T) (addr string, stop func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().String(), func() { l.Close() }
}

func TestZoneReachFindsAnOpenWallAndABrokenFlow(t *testing.T) {
	control, stopControl := listen(t)
	owner, stopOwner := listen(t)
	defer stopOwner()
	defer stopControl()
	zm := Map{Here: "edge",
		Zones: []Zone{{Name: "edge"}, {Name: "control", Internal: true, Services: []Service{{Name: "config", Addr: control}}},
			{Name: "owner", Internal: true, Services: []Service{{Name: "console", Addr: owner}}}},
		Flows: []Flow{{From: "edge", To: "control"}}}
	if err := zm.Validate(); err != nil {
		t.Fatal(err)
	}
	var d net.Dialer
	run := func() Result {
		return Run(context.Background(), []Check{ZoneReach(zm, d.DialContext)}, 10*time.Second).Results[0]
	}

	// The owner service answers although the map does not allow edge -> owner: a wall is open.
	r := run()
	if r.Status != Fail || len(r.Problems) != 1 || !strings.Contains(r.Problems[0], "owner/console") || !strings.Contains(r.Problems[0], "does not allow") {
		t.Fatalf("an open wall was not reported: %+v", r)
	}

	// Close it: the walls hold, and the allowed flow works.
	stopOwner()
	if r := run(); r.Status != Pass || r.Checked != 2 {
		t.Fatalf("a correct setup failed: %+v", r)
	}

	// The allowed flow breaks: reported, not passed over.
	stopControl()
	r = run()
	if r.Status != Fail || !strings.Contains(strings.Join(r.Problems, "\n"), "allowed to reach control/config but cannot") {
		t.Fatalf("a broken flow was not reported: %+v", r)
	}

	// A map that does not say where this machine is cannot be checked.
	zm.Here = ""
	if r := run(); r.Status != Skip {
		t.Fatalf("no \"here\": %+v", r)
	}
}

// ---- the tenant checks, against a stand-in that leaks in each way the checks look for ----

type leaks struct {
	globalIndex   bool // a record is found by its exact identifier whoever owns it
	foldCase      bool // the owner check is exact but the lookup ignores case, so another case slips past it
	suffix        bool // the owner check is exact but the lookup drops a trailing ".json" or "/"
	listAll       bool // a listing includes other tenants' records
	cannotReadOwn bool
	ignoreSNI     bool // the policy comes from the name connected to, the origin from the Host header
	trustHeaders  bool // X-Forwarded-Host decides the host
	absoluteForm  bool // an absolute-form target decides the host
	noBlocker     bool // no canary is in block mode
}

type fake struct {
	cans   []Canary
	data   map[string]map[Kind]map[string]string
	hostOf map[string]string // normalised host -> tenant
	block  map[string]bool
	l      leaks
}

func newFake(l leaks) *fake {
	f := &fake{data: map[string]map[Kind]map[string]string{}, hostOf: map[string]string{}, block: map[string]bool{}, l: l}
	for _, n := range []string{"a", "b", "c"} {
		marker := "MARK-" + strings.Repeat(n, 24)
		c := Canary{Tenant: "tenant-" + n, Hosts: []string{n + ".canary.test"}, Marker: marker, Blocking: n != "a" && !l.noBlocker,
			Records: map[Kind][]string{KindPolicy: {"Pol-" + n}, KindEvents: {"Ev-" + n}}}
		f.cans = append(f.cans, c)
		f.block[c.Tenant] = c.Blocking
		f.hostOf[c.Hosts[0]] = c.Tenant
		f.data[c.Tenant] = map[Kind]map[string]string{}
		for k, ids := range c.Records {
			f.data[c.Tenant][k] = map[string]string{ids[0]: "record " + marker}
		}
	}
	return f
}

func (f *fake) Canaries() []Canary { return f.cans }

type fakeSurface struct {
	f      *fake
	tenant string
}

func (f *fake) As(_ context.Context, tenant string) (Surface, error) {
	return fakeSurface{f, tenant}, nil
}

func (s fakeSurface) Read(_ context.Context, kind Kind, id string) ([]byte, error) {
	if s.f.l.cannotReadOwn {
		return nil, errors.New("not found")
	}
	if body, ok := s.f.data[s.tenant][kind][id]; ok {
		return []byte(body), nil
	}
	for tenant, byKind := range s.f.data {
		if tenant == s.tenant {
			continue
		}
		for known, body := range byKind[kind] {
			switch {
			case s.f.l.globalIndex && known == id:
				return []byte(body), nil
			case s.f.l.foldCase && known != id && strings.EqualFold(known, id):
				return []byte(body), nil
			case s.f.l.suffix && (id == known+".json" || id == known+"/"):
				return []byte(body), nil
			}
		}
	}
	return nil, errors.New("not found")
}

func (s fakeSurface) List(_ context.Context, kind Kind) ([]string, error) {
	var ids []string
	for tenant, byKind := range s.f.data {
		if tenant != s.tenant && !s.f.l.listAll {
			continue
		}
		for id := range byKind[kind] {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func norm(h string) string {
	h = strings.ToLower(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(h, ".")
}

func (f *fake) Edge(_ context.Context, r EdgeRequest) (EdgeReply, error) {
	// The checks a real edge makes are made on the Host header: it must name a tenant, and the same tenant as the name
	// the client connected to.
	hostTenant, ok := f.hostOf[norm(r.Host)]
	if !ok {
		return EdgeReply{Status: 421}, nil
	}
	connected := f.hostOf[norm(r.Connect)]
	if connected != hostTenant && !f.l.ignoreSNI {
		return EdgeReply{Status: 421}, nil
	}
	origin, policy := hostTenant, hostTenant // the origin and the policy follow the Host header that passed the checks
	if f.l.ignoreSNI {
		policy = connected // the bug: the policy of the name connected to is applied
	}
	// The bugs below choose the origin from something that was not checked.
	if f.l.trustHeaders && r.Header.Get("X-Forwarded-Host") != "" {
		if t, ok := f.hostOf[norm(r.Header.Get("X-Forwarded-Host"))]; ok {
			origin = t
		}
	}
	if f.l.absoluteForm && strings.HasPrefix(r.Target, "http://") {
		rest := strings.TrimPrefix(r.Target, "http://")
		slash := strings.Index(rest, "/")
		if t, ok := f.hostOf[norm(rest[:slash])]; ok {
			origin = t
		}
		r.Target = rest[slash:]
	}
	if f.block[policy] && strings.Contains(r.Target, "script") {
		return EdgeReply{Status: 403, Body: []byte("blocked")}, nil
	}
	var marker string
	for _, c := range f.cans {
		if c.Tenant == origin {
			marker = c.Marker
		}
	}
	return EdgeReply{Status: 200, Body: []byte("origin says " + marker)}, nil
}

func TestTenantChecksAgainstALeakyStandIn(t *testing.T) {
	const (
		api    = "tenant-api-isolation"
		route  = "tenant-edge-routing"
		policy = "tenant-policy-confusion"
	)
	tests := []struct {
		name string
		l    leaks
		fail []string // checks that must fail; all others must pass
	}{
		{"a clean deployment", leaks{}, nil},
		{"a record is found by its identifier whoever owns it", leaks{globalIndex: true}, []string{api}},
		{"the lookup ignores case after an exact owner check", leaks{foldCase: true}, []string{api}},
		{"the lookup drops a suffix after an exact owner check", leaks{suffix: true}, []string{api}},
		{"a listing includes everyone", leaks{listAll: true}, []string{api}},
		{"the tenant cannot read its own records", leaks{cannotReadOwn: true}, []string{api}},
		{"the Host header is trusted over the name connected to", leaks{ignoreSNI: true}, []string{route, policy}},
		{"a forwarded-host header decides the host", leaks{trustHeaders: true}, []string{route, policy}},
		{"an absolute-form target decides the host", leaks{absoluteForm: true}, []string{route, policy}},
		{"no tenant is blocking", leaks{noBlocker: true}, []string{policy}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := Run(context.Background(), TenantChecks(newFake(tt.l)), 30*time.Second)
			want := map[string]bool{}
			for _, n := range tt.fail {
				want[n] = true
			}
			for _, r := range rep.Results {
				got := r.Status == Fail
				if got != want[r.Check] {
					t.Errorf("%s: status %s, want failing=%v; problems %v", r.Check, r.Status, want[r.Check], r.Problems)
				}
				if want[r.Check] == false && r.Checked < 20 {
					t.Errorf("%s passed after only %d cases", r.Check, r.Checked)
				}
				for _, p := range r.Problems {
					if strings.Contains(p, "MARK-") {
						t.Errorf("%s: a problem line carries a marker: %s", r.Check, p)
					}
				}
			}
		})
	}
}

func TestTenantChecksNeedADeploymentAndTwoCanaries(t *testing.T) {
	for _, r := range Run(context.Background(), TenantChecks(nil), time.Second).Results {
		if r.Status != Skip {
			t.Errorf("%s with no deployment: %s, want skip", r.Check, r.Status)
		}
	}
	one := newFake(leaks{})
	one.cans = one.cans[:1]
	for _, r := range Run(context.Background(), TenantChecks(one), time.Second).Results {
		if r.Status != Fail {
			t.Errorf("%s with one canary: %s, want fail", r.Check, r.Status)
		}
	}
}

func TestHostVariantsAreWhatTheFakeCanActuallyTellApart(t *testing.T) {
	// The fake normalises case, a trailing dot and a port. The check must send those and the rest of its variants.
	got := strings.Join(hostVariants("a.canary.test"), "|")
	for _, want := range []string{"A.CANARY.TEST", "a.canary.test.", "a.canary.test:443", "x@a.canary.test", "a.canary.test%00"} {
		if !strings.Contains(got, want) {
			t.Errorf("no variant %q", want)
		}
	}
	hdrs := disguises("b.canary.test")
	var names []string
	for _, h := range hdrs {
		for k := range h {
			names = append(names, k)
		}
	}
	if len(names) < 6 || fmt.Sprint(http.CanonicalHeaderKey("x-forwarded-host")) != "X-Forwarded-Host" {
		t.Errorf("disguises: %v", names)
	}
}
