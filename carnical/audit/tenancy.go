package audit

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Kind is a sort of record a customer can reach through the portal, the feed or an export.
type Kind string

// The kinds of record the checks plant and look for.
const (
	KindPolicy  Kind = "policy"
	KindEvents  Kind = "events"
	KindTraffic Kind = "traffic"
	KindBans    Kind = "bans"
	KindReport  Kind = "report"
	KindExport  Kind = "export"
	KindFeed    Kind = "feed"
)

// Canary is a tenant that exists only for the checks. The auditor owns it, so reading or attacking it harms nobody.
type Canary struct {
	// Tenant is the opaque tenant id.
	Tenant string
	// Hosts are the names that are routed to this tenant's origin.
	Hosts []string
	// Records are the ids of records planted for the tenant, by kind.
	Records map[Kind][]string
	// Marker is a long random text planted in every record and in the origin's answers. It is never logged: seeing it
	// where it does not belong is the whole finding.
	Marker string
	// Blocking says the tenant's policy blocks attacks, which makes it a target for the policy-confusion check.
	Blocking bool
}

// Surface is what a customer can do through the portal and the API: it acts with one tenant's own credentials.
type Surface interface {
	// Read asks for one record by the identifier the caller supplies, exactly as supplied.
	Read(ctx context.Context, kind Kind, id string) ([]byte, error)
	// List asks for the identifiers of the tenant's records of a kind.
	List(ctx context.Context, kind Kind) ([]string, error)
}

// EdgeRequest is one request through the data plane. Connect is the name the client connects to (what it puts in the
// TLS server name), Host is the Host header, and they are different on purpose when the check is looking for a way
// to be treated as one tenant while reaching another.
type EdgeRequest struct {
	Connect, Host, Target string
	Header                http.Header
}

// EdgeReply is what came back.
type EdgeReply struct {
	Status int
	Body   []byte
}

// Tenancy is everything the tenant checks need from a deployment. The hosted registry and edge implement it; the
// checks are tested against stand-ins that leak in each way the checks look for.
type Tenancy interface {
	Canaries() []Canary
	As(ctx context.Context, tenant string) (Surface, error)
	Edge(ctx context.Context, req EdgeRequest) (EdgeReply, error)
}

// attackTarget is a request any CRS paranoia level 1 deployment blocks, used to see which tenant's policy applied.
const attackTarget = "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

// TenantChecks returns the three checks that look for one customer reaching another. They are skipped, loudly, when no
// deployment is supplied, and they fail when there are fewer than two canary tenants to set against each other.
func TenantChecks(t Tenancy) []Check {
	return []Check{
		{Name: "tenant-api-isolation", Zone: "outside",
			What: "Through the portal and API a tenant can read nothing of another tenant's, whatever it does to the identifier.",
			Run:  func(ctx context.Context) Outcome { return apiIsolation(ctx, t) }},
		{Name: "tenant-edge-routing", Zone: "outside",
			What: "A request is answered by the origin of the host it names and no other, however the host is written or hidden.",
			Run:  func(ctx context.Context) Outcome { return edgeRouting(ctx, t) }},
		{Name: "tenant-policy-confusion", Zone: "outside",
			What: "An attack that one tenant's policy would let through is still stopped by the policy of the tenant it is aimed at.",
			Run:  func(ctx context.Context) Outcome { return policyConfusion(ctx, t) }},
	}
}

func canaries(t Tenancy) ([]Canary, string) {
	if t == nil {
		return nil, "no deployment to check: the hosted registry and data plane are not connected"
	}
	cs := t.Canaries()
	if len(cs) < 2 {
		return nil, ""
	}
	return cs, ""
}

func contains(body []byte, marker string) bool {
	return marker != "" && bytes.Contains(body, []byte(marker))
}

// idVariants are the ways an identifier is bent to see whether a lookup is as exact as it claims to be.
func idVariants(id, own string) []string {
	return []string{
		id, strings.ToUpper(id), strings.ToLower(id), id + " ", " " + id, id + "/", id + "%00", id + ".json", id + "?",
		"../" + id, "..%2f" + id, own + "/../" + id, own + "," + id, id + "," + own, "*", "%",
	}
}

func apiIsolation(ctx context.Context, t Tenancy) (out Outcome) {
	cs, skip := canaries(t)
	if skip != "" {
		return Outcome{SkipReason: skip}
	}
	if cs == nil {
		return Outcome{Problems: []string{"fewer than two canary tenants, so there is nothing to set against each other"}}
	}
	for _, a := range cs {
		surf, err := t.As(ctx, a.Tenant)
		if err != nil {
			out.Problems = append(out.Problems, fmt.Sprintf("cannot act as canary %s: %v", a.Tenant, err))
			continue
		}
		own := ""
		// Positive control: the tenant must be able to read its own planted record, or "it could not read the
		// other's" means nothing.
		for _, kind := range sortedKinds(a.Records) {
			ids := a.Records[kind]
			if len(ids) == 0 {
				continue
			}
			if own == "" {
				own = ids[0]
			}
			body, err := surf.Read(ctx, kind, ids[0])
			out.Checked++
			if err != nil || !contains(body, a.Marker) {
				out.Problems = append(out.Problems, fmt.Sprintf("positive control failed: %s cannot read its own %s record", a.Tenant, kind))
			}
		}
		for _, b := range cs {
			if b.Tenant == a.Tenant {
				continue
			}
			for _, kind := range sortedKinds(b.Records) {
				for _, id := range b.Records[kind] {
					for n, v := range idVariants(id, own) {
						body, _ := surf.Read(ctx, kind, v) // an error is the right answer; only what came back matters
						out.Checked++
						if contains(body, b.Marker) {
							out.Problems = append(out.Problems, fmt.Sprintf("%s read %s's %s record (identifier variant %d)", a.Tenant, b.Tenant, kind, n))
						}
					}
				}
				ids, err := surf.List(ctx, kind)
				out.Checked++
				if err != nil {
					continue
				}
				theirs := map[string]bool{}
				for _, id := range b.Records[kind] {
					theirs[strings.ToLower(id)] = true
				}
				for _, id := range ids {
					if theirs[strings.ToLower(id)] {
						out.Problems = append(out.Problems, fmt.Sprintf("%s's %s listing includes %s's record", a.Tenant, kind, b.Tenant))
						break
					}
				}
			}
		}
	}
	sort.Strings(out.Problems)
	return out
}

// hostVariants are the ways a host name is written when the point is to be taken for it: case, a trailing dot, a port,
// a user-info prefix, an embedded NUL.
func hostVariants(h string) []string {
	return []string{h, strings.ToUpper(h), h + ".", h + ":443", h + ":80", "x@" + h, h + "%00", h + "\x00", " " + h, h + " "}
}

// disguises are the headers that name a host a second time.
func disguises(h string) []http.Header {
	var out []http.Header
	for _, name := range []string{"X-Forwarded-Host", "X-Host", "X-Original-Host", "X-Forwarded-Server", "X-HTTP-Host-Override"} {
		hdr := http.Header{}
		hdr.Set(name, h)
		out = append(out, hdr)
	}
	forwarded, original := http.Header{}, http.Header{}
	forwarded.Set("Forwarded", "host="+h)
	original.Set("X-Original-URL", "http://"+h+"/")
	return append(out, forwarded, original)
}

// routes lists every way of reaching tenant b's host while connected as tenant a's host, with a label for the report.
type route struct {
	label string
	req   EdgeRequest
}

func routesTo(a, b Canary, target string) []route {
	var out []route
	for _, ha := range a.Hosts {
		for _, hb := range b.Hosts {
			for n, v := range hostVariants(hb) {
				out = append(out, route{fmt.Sprintf("host header variant %d over a connection to %s's name", n, a.Tenant), EdgeRequest{Connect: ha, Host: v, Target: target}})
			}
			for n, h := range disguises(hb) {
				out = append(out, route{fmt.Sprintf("naming header %d beside %s's own host", n, a.Tenant), EdgeRequest{Connect: ha, Host: ha, Target: target, Header: h}})
			}
			out = append(out, route{fmt.Sprintf("absolute-form target over a connection to %s's name", a.Tenant), EdgeRequest{Connect: ha, Host: ha, Target: "http://" + hb + target}})
		}
	}
	return out
}

func edgeRouting(ctx context.Context, t Tenancy) (out Outcome) {
	cs, skip := canaries(t)
	if skip != "" {
		return Outcome{SkipReason: skip}
	}
	if cs == nil {
		return Outcome{Problems: []string{"fewer than two canary tenants, so there is nothing to set against each other"}}
	}
	for _, a := range cs {
		for _, h := range a.Hosts {
			rep, err := t.Edge(ctx, EdgeRequest{Connect: h, Host: h, Target: "/"})
			out.Checked++
			if err != nil || !contains(rep.Body, a.Marker) {
				out.Problems = append(out.Problems, fmt.Sprintf("positive control failed: %s's own host does not reach its origin", a.Tenant))
			}
		}
	}
	for _, a := range cs {
		for _, b := range cs {
			if a.Tenant == b.Tenant {
				continue
			}
			for _, r := range routesTo(a, b, "/") {
				rep, _ := t.Edge(ctx, r.req)
				out.Checked++
				if contains(rep.Body, b.Marker) {
					out.Problems = append(out.Problems, fmt.Sprintf("%s's origin answered a request that came in as %s's: %s", b.Tenant, a.Tenant, r.label))
				}
			}
		}
	}
	sort.Strings(out.Problems)
	return out
}

func policyConfusion(ctx context.Context, t Tenancy) (out Outcome) {
	cs, skip := canaries(t)
	if skip != "" {
		return Outcome{SkipReason: skip}
	}
	if cs == nil {
		return Outcome{Problems: []string{"fewer than two canary tenants, so there is nothing to set against each other"}}
	}
	blockers := 0
	for _, b := range cs {
		if !b.Blocking || len(b.Hosts) == 0 {
			continue
		}
		blockers++
		// Positive control: aimed straight at B, the attack is stopped.
		rep, _ := t.Edge(ctx, EdgeRequest{Connect: b.Hosts[0], Host: b.Hosts[0], Target: attackTarget})
		out.Checked++
		if rep.Status < 400 {
			out.Problems = append(out.Problems, fmt.Sprintf("positive control failed: %s does not block the canary attack aimed straight at it", b.Tenant))
			continue
		}
		for _, a := range cs {
			if a.Tenant == b.Tenant {
				continue
			}
			for _, r := range routesTo(a, b, attackTarget) {
				rep, _ := t.Edge(ctx, r.req)
				out.Checked++
				if rep.Status < 400 && contains(rep.Body, b.Marker) {
					out.Problems = append(out.Problems, fmt.Sprintf("an attack that came in as %s's reached %s's origin unblocked: %s", a.Tenant, b.Tenant, r.label))
				}
			}
		}
	}
	if blockers == 0 {
		out.Problems = append(out.Problems, "no canary tenant is in block mode, so there is no policy to confuse")
	}
	sort.Strings(out.Problems)
	return out
}

func sortedKinds(m map[Kind][]string) []Kind {
	ks := make([]Kind, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
	return ks
}
