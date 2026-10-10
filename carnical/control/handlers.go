// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/YurilLAB/coraza/carnical/control/feed"
)

// ------------------------------------------------------------------------------------------------ helpers

// fail turns an error from a store into an answer. Only the sentinels this package defines have a meaning to the
// caller; anything else is "internal", with no text from the store.
func (s *Server) fail(rc *reqCtx, step string, err error) *apiError {
	switch {
	case errors.Is(err, ErrUnavailable), errors.Is(err, context.DeadlineExceeded):
		s.internal(rc.id, step, err)
		return &apiError{status: http.StatusServiceUnavailable, code: "unavailable", msg: "a service this request depends on is not available; try again shortly", retry: 5}
	}
	s.internal(rc.id, step, err)
	return errInternal()
}

func cleanText(s string, max int) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			break
		}
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

func problemsJSON(in []Problem) []problemJSON {
	out := make([]problemJSON, 0, len(in))
	for _, p := range in {
		if len(out) >= 100 {
			break
		}
		out = append(out, problemJSON{Code: cleanText(p.Code, 64), Message: cleanText(p.Message, 300)})
	}
	return out
}

func changesJSON(in []Change) []changeJSON {
	out := make([]changeJSON, 0, len(in))
	for _, c := range in {
		if len(out) >= 100 {
			break
		}
		out = append(out, changeJSON{Code: cleanText(c.Code, 64), Summary: cleanText(c.Summary, 300)})
	}
	return out
}

func codes(in []changeJSON) []string {
	out := make([]string, len(in))
	for i, c := range in {
		out[i] = c.Code
	}
	return out
}

func strs(in []string, max, n int) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if len(out) >= max {
			break
		}
		out = append(out, cleanText(s, n))
	}
	return out
}

func etag(rev uint64) string { return `"` + strconv.FormatUint(rev, 10) + `"` }

// parseIfMatch reads a revision tag: a number in double quotes, as ETag shows it.
func parseIfMatch(v string) (uint64, *apiError) {
	if v == "" {
		return 0, &apiError{status: http.StatusPreconditionRequired, code: "precondition_required", msg: "send If-Match with the revision you last read"}
	}
	if len(v) < 3 || len(v) > 22 || v[0] != '"' || v[len(v)-1] != '"' {
		return 0, errBadRequest("If-Match must be a revision tag such as \"7\"")
	}
	d := v[1 : len(v)-1]
	if d != "0" && d[0] == '0' {
		return 0, errBadRequest("If-Match must be a revision tag such as \"7\"")
	}
	for i := 0; i < len(d); i++ {
		if d[i] < '0' || d[i] > '9' {
			return 0, errBadRequest("If-Match must be a revision tag such as \"7\"")
		}
	}
	n, err := strconv.ParseUint(d, 10, 64)
	if err != nil {
		return 0, errBadRequest("If-Match must be a revision tag such as \"7\"")
	}
	return n, nil
}

var errPreconditionFailed = &apiError{status: http.StatusPreconditionFailed, code: "precondition_failed", msg: "the policy has changed since you read it; read it again"}

func (s *Server) needStores(deps ...bool) *apiError {
	for _, ok := range deps {
		if !ok {
			return errNotImplemented()
		}
	}
	return nil
}

// current returns the tenant's current revision and body; revision 0 and a nil body when there is none yet.
func (s *Server) current(rc *reqCtx) (uint64, []byte, *apiError) {
	doc, err := s.cfg.Policies.Get(rc.ctx, rc.tenant)
	if errors.Is(err, ErrNotFound) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, s.fail(rc, "policy.get", err)
	}
	return doc.Revision, doc.Body, nil
}

func (s *Server) checkDocument(b []byte) *apiError {
	if err := checkJSON(b, 64); err != nil {
		return &apiError{status: http.StatusBadRequest, code: "invalid_json", msg: "the body is not a single JSON object that can be read one way only"}
	}
	return nil
}

// stepUpNeeded is the refusal for a change that weakens protection and has no recent step-up.
func stepUpNeeded(w []changeJSON) *apiError {
	return &apiError{status: http.StatusForbidden, code: "step_up_required", weakening: w,
		msg: "this change reduces protection; ask the customer to confirm with their password, then send the time they did in " + HeaderStepUp}
}

func validCursorText(c string) bool {
	if len(c) < 1 || len(c) > 512 {
		return false
	}
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' && ch != '_' {
			return false
		}
	}
	return true
}

func (s *Server) pageQuery(rc *reqCtx) (PageQuery, *apiError) {
	q := PageQuery{Limit: s.lim.PageDefault}
	if c, ok := rc.query["cursor"]; ok {
		if !validCursorText(c) {
			return q, errBadRequest("the cursor is not valid")
		}
		q.Cursor = c
	}
	if l, ok := rc.query["limit"]; ok {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > s.lim.PageMax || strings.TrimLeft(l, "0123456789") != "" || l[0] == '0' {
			return q, errBadRequest("limit must be a whole number from 1 to " + strconv.Itoa(s.lim.PageMax))
		}
		q.Limit = n
	}
	return q, nil
}

// ------------------------------------------------------------------------------------------------ policy

type policyJSON struct {
	Revision uint64          `json:"revision"`
	Updated  string          `json:"updated,omitempty"`
	Document json.RawMessage `json:"document"`
}

func (s *Server) getPolicy(rc *reqCtx) (*result, *apiError) {
	if e := s.needStores(s.cfg.Policies != nil); e != nil {
		return nil, e
	}
	doc, err := s.cfg.Policies.Get(rc.ctx, rc.tenant)
	if errors.Is(err, ErrNotFound) {
		return nil, &apiError{status: http.StatusNotFound, code: "no_policy", msg: "this tenant has no policy yet"}
	}
	if err != nil {
		return nil, s.fail(rc, "policy.get", err)
	}
	if checkJSON(doc.Body, 64) != nil {
		s.internal(rc.id, "policy.get", errors.New("the store returned a document that is not a JSON object"))
		return nil, errInternal()
	}
	rc.setBefore(doc.Revision)
	out := policyJSON{Revision: doc.Revision, Document: doc.Body}
	if !doc.Updated.IsZero() {
		out.Updated = doc.Updated.UTC().Format(time.RFC3339)
	}
	return &result{status: 200, body: out, headers: map[string]string{"ETag": etag(doc.Revision)}}, nil
}

type validationJSON struct {
	Valid          bool          `json:"valid"`
	Problems       []problemJSON `json:"problems"`
	Weakening      []changeJSON  `json:"weakening"`
	Diff           []string      `json:"diff"`
	StepUpRequired bool          `json:"step_up_required"`
}

func (s *Server) validatePolicy(rc *reqCtx) (*result, *apiError) {
	if e := s.needStores(s.cfg.Policies != nil, s.cfg.Validator != nil); e != nil {
		return nil, e
	}
	if e := s.checkDocument(rc.body); e != nil {
		return nil, e
	}
	cur, curBody, e := s.current(rc)
	if e != nil {
		return nil, e
	}
	rc.setBefore(cur)
	v, err := s.cfg.Validator.Validate(rc.ctx, rc.tenant, curBody, rc.body)
	if err != nil {
		return nil, s.fail(rc, "validate", err)
	}
	out := validationJSON{Problems: problemsJSON(v.Problems), Weakening: changesJSON(v.Weakening), Diff: strs(v.Diff, 200, 300)}
	out.Valid = len(out.Problems) == 0
	out.StepUpRequired = len(out.Weakening) > 0
	rc.changes = codes(out.Weakening)
	return &result{status: 200, body: out}, nil
}

type putResultJSON struct {
	Revision  uint64       `json:"revision"`
	Weakening []changeJSON `json:"weakening"`
}

func (s *Server) putPolicy(rc *reqCtx) (*result, *apiError) {
	if e := s.needStores(s.cfg.Policies != nil, s.cfg.Validator != nil); e != nil {
		return nil, e
	}
	expect, e := parseIfMatch(rc.ifMatch)
	if e != nil {
		return nil, e
	}
	if e := s.checkDocument(rc.body); e != nil {
		return nil, e
	}
	cur, curBody, e := s.current(rc)
	if e != nil {
		return nil, e
	}
	rc.setBefore(cur)
	if expect != cur {
		return nil, withTag(errPreconditionFailed, cur)
	}
	v, err := s.cfg.Validator.Validate(rc.ctx, rc.tenant, curBody, rc.body)
	if err != nil {
		return nil, s.fail(rc, "validate", err)
	}
	if len(v.Problems) > 0 {
		return nil, &apiError{status: http.StatusUnprocessableEntity, code: "invalid_policy", msg: "the policy cannot be accepted", problems: problemsJSON(v.Problems)}
	}
	weak := changesJSON(v.Weakening)
	rc.changes = codes(weak)
	if len(weak) > 0 {
		if !rc.stepUpFresh() {
			return nil, stepUpNeeded(weak)
		}
		rc.detail = "step_up"
	}
	rev, err := s.cfg.Policies.Put(rc.ctx, rc.tenant, rc.body, cur, PutMeta{Actor: rc.user, Credential: rc.cred.ID, RequestID: rc.id, Kind: "put", Weakening: codes(weak)})
	if errors.Is(err, ErrConflict) {
		return nil, withTag(errPreconditionFailed, cur)
	}
	if err != nil {
		return nil, s.fail(rc, "policy.put", err)
	}
	rc.setAfter(rev)
	return &result{status: 200, body: putResultJSON{Revision: rev, Weakening: weak}, headers: map[string]string{"ETag": etag(rev)}}, nil
}

// withTag is errPreconditionFailed carrying the current revision in the answer's ETag, so a client can read it again
// without a second request to find out which revision to ask for.
func withTag(e *apiError, cur uint64) *apiError {
	c := *e
	c.etag = etag(cur)
	return &c
}

type rollbackIn struct {
	Revision uint64 `json:"revision"`
}

type rollbackOut struct {
	Revision     uint64       `json:"revision"`
	RolledBackTo uint64       `json:"rolled_back_to"`
	Weakening    []changeJSON `json:"weakening"`
}

func (s *Server) rollbackPolicy(rc *reqCtx) (*result, *apiError) {
	if e := s.needStores(s.cfg.Policies != nil, s.cfg.Validator != nil); e != nil {
		return nil, e
	}
	var in rollbackIn
	if decodeEnvelope(rc.body, &in) != nil || in.Revision == 0 {
		return nil, errBadRequest(`the body must be {"revision": <a revision number>}`)
	}
	expect, e := parseIfMatch(rc.ifMatch)
	if e != nil {
		return nil, e
	}
	cur, curBody, e := s.current(rc)
	if e != nil {
		return nil, e
	}
	rc.setBefore(cur)
	if expect != cur {
		return nil, withTag(errPreconditionFailed, cur)
	}
	if in.Revision >= cur {
		return nil, &apiError{status: http.StatusUnprocessableEntity, code: "invalid_revision", msg: "a rollback goes to an earlier revision than the current one"}
	}
	old, err := s.cfg.Policies.Revision(rc.ctx, rc.tenant, in.Revision)
	if errors.Is(err, ErrNotFound) {
		return nil, &apiError{status: http.StatusNotFound, code: "revision_not_found", msg: "there is no such revision"}
	}
	if err != nil {
		return nil, s.fail(rc, "policy.revision", err)
	}
	if checkJSON(old.Body, 64) != nil {
		s.internal(rc.id, "policy.revision", errors.New("the store returned a document that is not a JSON object"))
		return nil, errInternal()
	}
	v, err := s.cfg.Validator.Validate(rc.ctx, rc.tenant, curBody, old.Body)
	if err != nil {
		return nil, s.fail(rc, "validate", err)
	}
	if len(v.Problems) > 0 {
		return nil, &apiError{status: http.StatusUnprocessableEntity, code: "invalid_policy", msg: "that revision can no longer be accepted", problems: problemsJSON(v.Problems)}
	}
	weak := changesJSON(v.Weakening)
	rc.changes = codes(weak)
	if len(weak) > 0 {
		if !rc.stepUpFresh() {
			return nil, stepUpNeeded(weak)
		}
		rc.detail = "step_up"
	}
	rev, err := s.cfg.Policies.Put(rc.ctx, rc.tenant, old.Body, cur, PutMeta{Actor: rc.user, Credential: rc.cred.ID, RequestID: rc.id, Kind: "rollback", RolledBackTo: in.Revision, Weakening: codes(weak)})
	if errors.Is(err, ErrConflict) {
		return nil, withTag(errPreconditionFailed, cur)
	}
	if err != nil {
		return nil, s.fail(rc, "policy.put", err)
	}
	rc.setAfter(rev)
	return &result{status: 200, body: rollbackOut{Revision: rev, RolledBackTo: in.Revision, Weakening: weak}, headers: map[string]string{"ETag": etag(rev)}}, nil
}

type historyEntryJSON struct {
	Revision     uint64   `json:"revision"`
	At           string   `json:"at,omitempty"`
	Actor        string   `json:"actor"`
	Credential   string   `json:"credential"`
	Kind         string   `json:"kind"`
	RolledBackTo uint64   `json:"rolled_back_to,omitempty"`
	Weakening    []string `json:"weakening"`
}

type historyJSON struct {
	Entries    []historyEntryJSON `json:"entries"`
	NextCursor string             `json:"next_cursor,omitempty"`
	HasMore    bool               `json:"has_more"`
}

func encodeRevisionCursor(rev uint64) string {
	return base64.RawURLEncoding.EncodeToString([]byte("r" + strconv.FormatUint(rev, 10)))
}

func decodeRevisionCursor(c string) (uint64, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(c)
	if err != nil || len(raw) < 2 || len(raw) > 21 || raw[0] != 'r' {
		return 0, false
	}
	d := string(raw[1:])
	if d[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(d); i++ {
		if d[i] < '0' || d[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(d, 10, 64)
	return n, err == nil
}

func (s *Server) policyHistory(rc *reqCtx) (*result, *apiError) {
	if e := s.needStores(s.cfg.Policies != nil); e != nil {
		return nil, e
	}
	q, e := s.pageQuery(rc)
	if e != nil {
		return nil, e
	}
	var before uint64
	if q.Cursor != "" {
		var ok bool
		if before, ok = decodeRevisionCursor(q.Cursor); !ok {
			return nil, errBadRequest("the cursor is not valid")
		}
	}
	entries, err := s.cfg.Policies.History(rc.ctx, rc.tenant, before, q.Limit+1)
	if err != nil {
		return nil, s.fail(rc, "policy.history", err)
	}
	if len(entries) > q.Limit+1 {
		s.internal(rc.id, "policy.history", errors.New("the store returned more entries than asked for"))
		return nil, errInternal()
	}
	out := historyJSON{Entries: make([]historyEntryJSON, 0, q.Limit)}
	for i, h := range entries {
		if i >= q.Limit {
			out.HasMore = true
			break
		}
		if before != 0 && h.Revision >= before {
			s.internal(rc.id, "policy.history", errors.New("the store ignored the cursor"))
			return nil, errInternal()
		}
		e := historyEntryJSON{Revision: h.Revision, Actor: cleanText(h.Actor, 128), Credential: cleanText(h.Credential, 48), Kind: cleanText(h.Kind, 16),
			RolledBackTo: h.RolledBackTo, Weakening: strs(h.Weakening, 100, 64)}
		if !h.At.IsZero() {
			e.At = h.At.UTC().Format(time.RFC3339)
		}
		out.Entries = append(out.Entries, e)
	}
	if out.HasMore && len(out.Entries) > 0 {
		out.NextCursor = encodeRevisionCursor(out.Entries[len(out.Entries)-1].Revision)
	}
	return &result{status: 200, body: out}, nil
}

// ------------------------------------------------------------------------------------------------ publish

type publishIn struct {
	Revision uint64 `json:"revision"`
}

type publishOut struct {
	Sequence uint64 `json:"sequence"`
	Revision uint64 `json:"revision"`
}

func validIdempotencyKey(k string) bool {
	if len(k) < 8 || len(k) > 64 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func (s *Server) publish(rc *reqCtx) (*result, *apiError) {
	if e := s.needStores(s.cfg.Policies != nil, s.cfg.Publisher != nil); e != nil {
		return nil, e
	}
	var in publishIn
	if decodeEnvelope(rc.body, &in) != nil || in.Revision == 0 {
		return nil, errBadRequest(`the body must be {"revision": <the current revision>}`)
	}
	if rc.idemKey == "" {
		return nil, &apiError{status: http.StatusPreconditionRequired, code: "precondition_required", msg: "send an Idempotency-Key header"}
	}
	if !validIdempotencyKey(rc.idemKey) {
		return nil, errBadRequest("Idempotency-Key must be 8 to 64 characters of letters, digits, - and _")
	}
	cur, _, e := s.current(rc)
	if e != nil {
		return nil, e
	}
	rc.setBefore(cur)
	// A repeated request gets its first answer even if the revision has moved on since, so the idempotency record is read
	// before the revision is compared: the client may have lost that answer.
	key := rc.cred.ID + "|" + rc.tenant + "|" + rc.idemKey
	switch v, status, body := s.idem.begin(rc.cred.ID, key, sha256.Sum256(rc.body), rc.now); v {
	case idemReplay:
		rc.setAfter(in.Revision)
		rc.detail = "idempotent_replay"
		return &result{status: status, body: json.RawMessage(body), headers: map[string]string{"Idempotent-Replay": "true"}}, nil
	case idemMismatch:
		return nil, &apiError{status: http.StatusUnprocessableEntity, code: "idempotency_key_reused", msg: "that Idempotency-Key was used for a different request"}
	case idemBusy:
		return nil, &apiError{status: http.StatusConflict, code: "in_progress", msg: "a request with that Idempotency-Key is still being handled", retry: 1}
	case idemFull:
		return nil, &apiError{status: http.StatusServiceUnavailable, code: "idempotency_full", msg: "too many idempotency keys are held; try again later", retry: 60}
	}
	// Failed calls, including panics recovered by ServeHTTP, release their
	// claim. A successful finish marks it done, so abandon keeps the answer.
	defer s.idem.abandon(key)
	if in.Revision != cur {
		// Publishing an old revision would put back an older policy without the weakening check a rollback has.
		return nil, withTag(&apiError{status: http.StatusConflict, code: "revision_not_current", msg: "only the current revision can be published; roll back first to publish an older one"}, cur)
	}
	res, err := s.cfg.Publisher.Publish(rc.ctx, rc.tenant, in.Revision, PublishMeta{Actor: rc.user, Credential: rc.cred.ID, RequestID: rc.id, IdempotencyKey: rc.idemKey})
	if errors.Is(err, ErrConflict) {
		// A write landed after the check above; the publisher's check, made with the sequence, is the one that holds.
		return nil, &apiError{status: http.StatusConflict, code: "revision_not_current", msg: "only the current revision can be published; roll back first to publish an older one"}
	}
	if err != nil {
		return nil, s.fail(rc, "publish", err)
	}
	out := publishOut{Sequence: res.Sequence, Revision: in.Revision}
	b, _ := json.Marshal(out)
	s.idem.finish(key, http.StatusOK, b, s.now())
	rc.setAfter(in.Revision)
	return &result{status: http.StatusOK, body: out}, nil
}

// ------------------------------------------------------------------------------------------------ hosts

type challengeJSON struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type hostJSON struct {
	Hostname   string         `json:"hostname"`
	State      string         `json:"state"`
	Routable   bool           `json:"routable"`
	Challenge  *challengeJSON `json:"challenge,omitempty"`
	CreatedAt  string         `json:"created_at,omitempty"`
	VerifiedAt string         `json:"verified_at,omitempty"`
	CheckedAt  string         `json:"checked_at,omitempty"`
}

func challengeName(host string) string   { return "_carnical-challenge." + host }
func challengeValue(token string) string { return "carnical-verify=" + token }

func toHostJSON(h Host) hostJSON {
	out := hostJSON{Hostname: cleanText(h.Hostname, 253), State: HostPending}
	if h.State == HostVerified {
		out.State, out.Routable = HostVerified, true
	} else if validHostname(h.Hostname) && h.Token != "" {
		out.Challenge = &challengeJSON{Type: "dns-txt", Name: challengeName(h.Hostname), Value: challengeValue(cleanText(h.Token, 64))}
	}
	f := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
	if !h.CreatedAt.IsZero() {
		out.CreatedAt = f(h.CreatedAt)
	}
	if h.VerifiedAt != nil {
		out.VerifiedAt = f(*h.VerifiedAt)
	}
	if h.CheckedAt != nil {
		out.CheckedAt = f(*h.CheckedAt)
	}
	return out
}

func (s *Server) listHosts(rc *reqCtx) (*result, *apiError) {
	if e := s.needStores(s.cfg.Hosts != nil); e != nil {
		return nil, e
	}
	hs, err := s.cfg.Hosts.List(rc.ctx, rc.tenant)
	if err != nil {
		return nil, s.fail(rc, "hosts.list", err)
	}
	out := struct {
		Hosts []hostJSON `json:"hosts"`
	}{Hosts: make([]hostJSON, 0, len(hs))}
	for _, h := range hs {
		if len(out.Hosts) >= 1000 {
			break
		}
		out.Hosts = append(out.Hosts, toHostJSON(h))
	}
	return &result{status: 200, body: out}, nil
}

type addHostIn struct {
	Hostname string `json:"hostname"`
}

type hostOut struct {
	Host hostJSON `json:"host"`
}

func (s *Server) addHost(rc *reqCtx) (*result, *apiError) {
	if e := s.needStores(s.cfg.Hosts != nil); e != nil {
		return nil, e
	}
	var in addHostIn
	if decodeEnvelope(rc.body, &in) != nil {
		return nil, errBadRequest(`the body must be {"hostname": "<a hostname>"}`)
	}
	host := strings.ToLower(in.Hostname)
	if !validHostname(host) {
		return nil, &apiError{status: http.StatusUnprocessableEntity, code: "invalid_hostname", msg: "that is not a hostname that can be registered: use a public name in lower case, with no wildcard, port or address"}
	}
	var tok [16]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return nil, s.fail(rc, "random", err)
	}
	token := hex.EncodeToString(tok[:])
	h, err := s.cfg.Hosts.Add(rc.ctx, rc.tenant, host, token)
	if errors.Is(err, ErrHostTaken) {
		return nil, &apiError{status: http.StatusConflict, code: "hostname_unavailable", msg: "that hostname cannot be registered"}
	}
	if err != nil {
		return nil, s.fail(rc, "hosts.add", err)
	}
	status := http.StatusOK
	if h.Token == token && h.State != HostVerified {
		status = http.StatusCreated
	}
	rc.detail = "host_" + h.State
	return &result{status: status, body: hostOut{Host: toHostJSON(h)}}, nil
}

func (s *Server) verifyHost(rc *reqCtx) (*result, *apiError) {
	if e := s.needStores(s.cfg.Hosts != nil, s.cfg.Verifier != nil); e != nil {
		return nil, e
	}
	host := rc.params["host"]
	h, err := s.cfg.Hosts.Get(rc.ctx, rc.tenant, host)
	if errors.Is(err, ErrNotFound) {
		return nil, &apiError{status: http.StatusNotFound, code: "host_not_found", msg: "this tenant has not registered that hostname"}
	}
	if err != nil {
		return nil, s.fail(rc, "hosts.get", err)
	}
	if h.State == HostVerified {
		return &result{status: 200, body: hostOut{Host: toHostJSON(h)}}, nil
	}
	if !s.hosts.allow(rc.tenant+"|"+host, rc.now, s.lim.HostCheckEvery) {
		return nil, &apiError{status: http.StatusTooManyRequests, code: "too_soon", msg: "that hostname was checked a moment ago; wait before checking again", retry: ceilSeconds(s.lim.HostCheckEvery)}
	}
	ok, err := s.cfg.Verifier.Verify(rc.ctx, host, challengeName(host), challengeValue(h.Token))
	if err != nil {
		s.internal(rc.id, "hosts.verify", err)
		return nil, &apiError{status: http.StatusBadGateway, code: "verification_unavailable", msg: "the check could not be made; try again shortly", retry: 10}
	}
	if !ok {
		if err := s.cfg.Hosts.MarkChecked(rc.ctx, rc.tenant, host, rc.now); err != nil {
			return nil, s.fail(rc, "hosts.check", err)
		}
		rc.detail = "host_not_verified"
	} else {
		err := s.cfg.Hosts.MarkVerified(rc.ctx, rc.tenant, host, rc.now)
		if errors.Is(err, ErrHostTaken) {
			return nil, &apiError{status: http.StatusConflict, code: "hostname_unavailable", msg: "that hostname cannot be registered"}
		}
		if err != nil {
			return nil, s.fail(rc, "hosts.verify", err)
		}
		rc.detail = "host_verified"
	}
	h, err = s.cfg.Hosts.Get(rc.ctx, rc.tenant, host)
	if err != nil {
		return nil, s.fail(rc, "hosts.get", err)
	}
	return &result{status: 200, body: hostOut{Host: toHostJSON(h)}}, nil
}

// ------------------------------------------------------------------------------------------------ status, events

type edgeJSON struct {
	Edge     string `json:"edge"`
	Sequence uint64 `json:"sequence"`
	At       string `json:"at,omitempty"`
}

type statusJSON struct {
	Health      string           `json:"health"`
	Notes       []string         `json:"notes"`
	LastPublish *lastPublishJSON `json:"last_publish,omitempty"`
	Edges       []edgeJSON       `json:"edges"`
}

type lastPublishJSON struct {
	Sequence uint64 `json:"sequence"`
	Revision uint64 `json:"revision"`
	At       string `json:"at,omitempty"`
	Actor    string `json:"actor,omitempty"`
}

func (s *Server) getStatus(rc *reqCtx) (*result, *apiError) {
	if e := s.needStores(s.cfg.Status != nil); e != nil {
		return nil, e
	}
	st, err := s.cfg.Status.Status(rc.ctx, rc.tenant)
	if err != nil {
		return nil, s.fail(rc, "status", err)
	}
	h := st.Health
	if h != "ok" && h != "degraded" && h != "down" {
		h = "degraded"
	}
	out := statusJSON{Health: h, Notes: strs(st.Notes, 50, 300), Edges: make([]edgeJSON, 0, len(st.Edges))}
	if st.LastPublish != nil {
		lp := &lastPublishJSON{Sequence: st.LastPublish.Sequence, Revision: st.LastPublish.Revision, Actor: cleanText(st.LastPublish.Actor, 128)}
		if !st.LastPublish.At.IsZero() {
			lp.At = st.LastPublish.At.UTC().Format(time.RFC3339)
		}
		out.LastPublish = lp
	}
	for _, e := range st.Edges {
		if len(out.Edges) >= 200 {
			break
		}
		ej := edgeJSON{Edge: cleanText(e.Edge, 64), Sequence: e.Sequence}
		if !e.At.IsZero() {
			ej.At = e.At.UTC().Format(time.RFC3339)
		}
		out.Edges = append(out.Edges, ej)
	}
	return &result{status: 200, body: out}, nil
}

type eventsJSON struct {
	Events     []json.RawMessage `json:"events"`
	NextCursor string            `json:"next_cursor,omitempty"`
	HasMore    bool              `json:"has_more"`
}

func (s *Server) listEvents(rc *reqCtx) (*result, *apiError) {
	if e := s.needStores(s.cfg.Events != nil); e != nil {
		return nil, e
	}
	q, e := s.pageQuery(rc)
	if e != nil {
		return nil, e
	}
	page, err := s.cfg.Events.Events(rc.ctx, rc.tenant, q)
	if err != nil {
		return nil, s.fail(rc, "events", err)
	}
	if len(page.Events) > q.Limit || (page.More && !validCursorText(page.Next)) {
		s.internal(rc.id, "events", errors.New("the source broke its contract"))
		return nil, errInternal()
	}
	cut := !rc.cred.HasScope(ScopeRawAddresses)
	out := eventsJSON{Events: make([]json.RawMessage, 0, len(page.Events)), HasMore: page.More}
	for _, ev := range page.Events {
		if b, ok := feed.MarshalEvent(ev, cut); ok {
			out.Events = append(out.Events, b)
		}
	}
	if page.More {
		out.NextCursor = page.Next
	}
	return &result{status: 200, body: out}, nil
}

type trafficJSON struct {
	Days       []json.RawMessage `json:"days"`
	NextCursor string            `json:"next_cursor,omitempty"`
	HasMore    bool              `json:"has_more"`
}

func (s *Server) listTraffic(rc *reqCtx) (*result, *apiError) {
	if e := s.needStores(s.cfg.Events != nil); e != nil {
		return nil, e
	}
	q, e := s.pageQuery(rc)
	if e != nil {
		return nil, e
	}
	page, err := s.cfg.Events.Traffic(rc.ctx, rc.tenant, q)
	if err != nil {
		return nil, s.fail(rc, "traffic", err)
	}
	if len(page.Days) > q.Limit || (page.More && !validCursorText(page.Next)) {
		s.internal(rc.id, "traffic", errors.New("the source broke its contract"))
		return nil, errInternal()
	}
	out := trafficJSON{Days: make([]json.RawMessage, 0, len(page.Days)), HasMore: page.More}
	for _, d := range page.Days {
		if b, ok := feed.MarshalTrafficDay(d); ok {
			out.Days = append(out.Days, b)
		}
	}
	if page.More {
		out.NextCursor = page.Next
	}
	return &result{status: 200, body: out}, nil
}

// ------------------------------------------------------------------------------------------------ credentials

type credentialJSON struct {
	ID            string   `json:"id"`
	Label         string   `json:"label,omitempty"`
	Tenants       any      `json:"tenants"`
	Scopes        []string `json:"scopes"`
	Sources       []string `json:"sources"`
	CertSPKI      []string `json:"cert_spki"`
	SigningKeyFpr string   `json:"signing_key_fingerprint"`
	NotAfter      string   `json:"not_after"`
	Revoked       bool     `json:"revoked"`
	Expired       bool     `json:"expired"`
}

func (s *Server) listCredentials(rc *reqCtx) (*result, *apiError) {
	list := s.cfg.Credentials.List()
	out := struct {
		Credentials []credentialJSON `json:"credentials"`
	}{Credentials: make([]credentialJSON, 0, len(list))}
	for _, c := range list {
		if len(out.Credentials) >= 1000 {
			break
		}
		cj := credentialJSON{ID: c.ID, Label: cleanText(c.Label, 80), Scopes: []string{}, Sources: []string{}, CertSPKI: []string{},
			NotAfter: c.NotAfter.UTC().Format(time.RFC3339), Revoked: c.Revoked, Expired: !rc.now.Before(c.NotAfter)}
		if c.AllTenants {
			cj.Tenants = "all"
		} else {
			cj.Tenants = append([]string{}, c.Tenants...)
		}
		for _, sc := range c.Scopes {
			cj.Scopes = append(cj.Scopes, string(sc))
		}
		for _, p := range c.Sources {
			cj.Sources = append(cj.Sources, p.String())
		}
		for _, f := range c.Certs {
			cj.CertSPKI = append(cj.CertSPKI, f.String())
		}
		sum := sha256.Sum256(c.SigningKey)
		cj.SigningKeyFpr = hex.EncodeToString(sum[:8])
		out.Credentials = append(out.Credentials, cj)
	}
	return &result{status: 200, body: out}, nil
}

type revokeOut struct {
	ID         string `json:"id"`
	Revoked    bool   `json:"revoked"`
	WasInForce bool   `json:"was_in_force"`
}

func (s *Server) revokeCredential(rc *reqCtx) (*result, *apiError) {
	id := rc.params["id"]
	if _, ok := s.cfg.Credentials.Lookup(id); !ok {
		return nil, &apiError{status: http.StatusNotFound, code: "credential_not_found", msg: "there is no such credential"}
	}
	was, err := s.cfg.Credentials.Revoke(id)
	if err != nil {
		return nil, s.fail(rc, "credentials.revoke", err)
	}
	rc.changes = []string{"revoked:" + id}
	return &result{status: 200, body: revokeOut{ID: id, Revoked: true, WasInForce: was}}, nil
}
