// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// idInspectorFailed is the identifier of a request refused because an inspector panicked.
const idInspectorFailed = 5000040

// runInspectors runs the configured inspectors, in order, on a request. It reports the body that replaces the request's (nil if
// none did) and whether the request may go on. A refusal has already been written when ok is false.
//
// An inspector that panics refuses the request (503) instead of letting it through unchecked or ending the process: a bug in
// a signature is an outage for one kind of request, not a hole.
func (e *Edge) runInspectors(w http.ResponseWriter, r *http.Request, rawPath, rawQuery string, body []byte, client netip.Addr) (req *inspect.Request, replaced []byte, ok bool) {
	req = &inspect.Request{
		Method: r.Method, Host: r.Host, Path: rawPath, RawQuery: rawQuery, Header: r.Header, Body: body, Client: client, TLS: r.TLS != nil,
	}
	for _, in := range e.cfg.Inspectors {
		res, err := safeInspect(in, req)
		if err != nil {
			m := Match{RuleID: idInspectorFailed, Severity: "CRITICAL", Message: "request inspector failed", Disruptive: true}
			if e.cfg.LogDetails {
				m.ExpandedMessage = in.Name() + " failed: " + err.Error()
			}
			e.log(m, r)
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return nil, nil, false
		}
		for _, h := range res.DelHeader {
			r.Header.Del(h)
		}
		for k, v := range res.SetHeader {
			r.Header.Set(k, v)
		}
		if res.Body != nil {
			req.Body, replaced = res.Body, res.Body
		}
		var blocking *inspect.Verdict
		for i := range res.Verdicts {
			v := res.Verdicts[i]
			sev := strings.ToUpper(v.Severity)
			if sev == "" {
				sev = "WARNING"
			}
			e.log(Match{RuleID: v.ID, Severity: sev, Message: v.Message, Disruptive: v.Block}, r)
			if v.Block && blocking == nil {
				blocking = &v
			}
		}
		if blocking != nil {
			status := blocking.Status
			if status < 400 || status > 599 {
				status = http.StatusForbidden
			}
			http.Error(w, http.StatusText(status), status)
			return nil, nil, false
		}
	}
	return req, replaced, true
}

// observed is the request as the inspectors last saw it, kept for the observers that are told the application's answer.
type observedKey struct{}

func safeInspect(in inspect.Inspector, req *inspect.Request) (res inspect.Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return in.Inspect(req), nil
}

// log reports a finding of the proxy's own, adding what identifies the request only if details are on.
func (e *Edge) log(m Match, r *http.Request) {
	if e.cfg.OnMatch == nil {
		return
	}
	if e.cfg.LogDetails {
		m.ClientIP, m.URI = r.RemoteAddr, r.RequestURI
	}
	e.cfg.OnMatch(m)
}
