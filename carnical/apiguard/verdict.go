// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"github.com/YurilLAB/coraza/carnical/inspect"
)

// Verdict identifiers, 5003000 to 5003999. They are the identifiers that appear in the log and the feed; docs/apiguard.md has the
// same table with what each means and which Modes field controls it.
const (
	// Level 0: the shield, which needs no description.
	IDMethodNotAllowed   = 5003001 // the method is not on the allow-list
	IDBodyTooLarge       = 5003002 // the body is larger than any request to that method should be
	IDContentTypeMissing = 5003003 // a body with no Content-Type
	IDContentTypeUnseen  = 5003004 // a Content-Type this API has not been seen to use
	IDBodyMalformed      = 5003005 // a JSON body that is not valid JSON
	IDBodyDuplicateKey   = 5003006 // a JSON body that repeats an object key
	IDRateLimited        = 5003010 // too many requests from one client
	IDAuthRateLimited    = 5003011 // too many attempts at an authentication endpoint
	IDMassAssignFlagged  = 5003020 // a privileged property in a write body (warning)
	IDMassAssignRefused  = 5003021 // a privileged property that this API's clients never send
	IDInternalError      = 5003990 // the guard failed on this request and did not inspect it

	// Level 1: the API's own description.
	IDSpecUnknownRoute     = 5003100
	IDSpecMethodNotAllowed = 5003101
	IDSpecPathParam        = 5003102
	IDSpecQueryParam       = 5003103
	IDSpecHeaderParam      = 5003104
	IDSpecCookieParam      = 5003105
	IDSpecMissingParam     = 5003106
	IDSpecContentType      = 5003107
	IDSpecBodySchema       = 5003108
	IDSpecUnknownProperty  = 5003109
	IDSpecReadOnlyProperty = 5003110
	IDSpecBodyMissing      = 5003111
	IDSpecUnexpectedBody   = 5003112
	IDSpecUnknownQuery     = 5003113
	IDSpecNoCredential     = 5003114
	IDSpecTooComplex       = 5003115

	// Level 2: what the guard learned.
	IDLearnedUnknownRoute    = 5003200
	IDLearnedMethodNotSeen   = 5003201
	IDLearnedQueryParam      = 5003203
	IDLearnedUnknownQuery    = 5003204
	IDLearnedMissingQuery    = 5003205
	IDLearnedContentType     = 5003206
	IDLearnedBodyType        = 5003207
	IDLearnedUnknownProperty = 5003208
	IDLearnedMissingProperty = 5003209
	IDLearnedUnexpectedBody  = 5003210
	IDLearnedBodyMissing     = 5003211
)

// VerdictInfo describes one verdict identifier.
type VerdictInfo struct {
	ID       int
	Name     string
	Level    int    // 0, 1 or 2
	Group    string // the Modes field that controls it
	Status   int    // the HTTP status when it blocks
	Severity string
	Meaning  string
}

// Verdicts lists every identifier the guard can report, in order. docs/apiguard.md is checked against it by a test.
func Verdicts() []VerdictInfo { return append([]VerdictInfo(nil), verdictTable...) }

var verdictTable = []VerdictInfo{
	{IDMethodNotAllowed, "method not allowed", 0, "Methods", 405, "medium", "The method is not on the allow-list."},
	{IDBodyTooLarge, "body too large", 0, "BodySize", 413, "medium", "The body is larger than any request to that method should carry."},
	{IDContentTypeMissing, "content type missing", 0, "Format", 415, "low", "The request has a body and no Content-Type."},
	{IDContentTypeUnseen, "content type unseen", 0, "Format", 415, "low", "The Content-Type is not one this API has been seen to use, or is not a media type."},
	{IDBodyMalformed, "body malformed", 0, "Format", 400, "low", "The body says it is JSON and is not valid JSON."},
	{IDBodyDuplicateKey, "body repeats a key", 0, "Format", 400, "medium", "A JSON object repeats a key, which different parsers read differently."},
	{IDRateLimited, "rate limited", 0, "Rate", 429, "medium", "One client sent more requests than the sustained or burst limit."},
	{IDAuthRateLimited, "authentication rate limited", 0, "AuthRate", 429, "high", "Too many requests to an authentication endpoint from one address (credential stuffing, password guessing)."},
	{IDMassAssignFlagged, "mass assignment suspected", 0, "MassAssign", 403, "medium", "A write body sets a privileged property (role, admin, price and the like). A warning only: nothing says clients never send it."},
	{IDMassAssignRefused, "mass assignment", 0, "MassAssign", 403, "high", "A write body sets a privileged property that the description or the learned model says this API's clients never send."},
	{IDInternalError, "internal error", 0, "-", 0, "high", "The guard failed on this request and did not inspect it. Never blocks."},

	{IDSpecUnknownRoute, "unknown route", 1, "Spec", 404, "medium", "No route in the description matches the path."},
	{IDSpecMethodNotAllowed, "method not allowed on route", 1, "Spec", 405, "medium", "The path is in the description but not with this method."},
	{IDSpecPathParam, "path parameter invalid", 1, "Spec", 400, "medium", "A path parameter has the wrong type or is outside its bounds."},
	{IDSpecQueryParam, "query parameter invalid", 1, "Spec", 400, "medium", "A query parameter has the wrong type, is outside its bounds, or is given more than once."},
	{IDSpecHeaderParam, "header parameter invalid", 1, "Spec", 400, "low", "A header parameter has the wrong type or is outside its bounds."},
	{IDSpecCookieParam, "cookie parameter invalid", 1, "Spec", 400, "low", "A cookie parameter has the wrong type or is outside its bounds."},
	{IDSpecMissingParam, "required parameter missing", 1, "Spec", 400, "medium", "A parameter the description requires is not there."},
	{IDSpecContentType, "content type not accepted", 1, "Spec", 415, "medium", "The route does not accept this Content-Type."},
	{IDSpecBodySchema, "body does not match schema", 1, "Spec", 400, "medium", "The JSON body does not satisfy the route's schema."},
	{IDSpecUnknownProperty, "unknown property", 1, "Spec", 400, "medium", "The body has a property the schema does not allow."},
	{IDSpecReadOnlyProperty, "read-only property", 1, "Spec", 403, "high", "The body sets a property the schema marks read-only."},
	{IDSpecBodyMissing, "body missing", 1, "Spec", 400, "low", "The route requires a body and there is none."},
	{IDSpecUnexpectedBody, "unexpected body", 1, "Spec", 400, "low", "The route takes no body and the request has one."},
	{IDSpecUnknownQuery, "unknown query parameter", 1, "Spec", 400, "low", "A query parameter the route does not list (only with RefuseUnknownParams)."},
	{IDSpecNoCredential, "credential missing", 1, "Spec", 401, "low", "The route requires a credential and none was presented."},
	{IDSpecTooComplex, "too complex to check", 1, "Spec", 400, "medium", "The body needs more work to check than the guard allows."},

	{IDLearnedUnknownRoute, "route never seen", 2, "Learned", 404, "low", "No learned route matches the path."},
	{IDLearnedMethodNotSeen, "method never seen on route", 2, "Learned", 405, "low", "The path is a learned route but this method has not been seen on it."},
	{IDLearnedQueryParam, "query parameter unlike what was seen", 2, "Learned", 400, "medium", "A query parameter has a kind of value, or a value, that was never seen for it."},
	{IDLearnedUnknownQuery, "query parameter never seen", 2, "Learned", 400, "low", "A query parameter that was never seen on the route."},
	{IDLearnedMissingQuery, "query parameter missing", 2, "Learned", 400, "low", "A parameter that every request to the route carried is missing."},
	{IDLearnedContentType, "content type never seen on route", 2, "Learned", 415, "low", "The Content-Type was never seen on the route."},
	{IDLearnedBodyType, "body value of an unseen type", 2, "Learned", 400, "medium", "A body property has a JSON type it was never seen with."},
	{IDLearnedUnknownProperty, "body property never seen", 2, "Learned", 400, "low", "The body has a property that was never seen on the route."},
	{IDLearnedMissingProperty, "body property missing", 2, "Learned", 400, "low", "A property that every body on the route carried is missing."},
	{IDLearnedUnexpectedBody, "body never seen on route", 2, "Learned", 400, "low", "The route has never been seen with a body."},
	{IDLearnedBodyMissing, "body missing on route", 2, "Learned", 400, "low", "Every request to the route carried a body and this one does not."},
}

var verdictByID = func() map[int]*VerdictInfo {
	m := make(map[int]*VerdictInfo, len(verdictTable))
	for i := range verdictTable {
		m[verdictTable[i].ID] = &verdictTable[i]
	}
	return m
}()

// finding is what a check found, before the mode decides whether it blocks.
type finding struct {
	id     int
	detail string // fixed text, or text drawn from the description's own names; never from the request
}

// verdict builds the inspect.Verdict for a finding under a mode.
func (f finding) verdict(m Mode) inspect.Verdict {
	info := verdictByID[f.id]
	msg := "apiguard: " + info.Name
	if f.detail != "" {
		msg += ": " + f.detail
	}
	status := info.Status
	return inspect.Verdict{ID: f.id, Message: msg, Block: m == ModeEnforce, Status: status, Severity: info.Severity}
}
