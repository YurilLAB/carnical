// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

// OCSF log format
// OCSF (Open Cybersecurity Schema Framework) (https://github.com/ocsf) is an open-source framework with the goal of providing an open standard for logging security events.
// This log format will produce a JSON log which adheres to the OCSF schema (https://schema.ocsf.io/)

package auditlog

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/events/application"
	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/events/application/enums"
	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/objects"
	ocsf_object_enums "github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/objects/enums"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

type ocsfFormatter struct{}

func (f ocsfFormatter) getRequestArguments(al plugintypes.AuditLog) string {
	argString := &strings.Builder{}
	if al.Transaction().Request().Args() != nil {
		args := al.Transaction().Request().Args().FindAll()

		argCount := len(args)
		for i, arg := range al.Transaction().Request().Args().FindAll() {
			fmt.Fprintf(argString, "%s=%s", arg.Key(), arg.Value())
			if i < argCount {
				argString.WriteString(",")
			}
		}
	}
	return argString.String()
}

func (f ocsfFormatter) getRequestHeaders(al plugintypes.AuditLog) []*objects.HttpHeader {
	requestHeaders := []*objects.HttpHeader{}
	for key, values := range al.Transaction().Request().Headers() {
		for _, value := range values {
			requestHeaders = append(requestHeaders, &objects.HttpHeader{
				Name:  key,
				Value: value,
			})
		}
	}
	return requestHeaders
}

func (f ocsfFormatter) getResponseHeaders(al plugintypes.AuditLog) []*objects.HttpHeader {
	responseHeaders := []*objects.HttpHeader{}
	for key, values := range al.Transaction().Response().Headers() {
		for _, value := range values {
			responseHeaders = append(responseHeaders, &objects.HttpHeader{
				Name:  key,
				Value: value,
			})
		}
	}
	return responseHeaders
}

func (f ocsfFormatter) getAffectedWebResources(al plugintypes.AuditLog) []*objects.WebResource {
	// Create an array of web Resources affected by this activity
	webResources := []*objects.WebResource{}
	webResources = append(webResources, &objects.WebResource{
		UrlString: al.Transaction().Request().URI(),
	})

	return webResources
}

// Returns an array of Enrichment objects containing the details of each message in AuditLog.Messages
func (f ocsfFormatter) getMatchDetails(al plugintypes.AuditLog) []*objects.Enrichment {
	matchDetails := []*objects.Enrichment{}

	for _, match := range al.Messages() {
		data := match.Data()
		if data == nil {
			continue // H-only messages have no K enrichment.
		}
		matchData, _ := json.Marshal(data)
		matchDetails = append(matchDetails, &objects.Enrichment{
			Data:  string(matchData),
			Name:  data.Msg(),
			Value: data.Data(),
		})
	}

	return matchDetails
}

// Returns an array of Observable objects
func (f ocsfFormatter) getObservables(al plugintypes.AuditLog) []*objects.Observable {
	observables := []*objects.Observable{}

	if al.Transaction().ServerID() != "" {
		observables = append(observables, &objects.Observable{
			Name:   "ServerID",
			Type:   "ServerID",
			TypeId: ocsf_object_enums.OBSERVABLE_TYPE_ID_OBSERVABLE_TYPE_ID_OTHER,
			Value:  al.Transaction().ServerID(),
		})
	}

	for _, file := range al.Transaction().Request().Files() {
		observables = append(observables, &objects.Observable{
			Name:   file.Name(),
			Type:   "File Name",
			TypeId: 7,
			Value:  file.Name(),
		})
		observables = append(observables, &objects.Observable{
			Name:   file.Name(),
			Type:   "Size",
			TypeId: ocsf_object_enums.OBSERVABLE_TYPE_ID_OBSERVABLE_TYPE_ID_OTHER,
			Value:  fmt.Sprint(file.Size()),
		})
		observables = append(observables, &objects.Observable{
			Name:   file.Name(),
			Type:   "Mime",
			TypeId: ocsf_object_enums.OBSERVABLE_TYPE_ID_OBSERVABLE_TYPE_ID_OTHER,
			Value:  file.Mime(),
		})
	}

	return observables
}

func (f ocsfFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	responseCode, err := ocsfInt32(al.Transaction().Response().Status())
	if err != nil {
		return nil, fmt.Errorf("OCSF response code: %w", err)
	}
	clientPort, err := ocsfInt32(al.Transaction().ClientPort())
	if err != nil {
		return nil, fmt.Errorf("OCSF client port: %w", err)
	}
	hostPort, err := ocsfInt32(al.Transaction().HostPort())
	if err != nil {
		return nil, fmt.Errorf("OCSF host port: %w", err)
	}
	_, offset := time.Now().Zone()
	// Go reports seconds; OCSF 1.2 requires minutes in [-1080, 1080].
	if offset < -18*60*60 || offset > 18*60*60 {
		return nil, fmt.Errorf("OCSF timezone offset is outside [-1080, 1080] minutes")
	}
	offsetMinutes, err := ocsfInt32(offset / 60)
	if err != nil {
		return nil, fmt.Errorf("OCSF timezone offset: %w", err)
	}

	// Determine the Action/ActionID based on whether the transaction was interrutped
	ActionID := enums.WEB_RESOURCES_ACTIVITY_ACTION_ID_WEB_RESOURCES_ACTIVITY_ACTION_ID_ALLOWED
	Action := "Allowed"
	if al.Transaction().IsInterrupted() {
		ActionID = enums.WEB_RESOURCES_ACTIVITY_ACTION_ID_WEB_RESOURCES_ACTIVITY_ACTION_ID_DENIED
		Action = "Denied"

	}

	// Populate the required fields for the WebRecourcesActivity
	webResourcesActivity := application.WebResourcesActivity{
		ActivityId:   enums.WEB_RESOURCES_ACTIVITY_ACTIVITY_ID_WEB_RESOURCES_ACTIVITY_ACTIVITY_ID_READ,
		ActivityName: "Read",
		CategoryName: "Application Activity",
		ClassName:    "Web Resources Activity",
		CategoryUid:  enums.WEB_RESOURCES_ACTIVITY_CATEGORY_UID_WEB_RESOURCES_ACTIVITY_CATEGORY_UID_APPLICATION_ACTIVITY,
		ClassUid:     enums.WEB_RESOURCES_ACTIVITY_CLASS_UID_WEB_RESOURCES_ACTIVITY_CLASS_UID_WEB_RESOURCES_ACTIVITY,
		Time:         al.Transaction().UnixTimestamp(),
		ActionId:     ActionID,
		Action:       Action,
		Metadata: &objects.Metadata{
			CorrelationUid: "",
			EventCode:      "",
			//Labels:         [2]string{"", ""},
			LogLevel: "",
			LogName:  "",
			//LogProvider: "OWASP Coraza Web Application Firewall",
			LogProvider: al.Transaction().Producer().Connector(),
			LogVersion:  al.Transaction().Producer().Version(),
			LoggedTime:  time.Now().UnixMicro(),
			Product: &objects.Product{
				VendorName: "OWASP Coraza Web Application Firewall",
			},
			Version: "1.2.0",
		},
		TypeUid:     enums.WEB_RESOURCES_ACTIVITY_TYPE_UID_WEB_RESOURCES_ACTIVITY_TYPE_UID_WEB_RESOURCES_ACTIVITY_READ,
		Enrichments: f.getMatchDetails(al),
		HttpRequest: &objects.HttpRequest{
			Version:     al.Transaction().Request().Protocol(),
			Args:        f.getRequestArguments(al),
			HttpMethod:  al.Transaction().Request().Method(),
			Uid:         al.Transaction().ID(),
			Url:         &objects.Url{UrlString: al.Transaction().Request().URI()},
			HttpHeaders: f.getRequestHeaders(al),
			Length:      al.Transaction().Request().Length(),
		},
		HttpResponse: &objects.HttpResponse{
			Code:        responseCode,
			HttpHeaders: f.getResponseHeaders(al),
		},
		SrcEndpoint: &objects.NetworkEndpoint{
			Ip:   al.Transaction().ClientIP(),
			Port: clientPort,
		},
		DstEndpoint: &objects.NetworkEndpoint{
			Ip:   al.Transaction().HostIP(),
			Port: hostPort,
		},
		WebResources: f.getAffectedWebResources(al),
	}

	userAgent := al.Transaction().Request().Headers()["user-agent"]
	if len(userAgent) > 0 {
		webResourcesActivity.HttpRequest.UserAgent = userAgent[0]
	}

	// Note: 'referer' is a misspelling of 'referrer' but was incorporated into the HTTP specification with this misspelling
	// see https://en.wikipedia.org/wiki/HTTP_referer
	referrer := al.Transaction().Request().Headers()["referer"]
	if len(referrer) > 0 {
		webResourcesActivity.HttpRequest.Referrer = referrer[0]
	}

	xForwardedFor := al.Transaction().Request().Headers()["x-forwarded-for"]
	if len(xForwardedFor) > 0 {
		webResourcesActivity.HttpRequest.XForwardedFor = xForwardedFor
	}

	if len(al.Messages()) > 0 {
		message := al.Messages()[0]
		webResourcesActivity.Message = message.Message()
		if trailer, ok := message.(auditLogWithErrMesg); ok && webResourcesActivity.Message == "" {
			webResourcesActivity.Message = trailer.ErrorMessage()
		}
	}

	webResourcesActivity.TimezoneOffset = offsetMinutes

	// The WebResource Activity Severity ID is not to be confused by the Transaction severity.  The Transaction severity has to do with Coraza error/debug severity,
	// while WebResource Activity Severity is defined by OCSF to represent the severity of the security event.
	// For now, we're setting severityID to 'Other' and setting Severity to the Highest severity of the matched rules.
	// A future update should map/translate rule severity to OCSF severity if possible.
	highestSeverity, _ := types.ParseRuleSeverity(al.Transaction().HighestSeverity())
	webResourcesActivity.Severity = highestSeverity.String()
	webResourcesActivity.SeverityId = enums.WEB_RESOURCES_ACTIVITY_SEVERITY_ID_WEB_RESOURCES_ACTIVITY_SEVERITY_ID_OTHER

	webResourcesActivity.StartTime = al.Transaction().UnixTimestamp()
	webResourcesActivity.TypeName = "Read"

	webResourcesActivity.Observables = f.getObservables(al)

	// Not implemented
	// webResourcesActivity.Count = 0
	// webResourcesActivity.Duration = 0
	// webResourcesActivity.EndTime = 0
	// webResourcesActivity.RawData = ""
	// webResourcesActivity.Status = ""
	// webResourcesActivity.StatusCode = ""
	// webResourcesActivity.StatusDetail = ""
	// webResourcesActivity.StatusId = enums.WEB_RESOURCES_ACTIVITY_STATUS_ID_WEB_RESOURCES_ACTIVITY_STATUS_ID_UNKNOWN
	// webResourcesActivity.Tls = &objects.Tls{}
	// webResourcesActivity.WebResourcesResult =
	// webResourcesActivity.Unmapped = nil

	return json.Marshal(&webResourcesActivity)
}

// ocsfInt32 preserves representable connector values and rejects overflow instead of changing the log.
func ocsfInt32(value int) (int32, error) {
	if value < math.MinInt32 || value > math.MaxInt32 {
		return 0, fmt.Errorf("value %d is outside the signed 32-bit schema range", value)
	}
	return int32(value), nil
}

func (ocsfFormatter) MIME() string {
	return "application/json"
}

var (
	_ plugintypes.AuditLogFormatter = (*ocsfFormatter)(nil)
)
