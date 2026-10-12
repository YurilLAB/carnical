// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// XML currently disabled on TinyGo
//go:build !tinygo

package engine

import (
	"strings"

	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the body processors work",
		Enabled:     true,
		Name:        "postxml.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "postxml",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php?t1=aaa&t2=bbb&t3=ccc",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/xml",
							},
							Data: `<?xml version="1.0"?><xml><Cs7QAF attribute_name="attribute_value">test123</Cs7QAF></xml>`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{101, 102, 500},
							NonTriggeredRules: []int{103, 200002},
						},
					},
				},
			},
		},
		{
			// Entities are not expanded, so a body that declares one is
			// refused instead of being inspected in pieces.
			Title: "xml entity declaration",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/xml",
							},
							Data: `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "test"><!ENTITY b "123">]><x>&a;&b;</x>`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{200002},
						},
					},
				},
			},
		},
		{
			// A body cut by the limit under ProcessPartial ends early and
			// what was read is inspected; one that arrives cut short is an
			// error as well.
			Title: "xml body cut by the limit",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/xml",
							},
							Data: `<?xml version="1.0"?><xml><a>test123</a><b>` + strings.Repeat("A", 200) + `</b></xml>`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{102},
							NonTriggeredRules: []int{200002},
						},
					},
				},
			},
		},
		{
			Title: "xml body that arrives cut short",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/xml",
							},
							Data: `<?xml version="1.0"?><!DOCTYPE x [<?pi it's?>]><x>test123</x>`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{200002},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On
SecRequestBodyLimit 150
SecRequestBodyLimitAction ProcessPartial
SecRule REQUEST_HEADERS:content-type "application/xml" "id: 100, phase:1, pass, log, ctl:requestBodyProcessor=XML"
SecRule REQBODY_PROCESSOR "XML" "id: 101,phase:2,log,block"
SecRule XML:/*|XML://@* "test123" "id:102, phase:2,log,block"
#REQUEST_BODY must be empty for XML body processor
SecRule XML:/* "test123" "id:500, log"
SecRule XML://@* "attribute_value" "id:501, log"
SecRule REQBODY_ERROR "!@eq 0" "id:200002, phase:2, t:none, log, pass"
`,
})
