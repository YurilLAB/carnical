// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the response action works",
		Enabled:     true,
		Name:        "response.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "response",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test.php?id=12345",
						},
						Output: profile.ExpectedOutput{
							Headers: map[string]string{
								"content-type": "secret/mime",
							},
							Data:           `<?php echo "Hello World!\n" ?>`,
							TriggeredRules: []int{953120},
						},
					},
				},
			},
		},
		{
			// Media types are case-insensitive and may carry whitespace
			// before the parameters (RFC 9110 8.3.1).
			Title: "response mime type matched case-insensitively",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test.php?id=12345",
						},
						Output: profile.ExpectedOutput{
							Headers: map[string]string{
								"content-type": "Secret/MIME ; charset=utf-8",
							},
							Data:           `<?php echo "Hello World!\n" ?>`,
							TriggeredRules: []int{953120},
						},
					},
				},
			},
		},
	},
	Rules: `
SecResponseBodyAccess On
SecResponseBodyMimeType secret/mime
SecRule RESPONSE_BODY "@rx <\?(?:=|php)?\s+" \
  "id:953120,\
  phase:4,\
  block,\
  capture,\
  log"
`,
})
