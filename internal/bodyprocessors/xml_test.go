// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"bytes"
	"errors"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

func TestXMLAttribures(t *testing.T) {
	xmldoc := `<?xml version="1.0" encoding="UTF-8"?>
<bookstore>
<book>
  <title lang="en">Harry <bold>Potter</bold> Biography</title>
  <price secret="value">29.99</price>
</book>

<book>
  <title lang="en">Learning XML</title>
  <price>39.95</price>
</book>

</bookstore>`
	attrs, contents, err := readXML(bytes.NewReader([]byte(xmldoc)))
	if err != nil {
		t.Error(err)
	}
	if len(attrs) != 3 {
		t.Errorf("Expected 3 attributes, got %d", len(attrs))
	}
	if len(contents) != 6 {
		t.Errorf("Expected 6 contents, got %d", len(contents))
	}
	eattrs := []string{"en", "value"}
	econtent := []string{"Harry", "Potter", "Biography", "29.99", "Learning XML", "39.95"}
	for _, attr := range eattrs {
		if !strings.InSlice(attr, attrs) {
			t.Errorf("Expected attribute %s, got %v", attr, attrs)
		}
	}
	for _, content := range econtent {
		if !strings.InSlice(content, contents) {
			t.Errorf("Expected content %s, got %v", content, contents)
		}
	}
}

func TestXMLPayloadFlexibility(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "an element left open",
			input: `<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading>
			<body>Don't forget me this weekend!
		</note>`,
			want: []string{"Tove", "Jani", "Reminder", "Don't forget me this weekend!"},
		},
		{
			name:  "XML-RPC parameters",
			input: `<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value><string>' OR 1=1--</string></value></param></params></methodCall>`,
			want:  []string{"wp.getUsersBlogs", "admin", "' OR 1=1--"},
		},
		{
			name:  "an RSS link",
			input: `<rss version="2.0"><channel><title>News</title><link>https://example.com/</link><item><link>https://example.com/a</link></item></channel></rss>`,
			want:  []string{"News", "https://example.com/", "https://example.com/a"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, contents, err := readXML(bytes.NewReader([]byte(tc.input)))
			if err != nil {
				t.Fatal(err)
			}
			if len(contents) != len(tc.want) {
				t.Fatalf("contents %q, want %q", contents, tc.want)
			}
			for i := range tc.want {
				if contents[i] != tc.want[i] {
					t.Errorf("content %d is %q, want %q", i, contents[i], tc.want[i])
				}
			}
		})
	}
}

func TestXMLUnexpectedEOF(t *testing.T) {
	testCases := []struct {
		Name  string
		Input string
		Want  []string
	}{
		{
			Name: "inTheMiddleOfText",
			Input: `<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading>
			<body>Don't forget`,
			Want: []string{"Tove", "Jani", "Reminder", "Don't forget"},
		},
		{
			Name: "inTheMiddleOfStartElement",
			Input: `<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading>
			<bod`,
			Want: []string{"Tove", "Jani", "Reminder"},
		},
		{
			Name: "inTheMiddleOfEndElement",
			Input: `<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading`,
			Want: []string{"Tove", "Jani", "Reminder"},
		},
		{
			// Go's scanner reads to the end of the body for a quote in a
			// processing instruction inside the internal subset.
			Name:  "aQuoteInAProcessingInstructionInTheDoctype",
			Input: `<?xml version="1.0"?><!DOCTYPE x [<?pi it's?>]><x>Tove</x>`,
			Want:  nil,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			xmldoc := tc.Input
			_, contents, err := readXML(bytes.NewReader([]byte(xmldoc)))
			if !errors.Is(err, errXMLEndedEarly) {
				t.Errorf("want errXMLEndedEarly, got %v", err)
			}
			if got, want := len(contents), len(tc.Want); got != want {
				t.Errorf("contents count mismatch, got=%d, want=%d", got, want)
			}
			for i := range min(len(contents), len(tc.Want)) {
				if got, want := contents[i], tc.Want[i]; got != want {
					t.Errorf("Expected content got=%s, want=%s", got, want)
				}
			}
		})
	}
}
