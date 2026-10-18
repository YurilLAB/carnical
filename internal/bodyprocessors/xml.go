// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type xmlBodyProcessor struct {
}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	values, contents, err := readXML(reader)
	// A body cut by SecRequestBodyLimit under ProcessPartial ends mid-document,
	// and what was read is inspected. One that arrived that way is malformed:
	// what was read is still inspected, but the body is also an error, since
	// the rest of it may reach a backend that reads it differently.
	if errors.Is(err, errXMLEndedEarly) && v.InboundDataError().Get() == "1" {
		err = nil
	}
	if err == nil || errors.Is(err, errXMLEndedEarly) {
		col := v.RequestXML()
		col.Set("//@*", values)
		col.Set("/*", contents)
	}
	return err
}

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

func readXML(reader io.Reader) ([]string, []string, error) {
	var attrs []string
	var content []string
	dec := xml.NewDecoder(reader)
	// Not strict, so that a malformed document is still read; but no AutoClose: HTML's empty elements are ordinary
	// elements in XML, and closing <param> or <link> as soon as it opens makes </param> an error, which refused every
	// XML-RPC call and RSS document.
	dec.Strict = false
	dec.Entity = xml.HTMLEntity
	endedEarly := false
	for {
		token, err := dec.Token()
		if err != nil && err != io.EOF {
			if !isUnexpectedEOFXMLSyntaxError(err) {
				return nil, nil, err
			}
			endedEarly = true
		}
		if token == nil {
			break
		}
		switch tok := token.(type) {
		case xml.Directive:
			// Entities are not expanded here, so a value an entity holds
			// would only be seen in pieces, while a backend that expands
			// them reads it whole. A document that declares one is refused.
			if declaresEntity(tok) {
				return nil, nil, errXMLEntity
			}
		case xml.StartElement:
			for _, attr := range tok.Attr {
				attrs = append(attrs, attr.Value)
			}
		case xml.CharData:
			if c := strings.TrimSpace(string(tok)); c != "" {
				content = append(content, c)
			}
		}
	}
	if endedEarly {
		return attrs, content, errXMLEndedEarly
	}
	return attrs, content, nil
}

var errXMLEndedEarly = errors.New("xml: unexpected end of the body")

var errXMLEntity = errors.New("xml: entity declarations are not supported")

// declaresEntity reports whether a DOCTYPE directive declares an entity in
// its internal subset. Go keeps the subset's declarations in the directive.
func declaresEntity(d xml.Directive) bool {
	const decl = "<!entity"
	for i := 0; i+len(decl) <= len(d); i++ {
		if d[i] == '<' && bytes.EqualFold(d[i:i+len(decl)], []byte(decl)) {
			return true
		}
	}
	return false
}

func isUnexpectedEOFXMLSyntaxError(err error) bool {
	var serr *xml.SyntaxError
	return errors.As(err, &serr) && serr.Msg == "unexpected EOF"
}

var (
	_ plugintypes.BodyProcessor = &xmlBodyProcessor{}
)

func init() {
	RegisterBodyProcessor("xml", func() plugintypes.BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
