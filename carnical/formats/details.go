// SPDX-License-Identifier: Apache-2.0

package formats

// detail is a fixed phrase that can be added to a verdict message. It is an enumeration and not a string on purpose: a message can
// only be made of a rule's own sentence, one of these phrases and numbers, so nothing from the request (a key, a name, a value) can
// find its way into a log line or a response.
type detail uint8

const (
	dNone detail = iota

	// Content-Type and header values.
	dTooLong
	dBadMediaType
	dBadParamSyntax
	dExtendedParam
	dTooManyParams
	dUnterminatedQuote
	dCharsetNotUTF8
	dInPart

	// JSON, and shared by the other parsers where the same words fit.
	dEmptyDocument
	dUnexpectedEnd
	dUnexpectedChar
	dBadLiteral
	dBadNumber
	dExponentTooLong
	dNumberTooLong
	dStringTooLong
	dKeyTooLong
	dTooManyKeys
	dTooManyValues
	dTooDeep
	dUnterminatedString
	dBadEscape
	dInString
	dExpectedKey
	dExpectedColon
	dExpectedCommaOrEnd
	dNotJSONStart
	dNameTooLong
	dValueTooLong

	// XML.
	dNotXMLStart
	dBadDeclaration
	dDeclNotFirst
	dNoRoot
	dTextOutsideRoot
	dContentAfterRoot
	dMismatchedTag
	dBadName
	dBadTag
	dMissingSpace
	dExpectedEquals
	dExpectedQuote
	dLessThanInAttr
	dBadReference
	dUnknownEntity
	dBadCharRef
	dCDATAEnd
	dBadComment
	dBadMarkup
	dUnterminatedComment
	dUnterminatedCDATA
	dUnterminatedDoctype
	dUnterminatedPI
	dTextTooLong
	dTooManyElements
	dTooManyAttributes
	dHeaderDisagrees
	dNonASCII
	dHeaderNoDeclaration

	// GraphQL.
	dBadSpread
	dNotExecutable
	dUnexpectedToken
	dExpectedName
	dFragmentNamedOn
	dExpectedOn
	dExpectedVariable
	dEmptyList
	dExpectedCloseBracket
	dExpectedSelection
	dTooManyOperations
	dTooManyDefinitions
	dTooManySelections
	dQueryTooLarge
	dInGraphQL
	dFragmentCycle
	dUnknownFragment
	dDuplicateDefinition
	dBatchElement
	dRootNotObject
	dQueryNotString
	dVariablesNotObject
	dOperationNameNotString
	dExtensionsNotObject
	dGivenTwice
	dInQueryString
	dOperationSelection
	dProtocolCaseAlias

	// Form.
	dTruncatedEscape
	dBadHexEscape
	dEscapedControl
	dRawControl

	// Multipart.
	dBoundaryTooLong
	dBoundaryTrailingSpace
	dBoundaryChar
	dNoBoundaryInBody
	dBadBoundaryLine
	dTooManyParts
	dMidLine
	dNoBlankLine
	dHeaderTooLarge
	dTooManyHeaders
	dBadHeaderLine
	dNoDisposition
	dNotFormData
	dNoName
	dBadExtValue
	dExtParam
	dStarOnly

	// Compression.
	dBadChecksum
	dTruncated
	dBadCompressionHeader
	dBadStream

	// YAML.
	dBodyTooLong
	dTooManyAnchors
	dTooManyAliases
	dParserFailed
	dTooMuchCollectionWork

	dCount
)

var detailText = [dCount]string{
	dNone: "",

	dTooLong:           "the value is longer than 1024 bytes",
	dBadMediaType:      "the media type is not type/subtype",
	dBadParamSyntax:    "a parameter is not name=value",
	dExtendedParam:     "an extended (RFC 2231) parameter",
	dTooManyParams:     "too many parameters",
	dUnterminatedQuote: "a quoted string is not closed",
	dCharsetNotUTF8:    "the declared charset is not UTF-8 and the body has bytes above 127",
	dInPart:            "in a part header",

	dEmptyDocument:      "the document is empty",
	dUnexpectedEnd:      "the document ends early",
	dUnexpectedChar:     "an unexpected character",
	dBadLiteral:         "a literal is not true, false or null",
	dBadNumber:          "a number is malformed",
	dExponentTooLong:    "a number's exponent has too many digits",
	dNumberTooLong:      "a number has too many characters",
	dStringTooLong:      "a string is too long",
	dKeyTooLong:         "a key is too long",
	dTooManyKeys:        "too many object members",
	dTooManyValues:      "too many values",
	dTooDeep:            "nested too deeply",
	dUnterminatedString: "a string is not closed",
	dBadEscape:          "a string escape is not valid",
	dInString:           "inside a string",
	dExpectedKey:        "a quoted key was expected",
	dExpectedColon:      "a colon was expected",
	dExpectedCommaOrEnd: "a comma or a closing bracket was expected",
	dNotJSONStart:       "the body does not start like JSON",
	dNameTooLong:        "a name is too long",
	dValueTooLong:       "a value is too long",

	dNotXMLStart:         "the body does not start with a tag",
	dBadDeclaration:      "the XML declaration is malformed",
	dDeclNotFirst:        "an XML declaration is not at the start of the document",
	dNoRoot:              "there is no root element",
	dTextOutsideRoot:     "character data outside the root element",
	dContentAfterRoot:    "content after the root element",
	dMismatchedTag:       "an end tag does not match the open element",
	dBadName:             "a name is expected",
	dBadTag:              "a tag is malformed",
	dMissingSpace:        "white space is missing between attributes",
	dExpectedEquals:      "an attribute has no equals sign",
	dExpectedQuote:       "an attribute value is not quoted",
	dLessThanInAttr:      "an attribute value holds a less-than sign",
	dBadReference:        "an ampersand does not start a reference",
	dUnknownEntity:       "an entity other than the five predefined ones",
	dBadCharRef:          "a character reference to a character XML forbids",
	dCDATAEnd:            "a CDATA end marker in text",
	dBadComment:          "a comment holds two hyphens or ends with one",
	dBadMarkup:           "markup that is not an element, comment or CDATA section",
	dUnterminatedComment: "a comment is not closed",
	dUnterminatedCDATA:   "a CDATA section is not closed",
	dUnterminatedDoctype: "a DOCTYPE is not closed",
	dUnterminatedPI:      "a processing instruction is not closed",
	dTextTooLong:         "a run of text is too long",
	dTooManyElements:     "too many elements",
	dTooManyAttributes:   "too many attributes on one element",
	dHeaderDisagrees:     "the declared encoding is not the Content-Type charset",
	dNonASCII:            "the encoding is ASCII and the body has bytes above 127",
	dHeaderNoDeclaration: "the Content-Type names a single-byte charset and the document does not declare it",

	dBadSpread:              "a point that is not the three of a spread",
	dNotExecutable:          "a type system definition in a request",
	dUnexpectedToken:        "an unexpected token",
	dExpectedName:           "a name was expected",
	dFragmentNamedOn:        "a fragment may not be named on",
	dExpectedOn:             "the word on was expected",
	dExpectedVariable:       "a variable was expected",
	dEmptyList:              "an empty list where at least one item is required",
	dExpectedCloseBracket:   "a closing bracket was expected",
	dExpectedSelection:      "a selection set was expected",
	dTooManyOperations:      "too many operations in one document",
	dTooManyDefinitions:     "too many operations and fragments in one document",
	dTooManySelections:      "too many selections in one document",
	dQueryTooLarge:          "the document is larger than the limit",
	dInGraphQL:              "in a GraphQL document",
	dFragmentCycle:          "fragments spread each other in a cycle",
	dUnknownFragment:        "a fragment is spread that is not defined",
	dDuplicateDefinition:    "a fragment is defined twice",
	dBatchElement:           "an element of the batch is not an object",
	dRootNotObject:          "the request is neither an object nor an array of objects",
	dQueryNotString:         "the query is not a string",
	dVariablesNotObject:     "the variables are not an object",
	dOperationNameNotString: "the operation name is not a string",
	dExtensionsNotObject:    "the extensions are not an object",
	dGivenTwice:             "a GraphQL protocol parameter is given twice",
	dInQueryString:          "in the query string",
	dOperationSelection:     "the operation name does not select one uniquely named operation",
	dProtocolCaseAlias:      "a GraphQL protocol parameter uses noncanonical case",

	dTruncatedEscape: "a percent sign at the end with fewer than two digits after it",
	dBadHexEscape:    "a percent sign that is not followed by two hex digits",
	dEscapedControl:  "an escape of NUL or a control character",
	dRawControl:      "a raw control character",

	dBoundaryTooLong:       "the boundary is longer than the limit",
	dBoundaryTrailingSpace: "the boundary ends with a space",
	dBoundaryChar:          "the boundary holds a character RFC 2046 does not allow",
	dNoBoundaryInBody:      "the body does not contain the boundary",
	dBadBoundaryLine:       "a line starts with the boundary and is not a delimiter",
	dTooManyParts:          "too many parts",
	dMidLine:               "the boundary appears inside a line",
	dNoBlankLine:           "the boundary comes straight after the part's headers",
	dHeaderTooLarge:        "a part's headers are too large",
	dTooManyHeaders:        "a part has too many headers",
	dBadHeaderLine:         "a header line is not name: value",
	dNoDisposition:         "a part has no Content-Disposition",
	dNotFormData:           "the disposition is not form-data",
	dNoName:                "a part has no name",
	dBadExtValue:           "filename* is not a valid extended value",
	dExtParam:              "an extended or continued parameter other than filename*",
	dStarOnly:              "a filename* with no filename, a file to some parsers and a field to others",

	dBadChecksum:          "the checksum does not match",
	dTruncated:            "the stream ends early",
	dBadCompressionHeader: "the compression header is not valid",
	dBadStream:            "the compressed data is not valid",

	dBodyTooLong:           "the body is larger than the limit for this format",
	dTooManyAnchors:        "too many anchors",
	dTooManyAliases:        "too many aliases",
	dParserFailed:          "the parser could not read the document",
	dTooMuchCollectionWork: "too much collection parser work",
}
