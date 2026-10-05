// SPDX-License-Identifier: Apache-2.0

package formats

import "sort"

// Action says what happens when a rule finds something.
type Action string

const (
	// Block refuses the request.
	Block Action = "block"
	// Monitor records the finding and lets the request through.
	Monitor Action = "monitor"
	// Off does not look for it at all.
	Off Action = "off"
)

// rule is one thing the inspector can find. Its identifier is stable (it appears in logs and the feed) and its name is what a
// policy uses to change what happens when it is found.
type rule struct {
	idx      int
	id       int
	name     string
	text     string // a fixed sentence: never anything from the request
	status   int
	severity string
	def      Action
}

// registry holds every rule, in the order they were declared.
var registry []*rule

func reg(id int, name string, status int, severity string, def Action, text string) *rule {
	r := &rule{idx: len(registry), id: id, name: name, text: text, status: status, severity: severity, def: def}
	registry = append(registry, r)
	return r
}

// The identifiers are grouped by format: 20xx content type, 202x shared text rules, 204x mismatch, 207x encoding, 21xx JSON,
// 22xx XML, 23xx GraphQL, 24xx NDJSON, 25xx YAML, 26xx form, 27xx multipart, 28xx URL query, 299x the inspector itself.
// docs/formats.md has the same table, and a test fails if the two differ.
var (
	// Content type.
	rTypeNotAllowed   = reg(5002001, "type-not-allowed", 415, "high", Block, "the Content-Type is not one this site accepts")
	rTypeOpaque       = reg(5002002, "type-opaque", 415, "high", Block, "a binary body type that nothing can inspect")
	rOpaqueTooLarge   = reg(5002003, "opaque-too-large", 413, "medium", Block, "a binary body larger than the site allows")
	rTypeMissing      = reg(5002004, "type-missing", 415, "medium", Block, "a request body with no Content-Type")
	rTypeMalformed    = reg(5002005, "type-malformed", 400, "high", Block, "a Content-Type that does not follow the grammar")
	rCharset          = reg(5002006, "charset-not-allowed", 415, "high", Block, "a charset this site does not accept")
	rTypeDupParam     = reg(5002007, "type-duplicate-param", 400, "high", Block, "a Content-Type parameter given more than once")
	rTypeDupHeader    = reg(5002008, "type-duplicate-header", 400, "high", Block, "more than one Content-Type header")
	rBodyOnGet        = reg(5002009, "body-on-get", 400, "medium", Block, "a request body on a GET or HEAD request")
	rBodyTooLarge     = reg(5002010, "body-too-large", 413, "medium", Block, "a request body larger than the site allows")
	rWideEncoding     = reg(5002020, "body-wide-encoding", 400, "high", Block, "a body in UTF-16 or UTF-32, which filters do not read")
	rInvalidUTF8      = reg(5002021, "body-invalid-utf8", 400, "high", Block, "a body that is not valid UTF-8")
	rControlChar      = reg(5002022, "body-control-char", 400, "medium", Block, "a NUL or control character where the format allows none")
	rBOM              = reg(5002023, "body-bom", 400, "medium", Block, "a byte order mark at the start of the body")
	rMismatchJSONBody = reg(5002040, "mismatch-json-body", 415, "high", Block, "a body that is JSON under a Content-Type that says it is not")
	rMismatchXMLBody  = reg(5002041, "mismatch-xml-body", 415, "high", Block, "a body that is XML under a Content-Type that says it is not")
	rMismatchMPBody   = reg(5002042, "mismatch-multipart-body", 415, "high", Block, "a body that is multipart under a Content-Type that says it is not")
	rMismatchDeclJSON = reg(5002043, "mismatch-declared-json", 400, "high", Block, "a body declared as JSON that does not start like JSON")
	rMismatchDeclXML  = reg(5002044, "mismatch-declared-xml", 400, "high", Block, "a body declared as XML that does not start like XML")

	// Content-Encoding.
	rEncUnsupported = reg(5002070, "encoding-unsupported", 415, "high", Block, "a Content-Encoding other than one gzip or deflate layer")
	rEncLayers      = reg(5002071, "encoding-layers", 415, "high", Block, "more than one layer of Content-Encoding")
	rEncCorrupt     = reg(5002072, "encoding-corrupt", 400, "high", Block, "a compressed body that cannot be decompressed")
	rEncTrailing    = reg(5002073, "encoding-trailing-data", 400, "high", Block, "data after the end of the compressed stream")
	rEncTooLarge    = reg(5002074, "encoding-too-large", 413, "high", Block, "a compressed body that expands past the size limit")
	rEncRatio       = reg(5002075, "encoding-ratio", 413, "high", Block, "a compressed body that expands far more than ordinary content does")

	// JSON.
	rJSONSyntax   = reg(5002100, "json-syntax", 400, "high", Block, "JSON that does not follow RFC 8259")
	rJSONTrailing = reg(5002101, "json-trailing-data", 400, "high", Block, "data after the JSON value")
	rJSONLimit    = reg(5002102, "json-limit", 400, "high", Block, "JSON over a size, depth or count limit")
	rJSONDupKey   = reg(5002103, "json-duplicate-key", 400, "high", Block, "an object key given twice (compared after decoding escapes, ignoring case)")
	rJSONProto    = reg(5002104, "json-proto-key", 400, "high", Block, "a key that pollutes an object prototype")
	rJSONNUL      = reg(5002105, "json-nul-escape", 400, "medium", Block, "an escaped NUL character in a string")
	rJSONSurr     = reg(5002106, "json-surrogate", 400, "high", Block, "an escaped surrogate that is not half of a valid pair")

	// XML.
	rXMLSyntax    = reg(5002200, "xml-syntax", 400, "high", Block, "XML that is not well formed")
	rXMLDoctype   = reg(5002201, "xml-doctype", 400, "high", Block, "a DOCTYPE declaration")
	rXMLEntDecl   = reg(5002202, "xml-entity-decl", 400, "critical", Block, "an ENTITY or other markup declaration")
	rXMLExternal  = reg(5002203, "xml-external-ref", 400, "critical", Block, "a reference to an external resource")
	rXMLEntRef    = reg(5002204, "xml-entity-ref", 400, "high", Block, "a reference to an entity that is not predefined, or an invalid character reference")
	rXMLXInclude  = reg(5002205, "xml-xinclude", 400, "critical", Block, "XInclude")
	rXMLXSLT      = reg(5002206, "xml-xslt", 400, "critical", Block, "an XSLT stylesheet namespace (xsl:include, xsl:import, document())")
	rXMLPI        = reg(5002207, "xml-pi", 400, "high", Block, "a processing instruction other than the XML declaration")
	rXMLEncMis    = reg(5002208, "xml-encoding-mismatch", 400, "high", Block, "a declared encoding that disagrees with the Content-Type charset or the bytes")
	rXMLEncWide   = reg(5002209, "xml-encoding-wide", 400, "high", Block, "a declared UTF-16 or UTF-32 encoding on a body that is not")
	rXMLEncBad    = reg(5002210, "xml-encoding-disallowed", 400, "high", Block, "a declared encoding this site does not accept")
	rXMLLimit     = reg(5002211, "xml-limit", 400, "high", Block, "XML over a size, depth or count limit")
	rXMLDupAttr   = reg(5002212, "xml-duplicate-attr", 400, "high", Block, "an attribute given twice on one element")
	rXMLTextSplit = reg(5002213, "xml-text-split", 400, "high", Block, "text split by a comment or CDATA section")

	// GraphQL.
	rGQLSyntax         = reg(5002300, "graphql-syntax", 400, "high", Block, "a GraphQL document that cannot be parsed")
	rGQLDepth          = reg(5002301, "graphql-depth", 400, "high", Block, "a GraphQL query nested deeper than the limit")
	rGQLFields         = reg(5002302, "graphql-fields", 400, "high", Block, "a GraphQL query that selects more fields than the limit")
	rGQLAliases        = reg(5002303, "graphql-aliases", 400, "high", Block, "a GraphQL query with more aliases than the limit")
	rGQLDirs           = reg(5002304, "graphql-directives", 400, "high", Block, "a GraphQL query with more directives than the limit")
	rGQLBatch          = reg(5002305, "graphql-batch", 400, "high", Block, "a GraphQL batch larger than the limit")
	rGQLIntro          = reg(5002306, "graphql-introspection", 403, "high", Block, "a GraphQL introspection query")
	rGQLFrag           = reg(5002307, "graphql-fragment", 400, "high", Block, "a GraphQL fragment that is cyclic, unknown or defined twice")
	rGQLShape          = reg(5002308, "graphql-request-shape", 400, "high", Block, "a GraphQL request whose parts are not the types the protocol uses")
	rGQLLimit          = reg(5002309, "graphql-limit", 400, "high", Block, "a GraphQL document over a size or count limit")
	rGQLGetMutation    = reg(5002310, "graphql-get-mutation", 403, "high", Block, "a GraphQL mutation selected for execution using GET")
	rGQLRequestFields  = reg(5002311, "graphql-request-fields", 400, "high", Block, "a GraphQL request whose selected operations exceed the total field limit")
	rGQLRequestAliases = reg(5002312, "graphql-request-aliases", 400, "high", Block, "a GraphQL request whose selected operations exceed the total alias limit")
	rGQLRequestDirs    = reg(5002313, "graphql-request-directives", 400, "high", Block, "a GraphQL request whose selected operations exceed the total directive limit")

	// NDJSON.
	rNDLines = reg(5002400, "ndjson-lines", 400, "high", Block, "more lines than the limit")
	rNDBlank = reg(5002401, "ndjson-blank-line", 400, "medium", Block, "a blank line between records")

	// YAML.
	rYAMLSyntax = reg(5002500, "yaml-syntax", 400, "high", Block, "YAML that cannot be parsed")
	rYAMLTag    = reg(5002501, "yaml-tag", 400, "critical", Block, "an explicit tag (a deserialisation attack)")
	rYAMLAnchor = reg(5002502, "yaml-anchor", 400, "high", Block, "more anchors or aliases than the limit (entity expansion)")
	rYAMLLimit  = reg(5002503, "yaml-limit", 400, "high", Block, "YAML over a size, depth or count limit")
	rYAMLMulti  = reg(5002504, "yaml-multi-document", 400, "high", Block, "more than one YAML document")
	rYAMLDup    = reg(5002505, "yaml-duplicate-key", 400, "high", Block, "a mapping key given twice")

	// application/x-www-form-urlencoded.
	rFormEscape = reg(5002600, "form-bad-escape", 400, "high", Block, "a percent escape that is not two hex digits")
	rFormCtl    = reg(5002601, "form-control-char", 400, "high", Block, "a NUL or control character, escaped or raw")
	rFormDup    = reg(5002602, "form-duplicate-param", 400, "medium", Monitor, "a parameter name given more than once")
	rFormLimit  = reg(5002603, "form-limit", 400, "high", Block, "a form over a count or length limit")
	rFormBrkt   = reg(5002604, "form-bracket-depth", 400, "high", Block, "a parameter name with brackets nested deeper than the limit")
	rFormSemi   = reg(5002605, "form-semicolon", 400, "high", Block, "a semicolon used as a separator")
	rFormProto  = reg(5002606, "form-proto-key", 400, "high", Block, "a parameter name that pollutes an object prototype")

	// multipart/form-data.
	rMPNoBoundary = reg(5002700, "multipart-no-boundary", 400, "high", Block, "a multipart type with no boundary")
	rMPBadBound   = reg(5002701, "multipart-bad-boundary", 400, "high", Block, "a boundary that RFC 2046 does not allow")
	rMPLimit      = reg(5002702, "multipart-limit", 400, "high", Block, "a multipart body over a part or header limit")
	rMPHeader     = reg(5002703, "multipart-header", 400, "high", Block, "a part header that does not follow the grammar")
	rMPDupHeader  = reg(5002704, "multipart-duplicate-header", 400, "high", Block, "a part header given twice")
	rMPDupName    = reg(5002705, "multipart-duplicate-name", 400, "medium", Monitor, "two parts with the same name")
	rMPFileMis    = reg(5002706, "multipart-filename-mismatch", 400, "critical", Block, "a filename and a filename* that disagree")
	rMPFileStar   = reg(5002707, "multipart-filename-star", 400, "medium", Monitor, "a filename* parameter, which RFC 7578 forbids")
	rMPNested     = reg(5002708, "multipart-nested", 400, "high", Block, "a multipart part inside a part")
	rMPTransfer   = reg(5002709, "multipart-transfer-encoding", 400, "high", Block, "a part transfer encoding that hides content from filters")
	rMPBareLF     = reg(5002710, "multipart-bare-lf", 400, "high", Block, "a line ending that is not CRLF where the structure needs one")
	rMPNoClose    = reg(5002711, "multipart-no-close", 400, "high", Block, "no closing boundary")
	rMPEpilogue   = reg(5002712, "multipart-epilogue", 400, "high", Block, "data after the closing boundary")
	rMPPreamble   = reg(5002713, "multipart-preamble", 400, "high", Block, "data before the first boundary")
	rMPDelim      = reg(5002714, "multipart-delimiter", 400, "high", Block, "a boundary line that is not a clean delimiter")
	rMPDisp       = reg(5002715, "multipart-disposition", 400, "high", Block, "a missing or invalid Content-Disposition")
	rMPDupParam   = reg(5002716, "multipart-duplicate-param", 400, "high", Block, "a Content-Disposition parameter given more than once")

	// URL query parameters, independent of form-body policy.
	rQueryEscape = reg(5002800, "query-bad-escape", 400, "high", Block, "a URL query percent escape that is not two hex digits")
	rQueryCtl    = reg(5002801, "query-control-char", 400, "high", Block, "a NUL or control character in URL query parameters")
	rQueryDup    = reg(5002802, "query-duplicate-param", 400, "medium", Monitor, "a URL query parameter name given more than once")
	rQueryLimit  = reg(5002803, "query-limit", 400, "high", Block, "URL query parameters over a count or length limit")
	rQueryBrkt   = reg(5002804, "query-bracket-depth", 400, "high", Block, "a URL query parameter name with brackets nested deeper than the limit")
	rQuerySemi   = reg(5002805, "query-semicolon", 400, "high", Block, "an unescaped semicolon in URL query parameters")
	rQueryProto  = reg(5002806, "query-proto-key", 400, "high", Block, "a URL query parameter name that pollutes an object prototype")
	rQueryUTF8   = reg(5002807, "query-invalid-utf8", 400, "high", Block, "URL query parameters that are not valid UTF-8")
	rQuerySize   = reg(5002808, "query-too-large", 414, "high", Block, "a raw URL query larger than the site allows")

	// The inspector itself.
	rPolicyInvalid = reg(5002990, "policy-invalid", 503, "critical", Block, "the formats policy is invalid, so bodies are refused")
	rInternal      = reg(5002991, "internal-error", 503, "critical", Block, "the body could not be checked")
)

// maxRules is the most rules the per-request bit set can hold.
const maxRules = 128

func ruleByName(name string) *rule {
	for _, r := range registry {
		if r.name == name {
			return r
		}
	}
	return nil
}

// RuleInfo describes one rule, for documentation and for a console that lets an owner choose what each one does.
type RuleInfo struct {
	ID       int
	Name     string
	Text     string
	Status   int
	Severity string
	Default  Action
}

// Rules lists every rule, in identifier order.
func Rules() []RuleInfo {
	out := make([]RuleInfo, 0, len(registry))
	for _, r := range registry {
		out = append(out, RuleInfo{ID: r.id, Name: r.name, Text: r.text, Status: r.status, Severity: r.severity, Default: r.def})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
