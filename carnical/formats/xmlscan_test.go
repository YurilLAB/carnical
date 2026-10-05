package formats

import (
	"strings"
	"testing"
)

const (
	idXMLSyntax    = 5002200
	idXMLDoctype   = 5002201
	idXMLEntDecl   = 5002202
	idXMLExternal  = 5002203
	idXMLEntRef    = 5002204
	idXMLXInclude  = 5002205
	idXMLXSLT      = 5002206
	idXMLPI        = 5002207
	idXMLEncMis    = 5002208
	idXMLEncWide   = 5002209
	idXMLEncBad    = 5002210
	idXMLLimit     = 5002211
	idXMLDupAttr   = 5002212
	idXMLTextSplit = 5002213
)

func utf16le(s string) string {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return string(b)
}

var xmlRows = register("xml", []row{
	// Accepted.
	{name: "element", ct: "application/xml", body: `<a>text</a>`},
	{name: "declaration and attributes", ct: "application/xml", body: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a x="1" y='2'><b/></a>`},
	{name: "text/xml", ct: "text/xml; charset=utf-8", body: `<?xml version="1.0"?><a>é</a>`},
	{name: "soap envelope", ct: "application/soap+xml; charset=utf-8", body: `<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body><m:GetPrice xmlns:m="https://example.test/p"><m:Item>Apples</m:Item></m:GetPrice></soap:Body></soap:Envelope>`},
	{name: "xml-rpc", ct: "text/xml", body: `<?xml version="1.0"?><methodCall><methodName>demo.sayHello</methodName><params><param><value><string>x</string></value></param></params></methodCall>`},
	{name: "predefined entities", ct: "application/xml", body: `<a b="&lt;&amp;&quot;">&lt;&gt;&amp;&apos;&quot;</a>`},
	{name: "character references", ct: "application/xml", body: `<a>&#65;&#x42;&#x1F600;</a>`},
	{name: "comments between elements", ct: "application/xml", body: `<!-- one --><a><!-- two --><b/><!-- three --></a><!-- four -->`},
	{name: "cdata alone", ct: "application/xml", body: `<a><![CDATA[<b>not markup</b>]]></a>`},
	{name: "empty cdata alone", ct: "application/xml", body: `<a><![CDATA[]]></a>`},
	{name: "line breaks and indentation", ct: "application/xml", body: "<a>\r\n  <b>1</b>\r\n  <c>2</c>\r\n</a>\r\n"},
	{name: "latin-1 declared and in the header", ct: "text/xml; charset=iso-8859-1", body: "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a>caf\xe9</a>"},
	{name: "unicode names", ct: "application/xml", body: `<名前 属性="1">x</名前>`},
	{name: "svg is xml", ct: "image/svg+xml", body: `<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>`},
	{name: "xml at the depth limit", ct: "application/xml", body: nested("<a>", "</a>", 32)},
	{name: "namespaced attributes", ct: "application/xml", body: `<a xmlns:x="urn:x" xmlns="urn:y" x:id="1"/>`},

	// DOCTYPE, entities, external references.
	{name: "doctype", ct: "application/xml", body: `<!DOCTYPE a><a/>`, want: idXMLDoctype},
	{name: "doctype in lower case", ct: "application/xml", body: `<!doctype html><a/>`, want: idXMLDoctype},
	{name: "doctype with an internal subset and no entity", ct: "application/xml", body: `<!DOCTYPE a [<!-- c -->]><a/>`, want: idXMLDoctype},
	{name: "doctype with an entity", ct: "application/xml", body: `<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>`, want: idXMLEntDecl},
	{name: "external entity", ct: "application/xml", body: `<?xml version="1.0"?><!DOCTYPE a [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><a>&xxe;</a>`, want: idXMLEntDecl},
	{name: "parameter entity", ct: "application/xml", body: `<!DOCTYPE a [<!ENTITY % p SYSTEM "http://evil.test/x.dtd"> %p;]><a/>`, want: idXMLEntDecl},
	{name: "external dtd", ct: "application/xml", body: `<!DOCTYPE a SYSTEM "http://evil.test/x.dtd"><a/>`, want: idXMLExternal},
	{name: "public dtd", ct: "application/xml", body: `<!DOCTYPE a PUBLIC "-//X//EN" "http://evil.test/x.dtd"><a/>`, want: idXMLExternal},
	{name: "doctype that hides a closing bracket in a quote", ct: "application/xml", body: `<!DOCTYPE a [<!ENTITY x "]>">]><a/>`, want: idXMLEntDecl},
	{name: "entity declaration outside a doctype", ct: "application/xml", body: `<!ENTITY x "y"><a/>`, want: idXMLEntDecl},
	{name: "billion laughs", ct: "application/xml", body: `<!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><l>&b;</l>`, want: idXMLEntDecl},
	{name: "reference to an undeclared entity", ct: "application/xml", body: `<a>&xxe;</a>`, want: idXMLEntRef},
	{name: "reference in an attribute", ct: "application/xml", body: `<a b="&xxe;"/>`, want: idXMLEntRef},
	{name: "bare ampersand", ct: "application/xml", body: `<a>fish & chips</a>`, want: idXMLEntRef},
	{name: "NUL character reference", ct: "application/xml", body: `<a>&#0;</a>`, want: idXMLEntRef},
	{name: "character reference above the range", ct: "application/xml", body: `<a>&#x110000;</a>`, want: idXMLEntRef},
	{name: "reference with no end", ct: "application/xml", body: `<a>&amp</a>`, want: idXMLEntRef},

	// XInclude, XSLT, processing instructions.
	{name: "xinclude", ct: "application/xml", body: `<a xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></a>`, want: idXMLXInclude},
	{name: "xinclude by default namespace", ct: "application/xml", body: `<include xmlns="http://www.w3.org/2001/XInclude" href="x"/>`, want: idXMLXInclude},
	{name: "xinclude namespace hidden by a character reference", ct: "application/xml", body: `<a xmlns:xi="&#104;ttp://www.w3.org/2001/XInclude"><xi:include href="x"/></a>`, want: idXMLXInclude},
	{name: "xslt include", ct: "application/xml", body: `<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="http://evil.test/x.xsl"/></xsl:stylesheet>`, want: idXMLXSLT},
	{name: "xslt import", ct: "application/xml", body: `<s xmlns:x="http://www.w3.org/1999/XSL/Transform"><x:import href="file:///etc/passwd"/></s>`, want: idXMLXSLT},
	{name: "stylesheet instruction", ct: "application/xml", body: `<?xml version="1.0"?><?xml-stylesheet type="text/xsl" href="http://evil.test/x.xsl"?><a/>`, want: idXMLPI},
	{name: "other processing instruction", ct: "application/xml", body: `<a><?php echo 1; ?></a>`, want: idXMLPI},
	{name: "declaration that is not first", ct: "application/xml", body: ` <?xml version="1.0"?><a/>`, want: idXMLSyntax},
	{name: "second declaration", ct: "application/xml", body: `<?xml version="1.0"?><a><?xml version="1.0"?></a>`, want: idXMLSyntax},

	// Encodings.
	{name: "declared utf-16 on a utf-8 body", ct: "application/xml", body: `<?xml version="1.0" encoding="UTF-16"?><a>x</a>`, want: idXMLEncWide},
	{name: "declared utf-32", ct: "application/xml", body: `<?xml version="1.0" encoding="UTF-32LE"?><a/>`, want: idXMLEncWide},
	{name: "declared ucs-2", ct: "application/xml", body: `<?xml version="1.0" encoding="ucs-2"?><a/>`, want: idXMLEncWide},
	{name: "declared encoding the site does not take", ct: "application/xml", body: `<?xml version="1.0" encoding="UTF-7"?><a>+ADw-script+AD4-</a>`, want: idXMLEncBad},
	{name: "declared shift_jis", ct: "application/xml", body: `<?xml version="1.0" encoding="Shift_JIS"?><a/>`, want: idXMLEncBad},
	{name: "declaration disagrees with the header", ct: "text/xml; charset=iso-8859-1", body: `<?xml version="1.0" encoding="UTF-8"?><a>x</a>`, want: idXMLEncMis},
	{name: "header names latin-1, document has accents and no declaration", ct: "text/xml; charset=iso-8859-1", body: "<a>caf\xe9</a>", want: idXMLEncMis},
	{name: "declared ascii but accents", ct: "application/xml", body: "<?xml version=\"1.0\" encoding=\"us-ascii\"?><a>caf\xc3\xa9</a>", want: idXMLEncMis},
	{name: "utf-16 body", ct: "application/xml", body: "\xff\xfe" + utf16le(`<a>x</a>`), want: idWide},
	{name: "utf-16le body without a mark", ct: "application/xml", body: utf16le(`<?xml version="1.0"?><a>x</a>`), want: idWide},
	{name: "byte order mark", ct: "application/xml", body: "\xef\xbb\xbf<a/>", want: idBOM},
	{name: "invalid utf-8", ct: "application/xml", body: "<a>\xff</a>", want: idBadUTF8},
	{name: "NUL in text", ct: "application/xml", body: "<a>x\x00y</a>", want: idControl},
	{name: "control character in an attribute", ct: "application/xml", body: "<a b=\"\x08\"/>", want: idControl},

	// Hiding text from a filter.
	{name: "text split by a comment", ct: "application/xml", body: `<a>sel<!-- -->ect</a>`, want: idXMLTextSplit},
	{name: "text split by an empty cdata section", ct: "application/xml", body: `<a>sel<![CDATA[]]>ect</a>`, want: idXMLTextSplit},
	{name: "text then cdata", ct: "application/xml", body: `<a>sel<![CDATA[ect]]></a>`, want: idXMLTextSplit},
	{name: "two cdata sections", ct: "application/xml", body: `<a><![CDATA[sel]]><![CDATA[ect]]></a>`, want: idXMLTextSplit},
	{name: "cdata then text", ct: "application/xml", body: `<a><![CDATA[sel]]>ect</a>`, want: idXMLTextSplit},

	// Structure and limits.
	{name: "duplicate attribute", ct: "application/xml", body: `<a x="1" x="2"/>`, want: idXMLDupAttr},
	{name: "declaration with an unquoted version", ct: "application/xml", body: `<?xml version=1.0?><a/>`, want: idXMLSyntax},
	{name: "declaration with an unknown version", ct: "application/xml", body: `<?xml version="2.0"?><a/>`, want: idXMLSyntax},
	{name: "declaration with no version", ct: "application/xml", body: `<?xml encoding="utf-8"?><a/>`, want: idXMLSyntax},
	{name: "declaration with the parts in the wrong order", ct: "application/xml", body: `<?xml encoding="utf-8" version="1.0"?><a/>`, want: idXMLSyntax},
	{name: "declaration with a standalone that is not yes or no", ct: "application/xml", body: `<?xml version="1.0" standalone="maybe"?><a/>`, want: idXMLSyntax},
	{name: "declaration with no space between parts", ct: "application/xml", body: `<?xml version="1.0"encoding="utf-8"?><a/>`, want: idXMLSyntax},
	{name: "declaration that is not closed", ct: "application/xml", body: `<?xml version="1.0" encoding="utf-8"`, want: idXMLSyntax},
	{name: "declaration with a part that has no equals sign", ct: "application/xml", body: `<?xml version="1.0" encoding?><a/>`, want: idXMLSyntax},
	{name: "declaration with an encoding that is not a name", ct: "application/xml", body: `<?xml version="1.0" encoding="9bad"?><a/>`, want: idXMLSyntax},
	{name: "declaration with a part that has no closing quote", ct: "application/xml", body: `<?xml version="1.0 encoding="utf-8?><a/>`, want: idXMLSyntax},
	{name: "empty declaration", ct: "application/xml", body: `<?xml ?><a/>`, want: idXMLSyntax},
	{name: "declaration with a colon for the equals sign", ct: "application/xml", body: `<?xml version:"1.0"?><a/>`, want: idXMLSyntax},
	{name: "declaration with asterisks for quotes", ct: "application/xml", body: `<?xml version=*1.0*?><a/>`, want: idXMLSyntax},
	{name: "declaration with no closing quote at all", ct: "application/xml", body: `<?xml version="1.0?><a/>`, want: idXMLSyntax},
	{name: "an attribute with a colon for the equals sign", ct: "application/xml", body: `<a x:"1"/>`, want: idXMLSyntax},
	{name: "an attribute with a semicolon for the equals sign", ct: "application/xml", body: `<a x;"1"/>`, want: idXMLSyntax},
	{name: "an attribute with asterisks for quotes", ct: "application/xml", body: `<a x=*1*/>`, want: idXMLSyntax},
	{name: "a cdata section before the root", ct: "application/xml", body: `<![CDATA[x]]><a/>`, want: idXMLSyntax},
	{name: "a cdata section that is too long", ct: "application/xml", body: `<a><![CDATA[` + strings.Repeat("x", 50) + `]]></a>`, want: idXMLLimit,
		tweak: func(p *Policy) { p.XML.MaxTextLen = 49 }},
	{name: "a doctype with no end", ct: "application/xml", body: `<!DOCTYPE a`, want: idXMLSyntax},
	{name: "a doctype whose subset is not closed", ct: "application/xml", body: `<!DOCTYPE a [<!ELEMENT a ANY>`, want: idXMLSyntax},
	{name: "a doctype with a comment that is not closed", ct: "application/xml", body: `<!DOCTYPE a [<!-- x ]><a/>`, want: idXMLSyntax},
	{name: "declaration and nothing else", ct: "application/xml", body: `<?xml version="1.0"?>`, want: idXMLSyntax},
	{name: "a comment and nothing else", ct: "application/xml", body: `<!-- only a comment -->`, want: idXMLSyntax},
	{name: "an ampersand after the root", ct: "application/xml", body: `<a/>&amp;`, want: idXMLSyntax},
	{name: "a bracket after the root", ct: "application/xml", body: `<a/>]`, want: idXMLSyntax},
	{name: "an attribute with no value", ct: "application/xml", body: `<a x/>`, want: idXMLSyntax},
	{name: "an end tag with no start tag", ct: "application/xml", body: `</a>`, want: idXMLSyntax},
	{name: "an end tag after the root", ct: "application/xml", body: `<a/></a>`, want: idXMLSyntax},
	{name: "a processing instruction that is not closed", ct: "application/xml", body: `<a><?x </a>`, want: idXMLSyntax},
	{name: "a name that is not one", ct: "application/xml", body: `<a><1/></a>`, want: idXMLSyntax},
	{name: "an end tag with extra characters", ct: "application/xml", body: `<a></a x>`, want: idXMLSyntax},
	{name: "a self-closing tag that is not closed", ct: "application/xml", body: `<a/ >`, want: idXMLSyntax},
	{name: "mismatched end tag", ct: "application/xml", body: `<a><b></a></b>`, want: idXMLSyntax},
	{name: "unclosed element", ct: "application/xml", body: `<a><b></b>`, want: idXMLSyntax},
	{name: "two roots", ct: "application/xml", body: `<a/><b/>`, want: idXMLSyntax},
	{name: "text outside the root", ct: "application/xml", body: `<a/>trailing`, want: idXMLSyntax},
	{name: "text before the root", ct: "application/xml", body: `hello<a/>`, want: 5002044},
	{name: "unquoted attribute", ct: "application/xml", body: `<a x=1/>`, want: idXMLSyntax},
	{name: "attribute with a less-than sign", ct: "application/xml", body: `<a x="<"/>`, want: idXMLSyntax},
	{name: "missing space between attributes", ct: "application/xml", body: `<a x="1"y="2"/>`, want: idXMLSyntax},
	{name: "comment with two hyphens", ct: "application/xml", body: `<a><!-- a -- b --></a>`, want: idXMLSyntax},
	{name: "unterminated comment", ct: "application/xml", body: `<a><!-- x</a>`, want: idXMLSyntax},
	{name: "unterminated cdata", ct: "application/xml", body: `<a><![CDATA[x</a>`, want: idXMLSyntax},
	{name: "cdata end in text", ct: "application/xml", body: `<a>x]]>y</a>`, want: idXMLSyntax},
	{name: "markup that is not xml", ct: "application/xml", body: `<a><%= 1 %></a>`, want: idXMLSyntax},
	{name: "empty document", ct: "application/xml", body: "   \n", want: idXMLSyntax},
	{name: "one past the depth limit", ct: "application/xml", body: nested("<a>", "</a>", 33), want: idXMLLimit},
	{name: "a hundred thousand open elements", ct: "application/xml", body: strings.Repeat("<a>", 100000), want: idXMLLimit},
	{name: "too many attributes", ct: "application/xml", body: `<a x1="1" x2="2" x3="3" x4="4"/>`, want: idXMLLimit,
		tweak: func(p *Policy) { p.XML.MaxAttributes = 3 }},
	{name: "too many elements", ct: "application/xml", body: `<a><b/><b/><b/><b/></a>`, want: idXMLLimit,
		tweak: func(p *Policy) { p.XML.MaxElements = 4 }},
	{name: "name too long", ct: "application/xml", body: `<` + strings.Repeat("n", 300) + `/>`, want: idXMLLimit},
	{name: "run of text too long", ct: "application/xml", body: `<a>` + strings.Repeat("t", 50) + `</a>`, want: idXMLLimit,
		tweak: func(p *Policy) { p.XML.MaxTextLen = 49 }},
	{name: "attribute value too long", ct: "application/xml", body: `<a x="` + strings.Repeat("v", 50) + `"/>`, want: idXMLLimit,
		tweak: func(p *Policy) { p.XML.MaxAttrValueLen = 49 }},

	// Declared as XML.
	{name: "declared xml but json", ct: "application/xml", body: `{"a":1}`, want: 5002044},
	{name: "declared xml but a form", ct: "text/xml", body: `a=1&b=2`, want: 5002044},
})

func TestXML(t *testing.T) { runTable(t, xmlRows) }

// TestXMLNamespacedXSLTAndXIncludeAreFoundWhateverThePrefix shows the detection is by what a prefix is bound to, not by what it is called.
func TestXMLNamespacedXSLTAndXIncludeAreFoundWhateverThePrefix(t *testing.T) {
	for _, prefix := range []string{"x", "xsl", "q1", "a_b", "é"} {
		r := row{ct: "application/xml", body: `<r xmlns:` + prefix + `="http://www.w3.org/1999/XSL/Transform"/>`, want: idXMLXSLT}
		if err := r.check(New(Policy{})); err != nil {
			t.Errorf("%s: %v", prefix, err)
		}
	}
}

func FuzzXML(f *testing.F) {
	for _, r := range xmlRows {
		f.Add(r.body)
	}
	in := New(Policy{})
	f.Fuzz(func(t *testing.T, body string) {
		fuzzNoPanic(t, in, row{ct: "application/xml", body: body})
		fuzzNoPanic(t, in, row{ct: "text/xml; charset=iso-8859-1", body: body})
	})
}

func BenchmarkXML(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?><orders xmlns="urn:example:orders">`)
	for i := 0; sb.Len() < 100<<10; i++ {
		sb.WriteString(`<order id="12345" status="open"><customer>Alice Example</customer><item sku="A-1" qty="2">Widget &amp; Gadget</item><note>Deliver to the front door</note></order>`)
	}
	sb.WriteString(`</orders>`)
	benchBody(b, "application/xml", sb.String())
}
