// SPDX-License-Identifier: Apache-2.0

package suricata

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

func TestSplitOptions(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []opt
		bad  bool
	}{
		{name: "plain", in: `msg:"a"; sid:1; nocase;`, want: []opt{{"msg", `"a"`, true}, {"sid", "1", true}, {"nocase", "", false}}},
		{name: "semicolon inside quotes", in: `content:"a;b"; sid:2;`, want: []opt{{"content", `"a;b"`, true}, {"sid", "2", true}}},
		{name: "escaped quote does not close", in: `content:"a\"b;c"; sid:3;`, want: []opt{{"content", `"a\"b;c"`, true}, {"sid", "3", true}}},
		{name: "escaped semicolon outside quotes", in: `msg:a\;b; sid:4;`, want: []opt{{"msg", `a\;b`, true}, {"sid", "4", true}}},
		{name: "colon in value kept", in: `pcre:"/a:b/i";`, want: []opt{{"pcre", `"/a:b/i"`, true}}},
		{name: "no trailing semicolon", in: `sid:5`, want: []opt{{"sid", "5", true}}},
		{name: "unterminated quote", in: `content:"abc; sid:6;`, bad: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := splitOptions(tt.in)
			if tt.bad {
				if err == nil {
					t.Fatalf("no error; got %v", got)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

func TestParseRuleHeader(t *testing.T) {
	good := `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"x"; sid:1;)`
	tests := []struct {
		name    string
		in      string
		proto   string
		wantErr error
	}{
		{name: "http", in: good, proto: "http"},
		{name: "bracketed address list", in: `alert http [1.1.1.1, 2.2.2.2] any -> [$A,$B] [80,443] (sid:1;)`, proto: "http"},
		{name: "both directions", in: `alert http any any <> any any (sid:1;)`, proto: "http"},
		{name: "tcp", in: `alert tcp any any -> any any (sid:1;)`, proto: "tcp"},
		{name: "reverse arrow is not a rule", in: `alert http any any <- any any (sid:1;)`, wantErr: errNotRule},
		{name: "missing words", in: `alert http any any -> any (sid:1;)`, wantErr: errNotRule},
		{name: "unknown action", in: `allow http any any -> any any (sid:1;)`, wantErr: errNotRule},
		{name: "no options", in: `alert http any any -> any any`, wantErr: errNotRule},
		{name: "not a rule at all", in: `hello (world)`, wantErr: errNotRule},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := parseRule(tt.in)
			if err != tt.wantErr {
				t.Fatalf("error %v, want %v", err, tt.wantErr)
			}
			if err == nil && r.proto != tt.proto {
				t.Fatalf("proto %q", r.proto)
			}
		})
	}
}

func TestDecodeContent(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: `abc`, want: "abc"},
		{in: `|41 42|c`, want: "ABc"},
		{in: `a|0d 0a|b`, want: "a\r\nb"},
		{in: `|3a|`, want: ":"},
		{in: `x\;y\"z\\w`, want: `x;y"z\w`},
		{in: `a\b`, want: `a\b`},      // an unknown escape keeps its backslash
		{in: `http\:`, want: "http:"}, // a colon is escaped in some rules and means a plain colon
		{in: `|41`, wantErr: true},
		{in: `|4g|`, wantErr: true},
		{in: `|4|`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := decodeContent(tt.in)
			if (err != nil) != tt.wantErr || (err == nil && string(got) != tt.want) {
				t.Fatalf("got %q, %v; want %q (err %v)", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestParsePCRE(t *testing.T) {
	tests := []struct {
		in      string
		want    pcreSpec
		wantErr bool
	}{
		{in: `"/a+b/i"`, want: pcreSpec{pattern: "a+b", flags: "i"}},
		{in: `"/a\/b/"`, want: pcreSpec{pattern: `a\/b`}},
		{in: `!"/x/R"`, want: pcreSpec{pattern: "x", flags: "R", negated: true}},
		{in: `"/a/b/s"`, want: pcreSpec{pattern: "a/b", flags: "s"}},
		{in: `"a/i"`, wantErr: true},
		{in: `"/abc"`, wantErr: true},
		{in: `/a/i`, wantErr: true},
		{in: `"/a/1"`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parsePCRE(tt.in)
			if (err != nil) != tt.wantErr || (err == nil && got != tt.want) {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}

// rl builds a rule around options; the sid and message are fixed.
func rl(opts string) string {
	return `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET TEST Thing"; flow:established,to_server; ` + opts + ` sid:2000001; rev:3; metadata:confidence High, signature_severity Major;)`
}

func conv(t *testing.T, rule string) importers.Result {
	t.Helper()
	return ConvertBytes("t.rules", []byte(rule+"\n"), importers.Options{})
}

func cond(op, pattern string, targets []string, transforms ...string) vpatch.Condition {
	return vpatch.Condition{Operator: op, Pattern: pattern, Targets: targets, Transforms: transforms}
}

var (
	uriT   = []string{"uri"}
	bodyT  = []string{"body"}
	bareT  = []string{"uri", "headers", "body"}
	dec    = "urldecode1"
	lower  = "lowercase"
	anyLen = `(?s:.)*`
)

func TestConvertRules(t *testing.T) {
	tests := []struct {
		name     string
		rule     string
		want     []vpatch.Condition // main first, then Also in order; nil when wantSkip is set
		wantSkip string
		wantDrop string
	}{
		// Buffers and how a content becomes a condition.
		{name: "uri content", rule: rl(`http.uri; content:"/a.php?";`), want: []vpatch.Condition{cond("contains", "/a.php?", uriT, dec)}},
		{name: "nocase lower-cases both sides", rule: rl(`http.uri; content:"/A.PHP"; nocase;`), want: []vpatch.Condition{cond("contains", "/a.php", uriT, dec, lower)}},
		{name: "startswith is a prefix", rule: rl(`http.uri; content:"/a"; startswith;`), want: []vpatch.Condition{cond("prefix", "/a", uriT, dec)}},
		{name: "endswith is a suffix", rule: rl(`http.uri; content:".php"; endswith;`), want: []vpatch.Condition{cond("suffix", ".php", uriT, dec)}},
		{name: "both is equality", rule: rl(`http.uri; content:"/a"; startswith; endswith;`), want: []vpatch.Condition{cond("equals", "/a", uriT, dec)}},
		{name: "raw uri is not decoded", rule: rl(`http.uri.raw; content:"%2e%2e";`), want: []vpatch.Condition{cond("contains", "%2e%2e", uriT)}},
		{name: "method token is equality", rule: rl(`http.method; content:"POST"; http.uri; content:"/x";`),
			want: []vpatch.Condition{cond("contains", "/x", uriT, dec), cond("equals", "POST", []string{"method"})}},
		{name: "body", rule: rl(`http.request_body; content:"a=b";`), want: []vpatch.Condition{cond("contains", "a=b", bodyT)}},
		{name: "cookie is the whole cookie header", rule: rl(`http.cookie; content:"uid=admin"; nocase;`), want: []vpatch.Condition{cond("contains", "uid=admin", []string{"header:cookie"}, lower)}},
		{name: "user agent", rule: rl(`http.user_agent; content:"Zollard";`), want: []vpatch.Condition{cond("contains", "Zollard", []string{"header:user-agent"})}},
		{name: "host and referer", rule: rl(`http.host; content:"a"; http.referer; content:"b";`),
			want: []vpatch.Condition{cond("contains", "a", []string{"header:host"}), cond("contains", "b", []string{"header:referer"})}},
		{name: "a content with no buffer is looked for in the whole request", rule: rl(`content:"func=";`), want: []vpatch.Condition{cond("contains", "func=", bareT)}},
		{name: "hex and escapes", rule: rl(`http.request_body; content:"|7b 22|a|22 3a|";`), want: []vpatch.Condition{cond("contains", `{"a":`, bodyT)}},
		{name: "legacy uricontent", rule: rl(`uricontent:"/x.php";`), want: []vpatch.Condition{cond("contains", "/x.php", uriT, dec)}},
		{name: "legacy modifiers after a content", rule: rl(`content:"/x"; http_uri; content:"a=1"; http_client_body; nocase;`),
			want: []vpatch.Condition{cond("contains", "/x", uriT, dec), cond("contains", "a=1", bodyT, lower)}},
		{name: "buffer transform", rule: rl(`http.uri; url_decode; to_lowercase; content:"/a";`), want: []vpatch.Condition{cond("contains", "/a", uriT, dec, dec, lower)}},

		// Order and position.
		{name: "distance zero keeps the order", rule: rl(`http.uri; content:"a"; content:"b"; distance:0;`),
			want: []vpatch.Condition{cond("rx", "a"+anyLen+"b", uriT, dec)}},
		{name: "contents with no relative modifier are independent", rule: rl(`http.uri; content:"a"; content:"b";`),
			want: []vpatch.Condition{cond("contains", "a", uriT, dec), cond("contains", "b", uriT, dec)}},
		{name: "distance and within bound the gap", rule: rl(`http.uri; content:"ab"; content:"cd"; distance:1; within:4;`),
			want: []vpatch.Condition{cond("rx", `ab(?s:.){1,3}cd`, uriT, dec)}},
		{name: "within alone starts at zero", rule: rl(`http.uri; content:"ab"; content:"cd"; within:5;`),
			want: []vpatch.Condition{cond("rx", `ab(?s:.){0,3}cd`, uriT, dec)}},
		{name: "exact gap", rule: rl(`http.uri; content:"s?"; distance:1; within:2;`), want: []vpatch.Condition{cond("contains", `s?`, uriT, dec)}},
		{name: "nocase pieces are scoped", rule: rl(`http.uri; content:"SELECT"; nocase; content:"from"; distance:0;`),
			want: []vpatch.Condition{cond("rx", `(?i:SELECT)`+anyLen+`from`, uriT, dec)}},
		{name: "startswith anchors the chain", rule: rl(`http.uri; content:"/ecp/"; startswith; content:"x="; distance:0;`),
			want: []vpatch.Condition{cond("rx", `\A/ecp/`+anyLen+`x=`, uriT, dec)}},
		{name: "endswith ends the chain", rule: rl(`http.uri; content:"a"; content:".cgi"; distance:0; endswith;`),
			want: []vpatch.Condition{cond("rx", `a`+anyLen+`\.cgi\z`, uriT, dec)}},
		{name: "depth alone is a window from the start", rule: rl(`http.request_body; content:"id="; depth:10;`),
			want: []vpatch.Condition{cond("rx", `\A(?s:.){0,7}id=`, bodyT)}},
		{name: "offset and depth are a window", rule: rl(`http.request_body; content:"def"; offset:3; depth:3;`),
			want: []vpatch.Condition{cond("rx", `\A(?s:.){3}def`, bodyT)}},
		{name: "offset alone", rule: rl(`http.request_body; content:"x"; offset:4;`), want: []vpatch.Condition{cond("rx", `\A(?s:.){4,}x`, bodyT)}},
		{name: "content then relative pcre is one chain", rule: rl(`http.uri; content:".cmd\""; nocase; pcre:"/\x26+/Ri";`),
			want: []vpatch.Condition{cond("rx", `(?i:\.cmd")(?s:.)*(?i:\x26+)`, uriT, dec)}},
		{name: "a leading ^ on a relative pcre means right after the previous match", rule: rl(`http.uri; content:"image="; nocase; pcre:"/^.+(?:script|onload)/Ri";`),
			want: []vpatch.Condition{cond("rx", `(?i:image=)(?i:.+(?:script|onload))`, uriT, dec)}},
		{name: "the A flag on a relative pcre is the same", rule: rl(`http.uri; content:"a="; pcre:"/\d+/RA";`),
			want: []vpatch.Condition{cond("rx", `a=(?:\d+)`, uriT, dec)}},
		{name: "a relative pcre that starts with a word boundary is not joined", rule: rl(`http.uri; content:"a="; pcre:"/\bunion\b/Ri";`),
			want: []vpatch.Condition{cond("contains", "a=", uriT, dec), {Operator: "rx", Pattern: `\bunion\b`, Flags: "i", Targets: uriT, Transforms: []string{dec}}}, wantDrop: "relative-pcre-order"},
		{name: "a relative pcre with ^ in the middle is not joined", rule: rl(`http.uri; content:"a="; pcre:"/(?:x|^y)/R";`),
			want: []vpatch.Condition{cond("contains", "a=", uriT, dec), cond("rx", `(?:x|^y)`, uriT, dec)}, wantDrop: "relative-pcre-order"},
		{name: "relative content after a pcre is not joined, and the tier drops", rule: rl(`http.uri; pcre:"/a+/"; content:"b"; distance:0;`),
			want: []vpatch.Condition{cond("rx", `a+`, uriT, dec), cond("contains", "b", uriT, dec)}, wantDrop: "relative-after-pcre-order"},

		// pcre.
		{name: "pcre flags", rule: rl(`http.uri; pcre:"/a.b/smi";`), want: []vpatch.Condition{{Operator: "rx", Pattern: `(?sm)a.b`, Flags: "i", Targets: uriT, Transforms: []string{dec}}}},
		{name: "pcre anchored flag", rule: rl(`http.uri; pcre:"/a|b/A";`), want: []vpatch.Condition{cond("rx", `\A(?:a|b)`, uriT, dec)}},
		{name: "pcre U flag is the uri buffer", rule: rl(`pcre:"/^.{1,5}x/U";`), want: []vpatch.Condition{cond("rx", `^.{1,5}x`, uriT, dec)}},
		{name: "pcre P flag is the body", rule: rl(`pcre:"/a=1/P";`), want: []vpatch.Condition{cond("rx", `a=1`, bodyT)}},
		{name: "pcre I flag is the raw uri", rule: rl(`pcre:"/%25/I";`), want: []vpatch.Condition{cond("rx", `%25`, uriT)}},
		{name: "negated pcre", rule: rl(`http.uri; content:"/a"; pcre:!"/b/";`), want: []vpatch.Condition{cond("contains", "/a", uriT, dec), {Operator: "rx", Pattern: "b", Targets: uriT, Transforms: []string{dec}, Negate: true}}},
		{name: "possessive quantifier translated", rule: rl(`http.uri; pcre:"/a\s*+b/";`), want: []vpatch.Condition{cond("rx", `a\s*b`, uriT, dec)}},
		{name: "pcre lookahead", rule: rl(`http.uri; pcre:"/a(?=b)/";`), wantSkip: "pcre:lookaround"},
		{name: "pcre x flag", rule: rl(`http.uri; pcre:"/a b/x";`), wantSkip: "pcre-flag:x"},
		{name: "pcre in the header block", rule: rl(`http.header; pcre:"/^a/m";`), wantSkip: "pcre-in-header-buffer"},

		// Negation and size.
		{name: "negated content", rule: rl(`http.uri; content:"/a"; content:!"/admin/"; nocase;`),
			want: []vpatch.Condition{cond("contains", "/a", uriT, dec), {Operator: "contains", Pattern: "/admin/", Targets: uriT, Transforms: []string{dec, lower}, Negate: true}}},
		{name: "relative negated content", rule: rl(`http.uri; content:"/a"; content:!"b"; within:5;`), wantSkip: "negated-relative-content"},
		{name: "only negated", rule: rl(`http.uri; content:!"/a";`), wantSkip: "only-negated-matches"},
		{name: "bsize greater", rule: rl(`http.uri; bsize:>600; content:"/a";`),
			want: []vpatch.Condition{cond("contains", "/a", uriT, dec), cond("rx", `(?s)\A.{601,}\z`, uriT, dec)}},
		{name: "bsize exact", rule: rl(`http.referer; bsize:14; content:"x";`),
			want: []vpatch.Condition{cond("contains", "x", []string{"header:referer"}), cond("rx", `(?s)\A.{14}\z`, []string{"header:referer"})}},
		{name: "urilen", rule: rl(`urilen:10; http.uri; content:"/login.cgi";`),
			want: []vpatch.Condition{cond("contains", "/login.cgi", uriT, dec), cond("rx", `(?s)\A.{10}\z`, uriT)}},
		{name: "bsize beyond what RE2 repeats", rule: rl(`http.uri; bsize:>20000; content:"/a";`), wantSkip: "bsize-too-large"},

		// The header block.
		{name: "a header line with its break", rule: rl(`http.header; content:"Authorization|3a 20|Basic abc|0d 0a|";`),
			want: []vpatch.Condition{cond("equals", "Basic abc", []string{"header:authorization"})}},
		{name: "a header line prefix", rule: rl(`http.header; content:"User-Agent|3a 20|Mozilla";`), want: []vpatch.Condition{cond("prefix", "Mozilla", []string{"header:user-agent"})}},
		{name: "a header line with nocase", rule: rl(`http.header; header_lowercase; content:"authorization|3a 20|Basic|20|YW"; nocase;`),
			want: []vpatch.Condition{cond("prefix", "basic yw", []string{"header:authorization"}, lower)}},
		{name: "a header that must be present", rule: rl(`http.header; content:"|0d 0a|X-Forwarded-Host|3a|";`), want: []vpatch.Condition{cond("rx", "^", []string{"header:x-forwarded-host"})}},
		{name: "a header that must be absent", rule: rl(`http.uri; content:"/a"; http.header; content:!"|0d 0a|Referer|3a|";`),
			want: []vpatch.Condition{cond("contains", "/a", uriT, dec), {Operator: "rx", Pattern: "^", Targets: []string{"header:referer"}, Negate: true}}},
		{name: "a piece of a header value", rule: rl(`http.header; content:"substr{"; nocase;`), want: []vpatch.Condition{cond("contains", "substr{", []string{"headers"}, lower)}},
		{name: "a url in a header is a piece, not a header line", rule: rl(`http.header; content:"http://evil";`), want: []vpatch.Condition{cond("contains", "http://evil", []string{"headers"})}},
		{name: "content that needs two header lines", rule: rl(`http.header; content:"a|0d 0a|b";`), wantSkip: "header-spanning-lines"},
		{name: "order between header contents is dropped", rule: rl(`http.header; content:"Content-Type|3a|"; content:"multipart"; distance:0;`),
			want: []vpatch.Condition{cond("rx", "^", []string{"header:content-type"}), cond("contains", "multipart", []string{"headers"})}, wantDrop: "header-content-order"},

		// What is not converted.
		{name: "response direction", rule: strings.Replace(rl(`http.uri; content:"/a";`), "to_server", "to_client", 1), wantSkip: "response-direction"},
		{name: "flowbits isset", rule: rl(`flowbits:isset,x; http.uri; content:"/a";`), wantSkip: "flowbits"},
		{name: "flowbits set with noalert", rule: rl(`flowbits:set,x; noalert; http.uri; content:"/a";`), wantSkip: "noalert"},
		{name: "xbits", rule: rl(`xbits:isset,x,track ip_src; http.uri; content:"/a";`), wantSkip: "stateful:xbits"},
		{name: "byte_test", rule: rl(`http.uri; content:"/a"; byte_test:2,>,5,0;`), wantSkip: "unsupported-keyword:byte_test"},
		{name: "isdataat", rule: rl(`http.uri; content:"/a"; isdataat:10,relative;`), wantSkip: "unsupported-keyword:isdataat"},
		{name: "request line buffer", rule: rl(`http.request_line; content:"GET /a";`), wantSkip: "unsupported-buffer:request-line"},
		{name: "header names buffer", rule: rl(`http.header_names; content:"|0d 0a|host|0d 0a|";`), wantSkip: "unsupported-buffer:header-names"},
		{name: "response buffer", rule: rl(`http.response_body; content:"x";`), wantSkip: "unsupported-buffer:response"},
		{name: "binary content", rule: rl(`http.uri; content:"|c0 af|";`), wantSkip: "binary-content"},
		{name: "not http", rule: strings.Replace(rl(`content:"x";`), "alert http", "alert udp", 1), wantSkip: "not-http-rule:udp"},
		{name: "tcp rule that uses http buffers", rule: strings.Replace(rl(`http.uri; content:"/a";`), "alert http", "alert tcp", 1), want: []vpatch.Condition{cond("contains", "/a", uriT, dec)}},
		{name: "action is not alert", rule: strings.Replace(rl(`http.uri; content:"/a";`), "alert http", "drop http", 1), wantSkip: "action-not-alert"},
		{name: "no sid", rule: `alert http any any -> any any (msg:"x"; http.uri; content:"/a";)`, wantSkip: "no-sid"},
		{name: "modifier without a content", rule: rl(`nocase;`), wantSkip: "modifier-without-content:nocase"},
		{name: "unknown keyword", rule: rl(`http.uri; content:"/a"; frobnicate:1;`), wantSkip: "unsupported-keyword:frobnicate"},
		{name: "within shorter than the content", rule: rl(`http.uri; content:"abc"; content:"defg"; within:2;`), wantSkip: "within-shorter-than-content"},
		{name: "malformed content", rule: rl(`http.uri; content:abc;`), wantSkip: "malformed-content"},
		{name: "no match at all", rule: rl(``), wantSkip: "no-match-conditions"},
		{name: "licence: a GPL sid", rule: strings.Replace(rl(`http.uri; content:"/a";`), "sid:2000001", "sid:2000", 1), wantSkip: "licence-not-bsd"},

		// Dropped constraints lower the tier.
		{name: "threshold is dropped", rule: rl(`threshold:type both,track by_dst,count 3,seconds 90; http.uri; content:"/a";`),
			want: []vpatch.Condition{cond("contains", "/a", uriT, dec)}, wantDrop: "threshold"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := conv(t, tt.rule)
			if tt.wantSkip != "" {
				if len(res.Signatures) != 0 || res.Report.Skipped[tt.wantSkip] != 1 {
					t.Fatalf("signatures %d, skipped %v, errors %v; want skip %q", len(res.Signatures), res.Report.Skipped, res.Report.Errors, tt.wantSkip)
				}
				return
			}
			if len(res.Signatures) != 1 {
				t.Fatalf("signatures %d, skipped %v, errors %v", len(res.Signatures), res.Report.Skipped, res.Report.Errors)
			}
			s := res.Signatures[0]
			got := append([]vpatch.Condition{s.Condition}, s.Also...)
			// The main condition is chosen by rank; compare as a set but keep the order of Also.
			if !sameConditions(got, tt.want) {
				t.Fatalf("got\n  %+v\nwant\n  %+v", got, tt.want)
			}
			wantTier := "community"
			if tt.wantDrop != "" {
				wantTier = "experimental"
				if res.Report.Dropped[tt.wantDrop] != 1 {
					t.Fatalf("dropped %v, want %q", res.Report.Dropped, tt.wantDrop)
				}
			}
			if s.Tier != wantTier {
				t.Fatalf("tier %q, want %q", s.Tier, wantTier)
			}
		})
	}
}

func sameConditions(got, want []vpatch.Condition) bool {
	if len(got) != len(want) {
		return false
	}
	used := make([]bool, len(want))
	for _, g := range got {
		found := false
		for i, w := range want {
			if !used[i] && reflect.DeepEqual(normalize(g), normalize(w)) {
				used[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func normalize(c vpatch.Condition) vpatch.Condition {
	if len(c.Transforms) == 0 {
		c.Transforms = nil
	}
	return c
}

func TestAllowCopyleft(t *testing.T) {
	rule := strings.Replace(rl(`http.uri; content:"/a";`), "sid:2000001", "sid:100000005", 1)
	if res := conv(t, rule); len(res.Signatures) != 0 || res.Report.Skipped["licence-not-bsd"] != 1 {
		t.Fatalf("a GPL rule was converted without being asked: %+v", res.Report.Skipped)
	}
	res := ConvertBytes("t.rules", []byte(rule), importers.Options{AllowCopyleft: true})
	if len(res.Signatures) != 1 {
		t.Fatalf("not converted with AllowCopyleft: %+v", res.Report.Skipped)
	}
}

func TestMetadata(t *testing.T) {
	rule := `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS WordPress Plugin foo SQL Injection Attempt (CVE-2024-1234)"; flow:established,to_server; ` +
		`http.uri; content:"/wp-content/plugins/foo/x.php"; nocase; reference:cve,2023-9999; classtype:web-application-attack; sid:2000009; rev:7; ` +
		`metadata:affected_product WordPress, confidence Low, signature_severity Minor, cve CVE_2022_0001;)`
	res := conv(t, rule)
	if len(res.Signatures) != 1 {
		t.Fatalf("%+v", res.Report)
	}
	s := res.Signatures[0]
	checks := map[string]bool{
		"id":          s.ID == "ET-2000009",
		"rev":         s.Rev == 7,
		"sources":     reflect.DeepEqual(s.Sources, []string{"suricata:2000009@7"}),
		"cves":        reflect.DeepEqual(s.CVEs, []string{"CVE-2022-0001", "CVE-2023-9999", "CVE-2024-1234"}),
		"category":    s.Category == "sqli",
		"severity":    s.Severity == "medium",
		"confidence":  s.Confidence == "low" && s.Action == "log",
		"scope":       reflect.DeepEqual(s.Scope, []string{"wordpress:plugin:foo"}),
		"description": strings.HasPrefix(s.Description, "ET WEB_SPECIFIC_APPS WordPress Plugin foo"),
	}
	for k, ok := range checks {
		if !ok {
			t.Errorf("%s wrong: %+v", k, s)
		}
	}
	res = ConvertBytes("t.rules", []byte(rule), importers.Options{Revision: "11303", Tier: "verified"})
	if res.Signatures[0].Sources[0] != "suricata:2000009@11303" || res.Signatures[0].Tier != "verified" {
		t.Errorf("revision and tier options: %+v", res.Signatures[0])
	}
}

func TestFileHandling(t *testing.T) {
	text := "# a comment\n\n" +
		"#" + rl(`http.uri; content:"/off";`) + "\n" + // switched off upstream
		rl(`http.uri; content:"/a";`) + "\n" +
		"alert http any any -> any any (msg:\"unterminated; sid:2000002;)\n" +
		"alert http any any -> any (sid:1;)\n" +
		"alert http any any -> any any (msg:\"x\"; http.uri; content:\"/b\"; \\\n  sid:2000003;)\n" // continued line
	res := ConvertBytes("t.rules", []byte(text), importers.Options{})
	r := res.Report
	if len(res.Signatures) != 2 || res.Signatures[0].ID != "ET-2000001" || res.Signatures[1].ID != "ET-2000003" {
		t.Fatalf("signatures %+v report %+v", res.Signatures, r)
	}
	if r.UnitsRead != 5 || r.Skipped["disabled-in-source"] != 1 || r.Skipped["malformed-rule"] != 2 {
		t.Fatalf("report %+v", r)
	}
	t.Run("a rule longer than the limit", func(t *testing.T) {
		long := `alert http any any -> any any (msg:"x"; http.uri; content:"` + strings.Repeat("a", 70000) + `"; sid:2000004;)`
		res := ConvertBytes("t.rules", []byte(long), importers.Options{})
		if len(res.Signatures) != 0 || res.Report.Skipped["rule-too-long"] != 1 {
			t.Fatalf("%+v", res.Report.Skipped)
		}
	})
	t.Run("a content longer than the pattern limit", func(t *testing.T) {
		long := `alert http any any -> any any (msg:"x"; http.uri; content:"` + strings.Repeat("a", 9000) + `"; sid:2000004;)`
		res := ConvertBytes("t.rules", []byte(long), importers.Options{})
		if len(res.Signatures) != 0 || res.Report.Skipped["pattern-too-long"] != 1 {
			t.Fatalf("%+v", res.Report.Skipped)
		}
	})
	t.Run("too many options", func(t *testing.T) {
		opts := strings.Repeat(`nocase; `, 300)
		res := ConvertBytes("t.rules", []byte(`alert http any any -> any any (msg:"x"; `+opts+`sid:1;)`), importers.Options{})
		if len(res.Signatures) != 0 || res.Report.Skipped["too-many-options"] != 1 {
			t.Fatalf("%+v", res.Report.Skipped)
		}
	})
}

// TestChainSemantics checks the regular expressions made for distance and within against subjects, because the claim that they mean what
// Suricata's relative matching means is the part of the conversion that the structure of a condition does not show.
func TestChainSemantics(t *testing.T) {
	tests := []struct {
		name    string
		opts    string
		matches []string
		misses  []string
	}{
		{name: "distance zero is order only", opts: `content:"ab"; content:"cd"; distance:0;`,
			matches: []string{"abcd", "ab--cd", "xxabyycdzz"}, misses: []string{"cdab", "ab", "cd"}},
		{name: "distance two needs two bytes between", opts: `content:"ab"; content:"cd"; distance:2;`,
			matches: []string{"ab12cd", "ab1234cd"}, misses: []string{"abcd", "ab1cd", "cdab12"}},
		{name: "within bounds the end", opts: `content:"ab"; content:"cd"; within:4;`,
			matches: []string{"abcd", "ab1cd", "ab12cd"}, misses: []string{"ab123cd", "cdab"}},
		{name: "distance and within", opts: `content:"ab"; content:"cd"; distance:1; within:3;`,
			matches: []string{"ab1cd", "ab12cd"}, misses: []string{"abcd", "ab123cd"}},
		{name: "an earlier occurrence does not hide a later one", opts: `content:"ab"; content:"cd"; distance:1; within:2;`,
			matches: []string{"ab--ab-cd"}, misses: []string{"ab--cd"}},
		{name: "depth window", opts: `content:"ab"; depth:4;`, matches: []string{"ab", "xxab", "xab--"}, misses: []string{"xxxab", "xxxxab"}},
		{name: "offset and depth window", opts: `content:"def"; offset:3; depth:3;`, matches: []string{"abcdef", "abcdefghi"}, misses: []string{"abdef", "abcxdef", "def"}},
		{name: "startswith in a chain", opts: `content:"ab"; startswith; content:"cd"; distance:0;`, matches: []string{"abcd", "ab--cd"}, misses: []string{"xabcd"}},
		{name: "endswith in a chain", opts: `content:"ab"; content:"cd"; distance:0; endswith;`, matches: []string{"abcd", "ab-cd"}, misses: []string{"abcd-", "cd"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := conv(t, rl(`http.request_body; `+tt.opts))
			if len(res.Signatures) != 1 {
				t.Fatalf("%+v", res.Report)
			}
			s := res.Signatures[0]
			pat := s.Pattern
			if s.Operator != "rx" {
				// a single content with no position is "contains", which the other tests cover
				t.Skipf("operator %s", s.Operator)
			}
			re := regexp.MustCompile(pat)
			for _, m := range tt.matches {
				if !re.MatchString(m) {
					t.Errorf("%q does not match %q", pat, m)
				}
			}
			for _, m := range tt.misses {
				if re.MatchString(m) {
					t.Errorf("%q matches %q", pat, m)
				}
			}
		})
	}
}

// TestFixtures converts real rules from the Emerging Threats Open rule set (copies, BSD licence, see LICENSE-NOTICE.txt).
func TestFixtures(t *testing.T) {
	tests := []struct {
		file     string
		wantSigs int
		wantSkip map[string]int
		check    func(t *testing.T, s []vpatch.Signature)
	}{
		{file: "bare-payload.rules", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if len(s[0].Also) != 2 || !reflect.DeepEqual(s[0].Targets, bareT) {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "exchange-bsize-chain.rules", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if s[0].Pattern != `\A/ecp/(?s:.)*__VIEWSTATEGENERATOR=(?s:.)*__VIEWSTATE=` || !reflect.DeepEqual(s[0].CVEs, []string{"CVE-2020-0688"}) ||
				!reflect.DeepEqual(s[0].Scope, []string{"exchange"}) || s[0].Severity != "high" {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "nocase-chain.rules", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if s[0].Category != "sqli" || s[0].Pattern != "/viewcat.php?" || len(s[0].Also) != 2 {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "geoserver-within.rules", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if !strings.Contains(s[0].Pattern, `\A/geoserver/w(?s:.){1}s\?`) {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "header-line.rules", wantSigs: 2, check: func(t *testing.T, s []vpatch.Signature) {
			all := append([]vpatch.Condition{s[0].Condition}, s[0].Also...)
			found := false
			for _, c := range all {
				if reflect.DeepEqual(c.Targets, []string{"header:authorization"}) && c.Operator == "equals" && c.Pattern == "Basic R2VtdGVrOmdlbXRla3N3ZA==" {
					found = true
				}
			}
			if !found || s[0].Confidence != "low" || s[0].Action != "log" {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "cookie.rules", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			all := append([]vpatch.Condition{s[0].Condition}, s[0].Also...)
			found := false
			for _, c := range all {
				if reflect.DeepEqual(c.Targets, []string{"header:cookie"}) && c.Pattern == "uid=admin" {
					found = true
				}
			}
			if !found {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "user-agent.rules", wantSigs: 1},
		{file: "pcre-relative.rules", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if s[0].Tier != "community" || s[0].Operator != "rx" {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "pcre-uri-flag.rules", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			// The pcre has the U flag, so it is looked for in the URI, and its i flag is kept.
			found := false
			for _, c := range s[0].Also {
				if c.Operator == "rx" && c.Flags == "i" && c.Pattern == `^.{1,50}\/uapi-cgi\/` && reflect.DeepEqual(c.Targets, uriT) {
					found = true
				}
			}
			if s[0].Tier != "community" || !found {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "threshold.rules", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if s[0].Tier != "experimental" {
				t.Fatalf("a rule with a threshold must be one tier lower: %+v", s[0])
			}
		}},
		{file: "urilen-depth.rules", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if len(s[0].Also) < 3 {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "negated.rules", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			neg := 0
			for _, c := range append([]vpatch.Condition{s[0].Condition}, s[0].Also...) {
				if c.Negate {
					neg++
				}
			}
			if neg != 1 || s[0].Condition.Negate {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "skipped.rules", wantSkip: map[string]int{"response-direction": 1, "not-http-rule:tcp": 1, "disabled-in-source": 1, "flowbits": 1, "binary-content": 1}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			res := ConvertBytes(tt.file, data, importers.Options{})
			if len(res.Signatures) != tt.wantSigs {
				t.Fatalf("signatures %d, want %d; skipped %v errors %v", len(res.Signatures), tt.wantSigs, res.Report.Skipped, res.Report.Errors)
			}
			if tt.wantSkip != nil && !reflect.DeepEqual(res.Report.Skipped, tt.wantSkip) {
				t.Fatalf("skipped %v, want %v", res.Report.Skipped, tt.wantSkip)
			}
			if tt.check != nil {
				tt.check(t, res.Signatures)
			}
		})
	}
	if len(tests) > 15 {
		t.Fatalf("%d fixtures; at most 15 are allowed", len(tests))
	}
}
