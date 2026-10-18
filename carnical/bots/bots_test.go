// SPDX-License-Identifier: Apache-2.0

package bots

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/alert"
)

const (
	chrome  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	safari  = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1"
	firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0"
)

func TestClassify(t *testing.T) {
	browser := http.Header{"Accept": {"text/html"}, "Accept-Language": {"en-GB,en;q=0.9"}}
	tests := []struct {
		name   string
		ua     string
		header http.Header // nil: a browser's Accept and Accept-Language
		proto  [2]int      // zero: HTTP/1.1
		method string
		want   alert.Client
		engine Engine
	}{
		{"Chrome", chrome, nil, [2]int{}, "", alert.ClientPerson, 0},
		{"Safari on an iPhone over HTTP/2", safari, nil, [2]int{2, 0}, "", alert.ClientPerson, 0},
		{"Firefox", firefox, nil, [2]int{}, "", alert.ClientPerson, 0},
		{"a phone named Cubot is not a bot", "Mozilla/5.0 (Linux; Android 13; CUBOT KINGKONG 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36", nil, [2]int{}, "", alert.ClientPerson, 0},
		{"a CORS preflight sends no language", chrome, http.Header{"Accept": {"*/*"}}, [2]int{}, http.MethodOptions, alert.ClientPerson, 0},
		{"an app's library on a phone", "okhttp/4.12.0", http.Header{}, [2]int{}, "", alert.ClientPerson, 0},
		{"an iPhone app", "Shop/4.2 (iPhone; iOS 17.4; Scale/3.00)", http.Header{}, [2]int{}, "", alert.ClientPerson, 0},
		{"a browser's user agent without its language", chrome, http.Header{"Accept": {"*/*"}}, [2]int{}, "", alert.ClientDisguised, 0},
		{"a browser's user agent without Accept", chrome, http.Header{"Accept-Language": {"en"}}, [2]int{}, "", alert.ClientDisguised, 0},
		{"a browser's user agent over HTTP/1.0", firefox, nil, [2]int{1, 0}, "", alert.ClientDisguised, 0},
		{"two user agents", "", http.Header{"Accept": {"*/*"}, "Accept-Language": {"en"}, "User-Agent": {chrome, "GPTBot/1.3"}}, [2]int{}, "", alert.ClientDisguised, 0},
		{"Internet Explorer 11 is still a browser", "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", nil, [2]int{}, "", alert.ClientPerson, 0},
		{"Internet Explorer 9 is not", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)", nil, [2]int{}, "", alert.ClientDisguised, 0},
		{"Metasploit's old Internet Explorer", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", nil, [2]int{}, "", alert.ClientBot, 0},
		{"Chrome 58, years out of use", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36", nil, [2]int{}, "", alert.ClientDisguised, 0},
		{"Firefox 45, years out of use", "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0", nil, [2]int{}, "", alert.ClientDisguised, 0},
		{"Firefox sends no client hints", firefox, withHints(`"Chromium";v="141"`, ""), [2]int{}, "", alert.ClientDisguised, 0},
		{"nor does Safari", safari, withHints(`"Chromium";v="141"`, ""), [2]int{}, "", alert.ClientDisguised, 0},
		{"Chrome's client hints name its version", chrome, withHints(`"Chromium";v="141", "Google Chrome";v="141", "Not?A_Brand";v="8"`, `"Windows"`), [2]int{}, "", alert.ClientPerson, 0},
		{"Edge's too", chrome + " Edg/141.0.0.0", withHints(`"Microsoft Edge";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`, `"Windows"`), [2]int{}, "", alert.ClientPerson, 0},
		{"client hints of another version", chrome, withHints(`"Chromium";v="120", "Google Chrome";v="120"`, ""), [2]int{}, "", alert.ClientDisguised, 0},
		{"client hints of another platform", chrome, withHints(`"Chromium";v="141", "Google Chrome";v="141"`, `"macOS"`), [2]int{}, "", alert.ClientDisguised, 0},
		{"a user agent longer than any browser's", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " + strings.Repeat("A", 600), nil, [2]int{}, "", alert.ClientBot, 0},
		{"a scanner's name past a long padding", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " + strings.Repeat("A", 600) + " sqlmap/1.8", nil, [2]int{}, "", alert.ClientScanner, 0},
		{"an agent that signs its requests", chrome, withHeader("Signature-Agent", `"https://chatgpt.com"`), [2]int{}, "", alert.ClientAI, 0},
		{"no user agent", "", nil, [2]int{}, "", alert.ClientBot, 0},
		{"a contact URL", "Mozilla/5.0 (compatible; Quokkabot/1.0; +https://quokka.example/bot)", nil, [2]int{}, "", alert.ClientBot, 0},
		{"a crawler word in a compatible browser", "Mozilla/5.0 (compatible; Barkeep crawler)", nil, [2]int{}, "", alert.ClientBot, 0},
		{"a program this package does not know", "SiteGrabber/3.1", nil, [2]int{}, "", alert.ClientBot, 0},
		{"Googlebot", "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.7390.122 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", http.Header{}, [2]int{}, "", alert.ClientSearch, EngineGoogle},
		{"Bingbot", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36", http.Header{}, [2]int{}, "", alert.ClientSearch, EngineBing},
		{"Applebot", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)", http.Header{}, [2]int{}, "", alert.ClientSearch, EngineApple},
		{"DuckDuckBot cannot be checked", "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)", http.Header{}, [2]int{}, "", alert.ClientSearch, 0},
		{"GPTBot", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.3; +https://openai.com/gptbot)", http.Header{}, [2]int{}, "", alert.ClientAI, 0},
		{"ClaudeBot", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", http.Header{}, [2]int{}, "", alert.ClientAI, 0},
		{"Bytespider", "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)", http.Header{}, [2]int{}, "", alert.ClientAI, 0},
		{"CCBot", "CCBot/2.0 (https://commoncrawl.org/faq/)", http.Header{}, [2]int{}, "", alert.ClientAI, 0},
		{"Amazonbot can be checked", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot) Chrome/119.0.6045.214 Safari/537.36", http.Header{}, [2]int{}, "", alert.ClientAI, EngineAmazon},
		{"AdsBot is one of Google's special-case crawlers", "AdsBot-Google (+http://www.google.com/adsbot.html)", http.Header{}, [2]int{}, "", alert.ClientSearch, EngineGoogleSpecial},
		{"GoogleOther is Google's, and can be checked", "Mozilla/5.0 (compatible; GoogleOther)", http.Header{}, [2]int{}, "", alert.ClientAI, EngineGoogle},
		{"Google's user-triggered fetchers cannot be", "FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)", http.Header{}, [2]int{}, "", alert.ClientSearch, 0},
		{"Meta's AI crawler", "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)", http.Header{}, [2]int{}, "", alert.ClientAI, 0},
		{"an assistant fetching for a user", chrome + " ChatGPT-User/1.0; +https://openai.com/bot", nil, [2]int{}, "", alert.ClientAI, 0},
		{"AhrefsBot", "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", http.Header{}, [2]int{}, "", alert.ClientSEO, 0},
		{"SemrushBot", "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)", http.Header{}, [2]int{}, "", alert.ClientSEO, 0},
		{"MJ12bot", "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)", http.Header{}, [2]int{}, "", alert.ClientSEO, 0},
		{"headless Chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36", nil, [2]int{}, "", alert.ClientHeadless, 0},
		{"headless Chrome by its client hints", chrome, http.Header{"Accept": {"*/*"}, "Accept-Language": {"en"}, "Sec-Ch-Ua": {`"HeadlessChrome";v="141", "Chromium";v="141"`}}, [2]int{}, "", alert.ClientHeadless, 0},
		{"curl", "curl/8.11.1", http.Header{}, [2]int{}, "", alert.ClientTool, 0},
		{"python-requests", "python-requests/2.32.3", http.Header{}, [2]int{}, "", alert.ClientTool, 0},
		{"aiohttp", "Python/3.12 aiohttp/3.10.5", http.Header{}, [2]int{}, "", alert.ClientTool, 0},
		{"Go", "Go-http-client/2.0", http.Header{}, [2]int{}, "", alert.ClientTool, 0},
		{"Node's fetch", "node", http.Header{}, [2]int{}, "", alert.ClientTool, 0},
		{"Scrapy names itself before its URL", "Scrapy/2.12.0 (+https://scrapy.org)", http.Header{}, [2]int{}, "", alert.ClientTool, 0},
		{"sqlmap", "sqlmap/1.8.11#stable (https://sqlmap.org)", http.Header{}, [2]int{}, "", alert.ClientScanner, 0},
		{"Nmap", "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", http.Header{}, [2]int{}, "", alert.ClientScanner, 0},
		{"a scanner wins over a library", "python-requests/2.31 nuclei", http.Header{}, [2]int{}, "", alert.ClientScanner, 0},
		{"the RedTail botnet", "libredtail-http", http.Header{}, [2]int{}, "", alert.ClientScanner, 0},
		{"Mirai's greeting", "Hello, World", http.Header{}, [2]int{}, "", alert.ClientScanner, 0},
		{"Hydra", "Mozilla/4.0 (Hydra)", http.Header{}, [2]int{}, "", alert.ClientScanner, 0},
		{"a brute-force kit", "Teh Forest Lobster", http.Header{}, [2]int{}, "", alert.ClientScanner, 0}, //nolint:misspell // the kit's own spelling
		{"OpenBullet", "Mozilla/5.0 OpenBullet2", http.Header{}, [2]int{}, "", alert.ClientScanner, 0},
		{"a misspelt Mozilla", "Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv)", http.Header{}, [2]int{}, "", alert.ClientScanner, 0},
		{"zgrab", "Mozilla/5.0 zgrab/0.x", http.Header{}, [2]int{}, "", alert.ClientScanner, 0},
		{"Palo Alto's Expanse", "Expanse, a Palo Alto Networks company, searches across the global IPv4 space multiple times per day", http.Header{}, [2]int{}, "", alert.ClientScanner, 0},
		{"an address harvester", "EmailCollector/1.0", http.Header{}, [2]int{}, "", alert.ClientSEO, 0},
		{"a site copier", "Mozilla/4.5 (compatible; HTTrack 3.0x; Windows 98)", http.Header{}, [2]int{}, "", alert.ClientSEO, 0},
		{"Teleport Pro", "Teleport Pro/1.29", http.Header{}, [2]int{}, "", alert.ClientSEO, 0},
		{"a feed reader fetches for people", "Feedly/1.0 (+http://www.feedly.com/fetcher.html; 3 subscribers)", http.Header{}, [2]int{}, "", alert.ClientPreview, 0},
		{"PycURL", "PycURL/7.45.3 libcurl/8.5.0", http.Header{}, [2]int{}, "", alert.ClientTool, 0},
		{"Censys", "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", http.Header{}, [2]int{}, "", alert.ClientScanner, 0},
		{"a Slack preview", "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", http.Header{}, [2]int{}, "", alert.ClientPreview, 0},
		{"a Facebook preview", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", http.Header{}, [2]int{}, "", alert.ClientPreview, 0},
		{"an uptime check", "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)", http.Header{}, [2]int{}, "", alert.ClientMonitor, 0},
		{"Gmail fetching an email's images", "Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0 (via ggpht.com GoogleImageProxy)", http.Header{}, [2]int{}, "", alert.ClientPreview, 0},
		{"Yahoo Mail fetching an email's images", "YahooMailProxy; https://help.yahoo.com/kb/yahoo-mail-proxy-SLN28749.html", http.Header{}, [2]int{}, "", alert.ClientPreview, 0},
		{"Google reading a page aloud for someone", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 (compatible; Google-Read-Aloud; +https://support.google.com/webmasters/answer/1061943)", http.Header{}, [2]int{}, "", alert.ClientPreview, 0},
		{"Microsoft Office opening a link", "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17628; Pro)", http.Header{}, [2]int{}, "", alert.ClientPerson, 0},
		{"a Roku player", "Roku/DVP-13.0 (13.0.0.4152-AE)", http.Header{}, [2]int{}, "", alert.ClientPerson, 0},
		{"the old Edge, which names an old Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.82 Safari/537.36 Edge/20.02", nil, [2]int{}, "", alert.ClientPerson, 0},
		{"a certificate authority's domain check", "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)", http.Header{}, [2]int{}, "", alert.ClientMonitor, 0},
		{"the user agent is matched without regard to case", "CURL/8.0", http.Header{}, [2]int{}, "", alert.ClientTool, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.header
			if h == nil {
				h = browser.Clone()
			}
			h = h.Clone()
			if tt.ua != "" {
				h.Set("User-Agent", tt.ua)
			}
			major, minor := tt.proto[0], tt.proto[1]
			if major == 0 {
				major, minor = 1, 1
			}
			method := tt.method
			if method == "" {
				method = http.MethodGet
			}
			r := &http.Request{Method: method, Header: h, ProtoMajor: major, ProtoMinor: minor}
			got, engine := Classify(r, Hello{})
			if got != tt.want || engine != tt.engine {
				t.Fatalf("Classify = %v, %v; want %v, %v", got, engine, tt.want, tt.engine)
			}
		})
	}
}

// Over a TLS connection carnical holds, a current browser's user agent must come with what that browser sends there.
func TestClassifyOverTLS(t *testing.T) {
	fetch := func(extra http.Header) http.Header {
		h := http.Header{"Accept": {"text/html"}, "Accept-Language": {"en"}, "Sec-Fetch-Mode": {"navigate"},
			"Sec-Fetch-Site": {"none"}, "Sec-Fetch-Dest": {"document"}}
		for k, v := range extra {
			h[k] = v
		}
		return h
	}
	hints := http.Header{"Sec-Ch-Ua": {`"Chromium";v="141", "Google Chrome";v="141", "Not?A_Brand";v="8"`},
		"Sec-Ch-Ua-Platform": {`"Windows"`}}
	grease, plain := Hello{Seen: true, GREASE: true}, Hello{Seen: true}
	// What Chromium sends to open a wss:// socket: no Accept, no Sec-Fetch and no client hints.
	linuxChrome := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	websocket := http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {"https://shop.example"},
		"Sec-Websocket-Version": {"13"}, "Sec-Websocket-Key": {"xSigGCz9DJMNplmLC15MhA=="}, "Accept-Language": {"en-US,en;q=0.9"}}
	samsung := "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36"
	oldSafari := "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1"
	tests := []struct {
		name   string
		ua     string
		header http.Header
		hello  Hello
		want   alert.Client
	}{
		{"Chrome as Chrome sends it", chrome, fetch(hints), grease, alert.ClientPerson},
		{"Chrome without Sec-Fetch", chrome, func() http.Header {
			h := fetch(hints)
			h.Del("Sec-Fetch-Mode")
			h.Del("Sec-Fetch-Site")
			h.Del("Sec-Fetch-Dest")
			return h
		}(), grease, alert.ClientDisguised},
		{"Chrome without client hints", chrome, fetch(nil), grease, alert.ClientDisguised},
		{"Samsung Internet may send no client hints", samsung, fetch(nil), grease, alert.ClientPerson},
		{"a program with Chrome's headers but not its TLS", chrome, fetch(hints), plain, alert.ClientDisguised},
		{"a signing agent with Chrome's TLS", chrome, fetch(http.Header{"Sec-Ch-Ua": hints["Sec-Ch-Ua"], "Sec-Ch-Ua-Platform": hints["Sec-Ch-Ua-Platform"], "Signature-Agent": {`"https://chatgpt.com"`}}), grease, alert.ClientAI},
		{"Chrome's WebSocket handshake", linuxChrome, websocket, grease, alert.ClientPerson},
		{"a program dressing a request as a WebSocket handshake", linuxChrome, websocket, plain, alert.ClientDisguised},
		{"a program that adds a signature header to pass", chrome, fetch(http.Header{"Sec-Ch-Ua": hints["Sec-Ch-Ua"], "Sec-Ch-Ua-Platform": hints["Sec-Ch-Ua-Platform"], "Signature-Agent": {`"https://chatgpt.com"`}}), plain, alert.ClientDisguised},
		{"no handshake seen says nothing", chrome, fetch(hints), Hello{}, alert.ClientPerson},
		{"Firefox", firefox, fetch(nil), Hello{Seen: true, RecordSizeLimit: true}, alert.ClientPerson},
		{"a program with Firefox's headers but not its TLS", firefox, fetch(nil), plain, alert.ClientDisguised},
		{"Firefox without Sec-Fetch", firefox, http.Header{"Accept": {"*/*"}, "Accept-Language": {"en"}}, plain, alert.ClientDisguised},
		{"Safari", safari, fetch(nil), Hello{}, alert.ClientPerson},
		{"Safari without Sec-Fetch", safari, http.Header{"Accept": {"*/*"}, "Accept-Language": {"en"}}, Hello{}, alert.ClientDisguised},
		{"Safari before Sec-Fetch", oldSafari, http.Header{"Accept": {"*/*"}, "Accept-Language": {"en"}}, Hello{}, alert.ClientPerson},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.header.Clone()
			h.Set("User-Agent", tt.ua)
			r := &http.Request{Method: http.MethodGet, Header: h, ProtoMajor: 2, TLS: &tls.ConnectionState{}}
			if got, _ := Classify(r, tt.hello); got != tt.want {
				t.Fatalf("Classify = %v, want %v", got, tt.want)
			}
		})
	}
}

func withHints(brands, platform string) http.Header {
	h := http.Header{"Accept": {"*/*"}, "Accept-Language": {"en"}, "Sec-Ch-Ua": {brands}}
	if platform != "" {
		h.Set("Sec-Ch-Ua-Platform", platform)
	}
	return h
}

func withHeader(name, value string) http.Header {
	return http.Header{"Accept": {"*/*"}, "Accept-Language": {"en"}, name: {value}}
}

// resolver answers from its tables and counts the lookups. gate, when set, holds every reverse lookup until it is closed.
type resolver struct {
	names   map[string][]string
	addrs   map[string][]netip.Addr
	failPTR bool
	gate    chan struct{}
	ptrs    atomic.Int32
}

func (r *resolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	r.ptrs.Add(1)
	if r.gate != nil {
		<-r.gate
	}
	if r.failPTR {
		return nil, &net.DNSError{Err: "server misbehaving", Name: addr, IsTemporary: true}
	}
	if n, ok := r.names[addr]; ok {
		return n, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func (r *resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if a, ok := r.addrs[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func TestVerify(t *testing.T) {
	google := netip.MustParseAddr("66.249.66.1")
	dns := func() *resolver {
		return &resolver{
			names: map[string][]string{
				"66.249.66.1":  {"crawl-66-249-66-1.googlebot.com."},
				"66.249.66.2":  {"crawl-66-249-66-2.googlebot.com."}, // resolves to another address
				"203.0.113.5":  {"crawl.googlebot.com.evil.example."},
				"203.0.113.6":  {"evilgooglebot.com."},
				"203.0.113.7":  {"vm-7.bc.googleusercontent.com."}, // any Google Cloud machine
				"157.55.39.1":  {"msnbot-157-55-39-1.search.msn.com."},
				"2001:db8::10": {"crawl.googlebot.com."},
				"66.249.90.77": {"google-proxy-66-249-90-77.google.com."},      // fetches any user asks Google for
				"66.249.81.1":  {"rate-limited-proxy-66-249-81-1.google.com."}, // AdsBot and the other special-case crawlers
				"66.249.81.9":  {"rate-limited-proxy-66-249-81-9.corp.google.com."},
			},
			addrs: map[string][]netip.Addr{
				"crawl-66-249-66-1.googlebot.com":                {google},
				"crawl-66-249-66-2.googlebot.com":                {netip.MustParseAddr("66.249.99.99")},
				"crawl.googlebot.com.evil.example":               {netip.MustParseAddr("203.0.113.5")},
				"evilgooglebot.com":                              {netip.MustParseAddr("203.0.113.6")},
				"vm-7.bc.googleusercontent.com":                  {netip.MustParseAddr("203.0.113.7")},
				"msnbot-157-55-39-1.search.msn.com":              {netip.MustParseAddr("157.55.39.1")},
				"crawl.googlebot.com":                            {netip.MustParseAddr("2001:db8::10")},
				"google-proxy-66-249-90-77.google.com":           {netip.MustParseAddr("66.249.90.77")},
				"rate-limited-proxy-66-249-81-1.google.com":      {netip.MustParseAddr("66.249.81.1")},
				"rate-limited-proxy-66-249-81-9.corp.google.com": {netip.MustParseAddr("66.249.81.9")},
			},
		}
	}
	tests := []struct {
		name   string
		addr   string
		engine Engine
		fail   bool
		want   bool
	}{
		{"Googlebot from its own name", "66.249.66.1", EngineGoogle, false, true},
		{"the same address seen as a mapped IPv6 one", "::ffff:66.249.66.1", EngineGoogle, false, true},
		{"Googlebot over IPv6", "2001:db8::10", EngineGoogle, false, true},
		{"Bingbot", "157.55.39.1", EngineBing, false, true},
		{"a Bing name does not make Googlebot", "157.55.39.1", EngineGoogle, false, false},
		{"a name that resolves elsewhere", "66.249.66.2", EngineGoogle, false, false},
		{"the domain inside another name", "203.0.113.5", EngineGoogle, false, false},
		{"a domain that only ends the same way", "203.0.113.6", EngineGoogle, false, false},
		{"a Google Cloud machine is not Googlebot", "203.0.113.7", EngineGoogle, false, false},
		{"a fetch any user asks Google for is not Googlebot", "66.249.90.77", EngineGoogle, false, false},
		{"nor AdsBot", "66.249.90.77", EngineGoogleSpecial, false, false},
		{"AdsBot from Google's special-case crawlers", "66.249.81.1", EngineGoogleSpecial, false, true},
		{"which are not Googlebot", "66.249.81.1", EngineGoogle, false, false},
		{"nor is Googlebot's name AdsBot's", "66.249.66.1", EngineGoogleSpecial, false, false},
		{"a deeper google.com name that starts the same way", "66.249.81.9", EngineGoogleSpecial, false, false},
		{"no reverse name", "198.51.100.1", EngineGoogle, false, false},
		{"a reverse lookup that fails", "66.249.66.1", EngineGoogle, true, false},
		{"no engine", "66.249.66.1", 0, false, false},
		{"Amazonbot from a range Amazon publishes, with no DNS name", "198.18.0.7", EngineAmazon, false, true},
		{"seen as a mapped IPv6 address", "::ffff:198.18.0.7", EngineAmazon, false, true},
		{"even when DNS fails", "198.18.0.7", EngineAmazon, true, true},
		{"Amazon's range does not make Googlebot", "198.18.0.7", EngineGoogle, false, false},
		{"an address next to the range", "198.18.1.7", EngineAmazon, false, false},
	}
	ranges := map[Engine][]netip.Prefix{EngineAmazon: {netip.MustParsePrefix("198.18.0.0/24")}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := dns()
			r.failPTR = tt.fail
			v := NewVerifier(r, 0, 0)
			v.Ranges = ranges
			addr := netip.MustParseAddr(tt.addr)
			if got := v.Verify(context.Background(), addr, tt.engine); got != tt.want {
				t.Fatalf("Verify = %v, want %v", got, tt.want)
			}
			if got := v.Verify(context.Background(), addr, tt.engine); got != tt.want || r.ptrs.Load() > 1 {
				t.Fatalf("again = %v after %d lookups, want %v from the cache", got, r.ptrs.Load(), tt.want)
			}
		})
	}

	t.Run("an answer is checked again once it expires", func(t *testing.T) {
		r := dns()
		v := NewVerifier(r, 0, 0)
		now := time.Unix(1e9, 0)
		v.now = func() time.Time { return now }
		v.Verify(context.Background(), google, EngineGoogle)
		now = now.Add(verifiedFor + time.Second)
		if !v.Verify(context.Background(), google, EngineGoogle) || r.ptrs.Load() != 2 {
			t.Fatalf("lookups %d, want 2", r.ptrs.Load())
		}
	})
	t.Run("with every slot taken the answer is no, and waiters share a check", func(t *testing.T) {
		r := dns()
		r.gate = make(chan struct{})
		v := NewVerifier(r, 1, 0)
		var wg sync.WaitGroup
		results := make([]bool, 3)
		for i := range results {
			wg.Go(func() { results[i] = v.Verify(context.Background(), google, EngineGoogle) })
		}
		for r.ptrs.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		if v.Verify(context.Background(), netip.MustParseAddr("157.55.39.1"), EngineBing) {
			t.Fatal("verified with no slot free")
		}
		close(r.gate)
		wg.Wait()
		if results[0] != true || results[1] != true || results[2] != true || r.ptrs.Load() != 1 {
			t.Fatalf("results %v after %d lookups, want all true after 1", results, r.ptrs.Load())
		}
	})
	t.Run("a waiter whose request ends is answered no", func(t *testing.T) {
		r := dns()
		r.gate = make(chan struct{})
		defer close(r.gate)
		v := NewVerifier(r, 0, 0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if v.Verify(ctx, google, EngineGoogle) {
			t.Fatal("verified after the request ended")
		}
	})
	t.Run("a flood of impostors does not push a verified crawler out", func(t *testing.T) {
		r := dns()
		v := NewVerifier(r, 0, 16)
		v.Verify(context.Background(), google, EngineGoogle)
		for i := range 100 {
			v.Verify(context.Background(), netip.AddrFrom4([4]byte{198, 51, byte(i), 1}), EngineGoogle)
		}
		before := r.ptrs.Load()
		if !v.Verify(context.Background(), google, EngineGoogle) || r.ptrs.Load() != before {
			t.Fatal("the verified crawler was dropped from the cache")
		}
	})
	t.Run("one network runs two checks at once", func(t *testing.T) {
		r := dns()
		r.gate = make(chan struct{})
		v := NewVerifier(r, 0, 0)
		var wg sync.WaitGroup
		for i := range 2 {
			wg.Go(func() {
				v.Verify(context.Background(), netip.AddrFrom4([4]byte{203, 0, 113, byte(10 + i)}), EngineGoogle)
			})
		}
		for r.ptrs.Load() < 2 {
			time.Sleep(time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second) // a third check would wait on the gate
		defer cancel()
		if v.Verify(ctx, netip.MustParseAddr("203.0.113.12"), EngineGoogle) || r.ptrs.Load() != 2 {
			t.Fatalf("a third check of one network ran: %d lookups", r.ptrs.Load())
		}
		close(r.gate)
		wg.Wait()
	})
	for _, trust := range []bool{false, true} {
		t.Run(fmt.Sprintf("with no check free, a verified crawler's network passes only when trusted (%v)", trust), func(t *testing.T) {
			r := dns()
			v := NewVerifier(r, 1, 0)
			v.TrustNetworks = trust
			if !v.Verify(context.Background(), google, EngineGoogle) {
				t.Fatal("not verified")
			}
			r.gate = make(chan struct{})
			var wg sync.WaitGroup
			wg.Go(func() { v.Verify(context.Background(), netip.MustParseAddr("203.0.113.5"), EngineGoogle) })
			for r.ptrs.Load() < 2 {
				time.Sleep(time.Millisecond)
			}
			if v.Verify(context.Background(), netip.MustParseAddr("66.249.66.77"), EngineGoogle) != trust {
				t.Errorf("an unchecked address of the verified network passed: %v, want %v", !trust, trust)
			}
			if v.Verify(context.Background(), netip.MustParseAddr("66.249.66.77"), EngineBing) {
				t.Error("the network was taken for another engine's")
			}
			if v.Verify(context.Background(), netip.MustParseAddr("66.249.99.5"), EngineGoogle) {
				t.Error("an address of another network passed")
			}
			close(r.gate)
			wg.Wait()
		})
	}
	t.Run("a full cache makes room", func(t *testing.T) {
		v := NewVerifier(dns(), 0, 16)
		for i := range 100 {
			v.Verify(context.Background(), netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), EngineGoogle)
		}
		if n := len(v.cache); n > 16 {
			t.Fatalf("%d answers kept, at most 16", n)
		}
	})
}
func TestParseRanges(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string // the ranges, or the error's text
		fail bool
	}{
		{"the JSON form Google publishes", `{"creationTime": "2026-10-01T00:00:00", "prefixes": [{"ipv4Prefix": "66.249.64.0/27"},
			{"ipv6Prefix": "2001:4860:4801:10::/64"}]}`, []string{"66.249.64.0/27", "2001:4860:4801:10::/64"}, false},
		{"one range or address a line, with comments", "# Amazonbot\n52.70.240.171\n\n  3.224.220.0/24 # crawl\n2600:1f18::1\n",
			[]string{"52.70.240.171/32", "3.224.220.0/24", "2600:1f18::1/128"}, false},
		{"a range given with its host bits", "66.249.64.5/27", []string{"66.249.64.0/27"}, false},
		{"a mapped IPv6 range is an IPv4 one", "::ffff:198.18.0.0/120", []string{"198.18.0.0/24"}, false},
		{"a line that is no range", "66.249.64.0/27\ncrawl.amazonbot.amazon\n", []string{`line 2: "crawl.amazonbot.amazon"`}, true},
		{"a prefix that is no range", `{"prefixes": [{"ipv4Prefix": "66.249.64.0/33"}]}`, []string{"prefix 1:"}, true},
		{"an address with a zone", "fe80::1%eth0", []string{"line 1:"}, true},
		{"a range wider than a /16", "10.0.0.0/8", []string{"wider than a /16"}, true},
		{"the whole Internet as a mapped range", "::ffff:0.0.0.0/96", []string{"wider than a /16"}, true},
		{"an IPv6 range wider than a /32", "2600::/16", []string{"wider than a /32"}, true},
		{"broken JSON", `{"prefixes": [`, []string{"not the JSON form"}, true},
		{"JSON with no prefixes", `{"creationTime": "2026-10-01T00:00:00"}`, []string{"no ranges"}, true},
		{"only comments", "# nothing yet\n", []string{"no ranges"}, true},
		{"a file over the limit", strings.Repeat("#", MaxRangesFile+1), []string{"more than"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRanges(strings.NewReader(tt.in))
			if tt.fail {
				if err == nil || !strings.Contains(err.Error(), tt.want[0]) {
					t.Fatalf("error %v, want one saying %q", err, tt.want[0])
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var texts []string
			for _, p := range got {
				texts = append(texts, p.String())
			}
			if !slices.Equal(texts, tt.want) {
				t.Fatalf("ranges %v, want %v", texts, tt.want)
			}
		})
	}
}

func TestPolicy(t *testing.T) {
	kinds := []struct {
		name string
		in   string
		want string
		bad  bool
	}{
		{"none", "none", "none", false},
		{"empty", "", "none", false},
		{"several, in any case and spacing", " AI , seo,fake", "fake,ai,seo", false},
		{"every kind", KindNames(), KindNames(), false},
		{"people cannot be refused", "person", "", true},
		{"nor real search engines", "search", "", true},
		{"nor previews", "fake,preview", "", true},
		{"an unknown word", "crawlers", "", true},
	}
	for _, tt := range kinds {
		t.Run("kinds "+tt.name, func(t *testing.T) {
			set, err := ParseKinds(tt.in)
			if (err != nil) != tt.bad || !tt.bad && Kinds(set) != tt.want {
				t.Fatalf("ParseKinds(%q) = %q, %v", tt.in, Kinds(set), err)
			}
		})
	}

	googlebot := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	r := &resolver{names: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com"}},
		addrs: map[string][]netip.Addr{"crawl-66-249-66-1.googlebot.com": {netip.MustParseAddr("66.249.66.1")}}}
	judge := []struct {
		name   string
		refuse string
		watch  string
		exempt string
		ua     string
		addr   string
		want   alert.Client
		action Action
	}{
		{"real Googlebot passes", "fake,ai", "", "", googlebot, "66.249.66.1", alert.ClientSearch, Pass},
		{"fake Googlebot is refused", "fake,ai", "", "", googlebot, "203.0.113.9", alert.ClientFake, Refuse},
		{"a watched fake is checked and only reported", "", "fake", "", googlebot, "203.0.113.9", alert.ClientFake, Watch},
		{"without fake no claim is checked", "ai", "", "", googlebot, "203.0.113.9", alert.ClientSearch, Pass},
		{"a fake GoogleOther is a fake too", "fake", "", "", "Mozilla/5.0 (compatible; GoogleOther)", "203.0.113.9", alert.ClientFake, Refuse},
		{"a listed kind is refused", "fake,ai", "", "", "GPTBot/1.3", "203.0.113.9", alert.ClientAI, Refuse},
		{"a watched kind is reported", "scanner", "ai", "", "GPTBot/1.3", "203.0.113.9", alert.ClientAI, Watch},
		{"refused wins over watched", "ai", "ai", "", "GPTBot/1.3", "203.0.113.9", alert.ClientAI, Refuse},
		{"a kind not listed passes", "fake,ai", "", "", "curl/8.11.1", "203.0.113.9", alert.ClientTool, Pass},
		{"an exempt address passes", "scanner", "", "203.0.113.0/24", "sqlmap/1.8", "203.0.113.9", alert.ClientScanner, Pass},
		{"another address does not", "scanner", "", "198.51.100.0/24", "sqlmap/1.8", "203.0.113.9", alert.ClientScanner, Refuse},
		{"a person passes", KindNames(), "", "", chrome, "203.0.113.9", alert.ClientPerson, Pass},
	}
	for _, tt := range judge {
		t.Run("judge "+tt.name, func(t *testing.T) {
			set, err := ParseKinds(tt.refuse)
			if err != nil {
				t.Fatal(err)
			}
			watch, err := ParseKinds(tt.watch)
			if err != nil {
				t.Fatal(err)
			}
			p := &Policy{Refuse: set, Watch: watch, Verifier: NewVerifier(r, 0, 0)}
			if tt.exempt != "" {
				p.Exempt = []netip.Prefix{netip.MustParsePrefix(tt.exempt)}
			}
			req, _ := http.NewRequest(http.MethodGet, "http://site.test/", nil)
			req.Header.Set("User-Agent", tt.ua)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en")
			got, action := p.Judge(context.Background(), req, netip.MustParseAddr(tt.addr), Hello{})
			if got != tt.want || action != tt.action {
				t.Fatalf("Judge = %v, %v; want %v, %v", got, action, tt.want, tt.action)
			}
		})
	}
}

func TestHellos(t *testing.T) {
	for _, tt := range []struct {
		v    uint16
		want bool
	}{{0x0a0a, true}, {0x3a3a, true}, {0xfafa, true}, {0x1301, false}, {0x0a1a, false}, {0xc02b, false}} {
		t.Run(fmt.Sprintf("GREASE %#04x", tt.v), func(t *testing.T) {
			if isGREASE(tt.v) != tt.want {
				t.Fatalf("isGREASE(%#04x) = %v", tt.v, !tt.want)
			}
		})
	}
	chrome, python := net.Pipe()
	defer chrome.Close()
	defer python.Close()
	other, _ := net.Pipe()
	defer other.Close()
	h := NewHellos(2)
	for _, ch := range []*tls.ClientHelloInfo{
		{Conn: chrome, CipherSuites: []uint16{0x1a1a, tls.TLS_AES_128_GCM_SHA256}},
		{Conn: python, CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256}, Extensions: []uint16{0, 10, 28, 43}},
		{Conn: other, CipherSuites: []uint16{0x2a2a}}, // over the limit: not kept
	} {
		if cfg, err := h.Observe(ch); cfg != nil || err != nil {
			t.Fatalf("Observe = %v, %v; want nil, nil", cfg, err)
		}
	}
	tests := []struct {
		name string
		conn net.Conn
		want Hello
	}{
		{"a browser's handshake", chrome, Hello{Seen: true, GREASE: true}},
		{"found through the TLS connection over it", tls.Server(chrome, &tls.Config{}), Hello{Seen: true, GREASE: true}},
		{"a program's handshake, with record_size_limit", python, Hello{Seen: true, RecordSizeLimit: true}},
		{"past the limit nothing is kept", other, Hello{}},
		{"no connection", nil, Hello{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := h.Of(tt.conn); got != tt.want {
				t.Fatalf("Of = %+v, want %+v", got, tt.want)
			}
		})
	}
	t.Run("a closed connection is forgotten and makes room", func(t *testing.T) {
		h.Forget(tls.Server(chrome, &tls.Config{}))
		_, _ = h.Observe(&tls.ClientHelloInfo{Conn: other, CipherSuites: []uint16{0x2a2a}}) // nil, nil: checked above
		if h.Of(chrome) != (Hello{}) || h.Of(other) != (Hello{Seen: true, GREASE: true}) {
			t.Fatalf("after Forget: %+v and %+v", h.Of(chrome), h.Of(other))
		}
	})
}
