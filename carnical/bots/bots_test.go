// SPDX-License-Identifier: Apache-2.0

package bots

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
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
		{"a browser's user agent without its language", chrome, http.Header{"Accept": {"*/*"}}, [2]int{}, "", alert.ClientBot, 0},
		{"a browser's user agent without Accept", chrome, http.Header{"Accept-Language": {"en"}}, [2]int{}, "", alert.ClientBot, 0},
		{"a browser's user agent over HTTP/1.0", firefox, nil, [2]int{1, 0}, "", alert.ClientBot, 0},
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
		{"Censys", "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", http.Header{}, [2]int{}, "", alert.ClientScanner, 0},
		{"a Slack preview", "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", http.Header{}, [2]int{}, "", alert.ClientPreview, 0},
		{"a Facebook preview", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", http.Header{}, [2]int{}, "", alert.ClientPreview, 0},
		{"an uptime check", "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)", http.Header{}, [2]int{}, "", alert.ClientMonitor, 0},
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
			got, engine := Classify(h, major, minor, method)
			if got != tt.want || engine != tt.engine {
				t.Fatalf("Classify = %v, %v; want %v, %v", got, engine, tt.want, tt.engine)
			}
		})
	}
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
			},
			addrs: map[string][]netip.Addr{
				"crawl-66-249-66-1.googlebot.com":   {google},
				"crawl-66-249-66-2.googlebot.com":   {netip.MustParseAddr("66.249.99.99")},
				"crawl.googlebot.com.evil.example":  {netip.MustParseAddr("203.0.113.5")},
				"evilgooglebot.com":                 {netip.MustParseAddr("203.0.113.6")},
				"vm-7.bc.googleusercontent.com":     {netip.MustParseAddr("203.0.113.7")},
				"msnbot-157-55-39-1.search.msn.com": {netip.MustParseAddr("157.55.39.1")},
				"crawl.googlebot.com":               {netip.MustParseAddr("2001:db8::10")},
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
		{"no reverse name", "198.51.100.1", EngineGoogle, false, false},
		{"a reverse lookup that fails", "66.249.66.1", EngineGoogle, true, false},
		{"no engine", "66.249.66.1", 0, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := dns()
			r.failPTR = tt.fail
			v := NewVerifier(r, 0, 0)
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
		kinds  string
		ua     string
		addr   string
		want   alert.Client
		refuse bool
	}{
		{"real Googlebot passes", "fake,ai", googlebot, "66.249.66.1", alert.ClientSearch, false},
		{"fake Googlebot is refused", "fake,ai", googlebot, "203.0.113.9", alert.ClientFake, true},
		{"without fake no claim is checked", "ai", googlebot, "203.0.113.9", alert.ClientSearch, false},
		{"a listed kind is refused", "fake,ai", "GPTBot/1.3", "203.0.113.9", alert.ClientAI, true},
		{"a kind not listed passes", "fake,ai", "curl/8.11.1", "203.0.113.9", alert.ClientTool, false},
		{"a person passes", "fake,ai,seo,tool,headless,scanner,bot", chrome, "203.0.113.9", alert.ClientPerson, false},
	}
	for _, tt := range judge {
		t.Run("judge "+tt.name, func(t *testing.T) {
			set, err := ParseKinds(tt.kinds)
			if err != nil {
				t.Fatal(err)
			}
			p := &Policy{Refuse: set, Verifier: NewVerifier(r, 0, 0)}
			req, _ := http.NewRequest(http.MethodGet, "http://site.test/", nil)
			req.Header.Set("User-Agent", tt.ua)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en")
			got, refuse := p.Judge(context.Background(), req, netip.MustParseAddr(tt.addr))
			if got != tt.want || refuse != tt.refuse {
				t.Fatalf("Judge = %v, %v; want %v, %v", got, refuse, tt.want, tt.refuse)
			}
		})
	}
}
