// SPDX-License-Identifier: Apache-2.0

// Package bots tells what kind of client sent a request from what the request says about itself, checks the claims of
// search engine crawlers by DNS, and refuses the kinds of client a site chooses (ADR-0087).
//
// A request's user agent is the client's own claim, so the reading is only as good as the claim: a declared crawler,
// tool or headless browser is named by it, a bot that copies a browser's headers exactly is read as a person, and only
// a search engine's claim can be checked, against the engine's DNS.
package bots

import (
	"net/http"
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/YurilLAB/coraza/carnical/alert"
)

// maxUA is how much of a user agent is read: a real one is well under it.
const maxUA = 512

// Engine is a search engine whose crawlers can be checked by DNS: the address's name must be in one of the engine's
// domains, and that name must resolve back to the address. 0 is none.
type Engine uint8

// The engines that publish their crawlers' DNS names. Google's googleusercontent.com is left out: every Google Cloud
// machine has a name there, so it would let anyone's VM pass as Googlebot.
const (
	EngineGoogle Engine = iota + 1
	EngineBing
	EngineApple
	EngineYandex
	EngineBaidu
	EnginePetal
	EngineSeznam
	EngineNaver

	numEngines = int(EngineNaver) + 1
)

var engines = [numEngines]struct {
	name    string
	domains []string
}{
	EngineGoogle: {"google", []string{"googlebot.com", "google.com"}},
	EngineBing:   {"bing", []string{"search.msn.com"}},
	EngineApple:  {"apple", []string{"applebot.apple.com"}},
	EngineYandex: {"yandex", []string{"yandex.ru", "yandex.net", "yandex.com"}},
	EngineBaidu:  {"baidu", []string{"baidu.com", "baidu.jp"}},
	EnginePetal:  {"petal", []string{"petalsearch.com"}},
	EngineSeznam: {"seznam", []string{"seznam.cz"}},
	EngineNaver:  {"naver", []string{"naver.com"}},
}

func (e Engine) String() string {
	if int(e) < numEngines {
		return engines[e].name
	}
	return ""
}

// signature is a word of a user agent, matched without regard to ASCII case, and what it names.
type signature struct {
	word   string
	client alert.Client
	engine Engine
}

// signatures name programs by the words their user agents carry. Where several match, the kind ranked first by rank
// wins: a scanner that also names a library is a scanner. ClientPerson here is an app's networking library on a phone,
// which people use.
var signatures = []signature{
	// Search engines. A claim from an engine with no published DNS names (DuckDuckGo, Qwant, Mojeek, Sogou) is a search
	// crawler that cannot be checked.
	{"googlebot", alert.ClientSearch, EngineGoogle}, {"adsbot-google", alert.ClientSearch, EngineGoogle},
	{"mediapartners-google", alert.ClientSearch, EngineGoogle}, {"google-inspectiontool", alert.ClientSearch, EngineGoogle},
	{"storebot-google", alert.ClientSearch, EngineGoogle}, {"apis-google", alert.ClientSearch, EngineGoogle},
	{"feedfetcher-google", alert.ClientSearch, EngineGoogle},
	{"bingbot", alert.ClientSearch, EngineBing}, {"msnbot", alert.ClientSearch, EngineBing},
	{"adidxbot", alert.ClientSearch, EngineBing}, {"bingpreview", alert.ClientSearch, EngineBing},
	{"applebot", alert.ClientSearch, EngineApple},
	{"yandexbot", alert.ClientSearch, EngineYandex}, {"yandeximages", alert.ClientSearch, EngineYandex},
	{"yandexmobilebot", alert.ClientSearch, EngineYandex}, {"yandex.com/bots", alert.ClientSearch, EngineYandex},
	{"baiduspider", alert.ClientSearch, EngineBaidu}, {"petalbot", alert.ClientSearch, EnginePetal},
	{"seznambot", alert.ClientSearch, EngineSeznam}, {"yeti/", alert.ClientSearch, EngineNaver},
	{"duckduckbot", alert.ClientSearch, 0}, {"qwantbot", alert.ClientSearch, 0}, {"qwantify", alert.ClientSearch, 0},
	{"mojeekbot", alert.ClientSearch, 0}, {"sogou web spider", alert.ClientSearch, 0},

	// AI companies' crawlers and fetchers (the ai.robots.txt project's list, and the companies' own pages).
	{"gptbot", alert.ClientAI, 0}, {"chatgpt-user", alert.ClientAI, 0}, {"chatgpt agent", alert.ClientAI, 0},
	{"oai-searchbot", alert.ClientAI, 0}, {"oai-adsbot", alert.ClientAI, 0},
	{"claudebot", alert.ClientAI, 0}, {"claude-user", alert.ClientAI, 0}, {"claude-searchbot", alert.ClientAI, 0},
	{"claude-web", alert.ClientAI, 0}, {"anthropic-ai", alert.ClientAI, 0},
	{"ccbot", alert.ClientAI, 0}, {"bytespider", alert.ClientAI, 0}, {"tiktokspider", alert.ClientAI, 0},
	{"perplexitybot", alert.ClientAI, 0}, {"perplexity-user", alert.ClientAI, 0},
	{"amazonbot", alert.ClientAI, 0}, {"amzn-searchbot", alert.ClientAI, 0}, {"amzn-user", alert.ClientAI, 0},
	{"amazonbuyforme", alert.ClientAI, 0}, {"novaact", alert.ClientAI, 0}, {"bedrockbot", alert.ClientAI, 0},
	{"meta-externalagent", alert.ClientAI, 0}, {"meta-externalfetcher", alert.ClientAI, 0},
	{"meta-webindexer", alert.ClientAI, 0}, {"facebookbot", alert.ClientAI, 0},
	{"googleother", alert.ClientAI, 0}, {"google-cloudvertexbot", alert.ClientAI, 0}, {"google-notebooklm", alert.ClientAI, 0},
	{"gemini-deep-research", alert.ClientAI, 0}, {"googleagent-", alert.ClientAI, 0}, {"google-agent", alert.ClientAI, 0},
	{"cohere-ai", alert.ClientAI, 0}, {"cohere-training-data-crawler", alert.ClientAI, 0},
	{"mistralai-", alert.ClientAI, 0}, {"deepseekbot", alert.ClientAI, 0}, {"duckassistbot", alert.ClientAI, 0},
	{"xai-grok", alert.ClientAI, 0}, {"grokbot", alert.ClientAI, 0}, {"youbot", alert.ClientAI, 0},
	{"diffbot", alert.ClientAI, 0}, {"timpibot", alert.ClientAI, 0}, {"imagesiftbot", alert.ClientAI, 0},
	{"omgili", alert.ClientAI, 0}, {"ai2bot", alert.ClientAI, 0}, {"kangaroo bot", alert.ClientAI, 0},
	{"pangubot", alert.ClientAI, 0}, {"img2dataset", alert.ClientAI, 0}, {"laion", alert.ClientAI, 0},
	{"crawl4ai", alert.ClientAI, 0}, {"firecrawl", alert.ClientAI, 0}, {"tavilybot", alert.ClientAI, 0},
	{"exabot", alert.ClientAI, 0}, {"exasearchbot", alert.ClientAI, 0}, {"iaskspider", alert.ClientAI, 0},
	{"iaskbot", alert.ClientAI, 0}, {"kimi-", alert.ClientAI, 0}, {"kimibot", alert.ClientAI, 0},
	{"moonshotbot", alert.ClientAI, 0}, {"linerbot", alert.ClientAI, 0}, {"phindbot", alert.ClientAI, 0},
	{"qwenbot", alert.ClientAI, 0}, {"tongyibot", alert.ClientAI, 0}, {"doubaobot", alert.ClientAI, 0},
	{"erniebot", alert.ClientAI, 0}, {"yiyanbot", alert.ClientAI, 0}, {"chatglm-spider", alert.ClientAI, 0},
	{"yibot", alert.ClientAI, 0}, {"sbintuitionsbot", alert.ClientAI, 0}, {"cotoyogi", alert.ClientAI, 0},
	{"velenpublicwebcrawler", alert.ClientAI, 0}, {"wardbot", alert.ClientAI, 0}, {"friendlycrawler", alert.ClientAI, 0},
	{"icc-crawler", alert.ClientAI, 0}, {"apifybot", alert.ClientAI, 0}, {"apifywebsitecontentcrawler", alert.ClientAI, 0},
	{"cloudflare-autorag", alert.ClientAI, 0}, {"cloudflarebrowserrenderingcrawler", alert.ClientAI, 0},
	{"manus-user", alert.ClientAI, 0}, {"azureai-searchbot", alert.ClientAI, 0}, {"andibot", alert.ClientAI, 0},
	{"brightbot", alert.ClientAI, 0}, {"bravebot", alert.ClientAI, 0}, {"yandexadditional", alert.ClientAI, 0},
	{"webzio-extended", alert.ClientAI, 0}, {"linkupbot", alert.ClientAI, 0}, {"keenablebot", alert.ClientAI, 0},
	{"channel3bot", alert.ClientAI, 0}, {"aihitbot", alert.ClientAI, 0}, {"agentdatabot", alert.ClientAI, 0},
	{"kagi-fetcher", alert.ClientAI, 0}, {"quillbot", alert.ClientAI, 0}, {"shapbot", alert.ClientAI, 0},

	// SEO, marketing, archive and data-mining crawlers.
	{"ahrefsbot", alert.ClientSEO, 0}, {"ahrefssiteaudit", alert.ClientSEO, 0}, {"semrushbot", alert.ClientSEO, 0},
	{"siteauditbot", alert.ClientSEO, 0}, {"mj12bot", alert.ClientSEO, 0}, {"dotbot", alert.ClientSEO, 0},
	{"blexbot", alert.ClientSEO, 0}, {"dataforseobot", alert.ClientSEO, 0}, {"serpstatbot", alert.ClientSEO, 0},
	{"barkrowler", alert.ClientSEO, 0}, {"seekportbot", alert.ClientSEO, 0}, {"megaindex", alert.ClientSEO, 0},
	{"rogerbot", alert.ClientSEO, 0}, {"screaming frog", alert.ClientSEO, 0}, {"sitebulb", alert.ClientSEO, 0},
	{"zoominfobot", alert.ClientSEO, 0}, {"linkdexbot", alert.ClientSEO, 0}, {"seokicks", alert.ClientSEO, 0},
	{"linkpadbot", alert.ClientSEO, 0}, {"spbot", alert.ClientSEO, 0}, {"trendictionbot", alert.ClientSEO, 0},
	{"turnitinbot", alert.ClientSEO, 0}, {"awario", alert.ClientSEO, 0}, {"brandwatch", alert.ClientSEO, 0},
	{"proximic", alert.ClientSEO, 0}, {"grapeshot", alert.ClientSEO, 0}, {"babbar", alert.ClientSEO, 0},
	{"netestate", alert.ClientSEO, 0}, {"sistrix", alert.ClientSEO, 0}, {"domainstatsbot", alert.ClientSEO, 0},
	{"magpie-crawler", alert.ClientSEO, 0}, {"keys-so-bot", alert.ClientSEO, 0}, {"dataprovider", alert.ClientSEO, 0},
	{"panscient", alert.ClientSEO, 0}, {"linkfluence", alert.ClientSEO, 0}, {"ia_archiver", alert.ClientSEO, 0},
	{"archive.org_bot", alert.ClientSEO, 0}, {"heritrix", alert.ClientSEO, 0}, {"factset_spyderbot", alert.ClientSEO, 0},
	{"mauibot", alert.ClientSEO, 0}, {"serendeputybot", alert.ClientSEO, 0}, {"clarabot", alert.ClientSEO, 0},

	// Browsers driven by programs.
	{"headlesschrome", alert.ClientHeadless, 0}, {"phantomjs", alert.ClientHeadless, 0},
	{"slimerjs", alert.ClientHeadless, 0}, {"lightpanda", alert.ClientHeadless, 0}, {"puppeteer", alert.ClientHeadless, 0},
	{"playwright", alert.ClientHeadless, 0}, {"selenium", alert.ClientHeadless, 0}, {"webdriver", alert.ClientHeadless, 0},
	{"htmlunit", alert.ClientHeadless, 0}, {"jsdom/", alert.ClientHeadless, 0},

	// Vulnerability scanners and internet-wide scanning services.
	{"nikto", alert.ClientScanner, 0}, {"sqlmap", alert.ClientScanner, 0}, {"nmap", alert.ClientScanner, 0},
	{"masscan", alert.ClientScanner, 0}, {"zgrab", alert.ClientScanner, 0}, {"nuclei", alert.ClientScanner, 0},
	{"wpscan", alert.ClientScanner, 0}, {"gobuster", alert.ClientScanner, 0}, {"feroxbuster", alert.ClientScanner, 0},
	{"dirbuster", alert.ClientScanner, 0}, {"dirsearch", alert.ClientScanner, 0}, {"fuzz faster u fool", alert.ClientScanner, 0},
	{"wfuzz", alert.ClientScanner, 0}, {"whatweb", alert.ClientScanner, 0}, {"acunetix", alert.ClientScanner, 0},
	{"netsparker", alert.ClientScanner, 0}, {"invicti", alert.ClientScanner, 0}, {"nessus", alert.ClientScanner, 0},
	{"openvas", alert.ClientScanner, 0}, {"qualys", alert.ClientScanner, 0}, {"jaeles", alert.ClientScanner, 0},
	{"arachni", alert.ClientScanner, 0}, {"w3af", alert.ClientScanner, 0}, {"skipfish", alert.ClientScanner, 0},
	{"commix", alert.ClientScanner, 0}, {"xsstrike", alert.ClientScanner, 0}, {"wapiti", alert.ClientScanner, 0},
	{"censysinspect", alert.ClientScanner, 0}, {"palo alto networks", alert.ClientScanner, 0},
	{"internet-measurement", alert.ClientScanner, 0}, {"modatscanner", alert.ClientScanner, 0},
	{"l9explore", alert.ClientScanner, 0}, {"l9tcpid", alert.ClientScanner, 0}, {"netlab360", alert.ClientScanner, 0},
	{"projectdiscovery", alert.ClientScanner, 0}, {"leakix", alert.ClientScanner, 0}, {"zmeu", alert.ClientScanner, 0},
	{"morfeus", alert.ClientScanner, 0}, {"jorgee", alert.ClientScanner, 0}, {"isscyberriskcrawler", alert.ClientScanner, 0},

	// Link previews of chat and social sites.
	{"facebookexternalhit", alert.ClientPreview, 0}, {"facebookcatalog", alert.ClientPreview, 0},
	{"twitterbot", alert.ClientPreview, 0}, {"slackbot", alert.ClientPreview, 0}, {"slack-imgproxy", alert.ClientPreview, 0},
	{"discordbot", alert.ClientPreview, 0}, {"telegrambot", alert.ClientPreview, 0}, {"whatsapp/", alert.ClientPreview, 0},
	{"linkedinbot", alert.ClientPreview, 0}, {"skypeuripreview", alert.ClientPreview, 0}, {"pinterestbot", alert.ClientPreview, 0},
	{"redditbot", alert.ClientPreview, 0}, {"embedly", alert.ClientPreview, 0}, {"iframely", alert.ClientPreview, 0},
	{"mastodon/", alert.ClientPreview, 0}, {"bluesky cardyb", alert.ClientPreview, 0}, {"applenewsbot", alert.ClientPreview, 0},

	// Uptime and health checks.
	{"uptimerobot", alert.ClientMonitor, 0}, {"pingdom", alert.ClientMonitor, 0}, {"statuscake", alert.ClientMonitor, 0},
	{"site24x7", alert.ClientMonitor, 0}, {"newrelicpinger", alert.ClientMonitor, 0}, {"datadog", alert.ClientMonitor, 0},
	{"betteruptime", alert.ClientMonitor, 0}, {"better uptime", alert.ClientMonitor, 0}, {"hetrixtools", alert.ClientMonitor, 0},
	{"freshping", alert.ClientMonitor, 0}, {"uptime-kuma", alert.ClientMonitor, 0}, {"checkly", alert.ClientMonitor, 0},
	{"elb-healthchecker", alert.ClientMonitor, 0}, {"googlehc", alert.ClientMonitor, 0}, {"kube-probe", alert.ClientMonitor, 0},
	{"consul health", alert.ClientMonitor, 0}, {"check_http", alert.ClientMonitor, 0}, {"zabbix", alert.ClientMonitor, 0},
	{"blackbox exporter", alert.ClientMonitor, 0}, {"googlestackdrivermonitoring", alert.ClientMonitor, 0},
	{"route53-health-check", alert.ClientMonitor, 0}, {"cloudflare-healthchecks", alert.ClientMonitor, 0},
	{"chrome-lighthouse", alert.ClientMonitor, 0}, {"gtmetrix", alert.ClientMonitor, 0}, {"updown.io", alert.ClientMonitor, 0},
	{"nodeping", alert.ClientMonitor, 0},

	// HTTP libraries, command-line tools and scraping frameworks.
	{"curl/", alert.ClientTool, 0}, {"libcurl", alert.ClientTool, 0}, {"wget/", alert.ClientTool, 0},
	{"python-requests", alert.ClientTool, 0}, {"python-urllib", alert.ClientTool, 0}, {"python-httpx", alert.ClientTool, 0},
	{"aiohttp/", alert.ClientTool, 0}, {"python/3", alert.ClientTool, 0}, {"go-http-client", alert.ClientTool, 0},
	{"go-resty", alert.ClientTool, 0}, {"fasthttp", alert.ClientTool, 0}, {"java/", alert.ClientTool, 0},
	{"java-http-client", alert.ClientTool, 0}, {"apache-httpclient", alert.ClientTool, 0},
	{"commons-httpclient", alert.ClientTool, 0}, {"libwww-perl", alert.ClientTool, 0}, {"lwp::", alert.ClientTool, 0},
	{"php/", alert.ClientTool, 0}, {"guzzlehttp", alert.ClientTool, 0}, {"wordpress/", alert.ClientTool, 0},
	{"node-fetch", alert.ClientTool, 0}, {"axios/", alert.ClientTool, 0}, {"undici", alert.ClientTool, 0},
	{"got (https://github.com/sindresorhus/got)", alert.ClientTool, 0}, {"scrapy", alert.ClientTool, 0},
	{"colly", alert.ClientTool, 0}, {"httrack", alert.ClientTool, 0}, {"nutch", alert.ClientTool, 0},
	{"mechanize", alert.ClientTool, 0}, {"httpie", alert.ClientTool, 0}, {"postmanruntime", alert.ClientTool, 0},
	{"insomnia/", alert.ClientTool, 0}, {"windowspowershell", alert.ClientTool, 0}, {"winhttp", alert.ClientTool, 0},
	{"reqwest", alert.ClientTool, 0}, {"dart:io", alert.ClientTool, 0}, {"rest-client", alert.ClientTool, 0},
	{"faraday v", alert.ClientTool, 0}, {"hackney", alert.ClientTool, 0}, {"http.rb", alert.ClientTool, 0},
	{"aria2", alert.ClientTool, 0}, {"cpp-httplib", alert.ClientTool, 0}, {"lua-resty-http", alert.ClientTool, 0},
	{"deno/", alert.ClientTool, 0}, {"bun/", alert.ClientTool, 0},

	// The networking libraries of phone apps, whose users are people.
	{"cfnetwork/", alert.ClientPerson, 0}, {"dalvik/", alert.ClientPerson, 0}, {"okhttp/", alert.ClientPerson, 0},
}

// exactTools are whole user agents that name a runtime's default client: Node's fetch, Ruby's Net::HTTP and so on.
var exactTools = map[string]bool{"node": true, "undici": true, "ruby": true, "python": true, "java": true, "go": true, "perl": true}

// rank orders the kinds a user agent can name: the first that matched wins.
var rank = [...]alert.Client{alert.ClientScanner, alert.ClientAI, alert.ClientSearch, alert.ClientSEO, alert.ClientHeadless,
	alert.ClientPreview, alert.ClientMonitor, alert.ClientTool, alert.ClientPerson}

var known = func() ahocorasick.AhoCorasick {
	words := make([]string, len(signatures))
	for i, s := range signatures {
		words[i] = s.word
	}
	b := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{AsciiCaseInsensitive: true, MatchKind: ahocorasick.StandardMatch, DFA: true})
	return b.Build(words)
}()

// botWords are what a bot's user agent says of it when it names no program this package knows. They count only outside
// a browser's user agent, or inside one that is marked "compatible;": a phone called Cubot is not a bot.
var botWords = func() ahocorasick.AhoCorasick {
	b := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{AsciiCaseInsensitive: true, MatchKind: ahocorasick.LeftMostFirstMatch, DFA: true})
	return b.Build([]string{"bot", "crawl", "spider", "scrape", "slurp", "fetcher", "headless"})
}()

// Classify reads what kind of client sent a request, and the search engine it claims to be when that can be checked by
// DNS (see Verifier). It reads the User-Agent, whether the Accept and Accept-Language headers every browser sends are
// there, and the protocol: a browser's user agent over HTTP/1.0, or without those headers, is a bot.
func Classify(h http.Header, protoMajor, protoMinor int, method string) (alert.Client, Engine) {
	ua := strings.TrimSpace(h.Get("User-Agent"))
	if len(ua) > maxUA {
		ua = ua[:maxUA]
	}
	if ua == "" {
		return alert.ClientBot, 0
	}
	best, engine := 0, Engine(0)
	it := known.IterOverlapping(ua)
	for m := it.Next(); m != nil; m = it.Next() {
		s := &signatures[m.Pattern()]
		if r := rankOf(s.client); best == 0 || r < best {
			best, engine = r, s.engine
		}
	}
	browser := strings.HasPrefix(ua, "Mozilla/5.0 (") || strings.HasPrefix(ua, "Opera/")
	switch {
	case best != 0 && rank[best-1] != alert.ClientPerson:
		return rank[best-1], engine
	case strings.Contains(h.Get("Sec-Ch-Ua"), "HeadlessChrome"):
		return alert.ClientHeadless, 0
	case exactTools[strings.ToLower(ua)]:
		return alert.ClientTool, 0
	case strings.Contains(ua, "http://") || strings.Contains(ua, "https://") || strings.Contains(ua, "+http"):
		return alert.ClientBot, 0 // a contact address: no browser has one
	case best != 0:
		return alert.ClientPerson, 0 // an app
	case !browser:
		if mobileApp(ua) {
			return alert.ClientPerson, 0
		}
		return alert.ClientBot, 0
	case strings.Contains(ua, "compatible;") && botWords.Iter(ua).Next() != nil:
		return alert.ClientBot, 0
	case protoMajor == 1 && protoMinor == 0:
		return alert.ClientBot, 0 // no browser of this century speaks HTTP/1.0
	case method != http.MethodOptions && (h.Get("Accept") == "" || h.Get("Accept-Language") == ""):
		return alert.ClientBot, 0 // a browser's user agent without what every browser sends
	}
	return alert.ClientPerson, 0
}

func rankOf(c alert.Client) int {
	for i, r := range rank {
		if r == c {
			return i + 1
		}
	}
	return len(rank) + 1
}

// mobileApp reports a user agent of the form apps on phones send, "Shop/4.2 (iPhone; iOS 17.4; Scale/3.00)".
func mobileApp(ua string) bool {
	i := strings.IndexByte(ua, '(')
	if i < 0 {
		return false
	}
	rest := ua[i:]
	return strings.Contains(rest, "iPhone") || strings.Contains(rest, "iPad") || strings.Contains(rest, "iOS ") ||
		strings.Contains(rest, "Android")
}
