// SPDX-License-Identifier: Apache-2.0

// Package bots tells what kind of client sent a request from what the request says about itself, checks the claims of
// search engine crawlers by DNS, and refuses the kinds of client a site chooses (ADR-0087).
//
// A request's user agent is the client's own claim. A declared crawler, tool or headless browser is named by it; a
// program that copies a browser's user agent is caught when the rest of its request (other headers, the TLS handshake)
// is not what that browser sends; one that copies all of it, or drives a real browser, is read as a person. Only a
// search engine's or crawler operator's claim can be checked, against its DNS.
package bots

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/YurilLAB/coraza/carnical/alert"
)

// maxUA is the longest a browser's user agent is: a longer one is a bot's. The whole of it is still searched for names,
// so padding cannot hide one; the server bounds headers (32 KiB).
const maxUA = 512

// Engine is a search engine or crawler operator whose crawlers can be checked by DNS: the address's name must be in one
// of the operator's domains, and that name must resolve back to the address. 0 is none.
type Engine uint8

// The operators that publish their crawlers' DNS names. Google has two: its common crawlers (Googlebot, GoogleOther, ...)
// are under googlebot.com, and its special-case crawlers (AdsBot, ...) are rate-limited-proxy-*.google.com. Neither
// accepts the rest of google.com, where Google's user-triggered fetchers (google-proxy-*.google.com) fetch whatever
// any user asks, nor googleusercontent.com, where every Google Cloud machine has a name.
const (
	EngineGoogle Engine = iota + 1
	EngineBing
	EngineApple
	EngineYandex
	EngineBaidu
	EnginePetal
	EngineSeznam
	EngineNaver
	EngineAmazon
	EngineGoogleSpecial

	numEngines = int(EngineGoogleSpecial) + 1
)

var engines = [numEngines]struct {
	name    string
	domains []string
}{
	EngineGoogle:        {"google", []string{"googlebot.com"}},
	EngineBing:          {"bing", []string{"search.msn.com"}},
	EngineApple:         {"apple", []string{"applebot.apple.com"}},
	EngineYandex:        {"yandex", []string{"yandex.ru", "yandex.net", "yandex.com"}},
	EngineBaidu:         {"baidu", []string{"baidu.com", "baidu.jp"}},
	EnginePetal:         {"petal", []string{"petalsearch.com"}},
	EngineSeznam:        {"seznam", []string{"seznam.cz"}},
	EngineNaver:         {"naver", []string{"naver.com"}},
	EngineAmazon:        {"amazon", []string{"crawl.amazonbot.amazon", "amazonadbot.com"}},
	EngineGoogleSpecial: {"google-special", []string{"rate-limited-proxy-*.google.com"}},
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

// words gives every word of a list the same kind.
func words(c alert.Client, ws ...string) []signature {
	out := make([]signature, len(ws))
	for i, w := range ws {
		out[i] = signature{w, c, 0}
	}
	return out
}

// signatures name programs by the words their user agents carry. Where several match, the kind ranked first by rank
// wins: a scanner that also names a library is a scanner. ClientPerson here is an app's networking library on a phone,
// which people use. The lists draw on the CRS scanner list, the nginx Ultimate Bad Bot Blocker's bad user agents and the
// ai.robots.txt project, keeping only words no browser's user agent contains.
var signatures = slices.Concat(
	// Search engines that publish their crawlers' DNS names.
	[]signature{
		{"googlebot", alert.ClientSearch, EngineGoogle}, {"adsbot-google", alert.ClientSearch, EngineGoogleSpecial},
		{"mediapartners-google", alert.ClientSearch, EngineGoogleSpecial}, {"google-inspectiontool", alert.ClientSearch, EngineGoogle},
		{"storebot-google", alert.ClientSearch, EngineGoogle}, {"apis-google", alert.ClientSearch, EngineGoogleSpecial},
		{"bingbot", alert.ClientSearch, EngineBing}, {"msnbot", alert.ClientSearch, EngineBing},
		{"adidxbot", alert.ClientSearch, EngineBing}, {"bingpreview", alert.ClientSearch, EngineBing},
		{"applebot", alert.ClientSearch, EngineApple},
		{"yandexbot", alert.ClientSearch, EngineYandex}, {"yandeximages", alert.ClientSearch, EngineYandex},
		{"yandexmobilebot", alert.ClientSearch, EngineYandex}, {"yandex.com/bots", alert.ClientSearch, EngineYandex},
		{"baiduspider", alert.ClientSearch, EngineBaidu}, {"petalbot", alert.ClientSearch, EnginePetal},
		{"seznambot", alert.ClientSearch, EngineSeznam}, {"yeti/", alert.ClientSearch, EngineNaver},
		{"googleother", alert.ClientAI, EngineGoogle}, {"google-cloudvertexbot", alert.ClientAI, EngineGoogle},
		{"amazonbot", alert.ClientAI, EngineAmazon}, {"amazonadbot", alert.ClientSEO, EngineAmazon},
	},
	// Search engines that publish no DNS names, and Google's user-triggered fetchers: claims that cannot be checked.
	words(alert.ClientSearch, "feedfetcher-google", "google-site-verification", "duckduckbot", "qwantbot", "qwantify",
		"mojeekbot", "sogou web spider", "sogouspider", "360spider", "haosouspider", "coccocbot", "istellabot", "mail.ru_bot",
		"yisouspider", "sosospider", "youdaobot", "aspiegelbot"),
	// AI companies' crawlers and fetchers, and agents that sign their requests (see Classify).
	words(alert.ClientAI, "gptbot", "chatgpt-user", "chatgpt agent", "oai-searchbot", "oai-adsbot", "openai.com",
		"claudebot", "claude-user", "claude-searchbot", "claude-web", "anthropic-ai", "ccbot", "bytespider", "tiktokspider",
		"perplexitybot", "perplexity-user", "amzn-searchbot", "amzn-user", "amazonbuyforme", "novaact", "bedrockbot",
		"meta-externalagent", "meta-externalfetcher", "meta-webindexer", "facebookbot", "google-notebooklm",
		"gemini-deep-research", "googleagent-", "google-agent", "cohere-ai", "cohere-training-data-crawler", "mistralai-",
		"deepseekbot", "duckassistbot", "xai-grok", "grokbot", "youbot", "diffbot", "timpibot", "imagesiftbot", "omgili",
		"ai2bot", "allenai.org", "kangaroo bot", "pangubot", "img2dataset", "laion", "crawl4ai", "firecrawl", "tavilybot",
		"exabot", "exasearchbot", "iaskspider", "iaskbot", "kimi-", "kimibot", "moonshotbot", "linerbot", "phindbot",
		"qwenbot", "tongyibot", "doubaobot", "erniebot", "yiyanbot", "chatglm-spider", "yibot", "sbintuitionsbot",
		"cotoyogi", "velenpublicwebcrawler", "wardbot", "friendlycrawler", "icc-crawler", "apifybot",
		"apifywebsitecontentcrawler", "cloudflare-autorag", "cloudflarebrowserrenderingcrawler", "manus-user",
		"azureai-searchbot", "andibot", "brightbot", "bravebot", "yandexadditional", "webzio-extended", "linkupbot",
		"keenablebot", "channel3bot", "aihitbot", "agentdatabot", "kagi-fetcher", "quillbot", "shapbot"),
	// SEO, marketing, archive and data-mining crawlers, address harvesters and site copiers.
	words(alert.ClientSEO, "ahrefsbot", "ahrefssiteaudit", "semrushbot", "siteauditbot", "mj12bot", "majestic", "dotbot",
		"blexbot", "dataforseobot", "serpstatbot", "barkrowler", "seekportbot", "megaindex", "rogerbot", "screaming frog",
		"sitebulb", "zoominfobot", "linkdexbot", "seokicks", "linkpadbot", "spbot", "trendictionbot", "turnitinbot",
		"awario", "brandwatch", "proximic", "grapeshot", "babbar", "netestate", "sistrix", "domainstatsbot",
		"magpie-crawler", "keys-so-bot", "dataprovider", "panscient", "linkfluence", "ia_archiver", "archive.org_bot",
		"heritrix", "factset_spyderbot", "mauibot", "serendeputybot", "clarabot", "80legs", "builtwith", "buzzsumo",
		"seobility", "seositecheckup", "sitechecker", "searchmetricsbot", "oncrawl", "openlinkprofiler", "rankactive",
		"backlinkcrawler", "brandprotect", "markmonitor", "nameprotect", "spyfu", "cognitiveseo", "netcraftsurveyagent",
		"demandbase", "salesintelligent", "linqia", "meanpathbot", "dnbcrawler", "adscanner", "domcopbot",
		"domaincrawler", "seolyt", "seoprofiler", "seostats", "screenerbot", "semanticjuice", "senutobot",
		"seocherrybot", "splitsignalbot", "rankingbot", "rankurbot", "rankivabot", "cocolyzebot", "mediatoolkitbot",
		"ltx71", "evc-batch", "zauba", "webmeup", "copyscape", "picscout",
		// Address harvesters and site copiers.
		"emailcollector", "emailsiphon", "email siphon", "emailwolf", "email wolf", "extractorpro", "blackwidow", "webzip",
		"teleport pro", "teleportpro", "webcopier", "webstripper", "websucker", "webreaper", "offline explorer",
		"offline navigator", "sitesnagger", "sitesucker", "cyotekwebcopy", "httrack", "getright", "flashget", "go!zilla",
		"leechget", "mass downloader", "netants", "pavuk", "wwwoffle"),
	// Browsers driven by programs.
	words(alert.ClientHeadless, "headlesschrome", "phantomjs", "slimerjs", "lightpanda", "puppeteer", "playwright",
		"selenium", "webdriver", "htmlunit", "jsdom/"),
	// Vulnerability scanners, attack and brute-force tools, internet-wide scanning services and botnets.
	words(alert.ClientScanner, "nikto", "sqlmap", "havij", "sqlninja", "sqlworm", "ghauri", "jsql", "nmap", "masscan",
		"zgrab", "nuclei", "jaeles", "wpscan", "wprecon", "wpprobe", "joomscan", "droopescan", "cmsmap", "whatweb",
		"whatwaf", "webshag", "libwhisker", "gobuster", "feroxbuster", "dirbuster", "dirsearch", "fuzz faster u fool",
		"wfuzz", "jbrofuzz", "acunetix", "appscan", "netsparker", "invicti", "nessus", "openvas", "qualys", "detectify",
		"arachni", "w3af", "skipfish", "commix", "xsstrike", "xsser", "dalfox", "wapiti", "fimap", "lfisuite", "lfimap",
		"dotdotpwn", "kadimus", "tplmap", "sstimap", "graphw00f", "graphql-cop", "trufflehog", "noseyparker", "nettacker",
		"bewica-security-scan", "cms-security-auditor", "tlm-audit-scanner", "infrasec scanner", "fhscan", "sysscan",
		"censysinspect", "palo alto networks", "internet-measurement", "internetmeasurement", "modatscanner", "shodan",
		"l9explore", "l9tcpid", "l9scan", "netlab360", "projectdiscovery", "leakix", "aliyunsecbot",
		"isscyberriskcrawler", "spy4x-domain-scanner", "scan.lol", "opendirme-credhunt", "litellm-recon",
		// Brute-force and credential-stuffing kits.
		"(hydra)", "forest lobster", "openbullet", "silverbullet", "sentrymba", "sentry mba", "blackbullet",
		// Botnets, exploit kits and malformed user agents no real client sends.
		"zmeu", "morfeus", "jorgee", "libredtail", "muhstik", "terrabot", "wp2shell", "t0phackteam", "datacha0s",
		"voideye", "probethenet", "check1.exe", "xpymep1.exe", "x09mozilla", "x22mozilla", "mozlila", "mozila/",
		"hello, world", "hello world"),
	// Link previews of chat and social sites, feed readers, mail services fetching a message's images, and a page read
	// aloud: fetches made for people.
	words(alert.ClientPreview, "googleimageproxy", "yahoomailproxy", "google-read-aloud", "google-speakr", "facebookexternalhit", "facebookcatalog", "twitterbot", "slackbot", "slack-imgproxy",
		"discordbot", "telegrambot", "whatsapp/", "linkedinbot", "skypeuripreview", "microsoftpreview", "pinterestbot",
		"redditbot", "embedly", "iframely", "mastodon/", "bluesky cardyb", "applenewsbot", "vkshare", "kakaotalk-scrap",
		"feedly", "feedbin", "newsblur", "inoreader", "freshrss", "tiny tiny rss", "theoldreader",
		"netnewswire", "miniflux"),
	// Uptime and health checks, and a certificate authority checking the site's domain (ACME HTTP-01).
	words(alert.ClientMonitor, "let's encrypt validation server", "uptimerobot", "pingdom", "statuscake", "site24x7", "newrelicpinger", "datadog",
		"betteruptime", "better uptime", "hetrixtools", "freshping", "uptime-kuma", "checkly", "elb-healthchecker",
		"googlehc", "kube-probe", "consul health", "check_http", "nagios", "zabbix", "blackbox exporter",
		"googlestackdrivermonitoring", "route53-health-check", "cloudflare-healthchecks", "azure traffic manager",
		"chrome-lighthouse", "gtmetrix", "updown.io", "nodeping", "cron-job.org", "elastic-heartbeat", "gatus/"),
	// HTTP libraries, command-line tools and scraping frameworks.
	words(alert.ClientTool, "curl/", "libcurl", "pycurl", "wget/", "lftp", "python-requests", "python-urllib", "urllib3",
		"httplib2", "python-httpx", "aiohttp/", "python/3", "trafilatura", "go-http-client", "go-resty", "fasthttp",
		"java/", "java-http-client", "apache-httpclient", "apache-httpasyncclient", "commons-httpclient", "jetty/",
		"crawler4j", "scalaj-http", "ktor-client", "libwww-perl", "lwp::", "lwp-request", "lwp-trivial", "mojolicious",
		"poe-component-client-http", "anyevent-http", "http::lite", "php/", "guzzlehttp", "symfony httpclient", "phpcrawl",
		"snoopy v", "wordpress/", "node-fetch", "axios/", "undici", "superagent", "got (https://github.com/sindresorhus/got)",
		"probe-image-size", "scrapy", "colly", "nutch", "mechanize", "httpie", "postmanruntime", "insomnia/",
		"windowspowershell", "winhttp", "indy library", "restsharp", "reqwest", "dart:io", "rest-client", "faraday v",
		"typhoeus", "hackney", "http.rb", "aria2", "cpp-httplib", "cpprest", "lua-resty-http", "deno/", "bun/"),
	// The networking libraries of phone apps, and apps and devices that fetch for the person using them.
	words(alert.ClientPerson, "cfnetwork/", "dalvik/", "okhttp/", "microsoft office", "roku/dvp-"),
)

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

// Hello is what the TLS handshake of a request's connection showed, when carnical terminated it (see Hellos).
type Hello struct {
	// Seen says the handshake was seen; the rest is meaningful only then.
	Seen bool
	// GREASE says the client offered GREASE values (RFC 8701): every Chromium-based browser does, and the TLS stacks of
	// Python, Go, Java, Node and curl do not.
	GREASE bool
	// RecordSizeLimit says the client offered the record_size_limit extension (RFC 8449): Firefox and the other
	// browsers built on its TLS (NSS) do, and OpenSSL, Go, Java and Node do not.
	RecordSizeLimit bool
}

// Classify reads what kind of client sent a request, and the operator it claims to be when that can be checked by DNS
// (see Verifier). It reads the User-Agent and, for a browser's user agent, whether the rest of the request is what that
// browser sends (see disguised); hello is the request's TLS handshake, the zero Hello when carnical did not see one.
func Classify(r *http.Request, hello Hello) (alert.Client, Engine) {
	h := r.Header
	agents := h.Values("User-Agent")
	ua := ""
	if len(agents) > 0 {
		ua = strings.TrimSpace(agents[0])
	}
	if ua == "" {
		return alert.ClientBot, 0
	}
	long := len(ua) > maxUA
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
	case long:
		return alert.ClientBot, 0 // longer than any browser's
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
	case len(agents) > 1 || disguised(r, ua, hello):
		return alert.ClientDisguised, 0
	// Headers a client adds of its own accord come after the checks they could otherwise get a program past.
	case h.Get("Signature-Agent") != "":
		return alert.ClientAI, 0 // a browser an agent drives, signing its requests (Web Bot Auth), such as ChatGPT's
	case strings.Contains(h.Get("Sec-Ch-Ua"), "HeadlessChrome"):
		return alert.ClientHeadless, 0
	}
	return alert.ClientPerson, 0
}

// disguised reports a browser's user agent on a request that browser would not send. Each sign is one every current
// release of the browser named shows, so that only a program that copied the user agent (and perhaps some headers)
// fails it:
//   - HTTP/1.0, or no Accept or Accept-Language header (a CORS preflight sends no language, a WebSocket handshake no
//     Accept);
//   - a version long out of use: Internet Explorer before 11, Chrome before 70, Firefox before 60;
//   - client hints (Sec-CH-UA) from Firefox or Safari, which send none, or from Chrome naming another version or platform;
//   - over a TLS connection carnical holds, a current Chrome, Firefox or Safari without the Sec-Fetch headers, or a
//     current Chrome without client hints (forks and embedded browsers that may not send them are left out);
//   - a Chromium-based browser whose TLS handshake offered no GREASE values, or a current Firefox whose handshake did not
//     offer record_size_limit: the TLS of the program that sent it, not of the browser.
func disguised(r *http.Request, ua string, hello Hello) bool {
	h := r.Header
	if r.ProtoMajor == 1 && r.ProtoMinor == 0 {
		return true
	}
	// A browser opening a WebSocket sends no Accept, and Chrome no Sec-Fetch or client hints either, so a handshake is
	// held to the rest: what a program could copy to pass does not get it past the TLS checks.
	socket := r.Method == http.MethodGet && strings.EqualFold(h.Get("Upgrade"), "websocket") &&
		h.Get("Sec-Websocket-Key") != "" && h.Get("Sec-Websocket-Version") != "" && h.Get("Origin") != ""
	if r.Method != http.MethodOptions && (h.Get("Accept") == "" && !socket || h.Get("Accept-Language") == "") {
		return true
	}
	if v, ok := version(ua, "MSIE "); ok && v < 11 {
		return true
	}
	chrome, isChrome := version(ua, "Chrome/")
	isChrome = isChrome && !strings.Contains(ua, " Edge/") // the old Edge (EdgeHTML) named a Chrome it was not
	firefox, isFirefox := version(ua, "Firefox/")
	safari, isSafari := 0, false
	if !isChrome && strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chromium/") {
		safari, isSafari = version(ua, "Version/")
	}
	if isChrome && chrome < 70 || isFirefox && !isChrome && firefox < 60 {
		return true
	}
	hints := h.Get("Sec-Ch-Ua")
	if hints != "" && !isChrome && (isFirefox || isSafari) {
		return true
	}
	if hints != "" && isChrome && (!hintsName(hints, chrome) || !samePlatform(ua, h.Get("Sec-Ch-Ua-Platform"))) {
		return true
	}
	if r.TLS != nil {
		fetch := h.Get("Sec-Fetch-Mode") != "" || h.Get("Sec-Fetch-Site") != "" || h.Get("Sec-Fetch-Dest") != ""
		if !fetch && (isChrome && chrome >= 80 && !socket || isFirefox && !isChrome && firefox >= 90 || isSafari && safari >= 17) {
			return true
		}
		if hints == "" && isChrome && chrome >= 90 && !socket && plainChrome(ua) {
			return true
		}
	}
	return hello.Seen && (isChrome && !hello.GREASE || isFirefox && !isChrome && firefox >= 90 && !hello.RecordSizeLimit)
}

// version reads the major version that follows token in a user agent.
func version(ua, token string) (int, bool) {
	i := strings.Index(ua, token)
	if i < 0 {
		return 0, false
	}
	v, digits := 0, 0
	for _, c := range []byte(ua[i+len(token):]) {
		if c < '0' || c > '9' || digits == 4 {
			break
		}
		v, digits = v*10+int(c-'0'), digits+1
	}
	return v, digits > 0
}

// hintsName reports whether Sec-CH-UA names the major version the user agent gives, as every Chromium brand list does
// (`"Chromium";v="141", "Google Chrome";v="141", "Not?A_Brand";v="8"`).
func hintsName(hints string, major int) bool {
	if len(hints) > 256 {
		hints = hints[:256]
	}
	want := `v="` + strconv.Itoa(major) + `"`
	return strings.Contains(hints, want)
}

// samePlatform reports whether Sec-CH-UA-Platform agrees with the user agent's operating system, when both say one.
func samePlatform(ua, platform string) bool {
	platform = strings.Trim(platform, `"`)
	if platform == "" {
		return true
	}
	var os string
	switch {
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "Windows NT"):
		os = "Windows"
	case strings.Contains(ua, "Macintosh"):
		os = "macOS"
	case strings.Contains(ua, "CrOS"):
		os = "Chrome OS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	default:
		return true
	}
	return platform == os
}

// plainChrome reports Chrome, Edge or Opera, which send client hints on every secure request, and not a fork or an
// embedded browser that may not: Samsung Internet, Yandex, UC, Silk, Android's WebView, Electron and Qt.
func plainChrome(ua string) bool {
	for _, fork := range [...]string{"SamsungBrowser", "YaBrowser", "UCBrowser", "Silk/", "; wv)", "Electron/", "QtWebEngine"} {
		if strings.Contains(ua, fork) {
			return false
		}
	}
	return true
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
