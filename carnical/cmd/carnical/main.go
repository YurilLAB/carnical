// SPDX-License-Identifier: Apache-2.0

// Command carnical puts the OWASP Core Rule Set, run by Coraza, in front of one website.
//
//	carnical -upstream http://127.0.0.1:8081 -listen :8080            (logs what the rules find, blocks nothing)
//	carnical -upstream http://127.0.0.1:8081 -mode block              (blocks at the anomaly threshold)
//
// Start in detect mode, read the log for a few days, add exclusions for the false positives, then switch to block.
package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"maps"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/YurilLAB/coraza/carnical/bots"
	"github.com/YurilLAB/coraza/carnical/crowdsec"
	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/proxy"
	"github.com/YurilLAB/coraza/carnical/sandbox"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "carnical:", err)
		os.Exit(1)
	}
}

func run() error {
	return runCommand(os.Args[1:], os.Stdin, os.Stdout)
}

// runArgs runs the proxy, leaving the settings a site file stores encrypted out of whatever error it returns.
func runArgs(args []string) error {
	return runArgsTo(os.Stderr, os.Stderr, args)
}

// runArgsTo is runArgs with the flag list of -h written to usage and the log to logs.
func runArgsTo(usage, logs io.Writer, args []string) error {
	private := map[string]string{}
	return redactPrivate(runFlags(usage, logs, args, private), private)
}

func runFlags(usage, logs io.Writer, args []string, private map[string]string) error {
	flags := flag.NewFlagSet("carnical", flag.ContinueOnError)
	flags.SetOutput(usage)
	flags.Usage = func() {
		fmt.Fprintln(usage, "Usage: carnical setup|check|start|help|version, or carnical [flags]\nRun 'carnical help' for a short guide. Every flag:")
		flags.PrintDefaults()
	}
	configFile := flags.String("config", "", "site JSON configuration, including encrypted setup fields (maximum 64 KiB; CLI flags override it)")
	flags.String("config-key-file", "", "owner-only 32-byte key file for encrypted site fields (default: setup user key store)")
	check := flags.Bool("check", false, "validate settings and local files, then exit without listening or applying confinement")
	checkOriginHTTP := flags.Bool("check-origin-http", false, "with -check -check-origin, send HEAD / to confirm origin HTTP acceptance; no redirects")
	originCert := flags.String("origin-client-cert", "", "PEM client certificate for authenticated HTTPS origin access")
	originKey := flags.String("origin-client-key", "", "private PEM key for -origin-client-cert (loaded before confinement)")
	originCA := flags.String("origin-ca-file", "", "PEM origin CA bundle (default: system roots; server verification always enabled)")
	checkOrigin := flags.Bool("check-origin", false, "with -check, also verify origin DNS, TCP and HTTPS certificate within 10s (sends no HTTP request)")
	listen := flags.String("listen", "127.0.0.1:8080", "address to listen on")
	healthListen := flags.String("health-listen", "", "private health listener: numeric loopback address and port (default: disabled)")
	probe := flags.String("probe", "", "probe live or ready on -health-listen, then exit without loading the WAF")
	drainDelay := flags.Duration("drain-delay", 0, "delay after withdrawing readiness before closing the visitor listener (0 to 1m)")
	shutdownTimeout := flags.Duration("shutdown-timeout", 30*time.Second, "total budget for drain delay and active HTTP requests (100ms to 10m)")
	upstream := flags.String("upstream", "", "the website to protect, such as http://127.0.0.1:8081 (required)")
	upstreamHost := flags.String("upstream-host", "", "Host header to send to the upstream (default: the visitor's)")
	mode := flags.String("mode", "detect", "detect (log only), block, or off")
	paranoia := flags.Int("paranoia", 1, "CRS paranoia level 1 to 4: rules at this level and below block")
	detection := flags.Int("detection-paranoia", 0, "log what a higher level would find (0 = same as -paranoia)")
	inbound := flags.Int("inbound-threshold", 5, "anomaly score at which a request is blocked")
	outbound := flags.Int("outbound-threshold", 4, "anomaly score at which a response is blocked (with -inspect-responses)")
	maxBody := flags.Int64("max-body", 1<<20, "largest request body inspected, in bytes; a larger body is refused")
	formatsMode := flags.String("formats-mode", "monitor", "request formats: monitor (default), block, or off; independent of -mode and overrides policy monitor")
	formatsPolicy := flags.String("formats-policy", "", "JSON request-format policy file (maximum 1 MiB; default: built-in format limits)")
	formatsStats := flags.Duration("formats-stats-interval", time.Minute, "log changed per-rule blocked/monitored format totals (0 = off; 100ms to 24h)")
	requestEncoding := flags.Bool("allow-request-encoding", false, "allow one bounded gzip or deflate layer through the format inspector (requires formats enabled)")
	responses := flags.Bool("inspect-responses", false, "also run the CRS response rules (buffers text, HTML and XML responses)")
	localRules := flags.Bool("local-rules", true, "run Carnical supplemental injection rules at PL1, with the selected CRS mode and threshold")
	localRulesOff := flags.String("local-rules-off", "", "comma-separated ids of single local rules to switch off (5006001 to 5006022; at most 32)")
	localRulesOn := flags.String("local-rules-on", "", "comma-separated ids of stricter local rules to switch on (5006101: the path /console; 5006102: a script on another host in a form or JSON field; 5006103: a forwarded host that is not the host asked for)")
	joinRepeated := flags.Bool("join-repeated-params", true, "also inspect the values of a parameter given more than once joined with commas, as ASP.NET and others hand them to the application")
	apiSpec := flags.String("api-spec", "", "local OpenAPI JSON/YAML contract; scalar/array parameters and JSON bodies (no fetching or learning)")
	apiSpecMode := flags.String("api-spec-mode", "block", "OpenAPI contract action: block or monitor (block requires formats block)")
	methods := flags.String("allowed-methods", "", "comma-separated HTTP methods to allow (default: the CRS list GET HEAD POST OPTIONS)")
	trustedList := flags.String("trusted-proxies", "", "comma-separated addresses or ranges that may supply X-Forwarded-For")
	originAllow := flags.String("origin-allow", "", "comma-separated addresses or ranges the upstream may be at even though they are not public (default: public addresses only)")
	hosts := flags.String("hosts", "", "comma-separated names this site answers to; any other Host gets 421 (default: any)")
	encodedSlash := flags.Bool("allow-encoded-slash", false, "allow %2f and %5c in request paths (refused by default)")
	pathParams := flags.Bool("allow-path-params", false, "allow a semicolon in request paths, as Java's ;jsessionid= needs (refused by default)")
	denyHeaders := flags.String("deny-headers", "", "comma-separated headers whose presence refuses the request, such as Next-Action on a site with no server actions")
	wordpress := flags.Bool("wordpress", false, "protect a WordPress site: no scripts from upload and cache directories, xmlrpc.php off, login attempts limited")
	xmlrpc := flags.Bool("allow-xmlrpc", false, "with -wordpress, leave xmlrpc.php reachable")
	loginRate := flags.Int("login-per-minute", 10, "with -wordpress, POSTs to wp-login.php one address may make a minute, 1 to 100000")
	apiRate := flags.Int("api-per-minute", 0, "shared API requests per verified client address in a sliding minute, 1 to 100000 (0 = disabled)")
	apiPaths := flags.String("api-rate-paths", "/api,/graphql", "plain path prefixes sharing -api-per-minute, matched by path segment; / covers every route")
	limits := &limitFlag{}
	flags.Var(limits, "limit", "per-client rate limits: [METHODS] PATHS COUNT/WINDOW [monitor], separated by ';' or given as repeated flags, as in 'POST /login 5/m; /api 600/m' (windows s, m or h, as in 5/m, 100/10s or 1k/h)")
	scriptNames := flags.Bool("allow-script-names", false, "allow uploads named like scripts (shell.php, .htaccess); refused by default")
	scriptContent := flags.Bool("allow-script-content", false, "allow uploads that contain a PHP, ASP or JSP opening tag; refused by default")
	keepBanners := flags.Bool("keep-banners", false, "keep X-Powered-By and Server headers from the application")
	keepCaching := flags.Bool("keep-caching", false, "do not add Cache-Control: private, no-store to responses that set a cookie or look like a stylesheet but are HTML")
	ddos := declareShieldFlags(flags)
	csAPI := flags.String("crowdsec-api", "", "CrowdSec LAPI HTTP(S) origin or absolute Unix socket path (empty = disabled; HTTP requires loopback)")
	csKey := flags.String("crowdsec-key-file", "", "private file containing a dedicated CrowdSec bouncer key")
	csCA := flags.String("crowdsec-ca-file", "", "PEM CA bundle for CrowdSec HTTPS (default: system roots; verification always enabled)")
	csInterval := flags.Duration("crowdsec-poll", 10*time.Second, "CrowdSec update interval, 1s to 1h")
	csTimeout := flags.Duration("crowdsec-timeout", 5*time.Second, "CrowdSec API timeout, 100ms to 30s")
	csStale := flags.Duration("crowdsec-max-stale", 2*time.Minute, "CrowdSec cache freshness limit; at least poll + timeout, at most 24h")
	csFailOpen := flags.Bool("crowdsec-fail-open", false, "allow unlisted visitors when CrowdSec cache is stale; unexpired bans still block")
	csLimit := flags.Int("crowdsec-max-decisions", 200000, "maximum stored CrowdSec bans and decisions in a response, 1 to 1000000")
	csOrigins := flags.String("crowdsec-origins", "", "optional comma-separated CrowdSec decision origins (empty = all)")
	maxConns := flags.Int("max-conns-per-ip", 128, "connections one address may hold open (negative = no limit)")
	uploadDir := flags.String("upload-dir", "", "directory for the file parts of uploads while a request runs (default: the system temporary directory; give it a private one)")
	fromSystemd := flags.Bool("systemd-socket", false, "use the listening socket systemd passes in (socket activation), so the proxy needs no privilege to use port 443")
	confine := flags.Bool("confine", false, "after start-up, confine the process: no new programs, no ptrace, no other files, no other ports (Linux; build with CGO_ENABLED=0)")
	confineConnect := flags.String("confine-connect", "80,443,53", "with -confine, the TCP ports the proxy may connect to: the ports of the origins, and 53 for DNS")
	confineRead := flags.String("confine-read", "", "with -confine, extra files and directories the proxy may read (for example a certificate directory it reloads from)")
	confineBestEffort := flags.Bool("confine-best-effort", false, "with -confine, carry on with the layers the kernel supports instead of refusing to start")
	allowUpgrade := flags.Bool("allow-upgrade", false, "let WebSocket upgrades through, uninspected")
	maxUpstream := flags.Int("max-upstream", 256, "requests allowed at the upstream at once")
	evalBudget := flags.Duration("eval-budget", 2*time.Second, "most time each phase of rule evaluation may take for one request; a request over it is refused with 503")
	maxEval := flags.Int("max-evaluations", 0, "requests in rule evaluation at once (0 = the number of CPUs, negative = no limit)")
	readTimeout := flags.Duration("read-timeout", 0, "how long a client has to send a whole request, headers and body; raise it for large uploads over slow connections (0 = 30s; else 1s to 23h)")
	writeTimeout := flags.Duration("write-timeout", 0, "how long a request may take from the end of its headers to the end of its response, so longer than -read-timeout and -upstream-timeout; raise it for large downloads and Server-Sent Events, and with -upstream-timeout for long polling (0 = -read-timeout plus 90s, 2m by default; else 1s to 24h)")
	upstreamTimeout := flags.Duration("upstream-timeout", 0, "how long the upstream has to start its response, so shorter than -write-timeout (the default of 30s too); raise both for long polling (0 = 30s; else 1s to 24h)")
	maxForm := flags.Int64("max-form-body", 128<<10, "largest request body that is not a file upload, in bytes, and the most an upload may hold besides the content of its files; uploads may be as large as -max-body")
	details := flags.Bool("log-details", false, "log client address, URI, matched data and macro-expanded messages (may contain credentials)")
	certFile := flags.String("tls-cert", "", "TLS certificate file")
	keyFile := flags.String("tls-key", "", "TLS key file (not accessible to everyone or writable by its group, as 0600 or 0640)")
	showVersion := flags.Bool("version", false, "print the CRS version that is embedded and exit")
	siteFlag := declareSiteFlags(flags)
	alertFlag := declareAlertFlags(flags)
	autoBlockFlag := declareAutoBlockFlags(flags)
	botFlag := declareBotFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		if *probe != "" || *check || *checkOrigin || *checkOriginHTTP {
			return errors.New("-version cannot be combined with probes or deployment checks")
		}
		info, err := crs.Info()
		if err != nil {
			return err
		}
		fmt.Printf("OWASP CRS %s (archive sha256 %s, signed by %s)\n", info.Version, info.ArchiveSHA256, info.SignerFingerprint)
		return nil
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments; use named flags")
	}
	limitSource := "flag"
	if !setFlags(flags)["limit"] {
		limitSource = "site configuration"
	}
	limitReplaced := false
	site := map[string]bool{} // the flags the site configuration gave, which the command line did not
	if *configFile != "" {
		given := setFlags(flags)
		encrypted, replaced, err := loadSiteConfig(*configFile, flags)
		if err != nil {
			return err
		}
		maps.Copy(private, encrypted)
		limitReplaced = slices.Contains(replaced, "limit")
		for name := range setFlags(flags) {
			site[name] = !given[name]
		}
	}
	if *checkOrigin && !*check {
		return errors.New("-check-origin requires -check")
	}
	if *checkOriginHTTP && (!*check || !*checkOrigin) {
		return errors.New("-check-origin-http requires -check and -check-origin")
	}
	lifecycle := lifecycleOptions{healthAddress: *healthListen, drain: *drainDelay, shutdown: *shutdownTimeout, details: *details}
	if err := lifecycle.validate(); err != nil {
		return err
	}
	if *probe != "" {
		if *check || *checkOrigin || *checkOriginHTTP {
			return errors.New("-probe cannot be combined with deployment checks")
		}
		return probeHealth(*probe, *healthListen)
	}
	// A hang-up drains like SIGTERM: there is no configuration to reload. Once the first signal has started the drain, the
	// handlers are removed, so a second signal ends the process at once instead of waiting out the shutdown budget.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	if *upstream == "" {
		return errors.New("-upstream is required")
	}
	if (*certFile == "") != (*keyFile == "") {
		return errors.New("give both -tls-cert and -tls-key, or neither")
	}
	if *formatsStats != 0 && (*formatsStats < 100*time.Millisecond || *formatsStats > 24*time.Hour) {
		return errors.New("-formats-stats-interval must be 0 or between 100ms and 24h")
	}
	if err := checkTimeouts(*readTimeout, *writeTimeout, *upstreamTimeout); err != nil {
		return fromSite(err, site, private)
	}
	// A negative limit would refuse every request and break the reading of a chunked body.
	if *maxForm < 0 {
		return errors.New("-max-form-body must not be negative")
	}
	target, err := url.Parse(*upstream)
	if err != nil {
		return fmt.Errorf("-upstream: %w", err)
	}
	originTLS, err := configureOriginTLS(target, *originCert, *originKey, *originCA)
	if err != nil {
		return err
	}
	trusted, err := proxy.ParseTrusted(*trustedList)
	if err != nil {
		return fromSite(refuseFlag("trusted-proxies", fmt.Errorf("-trusted-proxies: %w", err)), site, private)
	}
	if err := checkRateFlags(*loginRate, *apiRate, *apiPaths, setFlags(flags)); err != nil {
		return fromSite(err, site, private)
	}
	origin, err := proxy.ParseOriginAllow(*originAllow)
	if err != nil {
		return err
	}
	settings := crs.DefaultSettings()
	settings.Mode = crs.Mode(*mode)
	settings.ParanoiaLevel, settings.DetectionParanoiaLevel = *paranoia, *detection
	settings.InboundThreshold, settings.OutboundThreshold = *inbound, *outbound
	settings.RequestBodyLimit = *maxBody
	settings.InspectResponses = *responses
	settings.DisableLocalRules = !*localRules
	for _, field := range splitList(*localRulesOff) {
		id, err := strconv.Atoi(field)
		if err != nil {
			return fmt.Errorf("-local-rules-off: %q is not a rule id", field)
		}
		settings.LocalRulesOff = append(settings.LocalRulesOff, id)
	}
	for _, field := range splitList(*localRulesOn) {
		id, err := strconv.Atoi(field)
		if err != nil {
			return fmt.Errorf("-local-rules-on: %q is not a rule id", field)
		}
		settings.LocalRulesOn = append(settings.LocalRulesOn, id)
	}
	settings.UploadDir = *uploadDir
	if *methods != "" {
		for _, m := range strings.Split(*methods, ",") {
			settings.AllowedMethods = append(settings.AllowedMethods, strings.ToUpper(strings.TrimSpace(m)))
		}
	}

	log := slog.New(slog.NewJSONHandler(logs, nil))
	alerts, err := configureAlerts(log, alertFlag)
	if err != nil {
		return fromSite(err, site, private)
	}
	defer alerts.close() // after the server has stopped: the last requests' alerts and the final totals
	if limitReplaced {
		// The rules of -limit are one setting, as every flag is: the command line's do not add to the site's.
		log.Info("site configuration limit replaced by the command line")
	}
	cs, err := configureCrowdSec(crowdSecFlags{api: *csAPI, keyFile: *csKey, caFile: *csCA, origins: *csOrigins,
		interval: *csInterval, timeout: *csTimeout, maxStale: *csStale, failOpen: *csFailOpen, maxDecisions: *csLimit})
	if err != nil {
		return err
	}
	if cs != nil {
		defer cs.Close()
		if !*check {
			if err := cs.Sync(ctx); err != nil {
				return err
			} // authentication and complete snapshot required at startup
			log.Info("CrowdSec connected", "entries", cs.Stats().Entries, "skipped", cs.Stats().Skipped, "fail_open", *csFailOpen)
		}
	}
	// The flags given on the command line or in the site configuration; the others keep their defaults.
	explicit := setFlags(flags)
	autoBlock, err := autoBlockSettings(autoBlockFlag, explicit, ddos.mode, alerts.exclude)
	if err != nil {
		return fromSite(err, site, private)
	}
	botsPolicy, err := botPolicy(botFlag)
	if err != nil {
		return fromSite(err, site, private)
	}
	guard, err := configureShieldWith(log, *ddos, explicit, trusted, autoBlock, alerts.source)
	if err != nil {
		return fromSite(err, site, private)
	}
	if guard != nil {
		defer guard.Close()
	}
	// The reverse proxy's own lines (an application that stops part way through a response body) join the JSON log as
	// the servers' do, under the name "origin".
	originErrors := newServerErrors(log.With("server", "origin"), *details)
	defer originErrors.flush()
	var hellos *bots.Hellos // what each TLS handshake showed, for the bot reading, when the proxy holds the certificate
	if *certFile != "" {
		hellos = bots.NewHellos(0)
	}
	cfg := proxy.Config{
		Upstream: target, Origin: proxy.OriginPolicy{Allow: origin}, OriginTLS: originTLS, UpstreamHost: *upstreamHost, CRS: settings, TrustedProxies: trusted, AllowUpgrade: *allowUpgrade,
		MaxUpstreamInFlight: *maxUpstream, LogDetails: *details, EvalBudget: *evalBudget, MaxEvaluations: *maxEval, MaxFormBody: *maxForm,
		ReadTimeout: *readTimeout, WriteTimeout: *writeTimeout, ResponseHeaderTimeout: *upstreamTimeout,
		AllowedHosts: splitList(*hosts), Paths: proxy.PathPolicy{AllowEncodedSlash: *encodedSlash, AllowPathParams: *pathParams},
		DenyHeaders: splitList(*denyHeaders), WordPress: proxy.WordPressPolicy{Enabled: *wordpress, AllowXMLRPC: *xmlrpc, LoginPerMinute: *loginRate},
		APIRate: proxy.APIRatePolicy{PerMinute: *apiRate, Paths: splitList(*apiPaths)}, Limits: limits.rules,
		Uploads:   proxy.UploadPolicy{AllowExecutableNames: *scriptNames, AllowScriptContent: *scriptContent},
		Responses: proxy.ResponsePolicy{KeepBanners: *keepBanners, KeepCaching: *keepCaching}, MaxConnsPerIP: *maxConns,
		AllowRequestEncoding: *requestEncoding, NoJoinedParams: !*joinRepeated, Shield: guard, CrowdSec: cs, Bots: botsPolicy, Hellos: hellos,
		ErrorLog: stdlog.New(originErrors, "", 0), OnAlert: alerts.onAlert, Alerts: alerts.options, EvalBudgetDetect: alerts.evalMode,
		NoRuleMatches: !*alertFlag.ruleMatches,
		OnMatch: func(m proxy.Match) {
			attrs := []any{"rule", m.RuleID, "severity", m.Severity, "rule_msg", m.Message, "tx", m.TransactionID, "disruptive", m.Disruptive,
				"category", m.Category, "risk", m.Risk}
			if *details {
				attrs = append(attrs, "client", m.ClientIP, "uri", m.URI, "data", m.Data, "expanded_msg", m.ExpandedMessage)
			}
			log.Warn("rule matched", attrs...)
		},
	}
	formatInspector, effectiveFormatsMode, patches, err := configureSite(siteFlag, explicit, &cfg, log, *formatsMode, *formatsPolicy, *requestEncoding)
	if err != nil {
		return err
	}
	apiInspector, apiReport, err := configureAPI(*apiSpec, *apiSpecMode, effectiveFormatsMode)
	if err != nil {
		return err
	}
	if apiInspector != nil {
		cfg.Inspectors = append(cfg.Inspectors, apiInspector)
		log.Info("API contract loaded", "mode", *apiSpecMode, "sha256", apiReport.Hash, "routes", apiReport.Routes, "warnings", apiReport.Warnings, "warnings_dropped", apiReport.WarningsDropped)
	}
	for _, warning := range rateFlagWarnings(cfg, explicit) {
		log.Warn(warning)
	}
	edge, err := proxy.New(cfg)
	if err != nil {
		return err
	}
	defer edge.Close()

	server := edge.Server(*listen)
	// Everything the proxy needs from the outside is opened before it is confined: the certificate and key are read,
	// and the listening socket exists. After that it needs no more files, and no new ports to listen on.
	if *certFile != "" {
		certPEM, err := readTLSFile(*certFile, 1<<20, false)
		if err != nil {
			return fmt.Errorf("the certificate: %w", err)
		}
		keyPEM, err := readTLSFile(*keyFile, 64<<10, true)
		if err != nil {
			return fmt.Errorf("the TLS key: %w", err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("the certificate: %w", err)
		}
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, GetConfigForClient: hellos.Observe}
	}
	var confinement sandbox.Policy
	if *confine {
		ports, err := parsePorts(*confineConnect)
		if err != nil {
			return fmt.Errorf("-confine-connect: %w", err)
		}
		// The confined proxy can connect to these ports only, so a port it needs and was not given would pass -check and
		// then fail every request.
		listed := func(port uint16) bool {
			for _, p := range ports {
				if p == port {
					return true
				}
			}
			return false
		}
		originPort, err := upstreamPort(target)
		if err != nil {
			return err
		}
		if !listed(originPort) {
			return fmt.Errorf("the upstream's TCP port %d must be listed in -confine-connect", originPort)
		}
		if cs != nil && cs.ConnectPort() != 0 && !listed(cs.ConnectPort()) {
			return errors.New("CrowdSec API TCP port must be listed in -confine-connect")
		}
		confinement = sandbox.Policy{ReadOnly: splitList(*confineRead), ConnectTCP: ports, BindTCP: []uint16{}, Require: !*confineBestEffort}
		// The engine writes the file parts of an upload to disk, and the confined proxy may not write the system temporary
		// directory: without a directory of its own, such uploads are refused.
		if *uploadDir == "" {
			log.Warn("-confine without -upload-dir: uploads with file parts will be refused")
		} else {
			if err := checkUploadDir(*uploadDir); err != nil {
				return fmt.Errorf("-upload-dir: %w", err)
			}
			confinement.ReadWrite = []string{*uploadDir}
		}
	}
	if err := checkDeployment(deploymentCheck{listen: *listen, target: target, policy: proxy.OriginPolicy{Allow: origin},
		originTLS: originTLS, host: *upstreamHost, systemd: *fromSystemd, probe: *checkOrigin, probeHTTP: *checkOriginHTTP}); err != nil {
		return err
	}
	rateLimits := rateLimitAttrs(cfg, explicit, limitSource)
	if *check {
		log.Info("configuration checked", slices.Concat([]any{"mode", cfg.CRS.Mode, "formats_mode", effectiveFormatsMode, "origin_checked", *checkOrigin, "origin_http_checked", *checkOriginHTTP, "origin_client_identity", originTLS.Certificate != nil, "tls", *certFile != "", "sandbox_applied", false}, ddosLogAttrs(*ddos, explicit), rateLimits)...)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var ln net.Listener
	if *fromSystemd {
		if ln, err = systemdListener(); err != nil {
			return err
		}
	} else if ln, err = net.Listen("tcp", *listen); err != nil {
		return err
	}
	defer ln.Close()
	var healthListener net.Listener
	if *healthListen != "" {
		healthListener, err = net.Listen("tcp", *healthListen)
		if err != nil {
			return fmt.Errorf("health listener: %w", err)
		}
		defer healthListener.Close()
	}
	if guard != nil {
		ln = guard.Listener(ln)
	}
	if *confine {
		rep, err := sandbox.Apply(confinement)
		if err != nil {
			return err
		}
		log.Info("confined", "no_new_privs", rep.NoNewPrivs, "undumpable", rep.Undumpable, "landlock_abi", rep.LandlockABI,
			"files", rep.LandlockFS, "ports", rep.LandlockNet, "scope", rep.LandlockScope, "seccomp", rep.Seccomp, "notes", rep.Notes)
	}
	if cs != nil {
		pollCtx, cancelPoll := context.WithCancel(context.Background())
		pollDone := make(chan struct{})
		go func() {
			defer close(pollDone)
			cs.Run(pollCtx, func(s crowdsec.Stats, err error) {
				attrs := []any{"entries", s.Entries, "skipped", s.Skipped, "stale", s.Stale, "syncs", s.Syncs,
					"failures", s.Failures, "blocked", s.Blocked, "unavailable", s.Unavailable}
				if err != nil {
					attrs = append(attrs, "error", err.Error())
					log.Warn("CrowdSec refresh failed", attrs...)
				} else {
					log.Info("CrowdSec decisions", attrs...)
				}
			})
		}()
		defer func() { cancelPoll(); <-pollDone }()
	}
	if patches != nil {
		stop := startSnapshotLog(log, "virtual patch totals", siteFlag.vpatchStats, patches.Stats, vpatchStatsAttrs)
		defer stop()
	}
	stopStats := startFormatStats(log, formatInspector, *formatsStats)
	defer stopStats()
	alerts.start()
	health := &runtimeHealth{available: func() bool { return cs == nil || *csFailOpen || !cs.Stats().Stale }}
	log.Info("listening", slices.Concat([]any{"addr", ln.Addr().String(), "crs", crs.Version(), "mode", cfg.CRS.Mode, "paranoia", cfg.CRS.ParanoiaLevel,
		"inbound_threshold", cfg.CRS.InboundThreshold, "tls", *certFile != "", "confined", *confine, "formats_mode", effectiveFormatsMode, "request_encoding", *requestEncoding,
		"health_enabled", healthListener != nil, "alerts", *alertFlag.alerts, "auto_block", autoBlockMode(guard, autoBlock),
		"bots", botsMode(botsPolicy)}, ddosLogAttrs(*ddos, explicit), rateLimits)...)
	return serveRuntime(ctx, server, ln, healthListener, health, lifecycle, log)
}

// checkTimeouts checks -read-timeout and -write-timeout as the proxy would, and -upstream-timeout, naming the flags. The
// write timeout runs from the end of a request's headers, so it covers the time the body takes to arrive and must be
// longer than the read timeout, or an upload the read timeout allows could reach the application and its client never
// hear the outcome. The upstream timeout, given or its default of 30 seconds, must be shorter than the write timeout: an
// answer that comes later could no longer reach the client, and the request would keep its upstream place until then. A
// write timeout given at 30 seconds or less therefore needs a shorter upstream timeout given with it. A timeout under a second is
// refused: no client sends its headers, nor an application starts its answer, that fast everywhere. The read timeout is
// at most 23 hours, so that the write timeout, which must be longer, can be given within its own 24.
func checkTimeouts(read, write, upstream time.Duration) error {
	const shortest, longestRead, longest = time.Second, 23 * time.Hour, 24 * time.Hour
	const defaultRead, defaultUpstream, answerTime = 30 * time.Second, 30 * time.Second, 90 * time.Second
	out := func(d, most time.Duration) bool { return d != 0 && (d < shortest || d > most) }
	switch {
	case out(read, longestRead):
		return refuseFlag("read-timeout", errors.New("-read-timeout must be 0 (30s) or from 1s to 23h"))
	case out(write, longest):
		return refuseFlag("write-timeout", errors.New("-write-timeout must be 0 (-read-timeout plus 90s) or from 1s to 24h"))
	case out(upstream, longest):
		return refuseFlag("upstream-timeout", errors.New("-upstream-timeout must be 0 (30s) or from 1s to 24h"))
	}
	effectiveRead := cmp.Or(read, defaultRead)
	if write != 0 && write <= effectiveRead {
		return refuseFlag("write-timeout", fmt.Errorf("-write-timeout (%v) must be longer than -read-timeout (%v), as it includes the time the body takes to arrive",
			write, effectiveRead))
	}
	effectiveWrite := cmp.Or(write, effectiveRead+answerTime)
	switch {
	case upstream == 0 && defaultUpstream >= effectiveWrite: // only a write timeout given can be this short
		return refuseFlag("write-timeout", fmt.Errorf("-write-timeout (%v) must be longer than -upstream-timeout (%v, its default), or the client is cut off before the answer arrives; raise -write-timeout or give a shorter -upstream-timeout",
			effectiveWrite, defaultUpstream))
	case upstream >= effectiveWrite:
		return refuseFlag("upstream-timeout", fmt.Errorf("-upstream-timeout (%v) must be shorter than -write-timeout (%v), or the client is cut off before the answer arrives",
			upstream, effectiveWrite))
	}
	return nil
}

// systemdListener returns the listening socket systemd handed over as file descriptor 3 (see sd_listen_fds(3)).
func systemdListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return nil, errors.New("-systemd-socket was given, but systemd did not pass exactly one socket to this process")
	}
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	f := os.NewFile(3, "systemd-socket")
	defer f.Close() // FileListener duplicates it
	return net.FileListener(f)
}

// readTLSFile reads the visitor certificate or key. Links are followed (certbot's live/ directory is links into archive/),
// but only a regular file is read: it is opened without blocking, so a FIFO cannot hold start-up, and a key must not be
// readable by everyone or writable by its group (on Windows: by what its access list says, see privateFileAccess).
func readTLSFile(path string, limit int64, private bool) ([]byte, error) {
	// #nosec G304 -- The certificate and key paths are operator configuration, never request input.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	switch {
	case err != nil:
		return nil, err
	case !info.Mode().IsRegular():
		return nil, errors.New("not a regular file")
	case private && runtime.GOOS != "windows" && info.Mode().Perm()&0o027 != 0:
		return nil, fmt.Errorf("mode %04o: a private key must not be accessible to everyone or writable by its group", info.Mode().Perm())
	}
	if private { // on Windows the mode says nothing: the access list does
		if err := privateFileAccess(f); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return data, nil
}

// checkUploadDir is checked before the proxy confines itself to its upload directory: one that other users may write would
// let them reach what the proxy keeps there. (The engine has already checked that it is a directory it can write.)
func checkUploadDir(path string) error {
	info, err := os.Stat(path)
	switch {
	case err != nil:
		return err
	case !info.IsDir():
		return errors.New("not a directory")
	case runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("mode %04o: it must not be writable by its group or by everyone", info.Mode().Perm())
	}
	return nil
}

// parsePorts reads a comma-separated list of TCP ports.
func parsePorts(s string) ([]uint16, error) {
	ports := []uint16{}
	for _, part := range splitList(s) {
		n, err := strconv.ParseUint(part, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("%q is not a port", part)
		}
		ports = append(ports, uint16(n))
	}
	return ports, nil
}

// splitList reads a comma-separated list, ignoring empty items.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
