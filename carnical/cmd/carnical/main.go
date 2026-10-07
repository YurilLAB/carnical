// SPDX-License-Identifier: Apache-2.0

// Command carnical puts the OWASP Core Rule Set, run by Coraza, in front of one website.
//
//	carnical -upstream http://127.0.0.1:8081 -listen :8080            (logs what the rules find, blocks nothing)
//	carnical -upstream http://127.0.0.1:8081 -mode block              (blocks at the anomaly threshold)
//
// Start in detect mode, read the log for a few days, add exclusions for the false positives, then switch to block.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/YurilLAB/coraza/carnical/crowdsec"
	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/inspect"
	"github.com/YurilLAB/coraza/carnical/proxy"
	"github.com/YurilLAB/coraza/carnical/sandbox"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "carnical:", err)
		os.Exit(1)
	}
}

func run() error {
	configFile := flag.String("config", "", "operator site JSON configuration (maximum 64 KiB; explicit CLI flags override it)")
	check := flag.Bool("check", false, "validate settings and local files, then exit without listening or applying confinement")
	checkOrigin := flag.Bool("check-origin", false, "with -check, also verify origin DNS, TCP and HTTPS certificate within 10s (sends no HTTP request)")
	listen := flag.String("listen", "127.0.0.1:8080", "address to listen on")
	upstream := flag.String("upstream", "", "the website to protect, such as http://127.0.0.1:8081 (required)")
	upstreamHost := flag.String("upstream-host", "", "Host header to send to the upstream (default: the visitor's)")
	mode := flag.String("mode", "detect", "detect (log only), block, or off")
	paranoia := flag.Int("paranoia", 1, "CRS paranoia level 1 to 4: rules at this level and below block")
	detection := flag.Int("detection-paranoia", 0, "log what a higher level would find (0 = same as -paranoia)")
	inbound := flag.Int("inbound-threshold", 5, "anomaly score at which a request is blocked")
	outbound := flag.Int("outbound-threshold", 4, "anomaly score at which a response is blocked (with -inspect-responses)")
	maxBody := flag.Int64("max-body", 1<<20, "largest request body inspected, in bytes; a larger body is refused")
	formatsMode := flag.String("formats-mode", "monitor", "request formats: monitor (default), block, or off; independent of -mode and overrides policy monitor")
	formatsPolicy := flag.String("formats-policy", "", "JSON request-format policy file (maximum 1 MiB; default: built-in format limits)")
	formatsStats := flag.Duration("formats-stats-interval", time.Minute, "log changed per-rule blocked/monitored format totals (0 = off; 100ms to 24h)")
	requestEncoding := flag.Bool("allow-request-encoding", false, "allow one bounded gzip or deflate layer through the format inspector (requires formats enabled)")
	responses := flag.Bool("inspect-responses", false, "also run the CRS response rules (buffers text, HTML and XML responses)")
	localRules := flag.Bool("local-rules", true, "run Carnical supplemental injection rules at PL1, with the selected CRS mode and threshold")
	apiSpec := flag.String("api-spec", "", "local OpenAPI JSON/YAML contract; scalar/array parameters and JSON bodies (no fetching or learning)")
	apiSpecMode := flag.String("api-spec-mode", "block", "OpenAPI contract action: block or monitor (block requires formats block)")
	methods := flag.String("allowed-methods", "", "comma-separated HTTP methods to allow (default: the CRS list GET HEAD POST OPTIONS)")
	trustedList := flag.String("trusted-proxies", "", "comma-separated addresses or ranges that may supply X-Forwarded-For")
	originAllow := flag.String("origin-allow", "", "comma-separated addresses or ranges the upstream may be at even though they are not public (default: public addresses only)")
	hosts := flag.String("hosts", "", "comma-separated names this site answers to; any other Host gets 421 (default: any)")
	encodedSlash := flag.Bool("allow-encoded-slash", false, "allow %2f and %5c in request paths (refused by default)")
	pathParams := flag.Bool("allow-path-params", false, "allow a semicolon in request paths, as Java's ;jsessionid= needs (refused by default)")
	denyHeaders := flag.String("deny-headers", "", "comma-separated headers whose presence refuses the request, such as Next-Action on a site with no server actions")
	wordpress := flag.Bool("wordpress", false, "protect a WordPress site: no scripts from upload and cache directories, xmlrpc.php off, login attempts limited")
	xmlrpc := flag.Bool("allow-xmlrpc", false, "with -wordpress, leave xmlrpc.php reachable")
	loginRate := flag.Int("login-per-minute", 10, "with -wordpress, POSTs to wp-login.php one address may make a minute")
	apiRate := flag.Int("api-per-minute", 0, "shared API requests per verified client address in a sliding minute (0 = disabled; maximum 100000)")
	apiPaths := flag.String("api-rate-paths", "/api,/graphql", "plain path prefixes sharing -api-per-minute, matched by path segment; / covers every route")
	scriptNames := flag.Bool("allow-script-names", false, "allow uploads named like scripts (shell.php, .htaccess); refused by default")
	scriptContent := flag.Bool("allow-script-content", false, "allow uploads that contain a PHP, ASP or JSP opening tag; refused by default")
	keepBanners := flag.Bool("keep-banners", false, "keep X-Powered-By and Server headers from the application")
	keepCaching := flag.Bool("keep-caching", false, "do not add Cache-Control: private, no-store to responses that set a cookie or look like a stylesheet but are HTML")
	ddosMode := flag.String("ddos", "on", "flood protection: on (detect attacks, including ones spread over many addresses, and mitigate them), monitor (detect and log; baseline connection/request limits still apply), or off")
	ddosRate := flag.Float64("ddos-rate", 50, "the least requests a second one address may make, at all times; raised automatically to follow the busiest addresses on a busy site")
	ddosBurst := flag.Float64("ddos-burst", 200, "burst of requests one address may make at once")
	ddosConns := flag.Int("ddos-max-conns", 20000, "the least connections held open at once, raised with the site's average; a fifth are kept for clients that used the site before")
	ddosChallenge := flag.Bool("ddos-challenge", true, "during an attack, ask unknown browsers to pass a short JavaScript check instead of refusing them")
	ddosBaseline := flag.Float64("ddos-baseline-rate", 0, "the site's usual requests a second, to start from instead of learning it (so a restart during an attack is not fooled)")
	ddosRanges := flag.String("ddos-ranges", "", "address-range table (ip2asn TSV) naming the countries and networks an attack comes from, in the attack logs")
	csAPI := flag.String("crowdsec-api", "", "CrowdSec LAPI HTTP(S) origin or absolute Unix socket path (empty = disabled; HTTP requires loopback)")
	csKey := flag.String("crowdsec-key-file", "", "private file containing a dedicated CrowdSec bouncer key")
	csCA := flag.String("crowdsec-ca-file", "", "PEM CA bundle for CrowdSec HTTPS (default: system roots; verification always enabled)")
	csInterval := flag.Duration("crowdsec-poll", 10*time.Second, "CrowdSec update interval, 1s to 1h")
	csTimeout := flag.Duration("crowdsec-timeout", 5*time.Second, "CrowdSec API timeout, 100ms to 30s")
	csStale := flag.Duration("crowdsec-max-stale", 2*time.Minute, "CrowdSec cache freshness limit; at least poll + timeout, at most 24h")
	csFailOpen := flag.Bool("crowdsec-fail-open", false, "allow unlisted visitors when CrowdSec cache is stale; unexpired bans still block")
	csLimit := flag.Int("crowdsec-max-decisions", 200000, "maximum stored CrowdSec bans and decisions in a response, 1 to 1000000")
	csOrigins := flag.String("crowdsec-origins", "", "optional comma-separated CrowdSec decision origins (empty = all)")
	maxConns := flag.Int("max-conns-per-ip", 128, "connections one address may hold open (negative = no limit)")
	uploadDir := flag.String("upload-dir", "", "directory for the file parts of uploads while a request runs (default: the system temporary directory; give it a private one)")
	fromSystemd := flag.Bool("systemd-socket", false, "use the listening socket systemd passes in (socket activation), so the proxy needs no privilege to use port 443")
	confine := flag.Bool("confine", false, "after start-up, confine the process: no new programs, no ptrace, no other files, no other ports (Linux; build with CGO_ENABLED=0)")
	confineConnect := flag.String("confine-connect", "80,443,53", "with -confine, the TCP ports the proxy may connect to: the ports of the origins, and 53 for DNS")
	confineRead := flag.String("confine-read", "", "with -confine, extra files and directories the proxy may read (for example a certificate directory it reloads from)")
	confineBestEffort := flag.Bool("confine-best-effort", false, "with -confine, carry on with the layers the kernel supports instead of refusing to start")
	allowUpgrade := flag.Bool("allow-upgrade", false, "let WebSocket upgrades through, uninspected")
	maxUpstream := flag.Int("max-upstream", 256, "requests allowed at the upstream at once")
	evalBudget := flag.Duration("eval-budget", 2*time.Second, "most time each phase of rule evaluation may take for one request; a request over it is refused with 503")
	maxEval := flag.Int("max-evaluations", 0, "requests in rule evaluation at once (0 = the number of CPUs, negative = no limit)")
	maxForm := flag.Int64("max-form-body", 128<<10, "largest request body that is not a file upload, in bytes; uploads may be as large as -max-body")
	details := flag.Bool("log-details", false, "log client address, URI, matched data and macro-expanded messages (may contain credentials)")
	certFile := flag.String("tls-cert", "", "TLS certificate file")
	keyFile := flag.String("tls-key", "", "TLS key file")
	showVersion := flag.Bool("version", false, "print the CRS version that is embedded and exit")
	flag.Parse()

	if *showVersion {
		info, err := crs.Info()
		if err != nil {
			return err
		}
		fmt.Printf("OWASP CRS %s (archive sha256 %s, signed by %s)\n", info.Version, info.ArchiveSHA256, info.SignerFingerprint)
		return nil
	}
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments; use named flags")
	}
	if *configFile != "" {
		if err := loadSiteConfig(*configFile, flag.CommandLine); err != nil {
			return err
		}
	}
	if *checkOrigin && !*check {
		return errors.New("-check-origin requires -check")
	}
	if *upstream == "" {
		return errors.New("-upstream is required")
	}
	if (*certFile == "") != (*keyFile == "") {
		return errors.New("give both -tls-cert and -tls-key, or neither")
	}
	if *formatsStats != 0 && (*formatsStats < 100*time.Millisecond || *formatsStats > 24*time.Hour) {
		return errors.New("-formats-stats-interval must be 0 or between 100ms and 24h")
	}
	formatInspector, err := configureFormats(*formatsMode, *formatsPolicy, *requestEncoding)
	if err != nil {
		return err
	}
	var inspectors []inspect.Inspector
	if formatInspector != nil {
		inspectors = append(inspectors, formatInspector)
	}
	apiInspector, apiReport, err := configureAPI(*apiSpec, *apiSpecMode, *formatsMode)
	if err != nil {
		return err
	}
	if apiInspector != nil {
		inspectors = append(inspectors, apiInspector)
	}
	target, err := url.Parse(*upstream)
	if err != nil {
		return fmt.Errorf("-upstream: %w", err)
	}
	trusted, err := proxy.ParseTrusted(*trustedList)
	if err != nil {
		return err
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
	settings.UploadDir = *uploadDir
	if *methods != "" {
		for _, m := range strings.Split(*methods, ",") {
			settings.AllowedMethods = append(settings.AllowedMethods, strings.ToUpper(strings.TrimSpace(m)))
		}
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cs, err := configureCrowdSec(crowdSecFlags{api: *csAPI, keyFile: *csKey, caFile: *csCA, origins: *csOrigins,
		interval: *csInterval, timeout: *csTimeout, maxStale: *csStale, failOpen: *csFailOpen, maxDecisions: *csLimit})
	if err != nil {
		return err
	}
	if cs != nil {
		defer cs.Close()
		if !*check {
			if err := cs.Sync(context.Background()); err != nil {
				return err
			} // authentication and complete snapshot required at startup
			log.Info("CrowdSec connected", "entries", cs.Stats().Entries, "skipped", cs.Stats().Skipped, "fail_open", *csFailOpen)
		}
	}
	if apiInspector != nil {
		log.Info("API contract loaded", "mode", *apiSpecMode, "sha256", apiReport.Hash, "routes", apiReport.Routes,
			"warnings", apiReport.Warnings, "warnings_dropped", apiReport.WarningsDropped)
	}
	guard, err := configureShield(log, shieldFlags{mode: *ddosMode, rate: *ddosRate, burst: *ddosBurst, maxConns: *ddosConns,
		challenge: *ddosChallenge, baseline: *ddosBaseline, ranges: *ddosRanges}, trusted)
	if err != nil {
		return err
	}
	if guard != nil {
		defer guard.Close()
	}
	edge, err := proxy.New(proxy.Config{
		Upstream: target, Origin: proxy.OriginPolicy{Allow: origin}, UpstreamHost: *upstreamHost, CRS: settings, TrustedProxies: trusted, AllowUpgrade: *allowUpgrade,
		MaxUpstreamInFlight: *maxUpstream, LogDetails: *details, EvalBudget: *evalBudget, MaxEvaluations: *maxEval, MaxFormBody: *maxForm,
		AllowedHosts: splitList(*hosts), Paths: proxy.PathPolicy{AllowEncodedSlash: *encodedSlash, AllowPathParams: *pathParams},
		DenyHeaders: splitList(*denyHeaders), WordPress: proxy.WordPressPolicy{Enabled: *wordpress, AllowXMLRPC: *xmlrpc, LoginPerMinute: *loginRate},
		APIRate:   proxy.APIRatePolicy{PerMinute: *apiRate, Paths: splitList(*apiPaths)},
		Uploads:   proxy.UploadPolicy{AllowExecutableNames: *scriptNames, AllowScriptContent: *scriptContent},
		Responses: proxy.ResponsePolicy{KeepBanners: *keepBanners, KeepCaching: *keepCaching}, MaxConnsPerIP: *maxConns,
		Inspectors: inspectors, AllowRequestEncoding: *requestEncoding, Shield: guard, CrowdSec: cs,
		OnMatch: func(m proxy.Match) {
			attrs := []any{"rule", m.RuleID, "severity", m.Severity, "rule_msg", m.Message, "tx", m.TransactionID, "disruptive", m.Disruptive}
			if *details {
				attrs = append(attrs, "client", m.ClientIP, "uri", m.URI, "data", m.Data, "expanded_msg", m.ExpandedMessage)
			}
			log.Warn("rule matched", attrs...)
		},
	})
	if err != nil {
		return err
	}
	defer edge.Close()

	server := edge.Server(*listen)
	// Everything the proxy needs from the outside is opened before it is confined: the certificate and key are read,
	// and the listening socket exists. After that it needs no more files, and no new ports to listen on.
	if *certFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return fmt.Errorf("the certificate: %w", err)
		}
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	}
	var confinement sandbox.Policy
	if *confine {
		ports, err := parsePorts(*confineConnect)
		if err != nil {
			return fmt.Errorf("-confine-connect: %w", err)
		}
		if cs != nil && cs.ConnectPort() != 0 {
			allowed := false
			for _, p := range ports {
				if p == cs.ConnectPort() {
					allowed = true
				}
			}
			if !allowed {
				return errors.New("CrowdSec API TCP port must be listed in -confine-connect")
			}
		}
		confinement = sandbox.Policy{ReadOnly: splitList(*confineRead), ConnectTCP: ports, BindTCP: []uint16{}, Require: !*confineBestEffort}
		if *uploadDir != "" {
			confinement.ReadWrite = []string{*uploadDir}
		}
	}
	if err := checkDeployment(*listen, target, proxy.OriginPolicy{Allow: origin}, *fromSystemd, *checkOrigin); err != nil {
		return err
	}
	if *check {
		log.Info("configuration checked", "mode", *mode, "formats_mode", *formatsMode, "origin_checked", *checkOrigin, "tls", *certFile != "", "sandbox_applied", false)
		return nil
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cs != nil {
		pollCtx, cancelPoll := context.WithCancel(ctx)
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
	stopStats := startFormatStats(log, formatInspector, *formatsStats)
	defer stopStats()
	done := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", *listen, "upstream", target.String(), "crs", crs.Version(), "mode", *mode, "paranoia", *paranoia,
			"inbound_threshold", *inbound, "tls", *certFile != "", "confined", *confine, "ddos", *ddosMode, "formats_mode", *formatsMode, "request_encoding", *requestEncoding)
		if *certFile != "" {
			done <- server.ServeTLS(ln, "", "")
		} else {
			done <- server.Serve(ln)
		}
	}()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
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
