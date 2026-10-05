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
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/proxy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "carnical:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:8080", "address to listen on")
	upstream := flag.String("upstream", "", "the website to protect, such as http://127.0.0.1:8081 (required)")
	upstreamHost := flag.String("upstream-host", "", "Host header to send to the upstream (default: the visitor's)")
	mode := flag.String("mode", "detect", "detect (log only), block, or off")
	paranoia := flag.Int("paranoia", 1, "CRS paranoia level 1 to 4: rules at this level and below block")
	detection := flag.Int("detection-paranoia", 0, "log what a higher level would find (0 = same as -paranoia)")
	inbound := flag.Int("inbound-threshold", 5, "anomaly score at which a request is blocked")
	outbound := flag.Int("outbound-threshold", 4, "anomaly score at which a response is blocked (with -inspect-responses)")
	maxBody := flag.Int64("max-body", 1<<20, "largest request body inspected, in bytes; a larger body is refused")
	responses := flag.Bool("inspect-responses", false, "also run the CRS response rules (buffers text, HTML and XML responses)")
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
	scriptNames := flag.Bool("allow-script-names", false, "allow uploads named like scripts (shell.php, .htaccess); refused by default")
	scriptContent := flag.Bool("allow-script-content", false, "allow uploads that contain a PHP, ASP or JSP opening tag; refused by default")
	keepBanners := flag.Bool("keep-banners", false, "keep X-Powered-By and Server headers from the application")
	keepCaching := flag.Bool("keep-caching", false, "do not add Cache-Control: private, no-store to responses that set a cookie or look like a stylesheet but are HTML")
	maxConns := flag.Int("max-conns-per-ip", 128, "connections one address may hold open (negative = no limit)")
	uploadDir := flag.String("upload-dir", "", "directory for the file parts of uploads while a request runs (default: the system temporary directory; give it a private one)")
	allowUpgrade := flag.Bool("allow-upgrade", false, "let WebSocket upgrades through, uninspected")
	maxUpstream := flag.Int("max-upstream", 256, "requests allowed at the upstream at once")
	evalBudget := flag.Duration("eval-budget", 2*time.Second, "most time each phase of rule evaluation may take for one request; a request over it is refused with 503")
	maxEval := flag.Int("max-evaluations", 0, "requests in rule evaluation at once (0 = the number of CPUs, negative = no limit)")
	maxForm := flag.Int64("max-form-body", 128<<10, "largest request body that is not a file upload, in bytes; uploads may be as large as -max-body")
	details := flag.Bool("log-details", false, "log the client address, URI and matched data of each rule match (personal data)")
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
	if *upstream == "" {
		return errors.New("-upstream is required")
	}
	if (*certFile == "") != (*keyFile == "") {
		return errors.New("give both -tls-cert and -tls-key, or neither")
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
	settings.UploadDir = *uploadDir
	if *methods != "" {
		for _, m := range strings.Split(*methods, ",") {
			settings.AllowedMethods = append(settings.AllowedMethods, strings.ToUpper(strings.TrimSpace(m)))
		}
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	edge, err := proxy.New(proxy.Config{
		Upstream: target, Origin: proxy.OriginPolicy{Allow: origin}, UpstreamHost: *upstreamHost, CRS: settings, TrustedProxies: trusted, AllowUpgrade: *allowUpgrade,
		MaxUpstreamInFlight: *maxUpstream, LogDetails: *details, EvalBudget: *evalBudget, MaxEvaluations: *maxEval, MaxFormBody: *maxForm,
		AllowedHosts: splitList(*hosts), Paths: proxy.PathPolicy{AllowEncodedSlash: *encodedSlash, AllowPathParams: *pathParams},
		DenyHeaders: splitList(*denyHeaders), WordPress: proxy.WordPressPolicy{Enabled: *wordpress, AllowXMLRPC: *xmlrpc, LoginPerMinute: *loginRate},
		Uploads:   proxy.UploadPolicy{AllowExecutableNames: *scriptNames, AllowScriptContent: *scriptContent},
		Responses: proxy.ResponsePolicy{KeepBanners: *keepBanners, KeepCaching: *keepCaching}, MaxConnsPerIP: *maxConns,
		OnMatch: func(m proxy.Match) {
			attrs := []any{"rule", m.RuleID, "severity", m.Severity, "msg", m.Message, "tx", m.TransactionID, "disruptive", m.Disruptive}
			if *details {
				attrs = append(attrs, "client", m.ClientIP, "uri", m.URI, "data", m.Data)
			}
			log.Warn("rule matched", attrs...)
		},
	})
	if err != nil {
		return err
	}
	defer edge.Close()

	server := edge.Server(*listen)
	if *certFile != "" {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", *listen, "upstream", target.String(), "crs", crs.Version(), "mode", *mode, "paranoia", *paranoia,
			"inbound_threshold", *inbound, "tls", *certFile != "")
		if *certFile != "" {
			done <- server.ListenAndServeTLS(*certFile, *keyFile)
		} else {
			done <- server.ListenAndServe()
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
