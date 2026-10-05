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
	allowUpgrade := flag.Bool("allow-upgrade", false, "let WebSocket upgrades through, uninspected")
	maxUpstream := flag.Int("max-upstream", 256, "requests allowed at the upstream at once")
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
	settings := crs.DefaultSettings()
	settings.Mode = crs.Mode(*mode)
	settings.ParanoiaLevel, settings.DetectionParanoiaLevel = *paranoia, *detection
	settings.InboundThreshold, settings.OutboundThreshold = *inbound, *outbound
	settings.RequestBodyLimit = *maxBody
	settings.InspectResponses = *responses
	if *methods != "" {
		for _, m := range strings.Split(*methods, ",") {
			settings.AllowedMethods = append(settings.AllowedMethods, strings.ToUpper(strings.TrimSpace(m)))
		}
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	edge, err := proxy.New(proxy.Config{
		Upstream: target, UpstreamHost: *upstreamHost, CRS: settings, TrustedProxies: trusted, AllowUpgrade: *allowUpgrade,
		MaxUpstreamInFlight: *maxUpstream, LogDetails: *details,
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
