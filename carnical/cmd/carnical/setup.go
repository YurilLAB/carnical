// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YurilLAB/coraza/carnical/proxy"
)

type setupPrompt struct {
	input  *bufio.Scanner
	output io.Writer
}

// ask asks one question. fallback is the recommended answer: it is shown in brackets and taken when the answer is left
// blank. help is shown when the answer is "?".
func (p setupPrompt) ask(label, fallback, help string, validate func(string) error) (string, error) {
	prompt := label
	if fallback != "" {
		prompt += " [" + fallback + "]"
	}
	for {
		if _, err := fmt.Fprintf(p.output, "%s: ", prompt); err != nil {
			return "", err
		}
		if !p.input.Scan() {
			return "", errors.New("setup input ended; no configuration saved")
		}
		value := p.input.Text()
		if !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
			return "", errors.New("setup input must be UTF-8 without control characters")
		}
		value = strings.TrimSpace(value)
		if value == "?" {
			if help == "" {
				help = "No more help for this question; see carnical help setup."
			}
			if _, err := fmt.Fprintln(p.output, "  "+strings.ReplaceAll(help, "\n", "\n  ")); err != nil {
				return "", err
			}
			continue
		}
		if value == "" {
			value = fallback
		}
		if validate != nil {
			if err := validate(value); err != nil {
				if _, writeErr := fmt.Fprintln(p.output, "  "+err.Error()); writeErr != nil {
					return "", writeErr
				}
				continue
			}
		}
		return value, nil
	}
}

func setupChoice(options ...string) func(string) error {
	return func(value string) error {
		for _, option := range options {
			if value == option {
				return nil
			}
		}
		if len(options) == 2 {
			return fmt.Errorf("choose %s or %s", options[0], options[1])
		}
		return fmt.Errorf("choose %s or %s", strings.Join(options[:len(options)-1], ", "), options[len(options)-1])
	}
}

// choose asks for one of options, in any case, with recommended taken on a blank answer.
func (p setupPrompt) choose(label, recommended, help string, options ...string) (string, error) {
	value, err := p.ask(label+" ("+strings.Join(options, "/")+")", recommended, help, func(value string) error {
		return setupChoice(options...)(strings.ToLower(value))
	})
	return strings.ToLower(value), err
}

// yes asks a yes or no question. recommended is "y", "n", or "" for a question that must be answered.
func (p setupPrompt) yes(label, recommended, help string) (bool, error) {
	value, err := p.ask(label+" (y/n)", recommended, help, func(value string) error {
		return setupChoice("y", "yes", "n", "no")(strings.ToLower(value))
	})
	return strings.HasPrefix(strings.ToLower(value), "y"), err
}

// section starts a group of questions.
func (p setupPrompt) section(title string) error {
	_, err := fmt.Fprintf(p.output, "\n%s\n", title)
	return err
}

func requiredSetupValue(value string) error {
	if value == "" {
		return errors.New("a value is required")
	}
	return nil
}

func setupHost(value string) error {
	if ip, err := netip.ParseAddr(value); err == nil {
		if ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast() {
			return nil
		}
		return errors.New("use an unscoped website address")
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 {
		return errors.New("use a DNS name or IP address without a scheme, path or port")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("use valid DNS labels (international names need their ASCII form)")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return errors.New("use valid DNS labels (international names need their ASCII form)")
			}
		}
	}
	return nil
}

func setupOrigin(value string) (*url.URL, error) {
	if !strings.Contains(value, "://") {
		if ip, err := netip.ParseAddr(value); err == nil && ip.Is6() {
			value = "[" + value + "]"
		}
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Opaque != "" ||
		u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return nil, errors.New("use an HTTP(S) origin address without credentials, a path, query or fragment")
	}
	if err := setupHost(u.Hostname()); err != nil {
		return nil, err
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("origin port must be between 1 and 65535")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return nil, errors.New("origin port must be between 1 and 65535")
		}
	}
	u.Path = ""
	return u, nil
}

func setupListener(value string) error {
	address, err := netip.ParseAddrPort(value)
	if err != nil || address.Port() == 0 || address.Addr().Zone() != "" || address.Addr().IsMulticast() {
		return errors.New("use an IP address and port, such as 127.0.0.1:8080 or [::]:443")
	}
	return nil
}

// setupProtection holds setup's profile and security answers.
type setupProtection struct {
	site, level, mode, flood, autoBlock, login, alerts string
}

// loginLimit is the rate rule setup writes for a login page: as many POSTs a minute as -login-per-minute allows WordPress.
func loginLimit(path string) string { return "POST " + path + " 10/m" }

// flags are the settings the answers stand for. A level or site type adds only the flags that differ from the defaults.
func (s setupProtection) flags() map[string]any {
	values := map[string]any{"mode": s.mode, "formats-mode": "monitor", "ddos": s.flood, "auto-block": s.autoBlock, "alerts": s.alerts}
	if s.mode == "block" {
		values["formats-mode"] = "block"
	}
	switch s.site {
	case "wordpress":
		values["wordpress"] = true
	case "api":
		values["api-guard"] = "monitor"
	case "java":
		values["allow-path-params"] = true
	}
	switch s.level {
	case "relaxed":
		values["inbound-threshold"], values["outbound-threshold"] = 8, 8
	case "strict":
		values["paranoia"] = 2
	}
	if s.login != "" {
		values["limit"] = loginLimit(s.login)
	}
	return values
}

// askProtection asks for the site's profile and its basic security settings.
func askProtection(p setupPrompt) (setupProtection, error) {
	var s setupProtection
	var err error
	if err = p.section("3. Protection profile"); err != nil {
		return s, err
	}
	if s.site, err = p.choose("Site type", "general", "general: any site.\nwordpress: no scripts from uploads, xmlrpc.php off, logins limited.\napi: extra API method and body checks, reported only at first.\njava: lets ;jsessionid= through in paths, as Java applications need.",
		"general", "wordpress", "api", "java"); err != nil {
		return s, err
	}
	if s.level, err = p.choose("Attack detection level", "normal", "relaxed: fewest false alarms, misses more (CRS level 1, blocks at score 8).\nnormal: the OWASP Core Rule Set as published (level 1, score 5).\nstrict: finds more, and flags more ordinary traffic (level 2, score 5).",
		"relaxed", "normal", "strict"); err != nil {
		return s, err
	}
	if err = p.section("4. Security settings"); err != nil {
		return s, err
	}
	if s.mode, err = p.choose("When an attack is found", "detect", "detect: log it and let it through, to learn what the site needs first.\nblock: refuse it. Use block once a few days of alerts look right.",
		"detect", "block"); err != nil {
		return s, err
	}
	flood := "normal"
	if s.site == "api" {
		flood = "relaxed" // API clients send in bursts
	}
	if s.flood, err = p.choose("Flood protection", flood, "How fast one address may send before it is slowed down.\nrelaxed suits APIs and busy shared addresses; strict suits a small or often attacked site.",
		"relaxed", "normal", "strict"); err != nil {
		return s, err
	}
	if s.autoBlock, err = p.choose("Ban addresses that keep attacking", "monitor", "monitor: only log who would be banned.\non: ban for 10 minutes, longer each time (needs block).\nAn address many people share can be banned too, so start with monitor.",
		"off", "monitor", "on"); err != nil {
		return s, err
	}
	if s.site != "wordpress" { // WordPress has a login limit of its own
		if s.login, err = p.ask("Login page to protect from password guessing, such as /login (blank to skip)", "", "Each address may POST to it 10 times a minute.", func(value string) error {
			if value == "" {
				return nil
			}
			if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, " \t;") {
				return errors.New("use a path that starts with /, such as /login")
			}
			return (&limitFlag{}).Set(loginLimit(value))
		}); err != nil {
			return s, err
		}
	}
	s.alerts, err = p.choose("Intrusion alerts in the log", "on", "One line per attacker and attack, with exact totals; nothing of the request's content.",
		"on", "off")
	return s, err
}

// Validation runs the real startup checks in-process with a fresh FlagSet. No
// temporary plaintext configuration, child process arguments or listener is used.
func runSetup(input io.Reader, output io.Writer, validate func([]string) error) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 256), 4096)
	p := setupPrompt{input: scanner, output: output}
	if _, err := fmt.Fprintln(output, "Carnical setup\nPress Enter to take the recommended answer in [brackets], or type ? for help on a question.\nNothing is saved until the end. Give paths to certificate files; never paste passwords or keys."); err != nil {
		return err
	}
	if err := p.section("1. Your website"); err != nil {
		return err
	}
	values := map[string]any{}
	hosts, err := p.ask("Website names, separated by commas", "", "Every name visitors use, such as example.com,www.example.com.\nRequests for any other name are refused.", func(value string) error {
		for _, host := range strings.Split(value, ",") {
			if err := setupHost(strings.TrimSpace(host)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	names := splitList(hosts)
	values["hosts"] = strings.Join(names, ",")
	origin, err := p.ask("Origin server Carnical forwards to (URL or IP)", "", "The server that runs the site now, such as 10.0.0.5 or http://127.0.0.1:8081.\nWithout http:// or https://, HTTPS is used. It is stored encrypted.", func(value string) error {
		_, err := setupOrigin(value)
		return err
	})
	if err != nil {
		return err
	}
	target, err := setupOrigin(origin)
	if err != nil {
		return err
	}
	values["upstream"] = target.String()
	if ip, err := netip.ParseAddr(target.Hostname()); err == nil {
		ip = ip.Unmap()
		if err := (proxy.OriginPolicy{}).Check(ip); err != nil {
			allowed, err := p.yes("The origin is a private address. Allow Carnical to connect to it", "", "Carnical connects only to public addresses unless told otherwise,\nso a forged request cannot reach your internal network. Answer y if this is your server.")
			if err != nil {
				return err
			}
			if !allowed {
				return errors.New("origin is refused without an explicit allowance; setup cancelled")
			}
			values["origin-allow"] = netip.PrefixFrom(ip, ip.BitLen()).String()
		}
	} else {
		allow, err := p.ask("Private IPs or ranges the origin name resolves to (blank if public)", "", "Only needed when the origin's name points at a private address, such as 10.0.0.5.", func(value string) error {
			if _, err := proxy.ParseOriginAllow(value); err != nil {
				return errors.New("use specific origin IPs/CIDRs; an allow-all range is refused")
			}
			return nil
		})
		if err != nil {
			return err
		}
		if allow != "" {
			values["origin-allow"] = allow
		}
	}
	host, err := p.ask("Host name the origin expects", names[0], "The HTTP Host header sent to the origin.", setupHost)
	if err != nil {
		return err
	}
	values["upstream-host"] = host
	if err := p.section("2. Visitors"); err != nil {
		return err
	}
	visitorTLS, err := p.choose("How visitors reach Carnical", "https", "https: Carnical holds the site's certificate.\nproxy: a load balancer or CDN in front ends TLS.\nlocal: try Carnical out on this machine over plain HTTP.",
		"https", "proxy", "local")
	if err != nil {
		return err
	}
	listenDefault := "127.0.0.1:8080"
	if visitorTLS == "https" {
		listenDefault = "0.0.0.0:443"
	}
	listen, err := p.ask("Listen on (IP:port)", listenDefault, "0.0.0.0 listens on every IPv4 address, [::] on every address.", func(value string) error {
		if err := setupListener(value); err != nil {
			return err
		}
		addr, _ := netip.ParseAddrPort(value)
		ip := addr.Addr().Unmap()
		if visitorTLS == "local" && !ip.IsLoopback() {
			return errors.New("local HTTP requires a loopback listener")
		}
		if visitorTLS == "proxy" && !(ip.IsLoopback() || ip.IsPrivate()) {
			return errors.New("gateway HTTP requires a specific private or loopback listener; restrict access to the gateway")
		}
		return nil
	})
	if err != nil {
		return err
	}
	values["listen"] = listen
	if visitorTLS == "https" {
		for _, field := range []struct{ name, label string }{{"tls-cert", "Certificate file (PEM)"}, {"tls-key", "Private key file (PEM)"}} {
			value, err := p.ask(field.label, "", "The path of an existing file; it must cover every website name.", requiredSetupValue)
			if err != nil {
				return err
			}
			values[field.name], err = filepath.Abs(value)
			if err != nil {
				return err
			}
		}
		if err := checkSetupCertificate(values["tls-cert"].(string), values["tls-key"].(string), names); err != nil {
			return err
		}
	}
	if visitorTLS == "proxy" {
		trusted, err := p.ask("Load balancer or CDN addresses (IPs or ranges)", "", "Only these may tell Carnical the visitor's address (X-Forwarded-For).", func(value string) error {
			if value == "" {
				return errors.New("specify the gateway peers")
			}
			if _, err := proxy.ParseTrusted(value); err != nil {
				return errors.New("use specific trusted gateway IPs/CIDRs")
			}
			return nil
		})
		if err != nil {
			return err
		}
		values["trusted-proxies"] = trusted
	}
	if target.Scheme == "https" {
		ca, err := p.ask("Origin CA bundle file (blank for the system's)", "", "Only needed when the origin's certificate is from a private CA.", nil)
		if err != nil {
			return err
		}
		if ca != "" {
			values["origin-ca-file"], err = filepath.Abs(ca)
			if err != nil {
				return err
			}
		}
		mtls, err := p.yes("Authenticate Carnical to the origin with a client certificate", "n", "Lets the origin refuse anyone who goes around Carnical.")
		if err != nil {
			return err
		}
		if mtls {
			for _, field := range []struct{ name, label string }{{"origin-client-cert", "Client certificate file"}, {"origin-client-key", "Client private key file"}} {
				value, err := p.ask(field.label, "", "", requiredSetupValue)
				if err != nil {
					return err
				}
				values[field.name], err = filepath.Abs(value)
				if err != nil {
					return err
				}
			}
		}
	}
	protection, err := askProtection(p)
	if err != nil {
		return err
	}
	maps.Copy(values, protection.flags())
	if err := p.section("5. Check and save"); err != nil {
		return err
	}
	probe, err := p.yes("Check the connection to the origin now", "y", "Looks up the origin and connects to it (TLS included); sends no HTTP request.")
	if err != nil {
		return err
	}
	args := setupValidationArgs(values)
	if probe {
		args = append(args, "-check-origin")
	}
	if err := validate(args); err != nil {
		// Startup errors can include origin names or credential paths; do not
		// copy them to the wizard's transcript.
		return errors.New("setup validation failed; check origin, certificate files and settings before retrying")
	}
	login := "off"
	if protection.login != "" {
		login = protection.login + " 10/min"
	} else if protection.site == "wordpress" {
		login = "wp-login.php 10/min"
	}
	if _, err := fmt.Fprintf(output, "Settings checked:\n  site       %s on %s (%s)\n  profile    %s, %s detection, %s mode\n  security   flood %s, auto-block %s, login limit %s, alerts %s\nDNS and access to the origin still need to be arranged before visitors use Carnical.\n",
		values["hosts"], listen, visitorTLS, protection.site, protection.level, protection.mode, protection.flood, protection.autoBlock, login, protection.alerts); err != nil {
		return err
	}
	save, err := p.yes("Save these settings", "y", "")
	if err != nil {
		return err
	}
	if !save {
		_, err := fmt.Fprintln(output, "Nothing saved.")
		return err
	}
	return saveSetup(p, values)
}

// saveSetup saves the settings: the clear ones readable, the private ones encrypted with a new key in a separate file.
func saveSetup(p setupPrompt, values map[string]any) error {
	output := p.output
	savedPath, err := defaultSitePath()
	configDefault := savedPath
	if err != nil {
		savedPath, configDefault = "", "site.json"
	} else if _, err := os.Lstat(savedPath); !errors.Is(err, os.ErrNotExist) {
		configDefault = "site.json"
		if _, err := fmt.Fprintf(output, "A site is already saved at %s; it is never replaced.\n", savedPath); err != nil {
			return err
		}
	}
	configPath, err := p.ask("Save to", configDefault, "check and start find the site here without being told where it is.\nAn existing file is never replaced.", requiredSetupValue)
	if err != nil {
		return err
	}
	configPath, err = filepath.Abs(configPath)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(configPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("configuration destination exists or cannot be checked; choose a new file")
	}
	id, err := newSiteKeyID()
	if err != nil {
		return err
	}
	defaultKeyPath, err := siteKeyPath(id)
	if err != nil {
		defaultKeyPath = ""
		if _, err := fmt.Fprintln(output, "No account configuration directory is available. Choose a separate key file."); err != nil {
			return err
		}
	}
	keyPath, err := p.ask("Encryption key file", defaultKeyPath, "A separate file that unlocks the encrypted settings; the account that runs Carnical must read it.\nBack it up apart from the site file.", requiredSetupValue)
	if err != nil {
		return err
	}
	keyPath, err = filepath.Abs(keyPath)
	if err != nil {
		return err
	}
	if keyPath == configPath || runtime.GOOS == "windows" && strings.EqualFold(keyPath, configPath) {
		return errors.New("configuration and encryption key need separate files")
	}
	for _, made := range []struct{ path, saved string }{{keyPath, defaultKeyPath}, {configPath, savedPath}} {
		if made.path == made.saved {
			if err := os.MkdirAll(filepath.Dir(made.path), 0700); err != nil {
				return err
			}
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	defer clear(key)
	public, private := map[string]any{}, map[string]any{}
	for name, value := range values {
		if privateSiteFlag(name) {
			private[name] = value
		} else {
			public[name] = value
		}
	}
	sealed, err := sealSiteSettings(private, id, key)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(siteDocument{Version: 1, Flags: public, Private: sealed}, "", "  ")
	if err != nil || len(data)+1 > maxSiteConfigBytes {
		return errors.New("cannot encode site configuration within 64 KiB")
	}
	if err := writeNewSiteFile(keyPath, key); err != nil {
		return fmt.Errorf("cannot save protected encryption key: %w", err)
	}
	if err := writeNewSiteFile(configPath, append(data, '\n')); err != nil {
		return fmt.Errorf("cannot save configuration (key retained at %s): %w", keyPath, err)
	}
	site := ""
	if configPath != savedPath {
		site = " " + setupQuote(configPath)
	}
	if keyPath != defaultKeyPath {
		site += " -config-key-file " + setupQuote(keyPath)
	}
	_, err = fmt.Fprintf(output, "Saved. The origin details are encrypted; keep the key apart from backups of the site file.\nNext:\n  carnical check%s\n  carnical start%s\n", site, site)
	return err
}

func setupValidationArgs(values map[string]any) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	args := []string{"-check"}
	for _, name := range names {
		args = append(args, "-"+name+"="+fmt.Sprint(values[name]))
	}
	return args
}

func setupQuote(value string) string {
	if runtime.GOOS == "windows" {
		// PowerShell also ends single-quoted strings at typographic single quotes;
		// doubling any of them keeps it literal.
		var quoted strings.Builder
		quoted.WriteByte('\'')
		for _, r := range value {
			if r == '\'' || r >= 0x2018 && r <= 0x201b {
				quoted.WriteRune(r)
			}
			quoted.WriteRune(r)
		}
		quoted.WriteByte('\'')
		return quoted.String()
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func checkSetupCertificate(certPath, keyPath string, names []string) error {
	// Read as the proxy will read them at start-up, so setup does not accept a pair that start-up refuses.
	certPEM, err := readTLSFile(certPath, 1<<20, false)
	if err != nil {
		return fmt.Errorf("cannot read the visitor certificate: %w", err)
	}
	keyPEM, err := readTLSFile(keyPath, 64<<10, true)
	if err != nil {
		return fmt.Errorf("cannot read the visitor private key: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.New("cannot load the visitor certificate and matching private key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return errors.New("visitor certificate is invalid or outside its validity period")
	}
	for _, name := range names {
		if err := leaf.VerifyHostname(strings.TrimSuffix(name, ".")); err != nil {
			return errors.New("visitor certificate must cover every website name")
		}
	}
	return nil
}
