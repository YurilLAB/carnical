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

func (p setupPrompt) ask(label, fallback string, validate func(string) error) (string, error) {
	for {
		if _, err := fmt.Fprintf(p.output, "%s [%s]: ", label, fallback); err != nil {
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
		if value == "" {
			value = fallback
		}
		if validate != nil {
			if err := validate(value); err != nil {
				if _, writeErr := fmt.Fprintln(p.output, err); writeErr != nil {
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
		return fmt.Errorf("choose %s", strings.Join(options, " or "))
	}
}

func (p setupPrompt) yes(label string) (bool, error) {
	value, err := p.ask(label+" (y/n)", "n", func(value string) error {
		return setupChoice("y", "yes", "n", "no")(strings.ToLower(value))
	})
	return strings.HasPrefix(strings.ToLower(value), "y"), err
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

// Validation runs the real startup checks in-process with a fresh FlagSet. No
// temporary plaintext configuration, child process arguments or listener is used.
func runSetup(input io.Reader, output io.Writer, validate func([]string) error) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 256), 4096)
	p := setupPrompt{input: scanner, output: output}
	if _, err := fmt.Fprintln(output, "Carnical setup. Private origin details and file paths will be encrypted when saved.\nUse existing certificates and credential files; do not paste passwords or keys."); err != nil {
		return err
	}
	values := map[string]any{}
	hosts, err := p.ask("Website names, separated by commas", "", func(value string) error {
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
	origin, err := p.ask("Origin URL or IP (HTTPS assumed without a scheme)", "", func(value string) error {
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
	allowDefault := ""
	if ip, err := netip.ParseAddr(target.Hostname()); err == nil {
		ip = ip.Unmap()
		if err := (proxy.OriginPolicy{}).Check(ip); err != nil {
			allowed, err := p.yes("Allow this exact local/private origin address")
			if err != nil {
				return err
			}
			if !allowed {
				return errors.New("origin is refused without an explicit allowance; setup cancelled")
			}
			allowDefault = netip.PrefixFrom(ip, ip.BitLen()).String()
		}
	}
	allow, err := p.ask("Private origin IPs/CIDRs (blank for public origins)", allowDefault, func(value string) error {
		_, err := proxy.ParseOriginAllow(value)
		if err != nil {
			return errors.New("use specific origin IPs/CIDRs; an allow-all range is refused")
		}
		return nil
	})
	if err != nil {
		return err
	}
	values["origin-allow"] = allow
	host, err := p.ask("HTTP Host required by the origin", names[0], setupHost)
	if err != nil {
		return err
	}
	values["upstream-host"] = host
	visitorTLS, err := p.ask("Visitor connection: https, proxy (existing TLS gateway), or local (loopback test)", "https", setupChoice("https", "proxy", "local"))
	if err != nil {
		return err
	}
	listenDefault := "127.0.0.1:8080"
	if visitorTLS == "https" {
		listenDefault = "0.0.0.0:443"
	}
	listen, err := p.ask("Carnical listening IP and port", listenDefault, func(value string) error {
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
		for _, field := range []struct{ name, label string }{{"tls-cert", "Visitor PEM certificate file"}, {"tls-key", "Visitor private key file"}} {
			value, err := p.ask(field.label, "", requiredSetupValue)
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
		trusted, err := p.ask("Trusted TLS gateway IPs/CIDRs (only actual forwarding peers)", "", func(value string) error {
			if value == "" {
				return errors.New("specify the gateway peers")
			}
			_, err := proxy.ParseTrusted(value)
			if err != nil {
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
		ca, err := p.ask("Origin CA bundle file (blank for system trust)", "", nil)
		if err != nil {
			return err
		}
		if ca != "" {
			values["origin-ca-file"], err = filepath.Abs(ca)
			if err != nil {
				return err
			}
		}
		mtls, err := p.yes("Use a client certificate to authenticate Carnical to the origin")
		if err != nil {
			return err
		}
		if mtls {
			for _, field := range []struct{ name, label string }{{"origin-client-cert", "Origin client certificate file"}, {"origin-client-key", "Origin client private key file"}} {
				value, err := p.ask(field.label, "", requiredSetupValue)
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
	mode, err := p.ask("Content protection: detect (review traffic) or block", "detect", setupChoice("detect", "block"))
	if err != nil {
		return err
	}
	values["mode"], values["formats-mode"] = mode, "monitor"
	if mode == "block" {
		values["formats-mode"] = "block"
	}
	wordpress, err := p.yes("Enable WordPress protections")
	if err != nil {
		return err
	}
	values["wordpress"] = wordpress
	probe, err := p.yes("Check origin DNS/TCP/TLS now (no HTTP request)")
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
	if _, err := fmt.Fprintf(output, "Validated %s on %s (%s mode).\nDNS and origin access rules still need to be arranged before cutover.\n", values["hosts"], listen, mode); err != nil {
		return err
	}
	save, err := p.yes("Save these settings to a Carnical configuration file")
	if err != nil {
		return err
	}
	if !save {
		_, err := fmt.Fprintln(output, "Settings checked. No configuration or encryption key saved.")
		return err
	}
	configPath, err := p.ask("Configuration file (existing files will not be replaced)", "site.json", requiredSetupValue)
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
	keyPath, err := p.ask("Separate encryption key file (service account must be able to read it)", defaultKeyPath, requiredSetupValue)
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
	if keyPath == defaultKeyPath {
		if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
			return err
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
	keyArg := ""
	if keyPath != defaultKeyPath {
		keyArg = " -config-key-file " + setupQuote(keyPath)
	}
	_, err = fmt.Fprintf(output, "Saved configuration with encrypted private settings. Keep the key separate from config backups.\nCheck: carnical -config %s%s -check\nStart: carnical -config %s%s\n", setupQuote(configPath), keyArg, setupQuote(configPath), keyArg)
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
