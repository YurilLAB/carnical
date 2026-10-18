// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// runCommand runs one of the short commands, or the proxy with flags as before. The commands only choose flags: what
// they run is what the same flags run, so a saved site and its flags behave alike whichever way the proxy is started.
func runCommand(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 {
		return writeHelp(output, "")
	}
	switch args[0] {
	case "setup":
		if len(args) != 1 {
			return errors.New("use carnical setup without extra arguments")
		}
		// The check's log line would only interrupt the questions: setup says what it checked.
		return runSetup(input, output, func(args []string) error { return runArgsTo(io.Discard, io.Discard, args) })
	case "check", "start":
		run, err := commandArgs(args[0], args[1:])
		if err != nil {
			return err
		}
		return runArgs(run)
	case "help", "-help", "--help", "-h":
		switch len(args) {
		case 1:
			return writeHelp(output, "")
		case 2:
			if args[1] == "flags" {
				return runArgsTo(output, os.Stderr, []string{"-h"})
			}
			return writeHelp(output, args[1])
		}
		return errors.New("use carnical help [topic]")
	case "version":
		if len(args) != 1 {
			return errors.New("use carnical version without extra arguments")
		}
		return runArgs([]string{"-version"})
	}
	if !strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("unknown command %q; run carnical help", args[0])
	}
	return runArgs(args)
}

// commandArgs turns check or start, an optional site file and flags into the proxy's flags. Without a file, or a -config
// among the flags, the site setup saved in its default place is used.
func commandArgs(command string, args []string) ([]string, error) {
	file := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		file, args = args[0], args[1:]
	}
	named := false
	for _, arg := range args {
		if arg == "--" {
			break
		}
		name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		named = named || strings.HasPrefix(arg, "-") && name == "config"
	}
	if file != "" && named {
		return nil, fmt.Errorf("give the site file once: carnical %s FILE, or -config FILE", command)
	}
	run := []string{}
	if !named {
		if file == "" {
			saved, err := defaultSitePath()
			if err != nil {
				return nil, fmt.Errorf("%w; name the site file: carnical %s FILE", err, command)
			}
			if _, err := os.Lstat(saved); err != nil {
				return nil, fmt.Errorf("no saved site at %s; run carnical setup first, or name the file: carnical %s FILE", saved, command)
			}
			file = saved
		}
		run = append(run, "-config", file)
	}
	if command == "check" {
		run = append(run, "-check", "-check-origin")
	}
	return append(run, args...), nil
}

// defaultSitePath is where setup saves a site unless told otherwise, and where check and start look for it.
func defaultSitePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", errors.New("this account has no configuration directory")
	}
	return filepath.Join(dir, "carnical", "site.json"), nil
}

// helpTopics are the topics of carnical help, besides flags, which lists every flag.
var helpTopics = map[string]string{
	"": `Carnical is a web application firewall (WAF) that sits in front of your website.

Commands:
  carnical setup          set up a site step by step (start here)
  carnical check [FILE]   check the saved settings and the connection to your site
  carnical start [FILE]   start the WAF with the saved settings
  carnical help [TOPIC]   this help; topics: setup, profiles, security, bots, flags
  carnical version        show the version of the rules

Setup saves the site where check and start find it, so neither needs a file.
Flags after check or start change a setting for that run only:
  carnical start -mode block

Common flags:
  -mode detect|block              only log attacks, or block them
  -ddos relaxed|normal|strict     flood protection strength
  -auto-block off|monitor|on      ban addresses that keep attacking
  -bots scanner,fake,...          kinds of bot to block (help bots)
  -wordpress                      WordPress protections
  -log-details                    log addresses and matched data (sensitive)

Guides: docs/setup.md, and docs/README.md for the rest.
`,
	"setup": `carnical setup asks about your site, then checks and saves the answers.

Press Enter to take the recommended answer shown in [brackets], or type ? for help
on a question. Nothing is saved until the last questions, and an existing file is
never replaced. It asks, in order:

  1. Your website: its names and the origin server Carnical forwards to.
  2. Visitors: whether Carnical holds the certificate (https), sits behind a load
     balancer or CDN (proxy), or is tried out on this machine (local).
  3. Profile: what the site is, and how strict attack detection is.
  4. Security: block or only log, flood protection, auto-block, a login limit, bots
     and alerts.
  5. Check and save: the settings are checked as start-up checks them, then saved
     with the origin details encrypted, and its key kept apart.

Afterwards run: carnical check, then carnical start.
`,
	"profiles": `Setup offers a site type and a detection level. Both only choose flags.

Site types:
  general     any site (no extra flags)
  wordpress   -wordpress: no scripts from uploads, xmlrpc.php off, logins limited
  api         -api-guard monitor: API method and body checks, reported only;
              flood protection relaxed is recommended for busy API clients
  java        -allow-path-params: lets ;jsessionid= through, as Java needs

Detection levels (OWASP CRS paranoia level and blocking score):
  relaxed     level 1, blocks at 8: fewest false alarms, misses more
  normal      level 1, blocks at 5: the CRS as published (recommended)
  strict      level 2, blocks at 5: finds more, flags more ordinary traffic
`,
	"security": `The security settings setup asks for:

  mode         detect logs what would be blocked; block refuses it. Start with
               detect, read the alerts for a few days, then use block.
  flood        relaxed, normal or strict limits on how fast one address may send.
  auto-block   bans an address whose requests keep being blocked as attacks;
               monitor only logs who would be banned. Needs mode block to ban.
  login limit  POSTs one address may make to your login page a minute.
  bots         which bots to block: none, fake (recommended), ai or strict.
               Scanners are refused in every mode unless none. See help bots.
  alerts       one log line per attacker and attack, with exact totals.

Proxy safety checks and flood protection enforce in every mode.
`,
	"bots": `Carnical reads what kind of client sent each request from its user agent,
headers and, when it holds the certificate, its TLS handshake. It names the kind in
every alert ("client") and counts blocked requests by it: the "intrusion totals"
line has blocked_bots, blocked_people, how many addresses each came from, and
blocked_by_client.

Kinds -bots can refuse (-bots-monitor only logs them as would-be refusals):
  scanner   vulnerability scanners, attack and brute-force tools, botnets and
            internet-wide scanners: sqlmap, Nuclei, Hydra, zgrab, ZmEu, ...
            Refused by default, in every mode; their refusals count to auto-block.
  fake      claims to be Google, Bing, Apple, Yandex, Baidu, Petal, Seznam,
            Naver or Amazon, from an address that engine's DNS does not confirm
            (-bots-trust-networks also trusts the networks of crawlers verified)
  ai        AI crawlers and fetchers: GPTBot, ClaudeBot, CCBot, Bytespider, ...
  seo       SEO, marketing, archive and data-mining crawlers, address harvesters
            and site copiers: AhrefsBot, SemrushBot, HTTrack, ...
  tool      HTTP libraries and scripts: curl, python-requests, Go, Scrapy, ...
  headless  browsers driven by programs: HeadlessChrome, PhantomJS, ...
  disguised a program sending a browser's user agent: headers, client hints or
            the TLS handshake that do not match the browser it names
  bot       other bots: no user agent, a contact URL, or a crawler's words

Never refused for being a bot: people, search engines that are what they claim,
link previews (Slack, WhatsApp, ...) and uptime checks. -bots-exempt names
addresses never refused, such as your own scanners; -bots none refuses none.

Setup's answers: none; fake = fake,scanner; ai = also ai,seo; strict = every kind.
Use strict only for a site browsers alone use: apps and API clients are tools,
and a browser behind antivirus or a company proxy that reads HTTPS can look
disguised.
`,
}

// writeHelp writes the help of one topic.
func writeHelp(output io.Writer, topic string) error {
	text, ok := helpTopics[topic]
	if !ok {
		return fmt.Errorf("no help on %q; topics: setup, profiles, security, bots, flags", topic)
	}
	_, err := io.WriteString(output, text)
	return err
}
