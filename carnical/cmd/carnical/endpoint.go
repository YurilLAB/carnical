// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/YurilLAB/coraza/carnical/alert"
	"github.com/YurilLAB/coraza/carnical/notify"
	"github.com/YurilLAB/coraza/carnical/proxy"
	"github.com/YurilLAB/coraza/carnical/shield"
)

// endpointFlags are the flags of the alert endpoint: an HTTPS URL that is told of attacks as they happen.
type endpointFlags struct {
	url, secretFile, allow, caFile *string
}

func declareEndpointFlags(flags *flag.FlagSet) endpointFlags {
	return endpointFlags{
		url:        flags.String("alert-endpoint", "", "HTTPS URL that is sent signed JSON messages: the intrusion alerts the log writes (batched, a message a second) and when an attack starts, goes on (at most once a minute) and ends (default: none)"),
		secretFile: flags.String("alert-endpoint-secret-file", "", "file whose first line is the secret that signs the alert endpoint's messages, 32 to 1024 printable characters (not accessible to everyone or writable by its group)"),
		allow:      flags.String("alert-endpoint-allow", "", "comma-separated addresses or ranges the alert endpoint may be at even though they are not public (default: public addresses only)"),
		caFile:     flags.String("alert-endpoint-ca-file", "", "CA bundle that verifies the alert endpoint's certificate (default: the system's)"),
	}
}

// endpointUpdateGap is the least time between two updates of one attack: the shield reports every ten seconds, which a
// person or a pager does not need.
const endpointUpdateGap = time.Minute

// endpoint sends the intrusion alerts and the attacks the shield finds to the alert endpoint.
type endpoint struct {
	cfg        notify.Config
	site       string
	port       uint16
	sender     *notify.Sender
	alerts     *alerting
	intrusions *notify.AlertSink

	mu       sync.Mutex
	updated  map[string]time.Time // attack (by its start) -> when its last update was queued
	finished bool
	queued   uint64 // messages handed to the sender
}

// configureEndpoint checks the endpoint's flags; nil without -alert-endpoint. Nothing is started.
func configureEndpoint(log *slog.Logger, f endpointFlags, site string) (*endpoint, error) {
	if *f.url == "" {
		for name, v := range map[string]string{"alert-endpoint-secret-file": *f.secretFile, "alert-endpoint-allow": *f.allow, "alert-endpoint-ca-file": *f.caFile} {
			if v != "" {
				return nil, refuseFlag(name, fmt.Errorf("-%s needs -alert-endpoint", name))
			}
		}
		return nil, nil
	}
	u, err := notify.ParseURL(*f.url)
	if err != nil {
		return nil, refuseFlag("alert-endpoint", fmt.Errorf("-alert-endpoint: %w", err))
	}
	if *f.secretFile == "" {
		return nil, refuseFlag("alert-endpoint-secret-file", errors.New("-alert-endpoint needs -alert-endpoint-secret-file: its messages are signed"))
	}
	data, err := readCrowdSecFile(*f.secretFile, 4096, true)
	if err != nil {
		return nil, errors.New("cannot read the alert endpoint's secret file (regular file, maximum 4096 bytes, not accessible to everyone or writable by its group)")
	}
	secret, err := notify.ParseSecret(data)
	clear(data)
	if err != nil {
		return nil, fmt.Errorf("-alert-endpoint-secret-file: %w", err)
	}
	allow, err := proxy.ParseOriginAllow(*f.allow)
	if err != nil {
		return nil, refuseFlag("alert-endpoint-allow", fmt.Errorf("-alert-endpoint-allow: %w", err))
	}
	policy := proxy.OriginPolicy{Allow: allow}
	// An address in the URL is checked now, for a readable error; every connection is checked again when it is made.
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		if err := policy.Check(ip); err != nil {
			return nil, refuseFlag("alert-endpoint", errors.New("-alert-endpoint is at an address that is not public; list it in -alert-endpoint-allow if it is yours"))
		}
	}
	// The origin guard's dialer, whose refusal says it is one, so that it is not retried.
	dialer := policy.Dialer()
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		if err := policy.Control(network, address, c); err != nil {
			return fmt.Errorf("%w: %v", notify.ErrNotAllowed, err)
		}
		return nil
	}
	cfg := notify.Config{URL: u, Secret: secret, Dial: dialer.DialContext, Log: log}
	if *f.caFile != "" {
		pem, err := readCrowdSecFile(*f.caFile, 1<<20, false)
		if err != nil {
			return nil, errors.New("cannot read the alert endpoint's CA file (regular file, maximum 1 MiB)")
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("the alert endpoint's CA file contains no certificates")
		}
	}
	return &endpoint{cfg: cfg, site: site, port: notify.URLPort(u), updated: map[string]time.Time{}}, nil
}

// start begins sending, and sends the endpoint every intrusion alert alerts writes to the log, the source shown as
// there. The URL is not logged: it may hold a token, and it says where alerts go.
func (e *endpoint) start(log *slog.Logger, alerts *alerting) error {
	if e == nil {
		return nil
	}
	s, err := notify.New(e.cfg)
	if err != nil {
		return err
	}
	e.sender = s
	if alerts != nil && alerts.queue != nil {
		e.alerts, e.intrusions = alerts, notify.NewAlertSink(s, e.site, alerts.source)
		alerts.sendTo(e.intrusions)
	}
	log.Info("alert endpoint on", "port", e.port)
	return nil
}

// close sends what is waiting, for at most two seconds (an attack_end at shutdown), and logs what was sent. The alerts
// are closed first, so that the last requests' alerts and those the aggregator still holds are sent too.
func (e *endpoint) close(log *slog.Logger) {
	if e == nil || e.sender == nil {
		return
	}
	if e.intrusions != nil {
		e.alerts.close()
		e.intrusions.Close()
	}
	e.mu.Lock()
	e.finished = true
	e.mu.Unlock()
	e.sender.Close(2 * time.Second)
	st := e.sender.Stats()
	var messages, lost uint64
	if e.intrusions != nil {
		messages, lost = e.intrusions.Stats() // after the sender's close: with the alerts it could not deliver
	}
	e.mu.Lock()
	queued := e.queued + messages
	e.mu.Unlock()
	log.Info("alert endpoint closed", "queued", queued, "sent", st.Sent, "failed", st.Failed, "dropped", st.Dropped, "retries", st.Retries,
		"intrusions_not_sent", lost)
}

// shieldEvent sends an attack's start, its end and at most one update a minute, and the repeat-offender lines with the
// intrusion alerts, as the log writes them; the shield's other events are left to the log. It never blocks.
func (e *endpoint) shieldEvent(ev shield.Event) {
	if e == nil || e.sender == nil {
		return
	}
	if offenderEvent(ev.Kind) {
		if e.intrusions != nil {
			if l, _, ok := offenderLine(ev, e.alerts.source); ok {
				e.intrusions.SendLine(l)
			}
		}
		return
	}
	var kind notify.Event
	switch ev.Kind {
	case "attack_start":
		kind = notify.AttackStart
	case "attack_update":
		kind = notify.AttackUpdate
	case "attack_end":
		kind = notify.AttackEnd
	default:
		return
	}
	subject := ev.Incident.Start.UTC().Format(time.RFC3339Nano)
	if e.admit(kind, subject, ev.At) {
		e.sender.Send(notify.FromShield(kind, ev, e.site, subject))
	}
}

// admit says whether a message of kind about subject (an attack), at at, is to be sent: every start and end, and an
// update only a minute or more after the last one sent.
func (e *endpoint) admit(kind notify.Event, subject string, at time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.finished {
		return false
	}
	switch kind {
	case notify.AttackUpdate, notify.NetworkUpdate:
		if last, ok := e.updated[subject]; ok && at.Sub(last) < endpointUpdateGap {
			return false
		}
		e.updated[subject] = at
	case notify.AttackStart, notify.NetworkStart:
		e.updated[subject] = at
	default:
		delete(e.updated, subject)
	}
	// An attack whose end was never seen (the queue dropped it) must not be remembered for ever.
	if len(e.updated) > 64 {
		for k, last := range e.updated {
			if at.Sub(last) > time.Hour {
				delete(e.updated, k)
			}
		}
	}
	e.queued++
	return true
}

// endpointSite is the name messages give the site: its first host name, or nothing.
func endpointSite(hosts string) string {
	first, _, _ := strings.Cut(hosts, ",")
	first = strings.TrimSpace(first)
	if first == "" {
		return ""
	}
	if u, err := url.Parse("https://" + first); err == nil && u.Hostname() != "" {
		return alert.Clean(u.Hostname(), alert.MaxHost)
	}
	return ""
}
