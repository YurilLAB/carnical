// SPDX-License-Identifier: Apache-2.0

// Package notify tells the operator's own endpoint, over HTTPS, what carnical found while an attack goes on: a few
// small signed JSON messages per attack, sent by one goroutine from a bounded queue. It is made to run when resources
// are scarce: nothing is done per request, a message is a few kilobytes at most, one connection is kept and reused, and
// a slow or dead endpoint costs one goroutine and a queue of at most a few dozen messages.
//
// It is also made so that it cannot be turned against the endpoint or the network: it posts only to the one URL it was
// configured with, over a dialer the caller guards (the origin guard: no private, local or metadata address unless
// allowed), follows no redirect, sends one message at a time and never more often than MinGap. A message holds no
// query, body, cookie or visitor's address: only the bounded labels of FromShield's clusters hold what clients sent (a
// User-Agent's first bytes, a path template). The URL and the secret never appear in a log line or an error.
//
// Each message is signed: X-Carnical-Signature is "v1=" and the hex HMAC-SHA256, keyed with the shared secret, of the
// X-Carnical-Timestamp header, a full stop and the body. A receiver checks the signature with a constant-time compare,
// refuses a timestamp more than five minutes from its own clock, and drops a message whose signed id it has seen (a
// retry carries the same one). X-Carnical-Delivery is an unsigned copy of the id, for logs.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Limits.
const (
	MinSecret    = 32                     // bytes of a shared secret
	MaxSecret    = 1024                   // bytes of a shared secret
	MaxURL       = 2048                   // bytes of the endpoint's URL
	MaxBody      = 16 << 10               // bytes of one message
	DefaultQueue = 32                     // messages waiting
	MaxQueue     = 256                    // messages waiting, at most
	MinGap       = 500 * time.Millisecond // the least time between two posts
	maxReply     = 4 << 10                // bytes of a reply that are read (the rest is not)
)

// ParseURL reads the endpoint's URL. It must be absolute https, with a host, no user name or password (they would be
// sent in the clear to anything that logs URLs) and no fragment. Plain http is accepted for a loopback address only,
// for a relay on the same machine.
func ParseURL(s string) (*url.URL, error) {
	if s == "" || len(s) > MaxURL {
		return nil, fmt.Errorf("the alert endpoint must be an https URL of at most %d bytes", MaxURL)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c >= 0x7f {
			return nil, errors.New("the alert endpoint's URL must be ASCII without spaces or control characters (give a name in its punycode form)")
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("the alert endpoint's URL cannot be read")
	}
	switch {
	case u.User != nil:
		return nil, errors.New("the alert endpoint's URL must not hold a user name or password")
	case u.Fragment != "" || strings.Contains(s, "#"):
		return nil, errors.New("the alert endpoint's URL must not have a fragment")
	case u.Opaque != "" || u.Host == "" || u.Hostname() == "":
		return nil, errors.New("the alert endpoint must be an absolute URL with a host")
	case strings.Contains(u.Hostname(), "%"):
		// An IPv6 zone (fe80::1%eth0) names an interface, which the address check refuses; so is an escaped host.
		return nil, errors.New("the alert endpoint's host must not hold a zone or an escape")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, errors.New("the alert endpoint's port must be from 1 to 65535")
		}
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !ip.Unmap().IsLoopback() {
			return nil, errors.New("the alert endpoint must use https (plain http only to a loopback address)")
		}
	default:
		return nil, errors.New("the alert endpoint must use https")
	}
	return u, nil
}

// URLPort is the TCP port a URL from ParseURL is reached on.
func URLPort(u *url.URL) uint16 {
	if p := u.Port(); p != "" {
		n, _ := strconv.Atoi(p)
		return uint16(n) // #nosec G115 -- ParseURL bounded it to 1..65535
	}
	if u.Scheme == "http" {
		return 80
	}
	return 443
}

// ParseSecret reads a shared secret from the contents of its file: the bytes up to the first line end, without
// surrounding spaces, at least MinSecret and at most MaxSecret bytes, printable ASCII only (hex or base64 from
// "openssl rand", say). The secret is the text, not its decoding, so that both ends read it the same way.
func ParseSecret(data []byte) ([]byte, error) {
	line, _, _ := bytes.Cut(data, []byte("\n"))
	line = bytes.TrimSpace(line)
	if len(line) < MinSecret || len(line) > MaxSecret {
		return nil, fmt.Errorf("the alert signing secret must be %d to %d characters on its first line", MinSecret, MaxSecret)
	}
	for _, c := range line {
		if c <= ' ' || c > '~' {
			return nil, errors.New("the alert signing secret must be printable ASCII without spaces")
		}
	}
	return bytes.Clone(line), nil
}

// NewSecret makes a new shared secret: 32 random bytes in hex, a line of its own.
func NewSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 65)
	out = hex.AppendEncode(out, b)
	clear(b)
	return append(out, '\n'), nil
}

// ErrNotAllowed is what a Config.Dial returns, wrapped, for an address the guard refuses: no attempt can change that,
// so it is not retried.
var ErrNotAllowed = errors.New("the address is not allowed")

// Config is how to reach the endpoint.
type Config struct {
	URL    *url.URL // from ParseURL
	Secret []byte   // the shared secret, MinSecret to MaxSecret bytes; copied
	// Dial makes the connections. The caller guards it: carnical gives the origin guard's dialer, which checks the
	// address each connection is really about to use, so a name that resolves somewhere it must not gets nothing.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// RootCAs verifies the endpoint's certificate; nil is the system's.
	RootCAs *x509.CertPool
	// Timeout bounds one attempt, from dialling to the end of the reply; 0 is 5 seconds.
	Timeout time.Duration
	// Queue is how many messages may wait; 0 is DefaultQueue, at most MaxQueue.
	Queue int
	// Log, when set, is told of failed deliveries, at most once every 30 seconds, and of how many there were.
	Log *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Stats counts what the Sender did.
type Stats struct {
	Sent    uint64 // messages the endpoint took (a 2xx reply)
	Failed  uint64 // messages given up on after their attempts
	Dropped uint64 // messages the queue had no room for, or left when it closed
	Retries uint64 // attempts after the first
}

// Sender posts messages to one endpoint. Its methods may be called from any goroutine.
type Sender struct {
	url     string
	secret  []byte
	client  *http.Client
	timeout time.Duration
	now     func() time.Time
	log     *slog.Logger
	// retryWait is how long to wait before each attempt after the first; there are len(retryWait)+1 attempts.
	retryWait []time.Duration
	gap       time.Duration

	mu      sync.Mutex
	queue   []Message
	size    int
	closing bool
	closeOK bool   // what the first Close reported, once closed is closed
	unsent  uint64 // drops not yet reported in a message
	// unsentAlerts counts the intrusion alerts in messages that were dropped or not delivered, with the drops those
	// messages were to report, until a message of intrusion alerts reports them (see lose).
	unsentAlerts uint64
	wake         chan struct{}
	stop         chan struct{} // closed when Close stops waiting: the attempt in flight is cancelled
	done         chan struct{}
	closed       chan struct{} // closed when the first Close has its result

	sent, failed, dropped, retries atomic.Uint64
	lostAlerts                     atomic.Uint64 // intrusion alerts in messages dropped or not delivered
	logMu                          sync.Mutex
	lastLog                        time.Time
	unlogged                       uint64
}

// New checks cfg and starts the Sender's goroutine.
func New(cfg Config) (*Sender, error) {
	switch {
	case cfg.URL == nil:
		return nil, errors.New("notify: no endpoint")
	case len(cfg.Secret) < MinSecret || len(cfg.Secret) > MaxSecret:
		return nil, fmt.Errorf("notify: the secret must be %d to %d bytes", MinSecret, MaxSecret)
	case cfg.Dial == nil:
		return nil, errors.New("notify: no dialer")
	}
	if _, err := ParseURL(cfg.URL.String()); err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	size := cfg.Queue
	if size <= 0 {
		size = DefaultQueue
	}
	size = min(size, MaxQueue)
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	tr := &http.Transport{
		Proxy:                  nil, // never through a proxy the environment names
		DialContext:            cfg.Dial,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs},
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxIdleConns:           1,
		MaxIdleConnsPerHost:    1,
		MaxConnsPerHost:        1,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
		// A kept HTTP/2 connection to an endpoint that went silent is found dead by a ping, not by TCP's keep-alive minutes.
		HTTP2: &http.HTTP2Config{SendPingTimeout: 30 * time.Second, PingTimeout: timeout},
	}
	s := &Sender{
		url:    cfg.URL.String(),
		secret: bytes.Clone(cfg.Secret),
		client: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // a redirect is a failure: the endpoint is the one URL configured
		}},
		timeout: timeout, now: now, log: cfg.Log, retryWait: []time.Duration{time.Second, 3 * time.Second},
		gap: MinGap, size: size, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
		closed: make(chan struct{}),
	}
	go s.run()
	return s, nil
}

// Send queues m for delivery and reports whether there was room. It never blocks. When the queue is full, the oldest
// update or message of intrusion alerts waiting makes room (see Event.yields); such a message that finds none is
// dropped, and any other takes the place of the oldest message. An update of an attack whose last update still waits
// replaces it: the endpoint needs the latest.
func (s *Sender) Send(m Message) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		s.drop()
		s.lose(&m)
		return false
	}
	if m.Event.update() {
		for i := range s.queue {
			if s.queue[i].Event == m.Event && s.queue[i].Subject == m.Subject {
				s.queue[i] = m
				s.signal()
				return true
			}
		}
	}
	if len(s.queue) >= s.size {
		victim := -1
		for i := range s.queue {
			if s.queue[i].Event.yields() {
				victim = i
				break
			}
		}
		switch {
		case victim >= 0:
		case m.Event.yields():
			s.drop()
			s.lose(&m)
			return false
		default:
			victim = 0
		}
		s.lose(&s.queue[victim])
		s.queue = append(s.queue[:victim], s.queue[victim+1:]...)
		s.drop()
	}
	s.queue = append(s.queue, m)
	s.signal()
	return true
}

func (s *Sender) drop() {
	s.unsent++
	s.dropped.Add(1)
}

// lose counts the intrusion alerts of m, which is not delivered, as lost, and keeps them with the drops m was to report
// for the next message of intrusion alerts to report. s.mu is held.
func (s *Sender) lose(m *Message) {
	if m.Event != Intrusions {
		return
	}
	s.lostAlerts.Add(uint64(len(m.Intrusions)))
	s.unsentAlerts += uint64(len(m.Intrusions)) + m.IntrusionsDropped
}

func (s *Sender) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Stats returns the counts so far.
func (s *Sender) Stats() Stats {
	return Stats{Sent: s.sent.Load(), Failed: s.failed.Load(), Dropped: s.dropped.Load(), Retries: s.retries.Load()}
}

// Close stops taking messages and delivers those waiting, for at most wait; what is left then is counted as dropped and
// the attempt in flight is cancelled. It reports whether everything was delivered or given up on in time.
func (s *Sender) Close(wait time.Duration) bool {
	s.mu.Lock()
	already := s.closing
	s.closing = true
	s.signal()
	s.mu.Unlock()
	if already {
		<-s.closed
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.closeOK
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	ok := true
	select {
	case <-s.done:
	case <-t.C:
		close(s.stop)
		<-s.done
		ok = false
	}
	s.mu.Lock()
	s.closeOK = ok
	s.mu.Unlock()
	close(s.closed)
	return ok
}

func (s *Sender) run() {
	defer close(s.done)
	defer s.client.CloseIdleConnections()
	var last time.Time
	for {
		s.mu.Lock()
		for len(s.queue) == 0 {
			if s.closing {
				s.mu.Unlock()
				return
			}
			s.mu.Unlock()
			select {
			case <-s.wake:
			case <-s.stop:
				return
			}
			s.mu.Lock()
		}
		m := s.queue[0]
		s.queue[0] = Message{}
		s.queue = s.queue[1:]
		m.Dropped, s.unsent = s.unsent, 0
		if m.Event == Intrusions && s.unsentAlerts > 0 {
			m.IntrusionsDropped += s.unsentAlerts
			s.unsentAlerts = 0
			m.Severity, m.Text = intrusionSeverity(m.Intrusions, m.IntrusionsDropped), intrusionText(m.Intrusions, m.IntrusionsDropped, m.Site)
		}
		s.mu.Unlock()
		if wait := s.gap - s.now().Sub(last); wait > 0 && !s.sleep(wait) {
			s.mu.Lock()
			s.dropped.Add(1) // m
			s.lose(&m)
			s.mu.Unlock()
			s.abandonQueue()
			return
		}
		if !s.deliver(m) {
			// The drops it was to report, and its alerts, are reported by the next message instead.
			s.mu.Lock()
			s.unsent += m.Dropped
			s.lose(&m)
			s.mu.Unlock()
		}
		last = s.now()
		select {
		case <-s.stop:
			s.abandonQueue()
			return
		default:
		}
	}
}

// sleep waits d, or until Close stops waiting; it reports whether the wait ended on its own.
func (s *Sender) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-s.stop:
		return false
	}
}

func (s *Sender) abandonQueue() {
	s.mu.Lock()
	s.dropped.Add(uint64(len(s.queue)))
	for i := range s.queue {
		s.lose(&s.queue[i])
	}
	s.queue = nil
	s.mu.Unlock()
}

// deliver posts m, with the attempts retryWait allows for a failure that may pass (no reply, 408, 429 or 5xx). It
// reports whether the endpoint took it.
func (s *Sender) deliver(m Message) bool {
	if m.ID == "" {
		m.ID = newID()
	}
	if m.Version == 0 {
		m.Version = 1
	}
	if m.Severity == "" {
		m.Severity = m.Event.Severity()
	}
	body, err := json.Marshal(m)
	switch {
	case err != nil:
		s.failed.Add(1)
		s.report("message cannot be encoded", 0)
		return false
	case len(body) > MaxBody:
		s.failed.Add(1)
		s.report("message too large", 0)
		return false
	}
	for attempt := 0; ; attempt++ {
		status, err := s.post(m, body)
		if err == nil && status >= 200 && status < 300 {
			s.sent.Add(1)
			return true
		}
		retry := err != nil && !final(err) || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500
		if !retry || attempt >= len(s.retryWait) {
			s.failed.Add(1)
			s.report(reason(err), status)
			return false
		}
		if !s.sleep(s.retryWait[attempt]) { // Close stopped waiting: no further attempt
			s.failed.Add(1)
			return false
		}
		s.retries.Add(1)
	}
}

func (s *Sender) post(m Message, body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	go func() {
		select {
		case <-s.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	ts := strconv.FormatInt(s.now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "carnical-alert/1")
	req.Header.Set("X-Carnical-Event", string(m.Event))
	req.Header.Set("X-Carnical-Delivery", m.ID)
	req.Header.Set("X-Carnical-Timestamp", ts)
	req.Header.Set("X-Carnical-Signature", "v1="+Sign(s.secret, ts, body))
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	// Read a little of the reply so that the connection can be kept, and no more.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxReply))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// Sign is the hex HMAC-SHA256 of timestamp, ".", body, keyed with secret: what X-Carnical-Signature carries after "v1=".
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a message as a receiver would: the signature header against the timestamp and body, and the timestamp
// within skew of now. It uses a constant-time compare.
func Verify(secret []byte, timestamp, signature string, body []byte, now time.Time, skew time.Duration) bool {
	sec, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(sec, 0)); d > skew || d < -skew {
		return false
	}
	got, ok := strings.CutPrefix(signature, "v1=")
	if !ok {
		return false
	}
	want := Sign(secret, timestamp, body)
	return hmac.Equal([]byte(got), []byte(want))
}

// final says that an attempt failed in a way no later attempt can change: the address is refused, or the endpoint's
// certificate is not one to trust.
func final(err error) bool {
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.Is(err, ErrNotAllowed) || errors.As(err, &cert) || errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &invalid)
}

// reason names why an attempt failed without saying where it went: an error from the HTTP client holds the URL.
func reason(err error) string {
	var dns *net.DNSError
	var op *net.OpError
	var rec tls.RecordHeaderError
	switch {
	case err == nil:
		return "refused by the endpoint"
	case errors.Is(err, ErrNotAllowed):
		return "the address is not allowed"
	case final(err):
		return "the endpoint's certificate is not trusted"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timed out"
	case errors.As(err, &rec):
		return "TLS failed"
	case errors.As(err, &dns):
		return "name not found"
	case errors.As(err, &op) && op.Op == "dial":
		return "could not connect"
	}
	return "connection failed"
}

// report logs a failed delivery, at most once every 30 seconds, with how many failed since the last line.
func (s *Sender) report(why string, status int) {
	if s.log == nil {
		return
	}
	s.logMu.Lock()
	s.unlogged++
	now := s.now()
	if !s.lastLog.IsZero() && now.Sub(s.lastLog) < 30*time.Second {
		s.logMu.Unlock()
		return
	}
	n := s.unlogged
	s.lastLog, s.unlogged = now, 0
	s.logMu.Unlock()
	attrs := []any{"reason", why, "failed", n}
	if status != 0 {
		attrs = append(attrs, "status", status)
	}
	s.log.Warn("alert endpoint delivery failed", attrs...)
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read does not fail
	return hex.EncodeToString(b[:])
}
