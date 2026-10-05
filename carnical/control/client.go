// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Errors a Client returns.
var (
	// ErrResponseTooLarge means the server's answer was larger than ClientConfig.MaxResponse.
	ErrResponseTooLarge = errors.New("control: the response is larger than the limit")
	// ErrRedirect means the server answered with a redirect. A signed request is for one address only, so redirects
	// are never followed.
	ErrRedirect = errors.New("control: the server answered with a redirect, which is not followed")
	// ErrPin means the server's certificate key is not one of the pinned keys.
	ErrPin = errors.New("control: the server's certificate key is not a pinned key")
)

// ClientConfig makes a Client.
type ClientConfig struct {
	// BaseURL is https://host[:port]. Nothing else: no user name, path, query or fragment.
	BaseURL string
	// CredentialID and SigningKey are the credential the server knows this client by, and the private half of the key
	// it lists for it. The key is only ever used to sign; it never leaves the process.
	CredentialID string
	SigningKey   ed25519.PrivateKey
	// Certificate is the client certificate (mutual TLS). When CertFile and KeyFile are set instead, they are read
	// again whenever either file changes, so the certificate can be renewed without a restart.
	Certificate       *tls.Certificate
	CertFile, KeyFile string
	// RootCAs are the CAs the server's certificate must chain to; nil means the system's.
	RootCAs *x509.CertPool
	// ServerName overrides the name checked in the server's certificate (default: the host in BaseURL).
	ServerName string
	// PinnedSPKI, when set, are SHA-256 fingerprints of the server's public key; the connection is refused unless the
	// server's certificate holds one of them, whatever else it chains to.
	PinnedSPKI []Fingerprint
	// Timeout bounds one whole call (connecting, sending, and reading the answer); default 30 seconds.
	Timeout time.Duration
	// MaxResponse is the most bytes of answer read; default 4 MiB.
	MaxResponse int64
	// Now is the clock; default time.Now. Rand supplies nonces; default crypto/rand.
	Now  func() time.Time
	Rand io.Reader
}

// Client calls the control API. It is safe for concurrent use.
type Client struct {
	cfg  ClientConfig
	base *url.URL
	host string // the authority as it will be sent
	hc   *http.Client
	cert *certFiles
}

// NewClient checks the configuration and builds a client with TLS 1.3, mutual TLS, optional key pinning, no proxy, no
// redirects and a response size limit.
func NewClient(cfg ClientConfig) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("control: BaseURL must be https://host[:port] and nothing more")
	}
	if !ValidCredentialID(cfg.CredentialID) {
		return nil, errors.New("control: CredentialID is not valid")
	}
	if len(cfg.SigningKey) != ed25519.PrivateKeySize {
		return nil, errors.New("control: SigningKey must be an Ed25519 private key")
	}
	c := &Client{cfg: cfg, base: u, host: strings.ToLower(u.Host)}
	if !validHost(c.host) {
		return nil, errors.New("control: BaseURL host is not valid")
	}
	if c.cfg.Timeout <= 0 {
		c.cfg.Timeout = 30 * time.Second
	}
	if c.cfg.MaxResponse <= 0 {
		c.cfg.MaxResponse = 4 << 20
	}
	if c.cfg.Now == nil {
		c.cfg.Now = time.Now
	}
	if c.cfg.Rand == nil {
		c.cfg.Rand = rand.Reader
	}
	var getCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	switch {
	case cfg.Certificate != nil:
		cert := cfg.Certificate
		getCert = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	case cfg.CertFile != "" && cfg.KeyFile != "":
		cf, err := newCertFiles(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		c.cert = cf
		getCert = cf.get
	default:
		return nil, errors.New("control: a client certificate is required (Certificate, or CertFile and KeyFile)")
	}
	pins := append([]Fingerprint(nil), cfg.PinnedSPKI...)
	tc := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		RootCAs:                cfg.RootCAs,
		ServerName:             cfg.ServerName,
		GetClientCertificate:   getCert,
		CurvePreferences:       curvePreferences(),
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2", "http/1.1"},
		ClientSessionCache:     nil,
	}
	if len(pins) > 0 {
		// Pinning is in addition to the normal chain and name checks, never instead of them.
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrPin
			}
			fp := SPKIFingerprint(cs.PeerCertificates[0])
			for _, p := range pins {
				if p == fp {
					return nil
				}
			}
			return ErrPin
		}
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        tc,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  c.cfg.Timeout,
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        60 * time.Second,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	c.hc = &http.Client{
		Transport: tr,
		Timeout:   c.cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c, nil
}

// CloseIdleConnections closes the client's idle connections.
func (c *Client) CloseIdleConnections() { c.hc.CloseIdleConnections() }

// Call is one request.
type Call struct {
	Method string // GET, PUT or POST
	// Target is the path and query, such as /v1/tenants/<id>/policy or /v1/tenants/<id>/events?limit=50. It must be in
	// the form the server accepts (see checkTarget): lower-case letters, digits and / : . - in the path.
	Target string
	// Body is the request body: a policy document or one of the API's JSON objects. Empty for a request with no body.
	Body []byte
	// ActingUser is the id of the person this request is for. Required.
	ActingUser string
	// StepUp is the time the customer last re-entered their password, for a request that needs it; the zero time sends
	// none.
	StepUp time.Time
	// IfMatch is the revision the caller last read, for PUT policy and rollback.
	IfMatch uint64
	// SendIfMatch says whether to send If-Match (a revision of 0 is a real value: "there is no policy yet").
	SendIfMatch bool
	// IdempotencyKey is for publish.
	IdempotencyKey string
}

// Response is the server's answer, already read in full (up to the size limit).
type Response struct {
	Status    int
	Header    http.Header
	Body      []byte
	RequestID string
	// Proto is the protocol the answer came over, such as "HTTP/2.0".
	Proto string
}

// APIError is the uniform error body of the API.
type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
	Problems  []Problem
	Weakening []Change
}

func (e *APIError) Error() string {
	return fmt.Sprintf("control: %d %s: %s (request %s)", e.Status, e.Code, e.Message, e.RequestID)
}

// Err returns the API's error if the answer is one (any status of 400 or more), or nil.
func (r *Response) Err() *APIError {
	if r.Status < 400 {
		return nil
	}
	var b struct {
		Error struct {
			Code      string        `json:"code"`
			Message   string        `json:"message"`
			RequestID string        `json:"request_id"`
			Problems  []problemJSON `json:"problems"`
			Weakening []changeJSON  `json:"weakening"`
		} `json:"error"`
	}
	e := &APIError{Status: r.Status, Code: "unknown", RequestID: r.RequestID}
	if json.Unmarshal(r.Body, &b) == nil && b.Error.Code != "" {
		e.Code, e.Message, e.RequestID = b.Error.Code, b.Error.Message, b.Error.RequestID
		for _, p := range b.Error.Problems {
			e.Problems = append(e.Problems, Problem{Code: p.Code, Message: p.Message})
		}
		for _, c := range b.Error.Weakening {
			e.Weakening = append(e.Weakening, Change{Code: c.Code, Summary: c.Summary})
		}
	}
	return e
}

// Do signs and sends one request and reads the answer. It returns an error for a transport failure, a redirect or an
// answer that is too large; an answer with an error status is a Response (use Err).
func (c *Client) Do(ctx context.Context, call Call) (*Response, error) {
	if call.Method != http.MethodGet && call.Method != http.MethodPut && call.Method != http.MethodPost {
		return nil, errors.New("control: the method must be GET, PUT or POST")
	}
	if e := checkTarget(call.Target); e != nil {
		return nil, errors.New("control: the target is not one the server accepts")
	}
	if int64(len(call.Body)) > 256<<10 {
		return nil, errors.New("control: the body is larger than the server accepts")
	}
	var nonce [16]byte
	if _, err := io.ReadFull(c.cfg.Rand, nonce[:]); err != nil {
		return nil, err
	}
	sr := SignedRequest{Method: call.Method, Host: c.host, Target: call.Target, BodySHA256: sha256.Sum256(call.Body), Timestamp: c.cfg.Now().Unix(),
		Nonce: hex.EncodeToString(nonce[:]), Credential: c.cfg.CredentialID, Tenant: TenantFromTarget(call.Target), User: call.ActingUser,
		IdemKey: call.IdempotencyKey}
	if !call.StepUp.IsZero() {
		sr.StepUp, sr.HasStepUp = call.StepUp.Unix(), true
	}
	if call.SendIfMatch {
		sr.IfMatch = etag(call.IfMatch)
	}
	sig, err := Sign(c.cfg.SigningKey, sr)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if len(call.Body) > 0 {
		body = bytes.NewReader(call.Body)
	}
	req, err := http.NewRequestWithContext(ctx, call.Method, "https://"+c.base.Host+call.Target, body)
	if err != nil {
		return nil, err
	}
	// The server compares the signed target with the one on the wire, so make sure Go sends exactly this one.
	if req.URL.RequestURI() != call.Target {
		return nil, errors.New("control: the target would be sent differently from how it is signed")
	}
	req.Header.Set("Authorization", AuthHeader{Credential: sr.Credential, Timestamp: sr.Timestamp, Nonce: sr.Nonce, Signature: sig}.String())
	req.Header.Set(HeaderActingUser, call.ActingUser)
	if sr.HasStepUp {
		req.Header.Set(HeaderStepUp, strconv.FormatInt(sr.StepUp, 10))
	}
	if sr.IfMatch != "" {
		req.Header.Set("If-Match", sr.IfMatch)
	}
	if call.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", call.IdempotencyKey)
	}
	if len(call.Body) > 0 {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, ErrRedirect
	}
	if resp.ContentLength > c.cfg.MaxResponse {
		return nil, ErrResponseTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxResponse+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > c.cfg.MaxResponse {
		return nil, ErrResponseTooLarge
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: b, RequestID: resp.Header.Get(HeaderRequestID), Proto: resp.Proto}, nil
}

// ------------------------------------------------------------------------------------------------ conveniences

// Actor says who a request is for and, when the change needs it, when they last proved who they are.
type Actor struct {
	User   string
	StepUp time.Time
}

func tenantTarget(tenant, rest string) string { return "/v1/tenants/" + tenant + rest }

// GetPolicy reads a tenant's policy. It returns the revision and the document.
func (c *Client) GetPolicy(ctx context.Context, tenant string, a Actor) (uint64, json.RawMessage, error) {
	r, err := c.Do(ctx, Call{Method: "GET", Target: tenantTarget(tenant, "/policy"), ActingUser: a.User})
	if err != nil {
		return 0, nil, err
	}
	if e := r.Err(); e != nil {
		return 0, nil, e
	}
	var p policyJSON
	if err := json.Unmarshal(r.Body, &p); err != nil {
		return 0, nil, err
	}
	return p.Revision, p.Document, nil
}

// PutPolicy writes a policy document, given the revision the caller read (0 when there is none), and returns the new
// revision.
func (c *Client) PutPolicy(ctx context.Context, tenant string, expect uint64, doc []byte, a Actor) (uint64, error) {
	r, err := c.Do(ctx, Call{Method: "PUT", Target: tenantTarget(tenant, "/policy"), Body: doc, ActingUser: a.User, StepUp: a.StepUp, IfMatch: expect, SendIfMatch: true})
	if err != nil {
		return 0, err
	}
	if e := r.Err(); e != nil {
		return 0, e
	}
	var p putResultJSON
	if err := json.Unmarshal(r.Body, &p); err != nil {
		return 0, err
	}
	return p.Revision, nil
}

// Publish publishes the current revision and returns the sequence number of the configuration made for the edges.
func (c *Client) Publish(ctx context.Context, tenant string, revision uint64, idempotencyKey string, a Actor) (uint64, error) {
	body, _ := json.Marshal(publishIn{Revision: revision})
	r, err := c.Do(ctx, Call{Method: "POST", Target: tenantTarget(tenant, "/publish"), Body: body, ActingUser: a.User, IdempotencyKey: idempotencyKey})
	if err != nil {
		return 0, err
	}
	if e := r.Err(); e != nil {
		return 0, e
	}
	var p publishOut
	if err := json.Unmarshal(r.Body, &p); err != nil {
		return 0, err
	}
	return p.Sequence, nil
}
