// SPDX-License-Identifier: Apache-2.0

package bots

import (
	"crypto/tls"
	"net"
	"slices"
	"sync"
	"sync/atomic"
)

// DefaultHellos is how many connections' handshakes a Hellos keeps by default; past it a new connection's is not kept,
// and its requests are read as if no handshake had been seen.
const DefaultHellos = 1 << 18

// Hellos keeps what each TLS connection's ClientHello showed, for the requests that come on it. Observe is set as the
// server's tls.Config.GetConfigForClient, and Forget is called when the connection closes (http.Server.ConnState). It
// is safe for concurrent use.
type Hellos struct {
	m   sync.Map // net.Conn (the connection under TLS) to Hello
	n   atomic.Int64
	max int64
}

// NewHellos makes a Hellos that keeps at most max connections' handshakes (0: DefaultHellos).
func NewHellos(max int) *Hellos {
	if max <= 0 {
		max = DefaultHellos
	}
	return &Hellos{max: int64(max)}
}

// Observe notes a ClientHello. It returns no configuration, so the server's own is used.
func (h *Hellos) Observe(ch *tls.ClientHelloInfo) (*tls.Config, error) {
	if ch == nil || ch.Conn == nil {
		return nil, nil
	}
	hello := Hello{Seen: true, GREASE: hasGREASE(ch), RecordSizeLimit: slices.Contains(ch.Extensions, extRecordSizeLimit)}
	if _, ok := h.m.Load(ch.Conn); ok {
		h.m.Store(ch.Conn, hello)
		return nil, nil
	}
	if h.n.Add(1) > h.max {
		h.n.Add(-1)
		return nil, nil
	}
	if _, loaded := h.m.LoadOrStore(ch.Conn, hello); loaded {
		h.n.Add(-1)
	}
	return nil, nil
}

// Of returns what the handshake of c showed: c is a request's connection, a *tls.Conn or the connection under it.
func (h *Hellos) Of(c net.Conn) Hello {
	if h == nil || c == nil {
		return Hello{}
	}
	v, ok := h.m.Load(under(c))
	if !ok {
		return Hello{}
	}
	return v.(Hello)
}

// Forget drops what was kept of c.
func (h *Hellos) Forget(c net.Conn) {
	if h == nil || c == nil {
		return
	}
	if _, ok := h.m.LoadAndDelete(under(c)); ok {
		h.n.Add(-1)
	}
}

func under(c net.Conn) net.Conn {
	if tc, ok := c.(*tls.Conn); ok {
		return tc.NetConn()
	}
	return c
}

// extRecordSizeLimit is the record_size_limit extension (RFC 8449), which Firefox's TLS (NSS) always offers.
const extRecordSizeLimit = 28

// isGREASE reports a GREASE value (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa.
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func hasGREASE(ch *tls.ClientHelloInfo) bool {
	for _, v := range ch.CipherSuites {
		if isGREASE(v) {
			return true
		}
	}
	for _, v := range ch.Extensions {
		if isGREASE(v) {
			return true
		}
	}
	for _, v := range ch.SupportedVersions {
		if isGREASE(v) {
			return true
		}
	}
	for _, v := range ch.SupportedCurves {
		if isGREASE(uint16(v)) {
			return true
		}
	}
	return false
}
