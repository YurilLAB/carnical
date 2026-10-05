package proxy

import (
	"net/http"
	"strings"
)

// stripClaims removes every header by which a client could say who it is, which host it asked for or which
// route it wants, so the application sees only the four forwarding headers the proxy builds itself.
//
// PHP, CGI, WSGI and IIS build their variables by turning "-" into "_", so a client's X_Original_URL reaches such an
// application as the same input as X-Original-URL (and X_Forwarded_For can replace the proxy's own value). Names
// are therefore compared with both spellings folded to the dashed one.
func stripClaims(h http.Header) {
	for name := range h {
		key := strings.ReplaceAll(strings.ToLower(name), "_", "-")
		remove := strings.HasPrefix(key, "x-forwarded-") || isInternalHeader(key)
		switch key {
		case "forwarded", "forwarded-for", "x-forwarded", "x-real-ip", "x-client-ip", "client-ip", "true-client-ip",
			"cf-connecting-ip", "cf-connecting-ipv6", "cf-pseudo-ipv4", "fastly-client-ip", "x-cluster-client-ip",
			"x-original-forwarded-for", "proxy", "x-original-url", "x-rewrite-url", "x-override-url",
			"x-originating-ip", "x-remote-ip", "x-remote-addr", "proxy-client-ip", "wl-proxy-client-ip",
			"x-azure-clientip", "x-envoy-external-address", "x-proxyuser-ip", "x-host", "x-original-host",
			"front-end-https":
			remove = true
		}
		if remove {
			delete(h, name) // the actual key, including names that are not in canonical form
		}
	}
}

// wantsUpgrade reports whether the request asks to switch protocol (WebSocket, h2c). After the handshake the
// connection is a raw tunnel that nothing inspects.
func wantsUpgrade(h http.Header) bool {
	if len(h.Values("Upgrade")) > 0 {
		return true
	}
	for _, v := range h.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}
