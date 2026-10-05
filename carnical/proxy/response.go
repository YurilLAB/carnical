package proxy

import (
	"net/http"
	"strings"
)

// ResponsePolicy is what the proxy does to the application's response on the way out. The zero value is the default.
//
// None of this is detection. It limits what an attacker gets from a site that has a flaw the proxy could not see:
// a page that a shared cache keeps for the next visitor, a file the browser decides to run as a script, and the
// software versions a probe uses to pick an exploit.
type ResponsePolicy struct {
	// KeepBanners leaves X-Powered-By, X-AspNet-Version and the Server header as the application sent them.
	KeepBanners bool
	// KeepCaching leaves Cache-Control alone on responses that set a cookie or look like a static file but are HTML.
	KeepCaching bool
}

var staticSuffix = []string{".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2",
	".ttf", ".eot", ".txt", ".xml", ".json", ".pdf", ".mp4", ".webm", ".avif", ".bmp"}

func looksStatic(path string) bool {
	path = strings.ToLower(path)
	for _, s := range staticSuffix {
		if strings.HasSuffix(path, s) {
			return true
		}
	}
	return false
}

// harden changes the response headers of a response that was allowed through. path is the request path as sent.
func (p ResponsePolicy) harden(resp *http.Response, path string) {
	h := resp.Header
	if !p.KeepBanners {
		h.Del("X-Powered-By")
		h.Del("X-AspNet-Version")
		h.Del("X-AspNetMvc-Version")
		h.Del("Server")
	}
	// A file that the browser may decide is something else. nosniff makes it keep to the type it was sent as, so an
	// uploaded image or text file is never run as a script.
	if h.Get("X-Content-Type-Options") == "" {
		h.Set("X-Content-Type-Options", "nosniff")
	}
	if p.KeepCaching {
		return
	}
	// Web cache deception: a page for one visitor, at an address that ends like a stylesheet, is stored by a cache in
	// front of the site and served to the next visitor. And a response that sets a cookie belongs to one visitor.
	cc := h.Get("Cache-Control")
	htmlAtStaticPath := looksStatic(path) && strings.HasPrefix(strings.ToLower(h.Get("Content-Type")), "text/html")
	if htmlAtStaticPath || (len(h.Values("Set-Cookie")) > 0 && cc == "" && h.Get("Expires") == "") {
		h.Set("Cache-Control", "private, no-store")
		h.Del("Expires")
	}
}
