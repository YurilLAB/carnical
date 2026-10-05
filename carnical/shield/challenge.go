// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash/maphash"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// During an attack, a browser that the shield does not know and that falls into the attack's budget is not refused: it
// is asked to prove it is a browser with a person behind it, by doing a small amount of work (finding a number whose
// SHA-256, together with a token, starts with a given number of zero bits, about a second on a phone) in JavaScript. The
// answer earns a cookie that admits that browser, from that address, for a while. A bot that runs no JavaScript cannot
// answer at all; one that does pays a second of CPU for each address it uses, which is what makes a flood expensive.
// Nothing is stored on the server: the token and the cookie are authenticated with a key made at start-up.
//
// An API client or a script is never shown the page (it could not act on it): it gets 503 with Retry-After.

// VerifyPath is where the challenge page sends its answer. The shield answers it itself; it never reaches the site.
const VerifyPath = "/.well-known/carnical/verify"

const cookieName = "carnical_clr"

const tokenTTL = 5 * time.Minute

func newKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("shield: no randomness: " + err.Error())
	}
	return k
}

func (s *Shield) mac(kind string, data []byte, key netip.Addr) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(kind))
	m.Write(data)
	kb, _ := key.MarshalBinary()
	m.Write(kb)
	return m.Sum(nil)[:16]
}

// token makes a challenge for this source: issue time, a random nonce and the difficulty, authenticated together with
// the source, so that a token cannot be solved once and used from every address of a botnet.
func (s *Shield) token(key netip.Addr, now time.Time) string {
	raw := make([]byte, 17, 33)
	binary.BigEndian.PutUint64(raw, uint64(now.Unix()))
	rand.Read(raw[8:16])
	raw[16] = byte(s.cfg.ChallengeBits)
	raw = append(raw, s.mac("c1", raw, key)...)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// solved reports whether n is a correct answer to token, issued to this source within tokenTTL.
func (s *Shield) solved(token, n string, key netip.Addr, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 33 || len(n) == 0 || len(n) > 12 {
		return false
	}
	for i := 0; i < len(n); i++ {
		if n[i] < '0' || n[i] > '9' {
			return false
		}
	}
	if !hmac.Equal(raw[17:], s.mac("c1", raw[:17], key)) {
		return false
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(raw)), 0)
	if now.Before(issued.Add(-time.Minute)) || now.After(issued.Add(tokenTTL)) {
		return false
	}
	bits := int(raw[16])
	if bits < 1 || bits > 30 {
		return false
	}
	sum := sha256.Sum256([]byte(token + "." + n))
	return binary.BigEndian.Uint32(sum[:4]) < 1<<(32-bits)
}

var uaSeed = maphash.MakeSeed()

// clearance is the cookie value that admits this source with this browser until exp.
func (s *Shield) clearance(key netip.Addr, ua string, exp time.Time) string {
	raw := make([]byte, 16, 32)
	binary.BigEndian.PutUint64(raw, uint64(exp.Unix()))
	binary.BigEndian.PutUint64(raw[8:], maphash.String(uaSeed, ua))
	raw = append(raw, s.mac("k1", raw, key)...)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (s *Shield) cleared(r *http.Request, key netip.Addr, now time.Time) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != 32 {
		return false
	}
	if binary.BigEndian.Uint64(raw[8:16]) != maphash.String(uaSeed, r.Header.Get("User-Agent")) {
		return false
	}
	if !hmac.Equal(raw[16:], s.mac("k1", raw[:16], key)) {
		return false
	}
	return now.Before(time.Unix(int64(binary.BigEndian.Uint64(raw)), 0))
}

// safeReturn is the path the browser is sent back to after answering: a path on this site, never another site.
func safeReturn(to string) string {
	if len(to) == 0 || len(to) > 2048 || to[0] != '/' || strings.HasPrefix(to, "//") || strings.HasPrefix(to, "/\\") {
		return "/"
	}
	for i := 0; i < len(to); i++ {
		if to[i] <= 0x20 || to[i] >= 0x7f || to[i] == '\\' {
			return "/"
		}
	}
	return to
}

// verify answers a request to VerifyPath.
func (s *Shield) verify(r *http.Request, key netip.Addr, now time.Time) Decision {
	q := r.URL.Query()
	to := safeReturn(q.Get("to"))
	if r.Method != http.MethodGet || !s.solved(q.Get("t"), q.Get("n"), key, now) {
		s.det.count(now.UnixNano(), func(w *window) { w.refused++ })
		return Decision{Action: Respond, ID: idChallengeFailed, Status: http.StatusForbidden,
			resp: &response{body: "The check could not be confirmed. Go back and try again.\n", contentType: "text/plain; charset=utf-8"}}
	}
	s.counters.solved.Add(1)
	s.det.note(now.UnixNano(), func(w *window, inc *incidentAcc) {
		w.solved++
		if inc != nil {
			inc.solved++
		}
	})
	cookie := &http.Cookie{Name: cookieName, Value: s.clearance(key, r.Header.Get("User-Agent"), now.Add(s.cfg.ClearanceFor)),
		Path: "/", MaxAge: int(s.cfg.ClearanceFor / time.Second), HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil}
	return Decision{Action: Respond, ID: idChallengeSolved, Status: http.StatusSeeOther,
		resp: &response{cookie: cookie, location: to, contentType: "text/plain; charset=utf-8", body: "Thank you.\n"}}
}

// challengePage is the page a browser gets instead of the site during an attack.
func (s *Shield) challengePage(r *http.Request, key netip.Addr, now time.Time) (body, nonce string) {
	nb := make([]byte, 16)
	rand.Read(nb)
	nonce = base64.RawURLEncoding.EncodeToString(nb)
	token := s.token(key, now) // base64url: nothing in it needs escaping
	verify := VerifyPath + "?t=" + token + "&to=" + jsEscape(urlEscape(safeReturn(r.URL.RequestURI())))
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>One moment</title>`)
	b.WriteString(`<style>body{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:15vh auto;padding:0 16px;color:#1d1d1f;background:#fff}@media (prefers-color-scheme:dark){body{color:#e8e8e8;background:#141414}}</style></head><body>`)
	b.WriteString(`<h1>One moment</h1><p>This site is receiving an unusual amount of traffic. Your browser is doing a short calculation to show that it is not part of it, and the page will continue by itself in a few seconds.</p>`)
	b.WriteString(`<noscript><p>This check needs JavaScript. Please switch it on, or try again in a few minutes.</p></noscript>`)
	b.WriteString(`<script nonce="` + nonce + `">`)
	b.WriteString(`(function(){var u="` + verify + `",t="` + token + `",lim=Math.pow(2,` + strconv.Itoa(32-s.cfg.ChallengeBits) + `);`)
	b.WriteString(solverJS)
	b.WriteString(`var n=0;function step(){for(var end=n+20000;n<end;n++){if((h(t+"."+n)>>>0)<lim){location.replace(u+"&n="+n);return}}setTimeout(step,0)}step()})();</script></body></html>`)
	return b.String(), nonce
}

// solverJS defines h(s): the first 32-bit word of the SHA-256 of an ASCII string. The constants are computed from the
// primes, as the standard defines them, so that there is no table to mistype; a test runs it against crypto/sha256.
const solverJS = `var K=[],H0=[],p=2,k=0,comp={};while(k<64){if(!comp[p]){for(var q=p*p;q<400;q+=p)comp[q]=1;if(k<8)H0[k]=(Math.pow(p,.5)*4294967296)|0;K[k++]=(Math.pow(p,1/3)*4294967296)|0}p++}` +
	`function r(x,n){return(x>>>n)|(x<<(32-n))}` +
	`function h(s){var l=s.length,m=((l+8)>>6)+1,w=[],W=[],i,j;for(i=0;i<m*16;i++)w[i]=0;for(i=0;i<l;i++)w[i>>2]|=s.charCodeAt(i)<<(24-(i&3)*8);w[l>>2]|=128<<(24-(l&3)*8);w[m*16-1]=l*8;var H=H0.slice();` +
	`for(j=0;j<m*16;j+=16){var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],o=H[7];for(i=0;i<64;i++){if(i<16)W[i]=w[j+i]|0;else{var x=W[i-15],y=W[i-2];W[i]=(W[i-16]+(r(x,7)^r(x,18)^(x>>>3))+W[i-7]+(r(y,17)^r(y,19)^(y>>>10)))|0}` +
	`var t1=(o+(r(e,6)^r(e,11)^r(e,25))+((e&f)^(~e&g))+K[i]+W[i])|0,t2=((r(a,2)^r(a,13)^r(a,22))+((a&b)^(a&c)^(b&c)))|0;o=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0}` +
	`H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+o)|0}return H[0]}`

// urlEscape percent-encodes everything in a path and query that is not plainly safe inside a query parameter.
func urlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteString("%" + strings.ToUpper(strconv.FormatUint(uint64(c)>>4, 16)+strconv.FormatUint(uint64(c)&15, 16)))
		}
	}
	return b.String()
}

// jsEscape leaves only characters that cannot end a JavaScript string or an HTML script element.
func jsEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("/-_.~%?=&", c) >= 0 {
			b.WriteByte(c)
		} else {
			b.WriteString(`\x` + strconv.FormatUint(uint64(c)>>4, 16) + strconv.FormatUint(uint64(c)&15, 16))
		}
	}
	return b.String()
}
