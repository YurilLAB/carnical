// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// These targets check that nothing the network can send makes the package panic, and the properties that make the
// parsers and the privacy cut safe to rely on. Run one with
//
//	go test ./control/feed -run XXX -fuzz FuzzParseAuthorization -fuzztime 20s
func FuzzParseAuthorization(f *testing.F) {
	good := "SFW1 key=" + testKeyID + ", ts=1791014400, nonce=" + vectorNonce + ", sig=" + vectorSig
	for _, s := range []string{good, "", "SFW1", strings.Replace(good, ", ", ",", 1), good + "\n", good + good, "SFW1 key=, ts=, nonce=, sig="} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		az, ok := ParseAuthorization(s)
		if !ok {
			return
		}
		// what is accepted is exactly the documented form, with at most one optional space after each comma
		if !isLowerHex(az.KeyID, 16) || !isLowerHex(az.Nonce, 32) || !isLowerHex(az.Sig, 64) || len(az.TSText) < 1 || len(az.TSText) > 12 {
			t.Fatalf("accepted a malformed header: %+v", az)
		}
		for i := 0; i < len(az.TSText); i++ {
			if az.TSText[i] < '0' || az.TSText[i] > '9' {
				t.Fatalf("non-digit in ts: %q", az.TSText)
			}
		}
		if n, _ := strconv.ParseInt(az.TSText, 10, 64); n != az.TS {
			t.Fatalf("ts %d does not match %q", az.TS, az.TSText)
		}
		compact := "SFW1 key=" + az.KeyID + ",ts=" + az.TSText + ",nonce=" + az.Nonce + ",sig=" + az.Sig
		spaced := strings.ReplaceAll(compact, ",", ", ")
		if s != compact && s != spaced && !mixedSpacing(s, az) {
			t.Fatalf("accepted %q which is not the documented form", s)
		}
	})
}

// mixedSpacing allows the forms where only some commas are followed by a space.
func mixedSpacing(s string, az Authz) bool {
	for mask := 0; mask < 8; mask++ {
		var b strings.Builder
		parts := []string{"SFW1 key=" + az.KeyID, "ts=" + az.TSText, "nonce=" + az.Nonce, "sig=" + az.Sig}
		for i, p := range parts {
			b.WriteString(p)
			if i < 3 {
				b.WriteString(",")
				if mask&(1<<i) != 0 {
					b.WriteString(" ")
				}
			}
		}
		if b.String() == s {
			return true
		}
	}
	return false
}

func FuzzCutAddress(f *testing.F) {
	for _, s := range []string{"198.51.100.77", "2001:db8::1", "::ffff:1.2.3.4", "fe80::1%eth0", "", "1.2.3", "\x00", strings.Repeat("a", 100)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		cut, ok := CutAddress(s)
		whole, wok := WholeAddress(s)
		if ok != wok {
			t.Fatalf("Cut and Whole disagree about %q", s)
		}
		if !ok {
			if cut != "" || whole != "" {
				t.Fatalf("text returned for a non-address %q", s)
			}
			return
		}
		again, ok2 := CutAddress(cut)
		if !ok2 || again != cut {
			t.Fatalf("cutting is not stable: %q -> %q -> %q", s, cut, again)
		}
		if w2, _ := WholeAddress(whole); w2 != whole {
			t.Fatalf("whole is not stable: %q -> %q -> %q", s, whole, w2)
		}
		if len(cut) < 2 || len(cut) > 45 || strings.Trim(cut, "0123456789abcdefABCDEF:.") != "" || strings.Trim(whole, "0123456789abcdefABCDEF:.") != "" {
			t.Fatalf("not an address the reader accepts: %q / %q", cut, whole)
		}
		if strings.Contains(cut, ".") && !strings.HasSuffix(cut, ".0") {
			t.Fatalf("an IPv4 address kept its last byte: %q -> %q", s, cut)
		}
	})
}

func FuzzScrubAddresses(f *testing.F) {
	for _, s := range []string{"banned 203.0.113.7", "from 2001:db8:abcd:1234::1.", "::", "....", "1.2.3.4.5.6", ":::::::", "a:b:c:d:e:f:1:2", "\xff.1.2.3.4"} {
		f.Add(s, byte(1), byte(2), byte(3), byte(7))
	}
	f.Fuzz(func(t *testing.T, s string, a, b, c, d byte) {
		out := scrubAddresses(s)
		if scrubAddresses(out) != out {
			t.Fatalf("scrubbing is not stable: %q -> %q -> %q", s, out, scrubAddresses(out))
		}
		if len(out) > len(s)+4 {
			t.Fatalf("scrubbing made the text much longer: %d -> %d", len(s), len(out))
		}
		// an address with a non-zero last byte, written between spaces, never survives
		addr := strconv.Itoa(int(a)) + "." + strconv.Itoa(int(b)) + "." + strconv.Itoa(int(c)) + "." + strconv.Itoa(int(d)|1)
		text := "x " + addr + " " + s
		if got := scrubAddresses(text); strings.Contains(got, " "+addr+" ") {
			t.Fatalf("%q survived in %q", addr, got)
		}
	})
}

func FuzzMarshalEvent(f *testing.F) {
	f.Add("block", "high", "198.51.100.1", "/p", "\xff\xfe", "why 1.2.3.4", int64(1791014400), true)
	f.Add("", "", "", "", "", "", int64(-1), false)
	f.Fuzz(func(t *testing.T, kind, sev, ip, path, ua, why string, ts int64, cut bool) {
		e := Event{Time: time.Unix(ts, 0), Kind: kind, Sev: sev, IP: ip, Path: path, UA: ua, Why: why}
		b, ok := MarshalEvent(e, cut)
		if !ok {
			return
		}
		if !utf8.Valid(b) {
			t.Fatalf("invalid UTF-8 in an event: %q", b)
		}
		if !kindRE.MatchString(kind) || !severities[sev] {
			t.Fatalf("accepted kind %q sev %q", kind, sev)
		}
		b2, _ := MarshalEvent(e, cut)
		if string(b) != string(b2) {
			t.Fatal("not deterministic")
		}
		if cut && ip != "" {
			if c, ok := CutAddress(ip); ok && !strings.Contains(string(b), `"ip":"`+c+`"`) {
				t.Fatalf("ip %q was not cut to %q in %s", ip, c, b)
			}
		}
	})
}

// FuzzHandlerNeverPanics sends arbitrary targets and Authorization values to the handler. Whatever comes, the answer
// is one of the documented statuses with a JSON body, and the source is never asked anything unless the request was
// correctly signed (which random input never is).
func FuzzHandlerNeverPanics(f *testing.F) {
	f.Add("/feed", "SFW1 key="+testKeyID+", ts=1791014400, nonce="+vectorNonce+", sig="+vectorSig, "GET")
	f.Add("/feed?since=%zz&scopes=,,,", "", "GET")
	f.Add("*", "x", "OPTIONS")
	f.Add("//feed", "SFW1", "POST")
	f.Fuzz(func(t *testing.T, target, auth, method string) {
		r := newRig(t)
		req := &http.Request{Method: method, RequestURI: target, Header: http.Header{}}
		req.URL = &url.URL{Path: "/"}
		if auth != "" {
			req.Header["Authorization"] = []string{auth}
		}
		w := httptest.NewRecorder()
		r.h.ServeHTTP(w, req)
		switch w.Code {
		case 200, 400, 401, 403, 404, 405, 429, 500:
		default:
			t.Fatalf("status %d", w.Code)
		}
		if w.Code == 200 {
			t.Fatalf("random input was answered: %q %q %q", method, target, auth)
		}
		if len(r.src.calls) != 0 {
			t.Fatalf("the source was asked about an unsigned request: %v", r.src.calls)
		}
	})
}
