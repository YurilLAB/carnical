// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type failedRequestBody struct {
	io.Reader
	readErr, closeErr error
}

func (b failedRequestBody) Read(p []byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.Reader.Read(p)
}
func (b failedRequestBody) Close() error { return b.closeErr }

// This command had no test home. Real HTTP exchanges verify that the runner
// reports transport/body failures separately from a completed WAF decision.
func TestHTTPExchange(t *testing.T) {
	var reached atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		if r.URL.Path == "/truncated" {
			w.Header().Set("Content-Length", "10")
		}
		if _, err := io.WriteString(w, "ok"); err != nil {
			t.Error(err)
		}
	}))
	defer origin.Close()
	readErr, closeErr := errors.New("request read failed"), errors.New("request close failed")
	for _, tc := range []struct {
		name, path                string
		body                      io.ReadCloser
		framing                   string
		wantReadErr, wantCloseErr bool
		wantStatus                int
		wantReached               int32
	}{
		{name: "complete response", path: "/", body: io.NopCloser(strings.NewReader("hello")), wantStatus: 200, wantReached: 1},
		{name: "truncated response", path: "/truncated", body: http.NoBody, wantStatus: 200, wantReached: 1},
		{name: "request close failure", path: "/", body: failedRequestBody{Reader: strings.NewReader("hello"), closeErr: closeErr}, wantCloseErr: true},
		{name: "request read and close failure", path: "/", body: failedRequestBody{readErr: readErr, closeErr: closeErr}, wantReadErr: true, wantCloseErr: true},
		{name: "malformed framing still reaches HTTP refusal", path: "/", body: http.NoBody, framing: "invalid", wantStatus: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, origin.URL+tc.path, tc.body)
			if err != nil {
				t.Fatal(err)
			}
			if tc.framing != "" {
				req.Header.Set("Content-Length", tc.framing)
			}
			before := reached.Load()
			res, err := rawDo(req)
			if errors.Is(err, readErr) != tc.wantReadErr || errors.Is(err, closeErr) != tc.wantCloseErr {
				t.Fatalf("request errors lost: %v", err)
			}
			if tc.wantReadErr || tc.wantCloseErr {
				if res != nil {
					t.Fatal("failed request produced a response")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				_, readBodyErr := io.Copy(io.Discard, res.Body)
				closeBodyErr := res.Body.Close()
				if res.StatusCode != tc.wantStatus || closeBodyErr != nil {
					t.Fatalf("response: status %d, close %v", res.StatusCode, closeBodyErr)
				}
				if tc.path == "/truncated" {
					if !errors.Is(readBodyErr, io.ErrUnexpectedEOF) {
						t.Fatalf("truncated response accepted: %v", readBodyErr)
					}
				} else if readBodyErr != nil {
					t.Fatal(readBodyErr)
				}
			}
			if got := reached.Load() - before; got != tc.wantReached {
				t.Fatalf("origin reached %d times, want %d", got, tc.wantReached)
			}
		})
	}
	t.Run("corpus paths retain the owned destination", func(t *testing.T) {
		for _, uri := range []string{"/", "//elsewhere.invalid/a", "/@elsewhere.invalid/a", "/%2f%2felsewhere.invalid/a", "/path?next=http://elsewhere.invalid", "@elsewhere.invalid/a", "http://elsewhere.invalid/a"} {
			c := testCase{Request: request{Method: "GET", URI: uri, Headers: map[string]string{"Host": "elsewhere.invalid:80"}}}
			req, err := prepare(c, origin.URL, 1)
			if !strings.HasPrefix(uri, "/") {
				if err == nil {
					t.Fatalf("non-path target accepted: %q", uri)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if "http://"+req.URL.Host != origin.URL || req.Host != "elsewhere.invalid:80" {
				t.Fatalf("corpus changed destination: %q => %v", uri, req.URL)
			}
			if req.Body != nil {
				if err := req.Body.Close(); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}
