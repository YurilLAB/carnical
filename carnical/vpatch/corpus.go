// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// Limits on reading a sample or corpus file.
const (
	maxSampleLine  = 4 << 20
	maxSampleBytes = 512 << 20
	maxSamples     = 1000000
)

// A Sample is one request from a samples file or a replay corpus, with what the file says about it.
type Sample struct {
	// Sig is the signature a sample was written for (samples files only).
	Sig string
	// Kind is "attack" or "benign".
	Kind string
	// Group is the corpus' category or group of the request.
	Group   string
	Note    string
	Request *inspect.Request
	// Alt is the same request read the other way, if it can be read two ways (see sampleRequest.build); nil otherwise.
	Alt *inspect.Request
}

type sampleRequest struct {
	Method  string            `json:"method"`
	URI     string            `json:"uri"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Files   []sampleFile      `json:"files"`
}

type sampleFile struct {
	Field   string `json:"field"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

type sampleLine struct {
	Sig      string        `json:"sig"`
	Kind     string        `json:"kind"`
	Category string        `json:"category"`
	Group    string        `json:"group"`
	Note     string        `json:"note"`
	Request  sampleRequest `json:"request"`
}

// ReadSamples reads a samples file: JSON lines of {"sig", "kind", "request": {"method", "uri", "headers", "body"}}.
func ReadSamples(r io.Reader) ([]Sample, error) { return readSamples(r, "") }

// ReadCorpus reads a replay corpus: JSON lines of {"request": {...}, "group" or "category": ...}. Every request gets the given kind
// ("attack" or "benign"). A request with "files" is built as a multipart/form-data body with those files, using the boundary named
// in its Content-Type.
func ReadCorpus(r io.Reader, kind string) ([]Sample, error) { return readSamples(r, kind) }

func readSamples(r io.Reader, kind string) ([]Sample, error) {
	sc := bufio.NewScanner(io.LimitReader(r, maxSampleBytes))
	sc.Buffer(make([]byte, 0, 64<<10), maxSampleLine)
	var out []Sample
	for line := 1; sc.Scan(); line++ {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var l sampleLine
		if err := json.Unmarshal(raw, &l); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if len(out) >= maxSamples {
			return nil, fmt.Errorf("more than %d samples", maxSamples)
		}
		k := kind
		if k == "" {
			k = l.Kind
		}
		g := l.Group
		if g == "" {
			g = l.Category
		}
		req, alt := l.Request.build()
		out = append(out, Sample{Sig: l.Sig, Kind: k, Group: g, Note: l.Note, Request: req, Alt: alt})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// build turns a recorded request into the form the proxy hands an inspector. The URI is split at the first '?' and not otherwise
// touched, because a sample is written as it was sent.
//
// A URI that ends in a bare '?' is a problem: inspect.Request has no way to say "an empty query was sent", and a signature may
// test for "page.php?" on the URI or for a path that ends at "page.php". The request is built with the clean path and alt is the
// same request with the '?' kept at the end of the path; callers that check samples try both.
func (s sampleRequest) build() (req, alt *inspect.Request) {
	req = &inspect.Request{Method: s.Method, Header: http.Header{}}
	path, query := s.URI, ""
	bare := false
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, query = path[:i], path[i+1:]
		bare = query == ""
	}
	req.Path, req.RawQuery = path, query
	hostGiven := false
	for k, v := range s.Headers {
		if strings.EqualFold(k, "host") {
			req.Host, hostGiven = v, true
			continue
		}
		req.Header[http.CanonicalHeaderKey(k)] = []string{v}
	}
	if !hostGiven {
		// The proxy never sees a request with no Host (an HTTP/1.1 request without one is refused before it gets here), so a
		// sample that names none is given the usual one. A sample that names an empty Host keeps it: that is a test of its own.
		req.Host = "localhost"
	}
	if len(s.Files) > 0 {
		req.Body = multipartBody(req.Header.Get("Content-Type"), s.Files)
	} else if s.Body != "" {
		req.Body = []byte(s.Body)
	}
	if bare {
		a := *req
		a.Path = path + "?"
		alt = &a
	}
	return req, alt
}

func multipartBody(contentType string, files []sampleFile) []byte {
	_, params, _ := mime.ParseMediaType(contentType)
	boundary := params["boundary"]
	if boundary == "" {
		boundary = "----carnicalboundary"
	}
	var b bytes.Buffer
	for _, f := range files {
		fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=%q; filename=%q\r\nContent-Type: application/octet-stream\r\n\r\n", boundary, f.Field, f.Name)
		b.Write(latin1OrUTF8(f.Content))
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes()
}

// latin1OrUTF8 turns a JSON string back into bytes: if every character fits in one byte it was a binary file written as Latin-1
// (a JPEG's first bytes, say), otherwise it is text.
func latin1OrUTF8(s string) []byte {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r < 0 || r > 0xFF {
			return []byte(s)
		}
		b = append(b, byte(r))
	}
	return b
}
