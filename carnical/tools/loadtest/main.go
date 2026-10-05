// SPDX-License-Identifier: Apache-2.0

// Command loadtest runs the compiled Carnical WAF against a counted loopback origin.
// Corpus hostnames are never contacted. Availability failures are not detections.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type request struct {
	Method  string
	URI     string
	Headers map[string]string
	Body    string
	Files   []struct{ Field, Name, Content string }
}
type sample struct {
	Category, Group string
	Note            string
	Request         request
}
type testCase struct {
	Name        string
	Attack      bool
	Request     request
	Description string
	Parent      string `json:"Parent,omitempty"`
	Variation   string `json:"Variation,omitempty"`
}
type result struct {
	Name                              string
	Attack                            bool
	Requests, Errors                  int
	Statuses                          map[int]int
	ErrorExamples                     []string "json:\"error_examples,omitempty\""
	OriginReached                     int64
	Method, URI, WireURI, Description string
	Parent, Variation, RequestSHA256  string
	LatencyUS                         []int64 "json:\"-\""
}
type report struct {
	Suite, SuiteSHA256                                                                       string
	Scheduling                                                                               string
	UniqueAttackTemplates, UniqueBenignTemplates                                             int
	CategoryResults                                                                          []categoryResult
	AdmittedAttacks                                                                          []admittedAttack
	BinarySHA256, BenignCorpusSHA256, AttackCorpusSHA256                                     string
	Started, Completed, OS, Go, Binary                                                       string
	CPUs, Count, Concurrency, RPSLimit                                                       int
	WAFArgs                                                                                  []string
	ElapsedSeconds, RequestsPerSecond, LatencyP50MS, LatencyP95MS, LatencyP99MS              float64
	BenignRequests, BenignPassed, BenignRefused, AttackRequests, AttackRefused, AttackPassed int
	OriginBenign, OriginAttacks                                                              int64
	Unavailable, TransportErrors                                                             int
	Results                                                                                  []result
	LogRules                                                                                 map[int]int
	LogLines                                                                                 int
}

type admittedAttack struct {
	result
	Request request
}

type categoryResult struct {
	Category                                                                             string
	AttackCases, AdmittedAttackCases, BenignCases                                        int
	AttackRequests, AttackRefused, BenignRequests, BenignRefused, Errors, Unavailable    int
	AttackOrigin, BenignOrigin                                                           int64
	UniqueAttackTemplates, UniqueBenignTemplates, VariantAttackCases, VariantBenignCases int
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Go's HTTP client rejects malformed headers and normalizes framing. These cases
// use a raw connection to the same loopback WAF so they count as real requests.
func needsRaw(req *http.Request) bool {
	if req.Header.Get("Content-Length") != "" || req.Header.Get("Transfer-Encoding") != "" {
		return true
	}
	for _, values := range req.Header {
		for _, value := range values {
			for _, c := range []byte(value) {
				if c < 0x20 && c != '\t' || c == 0x7f {
					return true
				}
			}
		}
	}
	return false
}

func rawDo(req *http.Request) (*http.Response, error) {
	conn, err := net.DialTimeout("tcp", req.URL.Host, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	var body []byte
	if req.Body != nil {
		body, err = io.ReadAll(req.Body)
		req.Body.Close()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	var head strings.Builder
	fmt.Fprintf(&head, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, req.URL.RequestURI(), req.Host)
	var names []string
	for name := range req.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range req.Header[name] {
			fmt.Fprintf(&head, "%s: %s\r\n", name, value)
		}
	}
	if req.Header.Get("Content-Length") == "" && req.Header.Get("Transfer-Encoding") == "" {
		fmt.Fprintf(&head, "Content-Length: %d\r\n", len(body))
	}
	if req.Header.Get("Connection") == "" {
		head.WriteString("Connection: close\r\n")
	}
	head.WriteString("\r\n")
	if _, err = io.WriteString(conn, head.String()+string(body)); err != nil {
		conn.Close()
		return nil, err
	}
	// Signal the end of intentionally incomplete framing without waiting for a
	// timeout, while keeping the read side open for the server's refusal.
	if tcp, ok := conn.(*net.TCPConn); ok && (req.Header.Get("Content-Length") != "" || req.Header.Get("Transfer-Encoding") != "") {
		if err = tcp.CloseWrite(); err != nil {
			conn.Close()
			return nil, err
		}
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	res.Body = &rawBody{ReadCloser: res.Body, conn: conn}
	return res, nil
}

type rawBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *rawBody) Close() error { err := b.ReadCloser.Close(); _ = b.conn.Close(); return err }

func fileHash(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func readCorpus(path string, attack bool) ([]testCase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 4<<20)
	var out []testCase
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var s sample
		if err := json.Unmarshal(sc.Bytes(), &s); err != nil {
			return nil, err
		}
		category := s.Group
		if attack {
			category = s.Category
		}
		out = append(out, testCase{Name: fmt.Sprintf("%s/%d", category, len(out)), Attack: attack, Request: s.Request, Description: s.Note})
	}
	return out, sc.Err()
}

func prepare(c testCase, target string, index int) (*http.Request, error) {
	r := c.Request
	body := r.Body
	headers := make(http.Header)
	host := "www.example.com.au"
	for k, v := range r.Headers {
		if strings.EqualFold(k, "Host") {
			host = v
			continue
		}
		headers.Set(k, v)
	}
	if len(r.Files) > 0 {
		boundary := "CarnicalLoadBoundary"
		var b strings.Builder
		for _, f := range r.Files {
			fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=%q; filename=%q\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n", boundary, f.Field, f.Name, f.Content)
		}
		fmt.Fprintf(&b, "--%s--\r\n", boundary)
		body = b.String()
		headers.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	}
	// Encode spaces/non-ASCII/punctuation as the existing corpus harness does.
	// Existing percent escapes and query delimiters retain their wire spelling.
	var escaped strings.Builder
	for _, b := range []byte(r.URI) {
		if b > 0x20 && b < 0x7f && b != 0x60 && !strings.ContainsRune("#\"<>\\^{|}", rune(b)) {
			escaped.WriteByte(b)
		} else {
			fmt.Fprintf(&escaped, "%%%02X", b)
		}
	}
	if !strings.HasPrefix(escaped.String(), "/") {
		return nil, fmt.Errorf("corpus target must start with /")
	}
	req, err := http.NewRequest(r.Method, target+escaped.String(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	if req.URL.Fragment != "" || req.URL.RequestURI() != escaped.String() {
		return nil, fmt.Errorf("corpus URI changed during request construction")
	}
	req.Host, req.Header = host, headers
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0")
	}
	req.Header.Set("X-Loadtest-Case", strconv.Itoa(index))
	return req, nil
}

func probes() []testCase {
	add := func(name, method, uri, ct, body string, attack bool) testCase {
		h := map[string]string{}
		if ct != "" {
			h["Content-Type"] = ct
		}
		return testCase{Name: "regression/" + name, Attack: attack, Request: request{Method: method, URI: uri, Headers: h, Body: body}, Description: name}
	}
	var out []testCase
	for _, p := range []struct {
		name, method, uri, ct, body string
		attack                      bool
	}{
		{"graphql-get-query", "GET", "/graphql?query=%7Buser%7Bid%7D%7D", "", "", false},
		{"graphql-post-mutation", "POST", "/graphql", "application/json", "{\"query\":\"mutation{updateUser}\"}", false},
		{"json-order", "POST", "/api/orders", "application/json", "{\"product_id\":23,\"quantity\":2}", false},
		{"graphql-get-mutation", "GET", "/graphql?query=mutation%7BdeleteUser%7D", "", "", true},
		{"graphql-head-mutation", "HEAD", "/api/gql?%71uery=mutation%7BdeleteUser%7D", "", "", true},
		{"graphql-protocol-alias", "HEAD", "/graphql?QUERY=mutation%7BdeleteUser%7D", "", "", true},
		{"graphql-mixed-selection", "POST", "/graphql?operationName=Read", "application/json", "{\"query\":\"query Read{a} mutation Write{b}\",\"operationName\":\"Write\"}", true},
		{"graphql-method-metadata", "POST", "/graphql?_method=GET", "application/json", "{\"query\":\"mutation{deleteUser}\"}", true},
		{"graphql-hidden-batch", "PUT", "/api/gql", "application/json", "[{},{\"query\":\"mutation{deleteUser}\"}]", true},
		{"graphql-deep", "POST", "/graphql", "application/json", "{\"query\":\"" + strings.Repeat("{a", 14) + strings.Repeat("}", 14) + "\"}", true},
		{"duplicate-json", "POST", "/api/orders", "application/json", "{\"role\":\"user\",\"role\":\"admin\"}", true},
		{"xxe", "POST", "/api/xml", "application/xml", "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>", true},
		{"query-nul", "GET", "/api?x=%00", "", "", true},
		{"query-semicolon", "GET", "/api?x=1;y=2", "", "", true},
		{"query-prototype", "GET", "/api?__proto__%5Badmin%5D=1", "", "", true},
	} {
		out = append(out, add(p.name, p.method, p.uri, p.ct, p.body, p.attack))
	}
	p := add("method-override-header", "POST", "/api/orders", "application/json", "{\"id\":1}", true)
	p.Request.Headers["X-HTTP-Method-Override"] = "GET"
	return append(out, p)
}

func run() error {
	binary := flag.String("binary", "", "compiled Carnical executable (required)")
	corpus := flag.String("corpus", "", "directory with benign.jsonl and attack.jsonl (required)")
	output := flag.String("output", "", "JSON report path (required); WAF logs go alongside it")
	count := flag.Int("count", 500000, "number of measured requests")
	concurrency := flag.Int("concurrency", 16, "concurrent clients")
	rps := flag.Int("rps", 0, "global requests/second cap (0 = unpaced)")
	extended := flag.Bool("extended", false, "add six attack families and their benign controls")
	variants := flag.Bool("variants", false, "vary all attack categories and benign controls; implies -extended and alternates attack/benign requests")
	flag.Parse()
	if *binary == "" || *corpus == "" || *output == "" || *count < 1 || *concurrency < 1 || *concurrency > 128 || *rps < 0 {
		return fmt.Errorf("invalid flags")
	}
	b, err := readCorpus(filepath.Join(*corpus, "benign.jsonl"), false)
	if err != nil {
		return err
	}
	a, err := readCorpus(filepath.Join(*corpus, "attack.jsonl"), true)
	if err != nil {
		return err
	}
	cases := append(append(b, a...), probes()...)
	suite := "baseline-v1"
	if *extended || *variants {
		cases = append(cases, extendedCases()...)
		suite = "extended-v1"
	}
	if *variants {
		cases = append(cases, syntaxCases()...)
		generated, err := variedCases(cases)
		if err != nil {
			return err
		}
		cases = append(cases, generated...)
		suite = "variants-v1"
	}
	if len(cases) == 0 {
		return fmt.Errorf("empty corpus")
	}
	var attackIndexes, benignIndexes []int
	for i, c := range cases {
		if c.Attack {
			attackIndexes = append(attackIndexes, i)
		} else {
			benignIndexes = append(benignIndexes, i)
		}
	}
	if *variants && (len(attackIndexes) == 0 || len(benignIndexes) == 0 || *count < 2*max(len(attackIndexes), len(benignIndexes))) {
		return fmt.Errorf("variants require both classes and at least %d requests to exercise every template", 2*max(len(attackIndexes), len(benignIndexes)))
	}
	originCounts := make([]atomic.Int64, len(cases))
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if i, e := strconv.Atoi(r.Header.Get("X-Loadtest-Case")); e == nil && i >= 0 && i < len(cases) {
			originCounts[i].Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Loadtest-Origin", "counted-local-origin")
		_, _ = io.WriteString(w, "{\"ok\":true}")
	}))
	defer origin.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if err = os.MkdirAll(filepath.Dir(*output), 0700); err != nil {
		return err
	}
	logPath := *output + ".waf.log"
	logFile, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer logFile.Close()
	args := []string{"-listen", addr, "-upstream", origin.URL, "-origin-allow", "127.0.0.1/32", "-mode", "block", "-formats-mode", "block", "-inspect-responses", "-formats-stats-interval", "5s"}
	cmd := exec.Command(*binary, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err = cmd.Start(); err != nil {
		return err
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	defer func() { _ = cmd.Process.Kill(); <-waited }()
	transport := &http.Transport{MaxIdleConns: *concurrency * 2, MaxIdleConnsPerHost: *concurrency, MaxConnsPerHost: *concurrency}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	target := "http://" + addr
	ready := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		res, e := client.Get(target + "/__loadtest_ready")
		if e == nil {
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode == 200 {
				ready = true
				break
			}
		}
		select {
		case e := <-waited:
			waited <- e
			return fmt.Errorf("WAF exited during startup: %v", e)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		return fmt.Errorf("WAF did not become ready; see %s", logPath)
	}
	templates := make([]*http.Request, len(cases))
	seenNames := make(map[string]bool, len(cases))
	for i, c := range cases {
		if seenNames[c.Name] {
			return fmt.Errorf("duplicate case name %q", c.Name)
		}
		seenNames[c.Name] = true
		templates[i], err = prepare(c, target, i)
		if err != nil {
			return fmt.Errorf("case %s: %w", c.Name, err)
		}
	}
	fmt.Printf("WAF pid=%d loopback=%s suite=%s samples=%d (%d benign templates, %d attack templates) requests=%d concurrency=%d\n", cmd.Process.Pid, addr, suite, len(cases), len(benignIndexes), len(attackIndexes), *count, *concurrency)
	results := make([]result, len(cases))
	wireLabels := map[string]bool{}
	for i, c := range cases {
		key, err := wireFingerprint(templates[i])
		if err != nil {
			return err
		}
		if label, exists := wireLabels[key]; exists && label != c.Attack {
			return fmt.Errorf("conflicting labels for constructed request %s", c.Name)
		}
		wireLabels[key] = c.Attack
		results[i] = result{Name: c.Name, Attack: c.Attack, Method: c.Request.Method, URI: c.Request.URI, WireURI: templates[i].URL.RequestURI(), Description: c.Description, Parent: c.Parent, Variation: c.Variation, RequestSHA256: key, Statuses: map[int]int{}}
	}
	var next, done atomic.Int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := time.Now()
	for worker := 0; worker < *concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n := int(next.Add(1) - 1)
				if n >= *count {
					return
				}
				if *rps > 0 {
					deadline := start.Add(time.Duration(n) * time.Second / time.Duration(*rps))
					if d := time.Until(deadline); d > 0 {
						time.Sleep(d)
					}
				}
				i := n % len(cases)
				if *variants {
					if n%2 == 0 {
						i = attackIndexes[(n/2)%len(attackIndexes)]
					} else {
						i = benignIndexes[(n/2)%len(benignIndexes)]
					}
				}
				tmpl := templates[i]
				req := tmpl.Clone(context.Background())
				if tmpl.GetBody != nil {
					req.Body, _ = tmpl.GetBody()
				}
				t := time.Now()
				var res *http.Response
				var e error
				if needsRaw(req) {
					res, e = rawDo(req)
				} else {
					res, e = client.Do(req)
				}
				status := 0
				if e == nil {
					status = res.StatusCode
					_, e = io.Copy(io.Discard, res.Body)
					res.Body.Close()
				}
				latency := time.Since(t).Microseconds()
				mu.Lock()
				r := &results[i]
				r.Requests++
				r.LatencyUS = append(r.LatencyUS, latency)
				if e != nil {
					r.Errors++
					if len(r.ErrorExamples) < 2 {
						r.ErrorExamples = append(r.ErrorExamples, e.Error())
					}
				} else {
					r.Statuses[status]++
				}
				mu.Unlock()
				done.Add(1)
			}
		}()
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	running := true
	for running {
		select {
		case <-finished:
			running = false
		case <-ticker.C:
			fmt.Printf("progress %d/%d elapsed=%.1fs rate=%.1f/s\n", done.Load(), *count, time.Since(start).Seconds(), float64(done.Load())/time.Since(start).Seconds())
		}
	}
	elapsed := time.Since(start)
	rep := report{Started: start.UTC().Format(time.RFC3339), Completed: time.Now().UTC().Format(time.RFC3339), OS: runtime.GOOS, Go: runtime.Version(), CPUs: runtime.NumCPU(), Binary: *binary, WAFArgs: args, Count: *count, Concurrency: *concurrency, RPSLimit: *rps, ElapsedSeconds: elapsed.Seconds(), RequestsPerSecond: float64(*count) / elapsed.Seconds(), Results: results, LogRules: map[int]int{}}
	rep.Suite = suite
	rep.Scheduling = "cyclic-all-templates"
	if *variants {
		rep.Scheduling = "alternating-classes-cyclic-within-class"
	}
	suiteBytes, err := json.Marshal(cases)
	if err != nil {
		return err
	}
	rep.SuiteSHA256 = fmt.Sprintf("%x", sha256.Sum256(suiteBytes))
	if rep.BinarySHA256, err = fileHash(*binary); err != nil {
		return err
	}
	if rep.BenignCorpusSHA256, err = fileHash(filepath.Join(*corpus, "benign.jsonl")); err != nil {
		return err
	}
	if rep.AttackCorpusSHA256, err = fileHash(filepath.Join(*corpus, "attack.jsonl")); err != nil {
		return err
	}
	var latencies []int64
	for i := range rep.Results {
		r := &rep.Results[i]
		r.OriginReached = originCounts[i].Load()
		rep.TransportErrors += r.Errors
		latencies = append(latencies, r.LatencyUS...)
		if r.Attack {
			rep.AttackRequests += r.Requests
			rep.OriginAttacks += r.OriginReached
		} else {
			rep.BenignRequests += r.Requests
			rep.OriginBenign += r.OriginReached
		}
		for s, n := range r.Statuses {
			if s >= 500 && s != 501 {
				rep.Unavailable += n
				continue
			}
			if s == 200 {
				if r.Attack {
					rep.AttackPassed += n
				} else {
					rep.BenignPassed += n
				}
				continue
			}
			if s >= 400 && s < 500 || s == 501 {
				if r.Attack {
					rep.AttackRefused += n
				} else {
					rep.BenignRefused += n
				}
			}
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	percentile := func(p float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		return float64(latencies[int(float64(len(latencies)-1)*p)]) / 1000
	}
	rep.LatencyP50MS, rep.LatencyP95MS, rep.LatencyP99MS = percentile(.5), percentile(.95), percentile(.99)
	categories := map[string]*categoryResult{}
	uniqueAttacks, uniqueBenign := map[string]bool{}, map[string]bool{}
	categoryUnique := map[string]map[string]bool{}
	for i, r := range rep.Results {
		name := strings.SplitN(r.Name, "/", 2)[0]
		cat := categories[name]
		if cat == nil {
			cat = &categoryResult{Category: name}
			categories[name] = cat
			categoryUnique[name] = map[string]bool{}
		}
		cat.Errors += r.Errors
		if r.Attack {
			cat.AttackCases++
			if r.Variation != "" {
				cat.VariantAttackCases++
			}
			uniqueAttacks[r.RequestSHA256] = true
			if !categoryUnique[name][r.RequestSHA256] {
				cat.UniqueAttackTemplates++
			}
			cat.AttackRequests += r.Requests
			cat.AttackOrigin += r.OriginReached
			if r.OriginReached > 0 {
				cat.AdmittedAttackCases++
				rep.AdmittedAttacks = append(rep.AdmittedAttacks, admittedAttack{result: r, Request: cases[i].Request})
			}
		} else {
			cat.BenignCases++
			if r.Variation != "" {
				cat.VariantBenignCases++
			}
			uniqueBenign[r.RequestSHA256] = true
			if !categoryUnique[name][r.RequestSHA256] {
				cat.UniqueBenignTemplates++
			}
			cat.BenignRequests += r.Requests
			cat.BenignOrigin += r.OriginReached
		}
		categoryUnique[name][r.RequestSHA256] = true
		for status, n := range r.Statuses {
			if status >= 500 && status != 501 {
				cat.Unavailable += n
			} else if status >= 400 && status < 500 || status == 501 {
				if r.Attack {
					cat.AttackRefused += n
				} else {
					cat.BenignRefused += n
				}
			}
		}
	}
	rep.UniqueAttackTemplates, rep.UniqueBenignTemplates = len(uniqueAttacks), len(uniqueBenign)
	for _, cat := range categories {
		rep.CategoryResults = append(rep.CategoryResults, *cat)
	}
	sort.Slice(rep.CategoryResults, func(i, j int) bool { return rep.CategoryResults[i].Category < rep.CategoryResults[j].Category })
	sort.Slice(rep.AdmittedAttacks, func(i, j int) bool { return rep.AdmittedAttacks[i].Name < rep.AdmittedAttacks[j].Name })
	lf, e := os.Open(logPath)
	if e != nil {
		return fmt.Errorf("read WAF log: %w", e)
	}
	{
		sc := bufio.NewScanner(lf)
		sc.Buffer(make([]byte, 4096), 1<<20)
		for sc.Scan() {
			var event struct{ Rule int }
			if json.Unmarshal(sc.Bytes(), &event) == nil {
				rep.LogLines++
				if event.Rule != 0 {
					rep.LogRules[event.Rule]++
				}
			}
		}
		scanErr := sc.Err()
		closeErr := lf.Close()
		if scanErr != nil {
			return fmt.Errorf("scan WAF log: %w", scanErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close WAF log: %w", closeErr)
		}
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(*output, append(data, '\n'), 0600); err != nil {
		return err
	}
	fmt.Printf("DONE %d requests %.1f/s p50=%.3fms p95=%.3fms p99=%.3fms benign=%d/%d passed attacks=%d/%d refused attacks_at_origin=%d unavailable=%d transport_errors=%d report=%s\n", *count, rep.RequestsPerSecond, rep.LatencyP50MS, rep.LatencyP95MS, rep.LatencyP99MS, rep.BenignPassed, rep.BenignRequests, rep.AttackRefused, rep.AttackRequests, rep.OriginAttacks, rep.Unavailable, rep.TransportErrors, *output)
	return nil
}
