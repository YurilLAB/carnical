// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func entry(i int) AuditEntry {
	rb, ra := uint64(i), uint64(i+1)
	return AuditEntry{RequestID: "req_" + strconv.Itoa(1000+i), Credential: "ui-a", Tenant: tenantA, User: "user-1", Action: "policy.put",
		RevBefore: &rb, RevAfter: &ra, Changes: []string{"mode_lowered"}, Source: "198.51.100.10", Outcome: "ok"}
}

func openAudit(t *testing.T) (*FileAudit, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := OpenFileAudit(path, func() time.Time { return epoch })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a, path
}

func goodLog(t *testing.T, n int) (string, []byte) {
	t.Helper()
	a, path := openAudit(t)
	for i := 1; i <= n; i++ {
		if err := a.Append(entry(i)); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, b
}

func TestFileAuditBuildsAChain(t *testing.T) {
	a, path := openAudit(t)
	syncs := 0
	realSync := a.sync
	a.sync = func() error { syncs++; return realSync() }
	for i := 1; i <= 5; i++ {
		if err := a.Append(entry(i)); err != nil {
			t.Fatal(err)
		}
	}
	if syncs != 5 {
		t.Fatalf("%d flushes for 5 lines: every line must be on disk before Append returns", syncs)
	}
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("%d lines", len(lines))
	}
	prev := zeroHash
	for i, l := range lines {
		var e AuditEntry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		if e.Seq != uint64(i+1) || e.Prev != prev || e.Time != epoch.Format(time.RFC3339) {
			t.Fatalf("line %d: %+v", i+1, e)
		}
		sum := sha256.Sum256([]byte(l))
		prev = hex.EncodeToString(sum[:])
	}
	seq, head := a.Head()
	if seq != 5 || head != prev {
		t.Fatalf("head %d %s, want 5 %s", seq, head, prev)
	}
	rep, err := VerifyChain(bytes.NewReader(b))
	if err != nil || rep.Lines != 5 || rep.HeadSeq != 5 || rep.HeadHash != prev {
		t.Fatalf("%+v %v", rep, err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %o", st.Mode().Perm())
		}
	}
	if !strings.Contains(lines[0], `"seq":1`) || !strings.Contains(lines[0], `"prev":"`+zeroHash+`"`) {
		t.Fatalf("first line: %s", lines[0])
	}
	// every field the design names is in the line
	for _, f := range []string{`"credential":"ui-a"`, `"tenant":"` + tenantA + `"`, `"user":"user-1"`, `"action":"policy.put"`, `"rev_before":1`, `"rev_after":2`,
		`"changes":["mode_lowered"]`, `"source":"198.51.100.10"`, `"outcome":"ok"`, `"request_id":"req_1001"`} {
		if !strings.Contains(lines[0], f) {
			t.Fatalf("line lacks %s: %s", f, lines[0])
		}
	}
}

// rewrite recomputes the chain for lines, so an attacker who can write the whole file is modelled.
func rechain(t *testing.T, lines []string) []string {
	t.Helper()
	prev := zeroHash
	out := make([]string, len(lines))
	for i, l := range lines {
		var e AuditEntry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		e.Seq, e.Prev = uint64(i+1), prev
		b, _ := json.Marshal(e)
		out[i] = string(b)
		sum := sha256.Sum256(b)
		prev = hex.EncodeToString(sum[:])
	}
	return out
}

func TestChainTamperingIsFound(t *testing.T) {
	_, good := goodLog(t, 6)
	lines := strings.Split(strings.TrimSuffix(string(good), "\n"), "\n")
	join := func(ls []string) string { return strings.Join(ls, "\n") + "\n" }
	edit := func(i int, from, to string) string {
		out := append([]string(nil), lines...)
		if !strings.Contains(out[i], from) {
			t.Fatalf("line %d lacks %q: %s", i+1, from, out[i])
		}
		out[i] = strings.Replace(out[i], from, to, 1)
		return join(out)
	}
	remove := func(i int) []string { return append(append([]string(nil), lines[:i]...), lines[i+1:]...) }
	insertAt := func(i int, l string) []string {
		return append(append(append([]string(nil), lines[:i]...), l), lines[i:]...)
	}
	_, head := func() (uint64, string) {
		rep, err := VerifyChain(bytes.NewReader(good))
		if err != nil {
			t.Fatal(err)
		}
		return rep.HeadSeq, rep.HeadHash
	}()

	rows := []struct {
		name   string
		log    string
		line   int    // the first line the chain reports as broken; 0 when the chain alone cannot see it
		reason string // part of the reason
	}{
		{"an untouched log", string(good), 0, ""},
		{"the credential of line 3 edited", edit(2, `"credential":"ui-a"`, `"credential":"ui-b"`), 4, "hash of the line before"},
		{"the tenant of line 3 edited", edit(2, tenantA, tenantB), 4, "hash of the line before"},
		{"the user of line 3 edited", edit(2, `"user":"user-1"`, `"user":"user-9"`), 4, "hash of the line before"},
		{"the action of line 3 edited", edit(2, `"action":"policy.put"`, `"action":"policy.get"`), 4, "hash of the line before"},
		{"the outcome of line 3 edited", edit(2, `"outcome":"ok"`, `"outcome":"no"`), 4, "hash of the line before"},
		{"the change codes of line 3 removed", edit(2, `"changes":["mode_lowered"],`, ``), 4, "hash of the line before"},
		{"the source of line 3 edited", edit(2, `198.51.100.10`, `198.51.100.11`), 4, "hash of the line before"},
		{"the revisions of line 3 edited", edit(2, `"rev_after":4`, `"rev_after":9`), 4, "hash of the line before"},
		{"the time of line 2 edited", edit(1, epoch.Format(time.RFC3339), `2020-01-01T00:00:00Z`), 3, "hash of the line before"},
		{"the sequence number of line 3 edited", edit(2, `"seq":3`, `"seq":7`), 3, "sequence number"},
		{"the prev of line 3 edited", edit(2, `"prev":"`+lineHash(lines[1])[:8], `"prev":"deadbeef`), 3, "hash of the line before"},
		{"line 1 deleted", join(remove(0)), 1, "sequence number"},
		{"line 3 deleted", join(remove(2)), 3, "sequence number"},
		{"the last line deleted", join(remove(5)), 0, ""},
		{"the last two lines deleted", join(lines[:4]), 0, ""},
		{"line 2 duplicated", join(insertAt(2, lines[1])), 3, "sequence number"},
		{"lines 2 and 3 swapped", join([]string{lines[0], lines[2], lines[1], lines[3], lines[4], lines[5]}), 2, "sequence number"},
		{"a forged line inserted after line 2", join(insertAt(2, forge(t, lines[1], 3))), 4, "sequence number"},
		{"a forged line appended", join(append(append([]string(nil), lines...), forge(t, lines[5], 7))), 0, ""},
		{"an empty line in the middle", join(insertAt(3, "")), 4, "empty line"},
		{"CRLF line endings", strings.ReplaceAll(string(good), "\n", "\r\n"), 1, "control character"},
		{"a NUL byte in a line", edit(2, `"user":"user-1"`, "\"user\":\"user\x00\""), 3, "control character"},
		{"a line that is not JSON", join(insertAt(2, "this is not json")), 3, "not one JSON object"},
		{"a line that is a JSON array", join(insertAt(2, "[1,2,3]")), 3, "not one JSON object"},
		{"an unknown field in a line", edit(2, `"outcome":"ok"`, `"outcome":"ok","extra":1`), 3, "not an audit entry"},
		{"a repeated key in a line", edit(2, `"outcome":"ok"`, `"outcome":"ok","outcome":"no"`), 3, "not one JSON object"},
		{"white space inside a line", edit(2, `"seq":3,`, `"seq":3, `), 3, "form Append writes"},
		{"a character spelled as an escape", edit(2, `"outcome":"ok"`, `"outcome":"`+esc+`u006fk"`), 3, "form Append writes"},
		{"fields in another order", func() string {
			var e AuditEntry
			_ = json.Unmarshal([]byte(lines[2]), &e)
			b, _ := json.Marshal(map[string]any{"prev": e.Prev, "seq": e.Seq, "ts": e.Time, "request_id": e.RequestID, "credential": e.Credential, "tenant": e.Tenant,
				"user": e.User, "action": e.Action, "source": e.Source, "outcome": e.Outcome})
			out := append([]string(nil), lines...)
			out[2] = string(b)
			return join(out)
		}(), 3, "form Append writes"},
		{"a line over the size limit", join(insertAt(2, strings.Repeat("x", 40000))), 3, "too long"},
		{"garbage appended with no newline", string(good) + "garbage", 7, "not finished"},
		{"the last line cut in half", string(good[:len(good)-40]), 6, "not finished"},
		{"a line that is invalid UTF-8", edit(2, `"user":"user-1"`, "\"user\":\"\xff\""), 3, "not valid UTF-8"},
		{"an entry with a negative sequence", edit(2, `"seq":3`, `"seq":-3`), 3, "not an audit entry"},
	}
	if len(rows) < 15 {
		t.Fatal("the table shrank")
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			rep, err := VerifyChain(strings.NewReader(row.log))
			if row.line == 0 {
				if err != nil {
					t.Fatalf("the chain alone cannot see this, but it reported: %v", err)
				}
				return
			}
			var ce *ChainError
			if !errors.As(err, &ce) {
				t.Fatalf("not found: %+v, %v", rep, err)
			}
			if ce.Line != row.line || !strings.Contains(ce.Reason, row.reason) {
				t.Fatalf("reported at line %d (%s), want line %d (%s)", ce.Line, ce.Reason, row.line, row.reason)
			}
			if rep.Lines != row.line-1 {
				t.Fatalf("the report counts %d good lines before the break at %d", rep.Lines, row.line)
			}
		})
	}

	t.Run("what the chain alone cannot see, the recorded head can", func(t *testing.T) {
		seq := uint64(6)
		for name, log := range map[string]string{
			"the last line deleted":        join(remove(5)),
			"the last two lines gone":      join(lines[:4]),
			"a forged line appended":       join(append(append([]string(nil), lines...), forge(t, lines[5], 7))),
			"the last line edited":         edit(5, `"outcome":"ok"`, `"outcome":"no"`),
			"the whole log rewritten":      join(rechain(t, append(append([]string(nil), lines[:2]...), strings.Replace(lines[2], `"user-1"`, `"user-9"`, 1), lines[3], lines[4], lines[5]))),
			"the log emptied":              "",
			"every line edited, rechained": join(rechain(t, mapLines(lines, func(l string) string { return strings.Replace(l, `"ok"`, `"no"`, 1) }))),
		} {
			if _, err := VerifyChain(strings.NewReader(log)); err != nil && name != "the last line edited" && name != "the log emptied" {
				t.Fatalf("%s: the chain alone should not see this: %v", name, err)
			}
			if _, err := VerifyChainHead(strings.NewReader(log), seq, head); err == nil {
				t.Fatalf("%s: the recorded head did not notice", name)
			}
		}
		if _, err := VerifyChainHead(bytes.NewReader(good), seq, head); err != nil {
			t.Fatalf("the untouched log with its head: %v", err)
		}
	})
}

func mapLines(ls []string, f func(string) string) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = f(l)
	}
	return out
}

func lineHash(l string) string {
	s := sha256.Sum256([]byte(l))
	return hex.EncodeToString(s[:])
}

// forge makes a line that looks like the one after prevLine in a chain, with sequence number seq.
func forge(t *testing.T, prevLine string, seq uint64) string {
	t.Helper()
	e := entry(int(seq))
	e.Seq, e.Prev, e.Time = seq, lineHash(prevLine), epoch.Format(time.RFC3339)
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestOpenContinuesTheChainAndRecovers(t *testing.T) {
	t.Run("a second open continues where the first stopped", func(t *testing.T) {
		path, _ := goodLog(t, 3)
		a, err := OpenFileAudit(path, func() time.Time { return epoch })
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		if seq, _ := a.Head(); seq != 3 || a.Repaired() {
			t.Fatalf("head %d repaired %v", seq, a.Repaired())
		}
		if err := a.Append(entry(4)); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(path)
		if rep, err := VerifyChain(bytes.NewReader(b)); err != nil || rep.Lines != 4 {
			t.Fatalf("%+v %v", rep, err)
		}
	})
	t.Run("an empty or new file is fine", func(t *testing.T) {
		a, path := openAudit(t)
		if seq, head := a.Head(); seq != 0 || head != zeroHash {
			t.Fatalf("%d %s", seq, head)
		}
		a.Close()
		reopened, err := OpenFileAudit(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
	})
	t.Run("a line that was never finished is cut off", func(t *testing.T) {
		path, good := goodLog(t, 3)
		if err := os.WriteFile(path, append(append([]byte(nil), good...), []byte(`{"seq":4,"ts":"20`)...), 0o600); err != nil {
			t.Fatal(err)
		}
		a, err := OpenFileAudit(path, func() time.Time { return epoch })
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		if !a.Repaired() {
			t.Fatal("not reported as repaired")
		}
		if err := a.Append(entry(4)); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(path)
		if rep, err := VerifyChain(bytes.NewReader(b)); err != nil || rep.Lines != 4 {
			t.Fatalf("%+v %v", rep, err)
		}
	})
	t.Run("a broken chain is not opened", func(t *testing.T) {
		path, good := goodLog(t, 4)
		lines := strings.Split(string(good), "\n")
		lines[1] = strings.Replace(lines[1], `"ok"`, `"no"`, 1)
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := OpenFileAudit(path, nil)
		var ce *ChainError
		if !errors.As(err, &ce) || ce.Line != 3 {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a file other users can read is not opened", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("file modes are not meaningful on Windows")
		}
		path, _ := goodLog(t, 1)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileAudit(path, nil); err == nil {
			t.Fatal("opened a world-readable audit log")
		}
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileAudit(path, nil); err == nil {
			t.Fatal("opened a group-readable audit log")
		}
	})
	t.Run("a directory that does not exist", func(t *testing.T) {
		if _, err := OpenFileAudit(filepath.Join(t.TempDir(), "no", "such", "dir", "audit.log"), nil); err == nil {
			t.Fatal("opened")
		}
	})
	t.Run("a closed log refuses lines", func(t *testing.T) {
		a, _ := openAudit(t)
		a.Close()
		if err := a.Append(entry(1)); err == nil {
			t.Fatal("appended to a closed log")
		}
		if err := a.Close(); err != nil {
			t.Fatalf("closing twice: %v", err)
		}
	})
}

func TestAFailedWriteLeavesNoHalfLine(t *testing.T) {
	t.Run("Windows repair refuses a different file", func(t *testing.T) {
		if !isWindows() {
			t.Skip("Windows uses a second repair handle")
		}
		a, _ := openAudit(t)
		other := filepath.Join(t.TempDir(), "other.log")
		const untouched = "another file must stay intact"
		if err := os.WriteFile(other, []byte(untouched), 0600); err != nil {
			t.Fatal(err)
		}
		a.path = other
		if err := a.truncate(0); err == nil {
			t.Fatal("repair accepted a different file")
		}
		contents, err := os.ReadFile(other)
		if err != nil || string(contents) != untouched {
			t.Fatalf("repair changed the other file: %q, %v", contents, err)
		}
	})
	t.Run("rollback failure closes the log", func(t *testing.T) {
		a, _ := openAudit(t)
		if err := a.Append(entry(1)); err != nil {
			t.Fatal(err)
		}
		realWrite := a.write
		a.write = func(b []byte) (int, error) {
			n, _ := realWrite(b[:len(b)/2])
			_ = a.f.Close()
			return n, errors.New("failed write and unusable repair handle")
		}
		if err := a.Append(entry(2)); err == nil || !strings.Contains(err.Error(), "rollback failed") {
			t.Fatalf("rollback failure was not reported: %v", err)
		}
		if err := a.Append(entry(3)); !errors.Is(err, errAuditClosed) {
			t.Fatalf("log did not fail closed: %v", err)
		}
	})
	for _, mode := range []string{"write fails after half the line", "sync fails", "short write"} {
		t.Run(mode, func(t *testing.T) {
			a, path := openAudit(t)
			for i := 1; i <= 2; i++ {
				if err := a.Append(entry(i)); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			realWrite, realSync := a.write, a.sync
			switch mode {
			case "write fails after half the line":
				a.write = func(b []byte) (int, error) {
					n, _ := realWrite(b[:len(b)/2])
					return n, errors.New("no space left on device")
				}
			case "sync fails":
				a.sync = func() error { return errors.New("input/output error") }
			case "short write":
				a.write = func(b []byte) (int, error) { return realWrite(b[:len(b)-1]) }
			}
			if err := a.Append(entry(3)); err == nil {
				t.Fatal("the failure was not reported")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatalf("the file changed by a failed append: %d bytes became %d", len(before), len(after))
			}
			if seq, _ := a.Head(); seq != 2 {
				t.Fatalf("head moved to %d", seq)
			}
			// and it recovers: the next line carries on from the last good one
			a.write, a.sync = realWrite, realSync
			if err := a.Append(entry(3)); err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(path)
			if rep, err := VerifyChain(bytes.NewReader(b)); err != nil || rep.Lines != 3 {
				t.Fatalf("%+v %v", rep, err)
			}
		})
	}
}

func TestAnOutsideWritersTextIsNeverOverwritten(t *testing.T) {
	// the file is opened for appending, so something else writing to it cannot be clobbered or silently absorbed
	a, path := openAudit(t)
	_ = a.Append(entry(1))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("an intruder was here\n")
	f.Close()
	_ = a.Append(entry(2))
	b, _ := os.ReadFile(path)
	if !bytes.Contains(b, []byte("an intruder was here\n")) {
		t.Fatal("the intruder's line was overwritten")
	}
	_, err = VerifyChain(bytes.NewReader(b))
	var ce *ChainError
	if !errors.As(err, &ce) || ce.Line != 2 {
		t.Fatalf("the intruder's line was not found: %v", err)
	}
}

func TestAuditTextIsOneLineOfPrintableASCII(t *testing.T) {
	a, path := openAudit(t)
	e := AuditEntry{RequestID: "req_1\n{\"seq\":99}", Credential: "ui-a\r\n", Tenant: tenantA, User: "zoë\x00\x1b[31m", Action: strings.Repeat("a", 500), Source: "1.2.3.4 ",
		Outcome: "ok\t", Detail: "<script>&", Changes: []string{"a\nb", strings.Repeat("c", 200)}}
	if err := a.Append(e); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if bytes.Count(b, []byte("\n")) != 1 {
		t.Fatalf("the entry made %d lines", bytes.Count(b, []byte("\n")))
	}
	for _, c := range b[:len(b)-1] {
		if c < 0x20 || c > 0x7e {
			t.Fatalf("byte %#x in the line", c)
		}
	}
	if _, err := VerifyChain(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	var back AuditEntry
	_ = json.Unmarshal(bytes.TrimSpace(b), &back)
	if len(back.Action) != 48 || len(back.Changes[1]) != 64 || strings.Contains(back.RequestID, "\n") {
		t.Fatalf("%+v", back)
	}
	// more than 32 changes are cut
	many := make([]string, 50)
	for i := range many {
		many[i] = "c"
	}
	if err := a.Append(AuditEntry{Changes: many}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	_ = json.Unmarshal([]byte(lines[1]), &back)
	if len(back.Changes) != 32 {
		t.Fatalf("%d changes kept", len(back.Changes))
	}
}

func TestConcurrentAppendsMakeOneChain(t *testing.T) {
	a, path := openAudit(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				if err := a.Append(entry(g*100 + i)); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	b, _ := os.ReadFile(path)
	rep, err := VerifyChain(bytes.NewReader(b))
	if err != nil || rep.Lines != 320 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestServerWritesAVerifiableLogWithNoContentInIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	fa, err := OpenFileAudit(path, func() time.Time { return epoch })
	if err != nil {
		t.Fatal(err)
	}
	defer fa.Close()
	h := newHarness(t, func(c *Config) { c.Audit = fa })
	const secret = "CUSTOMER-SECRET-CONTENT"
	h.putPolicy("ui-a", tenantA, `{"mode":"block","threshold":5,"note":"`+secret+`"}`, 0, 0)
	h.do(reqOpts{target: policyTarget(tenantA)})
	h.do(reqOpts{as: "ui-b", target: policyTarget(tenantA)})                                                                            // denied
	h.do(reqOpts{target: policyTarget(tenantA), keyAs: "ui-b"})                                                                         // authentication failure
	h.do(reqOpts{target: policyTarget(tenantA), after: func(r *http.Request) { r.Header.Set("Authorization", secret) }})                // malformed
	h.do(reqOpts{method: "PUT", target: policyTarget(tenantA), body: []byte(`{"mode":"off","note":"` + secret + `"}`), ifMatch: `"1"`}) // step-up refused
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(secret)) || bytes.Contains(b, []byte(strings.ToLower(secret))) {
		t.Fatalf("customer content reached the audit log:\n%s", b)
	}
	rep, err := VerifyChain(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Lines != 8 {
		t.Fatalf("%d lines:\n%s", rep.Lines, b)
	}
	var outcomes []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e AuditEntry
		_ = json.Unmarshal([]byte(l), &e)
		outcomes = append(outcomes, e.Action+":"+e.Outcome)
		if e.RequestID == "" {
			t.Fatalf("no request id: %s", l)
		}
	}
	// the last request, the step-up refusal, has its started line and its closing line
	want := []string{"policy.put:started", "policy.put:ok", "policy.get:ok", "policy.get:denied", "authenticate:auth_failed", "authenticate:auth_failed",
		"policy.put:started", "policy.put:denied"}
	if strings.Join(outcomes, ",") != strings.Join(want, ",") {
		t.Fatalf("outcomes: %v", outcomes)
	}
}
