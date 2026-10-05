// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// AuditEntry is one line of the audit log. The server fills in what happened; the log fills in the sequence number,
// the time (when empty) and the hash of the line before.
//
// Nothing here is request content. The credential is the id the request claimed, kept only if it has the form of an
// id; the tenant, the user and the source have been validated before they are written; the action, outcome and detail
// are fixed words.
type AuditEntry struct {
	Seq        uint64   `json:"seq"`
	Time       string   `json:"ts"`
	Prev       string   `json:"prev"`
	RequestID  string   `json:"request_id"`
	Credential string   `json:"credential"`
	Tenant     string   `json:"tenant"`
	User       string   `json:"user"`
	Action     string   `json:"action"`
	RevBefore  *uint64  `json:"rev_before,omitempty"`
	RevAfter   *uint64  `json:"rev_after,omitempty"`
	Changes    []string `json:"changes,omitempty"`
	Source     string   `json:"source"`
	Outcome    string   `json:"outcome"`
	Detail     string   `json:"detail,omitempty"`
}

const (
	zeroHash     = "0000000000000000000000000000000000000000000000000000000000000000"
	maxAuditLine = 16 << 10
)

// FileAudit appends hash-chained JSON lines to a file. Each line carries the SHA-256 of the line before it (the first
// carries 64 zeros) and a sequence number that rises by one, so a line that is deleted, inserted, reordered or edited
// breaks the chain at that point and VerifyChain says where.
//
// The file is opened for appending only, with mode 0600, and every line is flushed to disk before Append returns. A
// failed write is undone when repair succeeds. If repair fails, the log closes and refuses further appends.
//
// One process may write a log. A chain cannot stop someone who can rewrite the whole file, and it cannot show that the
// last lines were cut off; for both, copy Head() somewhere the log's own user cannot write, and check with
// VerifyChainHead.
type FileAudit struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	now      func() time.Time
	seq      uint64
	prev     string
	size     int64
	repaired bool
	// write and sync are the file's own, as fields so that a test can watch every line being flushed and make either fail
	write func([]byte) (int, error)
	sync  func() error
}

// OpenFileAudit opens or creates the log, checks the whole chain already in it, and positions itself after the last
// line. It refuses a file whose chain is broken (the owner decides what to do with such a file) or that other users
// can read. A last line that was never finished (a crash during a write: Append had not yet returned) is cut off and
// reported by Repaired.
func OpenFileAudit(path string, now func() time.Time) (*FileAudit, error) {
	if now == nil {
		now = time.Now
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !isWindows() && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("control: the audit log %s is accessible to other users (mode %o); it must be 0600", path, st.Mode().Perm())
	}
	rep, err := verifyChain(f)
	a := &FileAudit{f: f, path: path, now: now, seq: rep.HeadSeq, prev: rep.HeadHash, size: rep.goodBytes, write: f.Write, sync: f.Sync}
	if rep.HeadHash == "" {
		a.prev = zeroHash
	}
	if err != nil {
		var ce *ChainError
		if errors.As(err, &ce) && ce.torn {
			if terr := a.truncate(rep.goodBytes); terr != nil {
				return nil, terr
			}
			a.repaired = true
		} else {
			return nil, err
		}
	}
	ok = true
	return a, nil
}

// Repaired reports whether Open cut off an unfinished last line.
func (a *FileAudit) Repaired() bool { return a.repaired }

// Head returns the sequence number and the hash of the last line: what to store elsewhere so that a cut-off tail can be
// found later.
func (a *FileAudit) Head() (uint64, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.seq, a.prev
}

// Close closes the file.
func (a *FileAudit) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	return err
}

var errAuditClosed = errors.New("control: the audit log is closed")

// Append writes one line and flushes it to disk. It returns an error if the line could not be made durable and attempts
// to restore the previous file contents. A failed repair closes the log rather than continuing a broken chain.
func (a *FileAudit) Append(e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return errAuditClosed
	}
	e = sanitizeEntry(e)
	e.Seq, e.Prev = a.seq+1, a.prev
	if e.Time == "" {
		e.Time = a.now().UTC().Format(time.RFC3339)
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(line) > maxAuditLine {
		return errors.New("control: audit line too long")
	}
	buf := append(line, '\n')
	n, err := a.write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = a.sync()
	}
	if err != nil {
		// undo whatever reached the file, so the chain has no stub
		if rollback := a.truncate(a.size); rollback != nil {
			_ = a.f.Close()
			a.f = nil
			return errors.Join(err, fmt.Errorf("control: audit rollback failed; log closed: %w", rollback))
		}
		return err
	}
	sum := sha256.Sum256(line)
	a.seq, a.prev, a.size = e.Seq, hex.EncodeToString(sum[:]), a.size+int64(len(buf))
	return nil
}

// Windows append-only handles omit FILE_WRITE_DATA, so they cannot truncate.
// Keep append semantics for normal writes, and open a checked second handle
// solely for repair. Never create a missing file or repair a substituted path.
func (a *FileAudit) truncate(size int64) error {
	if !isWindows() {
		return a.f.Truncate(size)
	}
	repair, err := os.OpenFile(a.path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer repair.Close()
	original, err := a.f.Stat()
	if err != nil {
		return err
	}
	current, err := repair.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(original, current) {
		return errors.New("control: audit repair path identifies a different file")
	}
	if err := repair.Truncate(size); err != nil {
		return err
	}
	return repair.Sync()
}

// sanitizeEntry makes every text field printable ASCII of bounded length, so a field can neither break the line nor
// carry something that was not meant to be logged.
func sanitizeEntry(e AuditEntry) AuditEntry {
	e.RequestID = clean(e.RequestID, 40)
	e.Credential = clean(e.Credential, 48)
	e.Tenant = clean(e.Tenant, 32)
	e.User = clean(e.User, 128)
	e.Action = clean(e.Action, 48)
	e.Source = clean(e.Source, 64)
	e.Outcome = clean(e.Outcome, 24)
	e.Detail = clean(e.Detail, 64)
	e.Time = clean(e.Time, 32)
	if len(e.Changes) > 32 {
		e.Changes = e.Changes[:32]
	}
	cs := make([]string, 0, len(e.Changes))
	for _, c := range e.Changes {
		cs = append(cs, clean(c, 64))
	}
	e.Changes = cs
	if len(cs) == 0 {
		e.Changes = nil
	}
	return e
}

func clean(s string, max int) string {
	if len(s) > max {
		s = s[:max]
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// ChainError says where a log stops being a valid chain.
type ChainError struct {
	Line   int // 1-based
	Reason string
	torn   bool
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("audit log broken at line %d: %s", e.Line, e.Reason)
}

// ChainReport describes a log that verified, or the part of it that did.
type ChainReport struct {
	Lines    int
	HeadSeq  uint64
	HeadHash string // hex SHA-256 of the last good line; empty for an empty log

	goodBytes int64
}

// VerifyChain reads a log and reports the first line that does not belong. A line that was edited is reported at the
// line after it, because that is the first line whose "prev" no longer matches; a line that is missing, inserted or
// moved is reported at the first line out of place. The edit of the very last line cannot be seen by the chain alone:
// use VerifyChainHead for that.
func VerifyChain(r io.Reader) (ChainReport, error) { return verifyChain(r) }

// VerifyChainHead is VerifyChain plus a check that the log ends where a head recorded earlier (Head) says: the same
// sequence number and hash. It finds a cut-off tail, and an edited last line.
func VerifyChainHead(r io.Reader, seq uint64, hash string) (ChainReport, error) {
	rep, err := verifyChain(r)
	if err != nil {
		return rep, err
	}
	if rep.HeadSeq != seq || rep.HeadHash != hash {
		return rep, &ChainError{Line: rep.Lines, Reason: fmt.Sprintf("the log ends at sequence %d but the recorded head is sequence %d", rep.HeadSeq, seq)}
	}
	return rep, nil
}

func verifyChain(r io.Reader) (ChainReport, error) {
	br := bufio.NewReaderSize(r, 32<<10)
	rep := ChainReport{}
	prev := zeroHash
	var offset int64
	for n := 1; ; n++ {
		line, err := br.ReadSlice('\n')
		if err == io.EOF {
			if len(line) == 0 {
				return rep, nil
			}
			return rep, &ChainError{Line: n, Reason: "the last line is not finished", torn: true}
		}
		if err == bufio.ErrBufferFull {
			return rep, &ChainError{Line: n, Reason: "line too long"}
		}
		if err != nil {
			return rep, &ChainError{Line: n, Reason: "read error"}
		}
		raw := line[:len(line)-1]
		if reason := checkLine(raw, uint64(n), rep.HeadSeq, prev); reason != "" {
			return rep, &ChainError{Line: n, Reason: reason}
		}
		sum := sha256.Sum256(raw)
		prev = hex.EncodeToString(sum[:])
		rep.Lines, rep.HeadSeq, rep.HeadHash = n, uint64(n), prev
		offset += int64(len(line))
		rep.goodBytes = offset
	}
}

// checkLine verifies one line against what must precede it. It returns the reason it is wrong, or "".
func checkLine(raw []byte, n, prevSeq uint64, prevHash string) string {
	if len(raw) == 0 {
		return "an empty line"
	}
	if bytes.IndexByte(raw, '\r') >= 0 || bytes.IndexByte(raw, 0) >= 0 {
		return "a control character in the line"
	}
	if !utf8.Valid(raw) {
		return "not valid UTF-8"
	}
	if err := checkJSON(raw, 4); err != nil {
		return "not one JSON object (" + err.Error() + ")"
	}
	var e AuditEntry
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return "not an audit entry"
	}
	// the one way to spell an entry: anything else was not written by Append
	if again, err := json.Marshal(e); err != nil || !bytes.Equal(again, raw) {
		return "not written in the form Append writes"
	}
	if e.Seq != prevSeq+1 || e.Seq != n {
		return fmt.Sprintf("the sequence number is %d, expected %d", e.Seq, prevSeq+1)
	}
	if e.Prev != prevHash {
		return "the hash of the line before does not match"
	}
	return ""
}
