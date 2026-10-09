// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// SeqStore is the edge's memory of the newest configuration it has accepted, which is what stops an old envelope being
// replayed. A stream is a tenant id (32 lower-case hex digits), or "keyset-" and a root key id for the key list (see
// KeySetStream). Implementations must be safe for concurrent use and must make Advance atomic: of any number of calls
// racing for one stream, a call is accepted only if its number is higher than every number accepted before it, and the
// highest number offered is always accepted.
type SeqStore interface {
	// Advance records seq as the newest for the stream if and only if it is higher than the stored number, and returns nil.
	// seq must be between 1 and MaxSequence inclusive; otherwise it returns ErrMalformed and changes nothing.
	// Otherwise it returns ErrRollback and changes nothing. It must not return nil until the new number would survive a
	// power cut. A failure to read or write returns an error for which errors.Is(err, ErrStore) is true, and a record that
	// cannot be trusted returns ErrStoreCorrupt; in both cases nothing is accepted.
	Advance(stream string, seq uint64) error
	// Last returns the newest accepted number for the stream, or 0 if none has been.
	Last(stream string) (uint64, error)
}

var streamRe = regexp.MustCompile(`\A(?:[0-9a-f]{32}|keyset-[0-9a-f]{16})\z`)

// KeySetStream is the stream name under which the sequence of a root key's key lists is kept.
func KeySetStream(rootKeyID string) string { return "keyset-" + rootKeyID }

func checkStream(stream string) error {
	if !streamRe.MatchString(stream) {
		return errors.New("config: not a tenant id or key list stream")
	}
	return nil
}

// MemSeqStore keeps sequence numbers in memory only. It forgets them when the process ends, which is exactly the hole a
// replay uses, so it is for tests and for tools that only check; an edge uses a FileSeqStore.
type MemSeqStore struct {
	mu sync.Mutex
	m  map[string]uint64
}

// NewMemSeqStore returns an empty in-memory store.
func NewMemSeqStore() *MemSeqStore { return &MemSeqStore{m: map[string]uint64{}} }

// Advance implements SeqStore.
func (s *MemSeqStore) Advance(stream string, seq uint64) error {
	if err := checkStream(stream); err != nil {
		return storeFailure(err)
	}
	if seq < 1 || seq > MaxSequence {
		return ErrMalformed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq <= s.m[stream] {
		return ErrRollback
	}
	s.m[stream] = seq
	return nil
}

// Last implements SeqStore.
func (s *MemSeqStore) Last(stream string) (uint64, error) {
	if err := checkStream(stream); err != nil {
		return 0, storeFailure(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[stream], nil
}

// FileSeqStore keeps one small file per stream in one directory, and survives a restart and a power cut.
//
// Each file is written the only way that is safe to interrupt: the new content goes to a temporary file in the same
// directory, which is flushed to disk; the temporary file is renamed over the old one (a rename is atomic, so the file
// is always the whole old record or the whole new one); and the directory is flushed so the rename itself is on disk.
// Advance returns only after that, so a number it has accepted is never lost. A file that is cut short, empty,
// altered, or that belongs to another stream is not read as "no record" or as a smaller number: it is reported as
// ErrStoreCorrupt and nothing is accepted for that stream until an operator calls Reset, because guessing a number
// could let an old envelope back in.
//
// A FileSeqStore assumes it is the only writer of its directory. Two processes sharing one directory could each read
// the same number and both write a larger one. The directory is created with mode 0700 and the files with 0600.
type FileSeqStore struct {
	dir string
	ops fileOps
	mu  sync.Mutex
}

// fileOps is every operation on the disk that the store performs, so a test can interrupt it at each step.
type fileOps interface {
	readFile(path string) ([]byte, error)
	// writeTemp creates a new file in dir whose name starts with prefix, writes data, flushes it to disk and closes it.
	writeTemp(dir, prefix string, data []byte) (path string, err error)
	rename(oldPath, newPath string) error
	syncDir(dir string) error
	remove(path string) error
	lstat(path string) (fs.FileInfo, error)
	readDir(dir string) ([]fs.DirEntry, error)
}

// OpenFileSeqStore opens (creating it if need be) the directory the files are kept in, and removes the temporary files
// an earlier interrupted write left behind. Existing directories must be real directories and grant no group/other
// permissions on Unix. Windows deployments must restrict access with ACLs. The operator must also protect the parent path.
// Relative directories are resolved at open; later working-directory changes do not redirect the store.
func OpenFileSeqStore(dir string) (*FileSeqStore, error) { return openFileSeqStore(dir, osOps{}) }

func openFileSeqStore(dir string, ops fileOps) (*FileSeqStore, error) {
	if dir == "" {
		return nil, errors.New("config: no directory given for the sequence record")
	}
	// Resolve once so a later working-directory change cannot select another rollback floor.
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, storeFailure(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, storeFailure(err)
	}
	fi, err := ops.lstat(dir)
	if err != nil {
		return nil, storeFailure(err)
	}
	if !fi.IsDir() {
		return nil, storeFailure(errors.New("sequence directory must be a real directory, not a symbolic link"))
	}
	if os.PathSeparator == '/' && fi.Mode().Perm()&0o077 != 0 {
		return nil, storeFailure(errors.New("sequence directory must not grant group or other permissions"))
	}
	s := &FileSeqStore{dir: dir, ops: ops}
	entries, err := ops.readDir(dir)
	if err != nil {
		return nil, storeFailure(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			_ = ops.remove(filepath.Join(dir, e.Name()))
		}
	}
	return s, nil
}

const recordMagic = "carnical-seq-v1"

// record is the whole content of a file:
//
//	carnical-seq-v1\n<stream>\n<decimal sequence>\n<first 16 hex digits of SHA-256 of the three lines above, newlines included>\n
//
// The checksum catches a cut or damaged file, and having the stream inside catches a file copied to another name.
func record(stream string, seq uint64) []byte {
	body := recordMagic + "\n" + stream + "\n" + strconv.FormatUint(seq, 10) + "\n"
	sum := sha256.Sum256([]byte(body))
	return []byte(body + hex.EncodeToString(sum[:8]) + "\n")
}

func parseRecord(stream string, data []byte) (uint64, error) {
	lines := strings.Split(string(data), "\n")
	if len(lines) != 5 || lines[4] != "" || lines[0] != recordMagic || lines[1] != stream {
		return 0, ErrStoreCorrupt
	}
	seq, err := strconv.ParseUint(lines[2], 10, 64)
	if err != nil || strconv.FormatUint(seq, 10) != lines[2] || seq > MaxSequence {
		return 0, ErrStoreCorrupt
	}
	if string(record(stream, seq)) != string(data) {
		return 0, ErrStoreCorrupt
	}
	return seq, nil
}

func (s *FileSeqStore) path(stream string) string { return filepath.Join(s.dir, stream+".seq") }

// load reads the stored number. A missing file is the first time (0); anything unreadable is not.
func (s *FileSeqStore) load(stream string) (uint64, error) {
	p := s.path(stream)
	if fi, err := s.ops.lstat(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, storeFailure(err)
	} else if !fi.Mode().IsRegular() {
		return 0, ErrStoreCorrupt
	}
	data, err := s.ops.readFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, storeFailure(err)
	}
	return parseRecord(stream, data)
}

// Last implements SeqStore.
func (s *FileSeqStore) Last(stream string) (uint64, error) {
	if err := checkStream(stream); err != nil {
		return 0, storeFailure(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load(stream)
}

// Advance implements SeqStore. The file is read again for every call, under the lock, so the number compared with is
// always the one on disk.
func (s *FileSeqStore) Advance(stream string, seq uint64) error {
	if err := checkStream(stream); err != nil {
		return storeFailure(err)
	}
	if seq < 1 || seq > MaxSequence {
		return ErrMalformed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.load(stream)
	if err != nil {
		return err
	}
	if seq <= cur {
		return ErrRollback
	}
	return s.write(stream, seq)
}

// Reset sets the stored number for a stream whatever it was, including lower or damaged. It is for an operator who has
// found the record damaged (ErrStoreCorrupt) and knows the newest sequence number the control plane has issued; no
// code path that handles an envelope calls it.
func (s *FileSeqStore) Reset(stream string, seq uint64) error {
	if err := checkStream(stream); err != nil {
		return storeFailure(err)
	}
	if seq > MaxSequence {
		return ErrMalformed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(stream, seq)
}

func (s *FileSeqStore) write(stream string, seq uint64) error {
	tmp, err := s.ops.writeTemp(s.dir, stream+".tmp-", record(stream, seq))
	if err != nil {
		return storeFailure(err)
	}
	if err := s.ops.rename(tmp, s.path(stream)); err != nil {
		_ = s.ops.remove(tmp)
		return storeFailure(err)
	}
	if err := s.ops.syncDir(s.dir); err != nil {
		return storeFailure(err)
	}
	return nil
}

// osOps is fileOps on the real disk.
type osOps struct{}

func (osOps) readFile(path string) ([]byte, error) {
	// #nosec G304 -- Private store directory plus a validated fixed-form stream ID; this reader is bounded to 1 KiB.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// A record is under 200 bytes. Reading at most a little more is how an oversized file is noticed without reading all of it,
	// and it is rejected by parseRecord.
	data, err := io.ReadAll(io.LimitReader(f, 1024))
	return data, errors.Join(err, f.Close())
}

func (osOps) writeTemp(dir, prefix string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, prefix+"*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	fail := func(err error) (string, error) {
		closeErr := f.Close()
		removeErr := os.Remove(name)
		return "", errors.Join(err, closeErr, removeErr)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		return "", errors.Join(err, os.Remove(name))
	}
	return name, nil
}

func (osOps) rename(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }

func (osOps) syncDir(dir string) error { return syncDirectory(dir) }

func (osOps) remove(path string) error                  { return os.Remove(path) }
func (osOps) lstat(path string) (fs.FileInfo, error)    { return os.Lstat(path) }
func (osOps) readDir(dir string) ([]fs.DirEntry, error) { return os.ReadDir(dir) }
