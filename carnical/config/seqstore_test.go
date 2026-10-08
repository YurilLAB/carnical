// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openStore(t *testing.T, dir string) *FileSeqStore {
	t.Helper()
	s, err := OpenFileSeqStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFileStoreSurvivesARestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "seq")
	s := openStore(t, dir)
	if last, err := s.Last(tenantA); err != nil || last != 0 {
		t.Fatalf("a new stream: %d, %v", last, err)
	}
	for _, seq := range []uint64{3, 10, 11} {
		if err := s.Advance(tenantA, seq); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Advance(tenantB, 2); err != nil {
		t.Fatal(err)
	}
	again := openStore(t, dir) // the process restarted
	for stream, want := range map[string]uint64{tenantA: 11, tenantB: 2, tenantC: 0} {
		if got, err := again.Last(stream); err != nil || got != want {
			t.Errorf("after a restart, %s holds %d (%v), want %d", stream[:4], got, err, want)
		}
	}
	for _, tc := range []struct {
		seq  uint64
		want error
	}{{11, ErrRollback}, {10, ErrRollback}, {1, ErrRollback}, {12, nil}} {
		if err := again.Advance(tenantA, tc.seq); !errors.Is(err, tc.want) && !(tc.want == nil && err == nil) {
			t.Errorf("Advance(%d) after a restart: %v, want %v", tc.seq, err, tc.want)
		}
	}
}

func TestFileStoreFilesAreOnePerStreamAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "seq")
	s := openStore(t, dir)
	for _, st := range []string{tenantA, tenantB, KeySetStream("0123456789abcdef")} {
		if err := s.Advance(st, 1); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		if fi, _ := e.Info(); fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
			t.Errorf("%s is readable by others: %v", e.Name(), fi.Mode())
		}
	}
	if len(names) != 3 {
		t.Fatalf("files: %v", names)
	}
	for _, n := range names {
		if strings.Contains(n, ".tmp-") {
			t.Errorf("a temporary file was left behind: %s", n)
		}
	}
	if os.PathSeparator == '/' {
		for _, mode := range []fs.FileMode{0o700, 0o750, 0o702, 0o777} {
			t.Run(mode.String(), func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "seq")
				if err := os.Mkdir(dir, mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, mode); err != nil {
					t.Fatal(err)
				}
				leftover := filepath.Join(dir, tenantA+".tmp-interrupted")
				if err := os.WriteFile(leftover, []byte("keep until directory validation"), 0o600); err != nil {
					t.Fatal(err)
				}
				store, err := OpenFileSeqStore(dir)
				if mode == 0o700 {
					if err != nil || store == nil {
						t.Fatalf("private directory rejected: %v", err)
					}
					if err := store.Advance(tenantA, 1); err != nil {
						t.Fatal(err)
					}
					return
				}
				if !errors.Is(err, ErrStore) || store != nil {
					t.Fatalf("shared directory accepted: store=%v err=%v", store != nil, err)
				}
				if _, err := os.Stat(leftover); err != nil {
					t.Fatalf("rejected directory modified: %v", err)
				}
				if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != mode {
					t.Fatalf("permissions changed: %v %v", fi, err)
				}
			})
		}
		t.Run("symlink directory", func(t *testing.T) {
			parent := t.TempDir()
			target := filepath.Join(parent, "private")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(parent, "seq")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{link, link + string(os.PathSeparator), link + string(os.PathSeparator) + "."} {
				t.Run(path, func(t *testing.T) {
					if store, err := OpenFileSeqStore(path); !errors.Is(err, ErrStore) || store != nil {
						t.Errorf("symlink directory %q accepted: store=%v err=%v", path, store != nil, err)
					}
				})
			}
		})
	}
}

func TestStreamNamesAreChecked(t *testing.T) {
	for _, store := range []SeqStore{NewMemSeqStore(), openStore(t, filepath.Join(t.TempDir(), "seq"))} {
		for name, stream := range map[string]string{
			"empty":                             "",
			"a path":                            "../" + tenantA,
			"a tenant with a dot":               tenantA[:31] + ".",
			"upper case":                        strings.ToUpper(tenantA),
			"short":                             tenantA[:31],
			"long":                              tenantA + "a",
			"a slash":                           tenantA[:30] + "/a",
			"a key list stream with a short id": "keyset-0123",
			"a bare key id":                     "0123456789abcdef",
		} {
			if err := store.Advance(stream, 1); !errors.Is(err, ErrStore) {
				t.Errorf("%T %s: Advance = %v", store, name, err)
			}
			if _, err := store.Last(stream); !errors.Is(err, ErrStore) {
				t.Errorf("%T %s: Last = %v", store, name, err)
			}
		}
	}
	for _, store := range []SeqStore{NewMemSeqStore(), openStore(t, filepath.Join(t.TempDir(), "seq"))} {
		if err := store.Advance(tenantA, 7); err != nil {
			t.Fatal(err)
		}
		for _, seq := range []uint64{0, MaxSequence + 1, ^uint64(0)} {
			if err := store.Advance(tenantA, seq); !errors.Is(err, ErrMalformed) {
				t.Errorf("%T: Advance(%d) = %v, want ErrMalformed", store, seq, err)
			}
			if last, err := store.Last(tenantA); err != nil || last != 7 {
				t.Fatalf("%T: invalid sequence changed state: %d, %v", store, last, err)
			}
		}
		if err := store.Advance(tenantA, MaxSequence); err != nil {
			t.Fatalf("%T: maximum sequence rejected: %v", store, err)
		}
		if err := store.Advance(tenantA, MaxSequence); !errors.Is(err, ErrRollback) {
			t.Fatalf("%T: duplicate maximum sequence = %v, want ErrRollback", store, err)
		}
	}
}

// Every prefix of a record, every single changed byte, and a record for another stream must be recognised as damaged
// and never be read as a number: a damaged file that read as a smaller number would let an old envelope in.
func TestADamagedRecordIsNeverReadAsANumber(t *testing.T) {
	good := record(tenantA, 123456)
	if seq, err := parseRecord(tenantA, good); err != nil || seq != 123456 {
		t.Fatalf("the good record: %d, %v", seq, err)
	}
	t.Run("every cut-short prefix", func(t *testing.T) {
		for n := 0; n < len(good); n++ {
			if seq, err := parseRecord(tenantA, good[:n]); err == nil {
				t.Errorf("a record cut to %d bytes was read as %d", n, seq)
			}
		}
	})
	t.Run("every single changed byte", func(t *testing.T) {
		for i := range good {
			for _, repl := range []byte{'0', '9', 'x', 0, '\n', 0xff} {
				if repl == good[i] {
					continue
				}
				bad := append([]byte(nil), good...)
				bad[i] = repl
				if seq, err := parseRecord(tenantA, bad); err == nil {
					t.Errorf("byte %d changed to %q was read as %d", i, repl, seq)
				}
			}
		}
	})
	t.Run("a lower number with the old checksum", func(t *testing.T) {
		bad := []byte(strings.Replace(string(good), "123456", "3", 1))
		if _, err := parseRecord(tenantA, bad); !errors.Is(err, ErrStoreCorrupt) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("another stream's record", func(t *testing.T) {
		if _, err := parseRecord(tenantB, good); !errors.Is(err, ErrStoreCorrupt) {
			t.Errorf("a record for tenant A was read as tenant B's: %v", err)
		}
	})
	t.Run("extra bytes after the record", func(t *testing.T) {
		for _, tail := range []string{"\n", "x", "123", " "} {
			if _, err := parseRecord(tenantA, append(append([]byte(nil), good...), tail...)); err == nil {
				t.Errorf("a record followed by %q was accepted", tail)
			}
		}
	})
	t.Run("a number that is not in its plain form", func(t *testing.T) {
		for _, num := range []string{"0123456", "+123456", "123456.0", "1e5", "-1", "99999999999999999999", "9007199254740992"} {
			body := recordMagic + "\n" + tenantA + "\n" + num + "\n"
			if _, err := parseRecord(tenantA, []byte(body+"0000000000000000\n")); err == nil {
				t.Errorf("%q was accepted", num)
			}
		}
	})
}

func TestADamagedFileFailsClosedAndResetRepairsIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "seq")
	s := openStore(t, dir)
	if err := s.Advance(tenantA, 50); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, tenantA+".seq")
	good, _ := os.ReadFile(file)
	damage := map[string]func(){
		"empty":                 func() { os.WriteFile(file, nil, 0o600) },
		"half a record":         func() { os.WriteFile(file, good[:len(good)/2], 0o600) },
		"garbage":               func() { os.WriteFile(file, []byte("not a record at all\n"), 0o600) },
		"a lower number":        func() { os.WriteFile(file, []byte(strings.Replace(string(good), "50", "5", 1)), 0o600) },
		"another tenant's file": func() { os.WriteFile(file, record(tenantB, 50), 0o600) },
		"a directory instead":   func() { os.Remove(file); os.Mkdir(file, 0o700) },
		"a huge file":           func() { os.WriteFile(file, make([]byte, 1<<20), 0o600) },
	}
	for name, do := range damage {
		t.Run(name, func(t *testing.T) {
			os.RemoveAll(file)
			os.WriteFile(file, good, 0o600)
			do()
			again := openStore(t, dir)
			if last, err := again.Last(tenantA); !errors.Is(err, ErrStoreCorrupt) {
				t.Fatalf("Last = %d, %v: a damaged file must not read as a number", last, err)
			}
			for _, seq := range []uint64{1, 5, 49, 50, 51, 1000} {
				if err := again.Advance(tenantA, seq); !errors.Is(err, ErrStoreCorrupt) {
					t.Fatalf("Advance(%d) = %v: nothing may be accepted while the record is damaged", seq, err)
				}
			}
			// The other tenant is unaffected by tenant A's file.
			if err := again.Advance(tenantB, 1); err != nil {
				t.Fatalf("tenant B refused because of tenant A's file: %v", err)
			}
			// An operator who knows the newest number issued repairs it.
			os.RemoveAll(file)
			os.WriteFile(file, []byte("x"), 0o600)
			if err := again.Reset(tenantA, 77); err != nil {
				t.Fatal(err)
			}
			if last, err := again.Last(tenantA); err != nil || last != 77 {
				t.Fatalf("after Reset: %d, %v", last, err)
			}
			if err := again.Advance(tenantA, 77); !errors.Is(err, ErrRollback) {
				t.Fatalf("Advance(77) after Reset: %v", err)
			}
			os.Remove(filepath.Join(dir, tenantB+".seq"))
		})
	}
}

// crashOps does what the disk does until the "power cut" at one step, then every call fails as if the machine had stopped.
// What is left on the disk is what a restart would find.
type crashOps struct {
	osOps
	at      string // which step is the last one that completes: "partial-write", "write", "rename"
	crashed bool
}

var errPowerCut = errors.New("power cut")

func (c *crashOps) writeTemp(dir, prefix string, data []byte) (string, error) {
	if c.crashed {
		return "", errPowerCut
	}
	if c.at == "partial-write" {
		f, err := os.CreateTemp(dir, prefix+"*")
		if err != nil {
			return "", err
		}
		f.Write(data[:len(data)/2])
		f.Close()
		c.crashed = true
		return "", errPowerCut
	}
	p, err := c.osOps.writeTemp(dir, prefix, data)
	if err == nil && c.at == "write" {
		c.crashed = true
		return "", errPowerCut // the file is complete and flushed, but never renamed
	}
	return p, err
}

func (c *crashOps) rename(oldPath, newPath string) error {
	if c.crashed {
		return errPowerCut
	}
	err := c.osOps.rename(oldPath, newPath)
	if err == nil && c.at == "rename" {
		c.crashed = true // renamed, but the directory was never flushed and Advance never returned
	}
	return err
}

func (c *crashOps) syncDir(dir string) error {
	if c.crashed {
		return errPowerCut
	}
	return c.osOps.syncDir(dir)
}

func TestAPowerCutNeverLowersTheStoredSequence(t *testing.T) {
	for _, step := range []string{"partial-write", "write", "rename"} {
		t.Run("cut at "+step, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "seq")
			before := openStore(t, dir)
			if err := before.Advance(tenantA, 5); err != nil {
				t.Fatal(err)
			}
			crashing, err := openFileSeqStore(dir, &crashOps{at: step})
			if err != nil {
				t.Fatal(err)
			}
			err = crashing.Advance(tenantA, 6)
			if !errors.Is(err, ErrStore) {
				t.Fatalf("the interrupted Advance returned %v: it must not report success", err)
			}
			// What the caller was told is that 6 was not accepted. The edge keeps what it is running.
			// Now the machine restarts.
			after := openStore(t, dir)
			last, err := after.Last(tenantA)
			if err != nil {
				t.Fatalf("the record after the cut is unreadable: %v", err)
			}
			if last < 5 {
				t.Fatalf("the cut lowered the stored sequence to %d", last)
			}
			if last != 5 && last != 6 {
				t.Fatalf("the stored sequence became %d", last)
			}
			// Replaying the old envelopes still fails, and the next real number is accepted.
			for _, old := range []uint64{1, 4, 5} {
				if err := after.Advance(tenantA, old); !errors.Is(err, ErrRollback) {
					t.Fatalf("Advance(%d) after the cut: %v", old, err)
				}
			}
			if err := after.Advance(tenantA, 7); err != nil {
				t.Fatalf("Advance(7) after the cut: %v", err)
			}
			// No temporary file survives the restart.
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				if strings.Contains(e.Name(), ".tmp-") {
					t.Errorf("a temporary file survived the restart: %s", e.Name())
				}
			}
		})
	}
	t.Run("a cut during the very first write leaves no record, not a number", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "seq")
		crashing, err := openFileSeqStore(dir, &crashOps{at: "partial-write"})
		if err != nil {
			t.Fatal(err)
		}
		if err := crashing.Advance(tenantA, 9); !errors.Is(err, ErrStore) {
			t.Fatal(err)
		}
		if last, err := openStore(t, dir).Last(tenantA); err != nil || last != 0 {
			t.Fatalf("Last = %d, %v", last, err)
		}
	})
}

// failOps fails one operation without any crash, as a full disk or a permission error would.
type failOps struct {
	osOps
	fail string
}

func (f failOps) writeTemp(d, p string, b []byte) (string, error) {
	if f.fail == "write" {
		return "", fs.ErrPermission
	}
	return f.osOps.writeTemp(d, p, b)
}
func (f failOps) rename(a, b string) error {
	if f.fail == "rename" {
		return fs.ErrPermission
	}
	return f.osOps.rename(a, b)
}
func (f failOps) syncDir(d string) error {
	if f.fail == "syncdir" {
		return fs.ErrPermission
	}
	return f.osOps.syncDir(d)
}
func (f failOps) readFile(p string) ([]byte, error) {
	if f.fail == "read" {
		return nil, fs.ErrPermission
	}
	return f.osOps.readFile(p)
}

func TestADiskErrorIsNotAnAcceptance(t *testing.T) {
	for _, fail := range []string{"write", "rename", "syncdir", "read"} {
		t.Run(fail, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "seq")
			if err := openStore(t, dir).Advance(tenantA, 5); err != nil {
				t.Fatal(err)
			}
			s, err := openFileSeqStore(dir, failOps{fail: fail})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Advance(tenantA, 6); !errors.Is(err, ErrStore) {
				t.Fatalf("Advance = %v, want an ErrStore failure", err)
			}
			if fail == "rename" {
				if entries, _ := os.ReadDir(dir); len(entries) != 1 {
					t.Errorf("a failed rename left %d files", len(entries))
				}
			}
		})
	}
	t.Run("an envelope is not accepted when its record cannot be written", func(t *testing.T) {
		s, err := openFileSeqStore(filepath.Join(t.TempDir(), "seq"), failOps{fail: "write"})
		if err != nil {
			t.Fatal(err)
		}
		r := newRig(t, s)
		_, err = r.ver.Accept(r.sign(t, tenantA, edgeID, 1), t0.Add(1))
		if !errors.Is(err, ErrStore) {
			t.Fatalf("Accept = %v", err)
		}
		if Reason(err) != "store" {
			t.Fatalf("Reason = %s", Reason(err))
		}
	})
}

func TestFileStoreCleansUpAfterAnInterruptedWriteOnOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "seq")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, tenantA+".tmp-12345"), []byte("half"), 0o600)
	os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("keep"), 0o600)
	openStore(t, dir)
	if _, err := os.Stat(filepath.Join(dir, tenantA+".tmp-12345")); err == nil {
		t.Error("the temporary file was left")
	}
	if _, err := os.Stat(filepath.Join(dir, "unrelated.txt")); err != nil {
		t.Error("a file that is not the store's was removed")
	}
	if _, err := OpenFileSeqStore(""); err == nil {
		t.Error("an empty directory name was accepted")
	}
}
