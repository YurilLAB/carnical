// SPDX-License-Identifier: Apache-2.0

package netwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// State is what carnical-netwatch writes after each event, and the edge reads: the latest event and its record. Seq
// goes up by one with each event, so a reader knows which it has seen.
type State struct {
	Version int       `json:"version"` // 1
	Seq     uint64    `json:"seq"`
	Event   Event     `json:"event"`
	At      time.Time `json:"at"`
	Attack  *Record   `json:"attack"`
}

// MaxState is the most bytes of a state file.
const MaxState = 64 << 10

// WriteState replaces the state file at path with s, atomically: a reader sees the old file or the new one, never a
// part. The file is readable by everyone (it holds counts, no secret) and written only by its owner.
func WriteState(path string, s State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(data) > MaxState {
		return errors.New("netwatch: state too large")
	}
	return writeAtomic(path, append(data, '\n'))
}

// writeAtomic replaces the file at path with data: written to a temporary file beside it (".NAME.*", which
// RemoveTemporary clears after a crash), made readable by everyone, synced and renamed over it.
func writeAtomic(path string, data []byte) error {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // nothing to remove after the rename
	err = tmp.Chmod(0o644)
	if err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if err = errors.Join(err, tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// RemoveTemporary removes what a write that was cut short (the process was killed between creating its temporary file
// and renaming it) left beside path.
func RemoveTemporary(path string) {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	left, _ := filepath.Glob(filepath.Join(dir, "."+name+".*"))
	for _, f := range left {
		_ = os.Remove(f)
	}
}

// baselineFile is what WriteBaseline keeps: the usual rate of drops, and when it was learnt.
type baselineFile struct {
	Baseline float64   `json:"baseline"`
	At       time.Time `json:"at"`
}

// WriteBaseline keeps the usual rate of drops at path, so that a restarted watch resumes it.
func WriteBaseline(path string, baseline float64, at time.Time) error {
	data, err := json.Marshal(baselineFile{Baseline: baseline, At: at})
	if err != nil {
		return err
	}
	return writeAtomic(path, append(data, '\n'))
}

// ReadBaseline reads what WriteBaseline kept, if it was kept less than maxAge before now and is a rate.
func ReadBaseline(path string, now time.Time, maxAge time.Duration) (float64, bool) {
	data, err := os.ReadFile(path) // #nosec G304 -- the watch's own file
	if err != nil || len(data) > 1024 {
		return 0, false
	}
	var b baselineFile
	if json.Unmarshal(data, &b) != nil || b.Baseline < 0 || b.Baseline > 1e12 || now.Sub(b.At) > maxAge || b.At.After(now) {
		return 0, false
	}
	return b.Baseline, true
}

var knownKinds = []string{KindUDPFlood, KindReflection, KindSYNFlood, KindBadTCP, KindEchoFlood}

// ReadState reads and checks a state file. A file that is missing reads as the zero State and no error: the watch has
// not reported anything yet. Anything else that is not what WriteState writes is an error.
func ReadState(path string) (State, error) { return ReadStateChecked(path, nil) }

// ReadStateChecked is ReadState with a check of the file it opened (its owner, its mode), before it is read: what is
// checked is what is read, whatever replaces the path meanwhile.
func ReadStateChecked(path string, check func(fs.FileInfo) error) (State, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's own setting
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return State{}, errors.New("netwatch: the state is not a regular file")
	}
	if check != nil {
		if err := check(st); err != nil {
			return State{}, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxState+1))
	if err != nil {
		return State{}, err
	}
	if len(data) > MaxState {
		return State{}, errors.New("netwatch: the state file is too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s State
	if err := dec.Decode(&s); err != nil {
		return State{}, errors.New("netwatch: the state file cannot be read")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return State{}, errors.New("netwatch: the state file has more after the state")
	}
	if !namesAsWritten(data) {
		return State{}, errors.New("netwatch: the state file names a field in a way the watch does not write")
	}
	return s, s.check()
}

// namesAsWritten says whether every name in the document is given once in its object and spelt as WriteState spells
// names, in lower-case ASCII letters, digits and '_'. encoding/json matches a name to a field in any case (and some
// other letters, such as the Kelvin sign for 'k') and keeps the last of two, so a file that differs from one the watch
// wrote would otherwise read as the same state. The document has already been decoded, so it is valid JSON.
func namesAsWritten(data []byte) bool {
	type object struct {
		names   map[string]bool
		wantKey bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []*object // nil for an array
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return true
		}
		if err != nil {
			return false
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{':
				stack = append(stack, &object{names: map[string]bool{}, wantKey: true})
				continue
			case '[':
				stack = append(stack, nil)
				continue
			}
			stack = stack[:len(stack)-1] // '}' or ']': a value of the enclosing object ended
		} else if name, ok := tok.(string); ok && len(stack) > 0 && stack[len(stack)-1] != nil && stack[len(stack)-1].wantKey {
			o := stack[len(stack)-1]
			if name == "" || o.names[name] || strings.ContainsFunc(name, func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' }) {
				return false
			}
			o.names[name], o.wantKey = true, false
			continue
		}
		if len(stack) > 0 && stack[len(stack)-1] != nil {
			stack[len(stack)-1].wantKey = true
		}
	}
}

// check refuses a state that WriteState would not have written from a Detector's record.
func (s State) check() error {
	if s.Version != 1 {
		return fmt.Errorf("netwatch: state version %d", s.Version)
	}
	switch s.Event {
	case Start, Update, End:
	default:
		return errors.New("netwatch: unknown event in the state")
	}
	r := s.Attack
	if r == nil || s.Seq == 0 {
		return errors.New("netwatch: an event without its record")
	}
	if (s.Event == End) != (r.Ended != nil) || r.Stopped && s.Event != End {
		return errors.New("netwatch: the record's end does not match the event")
	}
	if len(r.Kinds) > len(knownKinds) || len(r.Ports) > MaxPorts || len(r.SourcePorts) > MaxPorts {
		return errors.New("netwatch: too many entries in the record")
	}
	for _, k := range r.Kinds {
		if !slices.Contains(knownKinds, k.Kind) {
			return errors.New("netwatch: unknown kind in the record")
		}
	}
	for _, p := range slices.Concat(r.Ports, r.SourcePorts) {
		if p.Protocol != "udp" && (p.Protocol != "tcp" || p.Port == 0) {
			return errors.New("netwatch: a port in the record is not one")
		}
	}
	for _, f := range []float64{r.PacketRate, r.PeakRate, r.ByteRate, r.PeakBytes, r.Baseline} {
		if f < 0 || f > 1e15 {
			return errors.New("netwatch: a rate in the record is out of range")
		}
	}
	return nil
}
