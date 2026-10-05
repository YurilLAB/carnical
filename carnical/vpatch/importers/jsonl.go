// SPDX-License-Identifier: Apache-2.0

package importers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/YurilLAB/coraza/carnical/vpatch"
)

// WriteJSONL writes one signature per line, in the shape the signature library uses (without the library's "_" fields). HTML
// characters are not escaped, so a pattern containing "<" stays readable.
func WriteJSONL(w io.Writer, sigs []vpatch.Signature) error {
	bw := bufio.NewWriter(w)
	for _, s := range sigs {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(s); err != nil {
			return fmt.Errorf("encode %s: %w", s.ID, err)
		}
		if _, err := bw.Write(buf.Bytes()); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// ReadJSONL reads signatures written by WriteJSONL. It is strict about the fields the model has and ignores any others, and it
// refuses a line longer than maxLine bytes (0 means 1 MiB).
func ReadJSONL(r io.Reader, maxLine int) ([]vpatch.Signature, error) {
	if maxLine <= 0 {
		maxLine = 1 << 20
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	var out []vpatch.Signature
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var s vpatch.Signature
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", line+1, err)
	}
	return out, nil
}
