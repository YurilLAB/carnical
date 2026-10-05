package formats

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"strings"
)

// ratioFloor is the output size under which the compression ratio is not checked: a few hundred bytes of repetitive JSON can
// compress to a few dozen, which is a ratio over 100 and is not an attack.
const ratioFloor = 4 << 10

// decodeBody decompresses a request body that has a Content-Encoding. The proxy lets exactly one gzip or deflate layer through when
// the site allows it; this is where it is made into the body that can be read. Everything is bounded by the output limit: at most
// that many bytes (and one more, to tell that there were more) are ever produced, so the time and memory spent do not depend on what
// the compressed stream claims.
//
// It returns the decompressed body and whether there was any compression at all. It refuses a second layer, any other encoding, a
// stream that is truncated or fails its checksum, bytes after the end of the stream (a second gzip member is one: parsers differ
// about whether the rest is read or ignored), and a body that expands past the output limit or far past what content compresses to.
func (in *Inspector) decodeBody(f *finder, header []string, body []byte) (out []byte, did bool, ok bool) {
	var layers []string
	for _, h := range header {
		for _, tok := range strings.Split(h, ",") {
			t := strings.ToLower(strings.TrimSpace(tok))
			if t != "" && t != "identity" {
				layers = append(layers, t)
			}
		}
	}
	switch {
	case len(layers) == 0:
		return nil, false, true
	case len(layers) > 1:
		return nil, false, !f.hit(rEncLayers, -1, dNone)
	case layers[0] != "gzip" && layers[0] != "deflate":
		return nil, false, !f.hit(rEncUnsupported, -1, dNone)
	}
	lim := &in.pol.Encoding
	maxOut := int64(lim.MaxOutput)
	byRatio := int64(lim.MaxRatio) * int64(len(body))
	if byRatio < ratioFloor {
		byRatio = ratioFloor
	}
	ratioBinds := byRatio < maxOut
	if ratioBinds {
		maxOut = byRatio
	}

	br := bytes.NewReader(body)
	var r io.Reader
	if layers[0] == "gzip" {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, false, !f.hit(rEncCorrupt, 0, corruptDetail(err))
		}
		zr.Multistream(false)
		r = zr
	} else {
		zr, err := zlib.NewReader(br)
		switch {
		case err == nil:
			r = zr
		case lim.AllowRawDeflate && errors.Is(err, zlib.ErrHeader):
			br = bytes.NewReader(body)
			r = flate.NewReader(br)
		default:
			return nil, false, !f.hit(rEncCorrupt, 0, corruptDetail(err))
		}
	}
	var buf bytes.Buffer
	if n := min(maxOut, int64(len(body))*8); n > 0 {
		buf.Grow(int(n))
	}
	n, err := io.Copy(&buf, io.LimitReader(r, maxOut+1))
	if n > maxOut {
		rl := rEncTooLarge
		d := dNone
		if ratioBinds {
			rl = rEncRatio
		}
		return nil, false, !f.hitLimit(rl, d, int(maxOut), -1)
	}
	if err != nil {
		return nil, false, !f.hit(rEncCorrupt, int(int64(len(body))-int64(br.Len())), corruptDetail(err))
	}
	if br.Len() > 0 {
		return nil, false, !f.hit(rEncTrailing, len(body)-br.Len(), dNone)
	}
	out = buf.Bytes()
	if out == nil {
		out = []byte{}
	}
	return out, true, true
}

func corruptDetail(err error) detail {
	switch {
	case errors.Is(err, gzip.ErrChecksum), errors.Is(err, zlib.ErrChecksum):
		return dBadChecksum
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return dTruncated
	case errors.Is(err, gzip.ErrHeader), errors.Is(err, zlib.ErrHeader), errors.Is(err, zlib.ErrDictionary):
		return dBadCompressionHeader
	}
	return dBadStream
}
