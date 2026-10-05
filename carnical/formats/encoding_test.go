package formats

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	idEncUnsupported = 5002070
	idEncLayers      = 5002071
	idEncCorrupt     = 5002072
	idEncTrailing    = 5002073
	idEncTooLarge    = 5002074
	idEncRatio       = 5002075
)

func gz(s string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

func gzNamed(s string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Name, w.Comment, w.Extra = "data.json", "a comment", []byte("xy")
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

func zl(s string) string {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

func rawDeflate(s string) string {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, flate.DefaultCompression)
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

func flip(s string, from int) string {
	b := []byte(s)
	b[len(b)-from] ^= 0xff
	return string(b)
}

func enc(v string) map[string]string { return map[string]string{"Content-Encoding": v} }

const smallJSON = `{"user":"alice","roles":["a","b"]}`

var encodingRows = register("encoding", []row{
	// Accepted.
	{name: "gzip json", ct: appJSON, hdr: enc("gzip"), body: gz(smallJSON)},
	{name: "gzip in upper case", ct: appJSON, hdr: enc("GZIP"), body: gz(smallJSON)},
	{name: "gzip with a name, a comment and extra fields", ct: appJSON, hdr: enc("gzip"), body: gzNamed(smallJSON)},
	{name: "deflate json", ct: appJSON, hdr: enc("deflate"), body: zl(smallJSON)},
	{name: "identity", ct: appJSON, hdr: enc("identity"), body: smallJSON},
	{name: "gzip form", ct: form, hdr: enc("gzip"), body: gz("a=1&b=2")},
	{name: "gzip of an empty body", ct: appJSON, hdr: enc("gzip"), body: gz("")},
	{name: "a repetitive body under the ratio", ct: appJSON, hdr: enc("gzip"), body: gz(`{"a":"` + strings.Repeat("x", 3000) + `"}`)},
	{name: "raw deflate when the policy allows it", ct: appJSON, hdr: enc("deflate"), body: rawDeflate(smallJSON),
		tweak: func(p *Policy) { p.Encoding.AllowRawDeflate = true }},

	// Bombs.
	{name: "a gzip bomb at a ratio of a thousand", ct: appJSON, hdr: enc("gzip"), body: gz(strings.Repeat("0", 1<<20)), want: idEncRatio},
	{name: "a gzip bomb of sixteen megabytes", ct: appJSON, hdr: enc("gzip"), body: gz(strings.Repeat("0", 16<<20)), want: idEncTooLarge},
	{name: "a deflate bomb", ct: appJSON, hdr: enc("deflate"), body: zl(strings.Repeat("0", 8<<20)), want: idEncRatio},
	{name: "a gzip bomb when the ratio is not what limits it", ct: appJSON, hdr: enc("gzip"), body: gz(strings.Repeat("0", 8<<10)), want: idEncTooLarge,
		tweak: func(p *Policy) { p.Encoding.MaxOutput = 4096; p.Encoding.MaxRatio = 100000 }},
	{name: "output over the limit at a ratio under it", ct: appJSON, hdr: enc("gzip"), body: gz(`{"a":"` + strings.Repeat("0123456789abcdef", 600) + `"}`), want: idEncTooLarge,
		tweak: func(p *Policy) { p.Encoding.MaxOutput = 8000; p.Encoding.MaxRatio = 100000 }},
	{name: "output exactly at the limit", ct: appJSON, hdr: enc("gzip"), body: gz(`{"a":"` + strings.Repeat("0123456789abcdef", 600) + `"}`),
		tweak: func(p *Policy) { p.Encoding.MaxOutput = 9608; p.Encoding.MaxRatio = 100000 }},
	{name: "decompressed body over the body limit", ct: appJSON, hdr: enc("gzip"), body: gz(`{"a":"` + strings.Repeat("0123456789abcdef", 20) + `"}`), want: 5002010,
		tweak: func(p *Policy) { p.MaxBodyBytes = 200 }},

	// Layers and unsupported encodings.
	{name: "gzip twice in one header", ct: appJSON, hdr: enc("gzip, gzip"), body: gz(gz(smallJSON)), want: idEncLayers},
	{name: "gzip then deflate", ct: appJSON, hdr: enc("deflate, gzip"), body: gz(zl(smallJSON)), want: idEncLayers},
	{name: "brotli", ct: appJSON, hdr: enc("br"), body: smallJSON, want: idEncUnsupported},
	{name: "zstd", ct: appJSON, hdr: enc("zstd"), body: smallJSON, want: idEncUnsupported},
	{name: "compress", ct: appJSON, hdr: enc("compress"), body: smallJSON, want: idEncUnsupported},
	{name: "x-gzip", ct: appJSON, hdr: enc("x-gzip"), body: gz(smallJSON), want: idEncUnsupported},
	{name: "an encoding nobody defined", ct: appJSON, hdr: enc("rot13"), body: smallJSON, want: idEncUnsupported},

	// A stream that is not right.
	{name: "bytes after the gzip stream", ct: appJSON, hdr: enc("gzip"), body: gz(smallJSON) + "trailing", want: idEncTrailing},
	{name: "a second gzip member", ct: appJSON, hdr: enc("gzip"), body: gz(smallJSON) + gz(`{"evil":true}`), want: idEncTrailing},
	{name: "bytes after the zlib stream", ct: appJSON, hdr: enc("deflate"), body: zl(smallJSON) + "xx", want: idEncTrailing},
	{name: "a wrong checksum in gzip", ct: appJSON, hdr: enc("gzip"), body: flip(gz(smallJSON), 6), want: idEncCorrupt},
	{name: "a wrong length in gzip", ct: appJSON, hdr: enc("gzip"), body: flip(gz(smallJSON), 1), want: idEncCorrupt},
	{name: "a wrong checksum in zlib", ct: appJSON, hdr: enc("deflate"), body: flip(zl(smallJSON), 1), want: idEncCorrupt},
	{name: "a truncated gzip stream", ct: appJSON, hdr: enc("gzip"), body: gz(smallJSON)[:20], want: idEncCorrupt},
	{name: "a truncated zlib stream", ct: appJSON, hdr: enc("deflate"), body: zl(smallJSON)[:10], want: idEncCorrupt},
	{name: "no gzip header", ct: appJSON, hdr: enc("gzip"), body: smallJSON, want: idEncCorrupt},
	{name: "random bytes as gzip", ct: appJSON, hdr: enc("gzip"), body: "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xffgarbage garbage garbage", want: idEncCorrupt},
	{name: "no zlib header", ct: appJSON, hdr: enc("deflate"), body: smallJSON, want: idEncCorrupt},
	{name: "raw deflate when the policy does not allow it", ct: appJSON, hdr: enc("deflate"), body: rawDeflate(smallJSON), want: idEncCorrupt},
	{name: "a preset dictionary", ct: appJSON, hdr: enc("deflate"), body: "\x78\xbb\x00\x00\x00\x01" + rawDeflate(smallJSON), want: idEncCorrupt},

	// What is inside is read by its own type.
	{name: "gzip of json with a duplicate key", ct: appJSON, hdr: enc("gzip"), body: gz(`{"a":1,"A":2}`), want: idJSONDup},
	{name: "gzip of malformed json", ct: appJSON, hdr: enc("gzip"), body: gz(`{"a":`), want: idJSONSyntax},
	{name: "gzip of utf-16 json", ct: appJSON, hdr: enc("gzip"), body: gz(utf16le(`{"a":1}`)), want: idWide},
	{name: "gzip of a form with a semicolon", ct: form, hdr: enc("gzip"), body: gz("a=1;b=2"), want: idFormSemi},
	{name: "gzip of json under a form type", ct: form, hdr: enc("gzip"), body: gz(smallJSON), want: 5002040},
	{name: "deflate of xml with a doctype", ct: "application/xml", hdr: enc("deflate"), body: zl(`<!DOCTYPE a><a/>`), want: idXMLDoctype},
	{name: "gzip of a graphql batch of fifty", path: "/graphql", ct: appJSON, hdr: enc("gzip"), body: gz(batch(50, `{ a }`)), want: idGQLBatch},
})

func TestEncoding(t *testing.T) { runTable(t, encodingRows) }

// TestDecodedBodyIsHandedOn checks what the proxy needs: the decompressed body replaces the request's, and Content-Encoding goes.
func TestDecodedBodyIsHandedOn(t *testing.T) {
	in := New(Policy{})
	for _, tc := range []struct {
		name, enc, body string
	}{
		{"gzip", "gzip", gz(smallJSON)}, {"deflate", "deflate", zl(smallJSON)}, {"empty", "gzip", gz("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := in.Inspect(row{ct: appJSON, hdr: enc(tc.enc), body: tc.body}.request())
			if len(res.Verdicts) != 0 {
				t.Fatal(res.Verdicts)
			}
			want := smallJSON
			if tc.name == "empty" {
				want = ""
			}
			if res.Body == nil || string(res.Body) != want {
				t.Fatalf("body %q (nil %v), want %q", res.Body, res.Body == nil, want)
			}
			if len(res.DelHeader) != 1 || res.DelHeader[0] != "Content-Encoding" {
				t.Fatalf("headers to delete: %v", res.DelHeader)
			}
		})
	}
	t.Run("an identity body is not replaced", func(t *testing.T) {
		res := in.Inspect(row{ct: appJSON, body: smallJSON}.request())
		if res.Body != nil || res.DelHeader != nil {
			t.Fatalf("%v %v", res.Body, res.DelHeader)
		}
	})
	t.Run("a refused body is not handed on", func(t *testing.T) {
		res := in.Inspect(row{ct: appJSON, hdr: enc("gzip"), body: gz(`{"a":1,"a":2}`)}.request())
		if res.Body != nil || len(res.Verdicts) == 0 {
			t.Fatalf("%v", res)
		}
	})
	t.Run("monitor mode keeps the compressed body when it cannot be decompressed", func(t *testing.T) {
		res := New(Policy{Monitor: true}).Inspect(row{ct: appJSON, hdr: enc("gzip"), body: "not gzip at all"}.request())
		if res.Body != nil || res.DelHeader != nil || !has(ids(res.Verdicts), idEncCorrupt) {
			t.Fatalf("%v", res)
		}
		for _, v := range res.Verdicts {
			if v.Block {
				t.Fatalf("refused in monitor mode: %v", v)
			}
		}
	})
}

// TestDecompressionIsBoundedByTheLimitNotByTheInput measures that the bytes produced stay at the limit however large the stream says
// it is: a bomb that would expand to a gigabyte is stopped after the limit and one byte.
func TestDecompressionIsBoundedByTheLimitNotByTheInput(t *testing.T) {
	bomb := func(mib int) string {
		var b bytes.Buffer
		w, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
		chunk := bytes.Repeat([]byte{0}, 1<<20)
		for i := 0; i < mib; i++ {
			w.Write(chunk)
		}
		w.Close()
		return b.String()
	}
	huge, small := bomb(256), bomb(8) // a quarter of a gibibyte of zeros, and eight mebibytes
	if len(huge) > 1<<20 || len(small) > 16<<10 {
		t.Fatalf("the bombs are %d and %d bytes", len(huge), len(small))
	}
	for _, tc := range []struct {
		name string
		body string
		pol  Policy
		id   int
	}{
		{"stopped by the ratio", small, Policy{}, idEncRatio},
		{"stopped by the output limit", huge, Policy{}, idEncTooLarge},
		{"stopped by the output limit with the ratio off", huge, Policy{Encoding: EncodingLimits{MaxRatio: 100000}}, idEncTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := New(tc.pol)
			req := row{ct: appJSON, hdr: enc("gzip"), body: tc.body}.request()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			res := in.Inspect(req)
			took := time.Since(start)
			runtime.ReadMemStats(&after)
			if len(res.Verdicts) != 1 || res.Verdicts[0].ID != tc.id {
				t.Fatalf("%v", res.Verdicts)
			}
			// The output limit is 1 MiB: producing it, and one byte, is all that may be done, so memory stays a few multiples of it.
			if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
				t.Fatalf("allocated %d bytes for a 256 MiB bomb", grew)
			}
			if took > 500*time.Millisecond {
				t.Fatalf("took %v", took)
			}
		})
	}
}

func FuzzEncoding(f *testing.F) {
	for _, r := range encodingRows {
		if len(r.body) < 64<<10 {
			f.Add(r.body)
		}
	}
	in := New(Policy{})
	raw := New(Policy{Encoding: EncodingLimits{AllowRawDeflate: true}})
	f.Fuzz(func(t *testing.T, body string) {
		fuzzNoPanic(t, in, row{ct: appJSON, hdr: enc("gzip"), body: body})
		fuzzNoPanic(t, in, row{ct: appJSON, hdr: enc("deflate"), body: body})
		fuzzNoPanic(t, raw, row{ct: appJSON, hdr: enc("deflate"), body: body})
		fuzzNoPanic(t, in, row{ct: appJSON, hdr: enc("gzip"), body: gz(body)})
		fuzzNoPanic(t, in, row{ct: form, hdr: enc("deflate"), body: zl(body)})
	})
}

func BenchmarkGzip(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`{"users":[`)
	// Records that differ, so that the body compresses about as well as real JSON does (4 to 8 times), not a thousand times.
	for i := 0; sb.Len() < 400<<10; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"id":%d,"name":"User %x","email":"u%x@mail%d.example.test","tags":["t%d","x%x"],"active":%v,"score":%d.%d}`,
			12345+i*7919, i*2654435761, i*40503, i%97, i%13, i*31, i%3 == 0, i*17%1000, i%10)
	}
	sb.WriteString(`]}`)
	plain := sb.String()
	packed := gz(plain)
	in := New(Policy{})
	req := row{ct: appJSON, hdr: enc("gzip"), body: packed}.request()
	if res := in.Inspect(req); len(res.Verdicts) != 0 {
		b.Fatal(messages(res))
	}
	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in.Inspect(req)
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(plain)), "ns/byte")
}
