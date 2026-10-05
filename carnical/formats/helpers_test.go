package formats

import (
	"testing"
	"unicode"
)

// fuzzNoPanic runs a request and checks what must hold for every input: nothing panicked (an inspector that recovers one reports
// internal-error, and that is a failure here), every verdict has an identifier in the range and a plain message, and a verdict
// that blocks has a status that is an error.
func fuzzNoPanic(t testing.TB, in *Inspector, r row) {
	t.Helper()
	res := in.Inspect(r.request())
	for _, v := range res.Verdicts {
		if v.ID == rInternal.id {
			t.Fatalf("the inspector failed on its input: %s", v.Message)
		}
		if v.ID < 5002000 || v.ID > 5002999 {
			t.Fatalf("verdict id %d is outside the range", v.ID)
		}
		if len(v.Message) == 0 || len(v.Message) > 300 {
			t.Fatalf("message length %d", len(v.Message))
		}
		for _, c := range v.Message {
			if c > unicode.MaxASCII || !unicode.IsPrint(c) {
				t.Fatalf("message has an odd character: %q", v.Message)
			}
		}
		if v.Block && (v.Status < 400 || v.Status > 599) {
			t.Fatalf("blocking verdict with status %d", v.Status)
		}
	}
	if len(res.Verdicts) > maxVerdicts {
		t.Fatalf("%d verdicts", len(res.Verdicts))
	}
}

// benchBody measures the inspector on one body and reports nanoseconds per byte.
func benchBody(b *testing.B, ct, body string) {
	b.Helper()
	benchRow(b, row{ct: ct, body: body})
}

func benchRow(b *testing.B, r row) {
	b.Helper()
	in := New(r.policy(nil, false))
	req := r.request()
	if res := in.Inspect(req); len(res.Verdicts) != 0 {
		b.Fatalf("the benchmark body is refused: %s", messages(res))
	}
	b.SetBytes(int64(len(r.body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in.Inspect(req)
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(r.body)), "ns/byte")
}
