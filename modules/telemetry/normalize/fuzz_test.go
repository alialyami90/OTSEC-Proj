package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
)

// FuzzSERRow runs the whole read path on one row of arbitrary bytes, with
// the fields an adapter would split from it and a header of arbitrary
// bytes. Whatever the device sends, Normalize returns events that pass C4
// (it checks every event it builds) or an error, and never panics.
func FuzzSERRow(f *testing.F) {
	f.Add([]byte("8     02/28/2007   13:54:09.602   51P1P                    Asserted"), []byte("FEEDER 1   Time Source: Internal\r\n"), "")
	f.Add([]byte("1    10/24/2026 09:1#:0?.###   IN102             Asserted"), []byte(""), "DMY")
	f.Add([]byte("1 12/31/2016 23:59:60.602 X Y"), []byte("Time Source:"), "YMD")
	f.Fuzz(func(t *testing.T, line, header []byte, order string) {
		if len(line)+len(header) > 1<<16 {
			return
		}
		data := append(append(append([]byte{}, header...), '\n'), line...)
		rec := adapter.Record{Kind: SERKind, Span: adapter.Span{Offset: int64(len(header) + 1), Length: int64(len(line))},
			ContextSpan: &adapter.Span{Offset: 0, Length: int64(len(header))}}
		if fs := strings.Fields(string(line)); len(fs) == 5 {
			rec.ParseOK = true
			for i, name := range adapter.RecordFields[SERKind] {
				rec.Fields = append(rec.Fields, adapter.Field{Name: name, Value: fs[i]})
			}
		}
		in := testInput(nil)
		if dateOrders[order] != nil {
			in.DateOrder = order
		}
		sum := sha256.Sum256(data)
		rd := &read{in: in, assetID: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", target: asset.Simulated,
			invID: "0f3e6c1a-8b2d-4e7f-9a15-6c4d2b8e0a71", opID: "sel.ser.read_all", data: data, sha: hex.EncodeToString(sum[:]),
			endedAt: "2026-10-24T12:00:05.2Z", records: []adapter.Record{rec},
			rxAt: func(adapter.Span) string { return "2026-10-24T12:00:05.123456Z" }}
		out, err := rd.normalize()
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if len(out.Events)+len(out.Health) == 0 {
			t.Fatalf("%q: the row produced nothing", line)
		}
	})
}

// FuzzDecodeState: the state read back from the store is checked as if it
// were hostile, and whatever decodes re-encodes to the same keys.
func FuzzDecodeState(f *testing.F) {
	f.Add([]byte(`{"format":"otsec.normalize.ser-state/1","keys":["sha256:` + strings.Repeat("a", 64) + `"]}`))
	f.Add([]byte(`{"format":"otsec.normalize.ser-state/1","keys":[]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		keys, err := DecodeState(b)
		if err != nil || keys == nil {
			return
		}
		again, err := EncodeState(keys)
		if err != nil {
			t.Fatal(err)
		}
		back, err := DecodeState(again)
		if err != nil || len(back) != len(keys) {
			t.Fatalf("re-encoded state: %v", err)
		}
	})
}
