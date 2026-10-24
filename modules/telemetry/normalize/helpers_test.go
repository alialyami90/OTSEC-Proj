package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
)

const (
	c2Valid   = "../../../contracts/adapter/testdata/results/valid/"
	testNode  = event.NodeID("site-a-node1")
	serStream = event.Stream("sel751-feeder1/ser")
	hlStream  = event.Stream("platform/health")
)

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// c2Fixtures returns the C2 example invocation and asset that the C2 SER
// example results answer (contracts/adapter and contracts/asset test data).
func c2Fixtures(t testing.TB) (adapter.Invocation, asset.Asset) {
	t.Helper()
	inv, err := adapter.DecodeInvocation(readFile(t, "../../../contracts/adapter/testdata/invocations/valid/sel-ser-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := asset.Decode(readFile(t, "../../../contracts/asset/testdata/valid/sel-751-simulated.json"))
	if err != nil {
		t.Fatal(err)
	}
	return inv, a
}

func c2Result(t testing.TB, name string) adapter.Result {
	t.Helper()
	r, err := adapter.DecodeResult(readFile(t, c2Valid+name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

func testInput(prev []string) Input {
	return Input{
		Node: testNode, Stream: serStream, HealthStream: hlStream,
		ClockResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized, Source: "w32time"},
		Prev: prev,
	}
}

// testRow is one SER table line of a constructed read, and whether the
// constructed adapter parsed it.
type testRow struct {
	line   string
	parsed bool
}

// serLine formats a constructed SER row in the column layout of the C2
// examples. Constructed test data, not device output.
func serLine(num int, date, tm, element, state string) string {
	return fmt.Sprintf("%-5d%s %s   %-17s %s", num, date, tm, element, state)
}

// withRows returns a copy of the C2 result template (ok.json) whose SER
// table holds rows instead, in the given transcript order, with spans,
// segments, records and the transcript hash rebuilt so the result is still
// valid C2. Everything outside the table is unchanged. The bytes are
// constructed test data, not a device capture.
func withRows(t testing.TB, rows []testRow) adapter.Result {
	t.Helper()
	tpl := c2Result(t, "ok.json")
	first, last := tpl.Records[0], tpl.Records[len(tpl.Records)-1]
	start := first.Span.Offset
	end := last.Span.Offset + last.Span.Length
	lines := make([]string, len(rows))
	for i, r := range rows {
		lines[i] = r.line
	}
	table := strings.Join(lines, "\r\n")
	old := tpl.Transcript.Data
	data := append(append(append([]byte{}, old[:start]...), table...), old[end:]...)
	delta := int64(len(data) - len(old))
	segs := append([]adapter.Segment{}, tpl.Transcript.Segments...)
	for i := range segs {
		switch {
		case segs[i].Offset > start:
			segs[i].Offset += delta
		case segs[i].Offset+segs[i].Length >= end:
			segs[i].Length += delta
		}
	}
	res := tpl
	res.Transcript.Data = data
	res.Transcript.Segments = segs
	sum := sha256.Sum256(data)
	res.Transcript.SHA256 = hex.EncodeToString(sum[:])
	res.Records = nil
	off := start
	for _, r := range rows {
		rec := adapter.Record{Kind: SERKind, Span: adapter.Span{Offset: off, Length: int64(len(r.line))}, ContextSpan: first.ContextSpan, ParseOK: r.parsed}
		if r.parsed {
			f := strings.Fields(r.line)
			if len(f) != 5 {
				t.Fatalf("constructed row %q does not split into 5 fields", r.line)
			}
			for i, name := range adapter.RecordFields[SERKind] {
				rec.Fields = append(rec.Fields, adapter.Field{Name: name, Value: f[i]})
			}
		}
		res.Records = append(res.Records, rec)
		off += int64(len(r.line)) + 2
	}
	res.Status, res.Error = adapter.StatusOK, nil
	for _, r := range rows {
		if !r.parsed {
			res.Status, res.Error = adapter.StatusPartial, &adapter.Error{Code: adapter.PartialParseErrors}
		}
	}
	if err := res.Validate(); err != nil {
		t.Fatalf("constructed result is not valid C2: %v", err)
	}
	return res
}

// bufferRows is a constructed SER buffer: n distinct parsed rows, oldest
// first, each identified by its millisecond.
func bufferRows(n int) []string {
	out := make([]string, n)
	for i := range out {
		state := "Asserted"
		if i%2 == 1 {
			state = "Deasserted"
		}
		out[i] = fmt.Sprintf("10/24/2026 09:%02d:%02d.%03d   %-17s %s", i/60000%60, i/1000%60, i%1000, "IN101", state)
	}
	return out
}

// readOf prints the rows of a buffer window as the relay does: oldest
// first, numbered from len(window) down to 1.
func readOf(window []string) []testRow {
	rows := make([]testRow, len(window))
	for i, body := range window {
		rows[i] = testRow{line: fmt.Sprintf("%-5d%s", len(window)-i, body), parsed: true}
	}
	return rows
}
