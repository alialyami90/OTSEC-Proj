package normalize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
)

const c4Testdata = "../../../contracts/event/testdata/"

// fig1016Read is the C4 goldens' evidence, Figure 10.16 (A2's byte-exact
// transcription, documented-example), as a read: one record per table row
// in transcript order, its span and its fields split from the bytes, and
// the report header as context. The ID values are the goldens'
// (illustrative, see contracts/event/testdata/NOTES.md).
func fig1016Read(t *testing.T, in Input) *read {
	t.Helper()
	data := readFile(t, c4Testdata+"sel751-fig10-16.txt")
	s := string(data)
	hdr := strings.Index(s, "SEL-751")
	fid := strings.Index(s, "FID = ")
	ctx := &adapter.Span{Offset: int64(hdr), Length: int64(fid + strings.Index(s[fid:], "\n") - hdr)}
	heading := strings.Index(s, "#        DATE")
	off := heading + strings.Index(s[heading:], "\n") + 1
	var recs []adapter.Record
	for {
		n := strings.Index(s[off:], "\n")
		line := s[off : off+n]
		if strings.HasPrefix(line, "=>") {
			break
		}
		f := strings.Fields(line)
		if len(f) != 5 {
			t.Fatalf("table line %q", line)
		}
		rec := adapter.Record{Kind: SERKind, Span: adapter.Span{Offset: int64(off), Length: int64(n)}, ContextSpan: ctx, ParseOK: true}
		for i, name := range adapter.RecordFields[SERKind] {
			rec.Fields = append(rec.Fields, adapter.Field{Name: name, Value: f[i]})
		}
		recs = append(recs, rec)
		off += n + 1
	}
	sum := sha256.Sum256(data)
	return &read{
		in:      in,
		assetID: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13",
		target:  asset.Simulated,
		invID:   "0f3e6c1a-8b2d-4e7f-9a15-6c4d2b8e0a71",
		opID:    "sel.ser.read_all",
		data:    data,
		sha:     hex.EncodeToString(sum[:]),
		endedAt: "2026-10-24T12:00:05.200000Z",
		records: recs,
		rxAt:    func(adapter.Span) string { return "2026-10-24T12:00:05.123456Z" },
	}
}

// canonical decodes and re-encodes an event so two encodings compare by
// content.
func canonical(t *testing.T, b []byte) []byte {
	t.Helper()
	var e event.Event
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(&e)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Acceptance (P2-A4): the 8 rows of Figure 10.16 normalize to the 8 C4
// goldens exactly, oldest first, 1:1 with the native rows.
func TestFig1016MatchesC4Goldens(t *testing.T) {
	out, err := fig1016Read(t, testInput(nil)).normalize()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 8 || len(out.Health) != 0 || !out.StateChanged || len(out.State) != 8 {
		t.Fatalf("%d events, %d health, state %d changed %v", len(out.Events), len(out.Health), len(out.State), out.StateChanged)
	}
	for i := range out.Events {
		e := out.Events[i]
		e.ID.Seq = uint64(i + 1)
		asFrozen(t, &e)
		got, err := json.Marshal(&e)
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("sel751-fig10-16-row%d.json", 8-i)
		want := canonical(t, readFile(t, c4Testdata+"valid/"+name))
		if !bytes.Equal(got, want) {
			t.Errorf("%s:\n got %s\nwant %s", name, got, want)
		}
		if err := e.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// asFrozen stamps a produced event with the minor its C4 golden was frozen
// at, 0.1. C4 0.2 added only sender.tls_leaf_sha256, which no SER event
// carries, so the rest must match byte for byte.
func asFrozen(t *testing.T, e *event.Event) {
	t.Helper()
	if e.Schema != event.Identifier || (e.Source.Sender != nil && e.Source.Sender.TLSLeafSHA256 != "") {
		t.Fatalf("schema %s, sender %+v", e.Schema, e.Source.Sender)
	}
	e.Schema = "otsec.event/0.1"
}

// With DATE_F and the UTC offset known, row 8 matches the known-offset
// golden: no assumption flag, and UTC stated as wall clock minus offset.
func TestKnownOffsetMatchesC4Golden(t *testing.T) {
	in := testInput(nil)
	in.DateOrder, in.Offset, in.OffsetBasis = "MDY", "-08:00", event.BasisDeviceSetting
	out, err := fig1016Read(t, in).normalize()
	if err != nil {
		t.Fatal(err)
	}
	e := out.Events[0]
	e.ID.Seq = 1
	asFrozen(t, &e)
	got, _ := json.Marshal(&e)
	want := canonical(t, readFile(t, c4Testdata+"valid/sel751-row8-known-offset.json"))
	if !bytes.Equal(got, want) {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
}

// The constructed goldens' device times: an impossible date is kept with
// invalid-time, and second 60 is a wall clock with no UTC.
func TestConstructedGoldenDeviceTimes(t *testing.T) {
	for _, c := range []struct{ file, date, time string }{
		{"constructed-invalid-date.json", "02/30/2007", "13:54:09.602"},
		{"constructed-leap-second.json", "12/31/2016", "23:59:60.602"},
	} {
		var e event.Event
		if err := json.Unmarshal(readFile(t, c4Testdata+"valid/"+c.file), &e); err != nil {
			t.Fatal(err)
		}
		got := deviceTime(c.date, c.time, testInput(nil), "Internal")
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(e.DeviceTime)
		if !bytes.Equal(g, w) {
			t.Errorf("%s:\n got %s\nwant %s", c.file, g, w)
		}
	}
}
