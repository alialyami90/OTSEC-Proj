package normalize

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
)

// figureOrder is the C2 ok.json SER read with its two rows printed in the
// order Figure 10.16 prints rows: the older row 2 first, row 1 last.
func figureOrder(t *testing.T) adapter.Result {
	return withRows(t, []testRow{
		{serLine(2, "10/24/2026", "09:10:01.004", "IN101", "Asserted"), true},
		{serLine(1, "10/24/2026", "09:10:01.251", "IN101", "Deasserted"), true},
	})
}

func TestNormalizeC2Read(t *testing.T) {
	inv, a := c2Fixtures(t)
	res := figureOrder(t)
	out, err := Normalize(res, inv, a, testInput(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 2 || len(out.Health) != 0 {
		t.Fatalf("%d events, %d health", len(out.Events), len(out.Health))
	}
	for i, want := range []struct{ pos, time, state string }{{"2", "09:10:01.004", "Asserted"}, {"1", "09:10:01.251", "Deasserted"}} {
		e := out.Events[i]
		rec := res.Records[i]
		switch {
		case e.Collection.NativePosition != want.pos || e.Normalized.Value != want.state || e.DeviceTime.Native != "10/24/2026 "+want.time:
			t.Errorf("event %d: row %s %q %s", i, e.Collection.NativePosition, e.DeviceTime.Native, e.Normalized.Value)
		case e.Source.EvidenceClass != asset.Simulated || !e.Source.Simulated():
			t.Errorf("event %d: evidence class %q", i, e.Source.EvidenceClass)
		case e.Collection.Alignment != event.AlignFirstRead || e.Collection.InvocationID != res.InvocationID:
			t.Errorf("event %d: collection %+v", i, e.Collection)
		case e.Received.UTC != res.Transcript.ReceivedAt(rec.Span) || e.Received.UTC != "2026-10-24T09:15:01.3Z":
			t.Errorf("event %d: received %s", i, e.Received.UTC)
		case e.Native.Evidence.SHA256 != res.Transcript.SHA256 || e.Native.Evidence.Ref != store.EvidenceRef(res.Transcript.SHA256):
			t.Errorf("event %d: evidence %+v", i, e.Native.Evidence)
		case string(e.Native.Bytes) != string(res.Transcript.Data[rec.Span.Offset:rec.Span.Offset+rec.Span.Length]):
			t.Errorf("event %d: native bytes %q", i, e.Native.Bytes)
		case e.DeviceTime.Quality.TimeSource != "Internal" || !slices.Contains(e.DeviceTime.Flags, "date-format-assumed:MDY"):
			t.Errorf("event %d: device time %+v", i, e.DeviceTime)
		}
		for j, f := range rec.Fields {
			if e.Native.Fields[j].Name != f.Name || e.Native.Fields[j].Value != f.Value {
				t.Errorf("event %d field %d: %+v, want %+v", i, j, e.Native.Fields[j], f)
			}
		}
	}
	// The C5 records commit and read back as valid stored events.
	ser, hl, err := out.Records(serStream, hlStream)
	if err != nil || len(ser) != 2 || len(hl) != 0 {
		t.Fatalf("records: %d %d %v", len(ser), len(hl), err)
	}
	for i, r := range ser {
		if err := r.Validate(); err != nil || r.Class != store.ClassAdapterEvidence || r.Capture == nil {
			t.Errorf("record %d: %v", i, err)
		}
		stored := strings.Replace(string(r.Event), `"seq":0`, `"seq":7`, 1)
		if _, err := event.Decode([]byte(stored)); err != nil {
			t.Errorf("record %d does not decode once seq is assigned: %v", i, err)
		}
	}
	if ser[0].SourceCursor != nil {
		t.Error("state on a record other than the last")
	}
	if st, err := DecodeState(ser[1].SourceCursor); err != nil || !slices.Equal(st, out.State) {
		t.Errorf("state %v %v", st, err)
	}
}

// A read whose rows print row 1 (the newest) first, against Figure 10.16,
// would store the newest row first. It is kept as bytes and not aligned.
func TestNewestFirstReadIsNotAligned(t *testing.T) {
	inv, a := c2Fixtures(t)
	res := withRows(t, []testRow{
		{serLine(1, "10/24/2026", "09:10:01.251", "IN101", "Deasserted"), true},
		{serLine(2, "10/24/2026", "09:10:01.004", "IN101", "Asserted"), true},
	})
	out, err := Normalize(res, inv, a, testInput(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 0 || len(out.Health) != 1 || out.Health[0].Health.Type != event.HealthParseFailed || out.StateChanged || out.State != nil {
		t.Fatalf("%d events, health %+v", len(out.Events), out.Health)
	}
	if d := out.Health[0].Health.Details; d["aligned"] != "false" || !strings.Contains(d["reason"], "row number") {
		t.Errorf("details %v", d)
	}
}

// The C2 SER examples normalize when their rows follow Figure 10.16, and
// are kept as bytes when they print row 1 first (A2 is reordering them;
// this test holds before and after that change).
func TestC2SERExamples(t *testing.T) {
	inv, a := c2Fixtures(t)
	for _, name := range []string{"ok.json", "ok-with-echo.json", "partial.parse_errors.json"} {
		res := c2Result(t, name)
		inOrder := true
		for i, rec := range res.Records {
			if rec.ParseOK && rec.Fields[0].Value != strconv.Itoa(len(res.Records)-i) {
				inOrder = false
			}
		}
		out, err := Normalize(res, inv, a, testInput(nil))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if inOrder && len(out.Events) != len(res.Records) {
			t.Errorf("%s: %d events for %d rows", name, len(out.Events), len(res.Records))
		}
		if !inOrder && (len(out.Events) != 0 || out.Health[0].Health.Details["aligned"] != "false") {
			t.Errorf("%s: newest-first read aligned: %+v", name, out)
		}
	}
}

// A read over the row limit keeps its bytes, raises parse.failed and aligns
// nothing (D1-12); the health record carries the capture.
func TestReadRowsExceeded(t *testing.T) {
	inv, a := c2Fixtures(t)
	prev := []string{"sha256:" + strings.Repeat("a", 64)}
	res := c2Result(t, "partial.read_rows_exceeded.json")
	out, err := Normalize(res, inv, a, testInput(prev))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 0 || len(out.Health) != 1 || out.StateChanged || !slices.Equal(out.State, prev) {
		t.Fatalf("%+v", out)
	}
	h := out.Health[0]
	if h.Health.Type != event.HealthParseFailed || !strings.Contains(h.Health.Details["reason"], "D1-12") || h.Health.Details["evidence_sha256"] != res.Transcript.SHA256 {
		t.Errorf("health %+v", h.Health)
	}
	_, hl, err := out.Records(serStream, hlStream)
	if err != nil || len(hl) != 1 || hl[0].Capture == nil || hl[0].Capture.SHA256 != res.Transcript.SHA256 || hl[0].Class != store.ClassPlatform {
		t.Fatalf("health record: %+v %v", hl, err)
	}
	if err := hl[0].Validate(); err != nil {
		t.Error(err)
	}
}

// A failed or refused result with no records produces nothing and keeps the
// state.
func TestFailedAndRefusedProduceNothing(t *testing.T) {
	inv, a := c2Fixtures(t)
	prev := []string{"sha256:" + strings.Repeat("b", 64)}
	entries, err := os.ReadDir(c2Valid)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, de := range entries {
		name := de.Name()
		if !strings.HasPrefix(name, "failed.") && !strings.HasPrefix(name, "refused.") {
			continue
		}
		n++
		res := c2Result(t, name)
		// Each example answers its own invocation; tie it to the fixture
		// invocation so CheckAgainst passes and only the status decides.
		inv2 := inv
		inv2.InvocationID, inv2.OperationID = res.InvocationID, res.OperationID
		out, err := Normalize(res, inv2, a, testInput(prev))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(out.Events) != 0 || len(out.Health) != 0 || out.StateChanged || !slices.Equal(out.State, prev) {
			t.Errorf("%s: %+v", name, out)
		}
	}
	if n < 20 {
		t.Fatalf("only %d failed and refused examples", n)
	}
}

// A failed result that still carries rows is an unfinished read: kept as
// bytes, not aligned.
func TestFailedWithRecordsIsNotAligned(t *testing.T) {
	inv, a := c2Fixtures(t)
	res := figureOrder(t)
	res.Status, res.Error = adapter.StatusFailed, &adapter.Error{Code: adapter.FailedTimeout}
	out, err := Normalize(res, inv, a, testInput(nil))
	if err != nil {
		t.Skipf("C2 refuses a timeout after quit: %v", err)
	}
	if len(out.Events) != 0 || len(out.Health) != 1 || !strings.Contains(out.Health[0].Health.Details["reason"], "unfinished") {
		t.Errorf("%+v", out)
	}
}

// Fail closed: a result C2 refuses, or one that is not the answer to this
// invocation on this asset's endpoint, produces nothing.
func TestRefusesResult(t *testing.T) {
	inv, a := c2Fixtures(t)
	cases := map[string]func(*adapter.Result, *adapter.Invocation){
		"simulator reported as device": func(r *adapter.Result, _ *adapter.Invocation) { r.Target = asset.DeviceObserved },
		"transcript byte changed":      func(r *adapter.Result, _ *adapter.Invocation) { r.Transcript.Data[900] ^= 1 },
		"other invocation": func(_ *adapter.Result, i *adapter.Invocation) {
			i.InvocationID = "00000000-0000-4000-8000-000000000000"
		},
		"other endpoint": func(_ *adapter.Result, i *adapter.Invocation) { i.EndpointID = "port2-telnet" },
	}
	for name, mutate := range cases {
		res := figureOrder(t)
		inv2 := inv
		mutate(&res, &inv2)
		if _, err := Normalize(res, inv2, a, testInput(nil)); !errors.Is(err, ErrResult) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRefusesInput(t *testing.T) {
	inv, a := c2Fixtures(t)
	res := figureOrder(t)
	cases := map[string]func(*Input){
		"bad node":             func(in *Input) { in.Node = "Site" },
		"bad stream":           func(in *Input) { in.Stream = "a:b" },
		"shared stream":        func(in *Input) { in.HealthStream = in.Stream },
		"no clock resolution":  func(in *Input) { in.ClockResolutionNS = 0 },
		"bad clock sync":       func(in *Input) { in.Clock.Sync = "fine" },
		"bad date order":       func(in *Input) { in.DateOrder = "MYD" },
		"offset without basis": func(in *Input) { in.Offset = "+01:00" },
		"basis without offset": func(in *Input) { in.OffsetBasis = event.BasisOperator },
		"malformed offset":     func(in *Input) { in.Offset, in.OffsetBasis = "+1:00", event.BasisOperator },
		"malformed prev key":   func(in *Input) { in.Prev = []string{"sha256:XYZ"} },
		"prev too long":        func(in *Input) { in.Prev = make([]string, event.MaxAlignRows+1) },
	}
	for name, mutate := range cases {
		in := testInput(nil)
		mutate(&in)
		if _, err := Normalize(res, inv, a, in); !errors.Is(err, ErrInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A row the adapter could not parse, and a row whose parsed fields are not
// in its bytes, are still events: native bytes kept, nothing else (EP-1).
func TestUnparsedAndInconsistentRows(t *testing.T) {
	inv, a := c2Fixtures(t)
	res := withRows(t, []testRow{
		{"3    10/24/2026 09:1#:0?.###   IN102             Asserted", false},
		{serLine(2, "10/24/2026", "09:10:01.004", "IN101", "Asserted"), true},
		{serLine(1, "10/24/2026", "09:10:01.251", "IN101", "Deasserted"), true},
	})
	res.Records[1].Fields[3].Value = "IN999" // not what the row prints
	out, err := Normalize(res, inv, a, testInput(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 3 {
		t.Fatalf("%d events", len(out.Events))
	}
	for i, failed := range []bool{true, true, false} {
		e := out.Events[i]
		isFailed := e.Collection.ParseStatus == event.ParseFailed
		if isFailed != failed || (failed && (e.Normalized != nil || e.DeviceTime != nil || e.Native.Fields != nil || e.Native.Bytes == nil)) {
			t.Errorf("event %d: %+v", i, e.Collection)
		}
	}
	if len(out.Health) != 1 || out.Health[0].Health.Details["records_failed"] != "2" || out.Health[0].Health.Details["aligned"] != "true" {
		t.Errorf("health %+v", out.Health)
	}
	// The unparsed row's key skips its row number, so the same bytes
	// renumbered on the next read get the same key.
	want := fallbackKeyStart([]byte("3    10/24/2026"))
	if want != 5 {
		t.Errorf("fallback key start %d", want)
	}
}

func TestFieldsInRow(t *testing.T) {
	fields := func(v ...string) adapter.Record {
		r := adapter.Record{Kind: SERKind, ParseOK: true}
		for i, name := range adapter.RecordFields[SERKind] {
			r.Fields = append(r.Fields, adapter.Field{Name: name, Value: v[i]})
		}
		return r
	}
	ok := fields("8", "02/28/2007", "13:54:09.602", "51P1P", "Asserted")
	row := "8     02/28/2007   13:54:09.602   51P1P                    Asserted"
	if d, good := fieldsInRow([]byte(row), ok); !good || d != 6 {
		t.Fatalf("figure row: %d %v", d, good)
	}
	for name, c := range map[string]struct {
		row string
		rec adapter.Record
	}{
		"value missing":    {row, fields("8", "02/28/2007", "13:54:09.603", "51P1P", "Asserted")},
		"values reordered": {row, fields("8", "02/28/2007", "13:54:09.602", "Asserted", "51P1P")},
		"no space between": {"8 02/28/200713:54:09.602 51P1P Asserted", ok},
		"text after state": {row + " X", ok},
		"tab separator":    {"8\t02/28/2007 13:54:09.602 51P1P Asserted", ok},
		"carriage return":  {row + "\r", ok},
		"lowercase name": {row, func() adapter.Record {
			r := ok
			r.Fields = slices.Clone(ok.Fields)
			r.Fields[1].Name = "date"
			return r
		}()},
		"value is a prefix": {"8     02/28/2007   13:54:09.6021   51P1P   Asserted", ok},
		"not parsed":        {row, func() adapter.Record { r := ok; r.ParseOK = false; return r }()},
	} {
		if _, good := fieldsInRow([]byte(c.row), c.rec); good {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDeviceTime(t *testing.T) {
	known := testInput(nil)
	known.DateOrder, known.Offset, known.OffsetBasis = "DMY", "+05:30", event.BasisOperator
	for _, c := range []struct {
		name, date, time string
		in               Input
		wall, utc        string
		res              int64
		invalid          bool
	}{
		{"figure row", "02/28/2007", "13:54:09.602", testInput(nil), "2007-02-28T13:54:09.602", "", 1e6, false},
		{"no fraction", "02/28/2007", "13:54:09", testInput(nil), "2007-02-28T13:54:09", "", 1e9, false},
		{"nine digits", "02/28/2007", "13:54:09.123456789", testInput(nil), "2007-02-28T13:54:09.123456789", "", 1, false},
		{"leap year", "02/29/2024", "00:00:00.000", testInput(nil), "2024-02-29T00:00:00.000", "", 1e6, false},
		{"not a leap year", "02/29/2023", "00:00:00.000", testInput(nil), "", "", 1e6, true},
		{"month 13", "13/01/2007", "00:00:00.000", testInput(nil), "", "", 1e6, true},
		{"DMY known offset", "28/02/2007", "03:00:00.500", known, "2007-02-28T03:00:00.500", "2007-02-27T21:30:00.500Z", 1e6, false},
		{"two-digit year", "02/28/07", "13:54:09.602", testInput(nil), "", "", 1e6, true},
		{"hour 24", "02/28/2007", "24:00:00.000", testInput(nil), "", "", 1e6, true},
		{"ten digits", "02/28/2007", "13:54:09.1234567890", testInput(nil), "", "", 1e9, true},
		{"leap second unknown offset", "06/30/2015", "16:59:60.000", testInput(nil), "2015-06-30T16:59:60.000", "", 1e6, false},
		{"leap second not 23:59 UTC", "28/02/2007", "06:29:60.000", known, "", "", 1e6, true},
		{"leap second at 23:59 UTC", "01/01/2017", "05:29:60.000", known, "2017-01-01T05:29:60.000", "", 1e6, false},
		{"garbage", "ab/cd/efgh", "xx:yy:zz", testInput(nil), "", "", 1e9, true},
	} {
		dt := deviceTime(c.date, c.time, c.in, "Internal")
		inv := slices.Contains(dt.Flags, "invalid-time")
		if dt.WallClock != c.wall || dt.UTC != c.utc || dt.ResolutionNS != c.res || inv != c.invalid || dt.Native != c.date+" "+c.time {
			t.Errorf("%s: %+v", c.name, dt)
		}
		// Whatever the input, the result is valid C4.
		e := event.Event{Schema: event.Identifier, ID: event.EventID{NodeID: testNode, Stream: serStream}, Origin: event.OriginDevice, Kind: event.KindSER,
			Source:     event.Source{Sender: &event.Sender{Address: "x"}, OriginAuth: event.AuthSession, EvidenceClass: asset.Simulated},
			Flags:      []string{"asset-unresolved"},
			Collection: &event.Collection{Method: event.MethodAdapterPoll, InvocationID: "i", OperationID: "o", ParseStatus: event.ParsePartial},
			Received:   event.Received{UTC: "2026-10-24T00:00:00Z", ResolutionNS: 1, Clock: event.Clock{Sync: event.SyncUnknown}},
			Native:     &event.Native{RecordSHA256: strings.Repeat("0", 64), Evidence: event.Evidence{SHA256: strings.Repeat("0", 64)}},
			DeviceTime: &dt}
		if err := e.ValidatePending(); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestTruncateUTC(t *testing.T) {
	for _, c := range []struct {
		in   string
		res  int64
		want string
	}{
		{"2026-10-24T09:15:01.3Z", 1000, "2026-10-24T09:15:01.3Z"},
		{"2026-10-24T09:15:01.1234567Z", 1000, "2026-10-24T09:15:01.123456Z"},
		{"2026-10-24T09:15:01.1234567Z", 100, "2026-10-24T09:15:01.1234567Z"},
		{"2026-10-24T09:15:01.999Z", 1e9, "2026-10-24T09:15:01Z"},
		{"2026-10-24T09:15:01.987Z", 1500, "2026-10-24T09:15:01.987Z"},
		{"2026-10-24T09:15:01.98765Z", 15000, "2026-10-24T09:15:01.9876Z"},
		{"2026-10-24T09:15:01Z", 1, "2026-10-24T09:15:01Z"},
	} {
		if got := truncateUTC(c.in, c.res); got != c.want {
			t.Errorf("%s at %d ns: %s, want %s", c.in, c.res, got, c.want)
		}
	}
}

func TestHeaderTimeSource(t *testing.T) {
	for in, want := range map[string]string{
		"SEL-751  Date: 1\r\nFEEDER 1         Time Source: Internal\r\n\r\n": "Internal",
		"FEEDER RELAY      Time Source: External\nSerial":                    "External",
		"no label here":                           "",
		"Time Source:   \r\n":                     "",
		"Time Source: Int\x01ernal\r\n":           "",
		"Time Source: " + strings.Repeat("x", 33): "",
	} {
		if got := headerTimeSource([]byte(in)); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestStateRoundTrip(t *testing.T) {
	k := "sha256:" + strings.Repeat("c", 64)
	for _, keys := range [][]string{nil, {}, {k}, {k, k}} {
		b, err := EncodeState(keys)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeState(b)
		if err != nil || (got == nil) != (keys == nil) || !slices.Equal(got, keys) {
			t.Errorf("%v: %v %v", keys, got, err)
		}
	}
	for _, bad := range []string{
		`{"format":"otsec.normalize.ser-state/2","keys":[]}`,
		`{"format":"otsec.normalize.ser-state/1"}`,
		`{"format":"otsec.normalize.ser-state/1","keys":null}`,
		`{"format":"otsec.normalize.ser-state/1","keys":["sha256:00"]}`,
		`{"format":"otsec.normalize.ser-state/1","keys":[],"x":1}`,
		`{"format":"otsec.normalize.ser-state/1","keys":[]} {}`,
		`[]`,
		`{"format":"otsec.normalize.ser-state/1","keys":[]}}`,
		`{"format":"otsec.normalize.ser-state/1","keys":[]}]`,
		`{"format":"otsec.normalize.ser-state/1","keys":[]}x`,
	} {
		if _, err := DecodeState([]byte(bad)); !errors.Is(err, ErrInput) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, err := EncodeState([]string{"x"}); err == nil {
		t.Error("malformed key encoded")
	}
	big, _ := json.Marshal(stateDoc{Format: StateFormat, Keys: make([]string, event.MaxAlignRows+1)})
	if _, err := DecodeState(big); err == nil {
		t.Error("oversized state decoded")
	}
}
