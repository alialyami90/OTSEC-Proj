package normalize

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/event"
)

// The SER rows of a C2 0.5 result are read in the DATE_F order the adapter
// read in the same session (D2-20, A2's goldens on #175). Each of the three
// orders gives the same instants, and none is flagged as assumed.
func TestDateFRead(t *testing.T) {
	inv, a := c2Fixtures(t)
	for file, order := range map[string]string{"ok.json": "MDY", "ok-date-ymd.json": "YMD", "ok-date-dmy.json": "DMY"} {
		res := c2Result(t, file)
		if s, ok := res.Setting("DATE_F"); !ok || s.Value != order {
			t.Fatalf("%s: DATE_F %+v", file, s)
		}
		for _, caller := range []string{"", order} {
			in := testInput(nil)
			in.DateOrder = caller
			out, err := Normalize(res, inv, a, in)
			if err != nil {
				t.Fatalf("%s, caller %q: %v", file, caller, err)
			}
			var walls []string
			for _, e := range out.Events {
				dt := e.DeviceTime
				if e.Collection.ParseStatus != event.ParseOK || dt == nil || len(dt.Flags) != 0 {
					t.Errorf("%s: %s %+v", file, e.Collection.ParseStatus, dt)
					continue
				}
				walls = append(walls, dt.WallClock)
			}
			if want := []string{"2026-10-24T09:10:01.004", "2026-10-24T09:10:01.251"}; !slices.Equal(walls, want) {
				t.Errorf("%s, caller %q: wall clocks %v, want %v", file, caller, walls, want)
			}
		}
	}
}

// When the adapter could not use DATE_F (missing, unknown, or a row that
// does not fit it), every row comes unparsed: each becomes a parse-failed
// event with its bytes, and nothing is read in an assumed order.
func TestDateFUnusableRowsKept(t *testing.T) {
	inv, a := c2Fixtures(t)
	for _, file := range []string{"partial.parse_errors-date-f-missing.json", "partial.parse_errors-date-f-unknown.json", "partial.parse_errors-date-misfit.json"} {
		res := c2Result(t, file)
		out, err := Normalize(res, inv, a, testInput(nil))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if len(out.Events) == 0 || len(out.Events) != len(res.Records) {
			t.Fatalf("%s: %d events for %d records", file, len(out.Events), len(res.Records))
		}
		for i, e := range out.Events {
			span := res.Records[i].Span
			if e.Collection.ParseStatus != event.ParseFailed || e.DeviceTime != nil ||
				!bytes.Equal(e.Native.Bytes, res.Transcript.Data[span.Offset:span.Offset+span.Length]) {
				t.Errorf("%s event %d: %s, device time %+v, bytes %q", file, i, e.Collection.ParseStatus, e.DeviceTime, e.Native.Bytes)
			}
		}
	}
}

// What is refused, and why. A refused result produces no events; the node
// keeps it whole as quarantine and alarms (platform/node
// TestNormalizerRefusalEndsWithOneHealthEvent), so its rows' bytes are kept
// and the reason is recorded, never dropped (R1.4).
func TestDateFRefused(t *testing.T) {
	inv, a := c2Fixtures(t)
	ymd := c2Result(t, "ok-date-ymd.json")
	noSetting := ymd
	noSetting.Settings = nil
	unparsed := c2Result(t, "partial.parse_errors-date-f-missing.json")
	for _, c := range []struct {
		name   string
		res    adapter.Result
		caller string
		want   error
	}{
		{"caller disagrees with DATE_F", ymd, "MDY", ErrInput},
		{"parsed rows without DATE_F", noSetting, "", ErrResult},
		{"caller order for a 0.5 result without DATE_F", unparsed, "YMD", ErrInput},
	} {
		in := testInput(nil)
		in.DateOrder = c.caller
		out, err := Normalize(c.res, inv, a, in)
		if !errors.Is(err, c.want) || out != nil || !strings.Contains(err.Error(), "DATE_F") {
			t.Errorf("%s: %v (%v), want %v naming DATE_F", c.name, err, out, c.want)
		}
	}
}

// dateOrder on its own, including a DATE_F this package does not know with
// a parsed row, which a valid golden cannot carry, and results before 0.5,
// where the caller's order stands.
func TestDateOrder(t *testing.T) {
	setting := func(v string) []adapter.Setting { return []adapter.Setting{{Name: "DATE_F", Value: v}} }
	parsed := []adapter.Record{{Kind: SERKind, ParseOK: true}}
	unparsed := []adapter.Record{{Kind: SERKind}}
	for _, c := range []struct {
		name     string
		schema   string
		settings []adapter.Setting
		records  []adapter.Record
		caller   string
		want     string
		err      error
	}{
		{"0.4, caller's order", "otsec.adapter/0.4", nil, parsed, "DMY", "DMY", nil},
		{"0.4, unknown", "otsec.adapter/0.4", nil, parsed, "", "", nil},
		{"0.5, DATE_F", "otsec.adapter/0.5", setting("YMD"), parsed, "", "YMD", nil},
		{"0.5, DATE_F and the same caller order", "otsec.adapter/0.5", setting("YMD"), parsed, "YMD", "YMD", nil},
		{"0.5, caller disagrees", "otsec.adapter/0.5", setting("YMD"), parsed, "DMY", "", ErrInput},
		{"0.5, unknown DATE_F, parsed row", "otsec.adapter/0.5", setting("MYD"), parsed, "", "", ErrResult},
		{"0.5, lowercase DATE_F, parsed row", "otsec.adapter/0.5", setting("ymd"), parsed, "", "", ErrResult},
		{"0.5, no DATE_F, parsed row", "otsec.adapter/0.5", nil, parsed, "", "", ErrResult},
		{"0.5, unknown DATE_F, no parsed row", "otsec.adapter/0.5", setting("MYD"), unparsed, "", "", nil},
		{"0.5, no DATE_F, no rows", "otsec.adapter/0.5", nil, nil, "", "", nil},
		{"0.5, caller order without DATE_F", "otsec.adapter/0.5", nil, unparsed, "MDY", "", ErrInput},
		{"0.9, DATE_F", "otsec.adapter/0.9", setting("DMY"), parsed, "", "DMY", nil},
	} {
		got, err := dateOrder(adapter.Result{Schema: c.schema, Settings: c.settings, Records: c.records}, c.caller)
		if got != c.want || !errors.Is(err, c.err) || (c.err == nil) != (err == nil) {
			t.Errorf("%s: %q, %v; want %q, %v", c.name, got, err, c.want, c.err)
		}
	}
}
