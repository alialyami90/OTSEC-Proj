package sel751

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
)

// P3-A2: the C1 path rule before connecting, and DATE_F from SHO G before
// SER (register rev 4, C3 0.2 context, C2 0.5 settings). Every reply is
// invented (C2 testdata README): simulated evidence only.

// Only a direct path gets a session: no path (a C1 0.1 record), a port
// server and a path this build does not know are refused alike, with
// nothing sent and no dial (D2-16, H-13).
func TestEndpointPathRefused(t *testing.T) {
	for _, path := range []asset.Path{"", asset.PortServer, "serial-bridge"} {
		t.Run(string(path), func(t *testing.T) {
			f := load(t)
			f.asset.Endpoints[0].Path = path
			cfg := Config{Asset: f.asset, Profile: f.profile, Register: f.reg, Endpoint: f.inv.EndpointID,
				Secret: &secret{b: []byte(testSecret)}, Floor: &floor{}, Now: clock(),
				Dial: func(context.Context, string, string) (net.Conn, error) {
					t.Error("dialled")
					return nil, errors.New("test")
				}}
			got := Run(context.Background(), f.inv, cfg)
			if got.Error == nil || got.Error.Code != adapter.RefusedEndpointPath {
				t.Fatalf("result %s", jsonOf(t, got.Error))
			}
			if got.Session.Connected || len(got.Transcript.Data) != 0 || got.Error.Code.Stage() != adapter.StageBeforeConnect {
				t.Errorf("session %+v, %d bytes", got.Session, len(got.Transcript.Data))
			}
			check(t, f, got)
		})
	}
}

// sentOperate lists the operate-phase lines of a result, in order.
func sentOperate(r adapter.Result) []string {
	var out []string
	for _, sg := range r.Transcript.Segments {
		if sg.Dir == adapter.Sent && sg.Phase == adapter.PhaseOperate {
			out = append(out, string(bytes.TrimSuffix(r.Transcript.Data[sg.Offset:sg.Offset+sg.Length], []byte("\r\n"))))
		}
	}
	return out
}

// The context read comes after the language precondition's read and before
// the operation (A3 on D3-2), and its value is reported with a span on the
// relay's own bytes.
func TestDateFReadBeforeSER(t *testing.T) {
	for g, want := range map[string]string{"ok": "MDY", "ok-date-ymd": "YMD", "ok-date-dmy": "DMY"} {
		t.Run(g, func(t *testing.T) {
			res, _ := runSteps(t, load(t), Config{}, script(golden(t, g)), false)
			if res.Status != adapter.StatusOK {
				t.Fatalf("status %s %+v", res.Status, res.Error)
			}
			if got := sentOperate(res); len(got) != 3 || got[0] != "SHO P 1" || got[1] != "SHO G" || got[2] != "SER" {
				t.Errorf("operate lines %q, want SHO P 1, SHO G, SER", got)
			}
			st, ok := res.Setting("DATE_F")
			sp := st.Span
			if !ok || st.Value != want || string(res.Transcript.Data[sp.Offset:sp.Offset+sp.Length]) != want {
				t.Errorf("DATE_F %+v, want %s", st, want)
			}
			for _, rec := range res.Records {
				if !rec.ParseOK {
					t.Errorf("row %+v not parsed", rec)
				}
			}
		})
	}
}

// An order the adapter cannot read leaves the output unreadable: every row
// keeps its bytes and none is parsed, so no consumer can take its date in a
// guessed order (A3 on D3-2). A value outside MDY, YMD and DMY is still
// reported as printed.
func TestUnknownDateFLeavesRowsUnread(t *testing.T) {
	for g, want := range map[string]string{
		"partial.parse_errors-date-f-unknown": "MYD",
		"partial.parse_errors-date-f-missing": "",
		"partial.parse_errors-date-misfit":    "DMY",
	} {
		t.Run(g, func(t *testing.T) {
			res, _ := runSteps(t, load(t), Config{}, script(golden(t, g)), false)
			if res.Error == nil || res.Error.Code != adapter.PartialParseErrors || len(res.Records) == 0 {
				t.Fatalf("result %s, %d records", jsonOf(t, res.Error), len(res.Records))
			}
			for _, rec := range res.Records {
				if rec.ParseOK || len(rec.Fields) != 0 || rec.Span.Length == 0 {
					t.Errorf("row %+v: want unparsed, bytes kept", rec)
				}
			}
			st, ok := res.Setting("DATE_F")
			if ok != (want != "") || st.Value != want {
				t.Errorf("DATE_F %+v (%v), want %q", st, ok, want)
			}
		})
	}
}

// replaceReply changes the reply to the sent line in a script.
func replaceReply(t *testing.T, steps []step, sent string, f func([]byte) []byte) []step {
	t.Helper()
	for i := range steps {
		if string(steps[i].expect) == sent+"\r\n" {
			steps[i].reply = f(steps[i].reply)
			return steps
		}
	}
	t.Fatalf("no %q in the script", sent)
	return nil
}

// A SHO G reply the parser cannot read refuses nothing: DATE_F is unknown,
// SER is still read, and every row is left unparsed. SHO G serves no check,
// so this is not the failed.device_error a bad SHO P 1 gives.
func TestSHOGUnreadable(t *testing.T) {
	for name, f := range map[string]func([]byte) []byte{
		"invalid command": func([]byte) []byte { return []byte("SHO G\r\n\x02\r\nInvalid Command\r\n\x03=>") },
		"half-read line": func(b []byte) []byte {
			return bytes.Replace(b, []byte("DATE_F := MDY"), []byte("DATE_F := MDY  ?"), 1)
		},
		"not framed": func(b []byte) []byte {
			return bytes.ReplaceAll(bytes.ReplaceAll(b, []byte("\x02"), nil), []byte("\x03"), nil)
		},
		"DATE_F twice": func(b []byte) []byte { return bytes.Replace(b, []byte("FAULT "), []byte("DATE_F := MDY\r\nFAULT "), 1) },
	} {
		t.Run(name, func(t *testing.T) {
			steps := replaceReply(t, script(golden(t, "ok")), "SHO G", f)
			res, _ := runSteps(t, load(t), Config{}, steps, false)
			if res.Error == nil || res.Error.Code != adapter.PartialParseErrors {
				t.Fatalf("result %s", jsonOf(t, res.Error))
			}
			if got := sentOperate(res); len(got) != 3 || got[2] != "SER" || !res.Session.QuitSent {
				t.Errorf("operate lines %q, quit %v", got, res.Session.QuitSent)
			}
			if _, ok := res.Setting("DATE_F"); ok {
				t.Error("DATE_F reported from a reply that does not parse")
			}
			for _, rec := range res.Records {
				if rec.ParseOK {
					t.Errorf("row %+v parsed with DATE_F unknown", rec)
				}
			}
		})
	}
}

// The context read is a line like any other (D3-2): its reply counts
// against max_response_bytes, and the run stops inside it, with SER never
// sent and the SHO G bytes kept.
func TestContextReadCountsAgainstTheBudget(t *testing.T) {
	steps := script(golden(t, "ok"))
	var n int64
	for i, st := range steps {
		if string(st.expect) == "SHO G\r\n" {
			n += int64(len(st.reply)) / 2
			// Stopped at the limit, the session still ends with QUI (D18).
			steps = append(steps[:i+1:i+1], step{expect: []byte("QUI\r\n")})
			break
		}
		n += int64(len(st.reply))
	}
	f := load(t)
	f.inv.Limits.MaxResponseBytes = n
	res, _ := runSteps(t, f, Config{}, steps, true)
	if res.Error == nil || res.Error.Code != adapter.FailedResponseTooLarge {
		t.Fatalf("result %s", jsonOf(t, res.Error))
	}
	got := sentOperate(res)
	if len(got) != 2 || got[1] != "SHO G" {
		t.Errorf("operate lines %q, want SHO P 1 and SHO G only", got)
	}
	if !bytes.Contains(res.Transcript.Data, []byte("Global Settings")) {
		t.Error("the SHO G bytes are not in the transcript")
	}
}

// A context read this build has no reader for stops the run before it
// connects: the adapter does not send a line whose reply it cannot use.
func TestContextReadWithoutReader(t *testing.T) {
	for name, edit := range map[string]func(f *inputs){
		"another setting": func(f *inputs) { f.reg.Context[0].Setting = "PHROT" },
		"another value":   func(f *inputs) { f.reg.Context[0].Values = append(f.reg.Context[0].Values, "YDM") },
	} {
		t.Run(name, func(t *testing.T) {
			f := load(t)
			edit(&f)
			if err := f.reg.Validate(); err != nil {
				t.Fatalf("the edited register is invalid: %v", err)
			}
			cfg := Config{Asset: f.asset, Profile: f.profile, Register: f.reg, Endpoint: f.inv.EndpointID,
				Secret: &secret{b: []byte(testSecret)}, Floor: &floor{}, Now: clock(),
				Dial: func(context.Context, string, string) (net.Conn, error) {
					t.Error("dialled")
					return nil, errors.New("test")
				}}
			got := Run(context.Background(), f.inv, cfg)
			if got.Error == nil || got.Error.Code != adapter.FailedInternal || got.Session.Connected {
				t.Fatalf("result %s", jsonOf(t, got.Error))
			}
		})
	}
}

// Only the DATE_F label counts (A6): an order printed as another setting's
// value, or under a name that merely contains DATE_F, is never taken for
// it. With no DATE_F the rows stay unparsed; with DATE_F present, another
// setting's value does not change the order read.
func TestDateFOnlyFromItsLabel(t *testing.T) {
	for name, c := range map[string]struct {
		from, to string
		want     string // the DATE_F reported; "" for none
	}{
		"value of another setting": {"DATE_F := MDY", "DATEFM := DMY", ""},
		"longer name":              {"DATE_F := MDY", "DATE_FX := DMY", ""},
		"prefixed name":            {"DATE_F := MDY", "XDATE_F := DMY", ""},
		"beside the real one":      {"FNOM    := 60", "FNOM    := DMY", "MDY"},
	} {
		t.Run(name, func(t *testing.T) {
			steps := replaceReply(t, script(golden(t, "ok")), "SHO G", func(b []byte) []byte {
				if !bytes.Contains(b, []byte(c.from)) {
					t.Fatalf("no %q in the SHO G reply", c.from)
				}
				return bytes.Replace(b, []byte(c.from), []byte(c.to), 1)
			})
			res, _ := runSteps(t, load(t), Config{}, steps, false)
			st, ok := res.Setting("DATE_F")
			if ok != (c.want != "") || st.Value != c.want {
				t.Errorf("DATE_F %+v (%v), want %q", st, ok, c.want)
			}
			wantParsed := c.want != ""
			for _, rec := range res.Records {
				if rec.ParseOK != wantParsed {
					t.Errorf("row %+v: parsed %v, want %v", rec, rec.ParseOK, wantParsed)
				}
			}
		})
	}
}
