package sel751

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
)

// runSteps runs the invocation in f against a far end playing steps, with
// the test secret and floor, and returns the result and the floor.
func runSteps(t *testing.T, f inputs, cfg Config, steps []step, hangUp bool) (adapter.Result, *floor) {
	t.Helper()
	fl := &floor{}
	if cfg.Secret == nil {
		cfg.Secret = &secret{b: []byte(testSecret)}
	}
	cfg.Floor, cfg.Now = fl, clock()
	cfg.hooks = &hooks{quiet: 20 * time.Millisecond, wakeWait: 50 * time.Millisecond}
	cfg.Asset, cfg.Profile, cfg.Register, cfg.Endpoint = f.asset, f.profile, f.reg, f.inv.EndpointID
	near, far := net.Pipe()
	done := farEnd(far, steps, hangUp)
	cfg.Dial = func(context.Context, string, string) (net.Conn, error) { return near, nil }
	res := Run(context.Background(), f.inv, cfg)
	if err := <-done; err != nil {
		t.Errorf("far end: %v", err)
	}
	return res, fl
}

// withTIDLE is the ok golden's script with the SHO P 1 reply's TIDLE line
// replaced (S22 Table 4.104: TIDLE := 15 by default, range 1 to 30 min).
func withTIDLE(t *testing.T, line string) []step {
	t.Helper()
	steps := script(golden(t, "ok"))
	old := []byte("TIDLE   := 15\r\n")
	n := 0
	for i := range steps {
		if bytes.Contains(steps[i].reply, old) {
			steps[i].reply = bytes.Replace(steps[i].reply, old, []byte(line), 1)
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the ok golden has %d TIDLE lines", n)
	}
	return steps
}

// TestTIDLEReported: Config.TIDLE gets the port's Telnet time-out only for
// a whole number of minutes from 1 to 30; any other value, or no TIDLE at
// all, leaves the collector's floor at its longest. The run itself is ok
// either way, since TIDLE is not a check. (An empty value does not parse,
// so the port is not read as English: TestParseSettings.)
func TestTIDLEReported(t *testing.T) {
	cases := []struct {
		line string
		want time.Duration // 0: not called
	}{
		{"TIDLE   := 15\r\n", 15 * time.Minute},
		{"TIDLE   := 1\r\n", time.Minute},
		{"TIDLE   := 30\r\n", 30 * time.Minute},
		{"TIDLE   := 0\r\n", 0},
		{"TIDLE   := 31\r\n", 0},
		{"TIDLE   := 100\r\n", 0},
		{"TIDLE   := -5\r\n", 0},
		{"TIDLE   := +5\r\n", 0},
		{"TIDLE   := 5M\r\n", 0},
		{"TIDLE   := OFF\r\n", 0},
		{"", 0}, // no TIDLE line
	}
	for _, c := range cases {
		t.Run(c.line, func(t *testing.T) {
			f := load(t)
			var got []time.Duration
			cfg := Config{TIDLE: func(d time.Duration) { got = append(got, d) }}
			res, _ := runSteps(t, f, cfg, withTIDLE(t, c.line), false)
			if res.Status != adapter.StatusOK {
				t.Fatalf("status %s %+v", res.Status, res.Error)
			}
			switch {
			case c.want == 0 && len(got) != 0:
				t.Errorf("TIDLE reported %v", got)
			case c.want != 0 && (len(got) != 1 || got[0] != c.want):
				t.Errorf("TIDLE reported %v, want %v once", got, c.want)
			}
		})
	}
}

// TestTIDLENotFromSpanish: a Spanish port's settings are not interpreted
// (D16), so its TIDLE is not reported, though the line is there.
func TestTIDLENotFromSpanish(t *testing.T) {
	want := golden(t, "refused.language_not_english")
	if !bytes.Contains(want.Transcript.Data, []byte("TIDLE   := 15")) {
		t.Fatal("the golden has no TIDLE line")
	}
	var got []time.Duration
	res, _ := runSteps(t, load(t), Config{TIDLE: func(d time.Duration) { got = append(got, d) }}, script(want), false)
	if res.Error == nil || res.Error.Code != adapter.RefusedLanguageNotEnglish {
		t.Fatalf("result %+v", res.Error)
	}
	if len(got) != 0 {
		t.Errorf("TIDLE reported from a Spanish port: %v", got)
	}
}

// TestTIDLEOnlyWithTheLanguagePrecondition pins reportTIDLE's own English
// gate, which TestTIDLENotFromSpanish cannot reach: a Spanish port is refused
// before the read is interpreted (A6 on #114). With a register that does
// not make LANG := ENGLISH a precondition, the run still reads SHO P 1, but
// its settings are not known to be English, so TIDLE is not reported.
func TestTIDLEOnlyWithTheLanguagePrecondition(t *testing.T) {
	f := load(t)
	reg := *f.reg
	reg.Preconditions = nil
	for _, c := range f.reg.Preconditions {
		if c.Setting != "LANG" {
			reg.Preconditions = append(reg.Preconditions, c)
		}
	}
	if len(reg.Preconditions) == len(f.reg.Preconditions) {
		t.Fatal("the register has no LANG precondition")
	}
	f.reg = &reg
	var got []time.Duration
	res, _ := runSteps(t, f, Config{TIDLE: func(d time.Duration) { got = append(got, d) }}, script(golden(t, "ok")), false)
	if !bytes.Contains(res.Transcript.Data, []byte("TIDLE   := 15")) {
		t.Fatalf("SHO P 1 was not read: %s %+v", res.Status, res.Error)
	}
	if len(got) != 0 {
		t.Errorf("TIDLE reported without the language precondition: %v", got)
	}
}

// TestTIDLENil: without a callback a run is unchanged (the other tests).
func TestTIDLENil(t *testing.T) {
	res, _ := runSteps(t, load(t), Config{}, script(golden(t, "ok")), false)
	if res.Status != adapter.StatusOK {
		t.Fatalf("status %s", res.Status)
	}
}

// TestTIDLEOnlyAfterOKOrPartial: SHO P 1 shows TIDLE := 15 in every one of
// these runs, but only a run that ended ok or partial reports it (P3-A2,
// A6's acceptance; A3): a failed or refused session may have left the port
// in a state TIDLE does not describe, so the floor stays at its longest.
func TestTIDLEOnlyAfterOKOrPartial(t *testing.T) {
	for g, want := range map[string]bool{
		"ok": true, "partial.parse_errors": true, "partial.parse_errors-date-f-unknown": true,
		"partial.read_rows_exceeded": true,
		"failed.device_error":        false, "failed.identity_mismatch": false, "failed.access_level_dropped": false,
		"failed.timeout": false, "refused.firmware_condition_not_met": false,
	} {
		t.Run(g, func(t *testing.T) {
			f := load(t)
			if g == "refused.firmware_condition_not_met" {
				f.declare("firmware_id", fidR402)
			}
			if g == "failed.timeout" {
				f.inv.Limits.StepTimeoutMS = 300
			}
			var got []time.Duration
			res, _ := runSteps(t, f, Config{TIDLE: func(d time.Duration) { got = append(got, d) }}, script(golden(t, g)), false)
			if !bytes.Contains(res.Transcript.Data, []byte("TIDLE   := 15")) {
				t.Fatalf("SHO P 1 was not read: %s %+v", res.Status, res.Error)
			}
			if want != (res.Status == adapter.StatusOK || res.Status == adapter.StatusPartial) {
				t.Fatalf("status %s %+v", res.Status, res.Error)
			}
			if reported := len(got) == 1 && got[0] == 15*time.Minute; reported != want || len(got) > 1 {
				t.Errorf("%s: TIDLE reported %v, want %v", res.Status, got, want)
			}
		})
	}
}

// TestTIDLEOnlyFromSHOP1: TIDLE is the port's, so it is taken only from the
// reply to the read that serves the language precondition (SHO P 1). With
// that one's TIDLE out of range or absent, a SHO G reply that shows LANG :=
// ENGLISH and TIDLE := 1 reports nothing (A6 on #175).
func TestTIDLEOnlyFromSHOP1(t *testing.T) {
	for name, line := range map[string]string{"out of range": "TIDLE   := 31\r\n", "absent": ""} {
		t.Run(name, func(t *testing.T) {
			steps := replaceReply(t, withTIDLE(t, line), "SHO G", func(b []byte) []byte {
				if !bytes.Contains(b, []byte("FAULT ")) {
					t.Fatal("no FAULT line in the SHO G reply")
				}
				return bytes.Replace(b, []byte("FAULT "), []byte("LANG    := ENGLISH  TIDLE   := 1\r\nFAULT "), 1)
			})
			var got []time.Duration
			res, _ := runSteps(t, load(t), Config{TIDLE: func(d time.Duration) { got = append(got, d) }}, steps, false)
			if res.Status != adapter.StatusOK {
				t.Fatalf("status %s %+v", res.Status, res.Error)
			}
			if !bytes.Contains(res.Transcript.Data, []byte("TIDLE   := 1\r\n")) {
				t.Fatal("the SHO G reply's TIDLE is not in the transcript")
			}
			if len(got) != 0 {
				t.Errorf("TIDLE reported %v from SHO G", got)
			}
		})
	}
}
