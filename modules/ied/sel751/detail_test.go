package sel751

import (
	"bytes"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
)

// silentAfter is the golden's script up to the turn that sends expect, with
// that turn's reply removed: the far end goes quiet after it.
func silentAfter(t *testing.T, name string, expect []byte) []step {
	t.Helper()
	steps := script(golden(t, name))
	for i, st := range steps {
		if bytes.Equal(st.expect, expect) {
			out := append([]step(nil), steps[:i+1]...)
			out[i].reply = nil
			return out
		}
	}
	t.Fatalf("%s sends no %q", name, expect)
	return nil
}

// TestStepDetail: a step that ends with no prompt names the step in its
// detail, in the collector's own words, so health tells a late device from
// a hung SER read (A6, V-S12). The password is named, never written.
func TestStepDetail(t *testing.T) {
	ok := golden(t, "ok")
	ser := ""
	for _, sg := range ok.Transcript.Segments {
		if sg.Dir == adapter.Sent && sg.Phase == adapter.PhaseOperate {
			ser = strings.TrimRight(string(ok.Transcript.Data[sg.Offset:sg.Offset+sg.Length]), "\r\n")
		}
	}
	if !strings.HasPrefix(ser, "SER") {
		t.Fatalf("the ok golden's operate line is %q", ser)
	}
	cases := []struct {
		name   string
		steps  []step
		hangUp bool
		limits func(*adapter.Limits, []step)
		want   adapter.Code
		detail string
	}{
		{"no prompt after the wake", silentAfter(t, "ok", []byte("\r\n")), false, nil, adapter.FailedTimeout,
			"no prompt within the step timeout after the wake"},
		{"no prompt after the probe", script(golden(t, "failed.timeout-probe-unanswered")), false, nil, adapter.FailedTimeout,
			"no prompt after the QUI language probe; nothing more sent"},
		{"no prompt after ID", silentAfter(t, "ok", []byte("ID\r\n")), false, nil, adapter.FailedTimeout,
			"no prompt within the step timeout after ID"},
		{"no prompt after ACC", silentAfter(t, "ok", []byte("ACC\r\n")), false, nil, adapter.FailedTimeout,
			"no prompt within the step timeout after ACC"},
		{"no prompt after the password", silentAfter(t, "ok", []byte(testSecret+"\r\n")), false, nil, adapter.FailedTimeout,
			"no prompt within the step timeout after the password"},
		// At Level 1 the session still ends with QUI (D18, V-S13).
		{"no prompt after SHO P 1", append(silentAfter(t, "ok", []byte("SHO P 1\r\n")), step{expect: []byte("QUI\r\n")}), false, nil, adapter.FailedTimeout,
			"no prompt within the step timeout after SHO P 1"},
		{"a SER read that hangs", script(golden(t, "failed.timeout")), false, nil, adapter.FailedTimeout,
			"no prompt within the step timeout after " + ser},
		{"a SER read cut off", script(golden(t, "failed.transport_closed")), true, nil, adapter.FailedTransportClosed,
			"the connection closed with no prompt after " + ser},
		{"a SER reply past the budget", script(golden(t, "failed.response_too_large")), false, replayLimits(t, "failed.response_too_large"),
			adapter.FailedResponseTooLarge, "max_response_bytes reached with no prompt after " + ser},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := load(t)
			f.inv.Limits.StepTimeoutMS = 300
			if c.limits != nil {
				c.limits(&f.inv.Limits, c.steps)
			}
			res, _ := runSteps(t, f, Config{}, c.steps, c.hangUp)
			if err := res.Validate(); err != nil {
				t.Fatalf("result does not validate: %v", err)
			}
			if res.Error == nil || res.Error.Code != c.want || res.Error.Detail != c.detail {
				t.Fatalf("result %+v, want %s %q", res.Error, c.want, c.detail)
			}
			if strings.Contains(res.Error.Detail, testSecret) {
				t.Fatal("the detail holds the secret")
			}
		})
	}
}

func replayLimits(t *testing.T, name string) func(*adapter.Limits, []step) {
	t.Helper()
	for _, rp := range replays {
		if rp.golden == name {
			return rp.limits
		}
	}
	t.Fatalf("no replay of %s", name)
	return nil
}
