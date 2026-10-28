package sel751

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/config"
	"otsec.local/otsec/contracts/register"
)

// The configuration read (C2 0.6, register run sel.config.read_all, D4-13)
// is replayed against the simulated goldens in contracts/adapter/testdata/
// config, and against scripts built from them. Every transcript is invented:
// simulated evidence only, and how a real relay words any of it is H-13.

func configGolden(t testing.TB, name string) adapter.Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir, "config", "results", "valid", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := adapter.DecodeResult(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// loadConfig is load, for the configuration run: the run's invocation and
// register revision 5.
func loadConfig(t testing.TB) inputs {
	t.Helper()
	f := load(t)
	read := func(p ...string) []byte {
		b, err := os.ReadFile(filepath.Join(p...))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var err error
	if f.inv, err = adapter.DecodeInvocation(read(goldenDir, "config", "invocations", "valid", "sel-config-read.json")); err != nil {
		t.Fatal(err)
	}
	if f.reg, err = register.Decode(read("../../..", "contracts", "register", "testdata", "sel-751.json")); err != nil {
		t.Fatal(err)
	}
	return f
}

// play runs the invocation against a far end that plays steps.
func play(t *testing.T, f inputs, steps []step, hangUp bool, setup func(*Config)) (adapter.Result, *floor, []time.Duration) {
	t.Helper()
	sec, fl := &secret{b: []byte(testSecret)}, &floor{}
	var tidles []time.Duration
	cfg := Config{Asset: f.asset, Profile: f.profile, Register: f.reg, Endpoint: f.inv.EndpointID,
		Secret: sec, Floor: fl, Now: clock(), TIDLE: func(d time.Duration) { tidles = append(tidles, d) },
		hooks: &hooks{quiet: 20 * time.Millisecond, wakeWait: 50 * time.Millisecond}}
	if setup != nil {
		setup(&cfg)
	}
	near, far := net.Pipe()
	done := farEnd(far, steps, hangUp)
	cfg.Dial = func(context.Context, string, string) (net.Conn, error) { return near, nil }
	got := Run(context.Background(), f.inv, cfg)
	if err := <-done; err != nil {
		t.Errorf("far end: %v", err)
	}
	check(t, f, got)
	if sec.uses > 1 {
		t.Errorf("secret used %d times", sec.uses)
	}
	return got, fl, tidles
}

var configReplays = []struct {
	golden string
	hangUp bool
	limits func(*adapter.Limits, []step)
	tidle  bool // ok or partial: the port's TIDLE is reported
}{
	{golden: "ok", tidle: true},
	{golden: "ok-all-present", tidle: true},
	{golden: "ok-with-echo", tidle: true},
	{golden: "failed.config_unparsable"},
	{golden: "failed.device_error-required-class-absent"},
	{golden: "failed.access_level_dropped-in-run"},
	{golden: "failed.timeout-in-run", limits: func(l *adapter.Limits, _ []step) { l.StepTimeoutMS = 300 }},
	{golden: "failed.response_too_large-in-run", limits: func(l *adapter.Limits, steps []step) {
		// The run's total ends exactly where the golden's SHO 3 reply stops.
		var n int64
		for _, st := range steps[:len(steps)-1] {
			n += int64(len(st.reply))
		}
		l.MaxResponseBytes = n
	}},
}

func TestConfigReplayGoldens(t *testing.T) {
	for _, rp := range configReplays {
		t.Run(rp.golden, func(t *testing.T) {
			want := configGolden(t, rp.golden)
			f := loadConfig(t)
			steps := script(want)
			if rp.limits != nil {
				rp.limits(&f.inv.Limits, steps)
			}
			got, fl, tidles := play(t, f, steps, rp.hangUp, nil)
			keep := want.Error != nil && want.Error.Detail != ""
			if g, w := jsonOf(t, normal(got, keep)), jsonOf(t, normal(want, keep)); g != w {
				t.Errorf("result differs from the golden\n%s", diff(g, w))
			}
			if w := "before,confirmed"; strings.Join(fl.calls, ",") != w {
				t.Errorf("floor calls %v, want %q", fl.calls, w)
			}
			if rp.tidle != (len(tidles) == 1 && tidles[0] == 15*time.Minute) || len(tidles) > 1 {
				t.Errorf("TIDLE reported %v, want 15m: %v", tidles, rp.tidle)
			}
		})
	}
}

// A run is one session with one ACC: the golden has one of each of the
// session's lines, and the run's steps once each and in order (B3's
// condition 1).
func TestConfigRunIsOneSession(t *testing.T) {
	r := configGolden(t, "ok")
	var acc, qui, ids int
	for _, sg := range r.Transcript.Segments {
		if sg.Dir != adapter.Sent {
			continue
		}
		switch string(r.Transcript.Data[sg.Offset : sg.Offset+sg.Length]) {
		case "ACC\r\n":
			acc++
		case "QUI\r\n":
			if sg.Phase == adapter.PhaseClose {
				qui++
			}
		case "ID\r\n":
			ids++
		}
	}
	if acc != 1 || qui != 1 || ids != 1 {
		t.Errorf("ACC %d, closing QUI %d, ID %d; want one each", acc, qui, ids)
	}
}

// The gates of the register run are its first steps: a refusal there stops
// the run before any later form is sent. The scripts are the SER goldens'
// opening, which for these two outcomes is the run's too (SHO P 1 first).
func TestConfigGateRefusals(t *testing.T) {
	for _, c := range []struct {
		golden string
		fid    string
		code   adapter.Code
	}{
		{"refused.language_not_english", "", adapter.RefusedLanguageNotEnglish},
		{"refused.firmware_condition_not_met", fidR402, adapter.RefusedFirmwareCondition},
	} {
		t.Run(c.golden, func(t *testing.T) {
			want := golden(t, c.golden)
			f := loadConfig(t)
			if c.fid != "" {
				f.declare("firmware_id", c.fid)
			}
			got, _, _ := play(t, f, script(want), false, nil)
			if got.Error == nil || got.Error.Code != c.code {
				t.Fatalf("result %s, want %s", jsonOf(t, got.Error), c.code)
			}
			if len(got.Records) != 0 || got.Session.QuitSent != want.Session.QuitSent {
				t.Errorf("records %d, quit_sent %v (golden %v)", len(got.Records), got.Session.QuitSent, want.Session.QuitSent)
			}
			if !bytes.Equal(got.Transcript.Data, want.Transcript.Data) {
				t.Error("the transcript is not the golden's: the run sent a line after the gate refused")
			}
		})
	}
}

// "Invalid Command" is an English reply: to the language gate's own form, SHO
// P 1, it is a device error with its detail, as for every other required
// form, and never a refusal for language, which would suspend the asset
// (B6 on #331, B1's ruling).
func TestConfigGateFormNotAvailableIsADeviceError(t *testing.T) {
	for _, line := range []string{"SHO P 1", "SHO G", "SHO 1"} {
		steps := stepsUpTo(t, line, func(b []byte) []byte {
			i, j := bytes.IndexByte(b, 2), bytes.LastIndexByte(b, 3)
			return append(append(append([]byte(nil), b[:i+1]...), "Invalid Command\r\n"...), b[j:]...)
		})
		got, _, _ := play(t, loadConfig(t), steps, false, nil)
		if got.Error == nil || got.Error.Code != adapter.FailedDeviceError || !got.Session.QuitSent || len(got.Records) != 0 {
			t.Errorf("%s: result %s", line, jsonOf(t, got.Error))
			continue
		}
		if got.Error.Code.Suspends() != "" || !strings.Contains(got.Error.Detail, line+" answered that it is not available") {
			t.Errorf("%s: suspends %q, detail %q", line, got.Error.Code.Suspends(), got.Error.Detail)
		}
	}
}

// stepsUpTo returns the ok golden's script through the reply to line, then
// the closing QUI exchange, with the reply to line changed by f.
func stepsUpTo(t *testing.T, line string, f func(reply []byte) []byte) []step {
	t.Helper()
	all := script(configGolden(t, "ok"))
	for i, st := range all {
		if string(st.expect) == line+"\r\n" {
			out := append([]step(nil), all[:i+1]...)
			out[i].reply = f(append([]byte(nil), st.reply...))
			return append(out, all[len(all)-1])
		}
	}
	t.Fatalf("no step %q", line)
	return nil
}

// An unexpected level prompt mid-run ends the run with its code, and QUI
// (the session is at a level it did not expect, and the password was
// confirmed).
func TestConfigUnexpectedPromptMidRun(t *testing.T) {
	steps := stepsUpTo(t, "SHO 2", func(b []byte) []byte { return bytes.TrimSuffix(b, []byte("=>")) })
	steps[len(steps)-2].reply = append(steps[len(steps)-2].reply, "=>>"...)
	got, _, _ := play(t, loadConfig(t), steps, false, nil)
	if got.Error == nil || got.Error.Code != adapter.FailedUnexpectedLevel || !got.Session.QuitSent || len(got.Records) != 0 {
		t.Fatalf("result %s", jsonOf(t, got))
	}
}

// A password prompt mid-run is not answered, and not even QUI is sent (C-19).
func TestConfigPasswordPromptMidRun(t *testing.T) {
	steps := stepsUpTo(t, "SHO 2", func(b []byte) []byte {
		return append(bytes.TrimSuffix(b, []byte("=>")), "\r\nPassword: ?"...)
	})
	steps = steps[:len(steps)-1]
	got, _, _ := play(t, loadConfig(t), steps, false, nil)
	if got.Error == nil || got.Error.Code != adapter.FailedUnexpectedPasswordPrompt || got.Session.QuitSent {
		t.Fatalf("result %s", jsonOf(t, got.Error))
	}
}

// A relay that falls to Level 0 in the middle of the run (the golden shows
// it after SHO L 1) ends it there: no QUI, no further line, no record. B3's
// condition 1 and 4: Level 1 is not assumed to outlast the run.
func TestConfigDropToLevel0MidRun(t *testing.T) {
	for _, line := range []string{"SHO P F", "SHO DNP 3", "SHO G"} {
		steps := stepsUpTo(t, line, func(b []byte) []byte { return append(bytes.TrimSuffix(b, []byte("=>")), '=') })
		steps = steps[:len(steps)-1]
		got, _, _ := play(t, loadConfig(t), steps, false, nil)
		if got.Error == nil || got.Error.Code != adapter.FailedAccessLevelDropped || got.Session.QuitSent || len(got.Records) != 0 {
			t.Errorf("drop after %s: %s", line, jsonOf(t, got.Error))
		}
	}
}

// A reply over its own register limit fails the run, whatever the total
// allows, and the session still ends with QUI.
func TestConfigStepReplyCap(t *testing.T) {
	f := loadConfig(t)
	lim, _ := mustMatcher(t, f.reg).Limits("sel.settings.show_group_1")
	steps := stepsUpTo(t, "SHO 1", func(b []byte) []byte {
		echo := []byte("SHO 1\r\n\x02")
		out := append(echo, bytes.Repeat([]byte("S1A := 1\r\n"), int(lim.MaxReplyBytes)/10)...)
		return out[:lim.MaxReplyBytes]
	})
	got, _, _ := play(t, f, steps, false, nil)
	if got.Error == nil || got.Error.Code != adapter.FailedResponseTooLarge || !got.Session.QuitSent || len(got.Records) != 0 {
		t.Fatalf("result %s", jsonOf(t, got.Error))
	}
	if n := int64(len(got.Transcript.Data)); n < lim.MaxReplyBytes {
		t.Errorf("the transcript holds %d bytes: the bytes received are kept", n)
	}
}

func mustMatcher(t *testing.T, p *register.Package) *register.Matcher {
	t.Helper()
	m, err := register.NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// An invocation looser than the run is held to the run's total and deadline,
// and a step to the tighter of its own timeout and the invocation's.
func TestConfigLimitsAreTheTighter(t *testing.T) {
	f := loadConfig(t)
	s := &session{inv: f.inv, m: mustMatcher(t, f.reg)}
	run, _ := s.m.Run(opConfig)
	s.cfgRun = run
	s.inv.Limits.DeadlineMS, s.inv.Limits.MaxResponseBytes = 600_000, 1<<20
	if l := s.limits(); l.DeadlineMS != run.DeadlineMS || l.MaxResponseBytes != run.MaxTotalBytes {
		t.Errorf("limits %+v: want the run's %d ms and %d bytes", l, run.DeadlineMS, run.MaxTotalBytes)
	}
	s.inv.Limits.DeadlineMS, s.inv.Limits.MaxResponseBytes = 60_000, 4096
	if l := s.limits(); l.DeadlineMS != 60_000 || l.MaxResponseBytes != 4096 {
		t.Errorf("a tighter invocation was loosened: %+v", l)
	}
}

// A register without the run (revision 4) cannot be asked for it: nothing is
// dialled.
func TestConfigRunNeedsRevision5(t *testing.T) {
	f := loadConfig(t)
	f.reg = load(t).reg
	cfg := Config{Asset: f.asset, Profile: f.profile, Register: f.reg, Endpoint: f.inv.EndpointID,
		Secret: &secret{b: []byte(testSecret)}, Floor: &floor{}, Now: clock(),
		Dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("dialled")
			return nil, errors.New("test")
		}}
	got := Run(context.Background(), f.inv, cfg)
	if got.Error == nil || got.Error.Code != adapter.RefusedNotInvocable {
		t.Fatalf("result %s", jsonOf(t, got.Error))
	}
}

// The adapter's table of forms is C9's rule: the same commands, and the same
// forms that may be absent. The register's run steps are the rule's commands.
func TestCfgFormsAreTheRule(t *testing.T) {
	f := loadConfig(t)
	m := mustMatcher(t, f.reg)
	lines, err := m.RenderRun(opConfig)
	if err != nil {
		t.Fatal(err)
	}
	run, _ := m.Run(opConfig)
	if len(run.Steps) != len(config.RuleSEL751SHO.Classes) {
		t.Fatalf("%d steps, the rule has %d classes", len(run.Steps), len(config.RuleSEL751SHO.Classes))
	}
	for i, id := range run.Steps {
		mayBeAbsent, ok := cfgForms[id]
		if !ok {
			t.Errorf("step %s is not in cfgForms", id)
			continue
		}
		// C9 0.2: the rule lists the classes in the run's order.
		class := &config.RuleSEL751SHO.Classes[i]
		if class.Command != lines[i] {
			t.Errorf("step %d is %q, the rule's class %d is %q", i+1, lines[i], i+1, class.Command)
		} else if class.MayBeAbsent != mayBeAbsent {
			t.Errorf("%s: may be absent %v here, %v in the rule", id, mayBeAbsent, class.MayBeAbsent)
		}
	}
	if len(cfgForms) != len(run.Steps) {
		t.Errorf("cfgForms has %d forms, the run %d steps", len(cfgForms), len(run.Steps))
	}
	if config.RuleSEL751SHO.NotAvailable != cfgNotAvailable {
		t.Errorf("not available: %q here, %q in the rule", cfgNotAvailable, config.RuleSEL751SHO.NotAvailable)
	}
}

// The snapshot a run's result gives is the one the contract's tokenizer
// reads from the same bytes: the adapter's parser and C9's agree on every
// section of every ok golden, as the node checks.
func TestConfigRunSnapshotChecks(t *testing.T) {
	for _, n := range []string{"ok", "ok-all-present", "ok-with-echo"} {
		f := loadConfig(t)
		got, _, _ := play(t, f, script(configGolden(t, n)), false, nil)
		s, err := config.FromResult(config.RuleSEL751SHO.ID, mustMatcher(t, f.reg), f.inv, got)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if err := s.CheckAgainst(got.Transcript); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}

// FuzzRunConfig drives the whole configuration run against a far end that
// answers each line with fuzzer-chosen bytes. Whatever it sends, Run must
// return a result that passes Validate, CheckLines and CheckAgainst; when the
// result is ok, a snapshot built from it must pass the contract's check
// against the same bytes; the secret never reaches the transcript.
func FuzzRunConfig(f *testing.F) {
	ok := script(configGolden(f, "ok"))
	var seed [][]byte
	for _, st := range ok {
		seed = append(seed, bytes.ReplaceAll(st.reply, []byte(testSecret), []byte("x")))
	}
	f.Add(bytes.Join(seed, []byte{0xF7}))
	f.Add([]byte("\r\n=\xF7QUI\r\n=\xF7\x02\"FID=x\",\"0000\"\r\n\x03=\xF7\r\nPassword: ?"))
	f.Add([]byte("\xF7\r\n=\xF7\r\n=\xF7\x02\x03=\xF7=>\xF7\r\nPassword: ?\xF7=>\xF7\x02A := 1\r\n\x03=>\xF7\x02A := 1\r\nA := 2\r\n\x03=>"))
	in := loadConfig(f)
	m := mustMatcher(&testing.T{}, in.reg)
	f.Fuzz(func(t *testing.T, data []byte) {
		chunks := bytes.Split(data, []byte{0xF7})
		near, far := net.Pipe()
		go func() {
			defer far.Close()
			_ = far.SetDeadline(time.Now().Add(10 * time.Second))
			r := bufio.NewReader(far)
			for i, c := range chunks {
				if i > 0 {
					if _, err := r.ReadBytes('\n'); err != nil {
						return
					}
				}
				if len(c) > 0 {
					if _, err := far.Write(c); err != nil {
						return
					}
				}
			}
		}()
		inv := in.inv
		inv.Limits.StepTimeoutMS = 60
		cfg := Config{Asset: in.asset, Profile: in.profile, Register: in.reg, Endpoint: inv.EndpointID,
			Secret: &secret{b: []byte(testSecret)}, Floor: &floor{}, Now: clock(),
			hooks: &hooks{quiet: time.Millisecond, wakeWait: 5 * time.Millisecond},
			Dial:  func(context.Context, string, string) (net.Conn, error) { return near, nil }}
		got := Run(context.Background(), inv, cfg)
		x := in
		x.inv = inv
		check(t, x, got)
		if got.Status == adapter.StatusOK {
			s, err := config.FromResult(config.RuleSEL751SHO.ID, m, inv, got)
			if err != nil {
				t.Errorf("FromResult: %v", err)
			} else if err := s.CheckAgainst(got.Transcript); err != nil {
				t.Errorf("CheckAgainst: %v", err)
			}
		}
		if t.Failed() {
			t.Logf("%s\n%q", jsonOf(t, got.Session), got.Transcript.Data)
			if got.Error != nil {
				t.Logf("%s %s", got.Error.Code, got.Error.Detail)
			}
		}
	})
}

// A step is held to its own register timeout when that is tighter than the
// invocation's step timeout.
func TestConfigStepTimeoutIsTheRegisters(t *testing.T) {
	f := loadConfig(t)
	p := *f.reg
	p.Operations = append([]register.Operation(nil), p.Operations...)
	for i := range p.Operations {
		if p.Operations[i].ID == "sel.settings.show_logic_2" {
			l := *p.Operations[i].Limits
			l.TimeoutMS = 300
			p.Operations[i].Limits = &l
		}
	}
	f.reg = &p
	want := configGolden(t, "failed.timeout-in-run") // SHO L 2 stops part-way
	f.inv.Limits.StepTimeoutMS = 10_000
	start := time.Now()
	got, _, _ := play(t, f, script(want), false, nil)
	if got.Error == nil || got.Error.Code != adapter.FailedTimeout || !got.Session.QuitSent {
		t.Fatalf("result %s", jsonOf(t, got.Error))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v: the step ran to the invocation's timeout", d)
	}
}
