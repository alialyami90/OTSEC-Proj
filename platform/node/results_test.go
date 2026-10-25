package node

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
)

// The status file shows the collector's numbering and the asset's result
// as soon as a run ends, not only before the next run (A6 on #118: health
// showed collector_seq high 0 a run after 8 rows were delivered).
func TestStatusAfterRun(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" || rep.Events == 0 {
		t.Fatalf("run: %+v", rep)
	}
	f, err := ReadStatus(filepath.Join(dir, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if f.Collector == nil || f.Collector.High != seq || seq == 0 {
		t.Fatalf("status file after the run: collector %+v, collector_seq %d", f.Collector, seq)
	}
	if a := f.Assets[relayID]; a.Code != "ok" || a.Failures != 0 || a.At.IsZero() {
		t.Fatalf("asset result after the run: %+v", f.Assets)
	}
}

// switchCollector sends each run to fail while fail is true and to ok
// after.
type switchCollector struct {
	fail bool
	bad  Collector
	ok   Collector
}

func (s *switchCollector) Do(ctx context.Context, req *authz.CollectorRequest) (collectorclient.Response, error) {
	if s.fail {
		return s.bad.Do(ctx, req)
	}
	return s.ok.Do(ctx, req)
}

// A failure that suspends nothing repeats at every interval: health shows
// the last code and the count, the repeated-failure alarm is raised once
// at RepeatedFailureAfter, and a good run resets both (D2-17).
func TestRepeatedFailureShows(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	var seq uint64
	refuse := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		seq++
		return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
			Refusal: &authz.Refusal{Code: authz.RefuseRateLimited, Detail: "inside the floor"}, CollectorSeq: seq}}, nil
	}}
	col := &switchCollector{fail: true, bad: refuse, ok: wireCollector(t, func(*authz.CollectorRequest) {}, &seq)}
	s := newScheduler(t, r, col)
	for i := 1; i <= RepeatedFailureAfter+1; i++ {
		s.RunOnce(bg, 0)
		f, err := ReadStatus(filepath.Join(dir, "status.json"))
		if err != nil {
			t.Fatal(err)
		}
		a := f.Assets[relayID]
		if a.Code != AlarmCollectorRefused || a.Refusal != string(authz.RefuseRateLimited) || a.Failures != i {
			t.Fatalf("after %d refused runs: %+v", i, a)
		}
		want := 0
		if i >= RepeatedFailureAfter {
			want = 1
		}
		if n := countAlarms(st, AlarmRepeatedFailure); n != want {
			t.Fatalf("after %d refused runs: %d repeated-failure alarms, want %d", i, n, want)
		}
	}
	col.fail = false
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" {
		t.Fatalf("good run: %+v", rep)
	}
	if a := st.Snapshot("x").Assets[relayID]; a.Code != "ok" || a.Failures != 0 || a.Refusal != "" {
		t.Fatalf("after a good run: %+v", a)
	}
	// Failures start over, and so does the alarm.
	col.fail = true
	for range RepeatedFailureAfter {
		s.RunOnce(bg, 0)
	}
	if n := countAlarms(st, AlarmRepeatedFailure); n != 2 {
		t.Fatalf("%d repeated-failure alarms after a second run of failures, want 2", n)
	}
}

// A run that is not sent (here, held by the audit stream being full)
// changes no result: nothing reached the device.
func TestHeldRunIsNoResult(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	s := newScheduler(t, r, &fakeCollector{answer: func(*authz.CollectorRequest) (collectorclient.Response, error) {
		t.Fatal("a held run reached the collector")
		return collectorclient.Response{}, nil
	}})
	s.mu.Lock()
	s.node = AlarmSuspensionsUnknown
	s.mu.Unlock()
	if rep := s.RunOnce(bg, 0); rep.Sent {
		t.Fatalf("held run sent: %+v", rep)
	}
	if a, ok := st.Snapshot("x").Assets[relayID]; ok {
		t.Fatalf("held run recorded as a result: %+v", a)
	}
}

// Forwarding.Check writes the status file when a target's counts change,
// so health is one check behind, not one tick (A6 on #118), and does not
// rewrite it when nothing changed.
func TestCheckWritesStatusOnChange(t *testing.T) {
	nc, _, _ := forwardConfig(t, 9, nil) // the forwarder is never run
	lockTLS(t, nc)
	c := parse(t, nc)
	now := time.Date(2026, 10, 25, 6, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	st := NewStatus(StatusPath(c), nil, clock)
	r, err := Start(bg, c, RuntimeOptions{Status: st, Now: clock, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatal(err)
	}
	last := func() (uint64, time.Time) {
		t.Helper()
		f, err := ReadStatus(StatusPath(c))
		if err != nil {
			t.Fatal(err)
		}
		ts, ok := f.Targets["central"]
		if !ok {
			t.Fatalf("no target in the status file: %+v", f.Targets)
		}
		return ts.Streams[string(HealthStream)].Last, f.Written
	}
	fw.Check(bg)
	before, _ := last()
	r.health(bg, "test.change", nil)
	now = now.Add(time.Second)
	fw.Check(bg)
	after, written := last()
	if after <= before || !written.Equal(now) {
		t.Fatalf("health stream last %d after %d, file written %s at %s", after, before, written, now)
	}
	now = now.Add(time.Second)
	fw.Check(bg)
	if _, w := last(); !w.Equal(written) {
		t.Fatalf("file rewritten at %s with nothing changed", w)
	}
}

// The code status shows: the outcome's code, an unknown one read as
// failed.unknown (a quarantined outcome is unverified), the run's alarm
// when there is no outcome code, and ok otherwise.
func TestResultCode(t *testing.T) {
	for _, c := range []struct {
		rep  Report
		want string
	}{
		{Report{Code: adapter.FailedConnect, Alarm: AlarmOutcomeUnknown}, string(adapter.FailedConnect)},
		{Report{Code: "failed.not-a-code\x1b[2J"}, string(adapter.FailedUnknown)},
		{Report{Alarm: AlarmNoDecision}, AlarmNoDecision},
		{Report{}, "ok"},
	} {
		if got := c.rep.resultCode(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.rep, got, c.want)
		}
	}
}

// A partial result counts as a failure (A3 and A6 on #126): C2 gives every
// partial result a partial.* code, so none reads as ok.
func TestPartialIsAFailure(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	s := newScheduler(t, r, &fakeCollector{})
	s.recordResult(relayID, Report{Sent: true, Code: adapter.PartialParseErrors})
	if a := st.Snapshot("x").Assets[relayID]; a.Code != string(adapter.PartialParseErrors) || a.Failures != 1 {
		t.Fatalf("after a partial run: %+v", a)
	}
}

// The last result keeps the C2 detail of an outcome that passed its
// checks, which tells apart runs that end with the same code (A6, V-S12),
// and never one from a quarantined outcome or one C2 does not allow.
func TestResultDetail(t *testing.T) {
	for _, c := range []struct {
		quarantine   bool
		detail, want string
	}{
		{false, "second password prompt", "second password prompt"},
		{true, "second password prompt", ""},
		{false, "bell\x07", ""}, // not as C2 bounds it, so not kept
	} {
		cfg, dir := schedConfig(t, nil)
		r, st, _ := start(t, cfg, dir)
		col := suspendingCollector(t, c.quarantine)
		base := col.answer
		col.answer = func(req *authz.CollectorRequest) (collectorclient.Response, error) {
			resp, err := base(req)
			if resp.Outcome != nil {
				resp.Outcome.Result.Error = &adapter.Error{Code: adapter.FailedAuthRejected, Detail: c.detail}
			}
			return resp, err
		}
		newScheduler(t, r, col).RunOnce(bg, 0)
		if a := st.Snapshot("x").Assets[relayID]; a.Code != string(adapter.FailedAuthRejected) || a.Detail != c.want {
			t.Fatalf("%+v: %+v", c, a)
		}
		r.Close()
	}
	for d, want := range map[string]string{
		"read timed out after 3 of 8 rows":          "read timed out after 3 of 8 rows",
		"bell\x07":                                  "",
		strings.Repeat("x", adapter.MaxDetailLen+1): "",
		strings.Repeat("x", adapter.MaxDetailLen):   strings.Repeat("x", adapter.MaxDetailLen),
		"caf\xc3\xa9":                               "",
	} {
		if got := c2Detail(d); got != want {
			t.Errorf("c2Detail(%q) = %q", d, got)
		}
	}
}
