package contract

// C5 0.2 (P3-A5, docs/phase2/A5-p3-failed-open-retry.md, acceptance test 1):
// Resume retries ModeFailed only when the open step failed with
// CodeOpenBusy, and from every other failed step or cause returns prev
// unchanged, with no call to the environment. A6's own StartupEnv; nothing
// of A5's test fakes. Ground truth: GT-HAND from the brief and the C5 0.2
// rule text ("from error text never", "every other failure still needs a
// restart").

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/store"
)

var errA6 = errors.New("a6: injected")

// a6Busy is an open that failed only because the database was busy, as the
// contract says an implementation reports it: a CodeOpenBusy error, here
// wrapped twice to show the rule follows the chain.
var a6Busy = fmt.Errorf("open evidence.db: %w", fmt.Errorf("sqlite: %w", &store.Error{Code: store.CodeOpenBusy, Err: errA6}))

type a6Env struct {
	calls    []string
	fail     map[string]error
	exists   bool
	reserves map[store.Reserve]bool
	free     int64
	locks    int
	unlocked int
}

func newA6Env() *a6Env {
	return &a6Env{fail: map[string]error{}, exists: true, free: 1 << 30,
		reserves: map[store.Reserve]bool{store.ReserveRecovery: true, store.ReserveLastResort: true}}
}

func (e *a6Env) call(name string) error {
	e.calls = append(e.calls, name)
	return e.fail[name]
}

func (e *a6Env) Lock(context.Context) (func(), error) {
	if err := e.call("Lock"); err != nil {
		return nil, err
	}
	e.locks++
	return func() { e.unlocked++ }, nil
}

func (e *a6Env) StoreExists(context.Context) (bool, error) { return e.exists, e.call("StoreExists") }

func (e *a6Env) ReserveExists(_ context.Context, r store.Reserve) (bool, error) {
	return e.reserves[r], e.call("ReserveExists:" + string(r))
}

func (e *a6Env) ReleaseReserve(_ context.Context, r store.Reserve) error {
	if err := e.call("ReleaseReserve:" + string(r)); err != nil {
		return err
	}
	e.reserves[r] = false
	return nil
}

func (e *a6Env) FreeBytes(context.Context) (int64, error) { return e.free, e.call("FreeBytes") }

func (e *a6Env) Open(context.Context) (store.RecoveryStore, error) {
	if err := e.call("Open"); err != nil {
		return nil, err
	}
	return &a6Store{env: e}, nil
}

func (e *a6Env) CreateReserve(_ context.Context, r store.Reserve, _ int64) error {
	if err := e.call("CreateReserve:" + string(r)); err != nil {
		return err
	}
	e.reserves[r] = true
	return nil
}

// a6Store answers only what recovery of an empty, unpressured store asks;
// any other method panics through the nil embedded interface, so a retry
// that reaches further than the contract says shows up.
type a6Store struct {
	store.RecoveryStore
	env *a6Env
}

func (s *a6Store) CheckSettings(context.Context) error { return s.env.call("CheckSettings") }
func (s *a6Store) QuickCheck(context.Context) error    { return s.env.call("QuickCheck") }
func (s *a6Store) Usage(context.Context) (int64, int64, error) {
	return 0, 1 << 30, s.env.call("Usage")
}
func (s *a6Store) CompactStep(context.Context, int) (bool, error) {
	return false, s.env.call("CompactStep")
}
func (s *a6Store) Close() error { s.env.call("Close"); return nil }

func a6Policy() store.StartupPolicy {
	return store.StartupPolicy{
		Streams:                []store.StreamSpec{{ID: "node/audit", Class: store.ClassAudit}},
		RecoveryReserveBytes:   1 << 20,
		LastResortReserveBytes: 1 << 20,
		OpenHeadroomBytes:      store.MinOpenHeadroom,
		PruneStepEvents:        50,
		CompactStepPages:       64,
		PruneTarget:            0.8,
	}
}

func a6HasAlarm(r store.Report, c store.AlarmCode) bool {
	return slices.ContainsFunc(r.Alarms, func(a store.Alarm) bool { return a.Code == c })
}

// The retry starts at the headroom check under the lock already held: no
// second lock, no inspection, no reserve released twice; then it opens,
// checks, recovers and re-creates the released reserve.
func TestC5BusyOpenIsRetriedFromHeadroom(t *testing.T) {
	ctx := context.Background()
	e := newA6Env()
	e.fail["Open"] = a6Busy
	r := store.RunStartup(ctx, e, a6Policy())
	if r.Mode != store.ModeFailed || !r.OpenBusy() || !a6HasAlarm(r, store.AlarmOpenFailed) || r.Unlock == nil {
		t.Fatalf("first startup: mode %s busy %v alarms %v", r.Mode, r.OpenBusy(), r.Alarms)
	}
	if e.unlocked != 0 {
		t.Fatal("the failed startup gave up the store lock; a retry would open without it")
	}
	for i := 0; i < 3; i++ { // busy again, three ticks
		e.calls = nil
		r = store.Resume(ctx, e, a6Policy(), r)
		if r.Mode != store.ModeFailed || !r.OpenBusy() || r.Unlock == nil {
			t.Fatalf("busy retry %d: mode %s busy %v", i, r.Mode, r.OpenBusy())
		}
		if !slices.Equal(e.calls, []string{"FreeBytes", "Open"}) {
			t.Fatalf("busy retry %d calls %v", i, e.calls)
		}
	}
	delete(e.fail, "Open")
	e.calls = nil
	prev := r
	next := store.Resume(ctx, e, a6Policy(), prev)
	if next.Mode != store.ModeCollecting || next.Store == nil || next.OpenBusy() {
		t.Fatalf("retry after the lock is free: mode %s calls %v alarms %v", next.Mode, e.calls, next.Alarms)
	}
	if e.locks != 1 || e.unlocked != 0 || next.Unlock == nil {
		t.Fatalf("lock taken %d times, released %d, unlock kept %v", e.locks, e.unlocked, next.Unlock != nil)
	}
	// Reserves are checked again after recovery, to re-create the one the
	// first startup released; before the open, nothing but the headroom.
	for _, c := range e.calls[:slices.Index(e.calls, "Open")] {
		if c != "FreeBytes" {
			t.Fatalf("the retry repeated a step before the headroom check: %v", e.calls)
		}
	}
	for _, c := range e.calls {
		if c == "Lock" || c == "StoreExists" || strings.HasPrefix(c, "ReleaseReserve:") {
			t.Fatalf("the retry repeated a step before the headroom check: %v", e.calls)
		}
	}
	want := []string{"FreeBytes", "Open", "CheckSettings", "QuickCheck"}
	if !slices.Equal(e.calls[:4], want) {
		t.Fatalf("retry order %v, want it to start %v", e.calls, want)
	}
	if !e.reserves[store.ReserveRecovery] || !e.reserves[store.ReserveLastResort] {
		t.Fatalf("reserves not re-created after the retry: %v", e.reserves)
	}
	if c, ok := store.ModeChangeOf(prev, next, time.Now()); !ok || c.From != store.ModeFailed || c.To != store.ModeCollecting {
		t.Fatalf("no failed-to-collecting mode change: %+v %v", c, ok)
	}
}

// Every failure that is not "the open step, CodeOpenBusy" stays failed:
// Resume makes no call and returns prev. Table over every step that can
// fail before or after the open, each with a busy error (a busy error at
// another step is not an open that was only busy), and the open step with
// every other C5 code, a bare error, and errors whose text claims busy.
func TestC5EveryOtherFailureStaysTerminal(t *testing.T) {
	ctx := context.Background()
	other := []store.Code{store.CodeInvalid, store.CodeStartupFailed, store.CodeAuditUnavailable}
	type tc struct {
		name, call string
		err        error
	}
	var cases []tc
	for _, call := range []string{"Lock", "StoreExists", "ReserveExists:recovery", "ReserveExists:last-resort",
		"ReleaseReserve:recovery", "FreeBytes", "CheckSettings", "QuickCheck"} {
		cases = append(cases, tc{call + " busy", call, a6Busy})
	}
	for _, c := range other {
		cases = append(cases, tc{"Open " + string(c), "Open", fmt.Errorf("open: %w", &store.Error{Code: c, Err: errA6})})
	}
	cases = append(cases,
		tc{"Open bare", "Open", errA6},
		tc{"Open text says locked", "Open", errors.New("database is locked (5) (SQLITE_BUSY)")},
		tc{"Open text says open-busy", "Open", errors.New(string(store.CodeOpenBusy))},
		tc{"Open busy cause only in Detail", "Open", &store.Error{Code: store.CodeInvalid, Detail: "open-busy", Err: errA6}},
	)
	for _, c := range cases {
		e := newA6Env()
		e.fail[c.call] = c.err
		r := store.RunStartup(ctx, e, a6Policy())
		if r.Mode != store.ModeFailed {
			t.Errorf("%s: startup mode %s, want failed", c.name, r.Mode)
			continue
		}
		if r.OpenBusy() {
			t.Errorf("%s: OpenBusy true", c.name)
		}
		delete(e.fail, c.call)
		e.calls = nil
		next := store.Resume(ctx, e, a6Policy(), r)
		if next.Mode != store.ModeFailed || len(e.calls) != 0 || next.Store != nil {
			t.Errorf("%s: Resume gave %s with calls %v", c.name, next.Mode, e.calls)
		}
	}
	// An invalid policy fails before the lock; it is not retried either.
	e := newA6Env()
	p := a6Policy()
	p.PruneStepEvents = 0
	r := store.RunStartup(ctx, e, p)
	e.calls = nil
	if next := store.Resume(ctx, e, p, r); r.Mode != store.ModeFailed || r.OpenBusy() || len(e.calls) != 0 || next.Mode != store.ModeFailed {
		t.Errorf("invalid policy: %s busy %v, Resume %s calls %v", r.Mode, r.OpenBusy(), next.Mode, e.calls)
	}
}

// OpenBusy reads the last step only, and only in ModeFailed. Hand-built
// reports cover what RunStartup cannot produce, so a check on "any step"
// or "any mode" fails here.
// A busy retry first checks the headroom again: below it the node is
// blocked, not opened.
func TestC5BusyRetryBelowHeadroomIsBlocked(t *testing.T) {
	ctx := context.Background()
	e := newA6Env()
	e.fail["Open"] = a6Busy
	r := store.RunStartup(ctx, e, a6Policy())
	delete(e.fail, "Open")
	e.free = store.MinOpenHeadroom - 1
	e.calls = nil
	next := store.Resume(ctx, e, a6Policy(), r)
	if next.Mode != store.ModeBlocked || slices.Contains(e.calls, "Open") || next.Unlock == nil || e.unlocked != 0 {
		t.Fatalf("below headroom: mode %s calls %v unlock kept %v", next.Mode, e.calls, next.Unlock != nil)
	}
}

func TestC5OpenBusyNeedsFailedModeAndLastStep(t *testing.T) {
	busyOpen := store.StepResult{Step: store.StepOpen, Err: a6Busy}
	for _, c := range []struct {
		name string
		r    store.Report
		want bool
	}{
		{"failed, last step busy open", store.Report{Mode: store.ModeFailed, Steps: []store.StepResult{{Step: store.StepLock}, busyOpen}}, true},
		{"blocked, last step busy open", store.Report{Mode: store.ModeBlocked, Steps: []store.StepResult{busyOpen}}, false},
		{"drain-only, last step busy open", store.Report{Mode: store.ModeDrainOnly, Steps: []store.StepResult{busyOpen}}, false},
		{"collecting, last step busy open", store.Report{Mode: store.ModeCollecting, Steps: []store.StepResult{busyOpen}}, false},
		{"failed, busy open then a later failure", store.Report{Mode: store.ModeFailed, Steps: []store.StepResult{busyOpen, {Step: store.StepSettings, Err: errA6}}}, false},
		{"failed, busy at settings", store.Report{Mode: store.ModeFailed, Steps: []store.StepResult{{Step: store.StepOpen}, {Step: store.StepSettings, Err: a6Busy}}}, false},
		{"failed, open step with no error", store.Report{Mode: store.ModeFailed, Steps: []store.StepResult{{Step: store.StepOpen}}}, false},
		{"failed, no steps", store.Report{Mode: store.ModeFailed}, false},
	} {
		if got := c.r.OpenBusy(); got != c.want {
			t.Errorf("%s: OpenBusy %v, want %v", c.name, got, c.want)
		}
	}
}
