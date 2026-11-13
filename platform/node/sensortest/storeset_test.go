package sensortest

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/store"
)

// gate is a seam that blocks its first caller until released, and tells
// the test when that caller is in it.
type gate struct {
	in      chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func newGate() *gate { return &gate{in: make(chan struct{}), release: make(chan struct{})} }

// wait blocks the first call until release; later calls pass at once.
func (g *gate) wait() {
	if g.calls.Add(1) == 1 {
		close(g.in)
		<-g.release
	}
}

func (g *gate) open() { g.once.Do(func() { close(g.release) }) }

// entered waits up to 10 s for the first caller.
func (g *gate) entered(t *testing.T, what string) {
	t.Helper()
	select {
	case <-g.in:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s was not reached within 10 s", what)
	}
}

// F5 (section 1.9 item 1): a sensor database held drain-only, whose Resume
// does not return, holds neither the state lock that every Log, Store and
// Mode call of the scheduler and the Syslog intake takes, nor Tick, nor
// the sensor database's own accessor. While it is held: Tick returns,
// appends to platform/health, the audit stream and the listener's stream
// commit within 2 s, the evidence database's mode reads, and the sensor's
// alert stream reads as not open at once. Released, the database resumes
// to collecting. Controls: the sensor database back in Runtime.dbs, where
// Tick resumes it under the state lock (main's Tick); and the manager's
// lock held across Resume.
func TestSensorDrainOnlyDoesNotStallSyslog(t *testing.T) {
	g := newRig(t)
	resume := newGate()
	r, _ := g.start(node.SensorSeams{Startup: drainOnly,
		Resume: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy, prev c5.Report) c5.Report {
			resume.wait()
			return c5.Resume(ctx, env, p, prev)
		}})
	// The gate opens before Close, so a control that holds Close behind it ends.
	t.Cleanup(func() { r.Close() })
	t.Cleanup(resume.open)
	if m := r.Mode(node.NetworkDB); m != c5.ModeDrainOnly {
		t.Fatalf("network database %s", m)
	}
	ticked := make(chan struct{})
	go func() { r.Tick(bg); close(ticked) }()
	resume.entered(t, "the sensor database's Resume")
	select {
	case <-ticked:
	case <-time.After(2 * time.Second):
		t.Fatal("Tick did not return within 2 s while a sensor database's Resume runs")
	}
	collecting(t, r, 1)
	within(t, 2*time.Second, "the sensor's accessor", func() error {
		if r.Store(node.NetAlertStream(sensorID)) != nil {
			return errorf("the alert stream's database reads as open while it resumes")
		}
		return nil
	})
	resume.open()
	eventually(t, "the network database resumed", func() bool {
		return r.Mode(node.NetworkDB) == c5.ModeCollecting && r.Store(node.NetAlertStream(sensorID)) != nil
	})
}

// F6 (section 1.9 item 1): a sensor database's prune that does not return
// holds no prune of the node's own databases. Runtime.Prune, which the
// scheduler's cannotKeep calls before it holds a run when adapter-evidence
// is near its limit, returns within 2 s, and so does Tick. The seam runs
// before the sensor database's prune passes, so no class needs to be
// over its target. Control: Prune over the sensor store set as well
// (main's Prune).
func TestCannotKeepPrunesEvidenceOnly(t *testing.T) {
	g := newRig(t)
	prune := newGate()
	r, _ := g.start(node.SensorSeams{Prune: func(context.Context, c5.DatabaseID) error { prune.wait(); return nil }})
	// The gate opens before Close, so a control that holds Close behind it ends.
	t.Cleanup(func() { r.Close() })
	t.Cleanup(prune.open)
	within(t, 2*time.Second, "Tick", func() error { r.Tick(bg); return nil })
	prune.entered(t, "the sensor database's prune")
	within(t, 2*time.Second, "Runtime.Prune while a sensor database's prune is held", func() error { r.Prune(bg); return nil })
	collecting(t, r, 1)
	prune.open()
}

// F7 (section 1.9 item 1): a network database that opens and then fails
// its first read does not fail the node's start. The node starts, raises
// sensor-store-not-open once, and collects; the database reads as not
// open. The manager tries again at the next tick, and the database opens.
// Control: the sensor database back in Runtime.dbs (main's startDB, whose
// failure fails Start).
func TestSensorStoreFailsOpenNodeStarts(t *testing.T) {
	g := newRig(t)
	var opens atomic.Int32
	r, st := g.start(node.SensorSeams{Startup: failFirstRead(&opens)})
	defer r.Close()
	if n := alarms(st, string(node.AlarmSensorStoreNotOpen)); n != 1 || r.Mode(node.NetworkDB) != c5.ModeFailed || r.Store(node.NetAlertStream(sensorID)) != nil {
		t.Fatalf("%d not-open alarms, mode %s", n, r.Mode(node.NetworkDB))
	}
	collecting(t, r, 1)
	r.Tick(bg)
	eventually(t, "the network database opened at a later tick", func() bool {
		return r.Mode(node.NetworkDB) == c5.ModeCollecting && r.Store(node.NetAlertStream(sensorID)) != nil
	})
	if n := alarms(st, string(node.AlarmSensorStoreNotOpen)); n != 1 || opens.Load() != 2 {
		t.Fatalf("%d not-open alarms, %d opens", n, opens.Load())
	}
}

// failFirstRead is a Startup seam: the first startup's store is closed
// before the node reads it, so the node's first read of it fails; later
// startups are C5's.
func failFirstRead(opens *atomic.Int32) func(context.Context, c5.StartupEnv, c5.StartupPolicy) c5.Report {
	return func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
		rep := c5.RunStartup(ctx, env, p)
		if opens.Add(1) == 1 {
			if db, ok := store.AsDB(rep.Store); ok {
				db.Close()
			}
		}
		return rep
	}
}

// F2 (section 1.9 item 2): the intake's start is retried by the manager.
// With the network database not open at start, the intake does not start:
// sensor-intake-not-started is raised once and the sensor is refused. At
// the next tick the manager opens the database and starts the intake,
// which runs loadIntake, Link.RecoverHold and repairIntake, and the sensor
// is served. Control: the intake started at Start only, with no retry.
func TestIntakeStartRetried(t *testing.T) {
	g := newRig(t)
	var opens atomic.Int32
	r, st := g.start(node.SensorSeams{Startup: failFirstRead(&opens)})
	defer r.Close()
	if n := alarms(st, node.AlarmSensorIntakeNotStarted); n != 1 {
		t.Fatalf("%d intake alarms", n)
	}
	if err := r.ServeSensor(bg, bytes.NewReader(nil)); err == nil {
		t.Fatal("the sensor was served with the intake not started")
	}
	r.Tick(bg)
	eventually(t, "the intake started at a later tick", func() bool { return r.ServeSensor(bg, bytes.NewReader(nil)) == nil })
	if n := alarms(st, node.AlarmSensorIntakeNotStarted); n != 1 {
		t.Fatalf("%d intake alarms after the retry", n)
	}
}

// F9 (section 1.9 item 1): a sensor database's mode changes write at most
// one store.mode_change record and one mode_changed health event an hour,
// on the node's monotonic clock; the next record says how many were not
// written. Six changes within the hour after the start's record write
// nothing; the first after the hour writes one, naming the six. Control:
// the cap removed.
func TestSensorModeChangeCapped(t *testing.T) {
	g := newRig(t)
	// The database flaps between blocked, at each startup, and failed, at
	// each Resume; the manager starts a failed one again. ("drain-only"
	// is not used: C8's reason-code pattern refuses it, so main writes no
	// audit record for that mode at all.)
	r, st := g.start(node.SensorSeams{
		Startup: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
			rep := c5.RunStartup(ctx, env, p)
			if db, ok := store.AsDB(rep.Store); ok {
				db.Close()
			}
			return c5.Report{Mode: c5.ModeBlocked, Unlock: rep.Unlock}
		},
		Resume: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy, prev c5.Report) c5.Report {
			return c5.Report{Mode: c5.ModeFailed, Unlock: prev.Unlock}
		}})
	defer r.Close()
	flap := func() {
		t.Helper()
		was := r.Mode(node.NetworkDB)
		r.Tick(bg)
		eventually(t, "a mode change", func() bool { return r.Mode(node.NetworkDB) != was })
	}
	if recs, evs := modeChanges(t, r, node.NetworkDB); len(recs) != 1 || len(evs) != 1 {
		t.Fatalf("at start: %d records, %d events; %+v", len(recs), len(evs), st.Snapshot("x").Alarms)
	}
	for range 6 {
		g.advance(time.Minute)
		flap()
	}
	// The seventh change is seen only once the manager has finished the
	// sixth's step, so every record the six could write is written by then.
	g.advance(time.Hour)
	flap()
	eventually(t, "the record after the hour", func() bool {
		recs, evs := modeChanges(t, r, node.NetworkDB)
		return len(recs) >= 2 && len(evs) >= 2
	})
	recs, evs := modeChanges(t, r, node.NetworkDB)
	if len(recs) != 2 || len(evs) != 2 || !strings.Contains(recs[1].Detail, "6 earlier mode changes") || evs[1]["not_recorded"] != "6" {
		t.Fatalf("after the hour: %d records, %d events; last %+v, %v", len(recs), len(evs), recs[len(recs)-1], evs[len(evs)-1])
	}
}

// Section 1.9 item 10: a sensor database whose Resume never returns, not
// even on its context's end, does not hold the node's stop. Close returns
// within SensorStopTimeout and a little more, and the node's own databases
// are closed and their locks released: a new start opens the evidence
// database collecting. Control: Close waits for the manager without a
// bound.
func TestCloseWithStuckSensorResume(t *testing.T) {
	g := newRig(t)
	stuck := newGate()
	t.Cleanup(stuck.open)
	r, _ := g.start(node.SensorSeams{Startup: drainOnly,
		Resume: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy, prev c5.Report) c5.Report {
			stuck.wait()
			return prev
		}})
	r.Tick(bg)
	stuck.entered(t, "the sensor database's Resume")
	within(t, node.SensorStopTimeout+5*time.Second, "Close", func() error { return r.Close() })
	r2, _ := g.start(node.SensorSeams{})
	m := r2.Mode(node.EvidenceDB)
	r2.Close()
	if m != c5.ModeCollecting {
		t.Fatalf("evidence database after the stop: %s", m)
	}
	// Released, the manager stops and its database is closed then, so the
	// test's directory can be removed.
	stuck.open()
	eventually(t, "the sensor database closed once the manager stopped", func() bool { return r.Mode(node.NetworkDB) == "" })
}

// Section 1.9 item 9, in the manager: a panic on the manager's goroutine
// is recovered. sensor-failed is raised once, the sensor's work stops (the
// manager steps no more and the sensor is refused), and the node goes on:
// Tick returns and every collecting stream commits. Control: no recover,
// which ends the process. The detector drive's leg comes with F3, whose
// brief moves the drive onto the manager.
func TestSensorManagerPanicContained(t *testing.T) {
	g := newRig(t)
	var calls atomic.Int32
	r, st := g.start(node.SensorSeams{Startup: drainOnly,
		Resume: func(context.Context, c5.StartupEnv, c5.StartupPolicy, c5.Report) c5.Report {
			calls.Add(1)
			panic("sensortest: a fault in the sensor's work")
		}})
	defer r.Close()
	r.Tick(bg)
	eventually(t, "sensor-failed", func() bool { return alarms(st, node.AlarmSensorFailed) == 1 })
	within(t, 2*time.Second, "Tick after the panic", func() error { r.Tick(bg); return nil })
	collecting(t, r, 1)
	r.Tick(bg)
	if n := calls.Load(); n != 1 || alarms(st, node.AlarmSensorFailed) != 1 {
		t.Fatalf("%d calls into the seam, %d alarms", n, alarms(st, node.AlarmSensorFailed))
	}
	if err := r.ServeSensor(bg, bytes.NewReader(nil)); err == nil {
		t.Fatal("the sensor was served after its work failed")
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

func errorf(s string) error { return errorString(s) }
