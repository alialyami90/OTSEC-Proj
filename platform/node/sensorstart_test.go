package node

import (
	"context"
	"database/sql"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/sensorlink"
)

// waitSensor waits for the sensor manager's first step, which runs after
// Start returns, starts the retention consumer and ends with the sensor's
// tick, which starts the detector. So a test reads the sensor as Start
// used to leave it.
func waitSensor(t *testing.T, r *Runtime) {
	t.Helper()
	select {
	case <-r.SensorFirstStep():
	case <-time.After(30 * time.Second):
		t.Fatal("the sensor manager's first step did not end within 30 s")
	}
}

// sensorStep asks the sensor manager for a step, as Tick does, and waits
// for it and the drives it leaves (WaitSensorStep). Tick does not wait for
// the manager (F3), so a test that reads what the sensor's work did waits
// here.
func sensorStep(t *testing.T, r *Runtime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(bg, 30*time.Second)
	defer cancel()
	if err := r.WaitSensorStep(ctx); err != nil {
		t.Fatalf("the sensor manager's step: %v", err)
	}
}

// tick is Tick, then a wait for the sensor manager's step that Tick asked
// for and the drives it leaves.
func tick(t *testing.T, r *Runtime) {
	t.Helper()
	m := r.smgr
	if m == nil || m.kick == nil {
		r.Tick(bg)
		return
	}
	want := m.nextStep()
	r.Tick(bg)
	ctx, cancel := context.WithTimeout(bg, 30*time.Second)
	defer cancel()
	if err := r.waitSettled(ctx, want); err != nil {
		t.Fatalf("the sensor manager's step after Tick: %v", err)
	}
}

// heldManager runs f with the sensor manager held between steps, so f may
// reach the detector or the intake as the manager's goroutine does.
func heldManager(r *Runtime, f func()) {
	r.smgr.run.Lock()
	defer r.smgr.run.Unlock()
	f()
}

// F2 (F-027; D5-sensor-node.md section 1.9 item 2): an intake hold record
// that cannot be read does not fail the node's start. The node starts,
// raises sensor-intake-not-started once, refuses the sensor's connection,
// and a scheduled run is sent and stores its rows; each tick tries the
// intake again, and the alarm is not raised again while it stays down.
// The record is made unreadable in the database file, as a disk fault or
// an older build's record would leave it. Desk only: no sensor and no
// device; the collector is the in-memory wire.
func TestHoldRecordUnreadableNodeStarts(t *testing.T) {
	c, dir := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
	})
	r, _, _ := start(t, c, dir)
	if err := r.saveIntake(bg, sensorlink.RunRecord{State: sensorlink.HoldHolding,
		Run:   sensorlink.HoldRun{RequestID: "req-f2", AssetID: relayID, Endpoint: netip.MustParseAddrPort("127.0.0.1:2323"), L4: "tcp"},
		Flows: []sensorlink.HeldFlow{}, Open: []sensorlink.OpenFlow{}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	sdb, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(c.Store.Dir, string(ConfigDB)+".db")))
	if err != nil {
		t.Fatal(err)
	}
	res, err := sdb.Exec(`UPDATE events SET event = replace(event, '"state":"holding"', '"state":"broken"') WHERE stream = ? AND CAST(event AS TEXT) LIKE '%"request_id":"req-f2"%'`, string(NetBaselineStream(sensorID)))
	sdb.Close()
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("changed %d records", n)
	}

	r, st, _ := start(t, c, dir) // on main: "node: the sensor's intake: ..."
	defer r.Close()
	if n := countAlarms(st, AlarmSensorIntakeNotStarted); n != 1 {
		t.Fatalf("%d %s alarms", n, AlarmSensorIntakeNotStarted)
	}
	if err := r.ServeSensor(bg, sensorChannel(t, sensorFlow(1, sensorID))); err == nil {
		t.Fatal("the sensor was served with the intake not started")
	}
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	rep := s.RunOnce(bg, 0)
	if !rep.Sent || rep.Decision != authz.ReplyAccepted || rep.Outcome != "ok" || rep.Events == 0 || rep.Alarm != "" {
		t.Fatalf("run: %+v", rep)
	}
	ser, err := r.Store(SERStream(relayID)).Read(bg, SERStream(relayID), 0, 1000)
	if err != nil || len(ser) != rep.Events {
		t.Fatalf("SER stream: %d events, %v; the run says %d", len(ser), err, rep.Events)
	}
	tick(t, r)
	tick(t, r)
	if n := countAlarms(st, AlarmSensorIntakeNotStarted); n != 1 || r.sensor.Load() != nil {
		t.Fatalf("after two ticks: %d alarms, intake started %v", n, r.sensor.Load() != nil)
	}
}
