package node

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// TestSensorPanicContained, the detector drive's leg (section 1.9 item 9; brief
// P4-4-F27's table, step (3); D6 on #695): a panic in a drive of the
// detector between the steps Tick asks for, on the manager's goroutine, is
// recovered. sensor-failed is raised once, naming the sensor; the sensor's
// work stops (no further drive, the sensor refused, the manager ended); and
// the node goes on: Tick returns within 2 s, a scheduled run is sent and
// stores its SER rows, and the health stream and the Syslog listener's
// stream commit within 2 s. Desk only: no sensor and no device. Control:
// managerStep's recover removed, which ends the test process.
func TestSensorPanicContained(t *testing.T) {
	const lis = "lab-udp"
	c, dir := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
		nc.AddListener(lis, "syslog-udp", "127.0.0.1:0")
	})
	var calls atomic.Int32
	r, st := startSeams(t, c, dir, SensorSeams{Observe: func() {
		calls.Add(1)
		panic("node test: a fault in the detector's drive")
	}})
	defer r.Close()
	m := r.smgr
	m.stepMu.Lock()
	begun := m.begun
	m.stepMu.Unlock()
	// No Tick and no kick: the manager's drive ticker drives the detector.
	if err := r.ServeSensor(bg, sensorChannel(t, relayFlow(1), relayFlow(2))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the sensor manager did not stop within 10 s of the drive's panic")
	}
	m.stepMu.Lock()
	inStep := m.begun != begun
	m.stepMu.Unlock()
	if inStep {
		t.Fatal("a step Tick asked for began; the panic was not in a drive between steps")
	}
	if n := countAlarms(st, AlarmSensorFailed); n != 1 {
		t.Fatalf("%d sensor-failed alarms", n)
	}
	for _, a := range st.Snapshot("x").Alarms {
		if a.Code == AlarmSensorFailed && (!strings.Contains(a.Detail, sensorID) || !strings.Contains(a.Detail, "the detector's drive")) {
			t.Fatalf("sensor-failed detail: %.300s", a.Detail)
		}
	}
	ticked := make(chan struct{})
	go func() { r.Tick(bg); close(ticked) }()
	select {
	case <-ticked:
	case <-time.After(2 * time.Second):
		t.Fatal("Tick did not return within 2 s after the drive's panic")
	}
	runSent(t, r)
	appendWithin(t, HealthStream, func() (c5.Record, error) {
		return r.healthRecord(HealthStream, "node.test", map[string]string{"n": "1"})
	}, r)
	stream := ListenerStream(lis)
	appendWithin(t, stream, func() (c5.Record, error) {
		ev, err := normalize.Syslog(normalize.SyslogInput{Node: c.NodeID, Stream: event.Stream(stream),
			Message: []byte("<13>1 - relay - - - - test"), Sender: "127.0.0.2", Auth: event.AuthNone,
			AssetID: relayID, EvidenceClass: asset.Simulated, Dialect: normalize.DialectRFC, Received: r.received()})
		if err != nil {
			return c5.Record{}, err
		}
		b, err := json.Marshal(&ev)
		return c5.Record{Stream: stream, Class: c5.ClassSyslogDatagram, Event: b}, err
	}, r)
	if m := r.Mode(EvidenceDB); m != c5.ModeCollecting {
		t.Fatalf("the evidence database: %s", m)
	}
	if err := r.ServeSensor(bg, sensorChannel(t, relayFlow(3))); err == nil {
		t.Fatal("the sensor was served after its work failed")
	}
	if n, a := calls.Load(), countAlarms(st, AlarmSensorFailed); n != 1 || a != 1 {
		t.Fatalf("%d drives into the seam, %d sensor-failed alarms", n, a)
	}
}

// appendWithin builds a record with rec and appends it to stream, which
// must commit within 2 s.
func appendWithin(t *testing.T, stream c5.StreamID, rec func() (c5.Record, error), r *Runtime) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		x, err := rec()
		if err == nil {
			_, err = r.Log(stream).Append(bg, x)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("an append to %s: %v", stream, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("an append to %s did not commit within 2 s", stream)
	}
}
