package node

import (
	"net"
	"testing"
	"time"

	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// TestSensorFailedClosesConnection (section 1.9 item 9; D4-107 item 5.2,
// D6's O1 on #696): a sensor connection that is live at sensor-failed is
// closed, and nothing sent on it afterwards is read. Desk only: no sensor
// and no device; the channel is an in-memory pipe. Control: main's
// behaviour, where the connection stays open and is still read after
// sensor-failed.
func TestSensorFailedClosesConnection(t *testing.T) {
	c, dir := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
	})
	r, st := startSeams(t, c, dir, SensorSeams{Observe: func() { panic("node test: a fault in the detector's drive") }})
	defer r.Close()
	node, sensor := net.Pipe()
	defer sensor.Close()
	served := make(chan error, 1)
	go func() { served <- r.ServeSensor(bg, node) }()
	if _, err := sensor.Write(sensorChannel(t, relayFlow(1), relayFlow(2)).Bytes()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.smgr.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the sensor manager did not stop within 10 s of the drive's panic")
	}
	if n := countAlarms(st, AlarmSensorFailed); n != 1 {
		t.Fatalf("%d sensor-failed alarms", n)
	}
	select {
	case err := <-served:
		if err == nil {
			t.Fatal("ServeSensor returned nil: the connection ended as if the sensor had closed it")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the connection is still open 10 s after sensor-failed")
	}
	_ = sensor.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := sensor.Write(sensorChannel(t, relayFlow(3)).Bytes()); err == nil {
		t.Fatal("a frame sent after sensor-failed was read")
	}
}
