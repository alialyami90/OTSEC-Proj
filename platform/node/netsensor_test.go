package node

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/netretain"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

const sensorID = "6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7"

// sensorSection is a network_sensor section that loads.
func sensorSection() map[string]any {
	return map[string]any{"sensor_id": sensorID, "evidence_class": "simulated", "outage_hours": 72, "alert_retention_days": 30}
}

// sensorQuotas gives nc the configuration quota and both network quotas.
func sensorQuotas(nc *nodeconfigtest.Config) {
	nc.Store.Quotas["configuration"] = 16 << 20
	nc.Store.Quotas["network-observation"] = 64 << 20
	nc.Store.Quotas["network-alert"] = 16 << 20
}

func findDB(l c5.Layout, id c5.DatabaseID) *c5.Database {
	for i := range l.Databases {
		if l.Databases[i].ID == id {
			return &l.Databases[i]
		}
	}
	return nil
}

// With the section, the layout has the network database: writer detection,
// the sensor's two streams, each class with its quota and the 64 KiB record
// cap. The netbaseline stream is in the configuration database. A forwarding
// target consumes the alert stream and never the observation stream.
func TestNetworkSensorLayout(t *testing.T) {
	c, _ := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
		nc.AddRELPTarget("central", "127.0.0.1", 6514, "test-ca", "test-client", "test/durable-ack", true)
	})
	if !c.NetworkSensorOn() || c.NetworkSensor.SensorID != sensorID || c.NetworkSensor.OutageHours != 72 {
		t.Fatalf("section %+v", c.NetworkSensor)
	}
	l, err := c.Layout()
	if err != nil {
		t.Fatal(err)
	}
	d := findDB(l, NetworkDB)
	if d == nil {
		t.Fatalf("no network database in %+v", l.Databases)
	}
	want := []c5.StreamSpec{
		{ID: "network-observation/" + sensorID, Class: c5.ClassNetworkObservation},
		{ID: "network-alert/" + sensorID, Class: c5.ClassNetworkAlert},
	}
	if d.Writer != "detection" || len(d.Streams) != 2 || d.Streams[0] != want[0] || d.Streams[1] != want[1] {
		t.Fatalf("network database %+v", d)
	}
	if len(d.Quotas) != 2 {
		t.Fatalf("quotas %+v", d.Quotas)
	}
	for _, q := range d.Quotas {
		if q.MaxRecordBytes != 64<<10 || q.Bytes != c.Store.Quotas[string(q.Class)] {
			t.Errorf("quota %+v", q)
		}
	}
	cdb := findDB(l, ConfigDB)
	if cdb == nil {
		t.Fatal("no configuration database")
	}
	var baseline bool
	for _, s := range cdb.Streams {
		if s.ID == "netbaseline/"+sensorID && s.Class == c5.ClassConfiguration {
			baseline = true
		}
	}
	if !baseline {
		t.Fatalf("no netbaseline stream in %+v", cdb.Streams)
	}
	cs, err := c.Consumers()
	if err != nil {
		t.Fatal(err)
	}
	var alert bool
	for _, x := range cs {
		if x.ID == netretain.ConsumerID {
			t.Errorf("a retention consumer beside a target: %+v", x)
		}
		switch x.Stream {
		case NetObservationStream(sensorID), NetBaselineStream(sensorID):
			t.Errorf("a target consumes %s: %+v", x.Stream, x)
		case NetAlertStream(sensorID):
			alert = true
		}
	}
	if !alert {
		t.Errorf("no target consumes the alert stream: %+v", cs)
	}
}

// With the section absent, the layout is the one the node had before it:
// network quotas in store.quotas change nothing.
func TestNetworkSensorAbsent(t *testing.T) {
	layout := func(mod func(*nodeconfigtest.Config)) []byte {
		c, _ := schedConfig(t, func(nc *nodeconfigtest.Config) {
			nc.Store.Quotas["configuration"] = 16 << 20
			mod(nc)
		})
		if c.NetworkSensorOn() {
			t.Fatal("section on")
		}
		l, err := c.Layout()
		if err != nil {
			t.Fatal(err)
		}
		if findDB(l, NetworkDB) != nil {
			t.Fatalf("a network database without the section: %+v", l.Databases)
		}
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	before := layout(func(*nodeconfigtest.Config) {})
	after := layout(sensorQuotas)
	if string(before) != string(after) {
		t.Fatalf("network quotas changed the layout:\n%s\n%s", before, after)
	}
}

// Each refusal the section's text names refuses the whole file, with the
// field in the error.
func TestNetworkSensorRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mod     func(nc *nodeconfigtest.Config)
		refused string
	}{
		{"sensor_id upper case", func(nc *nodeconfigtest.Config) {
			nc.NetworkSensor["sensor_id"] = strings.ToUpper(sensorID)
		}, "network_sensor.sensor_id"},
		{"sensor_id not a UUID", func(nc *nodeconfigtest.Config) { nc.NetworkSensor["sensor_id"] = "sensor-1" }, "network_sensor.sensor_id"},
		{"sensor_id absent", func(nc *nodeconfigtest.Config) { delete(nc.NetworkSensor, "sensor_id") }, "network_sensor.sensor_id"},
		{"evidence_class documented", func(nc *nodeconfigtest.Config) {
			nc.NetworkSensor["evidence_class"] = "documented"
		}, "network_sensor.evidence_class"},
		{"evidence_class absent", func(nc *nodeconfigtest.Config) { delete(nc.NetworkSensor, "evidence_class") }, "network_sensor.evidence_class"},
		{"outage_hours 0", func(nc *nodeconfigtest.Config) { nc.NetworkSensor["outage_hours"] = 0 }, "network_sensor.outage_hours"},
		{"outage_hours negative", func(nc *nodeconfigtest.Config) { nc.NetworkSensor["outage_hours"] = -1 }, "network_sensor.outage_hours"},
		{"outage_hours 721", func(nc *nodeconfigtest.Config) {
			nc.NetworkSensor["outage_hours"] = MaxSyslogOutageHours + 1
		}, "network_sensor.outage_hours"},
		{"alert_retention_days absent with no target", func(nc *nodeconfigtest.Config) {
			delete(nc.NetworkSensor, "alert_retention_days")
		}, "network_sensor.alert_retention_days"},
		{"alert_retention_days 3651", func(nc *nodeconfigtest.Config) {
			nc.NetworkSensor["alert_retention_days"] = MaxAlertRetentionDays + 1
		}, "network_sensor.alert_retention_days"},
		{"alert_retention_days negative with a target", func(nc *nodeconfigtest.Config) {
			nc.NetworkSensor["alert_retention_days"] = -1
			nc.AddRELPTarget("central", "127.0.0.1", 6514, "test-ca", "test-client", "test/durable-ack", true)
		}, "network_sensor.alert_retention_days"},
		{"unknown field", func(nc *nodeconfigtest.Config) { nc.NetworkSensor["interfaces"] = []string{"eth1"} }, "interfaces"},
		{"no observation quota", func(nc *nodeconfigtest.Config) {
			delete(nc.Store.Quotas, "network-observation")
		}, "no quota for class network-observation"},
		{"no alert quota", func(nc *nodeconfigtest.Config) { delete(nc.Store.Quotas, "network-alert") }, "no quota for class network-alert"},
		{"quota below the record cap", func(nc *nodeconfigtest.Config) {
			nc.Store.Quotas["network-alert"] = 64<<10 - 1
		}, "network-alert"},
		{"no configuration quota", func(nc *nodeconfigtest.Config) {
			delete(nc.Store.Quotas, "configuration")
		}, "store.quotas.configuration is required: network_sensor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc := nodeconfigtest.New("site-a-node1", t.TempDir()).AddSEL751(relayID, "127.0.0.1", 2323, 300)
			sensorQuotas(nc)
			nc.NetworkSensor = sensorSection()
			tc.mod(nc)
			_, err := ParseConfig(nc.Bytes())
			if err == nil || !strings.Contains(err.Error(), tc.refused) {
				t.Fatalf("want a refusal naming %q, got %v", tc.refused, err)
			}
		})
	}

	nc := nodeconfigtest.New("site-a-node1", t.TempDir()).AddSEL751(relayID, "127.0.0.1", 2323, 300)
	sensorQuotas(nc)
	nc.NetworkSensor = sensorSection()
	if _, err := ParseConfig(nc.Bytes()); err != nil {
		t.Fatalf("the base case: %v", err)
	}
	for _, h := range []int{1, MaxSyslogOutageHours} {
		nc.NetworkSensor["outage_hours"] = h
		if _, err := ParseConfig(nc.Bytes()); err != nil {
			t.Fatalf("outage_hours %d: %v", h, err)
		}
	}
	for _, d := range []int{1, MaxAlertRetentionDays} {
		nc.NetworkSensor["alert_retention_days"] = d
		if _, err := ParseConfig(nc.Bytes()); err != nil {
			t.Fatalf("alert_retention_days %d: %v", d, err)
		}
	}
	nc.NetworkSensor["evidence_class"] = "device-observed"
	if _, err := ParseConfig(nc.Bytes()); !errors.Is(err, ErrDeviceObserved) {
		t.Fatalf("device-observed: %v", err)
	}
}

// With no forward target the alert stream has the node's retention
// consumer, required, and nothing else consumes it; with a target it
// doesn't, and the section needs no retention (D5-c5-0.9.md section 3).
func TestNetworkRetentionConsumer(t *testing.T) {
	c, _ := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
	})
	cs, err := c.Consumers()
	if err != nil {
		t.Fatal(err)
	}
	want := c5.Consumer{ID: netretain.ConsumerID, Stream: NetAlertStream(sensorID), Delivery: c5.Required}
	if !c.NetRetentionOn() || len(cs) != 1 || cs[0] != want {
		t.Fatalf("consumers %+v", cs)
	}
	c, _ = schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
		delete(nc.NetworkSensor, "alert_retention_days")
		nc.AddRELPTarget("central", "127.0.0.1", 6514, "test-ca", "test-client", "test/durable-ack", true)
	})
	if c.NetRetentionOn() {
		t.Fatal("a retention consumer beside a target")
	}
}
