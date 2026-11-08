package node

import (
	"fmt"

	"otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
)

// NetworkSensor is the network_sensor section (P4-4-B5 deliverable 6,
// docs/phase4/D5-sensor-node.md section 5). An absent section is off: the
// layout has no network database and no netbaseline stream, and nothing
// item 4 owns runs. The class quotas are in store.quotas, as every class's
// are.
type NetworkSensor struct {
	// SensorID is the sensor's lowercase UUID. The node checks every
	// record's sensor_id against it (C13 section 3).
	SensorID string `json:"sensor_id"`
	// EvidenceClass is the class the node gives every observation from
	// this sensor (C13 node.evidence_class, D1-23): it comes from here,
	// never from the record.
	EvidenceClass asset.EvidenceClass `json:"evidence_class"`
	// OutageHours is the planned outage over which unresolved
	// observations may take at most a quarter of the observation quota
	// (the unresolved budget, docs/phase4/D5-c5-0.9.md section 4).
	OutageHours int `json:"outage_hours"`
}

// NetworkDB holds the network classes and nothing else (C5 0.9), so a
// network flood never holds another database's write lock. It exists only
// with the network_sensor section.
const NetworkDB c5.DatabaseID = "network"

// NetworkRecordBytes is the record cap of both network classes: the
// smallest C5 allows, which C13 section 10 pins the worst stored
// observation and alert under.
const NetworkRecordBytes int64 = c5.MinRecordBytes

// NetObservationStream is a sensor's observation stream.
func NetObservationStream(sensorID string) c5.StreamID {
	return c5.StreamID("network-observation/" + sensorID)
}

// NetAlertStream is a sensor's alert stream.
func NetAlertStream(sensorID string) c5.StreamID {
	return c5.StreamID("network-alert/" + sensorID)
}

// NetBaselineStream is a sensor's stream of network baselines and the
// learner's and detector's checkpoints, in the configuration database
// (docs/phase4/D5-c5-0.9.md, "Where they live").
func NetBaselineStream(sensorID string) c5.StreamID {
	return c5.StreamID("netbaseline/" + sensorID)
}

// NetworkSensorOn reports whether the network_sensor section is set.
func (c *Config) NetworkSensorOn() bool { return c.NetworkSensor != nil }

// checkNetworkSensor checks the section's fields. The quotas are checked by
// Layout.
func (c *Config) checkNetworkSensor(fail func(format string, args ...any)) {
	s := c.NetworkSensor
	if s == nil {
		return
	}
	if !asset.ValidAssetID(s.SensorID) {
		fail("network_sensor.sensor_id %q is not a lowercase UUID", s.SensorID)
	}
	switch s.EvidenceClass {
	case asset.Simulated:
	case asset.DeviceObserved:
		fail("network_sensor.evidence_class: %w", ErrDeviceObserved)
	default:
		fail("network_sensor.evidence_class %q is not %s", s.EvidenceClass, asset.Simulated)
	}
	if s.OutageHours < 1 {
		fail("network_sensor.outage_hours %d is below 1: the unresolved budget refills over it", s.OutageHours)
	}
}

// networkLayout returns the network database, and adds the sensor's
// netbaseline stream to the configuration database, which therefore needs
// store.quotas.configuration. With the section absent it returns a database
// with no streams, which Layout leaves out.
func (c *Config) networkLayout(configDB *c5.Database) (c5.Database, error) {
	s := c.NetworkSensor
	if s == nil {
		return c5.Database{}, nil
	}
	if _, ok := c.Store.Quotas[string(c5.ClassConfiguration)]; !ok {
		return c5.Database{}, fmt.Errorf("store.quotas.configuration is required: network_sensor keeps its baseline and checkpoints on stream %s, of class configuration", NetBaselineStream(s.SensorID))
	}
	configDB.Streams = append(configDB.Streams, c5.StreamSpec{ID: NetBaselineStream(s.SensorID), Class: c5.ClassConfiguration})
	return c5.Database{ID: NetworkDB, Writer: "detection", Streams: []c5.StreamSpec{
		{ID: NetObservationStream(s.SensorID), Class: c5.ClassNetworkObservation},
		{ID: NetAlertStream(s.SensorID), Class: c5.ClassNetworkAlert},
	}}, nil
}
