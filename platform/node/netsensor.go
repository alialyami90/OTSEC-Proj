package node

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"

	"otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
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
	// AlertRetentionDays is how long the sensor's alerts are kept when no
	// forward target consumes the alert stream: the node's retention
	// consumer then moves past older alerts (D5-c5-0.9.md section 3,
	// netretain). It is required with no target, and refused with one,
	// where the target confirms alerts and nothing would read it (D1 in
	// D4-70).
	AlertRetentionDays int `json:"alert_retention_days,omitempty"`
	// NodeAddresses, NodeMACs and NodeVLANs are the node's own addresses,
	// MACs and VLANs, from the install configuration and never from
	// traffic (baseline note section 5, D1 in D4-72). Intake holds a flow
	// from a node address to a dispatched run's endpoint until the run's
	// result ties it; node-address-spoofed reads all three.
	NodeAddresses []string `json:"node_addresses"`
	NodeMACs      []string `json:"node_macs"`
	// NodeVLANs are VLAN IDs, 1 to 4094, as numbers, or the string
	// "untagged".
	NodeVLANs []NodeVLAN `json:"node_vlans"`
}

// NodeVLAN is one entry of node_vlans: a VLAN ID, or 0 for "untagged".
type NodeVLAN int

// UntaggedVLAN is the node_vlans entry for untagged frames.
const UntaggedVLAN = "untagged"

// MaxNodeIdentities bounds node_addresses and node_macs (D1 in D4-72).
const MaxNodeIdentities = 8

// UnmarshalJSON takes a number from 1 to 4094 or the string "untagged". A
// 0 is refused: it would read as untagged without saying so.
func (v *NodeVLAN) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		if s != UntaggedVLAN {
			return fmt.Errorf("network_sensor.node_vlans: %q is not a VLAN ID or %q", s, UntaggedVLAN)
		}
		*v = 0
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil || n < 1 || n > 4094 {
		return fmt.Errorf("network_sensor.node_vlans: %s is not a VLAN ID from 1 to 4094 or %q", b, UntaggedVLAN)
	}
	*v = NodeVLAN(n)
	return nil
}

// MarshalJSON writes the form UnmarshalJSON reads.
func (v NodeVLAN) MarshalJSON() ([]byte, error) {
	if v == 0 {
		return json.Marshal(UntaggedVLAN)
	}
	return json.Marshal(int(v))
}

// NodeAddrs returns node_addresses parsed, unmapped and without a zone.
func (s *NetworkSensor) NodeAddrs() []netip.Addr {
	out := make([]netip.Addr, 0, len(s.NodeAddresses))
	for _, a := range s.NodeAddresses {
		if p, err := netip.ParseAddr(a); err == nil {
			out = append(out, p.Unmap().WithZone(""))
		}
	}
	return out
}

// Exclusion is a flow the node makes on purpose that is not a collector
// session: the exact address, transport and port of a forward target
// (D1 in D4-72). The sensor link's own is added with its transport
// (ADR-0009).
type Exclusion struct {
	Addr netip.Addr
	L4   string
	Port int
}

// NetExclusions are the node's forward targets as exclusions. Load refuses
// a target whose host is not an IP literal when network_sensor is set, so
// every target has one.
func (c *Config) NetExclusions() []Exclusion {
	var out []Exclusion
	for _, t := range c.targets {
		a, err := netip.ParseAddr(t.Host)
		if err != nil {
			continue
		}
		l4 := "tcp"
		if t.Transport == syslog.TransportUDP {
			l4 = "udp"
		}
		out = append(out, Exclusion{Addr: a.Unmap().WithZone(""), L4: l4, Port: t.Port})
	}
	return out
}

// MaxAlertRetentionDays bounds alert_retention_days, so a typo can't keep
// alerts, and hold the alert class, for good.
const MaxAlertRetentionDays = 3650

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

// NetRetentionOn reports whether the sensor's alert stream has the
// retention consumer: the section is set and no forward target consumes
// the alert stream (every target consumes every event stream, Consumers).
func (c *Config) NetRetentionOn() bool { return c.NetworkSensor != nil && len(c.targets) == 0 }

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
	if s.OutageHours < 1 || s.OutageHours > MaxSyslogOutageHours {
		// The budget refills over it, so 0 has no rate, and a typo far above
		// any planned outage would starve unresolved observations (D1 on
		// #550). The bound is syslog_outage_hours's.
		fail("network_sensor.outage_hours %d not in [1, %d]: the unresolved budget refills over it", s.OutageHours, MaxSyslogOutageHours)
	}
	checkNodeIdentities(s, fail)
	for _, t := range c.targets {
		if _, err := netip.ParseAddr(t.Host); err != nil {
			fail("targets: %q has host %q, which is not an IP literal: with network_sensor, the node excludes its own forwarding flows by exact address, transport and port, so a target must name its address (D1 in D4-72)", t.Name, t.Host)
		}
	}
	switch d := s.AlertRetentionDays; {
	case len(c.targets) > 0 && d != 0:
		fail("network_sensor.alert_retention_days is set with a forwarding target: the target confirms the alert stream, so no retention applies; remove it")
	case len(c.targets) == 0 && (d < 1 || d > MaxAlertRetentionDays):
		fail("network_sensor.alert_retention_days %d not in [1, %d]: with no forwarding target, the retention consumer prunes the alert stream after it", d, MaxAlertRetentionDays)
	}
}

// checkNodeIdentities checks node_addresses, node_macs and node_vlans:
// each required, within its bound, in its canonical form and without
// repeats.
func checkNodeIdentities(s *NetworkSensor, fail func(format string, args ...any)) {
	if n := len(s.NodeAddresses); n < 1 || n > MaxNodeIdentities {
		fail("network_sensor.node_addresses has %d entries, not 1 to %d", n, MaxNodeIdentities)
	}
	seen := map[netip.Addr]bool{}
	for _, a := range s.NodeAddresses {
		p, err := netip.ParseAddr(a)
		switch {
		case err != nil || p.Zone() != "":
			fail("network_sensor.node_addresses: %q is not an IP literal without a zone", a)
			continue
		case seen[p.Unmap()]:
			fail("network_sensor.node_addresses: %q is listed twice", a)
		}
		seen[p.Unmap()] = true
	}
	if n := len(s.NodeMACs); n < 1 || n > MaxNodeIdentities {
		fail("network_sensor.node_macs has %d entries, not 1 to %d", n, MaxNodeIdentities)
	}
	macs := map[string]bool{}
	for _, m := range s.NodeMACs {
		hw, err := net.ParseMAC(m)
		switch {
		case err != nil || len(hw) != 6 || hw.String() != m:
			fail("network_sensor.node_macs: %q is not a MAC in lowercase colon form", m)
		case macs[m]:
			fail("network_sensor.node_macs: %q is listed twice", m)
		}
		macs[m] = true
	}
	if len(s.NodeVLANs) == 0 {
		fail("network_sensor.node_vlans is empty: list the node's VLAN IDs, or %q", UntaggedVLAN)
	}
	vlans := map[NodeVLAN]bool{}
	for _, v := range s.NodeVLANs {
		if vlans[v] {
			fail("network_sensor.node_vlans: %s is listed twice", must(json.Marshal(v)))
		}
		vlans[v] = true
	}
}

func must(b []byte, _ error) string { return string(b) }

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
