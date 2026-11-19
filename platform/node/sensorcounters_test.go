package node

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/platform/sensorlink"
)

// worstSensorCounters is the worst 0.4 sensor.counters event of C4 0.4
// section 4, built by hand with contracts/event: every difference of the
// 21 counters of 0.3 and 0.4 at 2^64 - 1, capture_loss naming all three,
// a 63-character node ID, and lowercase UUIDs for the sensor and the run.
func worstSensorCounters() *event.Event {
	max := strconv.FormatUint(math.MaxUint64, 10)
	d := map[string]string{"reported_by": event.SensorReported,
		"sensor_id": "ffffffff-ffff-4fff-bfff-ffffffffffff", "run_id": "eeeeeeee-eeee-4eee-beee-eeeeeeeeeeee",
		event.DetailCaptureLoss: strings.Join(event.CaptureLossCounters, " ")}
	for _, n := range append(append([]string{}, event.SensorCounters...), event.SensorCounters04...) {
		d["diff."+n] = max
	}
	return &event.Event{Schema: event.Identifier, ID: event.EventID{NodeID: event.NodeID(strings.Repeat("n", 63)), Stream: event.Stream(HealthStream), Seq: math.MaxUint64 >> 1},
		Origin: event.OriginPlatform, Kind: event.KindHealth, Source: event.Source{OriginAuth: event.AuthPlatform},
		Received: event.Received{UTC: "2026-11-01T00:00:00.000000001Z", ResolutionNS: 1, Clock: event.Clock{Sync: event.SyncSynchronized, Source: "ntp"}},
		Health:   &event.Health{Type: event.HealthSensorCounters, Details: d}}
}

// defaultTarget is TestSensorDropEventFits' target, at the default
// max_message_octets.
func defaultTarget(t *testing.T) *syslog.Target {
	t.Helper()
	tg, err := syslog.ParseTarget([]byte(`{"schema": "otsec.syslog/0.1", "name": "central", "host": "collector.example", "port": 6514,
		"transport": "tls", "format": "rfc5424", "framing": "octet-counting", "class": "best-effort", "replay_seconds": 3600, "max_message_octets": 2048,
		"tls": {"server_name": "collector.example", "trust_anchor_ref": "ca"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tg.MaxMessageOctets != syslog.DefaultMaxOctets {
		t.Fatalf("the target's limit is %d, not the default %d", tg.MaxMessageOctets, syslog.DefaultMaxOctets)
	}
	return tg
}

// E4-6 (C4 0.4 section 5): the worst 0.4 sensor.counters event, which C4
// validates, renders within the default target's 2,048 octets with its
// summary, and the octets are logged; this pins section 4's unreproduced
// estimate. The control is the agent's 14 counts added as
// diff.agent.<name>, in an event of a later minor so that C4 lets them
// pass, which Render refuses as too large. The node's builder leg is
// TestSensorCountersWorstCaseFits. Desk only.
func TestSensorCountersEventFits(t *testing.T) {
	e, tg := worstSensorCounters(), defaultTarget(t)
	if n := len(e.Health.Details); n != 25 {
		t.Fatalf("%d details, want section 4's 25", n)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("the worst event is not valid C4 0.4: %v", err)
	}
	msg, out, err := syslog.Render(e, tg)
	if err != nil || out.SummaryDropped || len(msg) > syslog.DefaultMaxOctets {
		t.Fatalf("%d octets (limit %d), %+v, %v", len(msg), syslog.DefaultMaxOctets, out, err)
	}
	t.Logf("worst 0.4 sensor.counters: %d octets of %d, %d details", len(msg), syslog.DefaultMaxOctets, len(e.Health.Details))

	// The control: the agent's counts (C13 0.2 CH-43), which C4 0.4 leaves
	// out of sensor.counters.
	e.Schema = "otsec.event/0.5"
	max := strconv.FormatUint(math.MaxUint64, 10)
	for _, n := range []string{"closes.handshake", "closes.node-hello", "closes.node-hello-timeout", "closes.binding", "closes.ack",
		"closes.type", "closes.idle", "closes.frame-too-large", "closes.superseded", "closes.run-complete", "closes.shutdown",
		"taken_ahead", "sync_late", "entries_unreadable"} {
		e.Health.Details["diff.agent."+n] = max
	}
	if n := len(e.Health.Details); n != 39 {
		t.Fatalf("%d details, want section 4's 39", n)
	}
	var se *syslog.Error
	if _, _, err := syslog.Render(e, tg); !errors.As(err, &se) || se.Code != syslog.CodeTooLarge {
		t.Fatalf("with the agent's counts: %v, want %s", err, syslog.CodeTooLarge)
	}
}

// E4-6's builder leg (P4-4-CC's table): the node's own worst-case
// sensor.counters, built by sensorlink.SensorCountersDetails from a rise of
// 2^64 - 1 in each of the 21 counters, so every capture-loss counter is
// named, with a 63-character node ID, is valid C4 0.4 and renders within
// the default target's 2,048 octets; and E5-6 (C4 0.5 as proposed in
// #753): the same with runs_folded at 2^64 - 1, stamped 0.5, which this
// build's C4 reads as a later minor's event, renders within it too. Control:
// the same event with the agent's 14 counts added, under a later minor so
// that C4 lets them pass, which Render refuses as too large; for E5-6,
// runs_folded left out (the octets logged for both). Desk only.
func TestSensorCountersWorstCaseFits(t *testing.T) {
	rises := map[string]uint64{}
	for _, n := range append(append([]string{}, event.SensorCounters...), event.SensorCounters04...) {
		rises[n] = math.MaxUint64
	}
	e := worstSensorCounters()
	e.Health.Details = sensorlink.SensorCountersDetails("ffffffff-ffff-4fff-bfff-ffffffffffff", "eeeeeeee-eeee-4eee-beee-eeeeeeeeeeee", rises)
	if n := len(e.Health.Details); n != 25 {
		t.Fatalf("%d details, want 25", n)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("the node's worst sensor.counters is not valid C4 0.4: %v", err)
	}
	tg := defaultTarget(t)
	msg, out, err := syslog.Render(e, tg)
	if err != nil || out.SummaryDropped || len(msg) > syslog.DefaultMaxOctets {
		t.Fatalf("%d octets (limit %d), %+v, %v", len(msg), syslog.DefaultMaxOctets, out, err)
	}
	t.Logf("the node's worst sensor.counters: %d octets of %d", len(msg), syslog.DefaultMaxOctets)
	max := strconv.FormatUint(math.MaxUint64, 10)
	e.Schema = "otsec.event/0.5"
	e.Health.Details[sensorlink.DetailRunsFolded] = max
	if err := e.Validate(); err != nil {
		t.Fatalf("E5-6: the worst folded sensor.counters is not valid: %v", err)
	}
	folded, out, err := syslog.Render(e, tg)
	if err != nil || out.SummaryDropped || len(folded) > syslog.DefaultMaxOctets || len(folded) <= len(msg) {
		t.Fatalf("E5-6: %d octets (limit %d, %d without runs_folded), %+v, %v", len(folded), syslog.DefaultMaxOctets, len(msg), out, err)
	}
	t.Logf("E5-6, runs_folded at its maximum: %d octets of %d", len(folded), syslog.DefaultMaxOctets)
	e.Schema = "otsec.event/0.99" // a minor that leaves the agent's counts unchecked
	for _, n := range []string{"closes.handshake", "closes.node-hello", "closes.node-hello-timeout", "closes.binding", "closes.ack",
		"closes.type", "closes.idle", "closes.frame-too-large", "closes.superseded", "closes.run-complete", "closes.shutdown",
		"taken_ahead", "sync_late", "entries_unreadable"} {
		e.Health.Details["diff.agent."+n] = max
	}
	var se *syslog.Error
	if _, _, err := syslog.Render(e, tg); !errors.As(err, &se) || se.Code != syslog.CodeTooLarge {
		t.Fatalf("control with the agent's counts: %v, want %s", err, syslog.CodeTooLarge)
	}
}
