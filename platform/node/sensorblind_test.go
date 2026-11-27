package node

import (
	"slices"
	"testing"
	"time"

	"otsec.local/otsec/platform/sensorlink"
)

// K-4's node half, the timer's part (P4-4-INT-D5-BLIND; C13 CH-44): the
// sensor-unreachable timer is reset by the link's accepted frames, which
// on the 0.2 link include a tick that is not early and a record taken
// (sensorlink.TestBlindAcceptedFrames shows what counts), and by nothing
// else: a tick with Stats unchanged keeps the alarm's stretch. Control:
// reset by a heartbeat only. Desk only.
func TestSensorUnreachableAcceptedFrames(t *testing.T) {
	run := func() *sensorIntake {
		in := &sensorIntake{raised: true, unreachable: true}
		in.heard(sensorlink.Stats{}) // nothing accepted: the stretch stands
		if !in.raised || !in.unreachable {
			t.Fatal("unchanged counts reset the timer")
		}
		in.heard(sensorlink.Stats{Accepted: 1, AcceptedMono: 70 * time.Second}) // an accepted tick
		return in
	}
	if in := run(); in.raised || in.unreachable || in.quietFrom != 70*time.Second {
		t.Fatalf("after an accepted tick: raised %v, unreachable %v, quiet from %s; want reset at 70s", in.raised, in.unreachable, in.quietFrom)
	}
	t.Run("control: a heartbeat only", func(t *testing.T) {
		unreachableHeartbeatsOnly = true
		t.Cleanup(func() { unreachableHeartbeatsOnly = false })
		if in := run(); !in.raised {
			t.Fatal("the control reset the timer at an accepted tick")
		}
	})
}

// Status's coverage and blind interfaces (CH-31, CH-44): "unknown" while
// coverage unknown stands, empty otherwise, and the stretch's names.
func TestSensorCoverageStatus(t *testing.T) {
	c, b := sensorCoverage(sensorlink.BlindStatus{Blind: []string{"eth2"}, CoverageUnknown: true})
	if c != "unknown" || !slices.Equal(b, []string{"eth2"}) {
		t.Fatalf("coverage %q, blind %v", c, b)
	}
	if c, b := sensorCoverage(sensorlink.BlindStatus{}); c != "" || b != nil {
		t.Fatalf("coverage %q, blind %v; want none", c, b)
	}
}
