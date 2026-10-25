package node

import (
	"testing"

	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// pruneNode is a node with a required target and an adapter-evidence
// quota of QuarantineRoom and room; 1024 is less than one run's SER events.
func pruneNode(t *testing.T, room int64) (*Runtime, *Status, *Config, *Scheduler) {
	t.Helper()
	nc, _, dir := forwardConfig(t, 9, func(nc *nodeconfigtest.Config) { // the forwarder is never run
		nc.Store.Quotas["adapter-evidence"] = QuarantineRoom + room
	})
	if err := nc.WriteInstallKey(testInstallKey); err != nil {
		t.Fatal(err)
	}
	lockTLS(t, nc)
	c := parse(t, nc)
	r, st, _ := start(t, c, dir)
	t.Cleanup(func() { r.Close() })
	var seq uint64
	return r, st, c, newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
}

// confirm persists the required target's cursor on the SER stream through
// seq, as the forwarder does after the target confirms.
func confirm(t *testing.T, r *Runtime, c *Config, seq c5.Seq) {
	t.Helper()
	cs, err := c.Consumers()
	if err != nil {
		t.Fatal(err)
	}
	stream := SERStream(relayID)
	for _, cn := range cs {
		if cn.Stream == stream && cn.Delivery == c5.Required {
			if err := r.Store(stream).SaveCursor(bg, c5.Cursor{Consumer: cn.ID, Stream: stream, Through: seq}); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("no required consumer of the SER stream")
}

// A6, V-S9: runs stop at the quota while the SER events are not confirmed,
// and start again once they are, without a restart or an operator: the
// node prunes the confirmed events, and nothing past the cursor.
func TestRunsResumeOnceConfirmed(t *testing.T) {
	r, st, c, s := pruneNode(t, 1024)
	stream := SERStream(relayID)
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" || rep.Events == 0 {
		t.Fatalf("first run: %+v", rep)
	}
	last, _ := r.Store(stream).LastCommitted(bg, stream)
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmNoQuarantineRoom || rep.Sent {
		t.Fatalf("unconfirmed: %+v", rep)
	}
	if got, _ := r.Store(stream).FirstRetained(bg, stream); got != 1 {
		t.Fatalf("unconfirmed events pruned: first retained %d", got)
	}
	// Half confirmed: only that half may go, and it is not enough.
	confirm(t, r, c, last/2)
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmNoQuarantineRoom {
		t.Fatalf("half confirmed: %+v", rep)
	}
	if got, _ := r.Store(stream).FirstRetained(bg, stream); got != last/2+1 {
		t.Fatalf("half confirmed: first retained %d, want %d", got, last/2+1)
	}
	confirm(t, r, c, last)
	if rep := s.RunOnce(bg, 0); !rep.Sent || rep.Alarm == AlarmNoQuarantineRoom {
		t.Fatalf("all confirmed: %+v", rep)
	}
	if n := countAlarms(st, AlarmNoQuarantineRoom); n != 1 {
		t.Fatalf("%d no-quarantine-room alarms, want 1", n)
	}
	// Below the warning band again, the warning is re-armed.
	s.mu.Lock()
	armed := !s.quiet["quarantine room low"]
	s.mu.Unlock()
	if !armed || countAlarms(st, AlarmQuarantineRoomLow) != 1 {
		t.Fatalf("after the prune: warning re-armed %v, %d raised", armed, countAlarms(st, AlarmQuarantineRoomLow))
	}
}

// Tick prunes a class above its runtime target too, so the room is there
// before the next run asks for it.
func TestTickPrunesConfirmed(t *testing.T) {
	r, _, c, s := pruneNode(t, 1024)
	stream := SERStream(relayID)
	s.RunOnce(bg, 0)
	last, _ := r.Store(stream).LastCommitted(bg, stream)
	r.Tick(bg)
	if got, _ := r.Store(stream).FirstRetained(bg, stream); got != 1 {
		t.Fatalf("Tick pruned unconfirmed events: first retained %d", got)
	}
	confirm(t, r, c, last)
	// One event per step, so the prune takes several passes.
	r.find(EvidenceDB).policy.PruneStepEvents = 1
	r.Tick(bg)
	used, err := r.Store(stream).ClassBytes(bg, c5.ClassAdapterEvidence)
	if err != nil || used+QuarantineRoom > c.Store.Quotas["adapter-evidence"] {
		t.Fatalf("after Tick: adapter-evidence %d bytes, %v", used, err)
	}
}

// The warning comes before runs stop, whatever the quota: at WarnFraction
// of the quota less QuarantineRoom, raised once (A6, V-S9 point 3). Here
// the room holds one run's evidence and a tenth, so the first run lands in
// the warning band while runs still go.
func TestQuarantineRoomLowWarnsFirst(t *testing.T) {
	r, _, _, s := pruneNode(t, 1<<20)
	s.RunOnce(bg, 0)
	one, err := r.Store(HealthStream).ClassBytes(bg, c5.ClassAdapterEvidence)
	if err != nil || one == 0 {
		t.Fatalf("one run's evidence: %d, %v", one, err)
	}
	_, st, _, s := pruneNode(t, one+one/10)
	if rep := s.RunOnce(bg, 0); rep.Alarm != "" || countAlarms(st, AlarmQuarantineRoomLow) != 0 {
		t.Fatalf("first run: %+v, warned before any evidence", rep)
	}
	if rep := s.RunOnce(bg, 0); !rep.Sent || countAlarms(st, AlarmQuarantineRoomLow) != 1 || countAlarms(st, AlarmNoQuarantineRoom) != 0 {
		t.Fatalf("second run: %+v; the warning must come while runs still go", rep)
	}
	s.RunOnce(bg, 0)
	if n := countAlarms(st, AlarmQuarantineRoomLow); n != 1 {
		t.Fatalf("%d quarantine-room-low alarms, want 1", n)
	}
}
