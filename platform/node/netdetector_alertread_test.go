package node

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// failAlertReads makes alertsAfter's next n reads of the alert stream fail,
// as a busy or faulty database would. It returns how many failed, and
// the count left to fail, which the test may set to 0.
func failAlertReads(t *testing.T, n int64) (failed, left *atomic.Int64) {
	t.Helper()
	failed, left = new(atomic.Int64), new(atomic.Int64)
	left.Store(n)
	t.Cleanup(func() { readAlertPage = (*store.DB).Read })
	readAlertPage = func(db *store.DB, ctx context.Context, stream c5.StreamID, after c5.Seq, max int) ([]c5.Stored, error) {
		if left.Add(-1) >= 0 {
			failed.Add(1)
			return nil, errors.New("test: the network database is busy")
		}
		return db.Read(ctx, stream, after, max)
	}
	return failed, left
}

// alertRestoreSetup stores two alerts and the detector's checkpoint past
// them, stops the node, and returns the checkpoints and alerts stored.
func alertRestoreSetup(t *testing.T) (*Config, string, []c5.Seq, int) {
	t.Helper()
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	ckpts, alerts := detectorCkpts(t, r), len(committedAlerts(t, r))
	r.Close()
	if len(ckpts) == 0 || alerts == 0 {
		t.Fatalf("checkpoints %v, %d alerts", ckpts, alerts)
	}
	return c, dir, ckpts, alerts
}

// D6's F4 on #766 (brief P4-NODE-ALERTSAFTER): a read of the alert stream
// that fails once during the restore fails the start, under
// network-detector-not-started, and the next tick restores from the same
// checkpoint: no network-detector-not-restored, the checkpoint kept, and
// no alert stored twice. Control: main's startDetector, which takes the
// failed read as a failed restore, raises not-restored, starts fresh and
// stores the committed alerts again.
func TestDetectorAlertReadFailsOnce(t *testing.T) {
	c, dir, ckpts, alerts := alertRestoreSetup(t)
	failed, _ := failAlertReads(t, 1)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	tick(t, r)
	d, n := detectorStatus(t, st), len(committedAlerts(t, r))
	if failed.Load() != 1 || !d.Restored || countAlarms(st, AlarmDetectorNotRestored) != 0 || countAlarms(st, AlarmDetectorNotStarted) != 1 ||
		n != alerts || d.Mismatches != 0 {
		t.Fatalf("%d reads failed, %d alerts stored (want %d), status %+v, %d not-restored, %d not-started", failed.Load(), n, alerts, d,
			countAlarms(st, AlarmDetectorNotRestored), countAlarms(st, AlarmDetectorNotStarted))
	}
	if got := detectorCkpts(t, r); len(got) == 0 || got[0] != ckpts[len(ckpts)-1] {
		t.Fatalf("checkpoints %v, want the restored %d kept", got, ckpts[len(ckpts)-1])
	}
}

// D6's F4 on #766: while the read of the alert stream keeps failing, the
// detector does not start and network-detector-not-started is raised once,
// whatever the ticks; no not-restored is raised and no alert is stored.
// When the read succeeds, the detector restores from the kept checkpoint
// and no alert is stored twice. Control: main's startDetector, as in
// TestDetectorAlertReadFailsOnce.
func TestDetectorAlertReadKeepsFailing(t *testing.T) {
	c, dir, ckpts, alerts := alertRestoreSetup(t)
	failed, left := failAlertReads(t, 1<<40)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	for range 3 {
		tick(t, r)
	}
	var down bool
	heldManager(r, func() { down = r.detector == nil })
	if failed.Load() < 4 || !down || countAlarms(st, AlarmDetectorNotStarted) != 1 || countAlarms(st, AlarmDetectorNotRestored) != 0 {
		t.Fatalf("%d reads failed, detector down %v, %d not-started, %d not-restored", failed.Load(), down,
			countAlarms(st, AlarmDetectorNotStarted), countAlarms(st, AlarmDetectorNotRestored))
	}
	if n := len(committedAlerts(t, r)); n != alerts {
		t.Fatalf("%d alerts stored while the read fails, want %d", n, alerts)
	}
	left.Store(0)
	tick(t, r)
	d := detectorStatus(t, st)
	if !d.Restored || countAlarms(st, AlarmDetectorNotRestored) != 0 || countAlarms(st, AlarmDetectorNotStarted) != 1 {
		t.Fatalf("after the read succeeds: status %+v, %d not-restored, %d not-started", d,
			countAlarms(st, AlarmDetectorNotRestored), countAlarms(st, AlarmDetectorNotStarted))
	}
	if got := detectorCkpts(t, r); len(got) == 0 || got[0] != ckpts[len(ckpts)-1] {
		t.Fatalf("checkpoints %v, want the restored %d kept", got, ckpts[len(ckpts)-1])
	}
	if n := len(committedAlerts(t, r)); n != alerts {
		t.Fatalf("%d alerts stored, want %d", n, alerts)
	}
}
