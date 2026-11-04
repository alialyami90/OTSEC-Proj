package node

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"otsec.local/otsec/contracts/audit"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// C6's probes on #405 (slice 1c). Evidence class: simulated.

func c6Exec(t *testing.T, g *runRig, q string, args ...any) int64 {
	t.Helper()
	var n int64
	paths, _ := filepath.Glob(filepath.Join(g.c.Store.Dir, "*.db"))
	for _, p := range paths {
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(p)+"?_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatal(err)
		}
		if res, err := db.Exec(q, args...); err == nil {
			k, _ := res.RowsAffected()
			n += k
		}
		db.Close()
	}
	return n
}

func c6Cursor(t *testing.T, g *runRig) c5.Seq {
	t.Helper()
	stream := ListenerStream(feedListener)
	cs, err := g.r.Store(stream).LoadCursors(bg, stream)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Consumer == EventBaselineConsumer {
			return c.Through
		}
	}
	return 0
}

func withTarget(nc *nodeconfigtest.Config) {
	nc.AddRELPTarget("central", "127.0.0.1", 6514, "test-ca", "test-client", "test/durable-ack", false)
}

// R17: a half that changed is checkpointed at most every CheckpointEvery.
func TestC6ProbeCheckpointAtMostEvery(t *testing.T) {
	g := newRunRig(t, withTarget)
	at := runT0.Add(time.Minute)
	g.syslog("door 0 opened", at)
	g.step(at.Add(FeedLateness + time.Second))
	for i := range 3 {
		at = at.Add(time.Minute)
		g.syslog(fmt.Sprintf("door %d opened", i+1), at)
		g.step(at.Add(FeedLateness + time.Second))
	}
	if st := g.st.Snapshot("n").EventCheckpoints[relayID]; st.Written != 1 {
		t.Fatalf("checkpoint status %+v: want one written within CheckpointEvery", st)
	}
}

// R8: a superseded checkpoint is not removed while the cursor after its
// successor is not saved; the cursor alarm is raised.
func TestC6ProbeNoRemovalWithoutTheCursor(t *testing.T) {
	g := newRunRig(t, withTarget)
	at := runT0.Add(time.Minute)
	g.syslog("door 0 opened", at)
	g.step(at.Add(FeedLateness + time.Second))
	if got := g.checkpointSeqs(CheckpointLearner); len(got) != 1 {
		t.Fatalf("checkpoints %v", got)
	}
	// The stored cursor is put ahead of where the node will save it, so its
	// save is refused as a regress.
	if n := c6Exec(t, g, `UPDATE cursors SET through = 1000 WHERE consumer = ? AND stream = ?`, string(EventBaselineConsumer), string(ListenerStream(feedListener))); n != 1 {
		t.Fatalf("changed %d cursors", n)
	}
	at = at.Add(CheckpointEvery)
	g.syslog("door 1 opened", at)
	g.step(at.Add(FeedLateness + time.Second))
	if got := g.checkpointSeqs(CheckpointLearner); len(got) != 2 {
		t.Fatalf("checkpoints %v: the superseded one was removed with the cursor not saved", got)
	}
	if !strings.Contains(fmt.Sprint(g.st.Snapshot("n").Alarms), AlarmEventBaselineCursor) {
		t.Fatalf("no cursor alarm: %+v", g.st.Snapshot("n").Alarms)
	}
}

// R10: superseded checkpoints found at a restart (a crash before the
// cursor) are removed once the restarted node saves the cursor.
func TestC6ProbeRestartRemovesSuperseded(t *testing.T) {
	g := newRunRig(t, withTarget)
	at := runT0.Add(time.Minute)
	g.syslog("door 0 opened", at)
	g.step(at.Add(FeedLateness + time.Second))
	at = at.Add(time.Minute)
	g.syslog("door 1 opened", at)
	g.set(at.Add(FeedLateness + time.Second))
	g.e.feed.Step(bg)
	ra := g.e.assets[relayID]
	hs := g.e.halves(relayID)
	if err := g.e.write(bg, ra, CheckpointLearner, hs[CheckpointLearner], g.e.feed.positions(ra.fa)); err != nil {
		t.Fatal(err)
	}
	g.restart(false)
	if got := g.checkpointSeqs(CheckpointLearner); len(got) != 2 {
		t.Fatalf("checkpoints %v before the restarted node's first pass", got)
	}
	g.step(g.clock().Add(time.Second))
	if got := g.checkpointSeqs(CheckpointLearner); len(got) != 1 {
		t.Fatalf("checkpoints %v: the superseded one stayed after the cursor was saved", got)
	}
}

// R19: a newest checkpoint record whose half does not read is not passed
// over for an older one: it is reported as corrupt.
func TestC6ProbeUnreadableNewestIsReported(t *testing.T) {
	g := newRunRig(t, withTarget)
	at := runT0.Add(time.Minute)
	g.syslog("door 0 opened", at)
	g.step(at.Add(FeedLateness + time.Second))
	at = at.Add(time.Minute)
	g.syslog("door 1 opened", at)
	g.set(at.Add(FeedLateness + time.Second))
	g.e.feed.Step(bg)
	ra := g.e.assets[relayID]
	hs := g.e.halves(relayID)
	if err := g.e.write(bg, ra, CheckpointLearner, hs[CheckpointLearner], g.e.feed.positions(ra.fa)); err != nil {
		t.Fatal(err)
	}
	seqs := g.checkpointSeqs(CheckpointLearner)
	if len(seqs) != 2 {
		t.Fatalf("checkpoints %v", seqs)
	}
	g.r.Close()
	g.r = nil
	if n := c6Exec(t, g, `UPDATE events SET event = replace(event, '"half":"learner"', '"half":"l3arner"') WHERE stream = ? AND seq = ?`,
		string(ConfigStream(relayID)), int64(seqs[1])); n != 1 {
		t.Fatalf("changed %d records", n)
	}
	g.open()
	nr := notRestored(t, g.r)
	if len(nr) != 1 || nr[0].ReasonCode != audit.ReasonCheckpointCorrupt || nr[0].Config.CheckpointSeq != uint64(seqs[1]) {
		t.Fatalf("records %+v: the unreadable newest was passed over", nr)
	}
}

// R25: a checkpoint in the asset's stream naming another asset is not
// restored.
func TestC6ProbeOtherAssetsCheckpoint(t *testing.T) {
	g := newRunRig(t, withTarget)
	at := runT0.Add(time.Minute)
	g.syslog("door 0 opened", at)
	g.step(at.Add(FeedLateness + time.Second))
	seqs := g.checkpointSeqs(CheckpointLearner)
	g.r.Close()
	g.r = nil
	other := strings.Replace(relayID, "2b7d", "2b7e", 1)
	if n := c6Exec(t, g, `UPDATE events SET event = replace(event, ?, ?) WHERE stream = ? AND seq = ?`,
		`"asset_id":"`+relayID+`"`, `"asset_id":"`+other+`"`, string(ConfigStream(relayID)), int64(seqs[0])); n != 1 {
		t.Fatalf("changed %d records", n)
	}
	g.open()
	nr := notRestored(t, g.r)
	if len(nr) != 1 || nr[0].ReasonCode != audit.ReasonCheckpointMismatch {
		t.Fatalf("records %+v: another asset's checkpoint was restored", nr)
	}
}

// R21: a stuck stream raises its alarm and its health record once.
func TestC6ProbeStuckStreamOnce(t *testing.T) {
	g := newRunRig(t, withTarget)
	at := runT0.Add(time.Minute)
	g.syslog("door 0 opened", at)
	if n := c6Exec(t, g, `UPDATE events SET event = 'not json' WHERE stream = ? AND seq = 1`, string(ListenerStream(feedListener))); n != 1 {
		t.Fatalf("changed %d records", n)
	}
	for i := range 3 {
		g.step(at.Add(FeedLateness + time.Duration(i+1)*time.Minute))
	}
	if hs := healthOf(t, g.r, HealthEventBaselineStreamStuck); len(hs) != 1 {
		t.Fatalf("%d stream-stuck health records, want 1", len(hs))
	}
	if !strings.Contains(fmt.Sprint(g.st.Snapshot("n").Alarms), AlarmEventBaselineStreamStuck) {
		t.Fatal("no stuck alarm")
	}
	if c := c6Cursor(t, g); c != 0 {
		t.Fatalf("cursor at %d past the stuck record", c)
	}
}

// R6: a stream two assets read keeps its cursor at the lower of their
// restart points.
func TestC6ProbeCursorIsTheLowerOfTwoAssets(t *testing.T) {
	const second = "3c8e5f21-9d40-4b6c-8f32-8d5e1e7b9c24"
	g := newRunRig(t, func(nc *nodeconfigtest.Config) {
		withTarget(nc)
		nc.AddSEL751(second, "", 2324, 300)
		nc.AddEventBaseline(second).AddSyslogSender(second, "syslog-2", "syslog-udp", "127.0.0.3", 0)
	})
	at := runT0.Add(time.Minute)
	for i := range 4 {
		g.syslog(fmt.Sprintf("door %d opened", i), at.Add(time.Duration(i)*time.Second))
	}
	g.step(at.Add(FeedLateness + time.Minute))
	s := ListenerStream(feedListener)
	saved := g.e.saved[s]
	if saved == 0 || saved != c6Cursor(t, g) {
		t.Fatalf("saved %d, stored %d", saved, c6Cursor(t, g))
	}
	// Four more records are committed; the assets' restart points in them
	// differ.
	for i := range 4 {
		g.syslog(fmt.Sprintf("door %d closed", i), at.Add(time.Hour+time.Duration(i)*time.Second))
	}
	g.e.assets[relayID].durable[s] = saved + 4
	g.e.assets[second].durable[s] = saved + 1
	if !g.e.saveCursors(bg) {
		t.Fatal("cursor not saved")
	}
	if c := c6Cursor(t, g); c != saved+1 {
		t.Fatalf("cursor at %d, want %d, the lagging asset's restart point", c, saved+1)
	}
}

// A checkpoint read that does not complete restores nothing and feeds no
// asset; the alarm says why (C1 on #387).
func TestC6ProbeUnreadCheckpointsFeedNothing(t *testing.T) {
	g := newRunRig(t, withTarget)
	at := runT0.Add(time.Minute)
	g.syslog("door 0 opened", at)
	g.step(at.Add(FeedLateness + time.Second))
	g.e.stop(bg)
	g.r.Close()
	g.r = nil
	st := NewStatus(filepath.Join(g.dir, "status.json"), func(string) {}, nil)
	r, err := Start(bg, g.c, RuntimeOptions{Status: st, Now: g.clock, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}, BusyTimeout: heldBusyTimeout})
	if err != nil {
		t.Fatal(err)
	}
	g.r, g.st = r, st
	g.syslog("door 1 opened", at.Add(time.Minute))
	r.Store(ConfigStream(relayID)).Close()
	e, err := newEventRun(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	g.e = e
	g.step(at.Add(FeedLateness + 2*time.Minute))
	if e.ready {
		t.Fatal("restored with the checkpoints unread")
	}
	if !strings.Contains(fmt.Sprint(st.Snapshot("n").Alarms), AlarmEventBaselineNotStarted) {
		t.Fatalf("no not-started alarm: %+v", st.Snapshot("n").Alarms)
	}
	if n := e.read(); n != 0 {
		t.Fatalf("the feeder read %d records with the checkpoints unread", n)
	}
}
