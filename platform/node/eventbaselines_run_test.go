package node

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

var runT0 = time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)

// runRig is a node on a clock of its own, observing the relay, which sends
// Syslog to the listener, restarted on one directory as a test asks.
type runRig struct {
	t   *testing.T
	c   *Config
	dir string

	mu  sync.Mutex
	now time.Time

	r  *Runtime
	st *Status
	e  *eventRun
}

func newRunRig(t *testing.T, mod func(*nodeconfigtest.Config)) *runRig {
	t.Helper()
	c, dir := configNode(t, func(nc *nodeconfigtest.Config) {
		nc.AddEventBaseline(relayID).AddListener(feedListener, "syslog-udp", "127.0.0.1:5514").
			AddSyslogSender(relayID, "syslog", "syslog-udp", "127.0.0.2", 0)
		if mod != nil {
			mod(nc)
		}
	})
	g := &runRig{t: t, c: c, dir: dir, now: runT0}
	g.open()
	t.Cleanup(func() {
		if g.r != nil {
			g.r.Close()
		}
	})
	return g
}

func (g *runRig) clock() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.now
}

func (g *runRig) set(at time.Time) {
	g.mu.Lock()
	g.now = at
	g.mu.Unlock()
}

func (g *runRig) open() {
	g.t.Helper()
	st := NewStatus(filepath.Join(g.dir, "status.json"), func(string) {}, nil)
	r, err := Start(bg, g.c, RuntimeOptions{Status: st, Now: g.clock, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}, BusyTimeout: heldBusyTimeout})
	if err != nil {
		g.t.Fatal(err)
	}
	e, err := newEventRun(bg, r)
	if err != nil {
		g.t.Fatal(err)
	}
	g.r, g.st, g.e = r, st, e
}

// restart stops the node, cleanly (its stop checkpoints) or as a crash, and
// starts it again.
func (g *runRig) restart(clean bool) {
	g.t.Helper()
	if clean {
		g.e.stop(bg)
	}
	g.r.Close()
	g.r = nil
	g.open()
}

// syslog stores a Syslog message of the relay received at at, as the
// listener does.
func (g *runRig) syslog(text string, at time.Time) {
	g.t.Helper()
	msg := fmt.Sprintf("<134>1 %s relay app - - - %s", at.UTC().Format(time.RFC3339Nano), text)
	stream := ListenerStream(feedListener)
	ev, err := normalize.Syslog(normalize.SyslogInput{Node: g.r.cfg.NodeID, Stream: event.Stream(stream), Message: []byte(msg), Sender: "127.0.0.2",
		Auth: event.AuthNone, AssetID: relayID, EvidenceClass: asset.Simulated, Dialect: normalize.DialectRFC,
		Received: event.Received{UTC: at.UTC().Format("2006-01-02T15:04:05.000000Z"), ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}}})
	if err != nil {
		g.t.Fatal(err)
	}
	b, err := json.Marshal(&ev)
	if err != nil {
		g.t.Fatal(err)
	}
	if _, err := g.r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: g.r.layout.StreamClasses()[stream], Event: b}); err != nil {
		g.t.Fatal(err)
	}
}

// step moves the clock to at and steps the feeder.
func (g *runRig) step(at time.Time) {
	g.set(at)
	g.e.step(bg)
}

func (g *runRig) learner() []byte {
	g.t.Helper()
	lr, _ := g.e.life.half(relayID)
	if lr == nil {
		g.t.Fatal("no learner")
	}
	b, err := lr.Snapshot(0)
	if err != nil {
		g.t.Fatal(err)
	}
	return b
}

// checkpointSeqs lists the relay's stored checkpoints of half.
func (g *runRig) checkpointSeqs(half string) []c5.Seq {
	g.t.Helper()
	list, err := g.e.checkpoints(bg, relayID)
	if err != nil {
		g.t.Fatal(err)
	}
	var out []c5.Seq
	for _, sc := range list {
		if sc.half == half {
			out = append(out, sc.st.Key.Seq)
		}
	}
	return out
}

// learnerRun sends the relay's Syslog in rounds, one round a step, and
// calls between after each step; it returns the learner's snapshot. The
// messages are of three types, one every 50 s, so the hour the learner needs
// is not reached. No message may arrive behind the watermark: a restart
// that read a stream again from before its checkpoint would show as late.
func learnerRun(t *testing.T, between func(g *runRig, round int)) []byte {
	g := newRunRig(t, nil)
	at := runT0
	for round := range 12 {
		for i := range 3 {
			at = at.Add(50 * time.Second)
			g.syslog(fmt.Sprintf("door %d opened", i), at)
		}
		g.step(at.Add(FeedLateness + time.Second))
		between(g, round)
	}
	g.step(at.Add(FeedLateness + time.Hour/4))
	if late := g.e.feed.assets[relayID].Late; late != 0 {
		t.Fatalf("%d messages late", late)
	}
	return g.learner()
}

// A node restarted after every step, cleanly, learns what one that ran
// straight through learns, byte for byte: each restart resumes the learner
// from its checkpoint and the streams from its positions, and passes no
// message twice and none not at all. Evidence class: simulated.
func TestEventRunRestartAtEveryStep(t *testing.T) {
	straight := learnerRun(t, func(*runRig, int) {})
	restarted := learnerRun(t, func(g *runRig, _ int) { g.restart(true) })
	if !bytes.Equal(straight, restarted) {
		t.Fatal("the learner restarted at every step is not the one that ran straight through")
	}
}

// A crash at any point loses or repeats nothing: after a checkpoint and its
// cursor (the restart resumes from both), after a checkpoint whose cursor
// was not saved (it resumes from the checkpoint, the later), and with
// messages stored after the checkpoint (they are read again, once).
// Evidence class: simulated.
func TestEventRunCrashBeforeAndAfterTheCursor(t *testing.T) {
	straight := learnerRun(t, func(*runRig, int) {})
	crashed := learnerRun(t, func(g *runRig, round int) {
		switch round % 3 {
		case 0:
			// A checkpoint and its cursor, then the crash.
			g.e.checkpoint(bg, true)
		case 1:
			// A checkpoint, and the crash before its cursor.
			ra := g.e.assets[relayID]
			hs := g.e.halves(relayID)
			if err := g.e.write(bg, ra, CheckpointLearner, hs[CheckpointLearner], g.e.feed.positions(ra.fa)); err != nil {
				t.Fatal(err)
			}
		case 2:
			// A message after the last checkpoint, passed before the crash,
			// and one stored and not yet passed.
			lateMessages(g)
		}
		g.restart(false)
	})
	if bytes.Equal(straight, crashed) {
		t.Fatal("the crashed run took no more messages than the straight one; the probe did not run")
	}
	// The probe sent two more messages every third round: compare with a
	// straight run that has them.
	again := learnerRun(t, func(g *runRig, round int) {
		if round%3 == 2 {
			lateMessages(g)
		}
	})
	if !bytes.Equal(again, crashed) {
		t.Fatal("the run that crashed is not the one that did not")
	}
}

// lateMessages stores a message received just after the watermark and
// steps past it, so it is passed, then stores one that is not yet passed.
func lateMessages(g *runRig) {
	at := g.clock().Add(-FeedLateness + 500*time.Millisecond)
	g.syslog("door 0 opened", at)
	g.step(g.clock().Add(time.Second))
	g.syslog("door 1 opened", g.clock())
}

// A checkpoint is stored every CheckpointEvery while the learner changes,
// and each one supersedes the last, which is removed once the cursor is
// saved after it; the cursor, on a stream a target consumes, is the restart
// point. Evidence class: simulated.
func TestEventRunCheckpointsAndRemoves(t *testing.T) {
	g := newRunRig(t, func(nc *nodeconfigtest.Config) {
		nc.AddRELPTarget("central", "127.0.0.1", 6514, "test-ca", "test-client", "test/durable-ack", false)
	})
	stream := ListenerStream(feedListener)
	if !g.e.consumed[stream] {
		t.Fatalf("no %s consumer on %s", EventBaselineConsumer, stream)
	}
	at := runT0
	for round := range 4 {
		at = at.Add(CheckpointEvery)
		g.syslog("door 0 opened", at)
		g.step(at.Add(FeedLateness + time.Second))
		if got := g.checkpointSeqs(CheckpointLearner); len(got) != 1 {
			t.Fatalf("round %d: learner checkpoints %v, want only the newest", round, got)
		}
	}
	st := g.st.Snapshot("n").EventCheckpoints[relayID]
	if st.Written != 4 || st.Removed != 3 || st.Refused != 0 {
		t.Fatalf("checkpoint status %+v", st)
	}
	if hs := healthOf(t, g.r, HealthEventBaselineCheckpointsRemoved); len(hs) != 3 || hs[0].Details["series"] != c5.SeriesCheckpointLearner {
		t.Fatalf("removal health %+v; alarms %+v", hs, g.st.Snapshot("n").Alarms)
	}
	cs, err := g.r.Store(stream).LoadCursors(bg, stream)
	if err != nil {
		t.Fatal(err)
	}
	var through c5.Seq
	for _, c := range cs {
		if c.Consumer == EventBaselineConsumer {
			through = c.Through
		}
	}
	if through != 4 {
		t.Fatalf("%s at %d, want 4 (every message passed)", EventBaselineConsumer, through)
	}
}

// A learner whose checkpoint was made under other parameters starts again,
// with the alarm and config.checkpoint_not_restored (reason mismatch,
// version 1); one whose stored snapshot is changed is corrupt. Neither is a
// silent restart, and the chain still verifies. Evidence class: simulated.
func TestEventRunCheckpointNotRestored(t *testing.T) {
	g := newRunRig(t, nil)
	at := runT0
	for i := range 3 {
		at = at.Add(time.Minute)
		g.syslog(fmt.Sprintf("door %d opened", i), at)
	}
	g.step(at.Add(FeedLateness + time.Second))
	g.restart(true)
	seq := g.checkpointSeqs(CheckpointLearner)
	if len(seq) != 1 {
		t.Fatalf("checkpoints %v", seq)
	}
	if lr, _ := g.e.life.half(relayID); lr.Progress(at).Events != 3 {
		t.Fatalf("restored with %d events", lr.Progress(at).Events)
	}

	// Other parameters.
	g.e.stop(bg)
	g.r.Close()
	g.r = nil
	g.c.EventBaselines[0].Params.MinEvents = 11
	g.open()
	if lr, _ := g.e.life.half(relayID); lr.Progress(at).Events != 0 {
		t.Fatal("a learner restored under other parameters")
	}
	if !hasAlarm(g.st, relayID, AlarmEventBaselineNotRestored) {
		t.Fatal("no alarm")
	}
	nr := notRestored(t, g.r)
	if len(nr) != 1 || nr[0].ReasonCode != audit.ReasonCheckpointMismatch || nr[0].Config.CheckpointSeq != uint64(seq[0]) ||
		nr[0].Config.CheckpointHalf != CheckpointLearner || nr[0].Config.BaselineVersion != 1 || nr[0].Config.PreviousDigest != "" {
		t.Fatalf("records %+v", nr)
	}

	// A changed snapshot: corrupt.
	g.syslog("door 0 opened", at.Add(time.Minute))
	g.step(at.Add(FeedLateness + 2*time.Minute))
	g.e.stop(bg)
	newest := g.checkpointSeqs(CheckpointLearner)
	g.r.Close()
	g.r = nil
	changed := int64(0)
	paths, _ := filepath.Glob(filepath.Join(g.c.Store.Dir, "*.db"))
	for _, p := range paths {
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(p))
		if err != nil {
			t.Fatal(err)
		}
		res, err := db.Exec(`UPDATE captures SET bytes = bytes || x'00' WHERE sha256 IN (SELECT capture FROM events WHERE stream = ? AND seq = ?)`,
			string(ConfigStream(relayID)), int64(newest[len(newest)-1]))
		if err == nil {
			n, _ := res.RowsAffected()
			changed += n
		}
		db.Close()
	}
	if changed != 1 {
		t.Fatalf("changed %d captures", changed)
	}
	g.open()
	nr = notRestored(t, g.r)
	if len(nr) != 2 || nr[1].ReasonCode != audit.ReasonCheckpointCorrupt || nr[1].Config.CheckpointSeq != uint64(newest[len(newest)-1]) {
		t.Fatalf("records %+v", nr)
	}
	if lr, _ := g.e.life.half(relayID); lr.Progress(at).Events != 0 {
		t.Fatal("a learner restored from a changed snapshot")
	}
}

func notRestored(t *testing.T, r *Runtime) []*audit.Record {
	t.Helper()
	recordedOf(t, r) // VerifyConfig
	recs, _, err := chainRecords(bg, r.Store(AuditStream))
	if err != nil {
		t.Fatal(err)
	}
	var out []*audit.Record
	for _, ar := range recs {
		if ar.rec.Action == audit.ActionConfigCheckpointNotRestored {
			out = append(out, ar.rec)
		}
	}
	return out
}

// An active detector that alarmed after its checkpoint, and then crashed,
// raises the alarm again from the checkpoint when restored; the alarm is not
// stored a second time. Evidence class: simulated.
func TestEventRunRestoredDetectorStoresNoAlarmTwice(t *testing.T) {
	g := newRunRig(t, nil)
	at := runT0
	for i := range 12 {
		at = at.Add(400 * time.Second)
		g.syslog("door 0 opened", at)
		_ = i
	}
	g.step(at.Add(FeedLateness + time.Second))
	recs := recordedOf(t, g.r)
	if len(recs) != 1 {
		t.Fatalf("%d recordings", len(recs))
	}
	h := recs[0].Config.BaselineDigest
	appendAck(t, g.r, h)
	g.e.life.acknowledged(relayID, h, g.clock())
	g.step(g.clock().Add(time.Minute))
	if _, d := g.e.life.half(relayID); d == nil {
		t.Fatal("not active")
	}
	if got := g.checkpointSeqs(CheckpointDetector); len(got) != 1 {
		t.Fatalf("detector checkpoints %v, want one at activation", got)
	}
	// A new type, alarmed, then a crash before the next checkpoint.
	g.syslog("pump started", g.clock())
	g.step(g.clock().Add(FeedLateness + time.Second))
	if n := len(healthOf(t, g.r, baseline.HealthDeparture)); n != 1 {
		t.Fatalf("%d departure alarms", n)
	}
	g.restart(false)
	if _, d := g.e.life.half(relayID); d == nil {
		t.Fatal("not active after the restart")
	}
	g.step(g.clock().Add(time.Minute))
	if n := len(healthOf(t, g.r, baseline.HealthDeparture)); n != 1 {
		t.Fatalf("%d departure alarms after the restart, want the one stored before it", n)
	}
	if nr := notRestored(t, g.r); len(nr) != 0 {
		t.Fatalf("records %+v", nr)
	}
	if strings.Contains(fmt.Sprint(g.st.Snapshot("n").Alarms), AlarmEventBaselineNotRestored) {
		t.Fatal("not-restored alarm")
	}
}

// A snapshot above the bound is refused: the last checkpoint stays, the
// cursor does not pass what it covers, and the refusal is an alarm and a
// health event, once; the next checkpoint that fits is stored. Evidence
// class: simulated.
func TestEventRunRefusedCheckpointKeepsTheLast(t *testing.T) {
	g := newRunRig(t, func(nc *nodeconfigtest.Config) {
		nc.AddRELPTarget("central", "127.0.0.1", 6514, "test-ca", "test-client", "test/durable-ack", false)
	})
	at := runT0.Add(time.Minute)
	g.syslog("door 0 opened", at)
	g.step(at.Add(FeedLateness + time.Second))
	kept := g.checkpointSeqs(CheckpointLearner)
	if len(kept) != 1 {
		t.Fatalf("checkpoints %v", kept)
	}
	stream := ListenerStream(feedListener)
	cursor := func() c5.Seq {
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
	before := cursor()
	if before != 1 {
		t.Fatalf("%s at %d, want 1", EventBaselineConsumer, before)
	}

	g.e.room = 1
	for i := range 2 {
		at = at.Add(CheckpointEvery)
		g.syslog(fmt.Sprintf("door %d opened", i+1), at)
		g.step(at.Add(FeedLateness + time.Second))
	}
	if got := g.checkpointSeqs(CheckpointLearner); !slices.Equal(got, kept) {
		t.Fatalf("checkpoints %v, want %v kept", got, kept)
	}
	if st := g.st.Snapshot("n").EventCheckpoints[relayID]; st.Written != 1 || st.Refused != 2 {
		t.Fatalf("checkpoint status %+v", st)
	}
	if !hasAlarm(g.st, relayID, AlarmEventBaselineCheckpoint) {
		t.Fatal("no alarm")
	}
	if hs := healthOf(t, g.r, HealthEventBaselineCheckpointRefused); len(hs) != 1 || hs[0].Details["half"] != CheckpointLearner {
		t.Fatalf("refusal health %+v", hs)
	}
	if got := cursor(); got != before {
		t.Fatalf("%s moved from %d to %d past the last checkpoint", EventBaselineConsumer, before, got)
	}

	g.e.room = checkpointRoom
	at = at.Add(CheckpointEvery)
	g.step(at)
	got := g.checkpointSeqs(CheckpointLearner)
	if len(got) != 1 || got[0] == kept[0] {
		t.Fatalf("checkpoints %v after the bound was restored", got)
	}
	if c := cursor(); c <= before {
		t.Fatalf("%s at %d, want past %d", EventBaselineConsumer, c, before)
	}
}
