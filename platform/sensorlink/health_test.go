package sensorlink

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

// Desk tests of the sensor's health events on the node (health.go,
// runfile.go, pool.go), on the test clocks, with the health stream an
// in-memory sink. No sensor produced the records and no device was
// contacted.

// sinkEvent is one health event written.
type sinkEvent struct {
	typ string
	d   map[string]string
}

// memSink is the node's health stream; it outlives a restart. fail makes
// writes of the named types fail.
type memSink struct {
	mu     sync.Mutex
	events []sinkEvent
	fail   map[string]error
	// refuse, when set, refuses the events it names, as the ceiling does.
	refuse func(typ string, d map[string]string) bool
}

func (s *memSink) WriteHealth(_ context.Context, typ string, d map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail[typ]; err != nil {
		return err
	}
	if s.refuse != nil && s.refuse(typ, d) {
		return errDown
	}
	s.events = append(s.events, sinkEvent{typ, maps.Clone(d)})
	return nil
}

func (s *memSink) failing(err error, types ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = map[string]error{}
	for _, t := range types {
		s.fail[t] = err
	}
}

func (s *memSink) of(typ string) []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]string
	for _, e := range s.events {
		if e.typ == typ {
			out = append(out, e.d)
		}
	}
	return out
}

func (s *memSink) count(typ string) int { return len(s.of(typ)) }

// sum adds detail k over the events of typ.
func (s *memSink) sum(typ, k string) (n uint64) {
	for _, d := range s.of(typ) {
		v, _ := strconv.ParseUint(d[k], 10, 64)
		n += v
	}
	return n
}

var errDown = errors.New("test: the health stream is down")

// healthRig is a rig whose link has a Health over sensorrun.json in a
// temporary directory and the in-memory health stream.
type healthRig struct {
	*rig
	path string
	sink *memSink
	file *RunFile
	h    *Health
	gen  *linkGen
}

// newHealthRig makes the rig for a sensor that has just been enrolled: no
// start is applied yet, since enrolment's first cursor is P4-4-DE's.
func newHealthRig(t *testing.T) *healthRig {
	r := &healthRig{rig: newRig(t, nil), path: filepath.Join(t.TempDir(), "sensorrun.json"), sink: &memSink{}}
	r.restartNoStart()
	return r
}

func (r *healthRig) restartNoStart() {
	r.file = OpenRunFile(r.path)
	// Each link's own view of the stores and the stream, so a kill can end
	// an old link's writes while its connection is still open (gapstart_test.go).
	gen := &linkGen{}
	r.gen = gen
	r.rig.opt = func(o *Options) {
		r.h = NewHealth(HealthConfig{SensorID: testSensor, Sink: genSink{gen, r.sink}, Monotonic: r.clk.mono, Now: r.now, Raise: o.Raise, File: r.file})
		o.Health, o.Owed, o.Cursor = r.h, nil, genCursor{gen, o.Cursor}
	}
	r.rig.restart()
}

// linkGen is one link's life: once dead, its stores and stream refuse it.
type linkGen struct {
	dead atomic.Bool
	// beforeSave, when set, runs before each cursor save that is let
	// through.
	beforeSave func()
}

var errKilled = errors.New("test: the link was killed")

type genCursor struct {
	g  *linkGen
	cs CursorStore
}

func (c genCursor) SourceCursor(ctx context.Context) ([]byte, error) {
	if c.g.dead.Load() {
		return nil, errKilled
	}
	return c.cs.SourceCursor(ctx)
}

func (c genCursor) SaveSourceCursor(ctx context.Context, b []byte) error {
	if c.g.dead.Load() {
		return errKilled
	}
	if c.g.beforeSave != nil {
		c.g.beforeSave()
	}
	return c.cs.SaveSourceCursor(ctx, b)
}

type genSink struct {
	g *linkGen
	s HealthSink
}

func (s genSink) WriteHealth(ctx context.Context, typ string, d map[string]string) error {
	if s.g.dead.Load() {
		return errKilled
	}
	return s.s.WriteHealth(ctx, typ, d)
}

// restart is a node restart: a new link and Health over the same stores
// and file, the file applied at the start and the owed events written.
func (r *healthRig) restart() {
	r.t.Helper()
	r.restartNoStart()
	if err := r.file.Start(bg, r.l); err != nil {
		r.t.Fatalf("start: %v", err)
	}
	if err := r.l.WriteOwed(bg); err != nil && !errors.Is(err, ErrHealthHeld) {
		r.t.Fatalf("owed at start: %v", err)
	}
}

// loseDatabase replaces the sensor database with a new, empty one.
func (r *healthRig) loseDatabase() {
	r.s = openNet(r.t, 64<<20)
	r.cs = &cursorStore{s: r.s}
}

// hb is a 0.2 heartbeat of testRun with packets rising with seq, changed
// by f.
func hb(seq int, f func(*netobs.Heartbeat)) *netobs.Heartbeat {
	h := heartbeat02(seq, uint64(100*seq))
	if f != nil {
		f(h)
	}
	return h
}

func outgoing(n uint64) func(*netobs.Heartbeat) {
	return func(h *netobs.Heartbeat) { h.Counters.FramesOutgoing = ptr(n) }
}

func capture(driver, holder, overlong uint64) func(*netobs.Heartbeat) {
	return func(h *netobs.Heartbeat) {
		h.Counters.DropsDriver, h.Counters.DropsHolder, h.Counters.FramesOverlong = ptr(driver), ptr(holder), ptr(overlong)
	}
}

func noEgress(h *netobs.Heartbeat) { h.EgressCheck = "" }

// beat sends heartbeats a second apart, so the position is saved and
// acked at each (CH-17), and waits for the last one's ack.
func (r *healthRig) beat(p *peer, hs ...*netobs.Heartbeat) {
	r.t.Helper()
	for _, h := range hs {
		p.taken() // the clock moves only once the frame before is acted on
		r.clk.add(cursorSpacing)
		p.send(h)
	}
	p.ack(num(hs[len(hs)-1].Seq))
}

// settleFile lets the run file's minute pass on both of the node's clocks
// (so the step check finds no step) and flushes, as the manager's tick
// does.
func (r *healthRig) settleFile() {
	r.t.Helper()
	r.pass(time.Minute)
	if err := r.h.Flush(bg); err != nil {
		r.t.Fatal(err)
	}
}

// W-8 (a) and the kill leg (section 1.8; D5's B1 on #634). Heartbeats
// with frames_outgoing 0 taken, the node restarted, then one with 1:
// sensor-transmitted is raised. With no alarm standing, the node killed
// after sensorrun.json takes the raise and before the cursor save that
// carries the baseline: after the start the alarm stands, and the resumed
// heartbeat with 1 raises it again. Controls: a node that compares within
// a connection only, which holds no baseline across the restart and stays
// silent (mutant M10, the durable frames_outgoing baseline off, run
// against this test); and a node that saves the baseline before the file,
// killed between, which raises nothing after the start (run here).
func TestTransmittedAfterNodeRestart(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(hello02())
	r.beat(p, hb(1, outgoing(0)), hb(2, outgoing(0)))
	p.end()
	r.restart()
	p = r.dial(enrolment())
	p.send(resume(3, 20))
	p.ack(2)
	r.beat(p, hb(3, outgoing(1)))
	if r.al.count(AlarmTransmitted) != 1 {
		t.Fatalf("raises %v", r.al.list)
	}
	// No rise against the durable baseline raises nothing new: after the
	// next start the alarm stands once, and a heartbeat still at 1 adds
	// no raise.
	p.end()
	r.restart()
	p = r.dial(enrolment())
	p.send(resume(4, 20))
	p.ack(3)
	r.beat(p, hb(4, outgoing(1)))
	if r.al.count(AlarmTransmitted) != 1 {
		t.Fatalf("no rise: raises %v", r.al.list)
	}

	kill := func(baselineFirst bool) (atStart, afterResend int) {
		r := newHealthRig(t)
		p := r.accepted(hello02())
		r.beat(p, hb(1, outgoing(0)))
		transmitBaselineFirst = baselineFirst
		t.Cleanup(func() { transmitBaselineFirst, runFileFault = false, nil })
		if baselineFirst {
			runFileFault = func() error { return errors.New("test: killed before the file's rename") }
		} else {
			r.cs.failNext(2) // the write number's save, then the baseline's: killed before it
		}
		r.clk.add(cursorSpacing)
		p.send(hb(2, outgoing(1)))
		if baselineFirst {
			p.taken()
			p.end() // killed after the baseline's save
		} else {
			p.closed() // store: the baseline's save failed
		}
		transmitBaselineFirst, runFileFault = false, nil
		r.restart()
		atStart = r.al.count(AlarmTransmitted)
		p = r.dial(enrolment())
		p.send(resume(2, 20))
		p.ack(1)
		r.beat(p, hb(2, outgoing(1)))
		return atStart, r.al.count(AlarmTransmitted)
	}
	if atStart, after := kill(false); atStart != 1 || after != 2 {
		t.Fatalf("killed between the file and the cursor: %d raises at the start, %d after the resend; want 1 and 2", atStart, after)
	}
	if atStart, after := kill(true); atStart != 0 || after != 0 {
		t.Fatalf("control, the baseline saved first: %d and %d raises; the test cannot tell", atStart, after)
	}
}

// W-8 (b): a run's first heartbeat, carrying frames_outgoing 1, evicted
// and declared; the first heartbeat the node takes also carries 1: the
// alarm is raised, with no baseline held. Control: mutant M13, a rise
// raised only against a value held (a node that compares within a
// connection), which stays silent.
func TestTransmittedFirstHeartbeatEvicted(t *testing.T) {
	r := newHealthRig(t)
	h := hello02()
	h.FirstSeq, h.DropsChannel = "2", "1"
	p := r.accepted(h)
	r.beat(p, hb(2, outgoing(1)))
	if r.al.count(AlarmTransmitted) != 1 {
		t.Fatalf("raises %v", r.al.list)
	}
}

// W-8 (c) and (e): egress_check carried, the node restarted, then left
// out: sensor-egress-absent is raised. (e): the sensor database lost, and
// a heartbeat of the run the sensor resends from its oldest record that
// omits the field: raised (SL-T24 (h)'s node leg; the re-arm is P4-4-DE's).
// Controls: mutant M14, the egress mark not kept in the cursor (a node
// that compares within a connection), and mutant M15, an omitted field
// read as never carried while no baseline is held; each stays silent.
func TestEgressDroppedAfterNodeRestart(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(hello02())
	r.beat(p, hb(1, nil))
	p.end()
	if c := cursorNow(t, r.cs); c.Egress != EgressCarried {
		t.Fatalf("egress mark %q", c.Egress)
	}
	r.restart()
	p = r.dial(enrolment())
	p.send(resume(2, 20))
	p.ack(1)
	r.beat(p, hb(2, noEgress))
	if r.al.count(AlarmEgressAbsent) != 1 {
		t.Fatalf("(c): raises %v", r.al.list)
	}

	r = newHealthRig(t)
	p = r.accepted(hello02())
	r.beat(p, hb(1, nil))
	p.end()
	r.loseDatabase()
	r.restart()
	h := hello02()
	h.FirstSeq = "5" // the agent's oldest record held
	p = r.accepted(h)
	r.beat(p, hb(5, noEgress))
	if r.al.count(AlarmEgressAbsent) != 1 {
		t.Fatalf("(e): raises %v", r.al.list)
	}
}

// W-8 (d) (SL-26 section 11.3's quiet case, CH-27's exception): a run whose
// every heartbeat omits egress_check, taken from its start: no
// sensor-egress-absent, and the mark says not carried, which status shows
// as unknown. The same run with its first heartbeat evicted and declared:
// raised once, not at each heartbeat (D6's M-O). Controls: mutant M8,
// fromStart ignored (a node that raises whenever it holds no baseline),
// which alarms in the first case; M-O, raised at every heartbeat.
func TestEgressNeverCarriedNoAlarm(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(hello02())
	r.beat(p, hb(1, noEgress), hb(2, noEgress))
	if n := r.al.count(AlarmEgressAbsent); n != 0 {
		t.Fatalf("from the start: raises %v", r.al.list)
	}
	if c := cursorNow(t, r.cs); c.Egress != EgressOmitted {
		t.Fatalf("egress mark %q", c.Egress)
	}
	r = newHealthRig(t)
	h := hello02()
	h.FirstSeq, h.DropsChannel = "2", "1"
	p = r.accepted(h)
	r.beat(p, hb(2, noEgress), hb(3, noEgress))
	if r.al.count(AlarmEgressAbsent) != 1 {
		t.Fatalf("first heartbeat evicted: raises %v", r.al.list)
	}
}

// capLoss is the drops_driver differences written, in order.
func capLoss(s *memSink) []string {
	var out []string
	for _, d := range s.of(EventCounters) {
		if v := d["diff.drops_driver"]; v != "" {
			out = append(out, v+" "+d[event.DetailCaptureLoss])
		}
	}
	return out
}

// W-8 (f) and (g), D1's one rule for the three capture-loss counters, and
// the run's boundary (D1's ruling 6850475569 on #655), each case on its own
// node. The controls are the earlier designs' rules, each run as a named
// mutant against this test (M6, M16, M17, M18; #747's comment).
func TestCaptureLossAcrossRestart(t *testing.T) {
	// (g): 7 taken with no baseline held, the file's minute passed, a
	// restart, then 11: diff 4 for each counter, all three named; the first
	// heartbeat's diff 7, the run total. A run of zeros: no capture_loss.
	// Control: M16, a node with no durable capture baseline, which reports
	// 11 after the restart.
	r := newHealthRig(t)
	p := r.accepted(hello02())
	r.beat(p, hb(1, capture(7, 7, 7)))
	r.settleFile()
	p.end()
	if d := r.sink.of(EventCounters); len(d) != 1 || d[0]["diff.drops_driver"] != "7" || d[0][event.DetailCaptureLoss] != "drops_driver drops_holder frames_overlong" {
		t.Fatalf("no baseline, 7: %v", d)
	}
	r.restart()
	p = r.dial(enrolment())
	p.send(resume(2, 20))
	p.ack(1)
	r.beat(p, hb(2, capture(11, 11, 11)))
	d := r.sink.of(EventCounters)
	if len(d) != 2 || d[1]["diff.drops_driver"] != "4" || d[1]["diff.drops_holder"] != "4" || d[1]["diff.frames_overlong"] != "4" {
		t.Fatalf("after the restart: %v", d)
	}
	z := newHealthRig(t)
	p = z.accepted(hello02())
	z.beat(p, hb(1, capture(0, 0, 0)))
	if d := z.sink.of(EventCounters); len(d) != 1 || d[0][event.DetailCaptureLoss] != "" || d[0]["diff.drops_driver"] != "" {
		t.Fatalf("zeros: %v", d)
	}

	// base has drops_driver 5 committed and in the last file write.
	base := func() (*healthRig, *peer) {
		r := newHealthRig(t)
		p := r.accepted(hello02())
		r.beat(p, hb(1, capture(5, 0, 0)))
		r.settleFile()
		return r, p
	}
	// (i): 9 taken, the run's records after it committed, the node killed
	// before the next file write: the start counts 4, at the start's time.
	// Control: M17, the cursor's capture counters advanced only with the
	// file, under which the cursor holds 5 and the start counts nothing.
	r, p = base()
	r.beat(p, hb(2, capture(9, 0, 0)))
	p.send(obs02(3))
	p.ack(3)
	p.end()
	if c := cursorNow(t, r.cs); *c.DropsDriver != 9 {
		t.Fatalf("(i): the cursor holds %d", *c.DropsDriver)
	}
	r.restart()
	if got := capLoss(r.sink); !slices.Equal(got, []string{"5 drops_driver", "4 drops_driver"}) {
		t.Fatalf("(i): %v", got)
	}
	// (ii): the same heartbeat, then the next run's hello accepted and row
	// 6's save made, the node killed after it: the file written before the
	// save holds the 4, written after the start. Control: row 6's save
	// before the file write, killed between, under which the cursor holds
	// run 6 and the file 5: nothing.
	r, p = base()
	r.beat(p, hb(2, capture(9, 0, 0)))
	p.end()
	p = r.accepted(run6())
	p.end()
	r.restart()
	if got := capLoss(r.sink); !slices.Equal(got, []string{"5 drops_driver", "4 drops_driver"}) {
		t.Fatalf("(ii): %v", got)
	}
	// (iii): killed after a file write that holds the 4 with the totals 9
	// and before the cursor save that follows it: 4, once, and the resent
	// 9 counts nothing. Control: the start leaving the cursor's 5, so that
	// the resend counts the 4 again.
	r, p = base()
	r.pass(time.Minute)
	r.cs.failNext(2) // the write number's save, then the baselines': killed before it
	r.pass(cursorSpacing)
	p.send(hb(2, capture(9, 0, 0)))
	p.closed()
	r.restart()
	if c := cursorNow(t, r.cs); *c.DropsDriver != 9 {
		t.Fatalf("(iii): the start left the cursor at %d (control's case)", *c.DropsDriver)
	}
	p = r.dial(enrolment())
	p.send(resume(2, 20))
	p.ack(1)
	r.beat(p, hb(2, capture(9, 0, 0)))
	r.pass(CountersSpacing)
	if err := r.h.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if got := capLoss(r.sink); !slices.Equal(got, []string{"5 drops_driver", "4 drops_driver"}) {
		t.Fatalf("(iii): %v", got)
	}
	// (iv): killed after a sensor.counters carrying the 4 commits and
	// before the file write that removes its counts: the 4 written again,
	// twice and never not at all. Control: the file written without the
	// counts before the event commits, killed between: none.
	r, p = base()
	r.pass(CountersSpacing)
	runFileFault = func() error { return errors.New("test: killed before the file's rename") }
	t.Cleanup(func() { runFileFault = nil })
	r.beat(p, hb(2, capture(9, 0, 0)))
	runFileFault = nil
	p.end()
	r.restart()
	if got := capLoss(r.sink); !slices.Equal(got, []string{"5 drops_driver", "4 drops_driver", "4 drops_driver"}) {
		t.Fatalf("(iv): %v", got)
	}
	// (v): a file write holding the 4 with the totals 9, then a rise to 12
	// saved in the cursor and a write holding 7 with the totals 12 whose
	// rename a power cut loses, no sensor.counters committed: at the start
	// the behind file's 4 and the 3 above its totals, 7 in all. Control: a
	// node that names a behind file's held loss as possibly lost and
	// writes nothing, which reports 3.
	r, p = base()
	r.sink.failing(errDown, EventCounters)
	r.pass(time.Minute)
	r.beat(p, hb(2, capture(9, 0, 0)))
	older, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	r.pass(time.Minute)
	r.beat(p, hb(3, capture(12, 0, 0)))
	p.end()
	if err := os.WriteFile(r.path, older, 0o600); err != nil {
		t.Fatal(err)
	}
	r.sink.failing(nil)
	r.restart()
	if got := capLoss(r.sink); !slices.Equal(got, []string{"5 drops_driver", "7 drops_driver"}) || r.h.Status().RunFile != "behind" {
		t.Fatalf("(v): %v, status %+v", got, r.h.Status())
	}
	// (vi): a loss committed while the pool has room, the file write after
	// it made, a clean stop and a start: nothing at the start. Control:
	// M18, the totals recorded only beside a held loss, under which the
	// file holds none and the start counts the 5 again.
	r, p = base()
	p.end()
	r.restart()
	if got := capLoss(r.sink); !slices.Equal(got, []string{"5 drops_driver"}) {
		t.Fatalf("(vi): %v", got)
	}
	// The sustained loss: drops_driver rising at every heartbeat, one each
	// 10 s for ten minutes: the file written at most once a minute, and
	// the differences written sum to exactly the run's rise. Control: a
	// file write at every rise, 60 in the ten minutes.
	r, p = base()
	r.file.mu.Lock()
	w0 := r.file.doc.WriteNo
	r.file.mu.Unlock()
	for i := 2; i <= 61; i++ {
		r.pass(10*time.Second - cursorSpacing)
		r.beat(p, hb(i, capture(uint64(5+i), 0, 0)))
	}
	r.pass(CountersSpacing)
	if err := r.h.Flush(bg); err != nil {
		t.Fatal(err)
	}
	r.file.mu.Lock()
	writes := r.file.doc.WriteNo - w0
	r.file.mu.Unlock()
	if writes > 11 {
		t.Fatalf("sustained: %d file writes in ten minutes", writes)
	}
	if n := r.sink.sum(EventCounters, "diff.drops_driver"); n != 66 {
		t.Fatalf("sustained: drops_driver %d in all, want the run's 66", n)
	}
	t.Logf("sustained: %d file writes for 60 rises, %d sensor.counters", writes, r.sink.count(EventCounters))
}

// H-10's legs outside P4-4-DE's (C13 0.2 §15; section 1.4's
// TestRunFileRolledBack, D1's alarm half): a run with sensor-transmitted
// standing, a prior whose sensor.run-loss has not committed, and a digest.
// The node stopped and sensorrun.json replaced by its copy from before
// those writes, then started; again with the file deleted; again with it
// unreadable; a fourth, on a node with one sensor, with the sensor
// database deleted and the file replaced by its old copy, so that nothing
// can show it behind; a fifth with the database kept and its cursor
// removed. In each: sensor-transmitted stands, sensor-state-unread stands
// with cause run-file, the held pool events are named possibly lost; in
// the first three the prior and the digest are the cursor's and the
// sensor.run-loss is written once or twice, never not at all, and status
// counts it as possibly a second copy. Controls: a node that trusts a
// readable file (the old copy as if current), which clears
// sensor-transmitted; and, for the fourth and fifth, a node whose database
// can be compared, which reads the old file as current and clears it.
func TestRunFileRolledBack(t *testing.T) {
	setup := func() (*healthRig, []byte) {
		r := newHealthRig(t)
		r.sink.failing(errDown, EventRunLoss, AlarmBufferSmall)
		p := r.accepted(hello02())
		r.beat(p, hb(1, outgoing(0)))
		old, err := os.ReadFile(r.path)
		if err != nil {
			t.Fatal(err)
		}
		r.h.Event(bg, AlarmBufferSmall, nil)
		r.beat(p, hb(2, outgoing(1)))
		p.end()
		if !r.h.Status().Transmitted {
			t.Fatal("not standing before the stop")
		}
		r.sink.failing(nil)
		return r, old
	}
	for _, k := range []struct {
		name string
		mut  func(r *healthRig, old []byte)
		want string
	}{
		{"old copy", func(r *healthRig, old []byte) { os.WriteFile(r.path, old, 0o600) }, "behind"},
		{"deleted", func(r *healthRig, _ []byte) { os.Remove(r.path) }, "lost"},
		{"unreadable", func(r *healthRig, _ []byte) { os.WriteFile(r.path, []byte("{not json"), 0o600) }, "unreadable"},
		{"database deleted", func(r *healthRig, old []byte) { r.loseDatabase(); os.WriteFile(r.path, old, 0o600) }, "not-comparable"},
		{"cursor removed", func(r *healthRig, _ []byte) { r.loseDatabase() }, "not-comparable"},
	} {
		t.Run(k.name, func(t *testing.T) {
			r, old := setup()
			k.mut(r, old)
			r.restart()
			st := r.h.Status()
			if !st.Transmitted || r.al.count(AlarmTransmitted) == 0 || st.RunFile != k.want || r.al.count(AlarmStateUnread) != 1 ||
				!r.raised(AlarmStateUnread, "cause run-file") || len(st.PossiblyLost) == 0 {
				t.Fatalf("status %+v, raises %v", st, r.al.list)
			}
			if k.name == "cursor removed" && !slices.Contains(st.PossiblyLost, AlarmBufferSmall) {
				t.Fatalf("the held event the file kept is not named: %v", st.PossiblyLost)
			}
			if k.want == "not-comparable" {
				return
			}
			if c := cursorNow(t, r.cs); c.Digest != testDigest || c.Prior == nil || c.Prior.Owed {
				t.Fatalf("cursor %+v", c)
			}
			if n := r.sink.count(EventRunLoss); n < 1 || n > 2 || st.StartCopies != 1 {
				t.Fatalf("run-loss written %d times, start copies %d", n, st.StartCopies)
			}
			if d := r.sink.of(EventRunLoss)[0]; d["generation"] != "2" || d["run_counter"] != "5" || d["run_id"] != testRun {
				t.Fatalf("run-loss %v", d)
			}
			// The start wrote the file above every cursor's number, so the
			// next start reads it as current (D6's M-AL).
			r.restart()
			if st := r.h.Status(); st.RunFile != "" {
				t.Fatalf("the next start: %+v", st)
			}
		})
	}
	// Control: the old copy trusted as current.
	r, old := setup()
	var doc runFileDoc
	if err := json.Unmarshal(old, &doc); err != nil {
		t.Fatal(err)
	}
	doc.WriteNo = 1 << 40
	b, _ := json.Marshal(&doc)
	os.WriteFile(r.path, b, 0o600)
	r.restart()
	if r.h.Status().Transmitted {
		t.Fatal("control trusting the old copy still raised; the test cannot tell")
	}
}

// D4-116 item 3.5's first limit, closed: an owed write that fails during a
// live connection is tried again on that connection, at most once a
// second, its failure raised once a connection over every failed retry,
// and its marks cleared once it is written. Controls: frames within the
// second, which make no retry, leave the marks (run here); M-F, the
// failure raised at every retry.
func TestOwedRetriedInLiveConnection(t *testing.T) {
	r := newHealthRig(t)
	r.sink.failing(errDown, EventRunLoss, EventCoverageGap)
	h := hello02()
	h.DropsChannel, h.Lost = "1", []netobs.Span{lspan("09:30:00", "09:31:00")}
	p := r.accepted(h)
	for i := 0; i < 2; i++ { // two more failed tries, a second apart
		r.clk.add(cursorSpacing)
		p.send(tick02(20, 0, 1))
		p.taken()
	}
	r.sink.failing(nil)
	p.send(obs02(1))
	p.ack(1)
	if c := cursorNow(t, r.cs); !c.Prior.Owed || !c.Spans[0].Owed || r.sink.count(EventCoverageGap) != 0 {
		t.Fatalf("control, within the second: retried: %+v", c)
	}
	r.clk.add(cursorSpacing)
	p.send(obs02(2))
	p.ack(2)
	p.stillOpen()
	if c := cursorNow(t, r.cs); c.Prior.Owed || c.Spans[0].Owed || r.sink.count(EventCoverageGap) != 1 || r.sink.count(EventRunLoss) != 1 {
		t.Fatalf("after the retry: %+v, gaps %d", c, r.sink.count(EventCoverageGap))
	}
	if r.al.count(AlarmPositionNotSaved) != 1 {
		t.Fatalf("raises %v", r.al.list)
	}
}

// D4-116 item 3.5's second limit, closed, and item 3.4: the writer is
// idempotent per event under Owed's key. Its events written and the save
// that clears their marks failing, a redial writes none of them again and
// clears the marks. Control: a writer idempotent per call, which writes
// them again at the redial.
func TestOwedNotRewrittenOnRedial(t *testing.T) {
	r := newHealthRig(t)
	h := hello02()
	h.DropsChannel, h.Lost = "1", []netobs.Span{lspan("09:30:00", "09:31:00")}
	ow := r.l.opt.Owed
	r.l.opt.Owed = func(ctx context.Context, w Owed) error {
		err := ow(ctx, w)
		r.cs.failNext(1) // the save that clears the marks fails
		return err
	}
	p := r.accepted(h)
	p.end()
	if c := cursorNow(t, r.cs); !c.Prior.Owed || r.sink.count(EventCoverageGap) != 1 {
		t.Fatalf("setup: %+v", c)
	}
	r.l.opt.Owed = ow
	p = r.dial(enrolment())
	rs := resume(1, 20)
	rs.DropsChannel, rs.Lost = h.DropsChannel, h.Lost
	p.send(rs)
	p.ack(0)
	p.end()
	if c := cursorNow(t, r.cs); c.Prior.Owed || c.Spans[0].Owed || r.sink.count(EventCoverageGap) != 1 || r.sink.count(EventRunLoss) != 1 {
		t.Fatalf("after the redial: %+v, gaps %d, run losses %d", c, r.sink.count(EventCoverageGap), r.sink.count(EventRunLoss))
	}
	// Control: per call, the redial writes them again.
	r.h.mu.Lock()
	r.h.written = nil
	r.h.mu.Unlock()
	if err := r.h.WriteOwed(bg, Owed{Generation: 2, RunCounter: 5, RunID: testRun, Spans: []HeldSpan{{FromUTC: "2026-11-07T09:30:00Z",
		ToUTC: "2026-11-07T09:31:00Z", CutUTC: "2026-11-07T09:31:00Z", Owed: true}}}); err != nil {
		t.Fatal(err)
	}
	if r.sink.count(EventCoverageGap) != 2 {
		t.Fatal("control per call did not write again; the test cannot tell")
	}
}

// N-9's node half (C13 0.3 CH-53): a 0.3 heartbeat's frame_stage and agent
// overlap counts are absent from the sensor.counters the node builds, which
// C4 0.4 validates. Control: a node that maps overlap_table_full to
// diff.overlap_table_full, which C4 0.4's closed set refuses.
func TestOverlapCountsNotInSensorCounters(t *testing.T) {
	h := heartbeat02(1, 100)
	h.Schema = netobs.Identifier03
	h.FrameStage = &netobs.FrameStage{OverlapTableFull: ptr(uint64(9))}
	h.Agent.OverlapJoinRefused, h.Agent.OverlapUnjoined = ptr(uint64(8)), ptr(uint64(7))
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := netobs.DecodeFromSensorIn(b, netobs.Identifier03)
	if err != nil || fs.Heartbeat == nil || *fs.Heartbeat.FrameStage.OverlapTableFull != 9 {
		t.Fatalf("decode: %v", err)
	}
	rises := map[string]uint64{}
	for n, v := range counterValues(&fs.Heartbeat.Counters) {
		if r := rise(v, nil); r > 0 {
			rises[n] = r
		}
	}
	d := SensorCountersDetails(testSensor, testRun, rises)
	for k := range d {
		for _, bad := range []string{"overlap_table_full", "overlap_join_refused", "overlap_unjoined"} {
			if k == "diff."+bad || k == bad {
				t.Fatalf("%s in sensor.counters", k)
			}
		}
	}
	ev := func(d map[string]string) *event.Event {
		return &event.Event{Schema: event.Identifier, ID: event.EventID{NodeID: testNode, Stream: "platform/health", Seq: 1},
			Origin: event.OriginPlatform, Kind: event.KindHealth, Source: event.Source{OriginAuth: event.AuthPlatform},
			Received: received(), Health: &event.Health{Type: event.HealthSensorCounters, Details: d}}
	}
	if err := ev(d).Validate(); err != nil {
		t.Fatalf("the node's sensor.counters is not C4 0.4: %v", err)
	}
	bad := maps.Clone(d)
	bad["diff.overlap_table_full"] = "9"
	if err := ev(bad).Validate(); err == nil {
		t.Fatal("control with diff.overlap_table_full validated; the test cannot tell")
	}
}
