package sensorlink

import (
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// Desk tests of the rules the reviews of #747 at c28398d2 found untested or
// wrong (D6's B1 to B6, D4's B1, B2 and N1), each with its control: a named
// mutant run against it, whose result #747's comment lists. No sensor
// produced the records and no device was contacted.

// D6's B1: a lost gap's times are its stated from_utc and its cut end
// (CH-40), not the sensor's stated end, and the event has no cut_utc. A
// hello at 10:00:00Z states a span from 09:30 to 23:00. Control: the stated
// end written.
func TestLostGapEndIsCutEnd(t *testing.T) {
	r := newHealthRig(t)
	h := hello02()
	h.DropsChannel, h.Lost = "1", []netobs.Span{lspan("09:30:00", "23:00:00")}
	p := r.accepted(h)
	p.end()
	g := r.sink.of(EventCoverageGap)
	if len(g) != 1 {
		t.Fatalf("%d gaps", len(g))
	}
	cut := cursorNow(t, r.cs).Spans[0].CutUTC
	if g[0]["from_utc"] != "2026-11-07T09:30:00Z" || g[0]["to_utc"] != cut || cut != "2026-11-07T10:00:00Z" {
		t.Fatalf("gap %v, cut end %s", g[0], cut)
	}
	if _, ok := g[0]["cut_utc"]; ok {
		t.Fatalf("cut_utc is not a detail of the gap: %v", g[0])
	}
}

// D6's B6 (M-A, M-B): the lost gaps' own budget of 4 an hour, the fourth
// slot carrying the rest merged (first start, last cut end, their number),
// and a gap past it waits. Six gaps owed at once: four events, the last
// merging three; a seventh in the hour waits (ErrHealthHeld), and is
// written once the hour has passed. Controls: a budget of 5; no merge at
// the last slot.
func TestGapLostBudget(t *testing.T) {
	f := newFoldRig(t)
	span := func(from, to, cut string) HeldSpan {
		return HeldSpan{FromUTC: "2026-11-07T" + from + "Z", ToUTC: "2026-11-07T" + to + "Z", CutUTC: "2026-11-07T" + cut + "Z", Owed: true}
	}
	o := Owed{Generation: 2, RunCounter: 5, RunID: testRun, Spans: []HeldSpan{
		span("09:00:00", "09:01:00", "09:01:00"), span("09:02:00", "09:03:00", "09:03:00"), span("09:04:00", "09:05:00", "09:05:00"),
		span("09:06:00", "09:07:00", "09:07:00"), span("09:08:00", "09:09:00", "09:09:00"), span("09:10:00", "23:00:00", "10:00:00")}}
	if err := f.h.WriteOwed(bg, o); err != nil {
		t.Fatal(err)
	}
	g := f.sink.of(EventCoverageGap)
	if len(g) != GapLostPerHour {
		t.Fatalf("%d gap events, want %d", len(g), GapLostPerHour)
	}
	if m := g[3]; m["merged"] != "3" || m["from_utc"] != "2026-11-07T09:06:00Z" || m["to_utc"] != "2026-11-07T10:00:00Z" {
		t.Fatalf("the last slot: %v", m)
	}
	late := Owed{Generation: 2, RunCounter: 5, RunID: testRun, Spans: []HeldSpan{span("09:20:00", "09:21:00", "09:21:00")}}
	f.clk.add(time.Hour - 1)
	if err := f.h.WriteOwed(bg, late); !errors.Is(err, ErrHealthHeld) {
		t.Fatalf("a fifth in the hour: %v", err)
	}
	f.clk.add(1)
	if err := f.h.WriteOwed(bg, late); err != nil || f.sink.count(EventCoverageGap) != GapLostPerHour+1 {
		t.Fatalf("after the hour: %v, %d gaps", err, f.sink.count(EventCoverageGap))
	}
}

// D6's B2: one writer of sensorrun.json at a time. Sensor B's write is held
// before its rename; no second writer can take a number meanwhile; sensor
// A's raise then lands after B's, and the file holds both. Control:
// today's write at c28398d2 (no wmu), under which a second writer takes
// the same number and B's older snapshot lands last.
func TestRunFileOneWriter(t *testing.T) {
	path := t.TempDir() + "/sensorrun.json"
	file := OpenRunFile(path)
	clk, wall := &aclock{}, time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	mk := func(id string) *Health {
		return NewHealth(HealthConfig{SensorID: id, Sink: &memSink{}, Monotonic: clk.mono, Now: func() time.Time { return wall }, File: file})
	}
	ha, hb := mk(testSensor), mk(otherSensor)
	atRename, release := make(chan struct{}), make(chan struct{})
	first := true
	runFileFault = func() error {
		if first {
			first = false
			close(atRename)
			<-release
		}
		return nil
	}
	t.Cleanup(func() { runFileFault = nil })
	bDone := make(chan error, 1)
	go func() { bDone <- hb.transmit(bg, "b") }()
	<-atRename
	if file.wmu.TryLock() {
		file.wmu.Unlock()
		t.Fatal("a second writer could take a number while one is before its rename")
	}
	aDone := make(chan error, 1)
	go func() { aDone <- ha.transmit(bg, "a") }()
	close(release)
	if err := errors.Join(<-bDone, <-aDone); err != nil {
		t.Fatal(err)
	}
	g := OpenRunFile(path)
	if g.readErr != nil || g.doc.WriteNo != 2 || g.doc.Sensors[testSensor] == nil || g.doc.Sensors[testSensor].Transmitted == nil ||
		g.doc.Sensors[otherSensor] == nil || g.doc.Sensors[otherSensor].Transmitted == nil {
		t.Fatalf("the file: %+v, %v", g.doc, g.readErr)
	}
}

// D6's B3, P4: a run file write that fails is returned by Event and Flush
// and raised once a failing stretch (sensor-state-not-durable), and status
// names it until a write succeeds. A node-only event that waits is held
// only once the file has it, so Event's nil means written or held (section
// 1.1's re-arm). Control: today's Event and Flush, which return nothing of
// the file and raise nothing.
func TestRunFileWriteFailsLoud(t *testing.T) {
	f := newFoldRig(t)
	f.h.mu.Lock()
	fillPool(t, f.h.pool, f.clk.mono())
	f.h.mu.Unlock()
	runFileFault = func() error { return errors.New("test: the disk is full") }
	t.Cleanup(func() { runFileFault = nil })
	for range 2 {
		if err := f.h.Event(bg, EventRedialGranted, map[string]string{"generation": "2"}); err == nil {
			t.Fatal("Event returned nil with the event neither written nor held")
		}
	}
	if err := f.h.Flush(bg); err == nil {
		t.Fatal("Flush returned nil")
	}
	if n := f.al.count(AlarmStateNotDurable); n != 1 || f.h.Status().NotDurable == "" {
		t.Fatalf("raised %d times, status %+v", n, f.h.Status())
	}
	runFileFault = nil
	f.clk.add(time.Minute)
	if err := f.h.Flush(bg); err != nil || f.h.Status().NotDurable != "" {
		t.Fatalf("after the fault: %v, %+v", err, f.h.Status())
	}
	if err := f.h.Event(bg, EventRedialGranted, map[string]string{"generation": "2"}); err != nil {
		t.Fatalf("held in the file: %v", err)
	}
	if g := OpenRunFile(f.path); g.readErr != nil || len(g.doc.Sensors[testSensor].Held) != 1 || g.doc.Sensors[testSensor].Held[0].Merged != 3 {
		t.Fatalf("the file holds %+v", g.doc.Sensors[testSensor])
	}
}

// D6's B3, P6, and M-AO: the cursor keeps its write number across a start
// whose file write fails and a new run's row 6. (i) The file current: row
// 6 skips the file (it holds the run's totals), and the new cursor carries
// the number the start read. (ii) The file behind: the start's failed
// write does not count it as written, so row 6 writes it, above the
// cursor's number. Controls: a link that takes the write number only from
// a file write in this process (i: the cursor falls to 0); a behind file
// counted as written at the start (ii: row 6 writes nothing).
func TestWriteNoKeptAcrossFailedStart(t *testing.T) {
	setup := func() (*healthRig, uint64, []byte) {
		r := newHealthRig(t)
		p := r.accepted(helloRun(0))
		r.beat(p, hbRun(0, 1, 100, outgoing(0)))
		old, err := os.ReadFile(r.path)
		if err != nil {
			t.Fatal(err)
		}
		r.beat(p, hbRun(0, 2, 200, outgoing(1))) // a transmit: the file written now, its number saved
		p.end()
		w := cursorNow(t, r.cs).WriteNo
		if w < 2 {
			t.Fatalf("setup: the cursor's write number is %d", w)
		}
		return r, w, old
	}
	failedStart := func(r *healthRig) {
		r.restartNoStart()
		runFileFault = func() error { return errors.New("test: killed before the file's rename") }
		if err := r.file.Start(bg, r.l); err == nil {
			t.Fatal("the start's write did not fail")
		}
		runFileFault = nil
	}
	t.Cleanup(func() { runFileFault = nil })
	r, w, _ := setup()
	failedStart(r)
	p := r.accepted(helloRun(1))
	p.end()
	if c := cursorNow(t, r.cs); c.RunID != runN(1) || c.WriteNo < w {
		t.Fatalf("(i): the new run's cursor carries write number %d, below %d", c.WriteNo, w)
	}

	r, w, old := setup()
	if err := os.WriteFile(r.path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	failedStart(r)
	p = r.accepted(helloRun(1))
	p.end()
	if g := OpenRunFile(r.path); g.readErr != nil || g.doc.WriteNo <= w {
		t.Fatalf("(ii): the file's write number %d is not above the cursor's %d: row 6 did not write it", g.doc.WriteNo, w)
	}
}

// D6's B5, P3, and M-S: an owed sensor.run-loss that waits is made due
// once, whatever the retries. The pool spent, a run whose prior declares
// a loss accepted, five frames a second apart (a retry at each): the run
// loss waits (ErrHealthHeld, nothing raised, the mark kept); once room
// returns it is written once, with no merged detail, and health_held
// counts it once. Controls: today's WriteOwed, which makes it due at each
// retry (merged 7, health_held 6); a WriteOwed that returns nil while it
// waits, which clears the mark with the loss in memory only.
func TestRunLossDueOnceWhileWaiting(t *testing.T) {
	r := newHealthRig(t)
	r.h.mu.Lock()
	fillPool(t, r.h.pool, r.clk.mono())
	r.h.mu.Unlock()
	p := r.accepted(hello02())
	for i := 1; i <= 5; i++ {
		r.clk.add(cursorSpacing)
		p.send(obs02(i))
		p.ack(uint64(i))
	}
	if c := cursorNow(t, r.cs); c.Prior == nil || !c.Prior.Owed || r.sink.count(EventRunLoss) != 0 || r.al.count(AlarmPositionNotSaved) != 0 {
		t.Fatalf("while it waits: cursor %+v, raises %v", c, r.al.list)
	}
	r.clk.add(time.Hour)
	p.send(obs02(6))
	p.ack(6)
	p.end()
	rl := r.sink.of(EventRunLoss)
	if len(rl) != 1 || rl[0]["merged"] != "" || r.h.Status().HealthHeld != 1 {
		t.Fatalf("run loss %v, health_held %d", rl, r.h.Status().HealthHeld)
	}
	if c := cursorNow(t, r.cs); c.Prior.Owed {
		t.Fatal("the mark stands once written")
	}
}

// D6's B6 (M-AG): an alarm the link raises makes its pool event due, and
// the pool's next write (Flush, on the manager's tick) writes it. Control:
// Link.raise making no pool event due.
func TestLinkAlarmEventWritten(t *testing.T) {
	r := newHealthRig(t)
	h := helloRun(0)
	h.BufferBytes = strconv.Itoa(netobs.MinBufferBytes) // below the site floor
	p := r.accepted(h)
	p.end()
	if err := r.h.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if e := r.sink.of(AlarmBufferSmall); len(e) != 1 || e[0]["sensor_id"] != testSensor || e[0]["detail"] == "" {
		t.Fatalf("buffer-small events %v, raises %v", e, r.al.list)
	}
}

// D6's B4 and its legs (M-C, M-D, M-E, M-AE): a run is seen from its start
// only while no loss is declared and no seq missed below the heartbeat
// (CH-27), so a heartbeat that omits egress_check after each of these
// raises sensor-egress-absent and holds no mark: a tick that declares a
// loss (P5: the run's first heartbeat evicted); a placement gap; a
// heartbeat whose drops_channel rises; a refusal that takes no seq; a
// hello with drops_channel above 0. Controls: each mutant that keeps the
// run seen from its start on that way, under which nothing is raised.
func TestEgressFromStartLost(t *testing.T) {
	for _, k := range []struct {
		name string
		run  func(r *healthRig) *peer
	}{
		{"tick declares a loss", func(r *healthRig) *peer {
			p := r.accepted(hello02())
			tk := tick02(20, 1, 1)
			tk.Lost = []netobs.Span{lspan("09:59:00", "09:59:30")}
			r.tickAfter(p, tk)
			r.beat(p, hb(2, noEgress))
			return p
		}},
		{"placement gap", func(r *healthRig) *peer {
			p := r.accepted(hello02())
			r.beat(p, hb(2, noEgress))
			return p
		}},
		{"heartbeat drops_channel rises", func(r *healthRig) *peer {
			p := r.accepted(hello02())
			r.beat(p, hb(1, func(h *netobs.Heartbeat) { noEgress(h); h.Counters.DropsChannel = 1 }))
			return p
		}},
		{"refused with no seq", func(r *healthRig) *peer {
			p := r.accepted(hello02())
			p.send([]byte(`{"schema":"otsec.netobs/0.2","type":"observation"}`))
			r.beat(p, hb(1, noEgress))
			return p
		}},
		{"hello drops_channel", func(r *healthRig) *peer {
			h := hello02()
			h.DropsChannel = "1"
			p := r.accepted(h)
			r.beat(p, hb(1, noEgress))
			return p
		}},
	} {
		t.Run(k.name, func(t *testing.T) {
			r := newHealthRig(t)
			k.run(r).end()
			if n := r.al.count(AlarmEgressAbsent); n != 1 {
				t.Fatalf("raises %v", r.al.list)
			}
			if c := cursorNow(t, r.cs); c.Egress != "" {
				t.Fatalf("mark %q held", c.Egress)
			}
		})
	}
}

// D4's N1: a resume of the run in the same process with no gap, before the
// run's first heartbeat, keeps it seen from its start, so a run that never
// carries egress_check raises nothing. After a node start it is not
// (stated in section 1.14, loud). Control: fromStart set only on the
// connection that accepted the run.
func TestEgressFromStartAcrossResume(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(hello02())
	p.end()
	p = r.dial(enrolment())
	p.send(resume(1, 20))
	p.ack(0)
	r.beat(p, hb(1, noEgress))
	p.end()
	if n := r.al.count(AlarmEgressAbsent); n != 0 || cursorNow(t, r.cs).Egress != EgressOmitted {
		t.Fatalf("raises %v, mark %q", r.al.list, cursorNow(t, r.cs).Egress)
	}
}

// D4's B1: a heartbeat stating egress_check absent records the field as
// carried (CH-27), so a later omission, after a node restart too, reads as
// absent. Control: today's code, which leaves the mark as it is (never
// carried) and raises nothing after the restart.
func TestEgressAbsentIsCarried(t *testing.T) {
	r := newHealthRig(t)
	absent := func(h *netobs.Heartbeat) { h.EgressCheck = "absent" }
	p := r.accepted(hello02())
	r.beat(p, hb(1, absent), hb(2, noEgress))
	p.end()
	if c := cursorNow(t, r.cs); c.Egress != EgressCarried || r.al.count(AlarmEgressAbsent) != 1 {
		t.Fatalf("mark %q, raises %v", c.Egress, r.al.list)
	}
	r.restart()
	p = r.dial(enrolment())
	p.send(resume(3, 20))
	p.ack(2)
	r.beat(p, hb(3, noEgress))
	if r.al.count(AlarmEgressAbsent) != 1 {
		t.Fatalf("after the restart: raises %v", r.al.list)
	}
}

// D4's B2: a heartbeat whose baseline save fails is not taken, so its
// resend follows: drops_driver 0 then 5, the second's save failing, the
// sensor resuming and resending it, then one more at 5: no
// counter-decrease. Control: today's order, the heartbeat taken before
// the save.
func TestHeartbeatResentAfterFailedSave(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(hello02())
	r.beat(p, hb(1, capture(0, 0, 0)))
	r.cs.failNext(1) // the baselines' save
	p.taken()
	r.clk.add(cursorSpacing)
	p.send(hb(2, capture(5, 0, 0)))
	if why := p.closed(); why != netobs.CloseStore {
		t.Fatalf("closed %q", why)
	}
	p = r.dial(enrolment())
	p.send(resume(2, 20))
	p.ack(1)
	r.beat(p, hb(2, capture(5, 0, 0)), hb(3, capture(5, 0, 0)))
	if n := r.l.Stats().Refused[RefusedCounterDecrease]; n != 0 {
		t.Fatalf("%d counter-decrease refusals", n)
	}
}

// D6's B6 (M-K, M-L): sensor.run-loss is written only for a prior that
// declares a loss or an unclean end, spans alone included (CH-45).
// Controls: declares always true; declares without the spans.
func TestRunLossOnlyDeclared(t *testing.T) {
	f := newFoldRig(t)
	clean := &HeldPrior{PreviousEnd: "clean", StartedBy: "agent", Owed: true}
	if err := f.h.WriteOwed(bg, Owed{Generation: 2, RunCounter: 5, RunID: testRun, Prior: clean}); err != nil || f.sink.count(EventRunLoss) != 0 {
		t.Fatalf("a clean prior: %v, %d written", err, f.sink.count(EventRunLoss))
	}
	spans := &HeldPrior{PreviousEnd: "clean", StartedBy: "agent", Owed: true, Spans: []HeldSpan{{FromUTC: "2026-11-07T09:00:00Z",
		ToUTC: "2026-11-07T09:01:00Z", CutUTC: "2026-11-07T09:01:00Z", Owed: true}}}
	if err := f.h.WriteOwed(bg, Owed{Generation: 2, RunCounter: 6, RunID: testRun2, Prior: spans}); err != nil || f.sink.count(EventRunLoss) != 1 {
		t.Fatalf("a prior with spans only: %v, %d written", err, f.sink.count(EventRunLoss))
	}
}

// D6's B6 (M-M): at a start, the cursor's capture totals are judged
// against the file's totals only for the same run; the file's totals of
// another run are no base. Control: the file's totals kept as the base.
func TestStartCaptureOtherRun(t *testing.T) {
	f := newFoldRig(t)
	five, three := uint64(5), uint64(3)
	e := &runFileSensor{Capture: &captureState{RunID: testRun, Key: "1", Totals: map[string]uint64{"drops_driver": five}}}
	f.h.start(e, true, true, "", &Cursor{RunID: testRun2, DropsDriver: &three})
	if w := f.h.Status().Waiting; len(w) != 1 || w[0].Rises["drops_driver"] != 3 || w[0].Key != startKey(testRun2) {
		t.Fatalf("waiting %+v", w)
	}
}

// D6's B6 (M-I): a missing run file reads as lost when a cursor holds a
// write number above 0, 1 included. Control: lost only above 1.
func TestRunFileMissingAtWriteNoOne(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(helloRun(0))
	if err := r.h.Event(bg, EventPastBlind, nil); err != nil { // the file's first write
		t.Fatal(err)
	}
	p.end()
	if c := cursorNow(t, r.cs); c.WriteNo != 1 {
		t.Fatalf("setup: write number %d", c.WriteNo)
	}
	if err := os.Remove(r.path); err != nil {
		t.Fatal(err)
	}
	r.restart()
	if st := r.h.Status(); st.RunFile != "lost" {
		t.Fatalf("status %+v", st)
	}
}

// D6's B6 (M-Q): an event merged into one that already waited is counted
// in health_held. Control: the merge not counted.
func TestPoolMergeCountedHeld(t *testing.T) {
	p := NewPool()
	fillPool(t, p, time.Hour)
	now := time.Hour + time.Minute
	emit := (&emitted{}).emit(&now)
	p.Due(HeldEvent{Name: AlarmBufferSmall})
	if err := p.Write(bg, now, emit); err != nil || p.Held != 1 {
		t.Fatalf("%v, health_held %d", err, p.Held)
	}
	p.Due(HeldEvent{Name: AlarmBufferSmall})
	if p.Held != 2 {
		t.Fatalf("health_held %d after a merge into a waiting event", p.Held)
	}
}

// D6's B6 (M-G): a record's commit carries a write number newer than its
// encoded cursor: a run file written between the record's encode and its
// commit (observeFault) is not written back below. Control: commitOne
// without its write-number check.
func TestCommitCarriesNewerWriteNo(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(hello02())
	observeFault = func() {
		observeFault = nil
		if err := r.file.write(bg); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { observeFault = nil })
	p.send(obs02(1))
	p.ack(1)
	p.end()
	g := OpenRunFile(r.path)
	if c := cursorNow(t, r.cs); g.readErr != nil || c.WriteNo != g.doc.WriteNo || c.Taken != 1 {
		t.Fatalf("cursor write number %d (taken %d), file %d", c.WriteNo, c.Taken, g.doc.WriteNo)
	}
}
