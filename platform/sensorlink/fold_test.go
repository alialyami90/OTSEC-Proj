package sensorlink

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

// Desk tests of sensor.counters' fold (D1's ruling 6996137498 on #747; C4
// 0.5 as proposed in #753, rows E5-5, E5-8 and E5-9; D3's B1 on #747). No
// sensor produced the counts and no device was contacted.

// runN is the k-th run of testSensor: a UUID and a hello with a clean
// prior, so it owes no sensor.run-loss.
func runN(k int) string { return fmt.Sprintf("%08x-1a2f-4e3b-8c7d-5f6a7b8c9d0f", 0x2c000000+k) }

func helloRun(k int) *netobs.SensorHello {
	h := hello02()
	h.RunCounter, h.RunID = strconv.Itoa(5+k), runN(k)
	h.Prior = &netobs.Prior{RunsSkipped: "0", RecordsLost: "0", Lost: []netobs.Span{}, PreviousEnd: "clean", StartedBy: "agent"}
	return h
}

// hbRun is heartbeat seq of run k with packets p (bytes and the interface
// count with it) and its capture counters changed by f.
func hbRun(k, seq int, p uint64, f func(*netobs.Heartbeat)) *netobs.Heartbeat {
	h := heartbeat02(seq, p)
	h.RunID = runN(k)
	if f != nil {
		f(h)
	}
	return h
}

// countersOf is the sensor.counters written.
func countersOf(s *memSink) []map[string]string { return s.of(EventCounters) }

// E5-5 (a) to (e), the node leg (C4-0.5-1, C4-0.5-2), through the link: (a)
// one run gives an event without runs_folded. (b) Runs B, D and F wait and
// are written as one: runs_folded 2, run_id F, each diff the sum, and
// drops_holder, which rose in B only, summed and named. (c) A node restart
// between D and F, with sensorrun.json read back, gives that same event.
// (d) Run C ends before a heartbeat and run E's only heartbeat adds no
// rise: neither counts, and run_id names neither. (e) Rises waiting under
// position generation 1, then a replace (generation 3, its own Began) and
// a run with rises: two events, the first with generation 1's run_id, the
// second without runs_folded. Controls (named mutants, run against this
// test; #747's comment lists each result): a fold without runs_folded; one
// that counts the latest run (off by one); one that loses the count across
// the restart; one that keeps the latest run's rises in place of the sum;
// one that counts every run accepted, or every run whose heartbeat was
// taken; one that folds across the replace.
func TestCountersFoldRuns(t *testing.T) {
	r := newHealthRig(t)
	run := func(k int, hs ...*netobs.Heartbeat) {
		t.Helper()
		p := r.dial(enrolment())
		p.send(helloRun(k))
		select {
		case <-p.acks:
		case why := <-p.done:
			t.Fatalf("run %d's hello closed %q: %v", k, why, r.al.list)
		}
		if len(hs) > 0 {
			r.beat(p, hs...)
		}
		p.end()
	}
	// (a): run A's first heartbeat is written at once.
	run(0, hbRun(0, 1, 100, nil))
	c := countersOf(r.sink)
	if len(c) != 1 || c[0]["run_id"] != runN(0) || c[0][DetailRunsFolded] != "" || c[0]["diff.packets"] != "100" {
		t.Fatalf("(a): %v", c)
	}
	// (b), (d): within the 10 minutes, B, C, D wait.
	run(1, hbRun(1, 1, 10, capture(0, 3, 0)))
	run(2)
	run(3, hbRun(3, 1, 20, nil))
	// (c): the file's minute passed, the waiting entry in sensorrun.json,
	// the node restarted. A start begins the budgets again (section 1.14),
	// so the store refuses sensor.counters until run F, as a spent pool
	// would hold it.
	r.clk.add(time.Minute)
	if err := r.h.Flush(bg); err != nil {
		t.Fatal(err)
	}
	r.sink.failing(errDown, EventCounters)
	r.restart()
	if w := r.h.Status().Waiting; len(w) != 1 || w[0].Folded != 1 || w[0].Run != runN(3) {
		t.Fatalf("(c): read back %+v", w)
	}
	run(4, hbRun(4, 1, 0, func(h *netobs.Heartbeat) { h.Counters.Bytes, h.Interfaces[0].Packets = 0, 0 }))
	run(5, hbRun(5, 1, 40, nil))
	if n := len(countersOf(r.sink)); n != 1 {
		t.Fatalf("written while held: %d", n)
	}
	r.sink.failing(nil)
	if err := r.h.Flush(bg); err != nil {
		t.Fatal(err)
	}
	c = countersOf(r.sink)
	if len(c) != 2 {
		t.Fatalf("(b): %v", c)
	}
	d := c[1]
	if d["run_id"] != runN(5) || d[DetailRunsFolded] != "2" || d["diff.packets"] != "70" || d["diff.drops_holder"] != "3" ||
		d[event.DetailCaptureLoss] != "drops_holder" || d["diff.bytes"] != strconv.Itoa(90*70) {
		t.Fatalf("(b) to (d): %v", d)
	}

	// (e): generation 1's rises wait, a replace begins generation 3.
	run(6, hbRun(6, 1, 5, nil))
	replaced := Enrolment{SensorID: testSensor, Generation: 3, Began: 3, ConfigDigest: testDigest}
	h := helloRun(7)
	h.Generation = "3"
	p := r.dial(replaced)
	p.send(h)
	p.ack(0)
	g := hbRun(7, 1, 9, nil)
	p.taken()
	r.clk.add(cursorSpacing)
	p.send(g)
	p.ack(1)
	p.end()
	if w := r.h.Status().Waiting; len(w) != 2 {
		t.Fatalf("(e): waiting %+v", w)
	}
	for range 2 {
		r.clk.add(CountersSpacing)
		if err := r.h.Flush(bg); err != nil {
			t.Fatal(err)
		}
	}
	c = countersOf(r.sink)
	if len(c) != 4 || c[2]["run_id"] != runN(6) || c[2]["diff.packets"] != "5" || c[2][DetailRunsFolded] != "" ||
		c[3]["run_id"] != runN(7) || c[3]["diff.packets"] != "9" || c[3][DetailRunsFolded] != "" {
		t.Fatalf("(e): %v", c[2:])
	}

	// Each event is valid C4 as this binary stamps it. A folded event
	// needs C4 0.5's validator, on main since #755: under 0.4, runs_folded
	// is refused. The skip below can no longer trigger (event.Identifier
	// is otsec.event/0.5), and is kept only as that record.
	t.Run("C4", func(t *testing.T) {
		if event.Identifier == "otsec.event/0.4" {
			t.Skip("needs C4 0.5's validator (#753), not on main yet: 0.4 refuses runs_folded; #747 merges only after it")
		}
		for _, d := range c {
			e := &event.Event{Schema: event.Identifier, ID: event.EventID{NodeID: testNode, Stream: "platform/health", Seq: 1},
				Origin: event.OriginPlatform, Kind: event.KindHealth, Source: event.Source{OriginAuth: event.AuthPlatform},
				Received: received(), Health: &event.Health{Type: event.HealthSensorCounters, Details: d}}
			if err := e.Validate(); err != nil {
				t.Fatalf("%v: %v", d, err)
			}
		}
	})
}

// foldRig is a Health with sensorrun.json and the in-memory health stream,
// driven without a link.
type foldRig struct {
	t    *testing.T
	clk  *aclock
	sink *memSink
	al   *alarms
	path string
	h    *Health
}

func newFoldRig(t *testing.T) *foldRig {
	f := &foldRig{t: t, clk: &aclock{}, sink: &memSink{}, al: &alarms{}, path: filepath.Join(t.TempDir(), "sensorrun.json")}
	wall := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	f.h = NewHealth(HealthConfig{SensorID: testSensor, Sink: f.sink, Monotonic: f.clk.mono, Now: func() time.Time { return wall },
		Raise: f.al.raise, File: OpenRunFile(f.path)})
	return f
}

// E5-8 (C4-0.5-3): sums never wrap. (a) Folded rises summing to exactly
// 2^64 - 1 give that value, and status names no saturation. (b1) Two
// runs, each with a drops_holder rise of 2^63, sum past it: the waiting
// entry holds 2^64 - 1, status names the saturation until the entry is
// written, and runs_folded and run_id still move with a third run whose
// only rise is on drops_holder. (b2) A fourth run with rises on
// frames_overlong and packets: they are summed into the entry,
// capture_loss is "drops_holder frames_overlong", runs_folded is 3, and
// status still names only drops_holder. (c) In each, capture_loss names
// drops_holder. Controls (named mutants): plain uint64 addition, which
// writes 0 with no capture_loss; the maximum held without the status
// line; for (a), a saturation check one too early (sum >= max, X-12's
// opposite, D6's B7 on #747); for (b2), the entry's rises frozen once any
// value saturates while run_id and runs_folded still move (X-13, D6's B8).
func TestCountersFoldSaturates(t *testing.T) {
	const half = uint64(1) << 63
	dh := func(v uint64) map[string]uint64 { return map[string]uint64{"drops_holder": v} }
	leg := func(rises ...map[string]uint64) (map[string]string, HealthStatus) {
		f := newFoldRig(t)
		f.h.counters(bg, "1", runN(0), map[string]uint64{"packets": 1}, [3]*uint64{}) // written: the spacing starts
		for i, r := range rises {
			f.h.counters(bg, "1", runN(1+i), r, [3]*uint64{})
		}
		st := f.h.Status()
		f.clk.add(CountersSpacing)
		if err := f.h.Flush(bg); err != nil {
			t.Fatal(err)
		}
		if after := f.h.Status(); len(after.Saturated) != 0 {
			t.Fatalf("saturation still named once written: %v", after.Saturated)
		}
		c := countersOf(f.sink)
		if len(c) != 2 {
			t.Fatalf("%d sensor.counters", len(c))
		}
		return c[1], st
	}
	top := strconv.FormatUint(math.MaxUint64, 10)
	d, st := leg(dh(half), dh(half-1))
	if d["diff.drops_holder"] != top || d[event.DetailCaptureLoss] != "drops_holder" || d[DetailRunsFolded] != "1" {
		t.Fatalf("(a): %v", d)
	}
	if len(st.Saturated) != 0 {
		t.Fatalf("(a): exactly 2^64 - 1, status names %v", st.Saturated)
	}
	d, st = leg(dh(half), dh(half), dh(1))
	if d["diff.drops_holder"] != top || d[event.DetailCaptureLoss] != "drops_holder" || d[DetailRunsFolded] != "2" || d["run_id"] != runN(3) {
		t.Fatalf("(b1): %v", d)
	}
	if !slices.Equal(st.Saturated, []string{"diff.drops_holder"}) {
		t.Fatalf("(b1): status names %v", st.Saturated)
	}
	d, st = leg(dh(half), dh(half), dh(1), map[string]uint64{"frames_overlong": 7, "packets": 3})
	if d["diff.drops_holder"] != top || d["diff.frames_overlong"] != "7" || d["diff.packets"] != "3" ||
		d[event.DetailCaptureLoss] != "drops_holder frames_overlong" || d[DetailRunsFolded] != "3" || d["run_id"] != runN(4) {
		t.Fatalf("(b2): %v", d)
	}
	if !slices.Equal(st.Saturated, []string{"diff.drops_holder"}) {
		t.Fatalf("(b2): status names %v", st.Saturated)
	}
	// runs_folded carried past its maximum is named, and the names are
	// kept in the run file's entry: a waiting entry read back from its
	// JSON names them still. One that only reaches the maximum is not.
	p := NewPool()
	p.Due(HeldEvent{Name: EventCounters, Key: "1", Run: runN(1), Folded: math.MaxUint64 - 1, Rises: map[string]uint64{"packets": 1}})
	p.Due(HeldEvent{Name: EventCounters, Key: "1", Run: runN(2), Rises: map[string]uint64{"packets": 1}})
	if w := p.Waiting(); w[0].Folded != math.MaxUint64 || len(w[0].Saturated) != 0 {
		t.Fatalf("runs_folded at exactly the maximum: %d, named %v", w[0].Folded, w[0].Saturated)
	}
	p.Due(HeldEvent{Name: EventCounters, Key: "1", Run: runN(3), Rises: map[string]uint64{"packets": 1}})
	b, err := json.Marshal(p.Waiting()[0])
	if err != nil {
		t.Fatal(err)
	}
	var back HeldEvent
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	q := NewPool()
	q.Due(back)
	if w := q.Waiting(); w[0].Folded != math.MaxUint64 || !slices.Equal(w[0].Saturated, []string{DetailRunsFolded}) {
		t.Fatalf("runs_folded past the maximum, read back: %d, named %v", w[0].Folded, w[0].Saturated)
	}
}

// E5-9 (C4 0.5 section 3): a sensorrun.json whose form version is above
// this reader's is refused: it reads as unreadable, sensor-state-unread
// with cause run-file, and no held entry from it is written. Control (a
// named mutant): a reader that ignores the version, which writes the held
// sensor.counters.
func TestRunFileLaterFormRefused(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(helloRun(0))
	r.beat(p, hbRun(0, 1, 100, nil))
	p.end()
	b, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	var doc runFileDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Schema = "otsec.node-sensorrun/0.2"
	doc.Sensors[testSensor].Held = []HeldEvent{{Name: EventCounters, Key: "1", Merged: 1, Run: runN(0), Rises: map[string]uint64{"packets": 7}}}
	if b, err = json.Marshal(&doc); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	r.restart()
	r.clk.add(CountersSpacing)
	if err := r.h.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if st := r.h.Status(); st.RunFile != "unreadable" || !r.raised(AlarmStateUnread, "cause run-file") {
		t.Fatalf("status %+v, raises %v", st, r.al.list)
	}
	for _, d := range countersOf(r.sink) {
		if d["diff.packets"] == "7" {
			t.Fatalf("the later form's held entry was written: %v", d)
		}
	}
}

// D3's B1 on #747, its test (D1's ruling 6996137498 item 5): a sensor
// that starts a new run at every RedialFloor (10 s) for a simulated day,
// each run's first heartbeat a capture loss, and each new run's row 6
// recording the replaced run's totals (beforeReplace). At every step at
// most one sensor.counters waits, and sensorrun.json, as a write would
// hold it (marshalled at each step: the day runs without the disk, whose
// round trip TestCountersFoldRuns shows), stays under 1,024 bytes; the
// drops_driver written plus the one waiting is exactly the day's loss;
// and each event's runs_folded is the number of runs it carries less one,
// its run_id the latest (E5-5's per-event check). Control (a named
// mutant): sensor.counters keyed by the run, which grows by a run each 10
// s (D3's probe: 8,544 waiting and 1,169,995 bytes at the day's end).
func TestCountersFoldBoundedOverADay(t *testing.T) {
	const redialFloor = 10 * time.Second
	f := newFoldRig(t)
	f.h.cfg.File = nil
	var loss, written uint64
	since := 0 // runs with rises since the last event
	prev := &Cursor{}
	for i := range int(24 * time.Hour / redialFloor) {
		f.clk.add(redialFloor)
		run := runN(i)
		if i > 0 {
			if err := f.h.beforeReplace(bg, prev); err != nil {
				t.Fatal(err)
			}
		}
		v := uint64(i%5 + 1)
		loss += v
		before := len(countersOf(f.sink))
		f.h.counters(bg, "1", run, map[string]uint64{"drops_driver": v, "packets": 1}, [3]*uint64{&v})
		since++
		if c := countersOf(f.sink); len(c) > before {
			d := c[len(c)-1]
			want := ""
			if since > 1 {
				want = strconv.Itoa(since - 1)
			}
			if d["run_id"] != run || d[DetailRunsFolded] != want {
				t.Fatalf("run %d: event %v, want runs_folded %q", i, d, want)
			}
			n, _ := strconv.ParseUint(d["diff.drops_driver"], 10, 64)
			written += n
			since = 0
		}
		if w := f.h.Status().Waiting; len(w) > 1 {
			t.Fatalf("run %d: %d waiting", i, len(w))
		}
		f.h.mu.Lock()
		e := f.h.entry()
		f.h.mu.Unlock()
		b, err := json.Marshal(&runFileDoc{Schema: RunFileSchema, WriteNo: math.MaxUint64, Sensors: map[string]*runFileSensor{testSensor: &e}})
		if err != nil || len(b) > 1024 {
			t.Fatalf("run %d: sensorrun.json would be %d bytes: %v", i, len(b), err)
		}
		prev = &Cursor{RunID: run, DropsDriver: &v}
	}
	var waiting uint64
	for _, w := range f.h.Status().Waiting {
		waiting += w.Rises["drops_driver"]
	}
	if written+waiting != loss {
		t.Fatalf("written %d and waiting %d, want the day's %d", written, waiting, loss)
	}
	t.Logf("a day of runs every %v: %d sensor.counters, %d drops_driver written and %d waiting", redialFloor, len(countersOf(f.sink)), written, waiting)
}
