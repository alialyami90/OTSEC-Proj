package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/platform/store"
)

// C4 0.6 step 2, S2-bc (brief P4-4-C4-06-S2; D1 on #772): option B's
// durable counts of refused stored observations, written as
// detector.observation-refused before the checkpoint that follows; the
// checkpoint hold; the forced checkpoint past RefusedCountsWait and
// network-refused-counts-unwritten; the start's scan, the seq rule and the
// counts begun again; and the lasting not-exact mark
// (docs/phase4/D5-refusal-alarms-options.md sections 2.4 and 5, tests T5,
// T6 and T10; docs/phase4/D4-c4-0.6-proposal.md sections 2.1 to 2.3 and 4,
// E6-16 and E6-18). Desk only: the refused records are this build's own
// observations of another sensor, stored by hand; no sensor wrote them and
// no device was contacted. A "crash" is a stop with no final step.

// countsRig is a node on the test's wall and monotonic clocks, with the
// OS log kept and the sensor seams the next start takes.
type countsRig struct {
	*retentionRig
	seams  SensorSeams
	mu     sync.Mutex
	logged []string
	base   []byte
}

func newCountsRig(t *testing.T) *countsRig {
	return &countsRig{retentionRig: newRetentionRig(t)}
}

// start starts the node, its monotonic clock restarting, and waits for
// the sensor manager's first step, which restores the detector.
func (g *countsRig) start() (*Runtime, *Status) {
	g.t.Helper()
	g.retentionRig.mu.Lock()
	g.mono = time.Minute
	g.retentionRig.mu.Unlock()
	st := NewStatus("", func(s string) { g.mu.Lock(); g.logged = append(g.logged, s); g.mu.Unlock() }, g.now)
	r, err := Start(bg, g.c, RuntimeOptions{Status: st, Now: g.now, Mono: g.monoNow, SensorSeams: g.seams,
		Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		g.t.Fatal(err)
	}
	waitSensor(g.t, r)
	return r, st
}

// first runs the node over one valid flow, so the detector checkpoints at
// 1, and keeps that record as base for the records stored after it.
func (g *countsRig) first() (*Runtime, *Status) {
	g.t.Helper()
	r, st := g.start()
	if err := r.ServeSensor(bg, sensorChannel(g.t, ownFlow(1))); err != nil {
		g.t.Fatal(err)
	}
	tick(g.t, r)
	e, err := event.Decode(storedObservation(g.t, r, 1).Event)
	if err != nil {
		g.t.Fatal(err)
	}
	e.ID.Seq = 0
	if g.base, err = json.Marshal(e); err != nil {
		g.t.Fatal(err)
	}
	return r, st
}

// store appends n records to the observation stream while the node runs:
// refused ones, of another sensor (detector-refused), or valid ones.
func (g *countsRig) store(r *Runtime, n int, refused bool) {
	g.t.Helper()
	b := g.base
	if refused {
		b = editNetobs(g.t, g.base, map[string]string{"sensor_id": `"` + otherSensor + `"`})
	}
	var recs []c5.Record
	for range n {
		recs = append(recs, c5.Record{Stream: NetObservationStream(sensorID), Class: c5.ClassNetworkObservation, Event: b})
	}
	if _, err := r.Log(NetObservationStream(sensorID)).AppendBatch(bg, recs); err != nil {
		g.t.Fatal(err)
	}
}

// logHas reports whether an OS log line holds every part.
func (g *countsRig) logHas(parts ...string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
outer:
	for _, l := range g.logged {
		for _, p := range parts {
			if !strings.Contains(l, p) {
				continue outer
			}
		}
		return true
	}
	return false
}

// crash stops the node with no final step: no counts write, no checkpoint
// and no alarm at the stop.
func crash(r *Runtime) {
	heldManager(r, func() { r.sensorFailed.Store(true) })
	r.Close()
}

// countsEvents are the detector.observation-refused events' details, oldest
// first.
func countsEvents(t *testing.T, r *Runtime) []map[string]string {
	t.Helper()
	_, out := countsEventsAt(t, r)
	return out
}

// countsEventsAt is countsEvents with each event's seq.
func countsEventsAt(t *testing.T, r *Runtime) (seqs []c5.Seq, out []map[string]string) {
	t.Helper()
	var got []c5.Stored
	for after := c5.Seq(0); ; {
		page, err := r.Store(HealthStream).Read(bg, HealthStream, after, 10000)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, page...)
		if len(page) < 10000 {
			break
		}
		after = page[len(page)-1].Key.Seq
	}
	for _, st := range got {
		var e struct {
			Health *event.Health `json:"health"`
		}
		if json.Unmarshal(st.Event, &e) == nil && e.Health != nil && e.Health.Type == event.HealthObservationRefused {
			seqs, out = append(seqs, st.Key.Seq), append(out, e.Health.Details)
		}
	}
	return seqs, out
}

// newest is the newest counts event, or nil.
func newest(t *testing.T, r *Runtime) map[string]string {
	t.Helper()
	if evs := countsEvents(t, r); len(evs) > 0 {
		return evs[len(evs)-1]
	}
	return nil
}

// failCheckpoint makes the detector's checkpoint fail until the test ends
// or the returned func is called.
func failCheckpoint(t *testing.T) func() {
	storeCheckpoint = func(*Runtime, context.Context, *netDetector) (c5.Seq, error) {
		return 0, errors.New("test: the checkpoint is not stored")
	}
	undo := func() { storeCheckpoint = (*Runtime).storeDetectorCheckpoint }
	t.Cleanup(undo)
	return undo
}

// failCounts makes the counts event's write fail until the returned func
// is called.
func failCounts(t *testing.T) func() {
	refusedWrite = func(*Runtime, context.Context, event.Health) (c5.Key, error) {
		return c5.Key{}, errors.New("test: the counts event is not written")
	}
	undo := func() { refusedWrite = (*Runtime).sensorHealth }
	t.Cleanup(undo)
	return undo
}

// marked leaves the store with U > T: n refusals after the checkpoint at
// 1, at seqs 2 to n+1, their counts event written with through n+1 and
// its checkpoint not stored, then a crash. T = 1 and U = n+1. It returns
// the counts event's seq on the health stream.
func (g *countsRig) marked(n int) c5.Seq {
	g.t.Helper()
	r, _ := g.first()
	g.store(r, n, true)
	undo := failCheckpoint(g.t)
	tick(g.t, r)
	seqs, evs := countsEventsAt(g.t, r)
	if len(evs) != 1 || evs[0]["through"] != strconv.Itoa(n+1) {
		g.t.Fatalf("the counts event before the crash: %v", evs)
	}
	crash(r)
	undo()
	return seqs[0]
}

// refusedOf is the detector-refused count in status.
func refusedOf(d DetectorStatus) int64 { return d.RefusedBy[RefusedByDetector] }

// T5 (a): refusals, then quiet checkpoints, then a restart: the counts are
// exact and not marked, and the quiet checkpoints write no counts event.
// The event carries the counts, the seqs, its checkpoint's Through and the
// writer's C13 identifier. Mutant: a start that marks any event whose
// through is below T, which marks them.
func TestRefusedCountsQuietCheckpoints(t *testing.T) {
	g := newCountsRig(t)
	r, _ := g.first()
	g.store(r, 3, true)
	tick(t, r)
	g.store(r, 2, false)
	tick(t, r)
	g.store(r, 1, false)
	tick(t, r)
	evs := countsEvents(t, r)
	want := map[string]string{"stream": string(NetObservationStream(sensorID)), "through": "4", "netobs": netobs.SelfIdentifier(), "count": "3",
		"reason.detector-refused": "3", "first_seq.detector-refused": "2", "last_seq.detector-refused": "4"}
	if len(evs) != 1 || len(evs[0]) != len(want)+1 {
		t.Fatalf("counts events %v", evs)
	}
	for k, v := range want {
		if evs[0][k] != v {
			t.Fatalf("%s = %q, want %q: %v", k, evs[0][k], v, evs[0])
		}
	}
	r.Close()
	r, st := g.start()
	defer r.Close()
	d := detectorStatus(t, st)
	if d.Checkpointed != 7 || refusedOf(d) != 3 || d.Refused != 3 || !d.RefusedExact || d.RefusedUnsure != "" || d.RefusedSince.Format(time.RFC3339Nano) != evs[0]["since"] {
		t.Fatalf("after a restart: %+v", d)
	}
}

// T5 (b): while the counts event's write fails, the checkpoint waits: the
// detector's Through moves and the stored checkpoint does not, and
// store-commit-failed is raised once. A restart in between gives exact
// counts, as the replay counts the refusals again. Once the write
// succeeds the checkpoint follows. Mutant: the checkpoint not held back,
// which loses the interval's refusals at the restart.
func TestRefusedCountsCheckpointWaits(t *testing.T) {
	g := newCountsRig(t)
	r, _ := g.first()
	undo := failCounts(t)
	g.store(r, 2, true)
	tick(t, r)
	g.store(r, 1, false)
	tick(t, r)
	if d := detectorStatus(t, r.opt.Status); d.Through != 4 || d.Checkpointed != 1 || countAlarms(r.opt.Status, string(c5.AlarmCommitFailed)) != 1 {
		t.Fatalf("while the write fails: %+v, %d store-commit-failed", d, countAlarms(r.opt.Status, string(c5.AlarmCommitFailed)))
	}
	r.Close()
	r, st := g.start()
	if d := detectorStatus(t, st); refusedOf(d) != 2 || !d.RefusedExact || d.Checkpointed != 1 {
		t.Fatalf("after a restart in between: %+v", d)
	}
	undo()
	tick(t, r)
	defer r.Close()
	if d := detectorStatus(t, st); d.Checkpointed != 4 || refusedOf(d) != 2 || newest(t, r)["through"] != "4" {
		t.Fatalf("after the write: %+v, %v", d, newest(t, r))
	}
}

// E6-16 (a): a counts event whose first write failed is built when it is
// written: the detector judges a record in between, and the event carries
// the Through of the checkpoint it then precedes. Mutant: the details
// built when it first became owed and retried unchanged, whose through is
// 2, below the checkpoint's.
func TestRefusedCountsBuiltAtWrite(t *testing.T) {
	g := newCountsRig(t)
	r, st := g.first()
	defer r.Close()
	undo := failCounts(t)
	g.store(r, 1, true)
	tick(t, r)
	g.store(r, 1, false)
	undo()
	tick(t, r)
	ev := newest(t, r)
	if d := detectorStatus(t, st); d.Checkpointed != 3 || ev["through"] != "3" || ev["last_seq.detector-refused"] != "2" {
		t.Fatalf("status %+v, event %v", d, ev)
	}
}

// T5 (c), E6-18 (a), (b) and (f), E6-16 (b). A crash after the counts event
// and before its checkpoint: the replay refuses those records again and
// does not count them (the seq rule), and the start marks T+1 to U, cause
// "a crash or a build change" at equal minors. The start's replay passes
// U, so the event owed for the mark is written then, at a Through at or
// above U, carrying unsure, and the counts stay marked after it (a). A
// clean stop and a restart with no refusal between keep the mark from
// unsure although U <= T (b, f), and the next counts event carries it
// again, its count the restored one plus the refusal counted since (E6-16
// (b)). Mutants: the seq rule removed, which counts 4 (T5 (c)); the mark
// cleared at the write (a); the start that ignores unsure when U <= T (b);
// no event owed for the mark alone, so the replay past U writes none (f).
func TestRefusedCountsCrashAfterEvent(t *testing.T) {
	g := newCountsRig(t)
	g.marked(2)
	r, st := g.start()
	d, ev := detectorStatus(t, st), newest(t, r)
	if refusedOf(d) != 2 || d.RefusedExact || d.RefusedUnsure != "2-3" || !strings.Contains(d.RefusedUnsureCause, "(a crash or a build change)") ||
		d.Checkpointed != 3 || ev["unsure"] != "2-3" || ev["through"] != "3" || ev["count"] != "2" {
		t.Fatalf("after the crash: %+v, newest event %v", d, ev)
	}
	r.Close()
	r, st = g.start()
	defer r.Close()
	if d := detectorStatus(t, st); refusedOf(d) != 2 || d.RefusedExact || d.RefusedUnsure != "2-3" || !strings.Contains(d.RefusedUnsureCause, "carried from an earlier start") {
		t.Fatalf("after a clean restart: %+v", d)
	}
	g.store(r, 1, true)
	tick(t, r)
	if ev := newest(t, r); ev["unsure"] != "2-3" || ev["reason.detector-refused"] != "3" || ev["first_seq.detector-refused"] != "2" || ev["last_seq.detector-refused"] != "4" {
		t.Fatalf("the next counts event: %v", ev)
	}
}

// The cause the start names: "a build change" when the newest event's
// envelope schema or netobs detail is not this build's own, at U > T
// (proposal section 4). Each is rewritten in the store, as another build
// would have written it. Control: U = T with netobs changed is not marked.
func TestRefusedCountsCauseBuildChange(t *testing.T) {
	other := "otsec.netobs/0.1"
	if netobs.SelfIdentifier() == other {
		other = "otsec.netobs/0.2"
	}
	for name, edit := range map[string][2]string{
		"netobs": {`"netobs":"` + netobs.SelfIdentifier() + `"`, `"netobs":"` + other + `"`},
		"schema": {`"schema":"` + event.Identifier + `"`, `"schema":"otsec.event/0.5"`},
	} {
		t.Run(name, func(t *testing.T) {
			g := newCountsRig(t)
			corruptEvent(t, g.c, HealthStream, g.marked(1), edit[0], edit[1])
			r, st := g.start()
			defer r.Close()
			if d := detectorStatus(t, st); d.RefusedUnsure != "2-2" || !strings.Contains(d.RefusedUnsureCause, "(a build change)") {
				t.Fatalf("%+v", d)
			}
		})
	}
	g := newCountsRig(t)
	r, _ := g.first()
	g.store(r, 1, true)
	tick(t, r)
	seqs, _ := countsEventsAt(t, r)
	r.Close()
	corruptEvent(t, g.c, HealthStream, seqs[0], `"netobs":"`+netobs.SelfIdentifier()+`"`, `"netobs":"`+other+`"`)
	r, st := g.start()
	defer r.Close()
	if d := detectorStatus(t, st); !d.RefusedExact || d.RefusedUnsure != "" || refusedOf(d) != 1 {
		t.Fatalf("control, U = T: %+v", d)
	}
}

// slowReplay is a detector that takes one observation per drive.
func slowReplay() SensorSeams {
	return SensorSeams{Observe: func() { time.Sleep(DriveTime + 50*time.Millisecond) }}
}

// E6-18 (c): with U > T and a slow replay, the start's checkpoint attempt
// between T and U is not stored, and a crash before any counts event
// leaves the next start marking the full range T+1 to U. The same with a
// clean stop in place of the crash. Mutants: the checkpoint between T and
// U stored, which narrows the range at the next start; in the stop run,
// the stop's checkpoint stored without the owed event, the same.
func TestRefusedCountsMarkHeldBelowU(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(fmt.Sprintf("clean-stop=%v", stop), func(t *testing.T) {
			g := newCountsRig(t)
			g.marked(20)
			g.seams = slowReplay()
			r, st := g.start()
			if d := detectorStatus(t, st); d.Through < 2 || d.Through >= 21 || d.Checkpointed != 1 || d.RefusedUnsure != "2-21" {
				t.Fatalf("the start's step: %+v", d)
			}
			if stop {
				r.Close()
			} else {
				crash(r)
			}
			g.seams = SensorSeams{}
			r, st = g.start()
			defer r.Close()
			if d := detectorStatus(t, st); d.RefusedUnsure != "2-21" || d.RefusedExact {
				t.Fatalf("the next start: %+v", d)
			}
		})
	}
}

// E6-18 (d) and (g): a carried range 2-3, from a crash at T=1 and U=3, and
// a new U=7 above T=5 at one start: the range widens to 2-7, the carried
// start and U, and the widening owes an event, which the replay past 7
// writes. After a clean stop the restart shows 2-7, and the newest event
// carries it. Mutants: the new range replacing the carried one (6-7); the
// carried one kept and the new one dropped (2-3); an event owed when a
// range is set and not when it is widened, which leaves 2-3 in the newest
// event and the restart's status.
func TestRefusedCountsMarkWidened(t *testing.T) {
	g := newCountsRig(t)
	g.marked(2)
	r, _ := g.start() // carried 2-3, written at 3, checkpoint 3
	g.store(r, 2, false)
	tick(t, r) // checkpoint 5
	g.store(r, 2, true)
	undo := failCheckpoint(t)
	tick(t, r) // the event at 7, its checkpoint not stored
	if ev := newest(t, r); ev["through"] != "7" || ev["unsure"] != "2-3" {
		t.Fatalf("before the crash: %v", ev)
	}
	crash(r)
	undo()
	r, st := g.start()
	d, ev := detectorStatus(t, st), newest(t, r)
	if d.RefusedUnsure != "2-7" || !strings.Contains(d.RefusedUnsureCause, "widened") || ev["unsure"] != "2-7" || ev["through"] != "7" || refusedOf(d) != 4 {
		t.Fatalf("the widened start: %+v, newest event %v", d, ev)
	}
	r.Close()
	r, st = g.start()
	defer r.Close()
	if d, ev := detectorStatus(t, st), newest(t, r); d.RefusedUnsure != "2-7" || d.RefusedExact || ev["unsure"] != "2-7" {
		t.Fatalf("after a clean restart: %+v, newest event %v", d, ev)
	}
}

// pruneHealth prunes the whole health stream, as Runtime.Prune would
// behind a consumer that confirmed it all. The rig's health stream has no
// consumer, so the test names one.
func pruneHealth(t *testing.T, r *Runtime) {
	t.Helper()
	db := r.Store(HealthStream)
	last, err := db.LastCommitted(bg, HealthStream)
	if err != nil {
		t.Fatal(err)
	}
	cs := []c5.Consumer{{ID: "test-pruner", Stream: HealthStream, Delivery: c5.Required}}
	if err := db.SaveCursor(bg, c5.Cursor{Consumer: cs[0].ID, Stream: HealthStream, Through: last}); err != nil {
		t.Fatal(err)
	}
	b, err := c5.ComputeBoundary(bg, db, db, cs, HealthStream, c5.ClassPlatform, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if k, err := db.PruneStep(bg, b, 1<<20); err != nil || k == 0 {
		t.Fatalf("pruned %d: %v", k, err)
	}
}

// fillHealth commits n other health records.
func fillHealth(t *testing.T, r *Runtime, n int) {
	t.Helper()
	for n > 0 {
		k := min(n, 100)
		recs := make([]c5.Record, k)
		for i := range recs {
			rec, err := r.healthRecord(HealthStream, "store.test", map[string]string{"i": strconv.Itoa(i)})
			if err != nil {
				t.Fatal(err)
			}
			recs[i] = rec
		}
		if _, err := r.Log(HealthStream).AppendBatch(bg, recs); err != nil {
			t.Fatal(err)
		}
		n -= k
	}
}

// T5 (e), T6 and E6-18 (e): the counts begin again, with a new since and
// through 0, when the newest counts event is past the start's scan, when
// it was pruned, and when the checkpoint does not restore; a carried mark
// is not carried across the new since, so the counts show as exact and the
// next counts event carries no unsure. Without a restored checkpoint the
// replay counts each retained refused record once (T6). Control: the
// event retained and within the scan keeps the counts, their since and
// the mark. Mutants: the range carried across a new since; the counts
// reported under the old since once its event is not found.
func TestRefusedCountsBeginAgain(t *testing.T) {
	for _, leg := range []string{"retained", "past-scan", "pruned", "not-restored"} {
		t.Run(leg, func(t *testing.T) {
			g := newCountsRig(t)
			g.marked(2)
			r, st := g.start() // marked 2-3, written with unsure
			old := detectorStatus(t, st).RefusedSince
			switch leg {
			case "past-scan":
				fillHealth(t, r, refusedCountsScan)
			case "pruned":
				pruneHealth(t, r)
			case "not-restored":
				foreignCheckpoint(t, r)
			}
			r.Close()
			g.advance(time.Hour)
			r, st = g.start()
			defer r.Close()
			d := detectorStatus(t, st)
			switch leg {
			case "retained":
				if refusedOf(d) != 2 || !d.RefusedSince.Equal(old) || d.RefusedUnsure != "2-3" {
					t.Fatalf("control: %+v", d)
				}
				return
			case "not-restored":
				if refusedOf(d) != 2 || d.Restored {
					t.Fatalf("each retained refused record once: %+v", d)
				}
			default:
				if refusedOf(d) != 0 {
					t.Fatalf("counts: %+v", d)
				}
			}
			if !d.RefusedExact || d.RefusedUnsure != "" || !d.RefusedSince.Equal(g.now()) {
				t.Fatalf("begun again: %+v", d)
			}
			g.store(r, 1, true)
			tick(t, r)
			if ev := newest(t, r); ev["unsure"] != "" || ev["since"] != g.now().Format(time.RFC3339Nano) {
				t.Fatalf("the next counts event: %v", ev)
			}
		})
	}
}

// T5 (d): a counts write held past RefusedCountsWait (the seam clock): the
// checkpoint is stored, network-refused-counts-unwritten raised once with
// the range and "a lower bound", network-detector-checkpoint-failed not
// raised, and the counts shown not exact with the range; a later
// checkpoint while the event is still owed is stored at its step, not
// held another hour. A restart before the event is written shows the
// counts as exact, as section 2.4's limit states, and the alarm's range is
// in the OS log. The alarm is raised again an hour after its last raise
// while the event is still owed, and at the stop. Control: the write
// succeeds within the bound, and nothing is marked or raised. Mutants: no
// bound; the bound restarted at each forced checkpoint; a raise at every
// step; a re-raise only past the hour; no raise at the stop.
func TestRefusedCountsForcedCheckpoint(t *testing.T) {
	g := newCountsRig(t)
	r, st := g.first()
	failCounts(t)
	g.store(r, 2, true)
	tick(t, r)
	g.advance(RefusedCountsWait)
	g.store(r, 1, false)
	tick(t, r)
	d := detectorStatus(t, st)
	alarm := adminAlarm(st, AlarmRefusedCountsUnwritten)
	if d.Checkpointed != 4 || d.RefusedExact || d.RefusedUnsure != "2-3" || countAlarms(st, AlarmRefusedCountsUnwritten) != 1 ||
		!strings.Contains(alarm, "at seqs 2-3 ") || !strings.Contains(alarm, "as a lower bound") || countAlarms(st, AlarmDetectorCheckpoint) != 0 {
		t.Fatalf("past the wait: %+v, %d alarms %q, %d checkpoint-failed", d, countAlarms(st, AlarmRefusedCountsUnwritten), alarm, countAlarms(st, AlarmDetectorCheckpoint))
	}
	g.store(r, 1, false)
	tick(t, r)
	if d := detectorStatus(t, st); d.Checkpointed != 5 || countAlarms(st, AlarmRefusedCountsUnwritten) != 1 {
		t.Fatalf("the next step: %+v", d)
	}
	g.advance(time.Hour)
	tick(t, r)
	if n := countAlarms(st, AlarmRefusedCountsUnwritten); n != 2 {
		t.Fatalf("an hour later, still owed: %d alarms", n)
	}
	g.advance(time.Minute)
	r.Close()
	if n := countAlarms(st, AlarmRefusedCountsUnwritten); n != 3 {
		t.Fatalf("at the stop, still owed: %d alarms", n)
	}
	refusedWrite = (*Runtime).sensorHealth
	r, st = g.start()
	defer r.Close()
	if d := detectorStatus(t, st); !d.RefusedExact || refusedOf(d) != 0 || !g.logHas(AlarmRefusedCountsUnwritten, "at seqs 2-3 ") {
		t.Fatalf("after a restart: %+v", d)
	}

	g = newCountsRig(t)
	r, st = g.first()
	defer r.Close()
	undo := failCounts(t)
	g.store(r, 2, true)
	tick(t, r)
	g.advance(RefusedCountsWait / 2)
	undo()
	tick(t, r)
	if d := detectorStatus(t, st); !d.RefusedExact || d.Checkpointed != 3 || countAlarms(st, AlarmRefusedCountsUnwritten) != 0 {
		t.Fatalf("control: %+v", d)
	}
}

// The budget: at most RefusedCountsPerHour counts events an hour; a fifth
// change in the hour holds its checkpoint until the oldest write is an
// hour old (section 5). Mutants: no budget, or one more, which writes a
// fifth; a write that leaves the hour only past an hour, which holds it
// at exactly an hour.
func TestRefusedCountsBudget(t *testing.T) {
	g := newCountsRig(t)
	r, st := g.first()
	defer r.Close()
	for range RefusedCountsPerHour + 1 {
		g.store(r, 1, true)
		tick(t, r)
		g.advance(time.Minute)
	}
	if n, d := len(countsEvents(t, r)), detectorStatus(t, st); n != RefusedCountsPerHour || d.Checkpointed != 5 || d.Through != 6 {
		t.Fatalf("%d counts events, status %+v", n, d)
	}
	g.advance(55 * time.Minute) // the oldest write is now exactly an hour old
	tick(t, r)
	if n, d := len(countsEvents(t, r)), detectorStatus(t, st); n != RefusedCountsPerHour+1 || d.Checkpointed != 6 || !d.RefusedExact {
		t.Fatalf("an hour later: %d counts events, status %+v", n, d)
	}
}

// E6-18 (h): the forced checkpoint of an event owed for the mark alone,
// with no refusal after the start, then a crash, so that the stop raises
// nothing. With the replay held, the forced checkpoint F is between T and
// U: F is stored, the mark-only alarm is raised once, naming T+1 to U and
// the cause "replay below U", and the restart marks F+1 to U. With the
// write failing, F is at or above U: F is stored, the alarm is raised once
// naming the write's failure, and the restart shows the counts as exact.
// Mutant: the alarm raised only when counts are owed, which raises none.
func TestRefusedCountsForcedMarkOnly(t *testing.T) {
	t.Run("replay-held", func(t *testing.T) {
		g := newCountsRig(t)
		g.marked(20)
		g.seams = slowReplay()
		r, st := g.start()
		g.advance(RefusedCountsWait)
		tick(t, r)
		d, alarm := detectorStatus(t, st), adminAlarm(st, AlarmRefusedCountsUnwritten)
		f := d.Checkpointed
		if f < 2 || f >= 21 || countAlarms(st, AlarmRefusedCountsUnwritten) != 1 || !strings.Contains(alarm, "the mark that the counts of refused observations may be wrong for seqs 2-21 ") ||
			!strings.Contains(alarm, "(replay below 21)") {
			t.Fatalf("forced: %+v, %d alarms %q", d, countAlarms(st, AlarmRefusedCountsUnwritten), alarm)
		}
		crash(r)
		g.seams = SensorSeams{}
		r, st = g.start()
		defer r.Close()
		if d := detectorStatus(t, st); d.RefusedUnsure != fmt.Sprintf("%d-21", f+1) {
			t.Fatalf("the restart, F = %d: %+v", f, d)
		}
	})
	t.Run("write-fails", func(t *testing.T) {
		g := newCountsRig(t)
		g.marked(2)
		undo := failCounts(t)
		r, st := g.start()
		g.advance(RefusedCountsWait)
		tick(t, r)
		d, alarm := detectorStatus(t, st), adminAlarm(st, AlarmRefusedCountsUnwritten)
		if d.Checkpointed != 3 || countAlarms(st, AlarmRefusedCountsUnwritten) != 1 || !strings.Contains(alarm, "seqs 2-3 ") ||
			!strings.Contains(alarm, "(its write failed: ") {
			t.Fatalf("forced: %+v, %d alarms %q", d, countAlarms(st, AlarmRefusedCountsUnwritten), alarm)
		}
		crash(r)
		undo()
		r, st = g.start()
		defer r.Close()
		if d := detectorStatus(t, st); !d.RefusedExact || d.RefusedUnsure != "" || refusedOf(d) != 2 {
			t.Fatalf("the restart: %+v", d)
		}
	})
}

// E6-18 (i): both ranges live. A start with U > T (2-11), then a counted
// refusal at 12 held past RefusedCountsWait: status shows one range from
// T+1 to the counted range's end, 2-12, not exact, and its cause names
// both; the alarm is the counts form with that range and reads "not
// exact". Once the event is written, its unsure is T+1 to U only. Mutants:
// the counted range put into unsure, which writes 2-12; the combined alarm
// reading "a lower bound".
func TestRefusedCountsBothRanges(t *testing.T) {
	g := newCountsRig(t)
	g.marked(10)
	undo := failCounts(t)
	r, st := g.start()
	defer r.Close()
	g.store(r, 1, true)
	g.advance(RefusedCountsWait)
	tick(t, r)
	d, alarm := detectorStatus(t, st), adminAlarm(st, AlarmRefusedCountsUnwritten)
	if d.RefusedUnsure != "2-12" || d.RefusedExact || !strings.Contains(d.RefusedUnsureCause, "(a crash or a build change)") ||
		!strings.Contains(d.RefusedUnsureCause, "seqs 12-12 counted since the last counts event") ||
		!strings.Contains(alarm, "at seqs 2-12 ") || !strings.Contains(alarm, "as not exact") {
		t.Fatalf("both live: %+v, alarm %q", d, alarm)
	}
	undo()
	tick(t, r)
	if ev, d := newest(t, r), detectorStatus(t, st); ev["unsure"] != "2-11" || ev["through"] != "12" || d.RefusedUnsure != "2-11" {
		t.Fatalf("written: %v, status %+v", ev, d)
	}
}

// T10: the counts event at its largest, every reason with every count and
// seq at 2^64 - 1, unsure at both ends 2^64 - 1, since with nanoseconds and
// a +14:00 offset, and the longest node ID, is valid and renders for a
// default Syslog target within three quarters of its 2,048 octets, as
// TestSensorDropEventFits pins for intake.drop-counted.
func TestRefusedCountsEventFits(t *testing.T) {
	const top = math.MaxUint64
	rc := refusedCounts{since: time.Date(2026, 11, 1, 0, 0, 0, 123456789, time.FixedZone("", 14*3600)), by: map[string]refusedReason{},
		unsure: refusedRange{top, top}}
	for _, reason := range event.ObservationRefusedReasons {
		rc.by[reason] = refusedReason{top / 3, top, top}
	}
	det := rc.details(NetObservationStream(sensorID), top)
	if len(det) != 15 || !strings.Contains(det["since"], "+14:00") {
		t.Fatalf("%d details: %v", len(det), det)
	}
	for k := range det {
		if strings.HasPrefix(k, "reason.") {
			det[k] = strconv.FormatUint(top/3, 10)
		}
	}
	e := &event.Event{Schema: event.Identifier, ID: event.EventID{NodeID: event.NodeID(strings.Repeat("n", 63)), Stream: event.Stream(HealthStream), Seq: top >> 1},
		Origin: event.OriginPlatform, Kind: event.KindHealth, Source: event.Source{OriginAuth: event.AuthPlatform},
		Received: event.Received{UTC: "2026-11-01T00:00:00.000000001Z", ResolutionNS: 1, Clock: event.Clock{Sync: event.SyncSynchronized, Source: "ntp"}},
		Health:   &event.Health{Type: event.HealthObservationRefused, Details: det}}
	tg, err := syslog.ParseTarget([]byte(`{"schema": "otsec.syslog/0.1", "name": "central", "host": "collector.example", "port": 6514,
		"transport": "tls", "format": "rfc5424", "framing": "octet-counting", "class": "best-effort", "replay_seconds": 3600, "max_message_octets": 2048,
		"tls": {"server_name": "collector.example", "trust_anchor_ref": "ca"}}`))
	if err != nil {
		t.Fatal(err)
	}
	msg, out, err := syslog.Render(e, tg)
	if err != nil || out.SummaryDropped || len(msg) > syslog.DefaultMaxOctets*3/4 {
		t.Fatalf("%d octets (limit %d), %+v, %v: %s", len(msg), syslog.DefaultMaxOctets*3/4, out, err, msg)
	}
	t.Logf("worst case: %d octets", len(msg))
}

// A start whose new range T+1 to U lies inside the carried one changes
// nothing and owes no event (proposal section 4, "Two ranges"): a crash
// after the event owed for a mark was written and before its checkpoint
// leaves both ranges 2-3. Mutant: an event owed at every U > T, which
// writes a third.
func TestRefusedCountsMarkInside(t *testing.T) {
	g := newCountsRig(t)
	g.marked(2)
	undo := failCheckpoint(t)
	r, _ := g.start() // writes the mark's event at 3, its checkpoint not stored
	if ev := newest(t, r); ev["unsure"] != "2-3" || detectorStatus(t, r.opt.Status).Checkpointed != 1 {
		t.Fatalf("before the crash: %v", ev)
	}
	crash(r)
	undo()
	r, st := g.start()
	defer r.Close()
	d := detectorStatus(t, st)
	if n := len(countsEvents(t, r)); n != 2 || d.RefusedUnsure != "2-3" || d.RefusedUnsureCause != "carried from an earlier start" || d.Checkpointed != 3 {
		t.Fatalf("%d counts events, status %+v", n, d)
	}
}

// A failed read of the health stream during the start's scan fails the
// start, under network-detector-not-started, and the next tick tries
// again, so the counts are not begun again on a transient fault (self-check
// item 3). Control: the start that then succeeds restores them. Mutant: a
// failed read taken as no event found, which begins the counts again.
func TestRefusedCountsScanReadFails(t *testing.T) {
	g := newCountsRig(t)
	r, _ := g.first()
	g.store(r, 2, true)
	tick(t, r)
	r.Close()
	fail := true
	readHealthPage = func(db *store.DB, ctx context.Context, s c5.StreamID, after c5.Seq, n int) ([]c5.Stored, error) {
		if fail {
			return nil, errors.New("test: the health stream's read fails")
		}
		return db.Read(ctx, s, after, n)
	}
	t.Cleanup(func() { readHealthPage = (*store.DB).Read })
	g.advance(time.Hour)
	r, st := g.start()
	defer r.Close()
	var down bool
	heldManager(r, func() { down, fail = r.detector == nil, false })
	if !down || countAlarms(st, AlarmDetectorNotStarted) != 1 {
		t.Fatalf("the failed read: detector down %v, %d not-started", down, countAlarms(st, AlarmDetectorNotStarted))
	}
	tick(t, r)
	if d := detectorStatus(t, st); refusedOf(d) != 2 || d.RefusedSince.Equal(g.now()) || !d.RefusedExact {
		t.Fatalf("the next start: %+v", d)
	}
}
