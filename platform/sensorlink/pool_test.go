package sensorlink

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// emitted is a pool's writes, in order.
type emitted struct {
	at    []time.Duration
	names []string
	rises []uint64
	merge []uint64
}

func (e *emitted) emit(now *time.Duration) func(context.Context, *HeldEvent) error {
	return func(_ context.Context, h *HeldEvent) error {
		e.at, e.names = append(e.at, *now), append(e.names, h.Name)
		e.rises, e.merge = append(e.rises, h.Rises["packets"]), append(e.merge, h.Merged)
		return nil
	}
}

func (e *emitted) of(name string) (n int, at []time.Duration, rises, merged uint64) {
	for i, x := range e.names {
		if x == name {
			n++
			at = append(at, e.at[i])
			rises += e.rises[i]
			merged += e.merge[i]
		}
	}
	return
}

// K-5 (CH-45): sensor.counters due every minute for an hour is written at
// most 4 times in the hour, none sooner than 10 minutes after its last,
// and every rise is carried, merged, into the next; another pool name due
// 10 times in the hour is written at most 4 times, its writes carrying
// the merged count. Controls: no per-name cap, under which the second
// name is written more than 4 times; and the 10 minutes not kept, under
// which two sensor.counters come less than 10 minutes apart.
func TestPoolPerNameCap(t *testing.T) {
	run := func(p *Pool) (*emitted, uint64, uint64) {
		e := &emitted{}
		for m := range 60 {
			now := time.Hour + time.Duration(m)*time.Minute
			p.Due(HeldEvent{Name: EventCounters, Key: testRun, Rises: map[string]uint64{"packets": 7}})
			if m%6 == 0 {
				p.Due(HeldEvent{Name: AlarmBufferSmall})
			}
			if err := p.Write(bg, now, e.emit(&now)); err != nil {
				t.Fatal(err)
			}
		}
		var left, leftMerged uint64
		for _, w := range p.Waiting() {
			switch w.Name {
			case EventCounters:
				left = w.Rises["packets"]
			case AlarmBufferSmall:
				leftMerged = w.Merged
			}
		}
		return e, left, leftMerged
	}
	e, left, leftMerged := run(NewPool())
	n, at, rises, _ := e.of(EventCounters)
	if n > PoolPerName || n == 0 {
		t.Fatalf("sensor.counters written %d times in the hour", n)
	}
	for i := 1; i < len(at); i++ {
		if at[i]-at[i-1] < CountersSpacing {
			t.Fatalf("sensor.counters at %v after %v", at[i], at[i-1])
		}
	}
	if rises+left != 60*7 {
		t.Fatalf("rises written %d and waiting %d, want %d carried", rises, left, 60*7)
	}
	m, _, _, merged := e.of(AlarmBufferSmall)
	if m > PoolPerName || merged+leftMerged != 10 {
		t.Fatalf("%s written %d times carrying %d, %d waiting; want at most %d writes carrying the 10 due", AlarmBufferSmall, m, merged, leftMerged, PoolPerName)
	}
	t.Logf("sensor.counters %d times at %v, %d rises written and %d waiting; %s %d times", n, at, rises, left, AlarmBufferSmall, m)

	noCap := NewPool()
	noCap.perName = PoolPerHour
	e, _, _ = run(noCap)
	if m, _, _, _ := e.of(AlarmBufferSmall); m <= PoolPerName {
		t.Fatalf("control without the per-name cap: %s written %d times; the test cannot tell", AlarmBufferSmall, m)
	}
	noSpacing := NewPool()
	noSpacing.spacing = 0
	e, _, _ = run(noSpacing)
	if _, at, _, _ := e.of(EventCounters); len(at) < 2 || at[1]-at[0] >= CountersSpacing {
		t.Fatalf("control without the spacing: sensor.counters at %v; the test cannot tell", at)
	}
}

// fillPool spends the pool's 24, one a second from start, with 6 other
// names, 4 each. At start + 1 h + (k-1) s the first k have left the hour.
func fillPool(t *testing.T, p *Pool, start time.Duration) {
	t.Helper()
	e := &emitted{}
	for i := range PoolPerHour {
		now := start + time.Duration(i)*time.Second
		p.Due(HeldEvent{Name: "sensor-fill-" + string(rune('a'+i/PoolPerName)), Key: string(rune('a' + i))})
		if err := p.Write(bg, now, e.emit(&now)); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.names) != PoolPerHour {
		t.Fatalf("filled %d", len(e.names))
	}
}

// K-6 (CH-45): the pool spent, then a sensor.counters, a sensor.run-loss,
// an alarm's event and a sensor.redial-granted due together: with room for
// one, sensor.redial-granted is written and the rest wait; with room for
// three, only sensor.counters waits; each waiting event is counted in
// health_held, held in sensorrun.json as its facts, and written first when
// room returns. A lost coverage gap due meanwhile is written under its own
// budget, never held in the pool. Controls: a pool that writes in arrival
// order (no rank), under which the alarm goes first (run here); and M19,
// a lost gap put through the pool, which the spent pool holds.
func TestPoolWaitOrder(t *testing.T) {
	due := []string{EventCounters, EventRunLoss, AlarmBufferSmall, EventRedialGranted}
	order := func(p *Pool, room int) []string {
		start := time.Hour
		fillPool(t, p, start)
		for _, n := range due {
			p.Due(HeldEvent{Name: n})
		}
		e, now := &emitted{}, start+time.Minute
		if err := p.Write(bg, now, e.emit(&now)); err != nil || len(e.names) != 0 || p.Held != 4 {
			t.Fatalf("with the pool spent: written %v, health_held %d, %v", e.names, p.Held, err)
		}
		now = start + time.Hour + time.Duration(room-1)*time.Second
		if err := p.Write(bg, now, e.emit(&now)); err != nil {
			t.Fatal(err)
		}
		return e.names
	}
	if got := order(NewPool(), 1); !slices.Equal(got, []string{EventRedialGranted}) {
		t.Fatalf("room for one: written %v", got)
	}
	p := NewPool()
	if got := order(p, 3); !slices.Equal(got, []string{EventRedialGranted, AlarmBufferSmall, EventRunLoss}) {
		t.Fatalf("room for three: written %v", got)
	}
	if w := p.Waiting(); len(w) != 1 || w[0].Name != EventCounters || p.Held != 4 {
		t.Fatalf("waiting %+v, health_held %d", w, p.Held)
	}
	arrival := NewPool()
	arrival.rankOf = func(string) int { return 0 }
	if got := order(arrival, 1); slices.Equal(got, []string{EventRedialGranted}) {
		t.Fatalf("control in arrival order wrote %v; the test cannot tell", got)
	}

	// Through Health: the waiting events are held in sensorrun.json as
	// their facts, never as event bytes, and a lost gap goes under its own
	// budget while the pool is spent.
	r := newHealthRig(t)
	h := r.h
	h.mu.Lock()
	fillPool(t, h.pool, r.clk.mono())
	h.mu.Unlock()
	for _, n := range []string{EventRedialGranted, AlarmBufferSmall} {
		h.Event(bg, n, map[string]string{"generation": "2"})
	}
	pe := r.accepted(hello02())
	r.tickAfter(pe, spanTick(1, lspan("09:00:00", "09:10:00")))
	pe.send(obs02(1))
	pe.ack(1)
	if got := r.sink.count(EventCoverageGap); got != 1 {
		t.Fatalf("%d lost gaps written with the pool spent", got)
	}
	r.clk.add(time.Minute)
	if err := h.Flush(bg); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	var doc runFileDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var held []string
	for _, e := range doc.Sensors[testSensor].Held {
		held = append(held, e.Name)
	}
	if !slices.Contains(held, EventRedialGranted) || !slices.Contains(held, AlarmBufferSmall) || slices.Contains(held, EventRunLoss) {
		t.Fatalf("sensorrun.json holds %v", held)
	}
	if strings.Contains(string(b), "otsec.event/") {
		t.Fatalf("event bytes in sensorrun.json: %s", b)
	}
	if st := h.Status(); st.HealthHeld == 0 {
		t.Fatalf("status %+v", st)
	}
}

// The pool's and the run file's boundaries (self-check item 2): a
// sensor.counters exactly 10 minutes after its last is written and one a
// nanosecond sooner waits; a slot spent exactly an hour ago is free again
// and one a nanosecond younger is not; the run file is written again
// exactly a minute after its last write and not a nanosecond sooner. Each
// comparison's off-by-one mutant fails one of the two cases.
func TestPoolBoundaries(t *testing.T) {
	at := func(p *Pool, name string, now time.Duration) bool {
		p.Due(HeldEvent{Name: name, Key: testRun, Rises: map[string]uint64{"packets": 1}})
		e := &emitted{}
		if err := p.Write(bg, now, e.emit(&now)); err != nil {
			t.Fatal(err)
		}
		return len(e.names) == 1
	}
	start := time.Hour
	p := NewPool()
	if !at(p, EventCounters, start) || at(p, EventCounters, start+CountersSpacing-1) || !at(p, EventCounters, start+CountersSpacing) {
		t.Fatal("sensor.counters' spacing is not 10 minutes exactly")
	}
	p = NewPool()
	fillPool(t, p, start)
	if at(p, AlarmBufferSmall, start+time.Hour-1) || !at(p, AlarmBufferSmall, start+time.Hour) {
		t.Fatal("the pool's hour is not an hour exactly")
	}

	r := newHealthRig(t)
	written := func() uint64 { r.file.mu.Lock(); defer r.file.mu.Unlock(); return r.file.doc.WriteNo }
	r.h.Event(bg, AlarmBufferSmall, nil) // the first write
	w := written()
	r.clk.add(time.Minute - 1)
	r.h.Event(bg, AlarmBufferSmall, nil)
	if written() != w {
		t.Fatal("the run file written within its minute")
	}
	r.clk.add(1)
	if err := r.h.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if written() != w+1 {
		t.Fatal("the run file not written once its minute passed")
	}
}
