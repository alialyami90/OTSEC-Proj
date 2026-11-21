package sensorlink

import (
	"fmt"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// The test-only C13 source of the break and tie rows (C13 0.2 T-8, T-13;
// docs/phase4/D5-sensor-node.md sections 1.5 and 1.6), desk only: an
// in-memory pipe and the rig's test clocks; no sensor and no device.

// rigStart is the rig's start; trueNow is true time on the rig, its start
// plus the monotonic time passed. The node's wall clock is true time plus
// every step the test made (rig.addWall).
var rigStart = time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)

func (r *rig) trueNow() time.Time { return rigStart.Add(r.clk.mono() - time.Hour) }

// live02 is hello02 with nothing buffered, newest_seq first_seq - 1, so
// the first backlog after a start is through at the hello (CH-39) and the
// records that follow are read live.
func live02() *netobs.SensorHello {
	h := hello02()
	h.NewestSeq = "0"
	return h
}

// inv is the invocation of the rig's own session n.
func inv(n int) string { return fmt.Sprintf("0e4d8a2c-6b1f-4c3e-9a5d-%012d", n) }

// dialFails dispatches own session n to the relay's endpoint and gives its
// Result after d of true time, the sensor running: a dial that failed,
// recorded over [dispatch, dispatch + d] on the node's wall clock. No flow
// of it is sent, so with nothing tied it enters the late index.
func (s *sim) dialFails(n int, d time.Duration) Session {
	s.t.Helper()
	r := s.r
	req := fmt.Sprintf("req-%d", n)
	if err := r.l.Dispatch(bg, HoldRun{RequestID: req, AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
		s.t.Fatal(err)
	}
	from := r.now()
	s.pass(d)
	ss := Session{InvocationID: inv(n), StartedAt: from, EndedAt: r.now()}
	if _, err := r.l.Result(bg, req, ss); err != nil {
		s.t.Fatal(err)
	}
	return ss
}

// sim is one sensor: its clock is true time plus off; it numbers each
// record in seq order and keeps it until it is sent, and while connected
// it sends what it numbers, unless hold is set, and ticks every 10 s of
// true time. With heartbeats set it makes a heartbeat every 10 s, as the
// agent does whether or not a connection is open (CH-39).
type sim struct {
	t       *testing.T
	r       *rig
	p       *peer
	en      Enrolment
	run     string
	counter int
	newRun  bool // the next hello begins the run
	off     time.Duration
	seq     int // the last seq numbered
	sent    int // the last seq sent
	drops   int
	buf     []any
	bufAt   []time.Time // the true time each kept record was made
	hold    bool
	// manual: no tick unless the test sends one.
	manual bool
	spans  []netobs.Span
	pk     uint64
	hbAt   time.Time
	tickAt time.Time
	beats  bool
}

func newSim(r *rig) *sim {
	return &sim{t: r.t, r: r, en: enrolment(), run: testRun, counter: 5, newRun: true}
}

// now is the sensor's clock.
func (s *sim) now() time.Time { return s.r.trueNow().Add(s.off) }

// connect dials and has the run's hello accepted: first_seq after the last
// seq sent, newest_seq the last numbered, current as given. What is
// numbered and not held is sent after it.
func (s *sim) connect(current bool) {
	s.t.Helper()
	if s.p != nil {
		s.t.Fatal("connect while connected")
	}
	h := hello02()
	h.Generation, h.RunID, h.RunCounter = itoa(int(s.en.Generation)), s.run, itoa(s.counter)
	h.FirstSeq, h.NewestSeq, h.DropsChannel = itoa(s.sent+1), itoa(s.seq), itoa(s.drops)
	h.Lost, h.Current, h.SensorUTC = append([]netobs.Span{}, s.spans...), ptr(current), canonUTC(s.now())
	if !s.newRun {
		h.Prior = nil
	}
	s.p = s.r.dial(s.en)
	s.p.send(h)
	s.p.ack(uint64(s.sent))
	s.newRun = false
	s.tickAt = s.r.trueNow().Add(10 * time.Second)
	if !s.hold {
		s.flush()
	}
}

// cut ends the connection from the sensor's side.
func (s *sim) cut() {
	s.t.Helper()
	s.p.end()
	s.p = nil
}

// write numbers v and keeps it; while connected and not holding, sends it.
func (s *sim) write(v any) {
	s.t.Helper()
	s.seq++
	switch x := v.(type) {
	case *netobs.Observation:
		x.Seq, x.RunID = itoa(s.seq), s.run
		x.Citation.CaptureID = "ring:" + s.run + ":3" // the ring of the record's run
		if x.MadeUTC == "" {
			x.MadeUTC = canonUTC(s.now())
		}
	case *netobs.Heartbeat:
		x.Seq, x.RunID = itoa(s.seq), s.run
	}
	s.buf, s.bufAt = append(s.buf, v), append(s.bufAt, s.r.trueNow())
	if s.p != nil && !s.hold {
		s.flush()
	}
}

// flow writes a record of the node's own flow from port sport to the
// relay's endpoint, its start captured at the sensor's time at, and made
// at made (zero: now on the sensor's clock); end makes it the flow's end.
func (s *sim) flow(sport int, at, made time.Time, end bool) {
	s.t.Helper()
	o := ownFlow02(0, sport, at, end)
	if !made.IsZero() {
		o.MadeUTC = canonUTC(made)
	} else {
		o.MadeUTC = ""
	}
	s.write(o)
}

// synEnd writes the syn_only end of the node's own flow from port sport,
// its start captured at the sensor's time at and made at made (zero: now
// on the sensor's clock): a dial's SYN that had no answer, the one late
// record a failed dial's entry ties (D1's ruling 1 on #770).
func (s *sim) synEnd(sport int, at, made time.Time) {
	s.t.Helper()
	o := ownFlow02(0, sport, at, true)
	o.Flow.SynOnly = ptr(true)
	if !made.IsZero() {
		o.MadeUTC = canonUTC(made)
	} else {
		o.MadeUTC = ""
	}
	s.write(o)
}

// flush sends every record kept.
func (s *sim) flush() {
	s.t.Helper()
	for _, v := range s.buf {
		s.p.send(v)
		s.sent = int(num(seqOf(v)))
	}
	s.buf, s.bufAt = nil, nil
	s.p.taken()
}

func seqOf(v any) string {
	switch x := v.(type) {
	case *netobs.Observation:
		return x.Seq
	case *netobs.Heartbeat:
		return x.Seq
	}
	return ""
}

// evict drops every kept record made in [from, to] of true time, as the
// agent evicts from its buffer: drops_channel rises by their number and
// the run states their span, from the earliest to the latest made on the
// sensor's clock (CH-40).
func (s *sim) evict(from, to time.Time) {
	s.t.Helper()
	var buf []any
	var at []time.Time
	var lo, hi time.Time
	for i, v := range s.buf {
		if at := s.bufAt[i]; !at.Before(from) && !at.After(to) {
			m := madeOf(v)
			if lo.IsZero() || m.Before(lo) {
				lo = m
			}
			if m.After(hi) {
				hi = m
			}
			s.drops++
			continue
		}
		buf, at = append(buf, v), append(at, s.bufAt[i])
	}
	s.buf, s.bufAt = buf, at
	if !lo.IsZero() {
		s.spans = append(s.spans, netobs.Span{FromUTC: canonUTC(lo), ToUTC: canonUTC(hi)})
	}
}

func madeOf(v any) time.Time {
	switch x := v.(type) {
	case *netobs.Observation:
		return parseUTC(x.MadeUTC)
	case *netobs.Heartbeat:
		return parseUTC(x.AtUTC)
	}
	return time.Time{}
}

// tick sends a tick on the sensor's clock: newest the last numbered, sent
// the last sent, the run's drops and spans.
func (s *sim) tick() {
	s.t.Helper()
	tk := tick02(s.seq, s.sent, s.drops)
	tk.RunID, tk.SensorUTC, tk.Lost = s.run, canonUTC(s.now()), append([]netobs.Span{}, s.spans...)
	s.p.send(tk)
	s.p.taken()
}

// heartbeat writes a heartbeat made now on the sensor's clock.
func (s *sim) heartbeat() {
	s.t.Helper()
	s.pk++
	hb := heartbeat02(0, s.pk)
	hb.AtUTC = canonUTC(s.now())
	hb.Counters.DropsChannel = uint64(s.drops)
	s.write(hb)
}

// beat starts the heartbeats, the first one 10 s from now.
func (s *sim) beat() {
	s.beats, s.hbAt = true, s.r.trueNow().Add(10*time.Second)
}

// pass lets d of true time pass on both of the node's clocks, the
// sensor's heartbeats and ticks on time.
func (s *sim) pass(d time.Duration) {
	s.t.Helper()
	end := s.r.trueNow().Add(d)
	for {
		next := end
		if s.beats && s.hbAt.Before(next) {
			next = s.hbAt
		}
		if s.p != nil && !s.manual && s.tickAt.Before(next) {
			next = s.tickAt
		}
		if dt := next.Sub(s.r.trueNow()); dt > 0 {
			s.r.pass(dt)
		}
		now := s.r.trueNow()
		if s.beats && !now.Before(s.hbAt) {
			s.heartbeat()
			s.hbAt = now.Add(10 * time.Second)
		}
		if s.p != nil && !s.manual && !now.Before(s.tickAt) {
			s.tick()
			s.tickAt = now.Add(10 * time.Second)
		}
		if !now.Before(end) {
			return
		}
	}
}

// step steps the node's wall clock by node and the sensor's by sensor.
func (s *sim) step(node, sensor time.Duration) {
	s.r.addWall(node)
	s.off += sensor
}

// fromPort is the stored observations of the node's own flow from sport.
func (r *rig) fromPort(sport int) []*netobs.Observation {
	r.t.Helper()
	var out []*netobs.Observation
	for _, o := range storedObs(r.t, r.s) {
		if o.IP != nil && o.IP.Sport != nil && *o.IP.Sport == sport && o.IP.Src == nodeAddr {
			out = append(out, o)
		}
	}
	return out
}

// one is the one stored record of sport's flow.
func (r *rig) one(sport int) *netobs.Node {
	r.t.Helper()
	os := r.fromPort(sport)
	if len(os) != 1 {
		r.t.Fatalf("%d stored records of port %d, want 1", len(os), sport)
	}
	return os[0].Node
}

// withSeams sets several control seams for one test.
func withSeams(t *testing.T, seams ...*bool) {
	for _, s := range seams {
		withSeam(t, s)
	}
}

// noOtherWindows checks that only the count at i of windows(st) moved, to
// n; i < 0: none.
func noOtherWindows(t *testing.T, st SkewStats, i int, n uint64) {
	t.Helper()
	w := windows(st)
	want := [5]uint64{}
	if i >= 0 {
		want[i] = n
	}
	if w != want {
		t.Fatalf("skew windows %v, want %v", w, want)
	}
}
