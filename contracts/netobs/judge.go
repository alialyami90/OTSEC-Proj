package netobs

import (
	"time"
)

// The pure checks of C13 0.2's channel (§15's "Contract" rows): judging a
// hello (CH-13), a tick (CH-8), an ack (CH-9) and a record's place in its
// run (CH-14), and the widening check on a loss's spans (CH-40). Each takes
// the state its caller holds and returns what CH-x decides. None reads a
// clock, saves anything or writes a record; the caller does, in the order
// the clause gives.

// Position is the node's saved position for a sensor (CH-18).
type Position struct {
	Generation uint64 // the generation the position was saved under
	RunCounter uint64
	RunID      string
	Taken      uint64 // T
	D          uint64 // the run's declaration (CH-15)
}

// HelloState is what the node holds when it judges a hello (CH-13).
type HelloState struct {
	// SensorID and Generation are the live enrolment of the key that
	// authenticated.
	SensorID   string
	Generation uint64
	// Began is the generation at which the node's position began (CH-12).
	// A Position saved under a lower generation reads as none.
	Began uint64
	// Position is the saved position, nil when none. After a lost sensor
	// database it is the run file's copy with Taken and D 0 (CH-18).
	Position *Position
	// Spans and Ds are the spans the node holds for the position's run, as
	// stated, and the D at which they were last accepted (CH-40).
	Spans []Span
	Ds    uint64
	// PinnedBy is the first pinned_by seen in the live generation, "" when
	// none has been (CH-33).
	PinnedBy string
	// ConfigDigest is the expected digest, network_sensor's (CH-32).
	ConfigDigest string
}

// How an accepted hello is taken (CH-13 rows 5, 5b and 6).
const (
	HelloResume = "resume"
	// HelloResumeRenewed is row 5b: a resume under a higher generation,
	// which a renew with the pin unchanged carries over. The node saves the
	// new generation in the cursor before it accepts the hello.
	HelloResumeRenewed = "resume-renewed"
	// HelloNewRun is row 6: the node runs CH-15's check for the run the
	// cursor still holds, then saves the new run, before it accepts.
	HelloNewRun = "new-run"
)

// HelloVerdict is CH-13's outcome. Close is a node close reason, "" when
// the hello is accepted as Accept. The raises never close: a digest that
// differs (sensor-coverage-mismatch), a buffer below the site floor
// (sensor-buffer-small), and a runs_skipped that disagrees
// (sensor-gap-undeclared, reason runs). SpansWidened says the hello's lost
// list holds a span new or wider than the node's, so the node sets Ds to
// the hello's drops_channel and opens each one's lost gap (CH-40).
type HelloVerdict struct {
	Close          string
	Accept         string
	DigestMismatch bool
	BufferSmall    bool
	RunsUndeclared bool
	SpansWidened   bool
}

// JudgeHello applies CH-13 to a hello that Validate passed (row 1), in its
// order, the first failure deciding. CH-40's widening check needs the run's
// held spans, so it is applied at row 5 or 6, still closing as hello.
func JudgeHello(s HelloState, h *SensorHello) HelloVerdict {
	var v HelloVerdict
	close := func(r string) HelloVerdict { return HelloVerdict{Close: r} }
	// Row 2.
	if h.SensorID != s.SensorID || num(h.Generation) != s.Generation {
		return close(CloseBinding)
	}
	var saved Position
	if p := s.Position; p != nil && p.Generation >= s.Began {
		saved = *p
	}
	counter, drops := num(h.RunCounter), num(h.DropsChannel)
	switch {
	case counter < saved.RunCounter: // row 3
		return close(CloseRunRegressed)
	case counter == saved.RunCounter && h.RunID != saved.RunID: // row 4
		return close(CloseRunForked)
	case counter == saved.RunCounter: // row 5, a resume
		if h.Prior != nil || drops < saved.D {
			return close(CloseHello)
		}
		v.Accept = HelloResume
		if saved.Generation > s.Generation {
			return close(CloseHello)
		}
		if saved.Generation < s.Generation {
			v.Accept = HelloResumeRenewed
		}
		if num(h.NewestSeq) < saved.Taken { // 5a
			return close(CloseRunRegressed)
		}
		widened, ok := widenedSpans(s.Spans, s.Ds, h.Lost, drops)
		if !ok {
			return close(CloseHello)
		}
		v.SpansWidened = widened
	default: // row 6, a new run
		if h.Prior == nil {
			return close(CloseHello)
		}
		widened, ok := widenedSpans(nil, 0, h.Lost, drops)
		if !ok {
			return close(CloseHello)
		}
		if _, ok := widenedSpans(nil, 0, h.Prior.Lost, num(h.Prior.RecordsLost)); !ok {
			return close(CloseHello)
		}
		v.Accept, v.SpansWidened = HelloNewRun, widened
		v.RunsUndeclared = num(h.Prior.RunsSkipped) != counter-saved.RunCounter-1
	}
	// Row 7.
	if s.PinnedBy != "" && h.PinnedBy != s.PinnedBy {
		return close(CloseBinding)
	}
	// Rows 8 and 9.
	v.DigestMismatch = h.ConfigDigest != s.ConfigDigest
	v.BufferSmall = num(h.BufferBytes) < SiteBufferFloor
	return v
}

// widenedSpans is CH-40's check of a declared lost list against the spans the
// node holds for the run, as stated. A stated span inside a held one is
// neither new nor wider; any other is, and then the list must come with a
// declared count above ds (drops_channel above Ds; for prior.lost,
// prior.records_lost above 0). It returns whether any span is new or
// wider, and false for ok when one is with no rise, which closes the
// connection (tick, or hello). The spans' form is Validate's.
func widenedSpans(held []Span, ds uint64, stated []Span, declared uint64) (widened, ok bool) {
	for _, s := range stated {
		if !inside(s, held) {
			widened = true
		}
	}
	return widened, !widened || declared > ds
}

// inside reports whether s lies within one of held, by time.
func inside(s Span, held []Span) bool {
	from, err1 := time.Parse(time.RFC3339Nano, s.FromUTC)
	to, err2 := time.Parse(time.RFC3339Nano, s.ToUTC)
	if err1 != nil || err2 != nil {
		return false
	}
	for _, h := range held {
		hf, err1 := time.Parse(time.RFC3339Nano, h.FromUTC)
		ht, err2 := time.Parse(time.RFC3339Nano, h.ToUTC)
		if err1 == nil && err2 == nil && !from.Before(hf) && !to.After(ht) {
			return true
		}
	}
	return false
}

// TickState is what the node holds on a connection when it judges a tick
// (CH-8).
type TickState struct {
	// Hello is the connection's accepted hello.
	Hello *SensorHello
	// Last is the last tick accepted on the connection, nil before the
	// first. Since is the node's monotonic time since it was accepted.
	Last  *Tick
	Since time.Duration
	// Spans and Ds are the run's held spans and Ds (CH-40).
	Spans []Span
	Ds    uint64
}

// TickVerdict is CH-8's outcome on a tick that Validate passed. Close is
// tick or "". SensorID says the close was for a sensor_id other than the
// hello's, which also counts under sensor-id and writes sensor.link_refused
// (CH-11, C8-4). Early is the rate rule: counted under tick_early, and the
// tick moves nothing. SpansWidened is as in HelloVerdict.
type TickVerdict struct {
	Close        string
	SensorID     bool
	Early        bool
	SpansWidened bool
}

// JudgeTick applies CH-8's checks and its rate rule. On the first tick of a
// connection the earlier values are the hello's newest_seq and
// drops_channel.
func JudgeTick(s TickState, t *Tick) TickVerdict {
	h := s.Hello
	if t.SensorID != h.SensorID {
		return TickVerdict{Close: CloseTick, SensorID: true}
	}
	if t.RunID != h.RunID {
		return TickVerdict{Close: CloseTick}
	}
	newest, sent, drops := num(t.NewestSeq), num(t.SentSeq), num(t.DropsChannel)
	pNewest, pDrops := num(h.NewestSeq), num(h.DropsChannel)
	if s.Last != nil {
		pNewest, pDrops = num(s.Last.NewestSeq), num(s.Last.DropsChannel)
		if sent < num(s.Last.SentSeq) {
			return TickVerdict{Close: CloseTick}
		}
	}
	if newest < pNewest || drops < pDrops || sent > newest {
		return TickVerdict{Close: CloseTick}
	}
	widened, ok := widenedSpans(s.Spans, s.Ds, t.Lost, drops)
	if !ok {
		return TickVerdict{Close: CloseTick}
	}
	return TickVerdict{Early: s.Last != nil && s.Since < TickMinSpacing, SpansWidened: widened}
}

// AckState is what the agent holds on a connection when it judges an ack
// (CH-9).
type AckState struct {
	RunCounter uint64
	RunID      string
	// LastAck is the last ack's seq on the connection, nil before the first.
	LastAck *uint64
	// FirstSeq is the hello's first_seq; SentSeq the highest seq sent, or
	// skipped as unreadable, on the connection (its latest sent_seq).
	FirstSeq uint64
	SentSeq  uint64
}

// AckValid applies CH-9 at the agent to an ack that Validate passed: the
// connection's run, not below the last ack, and at most the larger of
// first_seq - 1 and SentSeq. False closes the connection as ack.
func AckValid(s AckState, a *Ack) bool {
	seq := num(a.Seq)
	switch {
	case num(a.RunCounter) != s.RunCounter || a.RunID != s.RunID:
		return false
	case s.LastAck != nil && seq < *s.LastAck:
		return false
	}
	return seq <= max(s.FirstSeq-1, s.SentSeq)
}

// What CH-14 does with a record that decoded strictly.
const (
	PlaceRun       = "run"       // run_id not the hello's: close, run
	PlaceSensorID  = "sensor-id" // refused, audited under the cap; takes its seq
	PlaceSeq       = "seq"       // at or below L: refused, re-ordered or repeated
	PlaceDuplicate = "duplicate" // above L, at or below P: dropped, counted
	PlaceRead      = "read"      // read as in 0.1
)

// Placement is CH-14's outcome: the place, L after the record, and the
// seqs the record skipped above P, this run's gap (CH-15).
type Placement struct {
	Place string
	L     uint64
	Gap   uint64
}

// PlaceRecord applies CH-14 to a record of the run h names, with seq, read
// when the highest seq read on the connection is l and the run's saved
// taken position is p. A record takes its seq whatever later check refuses
// it, sensor-id included, so L moves and no false gap is counted.
func PlaceRecord(h *SensorHello, l, p uint64, sensorID, runID string, seq uint64) Placement {
	if runID != h.RunID {
		return Placement{Place: PlaceRun, L: l}
	}
	if seq <= l {
		place := PlaceSeq
		if sensorID != h.SensorID {
			place = PlaceSensorID
		}
		return Placement{Place: place, L: l}
	}
	pl := Placement{L: seq}
	if from := max(l, p); seq-1 > from {
		pl.Gap = seq - 1 - from
	}
	switch {
	case sensorID != h.SensorID:
		pl.Place = PlaceSensorID
	case seq <= p:
		pl.Place = PlaceDuplicate
	default:
		pl.Place = PlaceRead
	}
	return pl
}
