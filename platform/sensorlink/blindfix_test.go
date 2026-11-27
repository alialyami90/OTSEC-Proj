package sensorlink

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
)

// The fix round on #802 (P4-4-INT-D5-BLIND): D3's and D6's B1, D3's N1,
// N3 and N4, and D6's N1. Desk only: the in-memory pipe and the rig's
// test clocks, a test source in place of the sensor, the health stream an
// in-memory sink. No sensor produced the records and no device was
// contacted.

// B1 (D3 and D6 on #802): a new run does not end a standing stretch
// without a rise. eth2 named and standing; the sensor restarts, and run
// 6's current heartbeats keep eth2 flat: the stretch stands naming eth2
// at run 6's first current heartbeat and past blind_after_s of it, with no
// second status alarm; eth2's rise in run 6 ends it. Control: the grace
// for every interface at a new run, as at e3632e34 (the stretch ended at
// run 6's first current heartbeat).
func TestBlindNewRunStanding(t *testing.T) {
	run := func(t *testing.T) (*gsrc, *uint64) {
		g := newGsrc(t)
		e2 := new(uint64)
		g.two(e2)
		g.live(40, true) // eth2 blind, standing
		g.cut()
		g.restartSensor()
		g.reconnect(true)
		g.live(1, true) // run 6's first current heartbeat, eth2 flat
		return g, e2
	}
	g, e2 := run(t)
	if !slices.Equal(g.named(), []string{"eth2"}) || g.blindN() != 1 {
		t.Fatalf("at run 6's first current heartbeat: named %v, %d sensor-blind; want eth2 standing, one alarm", g.named(), g.blindN())
	}
	g.live(31, true) // 310 s of run 6, eth2 flat
	if !slices.Equal(g.named(), []string{"eth2"}) || g.blindN() != 1 {
		t.Fatalf("310 s into run 6: named %v, %d sensor-blind; want eth2 standing, one alarm", g.named(), g.blindN())
	}
	*e2 += 50
	g.live(1, true)
	if len(g.named()) != 0 {
		t.Fatalf("eth2 rose in run 6 and the stretch stands: %v", g.named())
	}
	t.Run("control: the grace for every interface at a new run", func(t *testing.T) {
		withSeam(t, &blindNewRunGrace)
		if g, _ := run(t); len(g.named()) != 0 {
			t.Fatalf("the control kept %v", g.named())
		}
	})
}

// D3's N1 on #802: the 60 s check runs at every accepted frame that is
// not a current heartbeat, not only at ticks. No tick is sent: backlog
// heartbeats that are not late, and, on a live link, observations
// committed with no heartbeat, each for 70 s, raise sensor-no-heartbeat
// once and show coverage unknown; so does one observation dropped by a
// full class, and one held, 61 s after the hello (D6's N2 on #802, its
// probe P9). Control: checked at accepted ticks only (nothing raised).
func TestBlindNoHeartbeatWithoutTicks(t *testing.T) {
	backlog := func(t *testing.T) *rig {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		g.buffer(12, true) // read 120 s late, under late_bound_s
		first := g.seq - len(g.buf) + 1
		g.p = g.r.dial(enrolment())
		g.send(g.hello(first, false))
		for range 7 { // one backlog heartbeat each 10 s, no tick
			g.r.pass(10 * time.Second)
			g.buf = append(g.buf, g.mk(true))
			h := g.buf[0]
			g.buf = g.buf[1:]
			g.send(h)
		}
		return g.r.rig
	}
	records := func(t *testing.T) *rig {
		g := newGsrc(t)
		g.live(6, true)
		for range 7 { // one observation each 10 s, no heartbeat or tick
			g.r.pass(10 * time.Second)
			g.seq++
			g.p.send(obs02(g.seq))
			g.p.ack(uint64(g.seq))
		}
		return g.r.rig
	}
	dropped := func(t *testing.T) *rig {
		r := newRig(t, func(o *Options) { o.Store = quotaStore{o.Store} })
		p := r.accepted(hello02())
		r.pass(61 * time.Second)
		p.send(obs02(1))
		p.taken()
		if d := r.l.Stats().Dropped[DropClassFull]; d != 1 {
			t.Fatalf("dropped %v, want one under %s", r.l.Stats().Dropped, DropClassFull)
		}
		return r
	}
	held := func(t *testing.T) *rig {
		r, hs := holdRig02(t)
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		h := hello02()
		h.FirstSeq, h.NewestSeq = itoa(1), itoa(0) // nothing buffered: no backlog
		p := r.accepted(h)
		r.pass(61 * time.Second)
		p.send(nodeFlow02(1))
		p.taken()
		if rec := hs.last(); rec.State != HoldHolding || len(rec.Flows) != 1 || len(rec.Flows[0].Records) != 1 {
			t.Fatalf("not held: %+v", rec)
		}
		return r
	}
	for _, c := range []struct {
		what string
		run  func(*testing.T) *rig
	}{{"backlog heartbeats", backlog}, {"observations", records}, {"a dropped observation", dropped}, {"a held observation", held}} {
		t.Run(c.what, func(t *testing.T) {
			r := c.run(t)
			if r.al.count(AlarmNoHeartbeat) != 1 || !r.l.BlindStatus().CoverageUnknown {
				t.Fatalf("%v, coverage unknown %v; want sensor-no-heartbeat once and coverage unknown", r.al.list, r.l.BlindStatus().CoverageUnknown)
			}
			t.Run("control: at accepted ticks only", func(t *testing.T) {
				withSeam(t, &noHbTicksOnly)
				if r := c.run(t); r.al.count(AlarmNoHeartbeat) != 0 {
					t.Fatal("the control raised it")
				}
			})
		})
	}
}

// quotaStore refuses every append with a full class: a final store error,
// so the record is dropped and counted (CH-17).
type quotaStore struct{ Appender }

func (quotaStore) Append(context.Context, c5.Record) (c5.Receipt, error) {
	return nil, &c5.Error{Code: c5.CodeQuotaReached}
}

// D3's N3 and D6's N1 on #802: the observation outcomes against CH-44's
// accepted frames. A duplicate placed at or below P, a resend released
// while it was taken (outDuplicate) and a record refused at the store
// leave Stats.Accepted unchanged; a record dropped by a full class and a
// record held each count one. Controls: every frame read counts (the
// three that do not count, then counted); the four mutants of
// observation's outcome switch (M1 to M4 of D6's N1) are run in the PR's
// comment, each failing its leg.
func TestBlindAcceptedOutcomes(t *testing.T) {
	accepted := func(r *rig) uint64 { return r.l.Stats().Accepted }
	duplicate := func(t *testing.T) (before, after uint64) {
		r := seeded(t, 3)
		p := r.dial(enrolment())
		p.send(resume(2, 9)) // L = 1, P = 3
		p.ackAtLeast(1)
		before = accepted(r)
		p.send(obs02(2))
		p.taken()
		if d := r.l.Stats().Dropped[RefusedDuplicate]; d != 1 {
			t.Fatalf("duplicates %d, want 1", d)
		}
		return before, accepted(r)
	}
	released := func(t *testing.T) (before, after uint64) {
		r, hs := holdRig02(t)
		heldDue(t, r, hs, false)
		p := r.accepted(r.agreeHello(resume(1, 20)))
		p.send(noSeq)
		p.taken()
		fired := false
		cursorEncodeFault = func(c *Cursor) error {
			if !fired && c.RunID == testRun && c.Taken == 1 {
				fired = true
				r.l.TickHold(bg) // the release disposes of record 1 at its encode
			}
			return nil
		}
		t.Cleanup(func() { cursorEncodeFault = nil })
		before = accepted(r)
		p.send(nodeFlow02(1))
		p.taken()
		if !fired || r.l.Stats().Dropped[RefusedDuplicate] != 1 {
			t.Fatalf("fired %v, duplicates %d; want the release's duplicate", fired, r.l.Stats().Dropped[RefusedDuplicate])
		}
		return before, accepted(r)
	}
	refused := func(t *testing.T) (before, after uint64) {
		r := newRig(t, nil)
		p := r.accepted(hello02())
		withSeam(t, &refuseStoredFault)
		before = accepted(r)
		p.send(obs02(1))
		p.taken()
		if n := r.l.Stats().Refused[RefusedStored]; n != 1 {
			t.Fatalf("refused at the store %d, want 1", n)
		}
		return before, accepted(r)
	}
	for _, c := range []struct {
		what string
		run  func(*testing.T) (uint64, uint64)
	}{{"a duplicate", duplicate}, {"a resend released while taken", released}, {"refused at the store", refused}} {
		t.Run(c.what+" does not count", func(t *testing.T) {
			if before, after := c.run(t); after != before {
				t.Fatalf("Accepted %d to %d, want unchanged", before, after)
			}
			t.Run("control: every frame read counts", func(t *testing.T) {
				withSeam(t, &acceptedAnyFrame)
				if before, after := c.run(t); after == before {
					t.Fatal("the control counted nothing")
				}
			})
		})
	}
	t.Run("dropped by a full class counts", func(t *testing.T) {
		r := newRig(t, func(o *Options) { o.Store = quotaStore{o.Store} })
		p := r.accepted(hello02())
		before := accepted(r)
		p.send(obs02(1))
		p.taken()
		if d := r.l.Stats().Dropped[DropClassFull]; d != 1 {
			t.Fatalf("dropped %v, want one under %s", r.l.Stats().Dropped, DropClassFull)
		}
		if after := accepted(r); after != before+1 {
			t.Fatalf("Accepted %d to %d, want one more", before, after)
		}
	})
	t.Run("held counts", func(t *testing.T) {
		r, hs := holdRig02(t)
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		h := hello02()
		h.FirstSeq, h.NewestSeq = itoa(1), itoa(0) // nothing buffered: no backlog
		p := r.accepted(h)
		before := accepted(r)
		p.send(nodeFlow02(1))
		p.taken()
		if rec := hs.last(); rec.State != HoldHolding || len(rec.Flows) != 1 || len(rec.Flows[0].Records) != 1 {
			t.Fatalf("not held: %+v", rec)
		}
		if after := accepted(r); after != before+1 {
			t.Fatalf("Accepted %d to %d, want one more", before, after)
		}
	})
}

// D3's N4 on #802: a stretch's names are at most MaxInterfaces across
// runs. Twenty runs, each with one interface of its own blind (carrier
// down), each judged twice: sensor-blind's stretch and the merged
// sensor.past-blind both name MaxInterfaces and count the rest once, and
// the detail says so. Control: every name kept.
func TestBlindNamesCapped(t *testing.T) {
	const runs = 20
	run := func() (named []string, more int, past *pastStretch) {
		b := &blindState{}
		at := t0
		for i := range runs {
			n, r := fmt.Sprintf("if%d", i), fmt.Sprintf("run%d", i)
			by := map[string]netobs.InterfaceCount{n: {Name: n, Carrier: "down"}}
			for range 2 {
				_, _, named, more = b.liveLocked(r, []string{n}, by, time.Duration(i)*time.Minute, at, 5*time.Minute)
				b.pastLocked(r, []string{n}, by, at, 5*time.Minute, false, true)
				at = at.Add(10 * time.Second)
			}
		}
		b.endPastLocked()
		return named, more, b.pend
	}
	named, more, past := run()
	if len(named) != netobs.MaxInterfaces || more != runs-netobs.MaxInterfaces {
		t.Fatalf("sensor-blind names %d and %d more, want %d and %d", len(named), more, netobs.MaxInterfaces, runs-netobs.MaxInterfaces)
	}
	if past == nil || len(past.names) != netobs.MaxInterfaces || past.more != runs-netobs.MaxInterfaces {
		t.Fatalf("sensor.past-blind %+v, want %d names and %d more", past, netobs.MaxInterfaces, runs-netobs.MaxInterfaces)
	}
	if s := nameList(named, more); !strings.HasSuffix(s, fmt.Sprintf(", and %d more not listed", runs-netobs.MaxInterfaces)) {
		t.Fatalf("detail names %q", s)
	}
	// D3's N7 and D6's N3 on #802: once a stretch's names have overflowed,
	// no interface gets the grace at a new run. Nine runs leave if0 to if7
	// named and if8 counted; run 9 carries only if7, blind, so the count
	// is in overPrev alone at run 10 (D6's N4, its probe P11); run 10
	// carries if8 up and flat: the stretch stands. Control: the grace for
	// a name counted past the cap.
	overflow := func() bool {
		b := &blindState{}
		at := t0
		step := func(r, n, carrier string, m time.Duration) {
			by := map[string]netobs.InterfaceCount{n: {Name: n, Carrier: carrier, Packets: 5}}
			b.pastLocked(r, []string{n}, by, at, 5*time.Minute, true, false)
			b.liveLocked(r, []string{n}, by, m, at, 5*time.Minute)
			at = at.Add(10 * time.Second)
		}
		for i := range 9 {
			step(fmt.Sprintf("run%d", i), fmt.Sprintf("if%d", i), "down", time.Duration(i)*time.Minute)
		}
		step("run9", "if7", "down", 9*time.Minute)
		step("run10", "if8", "up", 10*time.Minute)
		return b.standing
	}
	if !overflow() {
		t.Fatal("a new run gave the grace to a name counted past the cap, and the stretch ended")
	}
	t.Run("control: the grace past the cap", func(t *testing.T) {
		withSeam(t, &blindOverGrace)
		if overflow() {
			t.Fatal("the control kept the stretch")
		}
	})
	t.Run("control: every name kept", func(t *testing.T) {
		withSeam(t, &blindNamesUncapped)
		if named, _, past := run(); len(named) != runs || len(past.names) != runs {
			t.Fatalf("the control kept %d and %d names", len(named), len(past.names))
		}
	})
}

// B2 (D6 on #802; option (i), agreed by D6, D3 and D4): a rise seen only
// in backlog heartbeats is credited at the receipt less its age by at_utc.
// D6's P2: eth2 named and standing; a cut in which eth2 rises once at its
// start and is then flat for 400 s by at_utc; the backlog drains; the
// first current heartbeat, eth2 still flat, keeps eth2 named, and so do
// 300 s more, with one status alarm. Control: the rise credited at the
// receipt, as at 953809b7 (eth2 cleared). D6's P4, both interfaces rising
// through a ten-minute cut, then live: no sensor-blind.
func TestBlindOldRiseNotCredited(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		e2 := new(uint64)
		g.two(e2)
		g.live(40, true) // eth2 blind, standing
		g.cut()
		*e2 += 50
		g.buffer(1, true)  // eth2 rose once, at the cut's start
		g.buffer(40, true) // eth2 flat 400 s by at_utc
		g.reconnect(false)
		g.live(1, true) // the first current heartbeat, eth2 flat
		return g
	}
	g := run(t)
	if !slices.Equal(g.named(), []string{"eth2"}) {
		t.Fatalf("at the first current heartbeat: named %v, want eth2", g.named())
	}
	g.live(30, true)
	if !slices.Equal(g.named(), []string{"eth2"}) || g.blindN() != 1 {
		t.Fatalf("300 s later: named %v, %d sensor-blind; want eth2, one alarm", g.named(), g.blindN())
	}
	t.Run("control: credited at the receipt", func(t *testing.T) {
		withSeam(t, &blindCreditAtReceipt)
		if g := run(t); len(g.named()) != 0 {
			t.Fatalf("the control kept %v", g.named())
		}
	})
	t.Run("rising through a cut raises nothing", func(t *testing.T) {
		g := newGsrc(t)
		var e2 uint64
		g.f = func(h *netobs.Heartbeat) {
			e2 += 7
			ifs([]string{"eth1", "eth2"}, []uint64{g.pk, e2})(h)
		}
		g.live(6, true)
		g.cut()
		g.buffer(60, true)
		g.reconnect(false)
		g.live(3, true)
		if g.blindN() != 0 || len(g.named()) != 0 {
			t.Fatalf("%d sensor-blind, named %v; want none", g.blindN(), g.named())
		}
	})
}

// creditCase is one interface's comparison begun at m0 with packets 1,
// then a current heartbeat at m with packets 2, at_utc at, whose last rise
// has at_utc riseAt; it returns the interface's credit and grace. first:
// the interface was first seen within the comparison (no grace).
func creditCase(m0, m time.Duration, at, riseAt time.Time, first bool) (time.Duration, bool) {
	b := &blindState{}
	by := func(p uint64) map[string]netobs.InterfaceCount {
		return map[string]netobs.InterfaceCount{"eth1": {Name: "eth1", Carrier: "up", Packets: p}}
	}
	b.liveLocked(testRun, []string{"eth1"}, by(1), m0, t0, 5*time.Minute)
	if first {
		b.live["eth1"] = &ifBlind{packets: 1}
	}
	b.past = map[string]*ifBlind{"eth1": {at: riseAt}}
	b.liveLocked(testRun, []string{"eth1"}, by(2), m, at, 5*time.Minute)
	lv := b.live["eth1"]
	return lv.mono, lv.rose
}

// creditRise's clamps and guard (B2 on #802), each with its control:
//   - upper: a rise whose at_utc is an hour later than the heartbeat's is
//     credited no later than the receipt (control: no upper clamp,
//     credited an hour past it);
//   - lower: a rise older than the previous credit is credited at that
//     credit (control: no lower clamp, credited before it);
//   - guard: an at_utc that does not parse moves no credit, so an
//     interface with no grace keeps none (control: no guard, given grace).
//     netobs refuses such a heartbeat as form first; this is the guard.
func TestBlindCreditClamps(t *testing.T) {
	m := 1000 * time.Second
	upper := func() time.Duration {
		c, _ := creditCase(0, m, t0.Add(m), t0.Add(m+time.Hour), false)
		return c
	}
	lower := func() time.Duration {
		c, _ := creditCase(900*time.Second, m, t0.Add(2000*time.Second), t0, false)
		return c
	}
	guard := func() bool {
		_, rose := creditCase(0, m, time.Time{}, t0, true)
		return rose
	}
	if c := upper(); c != m {
		t.Fatalf("upper: credited at %s, want the receipt %s", c, m)
	}
	if c := lower(); c != 900*time.Second {
		t.Fatalf("lower: credited at %s, want the previous credit 900s", c)
	}
	if guard() {
		t.Fatal("guard: an at_utc that does not parse gave grace")
	}
	t.Run("control: no upper clamp", func(t *testing.T) {
		withSeam(t, &blindNoUpperClamp)
		if c := upper(); c <= m {
			t.Fatalf("the control credited at %s", c)
		}
	})
	t.Run("control: no lower clamp", func(t *testing.T) {
		withSeam(t, &blindNoLowerClamp)
		if c := lower(); c >= 900*time.Second {
			t.Fatalf("the control credited at %s", c)
		}
	})
	t.Run("control: no guard", func(t *testing.T) {
		withSeam(t, &blindNoParseGuard)
		if !guard() {
			t.Fatal("the control gave no grace")
		}
	})
}
