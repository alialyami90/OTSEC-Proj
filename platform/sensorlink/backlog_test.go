package sensorlink

import (
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// CH-39's break rule and its backlog (C13 0.2 T-8; D5-sensor-node.md
// section 1.6's tests; D1's end rule 7011321374 on #748 with D6's probe
// P9), desk only. The alert-key legs (sensor-records-late) are INT-D5b's.

// breakRig is a 0.2 rig holding the node's own flows, tie_grace_s g, its
// sensor connected and in agreement, nothing buffered, so the first
// backlog after the start is through at the hello; 20 s of ticks are read,
// and the last frame accepted is the tick at 20 s.
func breakRig(t *testing.T, g time.Duration) (*rig, *sim) {
	r, _ := holdRig02With(t, func(o *Options) { o.Hold.TieGrace = g })
	s := newSim(r)
	s.connect(true)
	s.pass(20 * time.Second)
	return r, s
}

// sendN sends the first n records kept.
func (s *sim) sendN(n int) {
	s.t.Helper()
	for _, v := range s.buf[:n] {
		s.p.send(v)
		s.sent = int(num(seqOf(v)))
	}
	s.buf, s.bufAt = s.buf[n:], s.bufAt[n:]
	s.p.taken()
}

// cut20 is T-8's first case: a cut of 20 s from the last frame accepted, a
// dial that fails 5 s into it for 2 s, and a backlog record of the node's
// own flow captured 6 s into it on the sensor's clock, made at made(b),
// where b is the break's start; brk is the cut's length.
func cut20(t *testing.T, brk time.Duration, made func(b time.Time) time.Time) (*rig, *netobs.Node) {
	r, s := breakRig(t, 30*time.Second)
	b := s.now()
	s.cut()
	s.pass(5 * time.Second)
	s.dialFails(1, 2*time.Second)
	s.synEnd(40001, b.Add(6*time.Second), made(b))
	s.pass(brk - 7*time.Second)
	s.connect(true)
	return r, r.one(40001)
}

func tiedTo(t *testing.T, nd *netobs.Node, n int) {
	t.Helper()
	if nd.PlatformSession == nil || nd.PlatformSession.InvocationID != inv(n) || nd.Backlog || nd.Skewed {
		t.Fatalf("want tied to session %d, unmarked: %+v", n, nd)
	}
}

func backlogUntied(t *testing.T, nd *netobs.Node) {
	t.Helper()
	if nd.PlatformSession != nil || !nd.Backlog || nd.Skewed {
		t.Fatalf("want untied with node.backlog and no node.skewed: %+v", nd)
	}
}

// T-8, the intake leg, and section 1.6's TestBreakUnderBoundTies and
// TestShortBreakMadeUtcCheck: a cut of 20 s; a backlog record whose
// made_utc + E falls in the break ties by the late index; one made before
// the break, or with its made_utc moved by 30 s, takes no tie and carries
// node.backlog, not node.skewed. Control: ties made by made_utc unchecked,
// which ties both.
func TestBacklogTieInBreak(t *testing.T) {
	in := func(b time.Time) time.Time { return b.Add(6 * time.Second) }
	before := func(b time.Time) time.Time { return b.Add(-3 * time.Second) }
	moved := func(b time.Time) time.Time { return b.Add(36 * time.Second) }
	r, nd := cut20(t, 20*time.Second, in)
	tiedTo(t, nd, 1)
	if st := r.l.Stats().Hold; st.LateTied != 1 {
		t.Fatalf("late_tied %d", st.LateTied)
	}
	for name, made := range map[string]func(time.Time) time.Time{"made before the break": before, "made_utc moved by 30 s": moved} {
		t.Run(name, func(t *testing.T) {
			r, nd := cut20(t, 20*time.Second, made)
			backlogUntied(t, nd)
			if st := r.l.SkewStats(); st.Backlog != 1 {
				t.Fatalf("backlog count %d", st.Backlog)
			}
			noOtherWindows(t, r.l.SkewStats(), -1, 0)
			t.Run("control: made_utc unchecked", func(t *testing.T) {
				withSeam(t, &breakNoMadeCheck)
				_, nd := cut20(t, 20*time.Second, made)
				tiedTo(t, nd, 1)
			})
		})
	}
	t.Run("a step inside the break", func(t *testing.T) { shortBreakNodeStep(t) })
	t.Run("a step after the hello", func(t *testing.T) { stepAfterHello(t) })
}

// TestBreakUnderBoundTies and TestShortBreakMadeUtcCheck are
// TestBacklogTieInBreak's first legs, by section 1.6's names. The made_utc
// check's case of section 1.6, a sensor clock set back 10 minutes inside a
// 30 s break and put back before the hello: a record made then, of a flow
// that matches a session ten minutes before, is untied; control: the check
// removed, which ties it (D3).
func TestBreakUnderBoundTies(t *testing.T) {
	_, nd := cut20(t, 20*time.Second, func(b time.Time) time.Time { return b.Add(6 * time.Second) })
	tiedTo(t, nd, 1)
}

func TestShortBreakMadeUtcCheck(t *testing.T) {
	run := func(t *testing.T) *netobs.Node {
		r, s := breakRig(t, 30*time.Second)
		// A session ten minutes before the break, released with no flow.
		s.dialFails(1, 2*time.Second)
		d := s.now().Add(-2 * time.Second)
		s.pass(10*time.Minute - 10*time.Second)
		s.cut()
		s.pass(5 * time.Second)
		s.step(0, -10*time.Minute) // the sensor's clock set back 10 minutes
		s.synEnd(40001, d.Add(time.Second), time.Time{})
		s.pass(5 * time.Second)
		s.step(0, 10*time.Minute) // and put back
		s.pass(20 * time.Second)
		s.connect(true)
		return r.one(40001)
	}
	backlogUntied(t, run(t))
	t.Run("control: made_utc unchecked", func(t *testing.T) {
		withSeam(t, &breakNoMadeCheck)
		tiedTo(t, run(t), 1)
	})
}

// shortBreakNodeStep is T-8's second case and section 1.6's
// TestShortBreakNodeStepNoTie: a break of 40 s, tie_grace_s 1 s, the
// sensor's clock and the node's stepped back 30 s together 10 s into it, a
// dial that fails 5 s into it, and a backlog record made 35 s into it and
// stamped 5 s, of a flow from the node's address to that relay: untied,
// node.backlog, no node.skewed. Controls: no rule on the two clocks (the
// break by its monotonic length alone, stored times compared as they are,
// no capture floor), which ties it; no rule on the break's ends, under
// which the capture floor and the stored window refuse it with
// node.skewed.
func shortBreakNodeStep(t *testing.T) {
	run := func(t *testing.T) (*rig, *netobs.Node) {
		r, s := breakRig(t, time.Second)
		s.cut()
		s.pass(5 * time.Second)
		s.dialFails(1, time.Second)
		s.pass(4 * time.Second)
		s.step(-30*time.Second, -30*time.Second)
		s.pass(25 * time.Second)
		s.synEnd(40001, s.now(), time.Time{}) // stamped 5 s into the break
		s.pass(5 * time.Second)
		s.connect(true)
		return r, r.one(40001)
	}
	r, nd := run(t)
	backlogUntied(t, nd)
	noOtherWindows(t, r.l.SkewStats(), -1, 0)
	t.Run("control: no rule on the two clocks", func(t *testing.T) {
		withSeams(t, &breakNoEnds, &skewNoStored, &skewNoFloor)
		_, nd := run(t)
		tiedTo(t, nd, 1)
	})
	t.Run("control: no rule on the break's ends", func(t *testing.T) {
		withSeam(t, &breakNoEnds)
		r, nd := run(t)
		if nd.PlatformSession != nil || nd.Backlog || !nd.Skewed {
			t.Fatalf("want untied with node.skewed: %+v", nd)
		}
		noOtherWindows(t, r.l.SkewStats(), 2, 1)
	})
}

// stepAfterHello is T-8's third case, D5's: a break of 40 s with no step
// in it, both clocks stepped back 30 s together 1 s after the hello, and
// the backlog read for 90 s; a dial that fails 24 s after the step, and a
// backlog record made 35 s into the break, stamped so, read 70 s after the
// step: untied, node.backlog, no node.skewed. Controls as the second case.
func stepAfterHello(t *testing.T) {
	run := func(t *testing.T) (*rig, *netobs.Node) {
		r, s := breakRig(t, time.Second)
		s.cut()
		s.hold = true
		s.pass(35 * time.Second)
		s.synEnd(40001, s.now(), time.Time{})
		s.pass(5 * time.Second)
		s.connect(true) // the record is N: the backlog is read until it is
		s.pass(time.Second)
		s.step(-30*time.Second, -30*time.Second)
		s.pass(24 * time.Second)
		s.dialFails(1, 2*time.Second)
		s.pass(44 * time.Second)
		s.flush()
		return r, r.one(40001)
	}
	r, nd := run(t)
	backlogUntied(t, nd)
	noOtherWindows(t, r.l.SkewStats(), -1, 0)
	t.Run("control: no rule on the two clocks", func(t *testing.T) {
		withSeams(t, &breakNoEnds, &skewNoStored, &skewNoFloor)
		_, nd := run(t)
		tiedTo(t, nd, 1)
	})
	t.Run("control: no rule on the break's ends", func(t *testing.T) {
		withSeam(t, &breakNoEnds)
		r, nd := run(t)
		if nd.PlatformSession != nil || nd.Backlog || !nd.Skewed {
			t.Fatalf("want untied with node.skewed: %+v", nd)
		}
		noOtherWindows(t, r.l.SkewStats(), 2, 1)
	})
}

// TestShortBreakNodeStepNoTie is section 1.6's name for T-8's second and
// third cases.
func TestShortBreakNodeStepNoTie(t *testing.T) {
	t.Run("a step inside the break", shortBreakNodeStep)
	t.Run("a step after the hello", stepAfterHello)
}

// TestBreakOverBoundNoTie: backlog_tie_s is 60 s; a break of exactly 60 s
// keeps its ties under the made_utc check, and one 1 ns longer ties
// nothing: each backlog record untied with node.backlog. The boundary is
// the control (self-check item 2): a bound taken as at or above 60 s
// unties the first, and one above 61 s ties the second.
func TestBreakOverBoundNoTie(t *testing.T) {
	in := func(b time.Time) time.Time { return b.Add(6 * time.Second) }
	_, nd := cut20(t, 60*time.Second, in)
	tiedTo(t, nd, 1)
	r, nd := cut20(t, 60*time.Second+time.Nanosecond, in)
	backlogUntied(t, nd)
	if st := r.l.SkewStats(); st.Backlog != 1 {
		t.Fatalf("backlog count %d", st.Backlog)
	}
	t.Run("backlog_tie_s at its 120 s ceiling", func(t *testing.T) {
		r, _ := holdRig02With(t, func(o *Options) { o.BacklogTie = MaxBacklogTie })
		if r.l.backlogTie() != MaxBacklogTie {
			t.Fatal("the ceiling was not taken")
		}
		o := Options{Store: r.s, Monotonic: r.clk.mono, Received: received, BacklogTie: MaxBacklogTie + time.Nanosecond}
		if _, err := New(Config{NodeID: testNode, SensorID: testSensor, OutageHours: 1, ObservationQuota: 1, Stream: obsStream}, o); err == nil {
			t.Fatal("a backlog_tie_s above 120 s was taken")
		}
		// D3's N2 on #770: a negative value is refused, not read as the
		// default.
		o.BacklogTie = -time.Nanosecond
		if _, err := New(Config{NodeID: testNode, SensorID: testSensor, OutageHours: 1, ObservationQuota: 1, Stream: obsStream}, o); err == nil {
			t.Fatal("a negative backlog_tie_s was taken")
		}
	})
}

// TestFirstBreakAfterStartUnknown: after a node start the first break is
// unknown and counts as longer than backlog_tie_s, so a backlog record of
// a dial made after the start, 10 s into the break on both clocks, is
// untied with node.backlog. Control: a node that takes the first break as
// one of no length, under which the start bound refuses it instead, with
// node.skewed (counted prestart).
func TestFirstBreakAfterStartUnknown(t *testing.T) {
	run := func(t *testing.T) (*rig, *netobs.Node) {
		r, s := breakRig(t, 30*time.Second)
		b := s.now()
		s.cut()
		s.pass(2 * time.Second)
		r.restart()
		s.pass(3 * time.Second)
		s.dialFails(1, 2*time.Second)
		s.synEnd(40001, b.Add(6*time.Second), time.Time{})
		s.pass(3 * time.Second)
		s.connect(true)
		return r, r.one(40001)
	}
	r, nd := run(t)
	backlogUntied(t, nd)
	noOtherWindows(t, r.l.SkewStats(), -1, 0)
	t.Run("control: the first break of no length", func(t *testing.T) {
		withSeam(t, &firstBreakKnown)
		r, nd := run(t)
		if nd.PlatformSession != nil || nd.Backlog || !nd.Skewed {
			t.Fatalf("want untied with node.skewed: %+v", nd)
		}
		noOtherWindows(t, r.l.SkewStats(), 3, 1)
	})
}

// TestBacklogEndsAtCurrentRun, C13 T-7's node legs: a cut of 5 minutes;
// the backlog's records are untied with node.backlog until the newest_seq
// of the first current hello is read; a second cut of 20 s before it is
// through extends it, and a record read after it, stamped inside the
// second break and matching a dial made there, is judged by the longest
// break: untied. Once N is read, a record ties. Control: a node that
// judges the backlog by its latest break only, which ties the second
// record.
func TestBacklogEndsAtCurrentRun(t *testing.T) {
	run := func(t *testing.T) (*rig, *sim) {
		r, s := breakRig(t, 30*time.Second)
		b := s.now()
		s.cut()
		s.hold = true
		s.pass(60 * time.Second)
		s.dialFails(1, 2*time.Second)
		s.synEnd(40001, b.Add(61*time.Second), time.Time{})
		// A record stamped for the second break, numbered in the first.
		s.synEnd(40002, b.Add(311*time.Second), b.Add(311*time.Second))
		s.write(obs02(0)) // N
		s.pass(5*time.Minute - 62*time.Second)
		s.connect(true)
		s.sendN(1)
		s.pass(5 * time.Second)
		s.cut()
		s.pass(5 * time.Second)
		s.dialFails(2, 2*time.Second)
		s.pass(13 * time.Second)
		s.connect(true)
		s.sendN(1) // the second record
		s.sendN(1) // N: the backlog is through
		s.pass(5 * time.Second)
		s.dialFails(3, 2*time.Second)
		s.synEnd(40003, s.now().Add(-time.Second), time.Time{})
		s.flush()
		return r, s
	}
	r, _ := run(t)
	backlogUntied(t, r.one(40001))
	backlogUntied(t, r.one(40002))
	tiedTo(t, r.one(40003), 3)
	t.Run("control: the latest break only", func(t *testing.T) {
		withSeam(t, &backlogLatestBreak)
		r, _ := run(t)
		tiedTo(t, r.one(40002), 2)
	})
}

// TestBacklogEndRule is D1's ruling 7011321374 on #748, option (c), with
// D6's probe P9: the first break after a start, and CH-39's backlog, end
// at the first of a record of run X at or above N, run X's position at or
// above N, and a hello of another run or a later generation. While the
// first break stands, each heartbeat read raises the capture floor; after
// it, none does. Control: the rule before the ruling, which ends it only at
// a record of run X at or above N, under which every later heartbeat
// raises the floor, with no end until a node start.
func TestBacklogEndRule(t *testing.T) {
	// started: run 5 has records 1 and 2 taken, the node restarted, and
	// its first hello, current, states newest_seq 30: the first break.
	started := func(t *testing.T) (*rig, *sim) {
		r, _ := holdRig02(t)
		s := newSim(r)
		s.connect(true)
		s.write(obs02(0))
		s.write(obs02(0))
		s.cut()
		r.restart()
		s.seq = 30 // newest_seq 30: records 3 to 30 to come
		s.connect(true)
		s.seq = 2
		return r, s
	}
	// raises reports whether a heartbeat of the sim's run, read now and
	// stated ahead by d, raises the floor. Each call states a later time
	// than the one before (D6's B2 on #770), so a floor raised once can be
	// raised again only while the first break stands.
	raises := func(t *testing.T, r *rig, s *sim, d time.Duration) bool {
		t.Helper()
		before := r.l.SkewStats().Floor
		s.off += d
		s.heartbeat()
		s.off -= d
		return !r.l.SkewStats().Floor.Equal(before)
	}
	legs := map[string]func(t *testing.T, r *rig, s *sim){
		// P9: run X's tail never comes; run 6's hello follows.
		"another run's hello (P9)": func(t *testing.T, r *rig, s *sim) {
			s.cut()
			s.run, s.counter, s.newRun, s.seq, s.sent = testRun2, 6, true, 0, 0
			s.connect(true)
		},
		// The tail evicted: a tick whose sent_seq reaches N, the gap counted.
		"run X's position at N": func(t *testing.T, r *rig, s *sim) {
			s.seq, s.sent = 30, 30
			s.tick() // sent_seq 30
		},
		// A rekey: a later generation's hello of the same run (D6's P4).
		"a later generation's hello": func(t *testing.T, r *rig, s *sim) {
			s.cut()
			s.en = Enrolment{SensorID: testSensor, Generation: 3, Began: 1, ConfigDigest: testDigest}
			s.connect(true)
		},
	}
	for name, leg := range legs {
		t.Run(name, func(t *testing.T) {
			r, s := started(t)
			if !raises(t, r, s, time.Hour) {
				t.Fatal("a heartbeat of the first break raised no floor")
			}
			leg(t, r, s)
			if raises(t, r, s, 2*time.Hour) {
				t.Fatalf("a heartbeat after the break's end raised the floor to %s", r.l.SkewStats().Floor)
			}
			t.Run("control: the end at a record of run X only", func(t *testing.T) {
				withSeam(t, &backlogEndRecordOnly)
				r, s := started(t)
				if !raises(t, r, s, time.Hour) {
					t.Fatal("a heartbeat of the first break raised no floor")
				}
				leg(t, r, s)
				if !raises(t, r, s, 2*time.Hour) {
					t.Fatal("the control ended the first break")
				}
			})
		})
	}
	t.Run("a record of run X at N", func(t *testing.T) {
		r, s := started(t)
		for s.seq < 29 {
			s.write(obs02(0))
		}
		if !raises(t, r, s, time.Hour) { // seq 30, N itself, still raises
			t.Fatal("N raised no floor")
		}
		if raises(t, r, s, 2*time.Hour) {
			t.Fatal("a heartbeat past N raised the floor")
		}
	})
	// A later backlog is not the first break: its heartbeat, read below its
	// N and stated later than the floor, raises nothing. Control: D6's
	// mutant E6, every backlog taken as the first break, which raises it.
	t.Run("a later backlog", func(t *testing.T) {
		r, s := started(t)
		if !raises(t, r, s, time.Hour) {
			t.Fatal("a heartbeat of the first break raised no floor")
		}
		legs["run X's position at N"](t, r, s)
		s.cut()
		s.hold = true
		before := r.l.SkewStats().Floor
		s.off += 2 * time.Hour
		s.heartbeat() // seq 31
		s.off -= 2 * time.Hour
		s.write(obs02(0)) // seq 32: N
		s.connect(true)
		s.sendN(1)
		if f := r.l.SkewStats().Floor; !f.Equal(before) {
			t.Fatalf("a heartbeat of a later backlog raised the floor to %s", f)
		}
		if st := r.l.SkewStats(); st.Backlog != 0 {
			t.Fatalf("backlog count %d: the heartbeat is not a record", st.Backlog)
		}
	})
}

// TestBacklogExtendedBySecondBreak is D1's ruling 3 on #770 (D6's B1, with
// D6's probes P1 and P2): a break that begins before the backlog is through
// extends it, N rising to the newest_seq of run X's next hello, so the
// second break's own records, numbered past the first N, are read in the
// backlog and judged by its longest break. Each leg: two records buffered
// in a first break, X's hello and the first record read; a second break
// before the second is read, in which a dial fails and its syn_only end is
// made (seq 3); reconnect and flush: record 3 is untied with node.backlog.
// "a long second break": first 20 s, second 5 min. "a shorter second
// break": first 50 s, second 10 s; the longest break is the first, outside
// which record 3 was made. Controls: mutant M3, N kept at the first
// hello's, which ties record 3 in both; D6's E10 (a long second break not
// marked long) ties it in the first leg, and E11 (judged by the latest
// break) in the second.
func TestBacklogExtendedBySecondBreak(t *testing.T) {
	for name, brk := range map[string][2]time.Duration{
		"a long second break":    {20 * time.Second, 5 * time.Minute},
		"a shorter second break": {50 * time.Second, 10 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			r, s := breakRig(t, 30*time.Second)
			s.cut()
			s.hold = true
			s.write(obs02(0))
			s.write(obs02(0))
			s.pass(brk[0])
			s.connect(true) // N = 2
			s.sendN(1)
			s.cut()
			s.pass(brk[1] / 2)
			d := s.dialFails(1, time.Second)
			s.synEnd(40003, d.StartedAt.Add(500*time.Millisecond), time.Time{})
			s.pass(brk[1] - brk[1]/2 - time.Second)
			s.connect(true) // newest_seq 3
			s.flush()
			backlogUntied(t, r.one(40003))
			if st := r.l.SkewStats(); st.Backlog != 3 {
				t.Fatalf("backlog count %d, want records 1 to 3", st.Backlog)
			}
		})
	}
}

// TestBacklogNoOpenTie is D1's ruling 5 on #770, D6's probe P3: a flow
// tied by the late index (a 0.8 result) and left open; a cut of 90 s, in
// which the flow's end record is made; it is read in the backlog and
// commits untied with node.backlog, though the open table holds its key.
// Control: D6's mutant E15, openTie without its backlog check, which ties
// it.
func TestBacklogNoOpenTie(t *testing.T) {
	r, s := released(t, Session{InvocationID: inv(1), Connected: true}, endpoint, "tcp")
	at := s.now()
	s.flow(40001, at, time.Time{}, false)
	if st := r.l.Stats().Hold; st.LateTied != 1 || st.Open != 1 {
		t.Fatalf("hold %+v: want the start late-tied and open", st)
	}
	s.cut()
	s.pass(30 * time.Second)
	s.flow(40001, at, time.Time{}, true)
	s.pass(60 * time.Second)
	s.connect(true)
	os := r.fromPort(40001)
	if len(os) != 2 {
		t.Fatalf("%d records of the flow, want 2", len(os))
	}
	tiedTo(t, os[0].Node, 1)
	backlogUntied(t, os[1].Node)
	if st := r.l.Stats().Hold; st.Open != 0 {
		t.Fatalf("hold %+v: want the end to release the key", st)
	}
}
