package sensorlink

import (
	"net/netip"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// The late index, part (e) of the hold (D5-sensor-node.md section 1.6 and
// its tests), desk only. Each own session is a dial that fails, released
// with no flow tied; the flow's record comes after its Result on a live
// connection, with no break.

func untiedOwnKey(t *testing.T, nd *netobs.Node) {
	t.Helper()
	if nd.PlatformSession != nil || nd.Backlog || nd.Skewed {
		t.Fatalf("want untied under its own key, unmarked: %+v", nd)
	}
}

// TestLateRecordTied: a record of a flow in a failed dial's window, read
// after the Result, ties by the late index. Control: no index, untied.
func TestLateRecordTied(t *testing.T) {
	run := func(t *testing.T) *rig {
		r, s := breakRig(t, 30*time.Second)
		d := s.dialFails(1, 2*time.Second)
		s.flow(40001, d.StartedAt.Add(time.Second), time.Time{}, false)
		return r
	}
	r := run(t)
	tiedTo(t, r.one(40001), 1)
	if st := r.l.Stats().Hold; st.LateTied != 1 || st.Late != 0 || st.Open != 1 {
		t.Fatalf("hold %+v: want one late tie, the entry spent, the flow open", st)
	}
	t.Run("control: no late index", func(t *testing.T) {
		withSeam(t, &lateIndexOff)
		untiedOwnKey(t, run(t).one(40001))
	})
	// Result's rules (section 1.6): a 0.9 result that connected ties its
	// 5-tuple only; a 0.8 result, with no local address, the first flow in
	// its window; a failed dial's window a TCP flow only. Mutants B7 and B8
	// (the PR's body): the 5-tuple unchecked, and a failed dial's window
	// open to any transport.
	released := func(t *testing.T, s Session, ep netip.AddrPort, l4 string) (*rig, *sim) {
		r, sm := breakRig(t, 30*time.Second)
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: ep, L4: l4}); err != nil {
			t.Fatal(err)
		}
		s.StartedAt = r.now()
		sm.pass(2 * time.Second)
		s.EndedAt = r.now()
		if _, err := r.l.Result(bg, "req-1", s); err != nil {
			t.Fatal(err)
		}
		return r, sm
	}
	t.Run("a 0.9 result: its 5-tuple only", func(t *testing.T) {
		r, s := released(t, Session{InvocationID: inv(1), Connected: true, Local: netip.AddrPortFrom(netip.MustParseAddr(nodeAddr), 40002)}, endpoint, "tcp")
		s.flow(40001, s.now(), time.Time{}, false)
		s.flow(40002, s.now(), time.Time{}, false)
		untiedOwnKey(t, r.one(40001))
		if ps := r.one(40002).PlatformSession; ps == nil || ps.Tie != TieConnection || ps.InvocationID != inv(1) {
			t.Fatalf("the session's 5-tuple: %+v", ps)
		}
	})
	t.Run("a 0.8 result: the first flow in its window", func(t *testing.T) {
		r, s := released(t, Session{InvocationID: inv(1), Connected: true}, endpoint, "tcp")
		s.flow(40001, s.now(), time.Time{}, false)
		tiedTo(t, r.one(40001), 1)
	})
	t.Run("a failed dial: a TCP flow only", func(t *testing.T) {
		r, s := released(t, Session{InvocationID: inv(1)}, netip.AddrPortFrom(endpoint.Addr(), 161), "udp")
		s.write(quietFlow(quietRun{40001, 161, "udp"}, s.now(), false))
		untiedOwnKey(t, r.one(40001))
	})
}

// TestLateIndexTiesOnce: an entry ties one flow and is then spent, so a
// second flow in the dial's window commits untied and alerts (AP-35).
// Control: the entry not spent, which ties both.
func TestLateIndexTiesOnce(t *testing.T) {
	run := func(t *testing.T) *rig {
		r, s := breakRig(t, 30*time.Second)
		d := s.dialFails(1, 2*time.Second)
		s.flow(40001, d.StartedAt.Add(time.Second), time.Time{}, false)
		s.flow(40002, d.StartedAt.Add(time.Second), time.Time{}, false)
		return r
	}
	r := run(t)
	tiedTo(t, r.one(40001), 1)
	untiedOwnKey(t, r.one(40002))
	t.Run("control: the entry not spent", func(t *testing.T) {
		withSeam(t, &lateNotSpent)
		tiedTo(t, run(t).one(40002), 1)
	})
	// A refusal spends it too: a first flow refused while the latest
	// sample stands outside max_skew_ms, and a second flow in the window
	// once the next tick has cleared it, untied. Mutant B6 (the PR's
	// body): an entry spent only by a tie, which ties the second.
	t.Run("a refusal spends it", func(t *testing.T) {
		r, s := breakRig(t, 30*time.Second)
		d := s.dialFails(1, 2*time.Second)
		s.pass(8 * time.Second)
		s.step(0, -3*time.Second)
		s.pass(10 * time.Second) // a tick 3 s behind: the latest sample stands
		s.flow(40001, d.StartedAt.Add(time.Second), time.Time{}, false)
		skewedUntied(t, r.one(40001))
		s.step(0, 3*time.Second)
		s.pass(10 * time.Second) // the next tick clears it
		s.flow(40002, d.StartedAt.Add(time.Second), time.Time{}, false)
		untiedOwnKey(t, r.one(40002))
		noOtherWindows(t, r.l.SkewStats(), cLatest, 1)
	})
}

// TestLateIndexOnlyUntiedSessions: a session whose Result tied a flow does
// not enter the index (D3's L2 (i)), so a later flow in its window
// commits untied. Control: a node that indexes every session released,
// which ties it.
func TestLateIndexOnlyUntiedSessions(t *testing.T) {
	run := func(t *testing.T) *rig {
		r, s := breakRig(t, 30*time.Second)
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		from := r.now()
		s.flow(40001, from, time.Time{}, false)
		end := ownFlow02(0, 40001, from, true)
		end.Flow.SynOnly = ptr(true)
		end.MadeUTC = ""
		s.write(end)
		r.pass(2 * time.Second)
		if _, err := r.l.Result(bg, "req-1", Session{InvocationID: inv(1), StartedAt: from, EndedAt: r.now()}); err != nil {
			t.Fatal(err)
		}
		s.flow(40002, from.Add(time.Second), time.Time{}, false)
		return r
	}
	r := run(t)
	if os := r.fromPort(40001); len(os) != 2 || os[0].Node.PlatformSession == nil {
		t.Fatalf("the dial's own flow did not tie at the Result: %d records", len(os))
	}
	untiedOwnKey(t, r.one(40002))
	t.Run("control: every session indexed", func(t *testing.T) {
		withSeam(t, &lateIndexAll)
		tiedTo(t, run(t).one(40002), 1)
	})
}

// TestLateIndexEmptyAtStart: a session released with no flow tied before a
// stop, and after the start, with no break left to judge, a flow from the
// node's address that matches it: committed untied under its own key,
// without node.skewed, and no skew count moves. Control: a node that
// rebuilds the index at a start (its entries recorded before the start),
// which commits it with node.skewed, counted prestart.
func TestLateIndexEmptyAtStart(t *testing.T) {
	run := func(t *testing.T, rebuild bool) *rig {
		r, s := breakRig(t, 60*time.Second)
		c := s.now()
		s.cut()
		s.pass(5 * time.Second)
		d := s.dialFails(1, 2*time.Second)
		s.pass(3 * time.Second)
		old := r.l.hold.late
		r.restart()
		if rebuild {
			for _, e := range old {
				e.live = false
				r.l.hold.late = append(r.l.hold.late, e)
			}
		}
		s.pass(c.Add(50 * time.Second).Sub(s.now()))
		s.connect(true) // nothing buffered: the first backlog is through at the hello
		s.flow(40001, d.StartedAt.Add(45*time.Second), time.Time{}, false)
		return r
	}
	r := run(t, false)
	untiedOwnKey(t, r.one(40001))
	noOtherWindows(t, r.l.SkewStats(), -1, 0)
	t.Run("control: the index rebuilt at the start", func(t *testing.T) {
		r := run(t, true)
		if nd := r.one(40001); nd.PlatformSession != nil || !nd.Skewed {
			t.Fatalf("want untied with node.skewed: %+v", nd)
		}
		noOtherWindows(t, r.l.SkewStats(), 3, 1)
	})
}

// TestLatePastHorizon: an entry ties a record read 15 minutes after its
// session's end, on the node's clock, and not one read 1 ns later, which
// commits untied, counted late_untied (horizon). The boundary is the
// control (self-check item 2).
func TestLatePastHorizon(t *testing.T) {
	run := func(t *testing.T, after time.Duration) *rig {
		r, s := breakRig(t, 30*time.Second)
		d := s.dialFails(1, 2*time.Second)
		s.hold = true
		s.flow(40001, d.StartedAt.Add(time.Second), time.Time{}, false)
		s.pass(after)
		s.flush()
		return r
	}
	r := run(t, HoldLateHorizon)
	tiedTo(t, r.one(40001), 1)
	r = run(t, HoldLateHorizon+time.Nanosecond)
	nd := r.one(40001)
	if nd.PlatformSession != nil || nd.Skewed || nd.Backlog {
		t.Fatalf("past the horizon: %+v", nd)
	}
	if st := r.l.Stats().Hold; st.LateHorizon != 1 || st.Late != 0 {
		t.Fatalf("hold %+v", st)
	}
}

// TestLateIndexBound: HoldLateEntries (1,024) entries are kept; one more
// evicts the oldest, counted late_untied (evicted), and raises
// sensor-late-index-short once for the stretch, inside its horizon; a flow
// that only the evicted entry matched commits untied. The boundary is the
// control: at 1,024 the oldest entry still ties and nothing is raised.
func TestLateIndexBound(t *testing.T) {
	run := func(t *testing.T, n int) *rig {
		r, s := breakRig(t, 30*time.Second)
		first := s.dialFails(1, 2*time.Second)
		r.pass(2 * time.Minute) // the others' windows are clear of the first's
		for i := 2; i <= n; i++ {
			s.dialFails(i, time.Millisecond)
		}
		s.flow(40001, first.StartedAt.Add(time.Second), time.Time{}, false)
		return r
	}
	r := run(t, HoldLateEntries)
	tiedTo(t, r.one(40001), 1)
	if r.al.count(AlarmLateIndexShort) != 0 || r.l.Stats().Hold.LateEvicted != 0 {
		t.Fatal("an entry was evicted at the bound")
	}
	r = run(t, HoldLateEntries+2)
	untiedOwnKey(t, r.one(40001))
	if st := r.l.Stats().Hold; st.LateEvicted != 2 || st.Late != HoldLateEntries {
		t.Fatalf("hold %+v", st)
	}
	if n := r.al.count(AlarmLateIndexShort); n != 1 {
		t.Fatalf("sensor-late-index-short raised %d times, want once for the stretch", n)
	}
}
