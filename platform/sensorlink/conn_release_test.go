package sensorlink

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// A-3's release legs (C13 0.2 section 15; D5-sensor-node.md section 1.4
// items 2 and 3) and D4's N3 on #732, desk only: the tests hand the link
// an in-memory pipe and a restored hold; no sensor and no device.

// holdSaves is the hold's saved records, kept across a restart, and what
// the next start restores.
type holdSaves struct {
	mu      sync.Mutex
	saved   []RunRecord
	restore []RunRecord
}

func (h *holdSaves) save(_ context.Context, rec RunRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	var back RunRecord
	if err := json.Unmarshal(b, &back); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.saved = append(h.saved, back)
	return nil
}

func (h *holdSaves) last() RunRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.saved[len(h.saved)-1]
}

// holdRig is a 0.2 rig whose link holds the node's own flows to endpoint.
func holdRig02(t *testing.T) (*rig, *holdSaves) {
	hs := &holdSaves{}
	var r *rig
	r = newRig(t, func(o *Options) {
		hs.mu.Lock()
		restore := hs.restore
		hs.mu.Unlock()
		o.Hold = HoldConfig{NodeAddrs: []netip.Addr{netip.MustParseAddr(nodeAddr)}, TieGrace: 30 * time.Second,
			Now: func() time.Time { return r.now() }, Save: hs.save, Restore: restore}
	})
	return r, hs
}

// nodeFlow02 is a flow start from the node's address to endpoint, which a
// dispatched run holds.
func nodeFlow02(seq int) *netobs.Observation {
	o := obs02(seq)
	o.IP.Src, o.IP.Dst, o.IP.Sport, o.IP.Dport = nodeAddr, endpoint.Addr().String(), ptr(40000+seq), ptr(int(endpoint.Port()))
	o.FirstUTC = t0.Add(time.Second).Format("2006-01-02T15:04:05.000000Z")
	o.LastUTC = o.FirstUTC
	return o
}

// heldOne dispatches a run, has run 5's hello accepted, and sends record
// n, which the hold keeps. The cursor saves after it are made to fail and
// the connection ends: the node killed between the hold's save and the
// next cursor save, so the saved T is n - 1. It returns the held record.
func heldOne(t *testing.T, r *rig, hs *holdSaves, n int) HeldRecord {
	t.Helper()
	if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
		t.Fatal(err)
	}
	h := hello02()
	h.FirstSeq = itoa(n)
	p := r.accepted(h)
	p.send(nodeFlow02(n))
	p.taken()
	rec := hs.last()
	if rec.State != HoldHolding || len(rec.Flows) != 1 || len(rec.Flows[0].Records) != 1 {
		t.Fatalf("not held: %+v", rec)
	}
	r.cs.failNext(1 << 20)
	p.end()
	r.cs.failNext(0)
	if c := cursorNow(t, r.cs); c.Taken != uint64(n-1) {
		t.Fatalf("saved T %d before the kill, want %d", c.Taken, n-1)
	}
	return rec.Flows[0].Records[0]
}

// restartHeld restarts the link with the hold's saved records restored,
// as a node start reads them, and runs RecoverHold.
func restartHeld(t *testing.T, r *rig, hs *holdSaves, restore []RunRecord) {
	t.Helper()
	hs.mu.Lock()
	hs.restore = restore
	hs.mu.Unlock()
	r.restart()
	if err := r.l.RecoverHold(bg); err != nil {
		t.Fatal(err)
	}
}

// withBody is hr with its stored body's run, seq, assets and node.lost
// set; "" keeps a field.
func withBody(t *testing.T, hr HeldRecord, run string, seq uint64, unresolved bool, lost []netobs.Span) HeldRecord {
	t.Helper()
	var top, node map[string]json.RawMessage
	if err := json.Unmarshal(hr.Observation, &top); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(top["node"], &node); err != nil {
		t.Fatal(err)
	}
	set := func(m map[string]json.RawMessage, k string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		m[k] = b
	}
	if run != "" {
		hr.RunID = run
		set(top, "run_id", run)
	}
	if seq != 0 {
		hr.Seq = seq
		set(top, "seq", itoa(int(seq)))
	}
	if unresolved {
		set(node, "src_asset", netobs.AssetUnresolved)
		set(node, "dst_asset", netobs.AssetUnresolved)
	}
	if lost != nil {
		set(node, "lost", lost)
	}
	set(top, "node", node)
	b, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	hr.Observation = b
	return hr
}

// releasing is a run saved as releasing rel, whose batch had not committed
// at the kill (head is the stream's head then).
func releasing(rel []HeldRecord, head uint64) RunRecord {
	rr := RunRecord{State: HoldReleasing, Run: HoldRun{RequestID: "req-k", AssetID: relay, Endpoint: endpoint, L4: "tcp",
		Deadline: t0.Add(time.Hour)}, Head: head}
	for _, hr := range rel {
		rr.Releasing = append(rr.Releasing, Release{Record: hr})
	}
	return rr
}

func saveTestCursor(t *testing.T, r *rig, c *Cursor) {
	t.Helper()
	b, err := encodeCursor(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.cs.SaveSourceCursor(bg, b); err != nil {
		t.Fatal(err)
	}
}

func head(t *testing.T, r *rig) uint64 {
	t.Helper()
	h, err := r.s.LastCommitted(bg)
	if err != nil {
		t.Fatal(err)
	}
	return uint64(h)
}

// TestHoldReleaseMovesTOnce is A-3's release legs: a record the hold keeps
// is stored once whichever way its release and its resend meet after a
// kill between the hold's save and the next cursor save. Controls: a
// release that does not move T in its transaction (n stored twice); a
// release that moves T whatever the run (the next run's records dropped as
// duplicates); an ack of T itself.
func TestHoldReleaseMovesTOnce(t *testing.T) {
	t.Run("deadline release before the resend", func(t *testing.T) {
		r, hs := holdRig02(t)
		heldOne(t, r, hs, 1)
		restartHeld(t, r, hs, []RunRecord{hs.last()})
		r.addWall(HoldRunLimit + time.Minute) // past the run's deadline
		r.l.TickHold(bg)
		if c := cursorNow(t, r.cs); c.Taken != 1 {
			t.Fatalf("the release left T at %d, want 1", c.Taken)
		}
		p := r.accepted(resume(1, 1))
		p.send(nodeFlow02(1)) // the resend
		p.taken()
		if n := len(storedObs(t, r.s)); n != 1 {
			t.Fatalf("record 1 stored %d times", n)
		}
		if d := r.l.Stats().Dropped[RefusedDuplicate]; d != 1 {
			t.Fatalf("duplicates %d, want 1", d)
		}
	})
	t.Run("RecoverHold at start", func(t *testing.T) {
		r, hs := holdRig02(t)
		hr := heldOne(t, r, hs, 1)
		restartHeld(t, r, hs, []RunRecord{releasing([]HeldRecord{hr}, head(t, r))})
		if c := cursorNow(t, r.cs); c.Taken != 1 {
			t.Fatalf("RecoverHold left T at %d, want 1: the first taken would leave record 1 out", c.Taken)
		}
		p := r.accepted(resume(1, 1))
		p.send(nodeFlow02(1))
		p.taken()
		if n := len(storedObs(t, r.s)); n != 1 {
			t.Fatalf("record 1 stored %d times", n)
		}
	})
	t.Run("a record the budget drops at its release", func(t *testing.T) {
		r, hs := holdRig02(t)
		hr := heldOne(t, r, hs, 1)
		// The unresolved budget starts empty, so the release drops it.
		hr = withBody(t, hr, "", 0, true, nil)
		restartHeld(t, r, hs, []RunRecord{releasing([]HeldRecord{hr}, head(t, r))})
		c := cursorNow(t, r.cs)
		if c.Taken != 1 || c.Dropped != 1 {
			t.Fatalf("after the drop T %d, dropped %d; want 1 and 1", c.Taken, c.Dropped)
		}
		if n := len(storedObs(t, r.s)); n != 0 {
			t.Fatalf("%d stored", n)
		}
	})
	t.Run("an earlier run's record after the next run's hello", func(t *testing.T) {
		r, hs := holdRig02(t)
		hr := heldOne(t, r, hs, 5)
		// Run 6 accepted with nothing taken; run 5's record 5 released now.
		saveTestCursor(t, r, &Cursor{Generation: 2, RunCounter: 6, RunID: testRun2, Digest: testDigest})
		dropped := withBody(t, hr, "", 6, true, nil)
		restartHeld(t, r, hs, []RunRecord{releasing([]HeldRecord{hr, dropped}, head(t, r))})
		c := cursorNow(t, r.cs)
		if c.RunID != testRun2 || c.Taken != 0 || c.Dropped != 1 {
			t.Fatalf("run 6's cursor %+v: want T 0 and run 5's drop in its total", c)
		}
		got := storedObs(t, r.s)
		if len(got) != 1 || got[0].RunID != testRun || got[0].Seq != "5" {
			t.Fatalf("stored %+v", got)
		}
		h := resume(1, 20) // run 6 resumed: its hello was accepted before the release
		h.RunCounter, h.RunID = "6", testRun2
		p := r.accepted(h)
		o := obs02(1)
		o.RunID, o.Citation.CaptureID = testRun2, "ring:"+testRun2+":3"
		p.send(o)
		p.ack(1)
		if n := len(storedObs(t, r.s)); n != 2 {
			t.Fatalf("run 6's record 1 not stored (%d stored)", n)
		}
	})
	t.Run("a mid-connection release acks no more than was read and sent", func(t *testing.T) {
		r, hs := holdRig02(t)
		hr := heldOne(t, r, hs, 1)
		late := withBody(t, hr, "", 10, false, nil)
		late.Seq = 10
		hold := RunRecord{State: HoldHolding, Run: HoldRun{RequestID: "req-m", AssetID: relay, Endpoint: endpoint, L4: "tcp",
			Deadline: r.now().Add(time.Second)}, Flows: []HeldFlow{{Records: []HeldRecord{late}}}}
		saveTestCursor(t, r, &Cursor{Generation: 2, RunCounter: 5, RunID: testRun, Taken: 9, G: 0, Digest: testDigest})
		restartHeld(t, r, hs, []RunRecord{hold})
		p := r.accepted(resume(4, 20)) // T 9 from the cursor, L 3 on this connection
		r.addWall(time.Minute)
		r.l.TickHold(bg) // releases record 10: T 10
		if c := cursorNow(t, r.cs); c.Taken != 10 {
			t.Fatalf("T %d after the release, want 10", c.Taken)
		}
		r.tickAfter(p, tick02(20, 3, 0)) // sent_seq 3: T is above what was read and sent
		p.send(obs02(11))
		select { // the next ack names 11: none named T 10 after the tick
		case a := <-p.acks:
			if a == nil || num(a.Seq) != 11 {
				t.Fatalf("ack %+v after the release, want 11", a)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("no ack of 11")
		}
	})
}

// D4's N3 on #732: a held observation that carries node.lost and is
// dropped at its release leaves its window unmarked, so the run's next
// stored observation carries it. Control: the marks kept as they were.
func TestHeldLostDroppedAtReleaseMarksNext(t *testing.T) {
	r, hs := holdRig02(t)
	hr := heldOne(t, r, hs, 1)
	w := lspan("09:00:00", "09:00:05")
	saveTestCursor(t, r, &Cursor{Generation: 2, RunCounter: 5, RunID: testRun, Digest: testDigest,
		Spans: []HeldSpan{{FromUTC: w.FromUTC, ToUTC: w.ToUTC, CutUTC: w.ToUTC, Marked: true}}})
	hr = withBody(t, hr, "", 0, true, []netobs.Span{w})
	restartHeld(t, r, hs, []RunRecord{releasing([]HeldRecord{hr}, head(t, r))})
	if c := cursorNow(t, r.cs); len(c.Spans) != 1 || c.Spans[0].Marked {
		t.Fatalf("the dropped record's window is still marked: %+v", c.Spans)
	}
	p := r.accepted(resume(2, 20))
	p.send(obs02(2))
	p.ack(2)
	got := storedObs(t, r.s)
	if len(got) != 1 || len(got[0].Node.Lost) != 1 || got[0].Node.Lost[0].FromUTC != w.FromUTC {
		t.Fatalf("the next stored observation carries %+v", got)
	}
}

// GapRaised in the link's memory (D1's ruling 6952181701 on #732, option
// (b)): sensor-gap-undeclared rises once for an excess, not again at a
// reconnect, and once more after a node start, which is loud, never
// quiet. Control: the excess forgotten at each connection, which raises
// it again at the reconnect.
func TestGapRaisedKeptInMemory(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	p.send(obs02(1), obs02(3)) // G 1 above D 0
	p.ack(3)
	p.end()
	if n := r.al.count(AlarmGapUndeclared); n != 1 {
		t.Fatalf("%d raises at the first connection's end", n)
	}
	p = r.accepted(resume(4, 20))
	p.end()
	if n := r.al.count(AlarmGapUndeclared); n != 1 {
		t.Fatalf("%d raises after a reconnect, want 1", n)
	}
	r.restart()
	p = r.accepted(resume(4, 20))
	p.end()
	if n := r.al.count(AlarmGapUndeclared); n != 1 {
		t.Fatalf("%d raises after the node start, want 1 (raised once more)", n)
	}
}

// An owed event written again is the same event byte for byte, though the
// sensor states its span's times in another form than the saved cursor
// keeps (Owed's key, D4's N4 on #732): the node writes a span's times in
// one form from admission on. The first write is from the connection's
// cursor, its clearing save fails, and the repeat after a node start is
// from the saved cursor. Control: the sensor's text kept at admission.
func TestOwedRepeatSameFormAcrossRestart(t *testing.T) {
	var r *rig
	var got []Owed
	r = newRig(t, func(o *Options) {
		o.Owed = func(_ context.Context, w Owed) error {
			got = append(got, w)
			r.cs.failNext(1) // the save that clears the marks
			return nil
		}
	})
	h := hello02()
	h.DropsChannel = "1"
	h.Lost = []netobs.Span{{FromUTC: "2026-11-07T09:30:00.000000Z", ToUTC: "2026-11-07T09:31:00.500000Z"}}
	h.Prior.RunsSkipped = "0"
	r.accepted(h).end()
	r.restart()
	_ = r.l.WriteOwed(bg) // its clearing save fails too: only the write is compared
	if len(got) != 2 {
		t.Fatalf("%d writes, want 2", len(got))
	}
	if a, b := string(mustJSON(t, got[0])), string(mustJSON(t, got[1])); a != b {
		t.Fatalf("the repeat differs:\n%s\n%s", a, b)
	}
}
