package sensorlink

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
)

// The intake hold (D4-72, baseline note section 5). Constructed records,
// desk only: no sensor produced them and no device was contacted. The node
// is at 192.0.2.5 and the relay's SSH endpoint at 192.0.2.20:22.
const nodeAddr = "192.0.2.5"

var (
	endpoint = netip.MustParseAddrPort("192.0.2.20:22")
	t0       = time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC) // the sensor's flows start just after
)

type holdRig struct {
	t        *testing.T
	s        netStore
	c        *clock
	wall     time.Time
	saved    []RunRecord
	failSave int
	okFirst  int // saves that pass before failSave's start failing
	l        *Link
	seq      int
	run      string
}

func newHoldRig(t *testing.T) *holdRig {
	t.Helper()
	g := &holdRig{t: t, s: openNet(t, 64<<20), c: &clock{}, wall: t0, run: testRun}
	g.l = g.link(nil)
	return g
}

// link makes a link over the rig's store, restored from restore.
func (g *holdRig) link(restore []RunRecord) *Link {
	g.t.Helper()
	l, err := New(Config{NodeID: testNode, SensorID: testSensor, EvidenceClass: "simulated", OutageHours: 1,
		ObservationQuota: 64 << 20, Stream: obsStream},
		Options{Assets: testAssets(), Store: g.s, Monotonic: g.c.mono, Received: received,
			Hold: HoldConfig{NodeAddrs: []netip.Addr{netip.MustParseAddr(nodeAddr)}, TieGrace: 30 * time.Second,
				Now: func() time.Time { return g.wall }, Save: g.save, Restore: restore}})
	if err != nil {
		g.t.Fatal(err)
	}
	return l
}

// save keeps each record as the node would store it: as JSON.
func (g *holdRig) save(_ context.Context, rec RunRecord) error {
	if g.okFirst > 0 {
		g.okFirst--
	} else if g.failSave > 0 {
		g.failSave--
		return errors.New("test: the intake write failed")
	}
	b, err := json.Marshal(rec)
	if err != nil {
		g.t.Fatal(err)
	}
	var back RunRecord
	if err := json.Unmarshal(b, &back); err != nil {
		g.t.Fatal(err)
	}
	g.saved = append(g.saved, back)
	return nil
}

// restore is what a start reads: the newest record of each run that is
// not released, in order, then the newest record of all.
func (g *holdRig) restore() []RunRecord {
	newest := map[string]int{}
	for i, r := range g.saved {
		newest[r.Run.RequestID] = i
	}
	var out []RunRecord
	for i, r := range g.saved {
		if newest[r.Run.RequestID] == i && r.State != HoldReleased && i != len(g.saved)-1 {
			out = append(out, r)
		}
	}
	return append(out, g.saved[len(g.saved)-1])
}

func (g *holdRig) dispatch(id string) {
	g.t.Helper()
	if err := g.l.Dispatch(bg, HoldRun{RequestID: id, AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
		g.t.Fatal(err)
	}
}

// obs is a record between the node's port sport and the endpoint, at
// first_utc t0+at: a flow start, a function, or an end (syn_only or not).
func (g *holdRig) obs(kind string, sport int, at time.Duration) *netobs.Observation {
	g.seq++
	o := flow(g.seq, nodeAddr, endpoint.Addr().String())
	o.RunID, o.Citation.CaptureID = g.run, "ring:"+g.run+":3"
	o.IP.Sport, o.IP.Dport = ptr(sport), ptr(int(endpoint.Port()))
	o.FirstUTC = t0.Add(at).Format("2006-01-02T15:04:05.000000Z")
	o.LastUTC = o.FirstUTC
	switch kind {
	case "function":
		o.Kind, o.Flow, o.Function = netobs.KindFunction, nil, &netobs.Function{Code: 1, Objects: []string{"g1v2"}}
	case "end", "syn":
		o.Flow = &netobs.Flow{Phase: "end", End: "fin", SynOnly: ptr(kind == "syn"), Packets: 3, Bytes: 222}
		if kind == "syn" {
			o.Flow.End = "rst"
		}
	}
	return o
}

func (g *holdRig) send(recs ...any) {
	g.t.Helper()
	if err := g.l.Serve(bg, stream(g.t, recs...)); err != nil {
		g.t.Fatal(err)
	}
}

// committed is each committed observation's sensor seq and tie.
type tied struct {
	seq        int
	invocation string
	tie        string
}

func (g *holdRig) committed() (out []tied) {
	g.t.Helper()
	for _, s := range stored(g.t, g.s) {
		var e event.Event
		if err := json.Unmarshal(s.Event, &e); err != nil {
			g.t.Fatal(err)
		}
		var o netobs.Observation
		if err := json.Unmarshal(e.Netobs, &o); err != nil {
			g.t.Fatal(err)
		}
		n, _ := strconv.Atoi(o.Seq)
		x := tied{seq: n}
		if ps := o.Node.PlatformSession; ps != nil {
			x.invocation, x.tie = ps.InvocationID, ps.Tie
		}
		out = append(out, x)
	}
	return out
}

func want(t *testing.T, got []tied, w ...tied) {
	t.Helper()
	if len(got) != len(w) {
		t.Fatalf("committed %+v, want %+v", got, w)
	}
	for i := range w {
		if got[i] != w[i] {
			t.Fatalf("committed %+v, want %+v", got, w)
		}
	}
}

const (
	inv1 = "11111111-1111-4111-8111-111111111111"
	inv2 = "22222222-2222-4222-8222-222222222222"
)

// session09 is a connected 0.9 session from the node's port sport.
func session09(inv string, sport int, connected time.Duration) Session {
	return Session{InvocationID: inv, StartedAt: t0.Add(connected - time.Second), EndedAt: t0.Add(connected + 20*time.Second),
		Connected: true, Local: netip.AddrPortFrom(netip.MustParseAddr(nodeAddr), uint16(sport)), ConnectedAt: t0.Add(connected)}
}

// (a) The connection tie: the session's own 5-tuple ties, in arrival order,
// and stays open by its key (d) until its end; a new start on the same
// 5-tuple after the end, and a flow from another port, are untied.
func TestHoldConnectionTie(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0), g.obs("function", 40001, time.Second))
	if c := g.committed(); len(c) != 0 || g.l.Stats().Hold.Held != 2 {
		t.Fatalf("committed before the result: %+v, %+v", c, g.l.Stats().Hold)
	}
	after, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0))
	if err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{2, inv1, TieConnection})
	if after.AfterSeq != 2 || after.OpenFlow {
		t.Fatalf("released %+v, want after_seq 2", after)
	}
	if last := g.saved[len(g.saved)-1]; last.State != HoldReleased || last.AfterSeq != 2 || len(last.Open) != 1 || last.Open[0].Key.Node.Port() != 40001 {
		t.Fatalf("the release record %+v", last)
	}
	// Later records tie by the open key; another port does not (row (d) 4).
	g.send(g.obs("function", 40001, time.Minute), g.obs("start", 40009, time.Minute))
	g.send(g.obs("end", 40001, 2*time.Minute))
	if last := g.saved[len(g.saved)-1]; len(last.Open) != 0 {
		t.Fatalf("the end did not release the key in the record: %+v", last.Open)
	}
	g.send(g.obs("start", 40001, 3*time.Minute)) // a new start after the end
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{2, inv1, TieConnection}, tied{3, inv1, TieConnection},
		tied{4, "", ""}, tied{5, inv1, TieConnection}, tied{6, "", ""})
	if s := g.l.Stats().Hold; s.Held != 0 || s.Runs != 0 || s.Open != 0 {
		t.Fatalf("hold %+v", s)
	}
}

// (b) The window tie of a 0.8 result: the first established flow in the
// window ties, and a second established one is untied.
func TestHoldWindowTie08(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0), g.obs("function", 40001, time.Second), g.obs("start", 40002, 2*time.Second), g.obs("function", 40002, 3*time.Second))
	s := Session{InvocationID: inv1, StartedAt: t0.Add(-time.Second), EndedAt: t0.Add(20 * time.Second), Connected: true}
	if _, err := g.l.Result(bg, "req-1", s); err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, inv1, TieWindow}, tied{2, inv1, TieWindow}, tied{3, "", ""}, tied{4, "", ""})
}

// A spoofed second session from the node's address inside the window
// commits untied, and only the session's own 5-tuple ties (AP-35).
func TestHoldSpoofedSecondSession(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40002, 0), g.obs("function", 40002, time.Second), g.obs("start", 40001, 2*time.Second))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 2*time.Second)); err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, "", ""}, tied{2, "", ""}, tied{3, inv1, TieConnection})
}

// An ephemeral port reused by a later run ties only to its own run (D2).
func TestHoldReusedPort(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	g.send(g.obs("end", 40001, 10*time.Second))
	g.wall = g.wall.Add(10 * time.Minute)
	g.dispatch("req-2")
	g.send(g.obs("start", 40001, 10*time.Minute), g.obs("end", 40001, 10*time.Minute+5*time.Second))
	if _, err := g.l.Result(bg, "req-2", session09(inv2, 40001, 10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{2, inv1, TieConnection}, tied{3, inv2, TieConnection}, tied{4, inv2, TieConnection})
	// A start outside the session's interval does not tie, even on its
	// exact 5-tuple.
	g.wall = g.wall.Add(10 * time.Minute)
	g.dispatch("req-3")
	g.send(g.obs("start", 40001, 0))
	if _, err := g.l.Result(bg, "req-3", session09(inv1, 40001, 20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if c := g.committed(); c[4] != (tied{5, "", ""}) {
		t.Fatalf("an old start tied: %+v", c)
	}
}

// (c) Failed dials: a syn_only flow to the endpoint from another port takes
// the window tie; one still open at the result waits for its end, takes the
// tie at a syn_only end, and gives way untied at its wait, or at once on a
// new sensor run.
func TestHoldFailedDial(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0), g.obs("syn", 40001, time.Second), g.obs("start", 40002, 2*time.Second), g.obs("start", 40003, 3*time.Second))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40003, 3*time.Second)); err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, inv1, TieWindow}, tied{2, inv1, TieWindow}, tied{4, inv1, TieConnection})
	if s := g.l.Stats().Hold; s.Held != 1 || s.Runs != 1 {
		t.Fatalf("the waiting dial: %+v", s)
	}
	g.send(g.obs("syn", 40002, 5*time.Second))
	want(t, g.committed(), tied{1, inv1, TieWindow}, tied{2, inv1, TieWindow}, tied{4, inv1, TieConnection},
		tied{3, inv1, TieWindow}, tied{5, inv1, TieWindow})

	// Its wait: arrival + MaxConnectTimeoutMS + flow_idle_s + g.
	g.dispatch("req-2")
	g.send(g.obs("start", 40005, 0), g.obs("start", 40006, 0))
	if _, err := g.l.Result(bg, "req-2", session09(inv2, 40006, 0)); err != nil {
		t.Fatal(err)
	}
	wait := HoldDialLimit + netobs.DefaultFlowIdleS*time.Second + 30*time.Second
	g.wall = g.wall.Add(wait - time.Second)
	g.l.TickHold(bg)
	if n := len(g.committed()); n != 6 {
		t.Fatalf("released before its wait: %d", n)
	}
	g.wall = g.wall.Add(time.Second)
	g.l.TickHold(bg)
	if c := g.committed(); len(c) != 7 || c[6] != (tied{6, "", ""}) || g.l.Stats().Hold.DeadlineReleases != 1 {
		t.Fatalf("at its wait: %+v, %+v", c, g.l.Stats().Hold)
	}

	// A new sensor run: a waiting dial gives way at once.
	g.dispatch("req-3")
	g.send(g.obs("start", 40007, 0), g.obs("start", 40008, 0))
	if _, err := g.l.Result(bg, "req-3", session09(inv1, 40008, 0)); err != nil {
		t.Fatal(err)
	}
	g.run, g.seq = "3c9e4c6d-1a2f-4e3b-8c7d-5f6a7b8c9d0e", 0
	hb := heartbeat(1, 10)
	hb.RunID = g.run
	g.send(hb)
	if c := g.committed(); len(c) != 9 || c[8] != (tied{8, "", ""}) || g.l.Stats().Hold.Runs != 0 {
		t.Fatalf("after a new sensor run: %+v", c)
	}
}

// The run's deadline releases untied; a backward clock step can't stretch
// it, because it is never later than now + HoldRunLimit + g (D1).
func TestHoldDeadline(t *testing.T) {
	g := newHoldRig(t)
	limit := HoldRunLimit + 30*time.Second
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	g.wall = g.wall.Add(limit - time.Second)
	g.l.TickHold(bg)
	if len(g.committed()) != 0 {
		t.Fatal("released before the deadline")
	}
	g.wall = g.wall.Add(time.Second)
	g.l.TickHold(bg)
	want(t, g.committed(), tied{1, "", ""})

	g.dispatch("req-2")
	g.send(g.obs("start", 40002, 0))
	g.wall = g.wall.Add(-time.Hour) // a backward step
	g.l.TickHold(bg)
	g.wall = g.wall.Add(limit)
	g.l.TickHold(bg)
	if c := g.committed(); len(c) != 2 || g.l.Stats().Hold.DeadlineReleases != 2 {
		t.Fatalf("the step stretched the hold: %+v", c)
	}
	// A run that ends without a result releases at once.
	g.dispatch("req-3")
	g.send(g.obs("start", 40003, 0))
	if _, err := g.l.Abandon(bg, "req-3"); err != nil {
		t.Fatal(err)
	}
	if c := g.committed(); len(c) != 3 || c[2].tie != "" {
		t.Fatalf("abandoned: %+v", c)
	}
}

// The bounds (D3's I1): a new flow past HoldFlowCap commits untied at once
// and evicts nothing; a record past HoldRecordCap releases the whole hold
// untied, itself included.
func TestHoldCaps(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	for p := range HoldFlowCap + 1 {
		g.send(g.obs("start", 40001+p, 0))
	}
	if c := g.committed(); len(c) != 1 || c[0].seq != HoldFlowCap+1 || g.l.Stats().Hold.PastFlowCap != 1 || g.l.Stats().Hold.Held != HoldFlowCap {
		t.Fatalf("past the flow cap: %+v, %+v", c, g.l.Stats().Hold)
	}
	for len(g.committed()) == 1 {
		g.send(g.obs("function", 40001, time.Second))
	}
	if c := g.committed(); len(c) != HoldRecordCap+2 || g.l.Stats().Hold.RecordCapReleases != 1 || g.l.Stats().Hold.Runs != 0 {
		t.Fatalf("at the record cap: %d committed, %+v", len(c), g.l.Stats().Hold)
	}
	for _, c := range g.committed() {
		if c.tie != "" {
			t.Fatalf("tied at the record cap: %+v", c)
		}
	}
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	if n := len(g.committed()); n != HoldRecordCap+2 {
		t.Fatalf("the result committed %d", n)
	}
}

// The open table's bound: past HoldOpenCap the oldest gives way, counted,
// and its later records are untied.
func TestHoldOpenCap(t *testing.T) {
	g := newHoldRig(t)
	for i := range HoldOpenCap + 1 {
		id := "req-" + strconv.Itoa(i)
		g.dispatch(id)
		g.send(g.obs("start", 41000+i, 0))
		if _, err := g.l.Result(bg, id, session09(inv1, 41000+i, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if s := g.l.Stats().Hold; s.Open != HoldOpenCap || s.OpenEvicted != 1 {
		t.Fatalf("open %+v", s)
	}
	g.send(g.obs("function", 41000, time.Second), g.obs("function", 41001, time.Second))
	c := g.committed()
	if c[len(c)-2].tie != "" || c[len(c)-1].tie != TieConnection {
		t.Fatalf("after the eviction: %+v", c[len(c)-2:])
	}
}

// A kill and restart: held flows and an open key survive in the saved
// records, the next records tie, and the end releases the key (D6's crash
// row for (d)).
func TestHoldRestart(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	g.dispatch("req-2")
	g.send(g.obs("start", 40002, 0))

	// Killed: no Close, nothing written at a stop. A start reads the
	// records back, with the clock on.
	g.wall = g.wall.Add(time.Minute)
	g.l = g.link(g.restore())
	if err := g.l.RecoverHold(bg); err != nil {
		t.Fatal(err)
	}
	if s := g.l.Stats().Hold; s.Held != 1 || s.Runs != 1 || s.Open != 1 {
		t.Fatalf("restored hold %+v", s)
	}
	g.send(g.obs("function", 40001, time.Minute))
	if _, err := g.l.Result(bg, "req-2", session09(inv2, 40002, 0)); err != nil {
		t.Fatal(err)
	}
	g.send(g.obs("end", 40001, 2*time.Minute), g.obs("function", 40001, 3*time.Minute))
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{3, inv1, TieConnection}, tied{2, inv2, TieConnection},
		tied{4, inv1, TieConnection}, tied{5, "", ""})

	// A backward step across the restart: the deadline is the earlier of
	// the stored one and now + the limit.
	g.dispatch("req-3")
	g.send(g.obs("start", 40003, 0))
	g.wall = g.wall.Add(-2 * time.Hour)
	g.l = g.link(g.restore())
	g.l.TickHold(bg)
	g.wall = g.wall.Add(HoldRunLimit + 30*time.Second)
	g.l.TickHold(bg)
	if c := g.committed(); len(c) != 6 || c[5] != (tied{6, "", ""}) {
		t.Fatalf("after a backward step and restart: %+v", c)
	}
}

// A failed intake write at the hold commits the flow untied and is counted
// (D4-72).
func TestHoldSaveFails(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.failSave = 1
	g.send(g.obs("start", 40001, 0))
	want(t, g.committed(), tied{1, "", ""})
	if s := g.l.Stats().Hold; s.CheckpointFailures != 1 || s.Held != 0 {
		t.Fatalf("hold %+v", s)
	}
	g.failSave = 1
	if err := g.l.Dispatch(bg, HoldRun{RequestID: "req-2", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err == nil {
		t.Fatal("a dispatch with no saved record")
	}
}

// A restart between a release's record and its batch commits the batch
// once: again if it did not commit, never twice if it did.
func TestHoldRecoverRelease(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	var releasing []RunRecord
	for _, r := range g.saved {
		if r.State == HoldReleasing {
			releasing = append(releasing, r)
		}
	}
	if len(releasing) != 1 || releasing[0].Head != 0 || len(releasing[0].Releasing) != 1 {
		t.Fatalf("releasing %+v", releasing)
	}
	// Committed already: the head is past the record's.
	l := g.link(releasing)
	if err := l.RecoverHold(bg); err != nil {
		t.Fatal(err)
	}
	if n := len(g.committed()); n != 1 {
		t.Fatalf("committed twice: %d", n)
	}
	// Not committed: a store whose head is the record's.
	g.s = openNet(t, 64<<20)
	l = g.link(releasing)
	if err := l.RecoverHold(bg); err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, inv1, TieConnection})
}

// A held record's saved form fits: the C4 observation body at its cap,
// raw, and the largest capture in base64, under 64 KiB, so HoldRecordCap
// of them and an envelope fit the configuration record cap (1.5 MiB).
func TestHoldRecordFits(t *testing.T) {
	body := make([]byte, event.MaxNetobsBytes)
	for i := range body {
		body[i] = 'a'
	}
	body[0], body[len(body)-1] = '"', '"'
	hr := HeldRecord{RunID: testRun, Seq: 1<<64 - 1, Observation: body,
		Capture: &c5.Capture{SHA256: hashOf(nil), Bytes: make([]byte, netobs.MaxCaptureBytes)}, Received: received()}
	b, err := json.Marshal(Release{Record: hr, Tie: &netobs.PlatformSession{InvocationID: inv1, Tie: TieConnection}, Asset: relay})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 64<<10 || (HoldRecordCap+1)*(64<<10) > 1536<<10 {
		t.Fatalf("a held record is %d bytes; %d of them and an envelope exceed 1.5 MiB", len(b), HoldRecordCap)
	}
}

// Degraded coverage: a waiting dial gives way untied at once, as on a new
// sensor run, but the open table stays (its ends may still come).
func TestHoldDegradedGivesWay(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0), g.obs("start", 40002, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40002, 0)); err != nil {
		t.Fatal(err)
	}
	hb := heartbeat(g.seq+1, 10)
	g.seq++
	hb.Coverage.Degraded = []string{"drops-driver"}
	g.send(hb)
	want(t, g.committed(), tied{2, inv1, TieConnection}, tied{1, "", ""})
	if s := g.l.Stats().Hold; s.Runs != 0 || s.Open != 1 {
		t.Fatalf("hold %+v", s)
	}
	g.send(g.obs("function", 40002, time.Second))
	if c := g.committed(); c[2] != (tied{4, inv1, TieConnection}) {
		t.Fatalf("after degraded coverage: %+v", c)
	}
}

// D3's H1 on #576, with D1's fix: an open key outlives a lost end only
// until a start on its 5-tuple, which is judged as a new flow, or until its
// expiry at its latest record + flow_idle_s + g.
func TestHoldOpenLostEnd(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	g.seq++ // the end is lost on the channel
	g.send(g.obs("start", 40001, time.Minute), g.obs("function", 40001, time.Minute))
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{3, "", ""}, tied{4, "", ""})
	if s := g.l.Stats().Hold; s.OpenSuperseded != 1 || s.Open != 0 {
		t.Fatalf("hold %+v", s)
	}
	if last := g.saved[len(g.saved)-1]; len(last.Open) != 0 {
		t.Fatalf("the superseded key is still saved: %+v", last.Open)
	}
}

// A live flow's expiry moves with each record; a record past it is untied,
// and TickHold removes it too.
func TestHoldOpenExpiry(t *testing.T) {
	g := newHoldRig(t)
	idle := netobs.DefaultFlowIdleS*time.Second + 30*time.Second // flow_idle_s + g
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	g.wall = g.wall.Add(idle - time.Second)
	g.send(g.obs("function", 40001, time.Minute))
	g.wall = g.wall.Add(idle - time.Second)
	g.send(g.obs("function", 40001, 2*time.Minute))
	g.wall = g.wall.Add(idle)
	g.send(g.obs("function", 40001, 3*time.Minute))
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{2, inv1, TieConnection}, tied{3, inv1, TieConnection}, tied{4, "", ""})
	if s := g.l.Stats().Hold; s.OpenExpired != 1 || s.Open != 0 {
		t.Fatalf("hold %+v", s)
	}

	g.dispatch("req-2")
	g.send(g.obs("start", 40002, 0))
	if _, err := g.l.Result(bg, "req-2", session09(inv2, 40002, 0)); err != nil {
		t.Fatal(err)
	}
	g.wall = g.wall.Add(idle)
	g.l.TickHold(bg)
	if s := g.l.Stats().Hold; s.OpenExpired != 2 || s.Open != 0 || len(g.saved[len(g.saved)-1].Open) != 0 {
		t.Fatalf("after TickHold: %+v", s)
	}
}

// The expiry survives a restart, as moved by the latest record, and a
// backward clock step across it can't stretch it.
func TestHoldOpenExpiryRestart(t *testing.T) {
	g := newHoldRig(t)
	idle := netobs.DefaultFlowIdleS*time.Second + 30*time.Second
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	g.wall = g.wall.Add(idle - time.Second)
	g.send(g.obs("function", 40001, time.Minute)) // moves the expiry
	g.wall = g.wall.Add(idle - time.Second)
	g.l = g.link(g.restore())
	g.send(g.obs("function", 40001, 2*time.Minute)) // within the moved expiry
	g.wall = g.wall.Add(idle)
	g.l = g.link(g.restore())
	g.send(g.obs("function", 40001, 3*time.Minute)) // past it
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{2, inv1, TieConnection}, tied{3, inv1, TieConnection}, tied{4, "", ""})

	g.dispatch("req-2")
	g.send(g.obs("start", 40002, 0))
	if _, err := g.l.Result(bg, "req-2", session09(inv2, 40002, 0)); err != nil {
		t.Fatal(err)
	}
	g.wall = g.wall.Add(-2 * time.Hour) // a backward step, then a restart
	g.l = g.link(g.restore())
	g.l.TickHold(bg) // at start, before Serve (D3's note for the wiring)
	g.wall = g.wall.Add(idle)
	g.send(g.obs("function", 40002, time.Minute))
	if c := g.committed(); c[len(c)-1] != (tied{6, "", ""}) {
		t.Fatalf("the step stretched the expiry: %+v", c)
	}
}

// D6's probes on #576 (P1 to P3) and the rows for its gaps G1 to G5.

// P1 (F1, D1's ruling): a flow the sensor first sees midstream, 60 s after
// connected_at, still ties: the window runs to ended_at + g.
func TestHoldMidstreamJoinTies(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, time.Minute))
	s := Session{InvocationID: inv1, StartedAt: t0.Add(-time.Second), EndedAt: t0.Add(5 * time.Minute), Connected: true,
		Local: netip.AddrPortFrom(netip.MustParseAddr(nodeAddr), 40001), ConnectedAt: t0}
	if _, err := g.l.Result(bg, "req-1", s); err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, inv1, TieConnection})
}

// G3: the connection tie's edges, [started_at - g, ended_at + g], to the
// microsecond.
func TestHoldConnectionTieEdges(t *testing.T) {
	s := session09(inv1, 40001, time.Minute) // started_at t0+59s, ended_at t0+80s
	lo, hi := s.StartedAt.Sub(t0)-30*time.Second, s.EndedAt.Sub(t0)+30*time.Second
	for _, c := range []struct {
		at  time.Duration
		tie string
	}{{lo - time.Microsecond, ""}, {lo, TieConnection}, {hi, TieConnection}, {hi + time.Microsecond, ""}} {
		g := newHoldRig(t)
		g.dispatch("req-1")
		g.send(g.obs("start", 40001, c.at))
		if _, err := g.l.Result(bg, "req-1", s); err != nil {
			t.Fatal(err)
		}
		if got := g.committed(); len(got) != 1 || got[0].tie != c.tie {
			t.Fatalf("a start at t0%+v: %+v, want tie %q", c.at, got, c.tie)
		}
	}
}

// P2 (G1): a flow whose first frame is the device's, src the endpoint and
// dst the node, is the node's own flow too, and ties.
func TestHoldDeviceFirstTies(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	o := g.obs("start", 40001, 0)
	o.IP.Src, o.IP.Dst = o.IP.Dst, o.IP.Src
	o.IP.Sport, o.IP.Dport = o.IP.Dport, o.IP.Sport
	g.send(o)
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, inv1, TieConnection})
}

// P3 (G2): a release whose releasing record can't be saved commits untied
// (D4-72).
func TestHoldReleaseSaveFailsUntied(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	g.failSave = 1
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, "", ""})
	if s := g.l.Stats().Hold; s.CheckpointFailures != 1 || s.Open != 0 {
		t.Fatalf("hold %+v", s)
	}
}

// G4 (H6): a backward step while a dial waits can't stretch its wait.
func TestHoldDialWaitBackwardStep(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0), g.obs("start", 40002, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40002, 0)); err != nil {
		t.Fatal(err)
	}
	g.wall = g.wall.Add(-time.Hour)
	g.l.TickHold(bg)
	g.wall = g.wall.Add(HoldDialLimit + netobs.DefaultFlowIdleS*time.Second + 30*time.Second)
	g.l.TickHold(bg)
	want(t, g.committed(), tied{2, inv1, TieConnection}, tied{1, "", ""})
}

// G4 (H9): a sensor restart before the result leaves a dial with no end
// to wait for: at the result it commits untied at once, never waiting.
func TestHoldEndLostBeforeResult(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	g.run, g.seq = "3c9e4c6d-1a2f-4e3b-8c7d-5f6a7b8c9d0e", 1
	hb := heartbeat(1, 10)
	hb.RunID = g.run
	g.send(hb)
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40002, 0)); err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, "", ""})
	if s := g.l.Stats().Hold; s.Runs != 0 {
		t.Fatalf("a dial waits for an end that can't come: %+v", s)
	}
}

// G5 (H10): a new sensor run_id still clears the open table (D1); only a
// seq gap or degraded coverage leaves it (TestHoldDegradedGivesWay).
func TestHoldNewRunClearsOpen(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	g.run, g.seq = "3c9e4c6d-1a2f-4e3b-8c7d-5f6a7b8c9d0e", 0
	g.send(g.obs("function", 40001, time.Second))
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{1, "", ""})
	if last := g.saved[len(g.saved)-1]; len(last.Open) != 0 || g.l.Stats().Hold.Open != 0 {
		t.Fatalf("the table survived a new run: %+v", last.Open)
	}
}

// G5 (H25): of two overlapping runs to one endpoint, a new flow goes to the
// newest, and a flow already held stays with its run.
func TestHoldOverlappingRuns(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	g.dispatch("req-2")
	g.send(g.obs("function", 40001, time.Second), g.obs("start", 40002, 2*time.Second))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{2, inv1, TieConnection})
	if _, err := g.l.Result(bg, "req-2", session09(inv2, 40002, 2*time.Second)); err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{2, inv1, TieConnection}, tied{3, inv2, TieConnection})
}

// G5 (H26): a second result for a run does nothing; a waiting dial keeps
// waiting and gives way untied at its wait.
func TestHoldSecondResult(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0), g.obs("start", 40002, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40002, 0)); err != nil {
		t.Fatal(err)
	}
	n := len(g.saved)
	if _, err := g.l.Result(bg, "req-1", session09(inv2, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	if len(g.saved) != n || g.l.Stats().Hold.Held != 1 {
		t.Fatalf("a second result changed the hold: %+v", g.l.Stats().Hold)
	}
	g.wall = g.wall.Add(HoldDialLimit + netobs.DefaultFlowIdleS*time.Second + 30*time.Second)
	g.l.TickHold(bg)
	want(t, g.committed(), tied{2, inv1, TieConnection}, tied{1, "", ""})
}

// An open entry's expiry runs from the flow's latest held record, not its
// first.
func TestHoldOpenExpiryFromLatestHeld(t *testing.T) {
	g := newHoldRig(t)
	idle := netobs.DefaultFlowIdleS*time.Second + 30*time.Second
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	g.wall = g.wall.Add(80 * time.Second)
	g.send(g.obs("function", 40001, 80*time.Second))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	g.wall = g.wall.Add(idle - time.Second)
	g.send(g.obs("function", 40001, 3*time.Minute))
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{2, inv1, TieConnection}, tied{3, inv1, TieConnection})
}

// D4's finding 3, as D1 ruled: a run whose session is a flow still open in
// the table (an SNMPv3 run reusing its conversation) re-points the entry to
// its own invocation and reports open_flow; the entry's later records tie
// to the new run.
func TestHoldResultRepointsOpen(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	g.wall = g.wall.Add(time.Minute)
	g.dispatch("req-2")
	g.send(g.obs("function", 40001, time.Minute)) // the old session's, until the result
	g.wall = g.wall.Add(10 * time.Second)
	got, err := g.l.Result(bg, "req-2", session09(inv2, 40001, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !got.OpenFlow {
		t.Fatalf("released %+v, want open_flow", got)
	}
	if last := g.saved[len(g.saved)-1]; len(last.Open) != 1 || last.Open[0].InvocationID != inv2 ||
		!last.Open[0].Expires.Equal(t0.Add(time.Minute+netobs.DefaultFlowIdleS*time.Second+30*time.Second)) {
		t.Fatalf("the saved table: %+v (the re-point leaves the expiry as the function record moved it)", last.Open)
	}
	g.send(g.obs("function", 40001, 2*time.Minute))
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{2, inv1, TieConnection}, tied{3, inv2, TieConnection})
}

// An expired entry is not re-pointed: the result reports no open flow, and
// a later record on the tuple is untied; another tuple is never re-pointed.
func TestHoldResultExpiredOpen(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	g.wall = g.wall.Add(netobs.DefaultFlowIdleS*time.Second + 30*time.Second)
	g.dispatch("req-2")
	got, err := g.l.Result(bg, "req-2", session09(inv2, 40001, 2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	g.dispatch("req-3")
	other, err := g.l.Result(bg, "req-3", session09(inv2, 40002, 2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got.OpenFlow || other.OpenFlow {
		t.Fatalf("released %+v and %+v, want no open flow", got, other)
	}
	g.send(g.obs("function", 40001, 3*time.Minute))
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{2, "", ""})
}

// D6's probe P4 on #576 (N1).
// P4: a re-point takes effect only once its record saves (D4-72). With the
// result's record failing, the result reports no open flow and the entry's
// later records still tie to the old session, in memory and after a restart.
func TestHoldRepointSaveFails(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	g.wall = g.wall.Add(time.Minute)
	g.dispatch("req-2")
	g.failSave = 1
	got, err := g.l.Result(bg, "req-2", session09(inv2, 40001, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	g.send(g.obs("function", 40001, 2*time.Minute))
	c := g.committed()
	if got.OpenFlow || c[len(c)-1].invocation != inv1 {
		t.Errorf("the re-point took effect though its record failed: open_flow %v, last tie %+v", got.OpenFlow, c[len(c)-1])
	}
	g.l = g.link(g.restore())
	g.send(g.obs("function", 40001, 2*time.Minute+time.Second))
	if c := g.committed(); c[len(c)-1].invocation != inv1 {
		t.Errorf("after a restart the entry ties to %+v", c[len(c)-1])
	}

	// With a batch, the releasing record fails and the final one saves: the
	// saved record says the re-point did not happen (D4's F1 on #584).
	g.dispatch("req-3")
	g.send(g.obs("start", 40003, 10*time.Minute)) // outside the session: released untied, in the batch
	g.failSave = 1
	got, err = g.l.Result(bg, "req-3", session09("8b3e4d10-5f6c-4e30-9d9c-4b2a0f7e3c52", 40001, 2*time.Minute))
	last := g.saved[len(g.saved)-1]
	if err != nil || got.OpenFlow || last.Run.RequestID != "req-3" || last.OpenFlow {
		t.Errorf("result %+v, %v; saved record %s open_flow %v", got, err, last.Run.RequestID, last.OpenFlow)
	}

	// With a batch, the releasing record saves and the final one fails, as
	// a crash between them would leave it: the re-point took effect, and
	// the record RecoverHold finishes from the releasing one says so
	// (D6's S3 on #584).
	g.dispatch("req-4")
	g.send(g.obs("start", 40004, 20*time.Minute)) // outside the session, in the batch
	g.okFirst, g.failSave = 1, 1
	got, err = g.l.Result(bg, "req-4", session09("9c4f5e21-6a7d-4f41-8e0d-5c3b1a8f4d63", 40001, 3*time.Minute))
	if err != nil || !got.OpenFlow {
		t.Fatalf("req-4's result: %+v, %v", got, err)
	}
	if last := g.saved[len(g.saved)-1]; last.Run.RequestID != "req-4" || last.State != HoldReleasing {
		t.Fatalf("newest record: %s %s", last.Run.RequestID, last.State)
	}
	g.l = g.link(g.restore())
	if err := g.l.RecoverHold(bg); err != nil {
		t.Fatal(err)
	}
	if last := g.saved[len(g.saved)-1]; last.Run.RequestID != "req-4" || last.State != HoldReleased || !last.OpenFlow {
		t.Errorf("recovered record: %s %s open_flow %v", last.Run.RequestID, last.State, last.OpenFlow)
	}
}
