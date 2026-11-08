package node

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/sensorlink"
)

// Constructed records, desk only: no sensor produced them and no device was
// contacted. The run is the SEL-751 fixture at 127.0.0.1:2323, and its 0.9
// session's local end, 192.0.2.10:49152 (ok-0.9.json), is the node address
// sensorSection gives.
const ok09Result = "../../contracts/adapter/testdata/results/valid/ok-0.9.json"

// holdConfig is a node with the network_sensor section and the relay.
func holdConfig(t *testing.T) (*Config, string) {
	t.Helper()
	return schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
	})
}

// ownFlow is a flow start between the session's local end and the relay,
// inside the fixture's session window.
func ownFlow(seq int) *netobs.Observation {
	o := sensorFlow(seq, sensorID)
	p := func(v int) *int { return &v }
	o.FirstUTC, o.LastUTC = "2026-10-24T09:15:00.100000Z", "2026-10-24T09:15:00.200000Z"
	o.Coverage.SinceUTC = "2026-10-24T08:00:00.000000Z"
	o.IP = &netobs.IP{Src: "192.0.2.10", Dst: "127.0.0.1", L4: "tcp", Sport: p(49152), Dport: p(2323)}
	o.Protocol, o.Coverage.Decodes = "unknown", []string{}
	return o
}

// intakeDocs are the netcheckpoint.intake records in the stream.
func intakeDocs(t *testing.T, r *Runtime) (seqs []c5.Seq, docs []intakeDoc) {
	t.Helper()
	stream := r.intakeStream()
	got, err := r.Store(stream).Read(bg, stream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range got {
		if !bytes.HasPrefix(st.Event, []byte(`{"schema":"`+IntakeSchema)) {
			continue
		}
		d, err := decodeIntake(st.Event)
		if err != nil {
			t.Fatal(err)
		}
		seqs, docs = append(seqs, st.Key.Seq), append(docs, d)
	}
	return seqs, docs
}

// healthRuns are the collection.run records on the health stream.
func healthRuns(t *testing.T, r *Runtime) (out []c5.Stored) {
	t.Helper()
	hs, err := r.Store(HealthStream).Read(bg, HealthStream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range hs {
		if e, _ := event.Decode(st.Event); e.Health != nil && e.Health.Type == HealthCollectionRun {
			out = append(out, st)
		}
	}
	return out
}

// observations are the committed observations, decoded.
func observations(t *testing.T, r *Runtime) (out []netobs.Observation) {
	t.Helper()
	stream := NetObservationStream(sensorID)
	got, err := r.Store(stream).Read(bg, stream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range got {
		e, err := event.Decode(st.Event)
		if err != nil {
			t.Fatal(err)
		}
		o, err := netobs.ObservationFromEvent(e)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, *o)
	}
	return out
}

// A scheduled run the hold watches: the flow the sensor sends while the run
// is in flight is held, ties to the run's session by connection, and
// commits before the collection.run, which carries every field the
// detector's session needs, so the session rebuilds from the committed
// record alone (D1 on the split of PR B). The run's older hold records are
// removed after its collection.run, and the series keeps its newest.
func TestIntakeRunSession(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	result, transcript := figureOrderFrom(t, ok09Result)
	var seq uint64
	client := wireCollectorResult(t, result, transcript, func(req *authz.CollectorRequest) {
		if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
			t.Error(err)
		}
		if n := len(observations(t, r)); n != 0 {
			t.Errorf("the run's own flow committed while the run was in flight: %d observations", n)
		}
	}, &seq)
	s := newScheduler(t, r, client)
	rep := s.RunOnce(bg, 0)
	if rep.Outcome != "ok" || rep.Alarm != "" {
		t.Fatalf("run: %+v", rep)
	}
	obs := observations(t, r)
	if len(obs) != 1 || obs[0].Node == nil || obs[0].Node.PlatformSession == nil ||
		obs[0].Node.PlatformSession.InvocationID != okInvocation || obs[0].Node.PlatformSession.Tie != sensorlink.TieConnection {
		t.Fatalf("the run's flow: %+v", obs)
	}
	runs := healthRuns(t, r)
	if len(runs) != 1 {
		t.Fatalf("%d collection.run records", len(runs))
	}
	got, ok, err := runSessionOf(runs[0])
	if err != nil || !ok {
		t.Fatalf("session from the record: %v, %v", ok, err)
	}
	obsHead, _ := r.Store(NetObservationStream(sensorID)).LastCommitted(bg, NetObservationStream(sensorID))
	want := RunSession{Seq: runs[0].Key.Seq, InvocationID: okInvocation, AssetID: relayID,
		Endpoint: netip.MustParseAddrPort("127.0.0.1:2323"), L4: "tcp", Local: netip.MustParseAddrPort("192.0.2.10:49152"),
		Connected: true, StartedUTC: "2026-10-24T09:15:00Z", EndedUTC: "2026-10-24T09:15:01.8Z", AfterSeq: obsHead}
	if got != want || obsHead == 0 {
		t.Fatalf("session\n got %+v\nwant %+v", got, want)
	}
	seqs, docs := intakeDocs(t, r)
	if len(docs) != 1 || docs[0].State != sensorlink.HoldReleased || docs[0].Session == nil || docs[0].AfterSeq != obsHead {
		t.Fatalf("hold records after the run: %v %+v", seqs, docs)
	}
}

// A run the hold doesn't watch, here with no network_sensor section, writes
// its collection.run as before, with no session details.
func TestIntakeOffNoSession(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" {
		t.Fatalf("run: %+v", rep)
	}
	runs := healthRuns(t, r)
	if _, ok, err := runSessionOf(runs[0]); len(runs) != 1 || ok || err != nil {
		t.Fatalf("collection.run of an unwatched run: %d, %v, %v", len(runs), ok, err)
	}
}

// The hold record's schema is its first field, ConfigDocuments takes it as
// working state of series netcheckpoint.intake with no capture, and the
// readers of config/<asset> pass over it (D1 on #571).
func TestIntakeDocuments(t *testing.T) {
	d := intakeDoc{Schema: IntakeSchema, RunRecord: sensorlink.RunRecord{State: sensorlink.HoldHolding,
		Run:   sensorlink.HoldRun{RequestID: "req-1", AssetID: relayID, Endpoint: netip.MustParseAddrPort("127.0.0.1:2323"), L4: "tcp"},
		Flows: []sensorlink.HeldFlow{}, Open: []sensorlink.OpenFlow{}}}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte(`{"schema":"otsec.netcheckpoint.intake/0.1",`)) {
		t.Fatalf("record starts %.60s", b)
	}
	info, err := ConfigDocuments(b, nil)
	if err != nil || info != (c5.DocumentInfo{Kind: c5.DocumentWorkingState, Series: c5.SeriesNetCheckpointIntake}) {
		t.Fatalf("ConfigDocuments: %+v, %v", info, err)
	}
	if _, err := ConfigDocuments(b, &c5.Capture{SHA256: okTranscript, Bytes: []byte("x")}); err == nil {
		t.Fatal("a hold record with a capture was taken")
	}
	for name, bad := range map[string][]byte{
		"unknown field": bytes.Replace(b, []byte(`"health_head":0`), []byte(`"health_head":0,"x":1`), 1),
		"state":         bytes.Replace(b, []byte(`"holding"`), []byte(`"held"`), 1),
		"request":       bytes.Replace(b, []byte(`"req-1"`), []byte(`""`), 1),
		"asset":         bytes.Replace(b, []byte(relayID), []byte("relay-1"), 1), // D6's R10
	} {
		if _, err := ConfigDocuments(bad, nil); err == nil {
			t.Errorf("%s: taken", name)
		}
	}

	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	stream := ConfigStream(relayID)
	if _, err := r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: b}); err != nil {
		t.Fatal(err)
	}
	if bs, err := (&eventLife{rt: r}).storedBaselines(bg, relayID); err != nil || len(bs) != 0 {
		t.Fatalf("storedBaselines: %d, %v", len(bs), err)
	}
	if cps, err := (&eventRun{rt: r}).checkpoints(bg, relayID); err != nil || len(cps) != 0 {
		t.Fatalf("checkpoints: %d, %v", len(cps), err)
	}
}

// crashAfterRelease leaves the node as a crash between a run's release and
// its collection.run would: the run dispatched, its collector.request
// with outcome committed (none when outcome is ""), its own flow held and its
// result released, and nothing of the result committed. With dial, a
// failed dial from another local port is still open at the result, so the
// run's record is left waiting for its end (D3's R3 on #584).
func crashAfterRelease(t *testing.T, r *Runtime, outcome audit.Outcome, dial bool) string {
	t.Helper()
	s := newScheduler(t, r, &fakeCollector{})
	id := s.newID()
	req := r.cfg.runRequest(0, id)
	col := r.cfg.Schedule[0]
	if s.dispatchHold(bg, col, id) == nil {
		t.Fatal("the hold doesn't watch the run")
	}
	if outcome != "" {
		reason := ""
		if outcome == audit.OutcomeDenied {
			reason = string(authz.RefuseUnknown)
		}
		rec, err := s.requestRecord(req, outcome, reason, 1)
		if err != nil {
			t.Fatal(err)
		}
		s.appendAudit(bg, relayID, []c5.Record{rec})
	}
	seq := 1
	if dial {
		d := ownFlow(seq)
		*d.IP.Sport = 49151
		if err := r.ServeSensor(bg, sensorChannel(t, d)); err != nil {
			t.Fatal(err)
		}
		seq++
	}
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(seq))); err != nil {
		t.Fatal(err)
	}
	seq++
	res, err := adapter.DecodeResult(readFile(t, ok09Result))
	if err != nil {
		t.Fatal(err)
	}
	sess := sensorlink.Session{InvocationID: okInvocation, Connected: true, Local: netip.MustParseAddrPort(res.Session.LocalAddr)}
	sess.StartedAt, _ = time.Parse(time.RFC3339Nano, res.StartedAt)
	sess.EndedAt, _ = time.Parse(time.RFC3339Nano, res.EndedAt)
	if _, err := r.sensor.link.Result(bg, id, sess); err != nil {
		t.Fatal(err)
	}
	// An observation after the release, so the repair's after_seq, the
	// head at the repair, is not the release's (D6's mutant).
	other := ownFlow(seq)
	other.IP.Src = "192.0.2.99" // not the node's, to the relay
	if err := r.ServeSensor(bg, sensorChannel(t, other)); err != nil {
		t.Fatal(err)
	}
	return id
}

// The start repair (D1 in D4-72, D3's R1 and R2, D6's row): a crash between
// a run's release and its collection.run leaves the release committed and
// no collection.run. The next start writes exactly one, from the release's
// session facts, with status not-committed, repaired_from
// netcheckpoint.intake and after_seq the observation stream's head at the
// repair; a second restart writes none. The SER rows the run read were not
// committed, so the next run of the schedule reads and commits them.
func TestIntakeStartRepair(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	id := crashAfterRelease(t, r, audit.OutcomeAllowed, false)
	if runs := healthRuns(t, r); len(runs) != 0 {
		t.Fatalf("%d collection.run records before the crash", len(runs))
	}
	r.Close()

	r, st, _ := start(t, c, dir)
	runs := healthRuns(t, r)
	if len(runs) != 1 {
		t.Fatalf("%d collection.run records after the repair", len(runs))
	}
	e, _ := event.Decode(runs[0].Event)
	d := e.Health.Details
	if d["request_id"] != id || d["status"] != RunNotCommitted || d["repaired_from"] != RepairedFromIntake ||
		d["schedule"] != c.Schedule[0].ID || d["operation"] != c.Schedule[0].Operation || d["events"] != "0" {
		t.Fatalf("repaired collection.run: %v", d)
	}
	got, ok, err := runSessionOf(runs[0])
	obsHead, _ := r.Store(NetObservationStream(sensorID)).LastCommitted(bg, NetObservationStream(sensorID))
	if _, docs := intakeDocs(t, r); len(docs) != 1 || obsHead <= docs[0].AfterSeq {
		t.Fatalf("observation head %d, hold records %+v", obsHead, docs)
	}
	// Its own tied flow is still open in the table, which is not an open
	// flow it reused (D4's F1 on #584).
	if err != nil || !ok || got.InvocationID != okInvocation || !got.Connected || got.AfterSeq != obsHead || got.Local.String() != "192.0.2.10:49152" || got.OpenFlow {
		t.Fatalf("repaired session: %+v, %v, %v", got, ok, err)
	}
	if f := st.Snapshot("x").Sensor; f == nil || f.Repaired != 1 || f.RepairRefused != 0 {
		t.Fatalf("status: %+v", f)
	}
	r.Close()

	r, st, _ = start(t, c, dir)
	if runs := healthRuns(t, r); len(runs) != 1 {
		t.Fatalf("a second restart repaired again: %d collection.run records", len(runs))
	}
	if f := st.Snapshot("x").Sensor; f == nil || f.Repaired != 0 || f.RepairRefused != 0 {
		t.Fatalf("a second restart judged the run again: %+v", f)
	}
	if _, docs := intakeDocs(t, r); len(docs) != 1 {
		t.Fatalf("%d hold records after the repair", len(docs))
	}
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" || rep.Events != 2 {
		t.Fatalf("the next run of the schedule: %+v", rep)
	}
	r.Close()
}

// A release whose run has no allowed collector.request after its dispatch
// is not repaired: no collection.run, a count and an alarm, and its hold
// records stay (D3's R1).
func TestIntakeRepairRefused(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	crashAfterRelease(t, r, "", false)
	r.Close()

	r, st, _ := start(t, c, dir)
	defer r.Close()
	if runs := healthRuns(t, r); len(runs) != 0 {
		t.Fatalf("%d collection.run records", len(runs))
	}
	if f := st.Snapshot("x").Sensor; f == nil || f.Repaired != 0 || f.RepairRefused != 1 || countAlarms(st, AlarmIntakeRepairRefused) != 1 {
		t.Fatalf("status: %+v", f)
	}
	if _, docs := intakeDocs(t, r); len(docs) < 2 {
		t.Fatalf("the refused run's hold records went: %d left", len(docs))
	}
}

// A run that ends without a result releases its held flow untied at once,
// and its hold records go, as no repair needs them.
func TestIntakeNoResultAbandons(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	s := newScheduler(t, r, &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
			t.Error(err)
		}
		return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
			Refusal: &authz.Refusal{Code: authz.RefuseUnknown}, CollectorSeq: 1}}, nil
	}})
	if rep := s.RunOnce(bg, 0); rep.Refusal == "" {
		t.Fatalf("run: %+v", rep)
	}
	obs := observations(t, r)
	if len(obs) != 1 || (obs[0].Node != nil && obs[0].Node.PlatformSession != nil) {
		t.Fatalf("the refused run's flow: %+v", obs)
	}
	if _, docs := intakeDocs(t, r); len(docs) != 1 || docs[0].State != sensorlink.HoldReleased {
		t.Fatalf("hold records: %+v", docs)
	}
}

// A run held when the node stopped, whose deadline passed while it was
// down, gives way at start, before the sensor is served: its flow commits
// untied (D3 on #576).
func TestIntakeDeadlinePassedWhileDown(t *testing.T) {
	c, _ := holdConfig(t)
	g := &retentionRig{t: t, c: c, wall: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), mono: time.Minute}
	r, _ := g.start()
	s := newScheduler(t, r, &fakeCollector{})
	if s.dispatchHold(bg, c.Schedule[0], s.newID()) == nil {
		t.Fatal("the hold doesn't watch the run")
	}
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	if n := len(observations(t, r)); n != 0 {
		t.Fatalf("%d observations while held", n)
	}
	r.Close()
	g.advance(sensorlink.HoldRunLimit + netobs.DefaultTieGraceS*time.Second + time.Second)
	r, _ = g.start()
	defer r.Close()
	obs := observations(t, r)
	if len(obs) != 1 || (obs[0].Node != nil && obs[0].Node.PlatformSession != nil) {
		t.Fatalf("after the restart: %+v", obs)
	}
}

// A crash between a release's releasing record and its batch: the next
// start commits the batch once, before the sensor is served (RecoverHold).
// The releasing record is built from the hold's own holding record.
func TestIntakeRecoversRelease(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	s := newScheduler(t, r, &fakeCollector{})
	if s.dispatchHold(bg, c.Schedule[0], s.newID()) == nil {
		t.Fatal("the hold doesn't watch the run")
	}
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	_, docs := intakeDocs(t, r)
	held := docs[len(docs)-1]
	if held.State != sensorlink.HoldHolding || len(held.Flows) != 1 || len(held.Flows[0].Records) != 1 {
		t.Fatalf("holding record: %+v", held)
	}
	held.State, held.Releasing, held.Head = sensorlink.HoldReleasing, []sensorlink.Release{{Record: held.Flows[0].Records[0]}}, 0
	held.Flows = []sensorlink.HeldFlow{}
	b, err := json.Marshal(held)
	if err != nil {
		t.Fatal(err)
	}
	stream := r.intakeStream()
	if _, err := r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: b}); err != nil {
		t.Fatal(err)
	}
	r.Close()
	for range 2 {
		r, _, _ = start(t, c, dir)
		if obs := observations(t, r); len(obs) != 1 {
			t.Fatalf("after the restart: %d observations", len(obs))
		}
		r.Close()
	}
}

// Item 3's ceiling holds the hold's records: with the class filled to it,
// a dispatch's record is refused, nothing is held, the run's flow commits
// untied at once, and the refusal is counted and alarmed (D3's I3).
func TestIntakeCeilingRefuses(t *testing.T) {
	// An event baseline puts a configuration floor under the quota, so the
	// ceiling, not the quota, refuses.
	c, dir := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.Store.Quotas["configuration"] = 64 << 20
		nc.NetworkSensor = sensorSection()
		nc.AddEventBaseline(relayID)
	})
	if q := c.Store.Quotas[string(c5.ClassConfiguration)]; c.Item3Ceiling() >= q {
		t.Fatalf("ceiling %d, quota %d", c.Item3Ceiling(), q)
	}
	r, st, _ := start(t, c, dir)
	defer r.Close()
	stream := r.intakeStream()
	db := r.Store(stream)
	// Filled until no smaller filler fits, so no hold record does.
	for size := 1 << 20; size >= 1; {
		filler := intakeDoc{Schema: IntakeSchema, RunRecord: sensorlink.RunRecord{State: sensorlink.HoldReleased,
			Run:   sensorlink.HoldRun{RequestID: "filler", AssetID: relayID, Endpoint: netip.MustParseAddrPort("127.0.0.1:2323"), L4: "tcp"},
			Flows: []sensorlink.HeldFlow{{Records: []sensorlink.HeldRecord{{Observation: json.RawMessage(strconv.Quote(strings.Repeat("x", size)))}}}},
			Open:  []sensorlink.OpenFlow{}}}
		b, err := json.Marshal(filler)
		if err != nil {
			t.Fatal(err)
		}
		used, err := db.ClassBytes(bg, c5.ClassConfiguration)
		if err != nil {
			t.Fatal(err)
		}
		if used+int64(len(b)) > c.Item3Ceiling() {
			size /= 2
			continue
		}
		if _, err := r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: b}); err != nil {
			t.Fatal(err)
		}
	}
	s := newScheduler(t, r, &fakeCollector{})
	if h := s.dispatchHold(bg, c.Schedule[0], s.newID()); h != nil {
		t.Fatal("a dispatch whose record was refused holds the run")
	}
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	r.Tick(bg)
	obs := observations(t, r)
	if len(obs) != 1 || (obs[0].Node != nil && obs[0].Node.PlatformSession != nil) {
		f := st.Snapshot("x").Sensor
		t.Fatalf("the refused run's flow: %+v; status %+v", obs, f)
	}
	if f := st.Snapshot("x").Sensor; f == nil || f.Hold.CheckpointFailures != 1 || f.SessionMissing != 1 || countAlarms(st, AlarmIntakeCheckpointFailed) != 1 {
		t.Fatalf("status: %+v", f)
	}
}

// D3's R3 on #584: a run whose result left a failed dial waiting for its
// end is saved waiting, with its session. A crash before its collection.run
// is repaired at the next start, as a released run's is.
func TestIntakeStartRepairWaiting(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	id := crashAfterRelease(t, r, audit.OutcomeAllowed, true)
	if _, docs := intakeDocs(t, r); docs[len(docs)-1].State != sensorlink.HoldWaiting {
		t.Fatalf("the run's record is %s, not waiting", docs[len(docs)-1].State)
	}
	r.Close()

	r, st, _ := start(t, c, dir)
	defer r.Close()
	runs := healthRuns(t, r)
	if len(runs) != 1 {
		t.Fatalf("%d collection.run records after the repair", len(runs))
	}
	if e, _ := event.Decode(runs[0].Event); e.Health.Details["request_id"] != id || e.Health.Details["repaired_from"] != RepairedFromIntake {
		t.Fatalf("repaired collection.run: %v", e.Health.Details)
	}
	if f := st.Snapshot("x").Sensor; f == nil || f.Repaired != 1 {
		t.Fatalf("status: %+v", f)
	}
	r.Close()
	r, st, _ = start(t, c, dir)
	if f := st.Snapshot("x").Sensor; len(healthRuns(t, r)) != 1 || f == nil || f.Repaired != 0 || f.RepairRefused != 0 {
		t.Fatalf("a second restart: %d collection.run records, status %+v", len(healthRuns(t, r)), f)
	}
}

// D4's F1 on #584: the repair writes the open_flow the live path would. Run
// A's own flow is still open when run B reuses its 5-tuple, so B's result
// re-points the entry and B is an open-flow session; A is not. Both crash
// before their collection.run, and the repair gives A false and B true.
func TestIntakeStartRepairOpenFlow(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	a := crashAfterRelease(t, r, audit.OutcomeAllowed, false)
	s := newScheduler(t, r, &fakeCollector{})
	b := s.newID()
	if s.dispatchHold(bg, c.Schedule[0], b) == nil {
		t.Fatal("the hold doesn't watch run B")
	}
	rec, err := s.requestRecord(r.cfg.runRequest(0, b), audit.OutcomeAllowed, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	s.appendAudit(bg, relayID, []c5.Record{rec})
	res, err := adapter.DecodeResult(readFile(t, ok09Result))
	if err != nil {
		t.Fatal(err)
	}
	sess := sensorlink.Session{InvocationID: "7a2d3c0f-4e5b-4d2f-8c8b-3a1f9e6d2b41", Connected: true, Local: netip.MustParseAddrPort(res.Session.LocalAddr)}
	sess.StartedAt, _ = time.Parse(time.RFC3339Nano, res.StartedAt)
	sess.EndedAt, _ = time.Parse(time.RFC3339Nano, res.EndedAt)
	if rel, err := r.sensor.link.Result(bg, b, sess); err != nil || !rel.OpenFlow {
		t.Fatalf("run B's result: %+v, %v", rel, err)
	}
	r.Close()

	r, _, _ = start(t, c, dir)
	defer r.Close()
	got := map[string]bool{}
	for _, st := range healthRuns(t, r) {
		e, _ := event.Decode(st.Event)
		rs, ok, err := runSessionOf(st)
		if err != nil || !ok {
			t.Fatalf("%v, %v", ok, err)
		}
		got[e.Health.Details["request_id"]] = rs.OpenFlow
	}
	if len(got) != 2 || got[a] || !got[b] {
		t.Fatalf("open_flow by run: %v (A %s, B %s)", got, a, b)
	}
}

// A result the hold can't release leaves its collection.run with no
// session, counted as runs_session_missing (D1 in D4-74): here the run's
// hold gave way at its deadline, and the observation stream's head can't
// be read when its result comes.
func TestIntakeResultFailsCounted(t *testing.T) {
	c, _ := holdConfig(t)
	g := &retentionRig{t: t, c: c, wall: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), mono: time.Minute}
	r, st := g.start()
	defer r.Close()
	s := newScheduler(t, r, &fakeCollector{})
	h := s.dispatchHold(bg, c.Schedule[0], s.newID())
	if h == nil {
		t.Fatal("the hold doesn't watch the run")
	}
	g.advance(sensorlink.HoldRunLimit + netobs.DefaultTieGraceS*time.Second + time.Second)
	r.Tick(bg) // the hold gives way at its deadline
	d := r.find(NetworkDB)
	r.state.RLock()
	db := d.db
	r.state.RUnlock()
	db.Close()
	if got := s.resultHold(bg, h, okInvocation, sessionResult{Connected: true, StartedAt: "2026-11-01T00:00:00Z", EndedAt: "2026-11-01T00:00:01Z"}); got != nil {
		t.Fatalf("session details with no head: %v", got)
	}
	r.Tick(bg)
	if f := st.Snapshot("x").Sensor; f == nil || f.SessionMissing != 1 {
		t.Fatalf("status: %+v", f)
	}
}

// D6's R13 on #584: a denied collector.request is not an allowed one, so a
// release whose run the collector refused is not repaired.
func TestIntakeRepairRefusedDenied(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	crashAfterRelease(t, r, audit.OutcomeDenied, false)
	r.Close()

	r, st, _ := start(t, c, dir)
	defer r.Close()
	if f := st.Snapshot("x").Sensor; len(healthRuns(t, r)) != 0 || f == nil || f.Repaired != 0 || f.RepairRefused != 1 {
		t.Fatalf("%d collection.run records, status %+v", len(healthRuns(t, r)), f)
	}
}

// D6's R6 on #584: a run whose release committed but whose collection.run
// was not stored (here its alignment state is unreadable, as
// missed_test.go breaks it) keeps its hold records for the start repair.
func TestIntakeResultNotStoredKeeps(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	result, transcript := figureOrderFrom(t, ok09Result)
	var seq uint64
	client := wireCollectorResult(t, result, transcript, func(*authz.CollectorRequest) {
		if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
			t.Error(err)
		}
	}, &seq)
	s := newScheduler(t, r, client)
	ser := SERStream(relayID)
	if err := r.Store(ser).SaveSourceCursor(bg, ser, []byte("not a state")); err != nil {
		t.Fatal(err)
	}
	rep := s.RunOnce(bg, 0)
	if rep.Alarm != AlarmEvidenceNotStored || len(healthRuns(t, r)) != 0 {
		t.Fatalf("run: %+v, %d collection.run records", rep, len(healthRuns(t, r)))
	}
	r.Tick(bg)
	kept := 0
	for _, d := range func() []intakeDoc { _, d := intakeDocs(t, r); return d }() {
		if d.Run.RequestID == rep.RequestID {
			kept++
		}
	}
	if kept < 2 {
		t.Fatalf("%d of the run's hold records kept", kept)
	}
}

// D6's F3 on #584: two runs fail the same way, their releases committed
// and their collection.run not stored. The collection.missed of the series
// names the first, but it is not the run's record, so the restart repairs
// both.
func TestIntakeRepairPastMissed(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	result, transcript := figureOrderFrom(t, ok09Result)
	var seq uint64
	served := false
	client := wireCollectorResult(t, result, transcript, func(*authz.CollectorRequest) {
		if !served {
			served = true
			if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
				t.Error(err)
			}
		}
	}, &seq)
	s := newScheduler(t, r, client)
	ser := SERStream(relayID)
	if err := r.Store(ser).SaveSourceCursor(bg, ser, []byte("not a state")); err != nil {
		t.Fatal(err)
	}
	first, second := s.RunOnce(bg, 0), s.RunOnce(bg, 0)
	if missed, _ := missedRecords(t, r); len(missed) != 1 || len(healthRuns(t, r)) != 0 {
		t.Fatalf("collection.missed %v, %d collection.run records", missed, len(healthRuns(t, r)))
	}
	r.Close()
	r, _, _ = start(t, c, dir)
	defer r.Close()
	got := map[string]string{}
	for _, st := range healthRuns(t, r) {
		e, _ := event.Decode(st.Event)
		got[e.Health.Details["request_id"]] = e.Health.Details["repaired_from"]
	}
	if len(got) != 2 || got[first.RequestID] != RepairedFromIntake || got[second.RequestID] != RepairedFromIntake {
		t.Fatalf("repaired runs %v (first %s, second %s)", got, first.RequestID, second.RequestID)
	}
}
