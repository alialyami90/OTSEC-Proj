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
// its collection.run would: the run dispatched, its allowed
// collector.request committed (when allowed), its own flow held and its
// result released, and nothing of the result committed.
func crashAfterRelease(t *testing.T, r *Runtime, allowed bool) string {
	t.Helper()
	s := newScheduler(t, r, &fakeCollector{})
	id := s.newID()
	req := r.cfg.runRequest(0, id)
	col := r.cfg.Schedule[0]
	if s.dispatchHold(bg, col, id) == nil {
		t.Fatal("the hold doesn't watch the run")
	}
	if allowed {
		rec, err := s.requestRecord(req, audit.OutcomeAllowed, "", 1)
		if err != nil {
			t.Fatal(err)
		}
		s.appendAudit(bg, relayID, []c5.Record{rec})
	}
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
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
	other := ownFlow(2)
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
	id := crashAfterRelease(t, r, true)
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
	if err != nil || !ok || got.InvocationID != okInvocation || !got.Connected || got.AfterSeq != obsHead || got.Local.String() != "192.0.2.10:49152" {
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
	crashAfterRelease(t, r, false)
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
	s.dispatchHold(bg, c.Schedule[0], s.newID())
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	r.Tick(bg)
	obs := observations(t, r)
	if len(obs) != 1 || (obs[0].Node != nil && obs[0].Node.PlatformSession != nil) {
		f := st.Snapshot("x").Sensor
		t.Fatalf("the refused run's flow: %+v; status %+v", obs, f)
	}
	if f := st.Snapshot("x").Sensor; f == nil || f.Hold.CheckpointFailures != 1 || countAlarms(st, AlarmIntakeCheckpointFailed) != 1 {
		t.Fatalf("status: %+v", f)
	}
}
