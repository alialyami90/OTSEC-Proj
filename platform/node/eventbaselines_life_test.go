package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/detection/eventbaseline"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// lifeNode is a node observing the relay, with the test parameters (an hour
// and ten events).
func lifeNode(t *testing.T) (*Config, string) {
	t.Helper()
	return configNode(t, func(nc *nodeconfigtest.Config) { nc.AddEventBaseline(relayID) })
}

var lifeSeq uint64

// lifeSER is a parsed SER row of the relay, received at at.
func lifeSER(elem, state string, at time.Time) eventbaseline.Obs {
	lifeSeq++
	row := fmt.Sprintf("%d %s %s", lifeSeq, elem, state)
	sum := sha256.Sum256([]byte(row))
	return eventbaseline.Obs{Event: &event.Event{
		ID:     event.EventID{NodeID: "site-a-node1", Stream: event.Stream(SERStream(relayID)), Seq: lifeSeq},
		Origin: event.OriginDevice, Kind: event.KindSER,
		Received:   event.Received{UTC: at.UTC().Format(time.RFC3339Nano), ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}},
		Source:     event.Source{Asset: &event.AssetRef{ID: relayID}},
		Collection: &event.Collection{Method: event.MethodAdapterPoll, Alignment: event.AlignOK, ParseStatus: event.ParseOK},
		Native:     &event.Native{Bytes: []byte(row), RecordSHA256: hex.EncodeToString(sum[:]), RecordLength: int64(len(row))},
		Normalized: &event.Normalized{Subject: elem, SubjectType: "relay-word-bit", Value: state, Category: event.Unmapped},
	}}
}

// learnOnce feeds eleven rows of one type 400 s apart from t0 and a
// watermark past both minima, which finishes the learner.
func learnOnce(t *testing.T, l *eventLife, t0 time.Time) time.Time {
	t.Helper()
	for i := range 11 {
		l.Observe(relayID, lifeSER("IN101", "Asserted", t0.Add(time.Duration(i)*400*time.Second)))
	}
	end := t0.Add(4400 * time.Second)
	l.Tick(relayID, end)
	return end
}

func rawStream(t *testing.T, r *Runtime, stream c5.StreamID) [][]byte {
	t.Helper()
	got, err := r.Store(stream).Read(bg, stream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, st := range got {
		out = append(out, st.Event)
	}
	return out
}

func healthOf(t *testing.T, r *Runtime, typ string) []*event.Health {
	t.Helper()
	var out []*event.Health
	for _, e := range streamEvents(t, r, HealthStream) {
		if e.Health != nil && e.Health.Type == typ {
			out = append(out, e.Health)
		}
	}
	return out
}

// recordedOf returns the chain's config.baseline_recorded records, after
// checking that the records VerifyConfig reads pass it.
func recordedOf(t *testing.T, r *Runtime) []*audit.Record {
	t.Helper()
	recs, err := chainRecords(bg, r.Store(AuditStream))
	if err != nil {
		t.Fatal(err)
	}
	var out []*audit.Record
	all := make([]*audit.Record, 0, len(recs))
	for _, ar := range recs {
		all = append(all, ar.rec)
		if ar.rec.Action == audit.ActionConfigBaselineRecorded {
			out = append(out, ar.rec)
		}
	}
	if err := audit.VerifyConfig(all); err != nil {
		t.Fatalf("the chain's configuration records: %v", err)
	}
	return out
}

// appendAck writes a succeeded event-kind acknowledgement as the node's
// node.baseline_ack path will: the collector's acceptance of the decision,
// then the acknowledgement that names it, so the chain still verifies.
func appendAck(t *testing.T, r *Runtime, digest string) {
	t.Helper()
	admin := audit.Actor{Type: authz.PrincipalHuman, ID: "admin@site-a", Role: authz.RoleAdmin}
	v := &audit.Admin{AdminKeyID: "ed25519-183d5080d1a2ef2b", Principal: "admin@site-a", Nonce: "AAECAwQFBgcICQoLDA0ODw",
		PayloadSHA256: strings.Repeat("a", 64), Kind: authz.KindNodeBaselineAck}
	for _, rec := range []audit.Record{
		{Contract: audit.ContractID, NodeID: string(r.cfg.NodeID), Time: r.received(), Actor: admin,
			Action: audit.ActionCollectorRequest, Outcome: audit.OutcomeAllowed, CorrelationID: "req-ack-1", CollectorSeq: 1, Verified: v},
		{Contract: audit.ContractID, NodeID: string(r.cfg.NodeID), Time: r.received(), Actor: admin,
			Action: audit.ActionConfigBaselineAcknowledge, Outcome: audit.OutcomeSucceeded, Target: &audit.Target{AssetID: relayID},
			CorrelationID: "req-ack-1",
			Config:        &audit.Config{DecisionSeq: 1, PayloadSHA256: v.PayloadSHA256, Kind: authz.BaselineEvent, BaselineDigest: digest}},
	} {
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Log(AuditStream).Append(bg, c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: b}); err != nil {
			t.Fatal(err)
		}
	}
}

// A learner whose minima are met at a watermark is finished there: the
// baseline is stored in the asset's configuration stream as Encode's bytes,
// then recorded (config.baseline_recorded, version 1, its digest as
// correlation_id), and the asset awaits acknowledgement. Evidence class:
// simulated.
func TestLifeRecordsAFinishedBaseline(t *testing.T) {
	c, dir := lifeNode(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	if lr, d := l.half(relayID); lr == nil || d != nil || l.awaiting(relayID) {
		t.Fatalf("a new asset: learner %v, detector %v", lr, d)
	}
	t0 := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	// Before both minima nothing is finished.
	l.Observe(relayID, lifeSER("IN101", "Asserted", t0))
	l.Tick(relayID, t0.Add(2*time.Hour))
	if got := rawStream(t, r, ConfigStream(relayID)); len(got) != 0 {
		t.Fatalf("%d records before the minima", len(got))
	}
	learnOnce(t, l, t0.Add(2*time.Hour))

	docs := rawStream(t, r, ConfigStream(relayID))
	if len(docs) != 1 {
		t.Fatalf("%d configuration records, want the baseline", len(docs))
	}
	b, err := baseline.Decode(docs[0])
	if err != nil || b.Version != 1 || b.Previous != "" || len(b.Types) != 1 {
		t.Fatalf("baseline %+v: %v", b, err)
	}
	h := baseline.Hash(docs[0])
	recs := recordedOf(t, r)
	if len(recs) != 1 {
		t.Fatalf("%d recordings", len(recs))
	}
	got := recs[0]
	if got.Config.BaselineDigest != h || got.Config.BaselineVersion != 1 || got.Config.PreviousDigest != "" ||
		got.CorrelationID != strings.TrimPrefix(h, "sha256:") || got.Target.AssetID != relayID || got.Actor.Type != authz.PrincipalNode {
		t.Fatalf("recording %+v %+v", got, got.Config)
	}
	if hs := healthOf(t, r, HealthEventBaselineRecorded); len(hs) != 1 || hs[0].Details["baseline"] != h || hs[0].Details["types_overflow"] != "0" {
		t.Fatalf("recorded health %+v", hs)
	}
	if !l.awaiting(relayID) {
		t.Fatal("not awaiting acknowledgement")
	}
	// Awaiting, events go nowhere and nothing more is stored.
	l.Observe(relayID, lifeSER("IN102", "Asserted", t0.Add(3*time.Hour)))
	l.Tick(relayID, t0.Add(4*time.Hour))
	if len(rawStream(t, r, ConfigStream(relayID))) != 1 || len(recordedOf(t, r)) != 1 {
		t.Fatal("something stored while awaiting")
	}
}

// The acknowledgement path's call activates the recorded baseline at the
// acknowledgement's time, on the feeder's next call. Events received before
// it are not the detector's; a new type after it is a departure alarm in
// platform/health that lists the event. Evidence class: simulated.
func TestLifeAcknowledgedBaselineAlarms(t *testing.T) {
	c, dir := lifeNode(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	end := learnOnce(t, l, t0)
	h := recordedOf(t, r)[0].Config.BaselineDigest

	ackAt := end.Add(time.Hour)
	l.acknowledged(relayID, h, ackAt)
	l.Observe(relayID, lifeSER("IN109", "Asserted", ackAt.Add(-time.Minute)))
	l.Tick(relayID, ackAt.Add(-time.Second)) // the watermark trails the chain time
	if _, d := l.half(relayID); d == nil {
		t.Fatal("not active after the acknowledgement")
	}
	if got := healthOf(t, r, baseline.HealthDeparture); len(got) != 0 || l.assets[relayID].Refused != 0 {
		t.Fatalf("an event before the acknowledgement reached the detector: alarms %+v, refused %d", got, l.assets[relayID].Refused)
	}
	o := lifeSER("IN109", "Asserted", ackAt.Add(time.Minute))
	l.Observe(relayID, o)
	got := healthOf(t, r, baseline.HealthDeparture)
	if len(got) != 1 {
		t.Fatalf("%d departures, want one new-type alarm", len(got))
	}
	al, err := baseline.AlarmFromHealth(*got[0])
	if err != nil {
		t.Fatal(err)
	}
	if al.Rule != baseline.RuleNewType || al.Baseline != h || len(al.Events) != 1 || al.Events[0] != o.Event.ID {
		t.Fatalf("alarm %+v", al)
	}
	if hs := healthOf(t, r, HealthEventBaselineActive); len(hs) != 1 || hs[0].Details["baseline"] != h {
		t.Fatalf("active health %+v", hs)
	}
}

// C5's case for seam A: the acknowledgement is in the chain, the call never
// came (a crash between the receipt and the call), and after a restart the
// asset is active from the acknowledgement's chain time. Evidence class:
// simulated.
func TestLifeStartsActiveFromTheChain(t *testing.T) {
	c, dir := lifeNode(t)
	r, _, _ := start(t, c, dir)
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	learnOnce(t, l, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	h := recordedOf(t, r)[0].Config.BaselineDigest
	appendAck(t, r, h)
	recordedOf(t, r) // the chain verifies with the acknowledgement
	r.Close()

	r, st, _ := start(t, c, dir)
	defer r.Close()
	l, err = newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	if lr, d := l.half(relayID); lr != nil || d == nil {
		t.Fatalf("after the restart: learner %v, detector %v; alarms %+v", lr, d, st.Snapshot("n").Alarms)
	}
	if a := l.assets[relayID]; a.active != h || a.activeFrom.IsZero() || a.recorded != nil || a.recordedHash != "" {
		t.Fatalf("active %q from %v, recorded %q", a.active, a.activeFrom, a.recordedHash)
	}
	if len(recordedOf(t, r)) != 1 {
		t.Fatal("a restart recorded the baseline again")
	}
}

// A chain whose configuration records do not verify (here an
// acknowledgement that names no acceptance) stops every observed asset at
// start: no learner, no detector, nothing recorded, and the alarm. Evidence
// class: simulated.
func TestLifeUnverifiedChainStopsEveryAsset(t *testing.T) {
	c, dir := lifeNode(t)
	r, _, _ := start(t, c, dir)
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	learnOnce(t, l, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	h := recordedOf(t, r)[0].Config.BaselineDigest
	// The acknowledgement names the recorded baseline, so only the chain
	// check stops the asset from going active (C6 on #384).
	rec := audit.Record{Contract: audit.ContractID, NodeID: string(r.cfg.NodeID), Time: r.received(),
		Actor:  audit.Actor{Type: authz.PrincipalHuman, ID: "admin@site-a", Role: authz.RoleAdmin},
		Action: audit.ActionConfigBaselineAcknowledge, Outcome: audit.OutcomeSucceeded, Target: &audit.Target{AssetID: relayID},
		CorrelationID: "req-ack-9",
		Config:        &audit.Config{DecisionSeq: 9, PayloadSHA256: strings.Repeat("a", 64), Kind: authz.BaselineEvent, BaselineDigest: h}}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Log(AuditStream).Append(bg, c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: b}); err != nil {
		t.Fatal(err)
	}
	r.Close()

	r, st, _ := start(t, c, dir)
	defer r.Close()
	l, err = newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	if lr, d := l.half(relayID); lr != nil || d != nil || !l.awaiting(relayID) {
		t.Fatalf("learner %v, detector %v, awaiting %v", lr, d, l.awaiting(relayID))
	}
	if !hasAlarm(st, relayID, AlarmEventBaselineState) {
		t.Fatal("no alarm")
	}
}

// A baseline stored with no config.baseline_recorded after it (a crash
// between the two) is recorded at the next start, and awaits
// acknowledgement (D4-26 item 4). Evidence class: simulated.
func TestLifeStartRecordsAStoredBaseline(t *testing.T) {
	c, dir := lifeNode(t)
	r, _, _ := start(t, c, dir)
	res := storeBaseline(t, r, c, relayID, 1, "")
	r.Close()

	r, _, _ = start(t, c, dir)
	defer r.Close()
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	recs := recordedOf(t, r)
	if len(recs) != 1 || recs[0].Config.BaselineDigest != res.Hash || recs[0].Config.BaselineVersion != 1 {
		t.Fatalf("recordings %+v", recs)
	}
	if !l.awaiting(relayID) {
		t.Fatal("not awaiting acknowledgement")
	}
}

// storeBaseline finishes a learner of asset at version, replacing
// previous, and appends its baseline to the relay's configuration stream
// with no recording: what a crash between the two leaves.
func storeBaseline(t *testing.T, r *Runtime, c *Config, asset string, version int, previous string) *eventbaseline.Result {
	t.Helper()
	e, _ := c.EventBaselineFor(relayID)
	ln, err := eventbaseline.NewLearner(eventbaseline.LearnerConfig{Node: c.NodeID, AssetID: asset, Params: e.Params, Version: version, Previous: previous})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC).Add(time.Duration(version) * 24 * time.Hour)
	for i := range 11 {
		o := lifeSER("IN101", "Asserted", t0.Add(time.Duration(i)*400*time.Second))
		o.Event.Source.Asset.ID = asset
		if err := ln.Observe(o); err != nil {
			t.Fatal(err)
		}
	}
	res, err := ln.Finish(t0.Add(4400 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Log(ConfigStream(relayID)).Append(bg, c5.Record{Stream: ConfigStream(relayID), Class: c5.ClassConfiguration, Event: res.Bytes}); err != nil {
		t.Fatal(err)
	}
	return res
}

// C3's B2 on #384: with no recording in the chain (none written, or pruned)
// and two baselines stored, either could be the one a crash left
// unrecorded. The node picks neither, whatever order it finds them in: the
// asset is stopped with its alarm and nothing is recorded. Evidence class:
// simulated.
func TestLifeStartRefusesAnAmbiguousRepair(t *testing.T) {
	c, dir := lifeNode(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	v1 := storeBaseline(t, r, c, relayID, 1, "")
	storeBaseline(t, r, c, relayID, 2, v1.Hash)
	// Map order varies from run to run; one start per run would not show
	// a dependence on it, so start the lifecycle many times.
	for range 50 {
		l, err := newEventLife(bg, r)
		if err != nil {
			t.Fatal(err)
		}
		if lr, d := l.half(relayID); lr != nil || d != nil || l.assets[relayID].recorded != nil {
			t.Fatalf("learner %v, detector %v, recorded %v", lr, d, l.assets[relayID].recorded)
		}
	}
	if got := recordedOf(t, r); len(got) != 0 {
		t.Fatalf("%d recordings", len(got))
	}
	if !hasAlarm(st, relayID, AlarmEventBaselineState) {
		t.Fatal("no alarm")
	}
}

// A baseline of another asset in the relay's configuration stream is not
// taken, even though its hash would identify it: the asset is stopped with
// its alarm (C3 on #384). Evidence class: simulated.
func TestLifeStartRefusesAnotherAssetsBaseline(t *testing.T) {
	c, dir := lifeNode(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	storeBaseline(t, r, c, "9c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f", 1, "")
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	if lr, d := l.half(relayID); lr != nil || d != nil || len(recordedOf(t, r)) != 0 {
		t.Fatalf("learner %v, detector %v", lr, d)
	}
	if !hasAlarm(st, relayID, AlarmEventBaselineState) {
		t.Fatal("no alarm")
	}
}

// Seam B: a learner restores from its snapshot; one that does not starts
// again, raises the alarm and returns the error; a snapshot of a half the
// asset no longer has is ignored. A detector that does not restore is
// rebuilt and watched from the restart's watermark. Evidence class:
// simulated.
func TestLifeRestore(t *testing.T) {
	c, dir := lifeNode(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	l.Observe(relayID, lifeSER("IN101", "Asserted", t0))
	lr, _ := l.half(relayID)
	snap, err := lr.Snapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	if lerr, derr := l.restore(relayID, snap, nil, t0); lerr != nil || derr != nil {
		t.Fatalf("restore: %v, %v", lerr, derr)
	}
	if got, _ := l.half(relayID); got == lr || got.Progress(t0).Events != 1 {
		t.Fatalf("the learner was not restored: %+v", got.Progress(t0))
	}
	bad := append([]byte{}, snap...)
	bad[len(bad)/2] ^= 1
	if lerr, _ := l.restore(relayID, bad, nil, t0); !errors.Is(lerr, eventbaseline.ErrSnapshot) {
		t.Fatalf("a changed snapshot: %v", lerr)
	}
	if got, _ := l.half(relayID); got.Progress(t0).Events != 1 {
		t.Fatal("a failed restore changed the learner")
	}
	if !hasAlarm(st, relayID, AlarmEventBaselineNotRestored) {
		t.Fatal("no alarm for the failed restore")
	}

	end := learnOnce(t, l, t0.Add(time.Hour))
	if lerr, derr := l.restore(relayID, snap, snap, end); lerr != nil || derr != nil {
		t.Fatalf("snapshots of halves the asset no longer has: %v, %v", lerr, derr)
	}
	if lr, d := l.half(relayID); lr != nil || d != nil {
		t.Fatalf("a stale snapshot brought back a half: learner %v, detector %v", lr, d)
	}
	h := recordedOf(t, r)[0].Config.BaselineDigest
	l.acknowledged(relayID, h, end)
	_, d := l.half(relayID)
	dsnap, err := d.Snapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, derr := l.restore(relayID, nil, dsnap, end); derr != nil {
		t.Fatalf("a good detector snapshot: %v", derr)
	}
	if _, nd := l.half(relayID); nd == nil || nd == d {
		t.Fatal("the detector was not restored")
	}
	_, d = l.half(relayID)
	// A restart soon after the acknowledgement: the watermark trails
	// ActiveFrom, and the rebuilt detector still starts at ActiveFrom.
	if _, derr := l.restore(relayID, nil, bad, end.Add(-time.Minute)); !errors.Is(derr, eventbaseline.ErrSnapshot) {
		t.Fatalf("a detector snapshot that is not one: %v", derr)
	}
	if _, nd := l.half(relayID); nd == nil || nd == d || !l.assets[relayID].activeFrom.Equal(end) {
		t.Fatalf("rebuilt from %v, want ActiveFrom %v", l.assets[relayID].activeFrom, end)
	}
	_, d = l.half(relayID)
	wm := end.Add(time.Hour)
	if _, derr := l.restore(relayID, nil, bad, wm); !errors.Is(derr, eventbaseline.ErrSnapshot) {
		t.Fatalf("a detector snapshot that is not one: %v", derr)
	}
	if _, nd := l.half(relayID); nd == nil || nd == d || !l.assets[relayID].activeFrom.Equal(wm) {
		t.Fatalf("the detector was not rebuilt from the watermark: %v", l.assets[relayID].activeFrom)
	}
}

func hasAlarm(st *Status, asset, code string) bool {
	for _, a := range st.Snapshot("n").Alarms {
		if a.Asset == asset && a.Code == code {
			return true
		}
	}
	return false
}

// Slice 1d's status: each asset's phase, the learner's progress with its
// lower-bound types_overflow and gap-budget drops, the recorded and active
// baselines with their versions and types_overflow, and the feeder's late,
// skipped and unresolved counts and Step error. Late events raise the
// asset's alarm (C3 on #365). Evidence class: simulated.
func TestLifePublish(t *testing.T) {
	c, dir := lifeNode(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	f, err := newEventFeed(c, nil, time.Now, l)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	l.Observe(relayID, lifeSER("IN101", "Asserted", t0))
	l.publish(f, t0.Add(time.Minute), nil)
	got := st.Snapshot("n")
	eb := got.EventBaselines[relayID]
	if eb.Phase != "learning" || eb.Learning == nil || eb.Learning.Version != 1 || eb.Learning.Events != 1 ||
		eb.Learning.TypesHeld != 1 || eb.Learning.CollectedS != 60 || eb.Recorded != nil || eb.Active != nil {
		t.Fatalf("learning: %+v %+v", eb, eb.Learning)
	}
	if got.EventFeed == nil || got.EventFeed.Unresolved != 0 || got.EventFeed.StepError != "" || len(got.EventFeed.Skipped) != 0 {
		t.Fatalf("feed: %+v", got.EventFeed)
	}
	if hasAlarm(st, relayID, AlarmEventBaselineLate) {
		t.Fatal("a late alarm with nothing late")
	}

	end := learnOnce(t, l, t0.Add(time.Hour))
	f.assets[relayID].Late, f.Unresolved = 2, 3
	f.streams = append(f.streams, &feedStream{id: SERStream(relayID), Skipped: 4})
	l.publish(f, end, errors.New("stream stuck"))
	got = st.Snapshot("n")
	eb = got.EventBaselines[relayID]
	h := recordedOf(t, r)[0].Config.BaselineDigest
	if eb.Phase != "awaiting" || eb.Learning != nil || eb.Recorded == nil || *eb.Recorded != (EventBaselineRef{Hash: h, Version: 1}) || eb.Late != 2 {
		t.Fatalf("awaiting: %+v", eb)
	}
	if fs := got.EventFeed; fs.Unresolved != 3 || fs.Skipped[SERStream(relayID)] != 4 || fs.StepError != "stream stuck" {
		t.Fatalf("feed: %+v", fs)
	}
	if !hasAlarm(st, relayID, AlarmEventBaselineLate) {
		t.Fatal("no late alarm")
	}

	l.acknowledged(relayID, h, end)
	l.Tick(relayID, end.Add(time.Minute))
	l.publish(f, end.Add(time.Minute), nil)
	eb = st.Snapshot("n").EventBaselines[relayID]
	if eb.Phase != "active" || eb.Recorded != nil || eb.Active == nil || eb.Active.Hash != h || !eb.ActiveFrom.Equal(end) {
		t.Fatalf("active: %+v", eb)
	}
}

// A gap the learner refuses is not dropped silently: it is counted, raises
// the asset's alarm, and writes one health event until the alarm clears
// (C4 and C3 on #365). Evidence class: simulated.
func TestLifeRefusedGapIsVisible(t *testing.T) {
	c, dir := lifeNode(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	l.Gap(relayID, t0.Add(time.Hour), t0, "collection-failed")
	l.Gap(relayID, t0.Add(time.Hour), t0, "collection-failed")
	if a := l.assets[relayID]; a.Refused != 2 {
		t.Fatalf("refused %d, want 2", a.Refused)
	}
	if !hasAlarm(st, relayID, AlarmEventBaselineRefused) {
		t.Fatal("no alarm")
	}
	hs := healthOf(t, r, HealthEventBaselineRefused)
	if len(hs) != 1 || hs[0].Details["asset_id"] != relayID || !strings.Contains(hs[0].Details["error"], "ends before it starts") {
		t.Fatalf("refused health %+v", hs)
	}
}

// setMode puts database id in mode m, as a store alarm would, so that the
// lifecycle's writes to it are refused until it is set back.
func setMode(r *Runtime, id c5.DatabaseID, m c5.Mode) {
	d := r.find(id)
	r.state.Lock()
	d.report.Mode = m
	r.state.Unlock()
}

// C6's case 1 on #384: a crash between storing a re-learnt v2 and recording
// it. At the restart v2 is recorded at version 2, replacing v1, which stays
// active while v2 awaits its own acknowledgement. Evidence class:
// simulated.
func TestLifeStartRecordsAStoredRelearn(t *testing.T) {
	c, dir := lifeNode(t)
	r, _, _ := start(t, c, dir)
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	learnOnce(t, l, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	v1 := recordedOf(t, r)[0].Config.BaselineDigest
	appendAck(t, r, v1)
	v2 := storeBaseline(t, r, c, relayID, 2, v1)
	r.Close()

	r, _, _ = start(t, c, dir)
	defer r.Close()
	l, err = newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	recs := recordedOf(t, r)
	if len(recs) != 2 || recs[1].Config.BaselineDigest != v2.Hash || recs[1].Config.BaselineVersion != 2 || recs[1].Config.PreviousDigest != v1 {
		t.Fatalf("recordings %+v", recs)
	}
	a := l.assets[relayID]
	if a.detector == nil || a.active != v1 || a.recordedHash != v2.Hash || a.unrecorded {
		t.Fatalf("active %q, recorded %q", a.active, a.recordedHash)
	}
}

// C6's case 2 on #384: the repairs start refuses. Each stops the asset with
// its alarm, records nothing more and starts no learner. Evidence class:
// simulated.
func TestLifeStartRefusals(t *testing.T) {
	other := "sha256:" + strings.Repeat("c", 64)
	cases := map[string]func(t *testing.T, r *Runtime, c *Config){
		"a stored v2 that replaces another baseline": func(t *testing.T, r *Runtime, c *Config) {
			l, err := newEventLife(bg, r)
			if err != nil {
				t.Fatal(err)
			}
			learnOnce(t, l, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
			storeBaseline(t, r, c, relayID, 2, other)
		},
		"no recording, and a stored v2": func(t *testing.T, r *Runtime, c *Config) {
			storeBaseline(t, r, c, relayID, 2, other)
		},
		"a recording whose baseline is not stored": func(t *testing.T, r *Runtime, c *Config) {
			l, err := newEventLife(bg, r)
			if err != nil {
				t.Fatal(err)
			}
			a := &lifeAsset{id: relayID, raised: map[string]bool{}, recorded: &baseline.Baseline{Version: 1}, recordedHash: other}
			if err := l.record(a); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			c, dir := lifeNode(t)
			r, _, _ := start(t, c, dir)
			setup(t, r, c)
			n := len(recordedOf(t, r))
			r.Close()

			r, st, _ := start(t, c, dir)
			defer r.Close()
			l, err := newEventLife(bg, r)
			if err != nil {
				t.Fatal(err)
			}
			if lr, d := l.half(relayID); lr != nil || d != nil || len(recordedOf(t, r)) != n {
				t.Fatalf("learner %v, detector %v, %d recordings, want %d", lr, d, len(recordedOf(t, r)), n)
			}
			if !hasAlarm(st, relayID, AlarmEventBaselineState) {
				t.Fatal("no alarm")
			}
		})
	}
}

// C6's case 4 on #384: an acknowledgement of another digest, or of a
// baseline whose recording is not yet written, activates nothing and raises
// the alarm. Evidence class: simulated.
func TestLifeAcknowledgementGuard(t *testing.T) {
	t.Run("another digest", func(t *testing.T) {
		c, dir := lifeNode(t)
		r, st, _ := start(t, c, dir)
		defer r.Close()
		l, err := newEventLife(bg, r)
		if err != nil {
			t.Fatal(err)
		}
		end := learnOnce(t, l, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
		l.acknowledged(relayID, "sha256:"+strings.Repeat("c", 64), end)
		if _, d := l.half(relayID); d != nil || !hasAlarm(st, relayID, AlarmEventBaselineState) {
			t.Fatalf("detector %v", d)
		}
	})
	t.Run("not yet recorded", func(t *testing.T) {
		c, dir := lifeNode(t)
		r, st, _ := start(t, c, dir)
		defer r.Close()
		l, err := newEventLife(bg, r)
		if err != nil {
			t.Fatal(err)
		}
		setMode(r, AuditDB, c5.ModeBlocked)
		end := learnOnce(t, l, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
		a := l.assets[relayID]
		if !a.unrecorded {
			t.Fatal("recorded with the audit database blocked")
		}
		l.acknowledged(relayID, a.recordedHash, end)
		if _, d := l.half(relayID); d != nil || !hasAlarm(st, relayID, AlarmEventBaselineState) {
			t.Fatalf("detector %v", d)
		}
	})
}

// C6's case 5 on #384: a baseline that cannot be stored keeps its learner,
// which finishes at the next watermark once the configuration database
// takes events again; a recording that cannot be written is written at the
// next watermark once the audit database does. Each raises the alarm while
// it waits, and the recording clears it. Evidence class: simulated.
func TestLifeRetriesStoreAndRecording(t *testing.T) {
	c, dir := lifeNode(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	setMode(r, ConfigDB, c5.ModeBlocked)
	end := learnOnce(t, l, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	if lr, _ := l.half(relayID); lr == nil || len(rawStream(t, r, ConfigStream(relayID))) != 0 || !hasAlarm(st, relayID, AlarmEventBaselineNotRecorded) {
		t.Fatalf("learner %v after a refused store", lr)
	}
	setMode(r, ConfigDB, c5.ModeCollecting)
	setMode(r, AuditDB, c5.ModeBlocked)
	l.Tick(relayID, end.Add(time.Minute))
	a := l.assets[relayID]
	if a.learner != nil || len(rawStream(t, r, ConfigStream(relayID))) != 1 || !a.unrecorded || len(recordedOf(t, r)) != 0 {
		t.Fatalf("learner %v, unrecorded %v", a.learner, a.unrecorded)
	}
	l.Tick(relayID, end.Add(2*time.Minute))
	if !a.unrecorded {
		t.Fatal("recorded with the audit database blocked")
	}
	setMode(r, AuditDB, c5.ModeCollecting)
	l.Tick(relayID, end.Add(3*time.Minute))
	if a.unrecorded || len(recordedOf(t, r)) != 1 || a.raised[AlarmEventBaselineNotRecorded] {
		t.Fatalf("unrecorded %v, alarm held %v", a.unrecorded, a.raised[AlarmEventBaselineNotRecorded])
	}
}

// C6's case 7 on #384 (C1's condition 4): a baseline that left types out
// raises event-baseline-partial, and its recorded health event carries the
// count. Evidence class: simulated.
func TestLifePartialBaseline(t *testing.T) {
	c, dir := configNode(t, func(nc *nodeconfigtest.Config) {
		nc.AddEventBaseline(relayID)
		nc.EventBaselines[0].Params["max_types"] = 2
	})
	r, st, _ := start(t, c, dir)
	defer r.Close()
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	for i := range 12 {
		l.Observe(relayID, lifeSER(fmt.Sprintf("IN10%d", i%3+1), "Asserted", t0.Add(time.Duration(i)*400*time.Second)))
	}
	l.Tick(relayID, t0.Add(4800*time.Second))
	hs := healthOf(t, r, HealthEventBaselineRecorded)
	if len(hs) != 1 || hs[0].Details["types_overflow"] != "1" || hs[0].Details["types"] != "2" {
		t.Fatalf("recorded health %+v", hs)
	}
	if !hasAlarm(st, relayID, AlarmEventBaselinePartial) {
		t.Fatal("no partial alarm")
	}
}
