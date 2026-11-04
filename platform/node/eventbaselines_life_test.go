package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

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
		l.Observe(relayID, lifeSER("IN101", "Asserted", t0.Add(time.Duration(i)*400*time.Second)), time.Time{})
	}
	end := t0.Add(4400 * time.Second)
	l.Tick(relayID, end, time.Time{})
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
	recs, _, err := chainRecords(bg, r.Store(AuditStream))
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
	l.Observe(relayID, lifeSER("IN101", "Asserted", t0), time.Time{})
	l.Tick(relayID, t0.Add(2*time.Hour), time.Time{})
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
	l.Observe(relayID, lifeSER("IN102", "Asserted", t0.Add(3*time.Hour)), time.Time{})
	l.Tick(relayID, t0.Add(4*time.Hour), time.Time{})
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
	l.Observe(relayID, lifeSER("IN109", "Asserted", ackAt.Add(-time.Minute)), time.Time{})
	l.Tick(relayID, ackAt.Add(-time.Second), time.Time{}) // the watermark trails the chain time
	if _, d := l.half(relayID); d == nil {
		t.Fatal("not active after the acknowledgement")
	}
	if got := healthOf(t, r, baseline.HealthDeparture); len(got) != 0 || l.assets[relayID].Refused != 0 {
		t.Fatalf("an event before the acknowledgement reached the detector: alarms %+v, refused %d", got, l.assets[relayID].Refused)
	}
	o := lifeSER("IN109", "Asserted", ackAt.Add(time.Minute))
	l.Observe(relayID, o, time.Time{})
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
	return storeBaselineAt(t, r, c, asset, version, previous, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC).Add(time.Duration(version)*24*time.Hour))
}

// storeBaselineAt is storeBaseline learned from t0, so two baselines of one
// version can differ.
func storeBaselineAt(t *testing.T, r *Runtime, c *Config, asset string, version int, previous string, t0 time.Time) *eventbaseline.Result {
	t.Helper()
	e, _ := c.EventBaselineFor(relayID)
	ln, err := eventbaseline.NewLearner(eventbaseline.LearnerConfig{Node: c.NodeID, AssetID: asset, Params: e.Params, Version: version, Previous: previous})
	if err != nil {
		t.Fatal(err)
	}
	// Ten rows meet both minima at the tenth, where the period ends (D4-45).
	for i := range 10 {
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
	l.Observe(relayID, lifeSER("IN101", "Asserted", t0), time.Time{})
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
	l.Observe(relayID, lifeSER("IN101", "Asserted", t0), time.Time{})
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
	l.Tick(relayID, end.Add(time.Minute), time.Time{})
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
	l.Tick(relayID, end.Add(time.Minute), time.Time{})
	a := l.assets[relayID]
	if a.learner != nil || len(rawStream(t, r, ConfigStream(relayID))) != 1 || !a.unrecorded || len(recordedOf(t, r)) != 0 {
		t.Fatalf("learner %v, unrecorded %v", a.learner, a.unrecorded)
	}
	l.Tick(relayID, end.Add(2*time.Minute), time.Time{})
	if !a.unrecorded {
		t.Fatal("recorded with the audit database blocked")
	}
	setMode(r, AuditDB, c5.ModeCollecting)
	l.Tick(relayID, end.Add(3*time.Minute), time.Time{})
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
		l.Observe(relayID, lifeSER(fmt.Sprintf("IN10%d", i%3+1), "Asserted", t0.Add(time.Duration(i)*400*time.Second)), time.Time{})
	}
	l.Tick(relayID, t0.Add(4800*time.Second), time.Time{})
	hs := healthOf(t, r, HealthEventBaselineRecorded)
	if len(hs) != 1 || hs[0].Details["types_overflow"] != "1" || hs[0].Details["types"] != "2" {
		t.Fatalf("recorded health %+v", hs)
	}
	if !hasAlarm(st, relayID, AlarmEventBaselinePartial) {
		t.Fatal("no partial alarm")
	}
}

// A store that refuses the finished baseline's append (here a context ended
// before the commit was queued; a database at its quota takes the same
// branch) keeps the learner, which finishes at the next watermark once the
// store takes it, and only one baseline is stored (C6's M24 on #384).
// Evidence class: simulated.
func TestLifeKeepsTheLearnerWhenTheAppendFails(t *testing.T) {
	c, dir := lifeNode(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	ctx, cancel := context.WithCancel(bg)
	l, err := newEventLife(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	end := learnOnce(t, l, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	if lr, _ := l.half(relayID); lr == nil || len(rawStream(t, r, ConfigStream(relayID))) != 0 || !hasAlarm(st, relayID, AlarmEventBaselineNotRecorded) {
		t.Fatalf("learner %v after a refused append", lr)
	}
	l.ctx = bg
	l.Tick(relayID, end.Add(time.Minute), time.Time{})
	if lr, _ := l.half(relayID); lr != nil || len(rawStream(t, r, ConfigStream(relayID))) != 1 || len(recordedOf(t, r)) != 1 {
		t.Fatalf("learner %v after the store took the baseline: %d stored, %d recorded", lr, len(rawStream(t, r, ConfigStream(relayID))), len(recordedOf(t, r)))
	}
}

// appendAudit appends rec to the node's audit stream and returns its seq.
func appendAudit(t *testing.T, r *Runtime, rec audit.Record) c5.Seq {
	t.Helper()
	rec.Contract, rec.NodeID, rec.Time = audit.ContractID, string(r.cfg.NodeID), r.received()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Log(AuditStream).Append(bg, c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: b}); err != nil {
		t.Fatal(err)
	}
	return auditHead(t, r)
}

func auditHead(t *testing.T, r *Runtime) c5.Seq {
	t.Helper()
	got, err := r.Store(AuditStream).Read(bg, AuditStream, 0, 10000)
	if err != nil || len(got) == 0 {
		t.Fatalf("%d audit records: %v", len(got), err)
	}
	return got[len(got)-1].Key.Seq
}

// pruneLifeAudit prunes the node's audit stream through through, as
// cfgNode.pruneAudit does. A record must follow through.
func pruneLifeAudit(t *testing.T, r *Runtime, through c5.Seq) {
	t.Helper()
	db := r.Store(AuditStream)
	fwd := c5.Consumer{ID: "fwd", Stream: AuditStream, Delivery: c5.Required}
	for _, id := range []c5.ConsumerID{fwd.ID, SuspensionConsumer, HoldsConsumer} {
		if err := db.SaveCursor(bg, c5.Cursor{Consumer: id, Stream: AuditStream, Through: through}); err != nil && !errors.Is(err, &c5.Error{Code: c5.CodeCursorRegress}) {
			t.Fatal(err)
		}
	}
	b, err := c5.ComputeBoundary(bg, db, db, pruneConsumers([]c5.Consumer{fwd}), AuditStream, c5.ClassAudit, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if k, err := db.PruneStep(bg, b, 1000); err != nil || k == 0 {
		t.Fatalf("pruned %d: %v", k, err)
	}
	if first, err := db.FirstRetained(bg, AuditStream); err != nil || first != through+1 {
		t.Fatalf("first retained %d, want %d: %v", first, through+1, err)
	}
}

// filler is an audit record that is not a configuration record, so a prune
// through the record before it can run.
var filler = audit.Record{Actor: audit.Actor{Type: authz.PrincipalSchedule, ID: "sch-cfg", Role: authz.RoleCollector},
	Action: audit.ActionCollectorRequest, Outcome: audit.OutcomeInfo, PolicyVersion: 3, CorrelationID: "req-filler"}

// recordingsIn counts the config.baseline_recorded records in the node's
// audit view, pruned or not.
func recordingsIn(t *testing.T, r *Runtime) int {
	t.Helper()
	recs, _, err := chainRecords(bg, r.Store(AuditStream))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, ar := range recs {
		if ar.rec.Action == audit.ActionConfigBaselineRecorded {
			n++
		}
	}
	return n
}

// C3's condition on #384 and D4-41: v1 is learned, recorded and
// acknowledged, and the audit stream is pruned past its recording and its
// acknowledgement. At the next start nothing is repaired or recorded: the
// active baseline is v1, found from the configuration store's baseline
// hold, and its activation time is provisional. restore then takes the
// checkpoint's activation time when it is no earlier than the baseline
// period's end and no later than the watermark, and otherwise rebuilds
// the detector from the watermark with the alarm and an error that wraps
// ErrSnapshotMismatch. With no snapshot it is rebuilt from the watermark,
// with no alarm, as nothing was lost. Evidence class: simulated.
func TestLifePrunedPastTheRecording(t *testing.T) {
	c, dir := lifeNode(t)
	r, _, _ := start(t, c, dir)
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	end := learnOnce(t, l, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	h := recordedOf(t, r)[0].Config.BaselineDigest
	appendAck(t, r, h)
	ackAt := end.Add(time.Hour)
	l.acknowledged(relayID, h, ackAt)
	l.Tick(relayID, ackAt, time.Time{})
	_, d := l.half(relayID)
	good, err := d.Snapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	b := l.assets[relayID].activeBaseline
	periodEnd, err := time.Parse(time.RFC3339Nano, b.Period.EndUTC)
	if err != nil {
		t.Fatal(err)
	}
	early, err := eventbaseline.NewDetector(eventbaseline.DetectorConfig{Baseline: b, Hash: h, ActiveFrom: periodEnd.Add(-time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	tooEarly, err := early.Snapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	ack := auditHead(t, r)
	r.Close()

	// The restart's reconcile holds v1 as baseline; the prune then takes
	// the recording and the acknowledgement.
	r, _, _ = start(t, c, dir)
	held, err := r.Store(ConfigStream(relayID)).Held(bg, ConfigStream(relayID))
	if err != nil || len(held) != 1 || held[0].Reason.Code != c5.HoldBaseline || held[0].Reason.Ref.Seq != ack {
		t.Fatalf("holds %+v: %v", held, err)
	}
	appendAudit(t, r, filler)
	pruneLifeAudit(t, r, ack)
	r.Close()

	restart := func(t *testing.T) (*Runtime, *Status, *eventLife) {
		t.Helper()
		r, st, _ := start(t, c, dir)
		t.Cleanup(func() { r.Close() })
		l, err := newEventLife(bg, r)
		if err != nil {
			t.Fatal(err)
		}
		a := l.assets[relayID]
		if lr, d := l.half(relayID); lr != nil || d == nil || a.active != h || !a.fromHold || a.recorded != nil {
			t.Fatalf("after the prune: learner %v, detector %v, active %q, from hold %v, recorded %v; alarms %+v", lr, d, a.active, a.fromHold, a.recorded, st.Snapshot("n").Alarms)
		}
		if l.first != ack+1 || recordingsIn(t, r) != 0 || len(rawStream(t, r, ConfigStream(relayID))) != 1 {
			t.Fatalf("first %d, %d recordings, %d configuration records", l.first, recordingsIn(t, r), len(rawStream(t, r, ConfigStream(relayID))))
		}
		return r, st, l
	}
	wm := ackAt.Add(time.Hour)
	for _, tc := range []struct {
		name     string
		snap     []byte
		wm, from time.Time
		mismatch bool
	}{
		{"the checkpoint's time", good, wm, ackAt, false},
		{"at the watermark", good, ackAt, ackAt, false},
		{"before the period's end", tooEarly, wm, wm, true},
		{"after the watermark", good, ackAt.Add(-time.Minute), ackAt.Add(-time.Minute), true},
		{"no snapshot", nil, wm, wm, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, st, l := restart(t)
			_, d := l.half(relayID)
			_, derr := l.restore(relayID, nil, tc.snap, tc.wm)
			a := l.assets[relayID]
			if errors.Is(derr, eventbaseline.ErrSnapshotMismatch) != tc.mismatch || (!tc.mismatch && derr != nil) {
				t.Fatalf("restore: %v", derr)
			}
			if _, nd := l.half(relayID); nd == nil || nd == d || a.fromHold || !a.activeFrom.Equal(tc.from) {
				t.Fatalf("detector %v (was %v), from hold %v, active from %v, want %v", nd, d, a.fromHold, a.activeFrom, tc.from)
			}
			if hasAlarm(st, relayID, AlarmEventBaselineNotRestored) != tc.mismatch {
				t.Fatalf("alarm %v", !tc.mismatch)
			}
			// Settled, a second restore is the ordinary one.
			if _, derr := l.restore(relayID, nil, nil, tc.wm.Add(time.Hour)); derr != nil || !a.activeFrom.Equal(tc.from) {
				t.Fatalf("again: %v, from %v", derr, a.activeFrom)
			}
		})
	}
}

// D4-41: of the records the configuration store holds as baseline, the one
// whose Ref is the highest seq is the active baseline, whatever their order
// in the stream; a hold whose Ref is in the view is refused, as the view
// would hold that acknowledgement. Evidence class: simulated.
func TestLifeHeldBaselineHighestRef(t *testing.T) {
	c, dir := lifeNode(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	v1 := storeBaseline(t, r, c, relayID, 1, "")
	v2 := storeBaseline(t, r, c, relayID, 2, v1.Hash)
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := l.storedBaselines(bg, relayID)
	if err != nil {
		t.Fatal(err)
	}
	cs := ConfigStream(relayID)
	hold := func(seq c5.Seq, ref c5.Seq) {
		t.Helper()
		if err := r.Store(cs).Hold(bg, c5.Hold{Stream: cs, Seq: seq, Reason: c5.HoldReason{Code: c5.HoldBaseline,
			Ref: c5.Key{NodeID: r.cfg.NodeID, Stream: AuditStream, Seq: ref}}}); err != nil {
			t.Fatal(err)
		}
	}
	l.first = 10
	for _, tc := range []struct {
		r1, r2 c5.Seq
		want   string
	}{{3, 5, v2.Hash}, {5, 3, v1.Hash}} {
		hold(1, tc.r1)
		hold(2, tc.r2)
		if got, err := l.heldBaseline(bg, relayID, stored); err != nil || got != tc.want {
			t.Fatalf("refs %d, %d: %q, %v; want %q", tc.r1, tc.r2, got, err, tc.want)
		}
	}
	hold(1, 10)
	if got, err := l.heldBaseline(bg, relayID, stored); err == nil {
		t.Fatalf("a Ref in the view: %q", got)
	}
}

// C3 on #384: with v1's recording in the view and two v2 baselines stored
// after it, either could be the one whose recording a crash left out. The
// node picks neither: the asset is stopped with its alarm and nothing is
// recorded. Evidence class: simulated.
func TestLifeStartRefusesTwoNextVersions(t *testing.T) {
	c, dir := lifeNode(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	learnOnce(t, l, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	h := recordedOf(t, r)[0].Config.BaselineDigest
	t2 := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	a := storeBaselineAt(t, r, c, relayID, 2, h, t2)
	b := storeBaselineAt(t, r, c, relayID, 2, h, t2.Add(time.Hour))
	if a.Hash == b.Hash {
		t.Fatal("the two v2 baselines are one")
	}
	l, err = newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	if lr, d := l.half(relayID); lr != nil || d != nil || l.assets[relayID].recordedHash != "" {
		t.Fatalf("learner %v, detector %v, recorded %q", lr, d, l.assets[relayID].recordedHash)
	}
	if got := recordedOf(t, r); len(got) != 1 {
		t.Fatalf("%d recordings", len(got))
	}
	if !hasAlarm(st, relayID, AlarmEventBaselineState) {
		t.Fatal("no alarm")
	}
}

// In a view cut by a prune, a stored baseline that no recording in the view
// and no baseline hold places could be recorded, acknowledged or neither:
// the node does not learn a first baseline over it, and stops the asset
// with its alarm (D4-41). Evidence class: simulated.
func TestLifePrunedStoredUnplaced(t *testing.T) {
	c, dir := lifeNode(t)
	r, _, _ := start(t, c, dir)
	storeBaseline(t, r, c, relayID, 1, "")
	through := appendAudit(t, r, filler)
	appendAudit(t, r, filler)
	pruneLifeAudit(t, r, through)
	r.Close()

	r, st, _ := start(t, c, dir)
	defer r.Close()
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	if lr, d := l.half(relayID); lr != nil || d != nil || recordingsIn(t, r) != 0 {
		t.Fatalf("learner %v, detector %v, %d recordings", lr, d, recordingsIn(t, r))
	}
	if !hasAlarm(st, relayID, AlarmEventBaselineState) {
		t.Fatal("no alarm")
	}
}

// C6's probe Q2 on #384: a broken hash link in the retained audit stream, in a record that
// VerifyConfigFrom does not read, stops every observed asset. Evidence
// class: simulated.
func TestLifeBrokenLinkStopsEveryAsset(t *testing.T) {
	c, dir := lifeNode(t)
	r, _, _ := start(t, c, dir)
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	learnOnce(t, l, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	appendAudit(t, r, filler)
	r.Close()
	// Change one byte of the filler record, in the audit database itself.
	paths, _ := filepath.Glob(filepath.Join(c.Store.Dir, "*.db"))
	changed := 0
	for _, p := range paths {
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(p))
		if err != nil {
			t.Fatal(err)
		}
		var id int64
		var ev []byte
		if err := db.QueryRow(`SELECT id, event FROM events WHERE stream = 'audit' AND instr(event, 'req-filler') > 0`).Scan(&id, &ev); err == nil {
			if _, err := db.Exec(`UPDATE events SET event = ? WHERE id = ?`, bytes.Replace(ev, []byte("req-filler"), []byte("req-fillex"), 1), id); err != nil {
				t.Fatal(err)
			}
			changed++
		}
		db.Close()
	}
	if changed != 1 {
		t.Fatalf("changed %d audit records", changed)
	}
	r, st, _ := start(t, c, dir)
	defer r.Close()
	l, err = newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	if lr, d := l.half(relayID); lr != nil || d != nil {
		t.Fatalf("learner %v, detector %v after a broken link", lr, d)
	}
	if !hasAlarm(st, relayID, AlarmEventBaselineState) {
		t.Fatal("no alarm")
	}
}

// C6's probe Q8 on #384: the asset's configuration stream also holds C9 snapshots, and the
// configuration baseline is held as baseline too (D4-41). A C9 baseline
// hold with the newest Ref is passed over: the event baseline is the
// newest-Ref C10 one. Evidence class: simulated.
func TestLifeHeldBaselineSkipsAConfigurationBaseline(t *testing.T) {
	c, dir := lifeNode(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	v1 := storeBaseline(t, r, c, relayID, 1, "")
	v2 := storeBaseline(t, r, c, relayID, 2, v1.Hash)
	snap, capture := configRead(t, "1")
	cs := ConfigStream(relayID)
	if _, err := r.Log(cs).Append(bg, c5.Record{Stream: cs, Class: c5.ClassConfiguration, Event: snap, Capture: &capture}); err != nil {
		t.Fatal(err)
	}
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := l.storedBaselines(bg, relayID)
	if err != nil {
		t.Fatal(err)
	}
	for seq, ref := range map[c5.Seq]c5.Seq{1: 3, 2: 5, 3: 7} {
		if err := r.Store(cs).Hold(bg, c5.Hold{Stream: cs, Seq: seq, Reason: c5.HoldReason{Code: c5.HoldBaseline,
			Ref: c5.Key{NodeID: r.cfg.NodeID, Stream: AuditStream, Seq: ref}}}); err != nil {
			t.Fatal(err)
		}
	}
	l.first = 10
	if got, err := l.heldBaseline(bg, relayID, stored); err != nil || got != v2.Hash {
		t.Fatalf("%q, %v; want v2 %q", got, err, v2.Hash)
	}
}

// C6's probe Q15 on #384: once restore settles a baseline taken from a hold, the health
// stream says when it is active from. Evidence class: simulated.
func TestLifeHeldRestoreSaysActiveFrom(t *testing.T) {
	c, dir := lifeNode(t)
	r, _, _ := start(t, c, dir)
	l, err := newEventLife(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	end := learnOnce(t, l, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	h := recordedOf(t, r)[0].Config.BaselineDigest
	appendAck(t, r, h)
	ackAt := end.Add(time.Hour)
	l.acknowledged(relayID, h, ackAt)
	l.Tick(relayID, ackAt, time.Time{})
	_, d := l.half(relayID)
	good, err := d.Snapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	ack := auditHead(t, r)
	r.Close()
	r, _, _ = start(t, c, dir)
	appendAudit(t, r, filler)
	pruneLifeAudit(t, r, ack)
	r.Close()
	wm := ackAt.Add(time.Hour)
	for _, tc := range []struct {
		name string
		snap []byte
		from time.Time
	}{{"the checkpoint's time", good, ackAt}, {"no snapshot", nil, wm}} {
		t.Run(tc.name, func(t *testing.T) {
			r, _, _ := start(t, c, dir)
			defer r.Close()
			l, err := newEventLife(bg, r)
			if err != nil {
				t.Fatal(err)
			}
			if _, derr := l.restore(relayID, nil, tc.snap, wm); derr != nil {
				t.Fatal(derr)
			}
			hs := healthOf(t, r, HealthEventBaselineActive)
			if len(hs) == 0 || hs[len(hs)-1].Details["active_from"] != tc.from.UTC().Format(time.RFC3339Nano) {
				t.Fatalf("health %+v, want the last active_from %s", hs, tc.from.UTC().Format(time.RFC3339Nano))
			}
		})
	}
}

// TestLifePeriodEndDoesNotDependOnTheTick: the same events and gaps, ticked
// at three cadences, store the same baseline bytes, and its period ends
// where both minima first hold, not at a watermark (D4-45; C6's F-020). The
// test minima are an hour and ten events. Evidence class: simulated.
func TestLifePeriodEndDoesNotDependOnTheTick(t *testing.T) {
	t0 := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	s := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Second) }
	type item struct {
		o     eventbaseline.Obs
		gap   [2]time.Time // a gap fed instead of an event
		open  time.Time
		at    time.Time
		isGap bool
		tick  bool // a watermark with no event: always ticked
	}
	ev := func(n int, open time.Time) item {
		return item{o: lifeSER("IN101", "Asserted", s(n)), open: open, at: s(n)}
	}
	// Ten events 400 s apart from 0 s meet both minima at 3600 s, with one
	// more at 3600 s, which counts, and one after, which does not.
	var plain []item
	for i := range 10 {
		plain = append(plain, ev(i*400, time.Time{}))
	}
	plain = append(plain, ev(3600, time.Time{}), ev(3700, time.Time{}), ev(5000, time.Time{}))
	// The same, with a gap open from 3000 s to 3800 s: the duration is not
	// met before it, so the events in it count and the end moves to 4400 s.
	var gapped []item
	for i := range 8 {
		gapped = append(gapped, ev(i*400, time.Time{}))
	}
	open := s(3000)
	// The watermark passes 3700 s while the gap is open; were the gap not
	// counted, the end would be there.
	gapped = append(gapped, ev(3200, open), ev(3600, open), ev(3700, open),
		item{tick: true, at: s(3790), open: open},
		item{isGap: true, gap: [2]time.Time{open, s(3800)}, at: s(3800)},
		ev(4400, time.Time{}), ev(4401, time.Time{}), ev(6000, time.Time{}))

	run := func(t *testing.T, items []item, tickAt func(i int, it item) bool) []byte {
		t.Helper()
		c, dir := lifeNode(t)
		r, _, _ := start(t, c, dir)
		defer r.Close()
		l, err := newEventLife(bg, r)
		if err != nil {
			t.Fatal(err)
		}
		var lastOpen time.Time
		for i, it := range items {
			if it.tick {
				l.Tick(relayID, it.at, it.open)
				continue
			}
			if it.isGap {
				l.Gap(relayID, it.gap[0], it.gap[1], "failed.timeout")
				lastOpen = time.Time{}
			} else {
				l.Observe(relayID, it.o, it.open)
				lastOpen = it.open
			}
			if tickAt(i, it) {
				l.Tick(relayID, it.at, lastOpen)
			}
		}
		l.Tick(relayID, s(86400), time.Time{})
		docs := rawStream(t, r, ConfigStream(relayID))
		if len(docs) != 1 {
			t.Fatalf("%d configuration records, want the baseline", len(docs))
		}
		return docs[0]
	}
	cadences := map[string]func(int, item) bool{
		"after every event": func(int, item) bool { return true },
		"every third":       func(i int, _ item) bool { return i%3 == 2 },
		"only at the end":   func(int, item) bool { return false },
	}
	for name, tc := range map[string]struct {
		items  []item
		end    time.Time
		events int64
	}{"no gap": {plain, s(3600), 11}, "a gap open across the end": {gapped, s(4400), 12}} {
		t.Run(name, func(t *testing.T) {
			var want []byte
			for cn, tick := range cadences {
				got := run(t, tc.items, tick)
				b, err := baseline.Decode(got)
				if err != nil {
					t.Fatal(err)
				}
				if e := tc.end.Format(time.RFC3339Nano); b.Period.EndUTC != e || b.RecordedUTC != e || b.Counts.Events != tc.events {
					t.Fatalf("%s: period ends %s, recorded %s, %d events; want %s and %d events", cn, b.Period.EndUTC, b.RecordedUTC, b.Counts.Events, e, tc.events)
				}
				if want == nil {
					want = got
				} else if !bytes.Equal(got, want) {
					t.Fatalf("%s: other baseline bytes than the first cadence", cn)
				}
			}
		})
	}
}
