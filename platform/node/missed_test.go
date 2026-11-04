package node

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// missedRecords is the collection.missed events on the health stream, in
// order, and every health type with them.
func missedRecords(t *testing.T, r *Runtime) (missed []map[string]string, types []string) {
	t.Helper()
	got, err := r.Store(HealthStream).Read(bg, HealthStream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		e, err := event.Decode(s.Event)
		if err != nil {
			t.Fatal(err)
		}
		types = append(types, e.Health.Type)
		if e.Health.Type == HealthCollectionMissed {
			missed = append(missed, e.Health.Details)
		}
	}
	return missed, types
}

// A run whose outcome arrived but was not stored writes one
// collection.missed, once for the whole outage however many runs fail;
// a stored read ends the outage, and the next failure writes a new one.
func TestMissedRunRecordedOncePerOutage(t *testing.T) {
	t.Parallel()
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	ser := SERStream(relayID)
	breakState := func() {
		if err := r.Store(ser).SaveSourceCursor(bg, ser, []byte("not a state")); err != nil {
			t.Fatal(err)
		}
	}

	breakState()
	first := s.RunOnce(bg, 0)
	second := s.RunOnce(bg, 0)
	if first.Alarm != AlarmEvidenceNotStored || second.Alarm != AlarmEvidenceNotStored {
		t.Fatalf("runs with an unreadable state: %+v, %+v", first, second)
	}
	missed, _ := missedRecords(t, r)
	if len(missed) != 1 {
		t.Fatalf("%d collection.missed records for one outage: %v", len(missed), missed)
	}
	m := missed[0]
	if m["asset_id"] != relayID || m["operation"] != "sel.ser.read_all" || m["missed"] != "1" ||
		m["alarm"] != AlarmEvidenceNotStored || m["request_id"] != first.RequestID {
		t.Fatalf("collection.missed details: %v", m)
	}

	b, err := normalize.EncodeState([]string{"sha256:" + strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Store(ser).SaveSourceCursor(bg, ser, b); err != nil {
		t.Fatal(err)
	}
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" || rep.Alarm != "" {
		t.Fatalf("run after the repair: %+v", rep)
	}
	breakState()
	s.RunOnce(bg, 0)
	if missed, _ := missedRecords(t, r); len(missed) != 2 {
		t.Fatalf("%d collection.missed records after a second outage, want 2", len(missed))
	}
}

// A quiet device is not a missed run: a read that adds no SER rows is
// stored through its collection.run, and a refusal through its
// collection.refused.
func TestStoredRunsAreNotMissed(t *testing.T) {
	t.Parallel()
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" || rep.Events == 0 {
		t.Fatalf("first read: %+v", rep)
	}
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" || rep.Events != 0 {
		t.Fatalf("a read with no new rows: %+v", rep)
	}
	s.c = &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
			Refusal: &authz.Refusal{Code: authz.RefuseRateLimited, Detail: "inside the floor"}, CollectorSeq: seq + 1}}, nil
	}}
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorRefused {
		t.Fatalf("refused: %+v", rep)
	}
	if missed, types := missedRecords(t, r); len(missed) != 0 {
		t.Fatalf("collection.missed after stored runs: %v", types)
	}
}

// A failed run whose collection.* record is stored is a recorded failure,
// not a missed run: no decision, an outcome that did not arrive, and a
// quarantined outcome.
func TestRecordedFailuresAreNotMissed(t *testing.T) {
	t.Parallel()
	for name, answer := range map[string]func(req *authz.CollectorRequest) (collectorclient.Response, error){
		"no decision": func(*authz.CollectorRequest) (collectorclient.Response, error) {
			return collectorclient.Response{}, fmt.Errorf("%w: status %q", collectorclient.ErrProtocol, "maybe")
		},
		"outcome unknown": func(req *authz.CollectorRequest) (collectorclient.Response, error) {
			return collectorclient.Response{Reply: accepted(req, 1)}, fmt.Errorf("%w: connection closed", collectorclient.ErrOutcomeUnknown)
		},
		"quarantined": func(req *authz.CollectorRequest) (collectorclient.Response, error) {
			return collectorclient.Response{Reply: accepted(req, 1), Quarantine: &collectorclient.Quarantine{Raw: []byte("frame"), Reason: "r"}},
				fmt.Errorf("%w: %w", collectorclient.ErrOutcomeUnknown, collectorclient.ErrOutcomeQuarantined)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, dir := schedConfig(t, nil)
			r, _, _ := start(t, c, dir)
			defer r.Close()
			if rep := newScheduler(t, r, &fakeCollector{answer: answer}).RunOnce(bg, 0); !rep.Sent || rep.Alarm == "" {
				t.Fatalf("%+v", rep)
			}
			if missed, types := missedRecords(t, r); len(missed) != 0 {
				t.Fatalf("collection.missed after a recorded failure: %v", types)
			}
		})
	}
}

// A slot that never sends its run (here the audit database is full, so the
// collector is held) is missed too: one record for the run of skips, with
// no request ID, since none was made.
func TestSkippedRunsAreMissed(t *testing.T) {
	t.Parallel()
	c, dir := schedConfig(t, func(nc *nodeconfigtest.Config) { nc.Store.Quotas["audit"] = 600 })
	r, _, _ := start(t, c, dir)
	defer r.Close()
	f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: accepted(req, 1)}, nil
	}}
	s := newScheduler(t, r, f)
	for i := 0; i < 3; i++ {
		if rep := s.RunOnce(bg, 0); rep.Sent || rep.Alarm != AlarmAuditUnavailable {
			t.Fatalf("run %d: %+v", i, rep)
		}
	}
	missed, _ := missedRecords(t, r)
	if len(missed) != 1 || missed[0]["alarm"] != AlarmAuditUnavailable || missed[0]["missed"] != "1" ||
		missed[0]["request_id"] != "" || missed[0]["schedule"] != c.Schedule[0].ID {
		t.Fatalf("collection.missed: %v", missed)
	}
	if _, err := time.Parse(time.RFC3339Nano, missed[0]["first_at"]); err != nil {
		t.Fatalf("first_at: %v", err)
	}
}

// With the evidence database not open, a missed run cannot be recorded at
// once. It is written, with the count of runs missed, at the first run
// after the database opens, before that run's own records, so the read
// that follows the outage comes after its gap. Each busy open waits out the
// store's busy_timeout, so this test takes a few seconds.
func TestMissedRunWrittenWhenTheStoreAccepts(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out busy_timeout")
	}
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir) // creates the databases
	r.Close()
	release := holdDB(t, c.Store.Dir, EvidenceDB)
	r, _, _ = start(t, c, dir)
	defer r.Close()
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	for i := 0; i < 2; i++ {
		if rep := s.RunOnce(bg, 0); rep.Sent {
			t.Fatalf("run %d with the evidence database not open was sent: %+v", i, rep)
		}
	}
	release()
	r.Tick(bg)
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" {
		t.Fatalf("run after the database opened: %+v", rep)
	}
	missed, types := missedRecords(t, r)
	if len(missed) != 1 || missed[0]["missed"] != "2" {
		t.Fatalf("collection.missed: %v", missed)
	}
	if m, run := slices.Index(types, HealthCollectionMissed), slices.Index(types, HealthCollectionRun); m < 0 || run < m || count(types, HealthCollectionRun) != 1 {
		t.Fatalf("health order: %v", types)
	}
}

// D4-37, C6's probe on #372: with the platform class full and
// adapter-evidence not, a read still stores its rows, so its run is not
// missed. A run whose own collection.* record is refused is missed, and
// while its collection.missed is not stored the entry's runs are held:
// the held slot joins the series and no request is sent. Once the class
// has room, the record is stored before the next run's request, with the
// first slot's time, alarm and request ID. Evidence class: simulated.
func TestMissedSeriesHoldsRunsUntilStored(t *testing.T) {
	t.Parallel()
	const quota = 64 << 10
	r, st, c, _ := pruneNode(t, 1<<30, func(nc *nodeconfigtest.Config) { nc.Store.Quotas["platform"] = quota })
	var seq uint64
	var sent, missedAtSend int
	wire := wireCollector(t, func(*authz.CollectorRequest) {
		sent++
		m, _ := missedRecords(t, r)
		missedAtSend = len(m)
	}, &seq)
	s := newScheduler(t, r, wire)
	log, db := r.Log(HealthStream), r.Store(HealthStream)
	fill := func() {
		for i := 0; ; i++ {
			rec, err := r.healthRecord(HealthStream, HealthCollectionRun, map[string]string{"n": "filler"})
			if err == nil {
				_, err = log.Append(bg, rec)
			}
			if err != nil {
				return
			}
			if i > 5000 {
				t.Fatalf("platform still takes events after %d", i)
			}
		}
	}
	fill()

	// A read with the class full: its rows are stored, so it starts no
	// series and the next run is sent (X1).
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" || rep.Events == 0 {
		t.Fatalf("read with platform full: %+v", rep)
	}
	// A refusal whose collection.refused is refused is missed (X10).
	refuse := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		seq++
		return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
			Refusal: &authz.Refusal{Code: authz.RefuseRateLimited, Detail: "inside the floor"}, CollectorSeq: seq}}, nil
	}}
	s.c = refuse
	before := time.Now()
	refused := s.RunOnce(bg, 0)
	after := time.Now()
	if !refused.Sent || refused.Alarm != AlarmCollectorRefused {
		t.Fatalf("refusal after the read was not sent: %+v", refused)
	}
	id := c.Schedule[0].ID
	raised := func() (n int) {
		for _, a := range st.Snapshot("x").Alarms {
			if a.Code == AlarmEvidenceNotStored && strings.Contains(a.Detail, HealthCollectionMissed+" of schedule entry "+id+" not stored") {
				n++
			}
		}
		return n
	}
	if n := raised(); n != 1 {
		t.Fatalf("%d alarms for the unwritten series, want 1 (X14)", n)
	}

	// The next slot is held: nothing is sent while the series is unwritten.
	s.c = wire
	n := sent
	if rep := s.RunOnce(bg, 0); rep.Sent || rep.Alarm != AlarmEvidenceNotStored || sent != n {
		t.Fatalf("run with its series unwritten: %+v, %d requests", rep, sent-n)
	}
	if m, _ := missedRecords(t, r); len(m) != 0 {
		t.Fatalf("collection.missed stored with platform full: %v", m)
	}

	last, _ := db.LastCommitted(bg, HealthStream)
	confirmStream(t, r, c, HealthStream, last)
	r.Prune(bg)
	ser := SERStream(relayID)
	b, err := normalize.EncodeState([]string{"sha256:" + strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Store(ser).SaveSourceCursor(bg, ser, b); err != nil { // the rows are new again
		t.Fatal(err)
	}
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" || rep.Events == 0 || sent != n+1 {
		t.Fatalf("read once platform has room: %+v", rep)
	}
	if missedAtSend != 1 {
		t.Fatalf("%d collection.missed stored when the read was sent, want 1", missedAtSend)
	}
	missed, types := missedRecords(t, r)
	if len(missed) != 1 {
		t.Fatalf("collection.missed: %v", missed)
	}
	m := missed[0]
	if m["missed"] != "2" || m["alarm"] != AlarmCollectorRefused || m["request_id"] != refused.RequestID || m["schedule"] != id {
		t.Fatalf("collection.missed details (X15, X17): %v", m)
	}
	at, err := time.Parse(time.RFC3339Nano, m["first_at"])
	if err != nil || at.Before(before) || at.After(after) {
		t.Fatalf("first_at %q is not the refused slot's time, %v to %v (X16)", m["first_at"], before, after)
	}
	run := -1
	for j, typ := range types {
		if typ == HealthCollectionRun {
			run = j
		}
	}
	if i := slices.Index(types, HealthCollectionMissed); i < 0 || run < i {
		t.Fatalf("health order: %v", types)
	}

	// A later series held on the same entry raises the alarm again (D4-37,
	// C6's H3 on #372).
	fill()
	s.c = refuse
	if rep := s.RunOnce(bg, 0); !rep.Sent || rep.Alarm != AlarmCollectorRefused {
		t.Fatalf("second refusal: %+v", rep)
	}
	if n := raised(); n != 2 {
		t.Fatalf("%d alarms after a second unwritten series, want 2", n)
	}
}
