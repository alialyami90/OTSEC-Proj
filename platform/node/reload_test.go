package node

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
)

// holdDB opens database id of the store in dir with an exclusive-locking
// connection, so that every other open of it is busy until the returned
// release is called.
func holdDB(t *testing.T, dir string, id c5.DatabaseID) (release func()) {
	t.Helper()
	h, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(dir, string(id)+".db")))
	if err != nil {
		t.Fatal(err)
	}
	h.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA locking_mode=EXCLUSIVE", "BEGIN IMMEDIATE", "SELECT count(*) FROM meta", "COMMIT"} {
		if _, err := h.ExecContext(context.Background(), q); err != nil {
			h.Close()
			t.Fatalf("hold %s: %s: %v", id, q, err)
		}
	}
	done := false
	release = func() {
		if !done {
			done = true
			h.Close()
		}
	}
	t.Cleanup(release)
	return release
}

// C5 0.2 in the node (P3-A5): a database whose open was only busy at start
// is opened by a later Tick, with no restart. Until then every run is held;
// a retry that is busy again raises nothing new; the recovery is a
// store.mode_change in the audit stream; and runs go again only after the
// suspensions are rebuilt from the recovered audit stream and the halts
// read from the recovered quarantine streams. Each busy open waits out the
// store's busy_timeout, so this test takes about 15 s.
func TestBusyOpenRetriedAtTick(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out busy_timeout")
	}
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	newScheduler(t, r, suspendingCollector(t, false)).RunOnce(bg, 0) // suspends the asset
	r.Close()

	releaseAudit := holdDB(t, c.Store.Dir, AuditDB)
	releaseEvidence := holdDB(t, c.Store.Dir, EvidenceDB)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	for _, id := range []c5.DatabaseID{AuditDB, EvidenceDB} {
		if d := r.find(id); d.report.Mode != c5.ModeFailed || !d.report.OpenBusy() {
			t.Fatalf("%s at start: mode %s, busy %v", id, d.report.Mode, d.report.OpenBusy())
		}
	}
	col := suspendingCollector(t, false)
	s := newScheduler(t, r, col)
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectionDisabled || col.n() != 0 {
		t.Fatalf("run with the audit database failed: %+v, %d requests", rep, col.n())
	}
	openFailed := func() (n int) {
		for _, a := range st.Snapshot("x").Alarms {
			if a.Code == string(c5.AlarmOpenFailed) && a.Database == AuditDB {
				n++
			}
		}
		return n
	}
	if n := openFailed(); n != 1 {
		t.Fatalf("%d open-failed alarms for audit at start, want 1", n)
	}
	if h := st.Snapshot("x").RunsHeld; h != AlarmSuspensionsUnknown {
		t.Fatalf("runs held %q at start, want %s", h, AlarmSuspensionsUnknown)
	}

	releaseEvidence()
	r.Tick(bg) // evidence opens; audit is busy again
	if m := r.Mode(EvidenceDB); m != c5.ModeCollecting {
		t.Fatalf("evidence after a retry: %s", m)
	}
	if d := r.find(AuditDB); d.report.Mode != c5.ModeFailed || !d.report.OpenBusy() {
		t.Fatalf("audit still held: mode %s", d.report.Mode)
	}
	if n := openFailed(); n != 1 {
		t.Fatalf("%d open-failed alarms for audit after a busy retry, want 1", n)
	}
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectionDisabled || col.n() != 0 {
		t.Fatalf("run with the audit database still failed: %+v", rep)
	}

	releaseAudit()
	r.Tick(bg)
	if m := r.Mode(AuditDB); m != c5.ModeCollecting {
		t.Fatalf("audit after the holder let go: %s", m)
	}
	recs := auditRecords(t, r)
	if !slices.ContainsFunc(recs, func(rec *audit.Record) bool {
		return rec.Action == audit.ActionStoreModeChange && rec.ReasonCode == string(c5.ModeCollecting) && rec.Detail == "database audit: failed to collecting"
	}) {
		t.Fatal("no store.mode_change for the audit database's recovery")
	}
	// What the second start could not record is in the chain, in order and
	// before the recovery: its service.start and every first mode (A6 on
	// #147), and the evidence database's recovery while audit was busy.
	at := func(action audit.Action, detail string) int {
		return slices.IndexFunc(recs, func(rec *audit.Record) bool {
			return rec.Action == action && strings.HasPrefix(rec.Detail, detail)
		})
	}
	recovered := at(audit.ActionStoreModeChange, "database audit: failed to collecting")
	firstAuditFailed := at(audit.ActionStoreModeChange, "database audit: none to failed;")
	evidenceRecovered := at(audit.ActionStoreModeChange, "database evidence: failed to collecting")
	var starts []int
	for i, rec := range recs {
		if rec.Action == audit.ActionServiceStart {
			starts = append(starts, i)
		}
	}
	if len(starts) != 2 || firstAuditFailed < starts[0] || !(firstAuditFailed < starts[1] && starts[1] < evidenceRecovered && evidenceRecovered < recovered) {
		t.Fatalf("restart records out of the chain or out of order: starts %v, audit none to failed %d, evidence recovered %d, audit recovered %d", starts, firstAuditFailed, evidenceRecovered, recovered)
	}
	for i := starts[1]; i < recovered; i++ {
		if recs[i].Time.UTC > recs[i+1].Time.UTC {
			t.Fatalf("record %d (%s) is timed %s, after the next one at %s", i, recs[i].Action, recs[i].Time.UTC, recs[i+1].Time.UTC)
		}
	}
	if !slices.ContainsFunc(st.Snapshot("x").Alarms, func(a StatusAlarm) bool {
		return a.Code == AlarmAuditNotRecorded && strings.Contains(a.Detail, "kept, to be recorded")
	}) {
		t.Fatalf("no %s alarm for a kept record", AlarmAuditNotRecorded)
	}
	// The suspension recorded before the restart is rebuilt and enforced,
	// so the run is held for it, not for unknown suspensions or a halt.
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmAssetSuspended || col.n() != 0 {
		t.Fatalf("run after the retry: %+v, %d requests", rep, col.n())
	}
	if !slices.ContainsFunc(st.Snapshot("x").Alarms, func(a StatusAlarm) bool { return a.Code == AlarmSuspensionsRebuilt }) {
		t.Fatal("no asset-suspensions-rebuilt in status")
	}
	// The unknown-suspensions alarm stays in the history, but status no
	// longer shows it as current (A3 on #147).
	if h := st.Snapshot("x").RunsHeld; h != "" {
		t.Fatalf("runs still held %q after the rebuild", h)
	}
}

// A rebuild that fails once the audit database opens keeps every run
// held, as it would at start: here the checkpoint claims more of the
// audit stream than the stream holds.
func TestBusyOpenRetryKeepsUnknownSuspensionsHeld(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out busy_timeout")
	}
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	r.Close()
	if err := writeSuspensions(filepath.Join(c.Store.Dir, SuspensionsFileName), 1<<40, nil, nil, collectorState{}, nil); err != nil {
		t.Fatal(err)
	}
	release := holdDB(t, c.Store.Dir, AuditDB)
	r, _, _ = start(t, c, dir)
	defer r.Close()
	col := suspendingCollector(t, false)
	s := newScheduler(t, r, col)
	release()
	r.Tick(bg)
	if m := r.Mode(AuditDB); m != c5.ModeCollecting {
		t.Fatalf("audit after the holder let go: %s", m)
	}
	for i := 0; i < 2; i++ {
		if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectionDisabled || col.n() != 0 {
			t.Fatalf("run %d with unknown suspensions: %+v, %d requests", i, rep, col.n())
		}
	}
	if why := s.Halted(relayID); why != AlarmSuspensionsUnknown {
		t.Fatalf("halted: %q", why)
	}
	if h := s.rt.opt.Status.Snapshot("x").RunsHeld; h != AlarmSuspensionsUnknown {
		t.Fatalf("runs held %q, want %s", h, AlarmSuspensionsUnknown)
	}
}

// The halt the busy-open retry reads again (D2-15, A6 on #147): with the
// evidence database busy at start every asset is held as halted, because
// its quarantine cannot be read. Once a retry opens it, an asset whose
// quarantine holds an unauthorized-line record stays halted, and one whose
// quarantine holds only another kind runs again.
func TestBusyEvidenceRetryKeepsUnauthorizedHalt(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out busy_timeout")
	}
	for _, unauthorized := range []bool{true, false} {
		t.Run(map[bool]string{true: "unauthorized line", false: "other quarantine"}[unauthorized], func(t *testing.T) {
			c, dir := schedConfig(t, nil)
			r, _, _ := start(t, c, dir)
			reason := "result: does not decode"
			err := fmt.Errorf("%w: %w: %s", collectorclient.ErrOutcomeUnknown, collectorclient.ErrOutcomeQuarantined, reason)
			if unauthorized {
				reason = "result: line 7 is not permitted for sel.ser.read_all"
				err = fmt.Errorf("%w: %w: %w: %s", collectorclient.ErrOutcomeUnknown, collectorclient.ErrOutcomeQuarantined, collectorclient.ErrUnauthorizedLine, reason)
			}
			frame := []byte(`{"wire":"otsec.collectorwire/0.1","invocation_id":"` + okInvocation + `","result":{},"audit":[]}`)
			f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
				return collectorclient.Response{Reply: accepted(req, 1), Quarantine: &collectorclient.Quarantine{Raw: frame, Reason: reason, UnauthorizedLine: unauthorized}}, err
			}}
			if rep := newScheduler(t, r, f).RunOnce(bg, 0); rep.Outcome != "quarantined" {
				t.Fatalf("first run: %+v", rep)
			}
			r.Close()

			release := holdDB(t, c.Store.Dir, EvidenceDB)
			r, st, _ := start(t, c, dir)
			defer r.Close()
			f.answer = func(req *authz.CollectorRequest) (collectorclient.Response, error) {
				return collectorclient.Response{}, errors.New("collector not reachable")
			}
			s := newScheduler(t, r, f)
			if s.Halted(relayID) == "" {
				t.Fatal("not held as halted with its quarantine unreadable")
			}
			release()
			r.Tick(bg)
			if m := r.Mode(EvidenceDB); m != c5.ModeCollecting {
				t.Fatalf("evidence after a retry: %s", m)
			}
			s.RunOnce(bg, 0)
			if !unauthorized {
				if s.Halted(relayID) != "" || f.n() != 2 {
					t.Fatalf("other quarantine: halted %q, %d requests, want a run", s.Halted(relayID), f.n())
				}
				return
			}
			if s.Halted(relayID) == "" || f.n() != 1 {
				t.Fatalf("unauthorized line: halted %q, %d requests, want no run", s.Halted(relayID), f.n())
			}
			if !slices.ContainsFunc(st.Snapshot("x").Alarms, func(a StatusAlarm) bool {
				return a.Code == AlarmCollectionDisabled && a.Asset == relayID && strings.Contains(a.Detail, "does not permit")
			}) {
				t.Fatalf("no %s for the unauthorized line after the retry", AlarmCollectionDisabled)
			}
		})
	}
}

// Records kept while the audit database is busy are bounded: past
// MaxDeferredAudit each is dropped, and once a retry opens the database
// one storage.alarm record says how many were (A6 on #147).
func TestBusyAuditKeptRecordsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out busy_timeout")
	}
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	r.Close()
	release := holdDB(t, c.Store.Dir, AuditDB)
	r, _, _ = start(t, c, dir)
	defer r.Close()
	kept := len(r.deferred)
	for i := 0; i < MaxDeferredAudit; i++ {
		r.audit(bg, audit.ActionPolicyApply, audit.OutcomeInfo, "", fmt.Sprintf("test record %d", i))
	}
	dropped := kept
	release()
	r.Tick(bg)
	recs := auditRecords(t, r)
	var tests int
	for _, rec := range recs {
		if rec.Action == audit.ActionPolicyApply && strings.HasPrefix(rec.Detail, "test record ") {
			tests++
		}
	}
	if tests != MaxDeferredAudit-kept {
		t.Fatalf("%d test records committed, want %d", tests, MaxDeferredAudit-kept)
	}
	want := fmt.Sprintf("%d node records were not recorded", dropped)
	if !slices.ContainsFunc(recs, func(rec *audit.Record) bool {
		return rec.Action == audit.ActionStorageAlarm && strings.HasPrefix(rec.Detail, want)
	}) {
		t.Fatalf("no storage.alarm saying %q", want)
	}
	if len(r.deferred) != 0 || r.dropped != 0 {
		t.Fatalf("still kept: %d, dropped %d", len(r.deferred), r.dropped)
	}
}

// When a retry opens the audit database, the kept records and the
// recovery's store.mode_change commit together, before any record another
// goroutine writes once the database is open: a record made after the
// release never lands among them (D3-6; B6 on #249, where a scheduled
// run's collector.request did).
func TestKeptRecordsCommitBeforeOthers(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out busy_timeout")
	}
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	r.Close()
	release := holdDB(t, c.Store.Dir, AuditDB)
	r, _, _ = start(t, c, dir)
	defer r.Close()
	stop := make(chan struct{})
	done := make(chan struct{})
	// The writer says when it has made its first record of each kind, so
	// the test waits on that and not on a sleep (B6 on #262).
	sawKept, sawLive := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var kept, live bool
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			// "live": the open Log was visible before this record was made.
			label := "kept"
			if r.Log(AuditStream) != nil {
				label = "live"
			}
			r.audit(bg, audit.ActionPolicyApply, audit.OutcomeInfo, "", fmt.Sprintf("%s %d", label, i))
			switch {
			case label == "kept" && !kept:
				kept = true
				close(sawKept)
			case label == "live" && !live:
				live = true
				close(sawLive)
			}
		}
	}()
	wait := func(ch chan struct{}, what string) {
		select {
		case <-ch:
		case <-time.After(time.Minute):
			close(stop)
			<-done
			t.Fatalf("no %s record after a minute", what)
		}
	}
	wait(sawKept, "kept")
	release()
	r.Tick(bg)
	wait(sawLive, "live")
	close(stop)
	<-done
	recs := auditRecords(t, r)
	rec := slices.IndexFunc(recs, func(x *audit.Record) bool {
		return x.Action == audit.ActionStoreModeChange && x.Detail == "database audit: failed to collecting"
	})
	if rec < 0 {
		t.Fatal("no recovery record")
	}
	live, kept := 0, 0
	for i, x := range recs {
		switch {
		case i < rec && strings.HasPrefix(x.Detail, "live "):
			t.Fatalf("record %d (%q), made once the audit Log was visible, sits before the recovery at %d, among the kept records",
				i, x.Detail, rec)
		case i < rec && strings.HasPrefix(x.Detail, "kept "):
			kept++
		case i > rec && strings.HasPrefix(x.Detail, "live "):
			live++
		}
	}
	if kept == 0 || live == 0 {
		t.Fatalf("%d kept and %d live records: the test did not race", kept, live)
	}
}
