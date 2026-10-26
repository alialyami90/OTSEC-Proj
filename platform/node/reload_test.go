package node

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"

	_ "modernc.org/sqlite"

	"otsec.local/otsec/contracts/audit"
	c5 "otsec.local/otsec/contracts/store"
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
