package node

import (
	"context"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
	c5 "otsec.local/otsec/contracts/store"
)

// F-028 (brief P4-4-DO): a store.mode_change record's reason_code is the
// new C5 mode with "-" written as "_", so a database that goes drain-only
// is recorded as drain_only, which C8's reason_code pattern accepts. Each
// of the three writers has its own test. Each test's control is the
// mapping removed from its writer (string(mc.To) back in place of
// modeReason(mc.To)): the record then fails audit.ValidatePending, no
// record is written, and the test fails. Desk only: no device.

// drainOnlyRecord finds the store.mode_change record whose detail starts
// with prefix, and checks that it carries drain_only, that it passes C8's
// validation as committed, and that no store-commit-failed was raised.
func drainOnlyRecord(t *testing.T, r *Runtime, st *Status, prefix string) {
	t.Helper()
	var found *audit.Record
	for _, rec := range auditRecords(t, r) { // ParseRecord validates each
		if rec.Action == audit.ActionStoreModeChange && strings.HasPrefix(rec.Detail, prefix) {
			found = rec
		}
	}
	if found == nil {
		t.Fatalf("no store.mode_change record %q; commit-failed alarms %d", prefix, countAlarms(st, string(c5.AlarmCommitFailed)))
	}
	if found.ReasonCode != "drain_only" {
		t.Fatalf("reason_code %q, want drain_only", found.ReasonCode)
	}
	if n := countAlarms(st, string(c5.AlarmCommitFailed)); n != 0 {
		t.Fatalf("%d store-commit-failed alarms", n)
	}
}

// drainOnlyHealth checks that the C4 health event of db's change keeps the
// C5 spelling: "to" is drain-only while the record's reason_code is
// drain_only (C8 0.13's and C5's sentences; D3's N1 on #692). Control: "to"
// mapped as reason_code is, in modeHealth or in recordMode.
func drainOnlyHealth(t *testing.T, r *Runtime, db c5.DatabaseID) {
	t.Helper()
	var to []string
	for _, h := range healthOf(t, r, c5.HealthModeChanged) {
		if h.Details["database"] == string(db) {
			to = append(to, h.Details["to"])
		}
	}
	if len(to) == 0 || to[len(to)-1] != string(c5.ModeDrainOnly) {
		t.Fatalf("%s's mode-changed health events have to %q; want the last drain-only", db, to)
	}
}

// modeChanged (Start's recordStart and Tick's retries): the evidence
// database's change to drain-only is recorded as drain_only.
func TestModeChangedRecordsDrainOnly(t *testing.T) {
	c, dir := runtimeConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	r.modeChanged(bg, r.find(EvidenceDB), c5.ModeChange{From: c5.ModeCollecting, To: c5.ModeDrainOnly, At: r.opt.Now()})
	drainOnlyRecord(t, r, st, "database evidence: collecting to drain-only")
	drainOnlyHealth(t, r, EvidenceDB)
}

// commitDeferred (Tick's retry that opens a busy audit database). It is
// called directly: it commits only while the audit database collects, and
// the change it records is the audit database's own, so on main its
// reason is always collecting. The test holds the writer to the mapping
// for any mode it is given.
func TestCommitDeferredRecordsDrainOnly(t *testing.T) {
	c, dir := runtimeConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	if !r.commitDeferred(bg, r.find(AuditDB), c5.ModeChange{From: c5.ModeFailed, To: c5.ModeDrainOnly, At: r.opt.Now()}, true) {
		t.Fatal("commitDeferred reports the change not recorded")
	}
	drainOnlyRecord(t, r, st, "database audit: failed to drain-only")
}

// The sensor manager's recordMode, through sensorModeChanged at the first
// step: the network database opens drain-only, and its first mode is
// recorded as drain_only.
func TestSensorRecordModeRecordsDrainOnly(t *testing.T) {
	c, dir := holdConfig(t)
	r, st := startSeams(t, c, dir, SensorSeams{
		Startup: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
			rep := c5.RunStartup(ctx, env, p)
			if rep.Mode == c5.ModeCollecting {
				rep.Mode = c5.ModeDrainOnly
			}
			return rep
		}})
	defer r.Close()
	if m := r.Mode(NetworkDB); m != c5.ModeDrainOnly {
		t.Fatalf("network database %s", m)
	}
	drainOnlyRecord(t, r, st, "database "+string(NetworkDB)+": none to drain-only")
	drainOnlyHealth(t, r, NetworkDB)
}
