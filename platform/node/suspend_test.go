package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// authRejected is the C2 example of a rejected password: its code
// suspends the asset (auth-failed).
const authRejected = "../../contracts/adapter/testdata/results/valid/failed.auth_rejected.json"

// suspendingCollector accepts every run and answers with the
// failed.auth_rejected example, as a checked outcome or, with quarantine,
// as an outcome that failed a check.
func suspendingCollector(t *testing.T, quarantine bool) *fakeCollector {
	t.Helper()
	raw := readFile(t, authRejected)
	res, err := adapter.DecodeResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	seq := uint64(0)
	return &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		seq++
		rep := accepted(req, seq)
		// Each run gets its own invocation ID, as the collector gives.
		rep.InvocationID = fmt.Sprintf("inv-run-%d", seq)
		res := res
		res.InvocationID = rep.InvocationID
		if quarantine {
			return collectorclient.Response{Reply: rep, Quarantine: &collectorclient.Quarantine{Raw: raw, Reason: "test: a check failed", ResultJSON: raw}},
				collectorclient.ErrOutcomeQuarantined
		}
		return collectorclient.Response{Reply: rep, Outcome: &collectorclient.Outcome{InvocationID: rep.InvocationID, Result: res, ResultJSON: raw}}, nil
	}}
}

// suspendConfig is a node whose admin_dir is the test's tls_dir, which
// lockTLS gives the protected-file rule clear-suspension.json is read
// under (D2-12's rule, the same as an admin file's).
func suspendConfig(t *testing.T) (*Config, string, *nodeconfigtest.Config) {
	t.Helper()
	var nc *nodeconfigtest.Config
	c, dir := schedConfig(t, func(n *nodeconfigtest.Config) {
		n.AdminDir = n.TLSDir
		nc = n
	})
	if err := store.CreateDir(nc.TLSDir, ""); err != nil {
		t.Fatal(err)
	}
	lockTLS(t, nc)
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	return c, dir, nc
}

// writeClear writes clear-suspension.json in admin_dir and locks it.
func writeClear(t *testing.T, nc *nodeconfigtest.Config, assetID, ref string) {
	t.Helper()
	nc.UnlockTLS()
	b, _ := json.Marshal(map[string]string{"schema": ClearSuspensionSchema, "asset_id": assetID, "ref": ref})
	if err := os.WriteFile(filepath.Join(nc.AdminDir, ClearSuspensionFileName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	lockTLS(t, nc)
}

func suspensionRecords(t *testing.T, r *Runtime) (suspends, clears []*audit.Record) {
	t.Helper()
	for _, rec := range auditRecords(t, r) {
		switch rec.Action {
		case audit.ActionAssetSuspend:
			suspends = append(suspends, rec)
		case audit.ActionAssetSuspensionClear:
			clears = append(clears, rec)
		}
	}
	return suspends, clears
}

// An outcome code that suspends (failed.auth_rejected) stops the asset's
// runs, is recorded as asset.suspend and in the checkpoint, and shows in
// status, whether the outcome passed its checks or was quarantined (A1:
// a result that fails validation still suspends).
func TestOutcomeCodeSuspends(t *testing.T) {
	for _, quarantined := range []bool{false, true} {
		c, dir := schedConfig(t, nil)
		r, st, _ := start(t, c, dir)
		col := suspendingCollector(t, quarantined)
		s := newScheduler(t, r, col)
		s.RunOnce(bg, 0)
		if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmAssetSuspended || col.n() != 1 {
			t.Fatalf("quarantined %v: second run %+v after %d requests", quarantined, rep, col.n())
		}
		ref := "inv-run-1"
		want := asset.Suspension{Reason: asset.SuspendAuthFailed, Ref: ref}
		got := s.Suspensions()[relayID]
		if got.Reason != want.Reason || got.Ref != want.Ref || !asset.ValidTime(got.Since) {
			t.Fatalf("quarantined %v: suspension %+v", quarantined, got)
		}
		sus, _ := suspensionRecords(t, r)
		if len(sus) != 1 || sus[0].Target.AssetID != relayID || sus[0].CorrelationID != ref ||
			sus[0].Suspension == nil || *sus[0].Suspension != (audit.Suspension{Reason: asset.SuspendAuthFailed, Code: "failed.auth_rejected"}) || sus[0].Actor.Type != authz.PrincipalNode {
			t.Fatalf("quarantined %v: asset.suspend records %+v", quarantined, sus)
		}
		f, err := readSuspensions(filepath.Join(c.Store.Dir, SuspensionsFileName))
		if err != nil || f.Suspensions[relayID].Ref != ref {
			t.Fatalf("quarantined %v: checkpoint %+v: %v", quarantined, f, err)
		}
		if snap := st.Snapshot("site-a-node1"); snap.Suspensions[relayID].Ref != ref {
			t.Fatalf("quarantined %v: status suspensions %+v", quarantined, snap.Suspensions)
		}
		r.Close()
	}
}

// A code that suspends nothing (the ok.json read) leaves the asset
// collecting.
func TestOKOutcomeDoesNotSuspend(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	s.RunOnce(bg, 0)
	if rep := s.RunOnce(bg, 0); rep.Alarm == AlarmAssetSuspended || len(s.Suspensions()) != 0 {
		t.Fatalf("second run %+v; suspensions %v", rep, s.Suspensions())
	}
}

// A suspension survives a restart from the checkpoint; with the checkpoint
// removed or corrupt, it is rebuilt from the audit stream.
func TestSuspensionSurvivesRestart(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	s := newScheduler(t, r, suspendingCollector(t, false))
	s.RunOnce(bg, 0)
	r.Close()
	path := filepath.Join(c.Store.Dir, SuspensionsFileName)
	for name, damage := range map[string]func(){
		"checkpoint":         func() {},
		"no checkpoint":      func() { os.Remove(path) },
		"corrupt checkpoint": func() { os.WriteFile(path, []byte("{not json"), 0o600) },
	} {
		damage()
		r, _, _ := start(t, c, dir)
		col := suspendingCollector(t, false)
		s := newScheduler(t, r, col)
		if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmAssetSuspended || col.n() != 0 {
			t.Errorf("%s: run %+v, %d requests", name, rep, col.n())
		}
		r.Close()
	}
}

// When the suspensions cannot be rebuilt, nothing is collected from any
// asset (A1, D2-15). A checkpoint that claims more of the audit stream
// than the stream holds is one such case.
func TestUnknownSuspensionsHoldEverything(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	if err := writeSuspensions(filepath.Join(c.Store.Dir, SuspensionsFileName), 1<<40, nil, nil, collectorState{}); err != nil {
		t.Fatal(err)
	}
	col := suspendingCollector(t, false)
	s := newScheduler(t, r, col)
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectionDisabled || col.n() != 0 {
		t.Fatalf("run %+v, %d requests", rep, col.n())
	}
	if why := s.Halted(relayID); why != AlarmSuspensionsUnknown {
		t.Fatalf("halted: %q", why)
	}
}

// A suspension whose asset.suspend record is not in the audit stream holds
// all collection on the node until it is, whether or not the checkpoint
// was written (A1, D2-15 at 0ef6641).
func TestUnauditedSuspensionHoldsTheNode(t *testing.T) {
	for _, fileWritable := range []bool{true, false} {
		c, dir := schedConfig(t, nil)
		r, _, _ := start(t, c, dir)
		col := suspendingCollector(t, false)
		s := newScheduler(t, r, col)
		path := filepath.Join(c.Store.Dir, SuspensionsFileName)
		if !fileWritable {
			// The checkpoint cannot be renamed into place over a directory.
			os.Remove(path)
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		// The audit database is closed under the scheduler.
		db := r.find(AuditDB)
		r.state.Lock()
		log := db.log
		db.log = nil
		r.state.Unlock()
		s.suspend(bg, relayID, "inv-test", "failed.auth_rejected")
		if why := s.Halted("any-other-asset"); why != AlarmSuspensionNotDurable {
			t.Fatalf("file writable %v: node not held: %q", fileWritable, why)
		}
		if f, err := readSuspensions(path); fileWritable && (err != nil || f.Suspensions[relayID].Ref != "inv-test") {
			t.Fatalf("checkpoint %+v: %v", f, err)
		}
		if rep := s.RunOnce(bg, 0); col.n() != 0 {
			t.Fatalf("file writable %v: run %+v sent %d requests", fileWritable, rep, col.n())
		}
		// Still held after the run's own settle, which wrote the checkpoint
		// if it could.
		if why := s.Halted("any-other-asset"); why != AlarmSuspensionNotDurable {
			t.Fatalf("file writable %v: hold lifted without the audit record: %q", fileWritable, why)
		}
		// The audit write succeeds again: the hold lifts, and the
		// suspension is in both places.
		r.state.Lock()
		db.log = log
		r.state.Unlock()
		os.Remove(path)
		s.settle(bg)
		if why := s.Halted("any-other-asset"); why != "" {
			t.Fatalf("file writable %v: node still held: %q", fileWritable, why)
		}
		if sus, _ := suspensionRecords(t, r); len(sus) != 1 || sus[0].CorrelationID != "inv-test" {
			t.Fatalf("asset.suspend records %+v", sus)
		}
		if f, err := readSuspensions(path); err != nil || f.Suspensions[relayID].Ref != "inv-test" {
			t.Fatalf("checkpoint %+v: %v", f, err)
		}
		r.Close()
	}
}

// Pruning never passes the checkpoint's through_seq (A1, D2-15 at
// 0ef6641): with a forwarder that confirmed the whole audit stream, the
// boundary stays at the checkpoint while the checkpoint is behind, and
// follows it once it is written.
func TestPruneStopsAtCheckpoint(t *testing.T) {
	fwd := c5.Consumer{ID: "fwd", Stream: AuditStream, Delivery: c5.Required}
	if got := pruneConsumers(nil); len(got) != 0 {
		t.Fatalf("no audit consumer: %+v", got)
	}
	if got := pruneConsumers([]c5.Consumer{{ID: "be", Stream: AuditStream, Delivery: c5.BestEffort, ReplayWindow: time.Hour}}); len(got) != 1 {
		t.Fatalf("best-effort only: %+v", got)
	}
	consumers := pruneConsumers([]c5.Consumer{fwd})
	if len(consumers) != 2 || consumers[1].ID != SuspensionConsumer {
		t.Fatalf("consumers %+v", consumers)
	}
	// A node whose audit stream is forwarded holds pruning at its
	// checkpoint from the first startup prune.
	ac, adir := schedConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddRELPTarget("central", "127.0.0.1", 2514, "test-ca", "test-client", "test/durable-ack", true)
	})
	ar, _, _ := start(t, ac, adir)
	var found bool
	for _, x := range ar.find(AuditDB).policy.Consumers {
		found = found || x.ID == SuspensionConsumer && x.Stream == AuditStream && x.Delivery == c5.Required
	}
	ar.Close()
	if !found {
		t.Fatal("the audit database's startup policy has no suspension consumer")
	}
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	s := newScheduler(t, r, suspendingCollector(t, false))
	s.RunOnce(bg, 0)
	boundary := func() (c5.Seq, c5.Seq) {
		db := r.Store(AuditStream)
		t.Helper()
		last, err := db.LastCommitted(bg, AuditStream)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.SaveCursor(bg, c5.Cursor{Consumer: fwd.ID, Stream: AuditStream, Through: last}); err != nil {
			t.Fatal(err)
		}
		b, err := c5.ComputeBoundary(bg, db, db, consumers, AuditStream, c5.ClassAudit, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return b.Through(), last
	}
	if b, last := boundary(); b != last || uint64(b) != s.checkpointSeq() {
		t.Fatalf("checkpoint current: boundary %d, last %d, checkpoint %d", b, last, s.checkpointSeq())
	}
	held := s.checkpointSeq()
	path := filepath.Join(c.Store.Dir, SuspensionsFileName)
	os.Remove(path)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	s.suspend(bg, "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b", "inv-other", "failed.auth_rejected")
	if b, last := boundary(); uint64(b) != held || b >= last {
		t.Fatalf("checkpoint behind: boundary %d, last %d, checkpoint %d", b, last, held)
	}
	os.Remove(path)
	s.settle(bg)
	if b, last := boundary(); b != last || uint64(b) != s.checkpointSeq() {
		t.Fatalf("checkpoint written: boundary %d, last %d, checkpoint %d", b, last, s.checkpointSeq())
	}
	// Behind again at shutdown: the next start's rebuild writes the
	// checkpoint and moves the cursor with it.
	os.Remove(path)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	s.suspend(bg, "7a2b3c4d-5e6f-4a70-8b9c-0d1e2f3a4b5c", "inv-third", "failed.auth_rejected")
	r.Close()
	os.Remove(path)
	r, _, _ = start(t, c, dir)
	defer r.Close()
	s = newScheduler(t, r, suspendingCollector(t, false))
	if b, last := boundary(); b != last || uint64(b) != s.checkpointSeq() {
		t.Fatalf("after restart: boundary %d, last %d, checkpoint %d", b, last, s.checkpointSeq())
	}
}

// An administrator's clear-suspension.json clears exactly one suspension:
// the asset and ref must match, asset.suspension_clear is in the audit
// stream before the asset's next collector.request, and the clear holds
// across a restart. A mismatched or stale file changes nothing.
func TestClearSuspension(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	col := suspendingCollector(t, false)
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0)
	ref := s.Suspensions()[relayID].Ref

	writeClear(t, nc, relayID, "inv-not-this-one")
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmAssetSuspended || col.n() != 1 {
		t.Fatalf("mismatched clear: run %+v, %d requests", rep, col.n())
	}
	refused := func() int {
		n := 0
		for _, a := range st.Snapshot("site-a-node1").Alarms {
			if a.Code == AlarmSuspensionClearRefused {
				n++
			}
		}
		return n
	}
	s.RunOnce(bg, 0)
	if refused() != 1 {
		t.Fatalf("%d clear-refused alarms for one mismatched file", refused())
	}

	writeClear(t, nc, relayID, ref)
	if rep := s.RunOnce(bg, 0); rep.Alarm == AlarmAssetSuspended || col.n() != 2 {
		t.Fatalf("matching clear: run %+v, %d requests", rep, col.n())
	}
	// The run after the clear fails the same way, so the asset is
	// suspended again under the new run's ref; the clear came first in the
	// chain.
	recs := auditRecords(t, r)
	clearAt, requestAt := -1, -1
	for i, rec := range recs {
		switch {
		case rec.Action == audit.ActionAssetSuspensionClear:
			clearAt = i
		case rec.Action == audit.ActionCollectorRequest && clearAt >= 0 && requestAt < 0:
			requestAt = i
		}
	}
	if clearAt < 0 || requestAt < clearAt {
		t.Fatalf("asset.suspension_clear at %d, next collector.request at %d", clearAt, requestAt)
	}
	if _, clears := suspensionRecords(t, r); len(clears) != 1 || clears[0].CorrelationID != ref || clears[0].Target.AssetID != relayID {
		t.Fatalf("asset.suspension_clear records %+v", clears)
	}

	second := s.Suspensions()[relayID].Ref
	if second == "" || second == ref {
		t.Fatalf("suspension after the clear: %q", second)
	}
	// The file still names the cleared ref, so it does not clear the new
	// suspension, and after a restart (suspend, clear, suspend in the
	// chain) the new one stands.
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmAssetSuspended || col.n() != 2 {
		t.Fatalf("stale clear: run %+v, %d requests", rep, col.n())
	}
	r.Close()
	os.Remove(filepath.Join(c.Store.Dir, SuspensionsFileName)) // rebuild from the chain
	r, _, _ = start(t, c, dir)
	defer r.Close()
	s = newScheduler(t, r, suspendingCollector(t, false))
	if got := s.Suspensions()[relayID].Ref; got != second {
		t.Fatalf("after restart: suspension %q, want %q", got, second)
	}
}

// A clear for an asset with no suspension, or a file that is not a clear,
// changes nothing and is raised once.
func TestBadClearFileChangesNothing(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	for _, body := range []string{
		`{"schema":"` + ClearSuspensionSchema + `","asset_id":"` + relayID + `","ref":"inv-x"}`,
		`{"schema":"` + ClearSuspensionSchema + `","asset_id":"` + relayID + `","ref":"inv-x","extra":1}`,
		`not json`,
	} {
		nc.UnlockTLS()
		os.WriteFile(filepath.Join(nc.AdminDir, ClearSuspensionFileName), []byte(body), 0o600)
		lockTLS(t, nc)
		s.RunOnce(bg, 0)
		s.RunOnce(bg, 0)
	}
	n := 0
	for _, a := range st.Snapshot("site-a-node1").Alarms {
		if a.Code == AlarmSuspensionClearRefused {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("%d clear-refused alarms for three bad files", n)
	}
	if _, clears := suspensionRecords(t, r); len(clears) != 0 {
		t.Fatalf("clear records %+v", clears)
	}
}

// strangerSID is a service SID that is not in AdminReaders.
const strangerSID = "S-1-5-80-1111111111-2222222222-3333333333-4000000000-555555555"

// writeShared writes name in admin_dir and locks the directory as the
// installer lays out OTSEC\config\admin, with reader as the other
// service's read entry (nodeconfigtest.ShareTLS). Like lockTLS, a
// non-elevated Windows run skips, except under GitHub Actions or with
// OTSEC_REQUIRE_ELEVATED=1.
func writeShared(t *testing.T, nc *nodeconfigtest.Config, name string, body []byte, reader string) {
	t.Helper()
	nc.UnlockTLS()
	if err := os.WriteFile(filepath.Join(nc.AdminDir, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := nc.ShareTLS(reader); errors.Is(err, nodeconfigtest.ErrNeedsElevation) {
		if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("OTSEC_REQUIRE_ELEVATED") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
}

// admin_dir as the installer lays it out, shared with the collector (A3
// #117): a directory and file the collector may also read are accepted,
// and on Windows a read entry for a service not in AdminReaders is
// refused, as it is by the collector.
func TestAdminDirSharedWithCollector(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := suspendingCollector(t, false)
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0)
	ref := s.Suspensions()[relayID].Ref
	b, _ := json.Marshal(map[string]string{"schema": ClearSuspensionSchema, "asset_id": relayID, "ref": ref})
	share := func(reader string) { t.Helper(); writeShared(t, nc, ClearSuspensionFileName, b, reader) }
	if runtime.GOOS == "windows" {
		share(strangerSID)
		if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmAssetSuspended {
			t.Fatalf("a reader not in AdminReaders: run %+v", rep)
		}
		if !slices.ContainsFunc(st.Snapshot("site-a-node1").Alarms, func(a StatusAlarm) bool { return a.Code == AlarmSuspensionClearRefused }) {
			t.Fatal("no clear-refused alarm for a reader not in AdminReaders")
		}
	}
	share(collectorwire.ServiceSID(collectorwire.CollectorService))
	if rep := s.RunOnce(bg, 0); rep.Alarm == AlarmAssetSuspended {
		t.Fatalf("shared admin_dir: run %+v", rep)
	}
	if _, clears := suspensionRecords(t, r); len(clears) != 1 || clears[0].CorrelationID != ref {
		t.Fatalf("clear records %+v", clears)
	}
}

// clear-suspension.json is decoded as strictly as the collector decodes
// it (A3 #117): a key in another case, a duplicate key or a value after
// the object clears nothing, even when it names the held suspension, so
// the node never clears what the collector would refuse.
func TestClearFileDecodedStrictly(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	col := suspendingCollector(t, false)
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0)
	ref := s.Suspensions()[relayID].Ref
	head := `{"schema":"` + ClearSuspensionSchema + `",`
	for name, body := range map[string]string{
		"key case":  head + `"ASSET_ID":"` + relayID + `","ref":"` + ref + `"}`,
		"duplicate": head + `"asset_id":"other","asset_id":"` + relayID + `","ref":"` + ref + `"}`,
		"trailing":  head + `"asset_id":"` + relayID + `","ref":"` + ref + `"}{}`,
	} {
		nc.UnlockTLS()
		os.WriteFile(filepath.Join(nc.AdminDir, ClearSuspensionFileName), []byte(body), 0o600)
		lockTLS(t, nc)
		if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmAssetSuspended {
			t.Fatalf("%s: run %+v", name, rep)
		}
	}
	if _, clears := suspensionRecords(t, r); len(clears) != 0 {
		t.Fatalf("clear records %+v", clears)
	}
}

// A clear of a suspension whose asset.suspend is not yet in the audit
// stream waits until it is (A6's probe on #107). Written first, the clear
// would name a suspension the chain does not hold, and the node's next
// settle would hold every asset as unknown, for good.
func TestClearOfUnauditedSuspensionWaits(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	s := newScheduler(t, r, suspendingCollector(t, false))
	db := r.find(AuditDB)
	r.state.Lock()
	log := db.log
	db.log = nil
	r.state.Unlock()
	s.suspend(bg, relayID, "inv-test", "failed.auth_rejected")
	r.state.Lock()
	db.log = log
	r.state.Unlock()

	// The audit stream is back, but no settle has written the suspension
	// yet when the clear is read.
	writeClear(t, nc, relayID, "inv-test")
	s.checkClear(bg)
	if sus, clears := suspensionRecords(t, r); len(sus) != 0 || len(clears) != 0 {
		t.Fatalf("before the suspension is written: suspends %+v, clears %+v", sus, clears)
	}
	if !s.suspended(relayID) {
		t.Fatal("cleared before the suspension was in the audit stream")
	}
	refused := 0
	for _, a := range st.Snapshot("site-a-node1").Alarms {
		if a.Code == AlarmSuspensionClearRefused && a.Asset == relayID {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("%d clear-refused alarms for the waiting clear", refused)
	}

	s.settle(bg)
	if why := s.Halted("any-other-asset"); why != "" {
		t.Fatalf("node held after the suspension was written: %q", why)
	}
	s.checkClear(bg)
	if why := s.Halted("any-other-asset"); why != "" {
		t.Fatalf("node held after the clear: %q", why)
	}
	if s.suspended(relayID) {
		t.Fatal("still suspended once the clear could apply")
	}
	suspendAt, clearAt := -1, -1
	for i, rec := range auditRecords(t, r) {
		switch rec.Action {
		case audit.ActionAssetSuspend:
			suspendAt = i
		case audit.ActionAssetSuspensionClear:
			clearAt = i
		}
	}
	if suspendAt < 0 || clearAt < suspendAt {
		t.Fatalf("asset.suspend at %d, asset.suspension_clear at %d", suspendAt, clearAt)
	}
}

// A start whose checkpoint is behind audit records already pruned cannot
// rebuild the suspensions those records hold, so it holds every asset and
// sends nothing (A6 on #107). Here the checkpoint is lost after a prune
// that its cursor allowed, and the asset's suspension is only in the
// pruned part of the stream.
func TestPrunedPastCheckpointHoldsAtLoad(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	s := newScheduler(t, r, suspendingCollector(t, false))
	s.RunOnce(bg, 0)
	if !s.suspended(relayID) {
		t.Fatal("not suspended")
	}
	fwd := c5.Consumer{ID: "fwd", Stream: AuditStream, Delivery: c5.Required}
	db := r.Store(AuditStream)
	last, err := db.LastCommitted(bg, AuditStream)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveCursor(bg, c5.Cursor{Consumer: fwd.ID, Stream: AuditStream, Through: last}); err != nil {
		t.Fatal(err)
	}
	b, err := c5.ComputeBoundary(bg, db, db, pruneConsumers([]c5.Consumer{fwd}), AuditStream, c5.ClassAudit, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n, err := db.PruneStep(bg, b, 1000); err != nil || n == 0 {
		t.Fatalf("pruned %d: %v", n, err)
	}
	s.suspend(bg, "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b", "inv-other", "failed.auth_rejected")
	r.Close()
	os.Remove(filepath.Join(c.Store.Dir, SuspensionsFileName))

	r, _, _ = start(t, c, dir)
	defer r.Close()
	col := suspendingCollector(t, false)
	s = newScheduler(t, r, col)
	if rep := s.RunOnce(bg, 0); col.n() != 0 || rep.Alarm != AlarmCollectionDisabled {
		t.Fatalf("run %+v sent %d requests", rep, col.n())
	}
	if why := s.Halted("any-other-asset"); why != AlarmSuspensionsUnknown {
		t.Fatalf("node not held as unknown: %q", why)
	}
}

// clear-suspension.json is read only from an admin_dir the node cannot
// write and that is not a link (A3 on #107): otherwise the node, or
// another account, could have written the file. A matching clear in such a
// directory changes nothing and is raised once.
func TestClearNeedsProtectedAdminDir(t *testing.T) {
	for _, name := range []string{"writable", "link"} {
		t.Run(name, func(t *testing.T) {
			c, dir, nc := suspendConfig(t)
			r, st, _ := start(t, c, dir)
			defer r.Close()
			s := newScheduler(t, r, suspendingCollector(t, false))
			s.RunOnce(bg, 0)
			writeClear(t, nc, relayID, s.Suspensions()[relayID].Ref)
			switch name {
			case "writable":
				if err := nc.LoosenTLS(""); err != nil {
					t.Fatal(err)
				}
			case "link":
				link := filepath.Join(t.TempDir(), "admin-link")
				if err := os.Symlink(nc.AdminDir, link); err != nil {
					t.Skip("cannot create a link here: ", err)
				}
				s.rt.cfg.AdminDir = link
			}
			s.RunOnce(bg, 0)
			s.RunOnce(bg, 0)
			if !s.suspended(relayID) {
				t.Fatal("cleared from an unprotected admin_dir")
			}
			if _, clears := suspensionRecords(t, r); len(clears) != 0 {
				t.Fatalf("asset.suspension_clear records %+v", clears)
			}
			n := 0
			for _, a := range st.Snapshot("site-a-node1").Alarms {
				if a.Code == AlarmSuspensionClearRefused {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("%d clear-refused alarms", n)
			}
		})
	}
}

// A cleared suspension stays cleared across a restart, from the checkpoint
// or, without one, from the chain: the rebuild applies the clear after the
// suspension, in chain order (A1, D2-15).
func TestClearSurvivesRestart(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	s := newScheduler(t, r, suspendingCollector(t, false))
	s.RunOnce(bg, 0)
	writeClear(t, nc, relayID, s.Suspensions()[relayID].Ref)
	// From here the collector refuses every run, so nothing suspends again.
	s.c = &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
			Refusal: &authz.Refusal{Code: authz.RefuseRateLimited, Detail: "test"}, CollectorSeq: 99}}, nil
	}}
	s.RunOnce(bg, 0)
	if len(s.Suspensions()) != 0 {
		t.Fatalf("suspensions after the clear: %v", s.Suspensions())
	}
	r.Close()
	path := filepath.Join(c.Store.Dir, SuspensionsFileName)
	for name, damage := range map[string]func(){
		"checkpoint":    func() {},
		"no checkpoint": func() { os.Remove(path) },
	} {
		damage()
		r, _, _ := start(t, c, dir)
		s := newScheduler(t, r, suspendingCollector(t, false))
		if len(s.Suspensions()) != 0 {
			t.Errorf("%s: suspensions after restart: %v", name, s.Suspensions())
		}
		r.Close()
	}
}

// A suspension whose asset.suspend record was not written when the node
// stopped is in the checkpoint as unaudited: the next start holds the node,
// writes the record once the audit stream accepts it, and then resumes.
func TestUnauditedSuspensionSurvivesRestart(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	s := newScheduler(t, r, suspendingCollector(t, false))
	db := r.find(AuditDB)
	r.state.Lock()
	log := db.log
	db.log = nil
	r.state.Unlock()
	s.suspend(bg, relayID, "inv-test", "failed.auth_rejected")
	f, err := readSuspensions(filepath.Join(c.Store.Dir, SuspensionsFileName))
	if err != nil || len(f.Unaudited) != 1 || f.Unaudited[0] != (pendingSuspension{relayID, "inv-test", "failed.auth_rejected"}) {
		t.Fatalf("checkpoint %+v: %v", f, err)
	}
	r.state.Lock()
	db.log = log
	r.state.Unlock()
	r.Close()

	r, _, _ = start(t, c, dir)
	defer r.Close()
	s = newScheduler(t, r, suspendingCollector(t, false))
	if why := s.Halted("any-other-asset"); why != "" {
		t.Fatalf("held after the record was written at start: %q", why)
	}
	if sus, _ := suspensionRecords(t, r); len(sus) != 1 || sus[0].CorrelationID != "inv-test" || sus[0].Suspension.Code != "failed.auth_rejected" {
		t.Fatalf("asset.suspend records %+v", sus)
	}
	if f, err := readSuspensions(filepath.Join(c.Store.Dir, SuspensionsFileName)); err != nil || len(f.Unaudited) != 0 || f.Suspensions[relayID].Ref != "inv-test" {
		t.Fatalf("checkpoint after start %+v: %v", f, err)
	}
}

// A suspension whose append reported an error but was committed is found
// in the stream and not written again: C8 0.2 breaks the chain on a
// duplicate suspend.
func TestCommittedSuspensionNotWrittenTwice(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	s := newScheduler(t, r, suspendingCollector(t, false))
	sp := asset.Suspension{Reason: asset.SuspendAuthFailed, Since: "2026-10-25T06:00:00Z", Ref: "inv-test"}
	if err := s.commitSuspensionRecord(bg, audit.ActionAssetSuspend, relayID, sp, "failed.auth_rejected", "test"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.susp[relayID] = sp
	s.unaudited = append(s.unaudited, unaudited{relayID, sp, "failed.auth_rejected"})
	s.mu.Unlock()
	s.settle(bg)
	if sus, _ := suspensionRecords(t, r); len(sus) != 1 {
		t.Fatalf("%d asset.suspend records", len(sus))
	}
	if why := s.Halted("any-other-asset"); why != "" {
		t.Fatalf("node held: %q", why)
	}
	if !s.suspended(relayID) {
		t.Fatal("asset not suspended")
	}
}

// A clear whose append reported an error but was committed is found in
// the stream before the file is matched again, so it is not written twice:
// C8 0.2 breaks the chain on a second clear. Here the run's own settle has
// not applied it, as when its fold could not read the stream.
func TestCommittedClearNotWrittenTwice(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	s := newScheduler(t, r, suspendingCollector(t, false))
	s.RunOnce(bg, 0)
	sp := s.Suspensions()[relayID]
	if err := s.commitSuspensionRecord(bg, audit.ActionAssetSuspensionClear, relayID, sp, "", "test"); err != nil {
		t.Fatal(err)
	}
	writeClear(t, nc, relayID, sp.Ref)
	s.checkClear(bg)
	if _, clears := suspensionRecords(t, r); len(clears) != 1 {
		t.Fatalf("%d asset.suspension_clear records", len(clears))
	}
	if why := s.Halted("any-other-asset"); why != "" {
		t.Fatalf("node held: %q", why)
	}
	if s.suspended(relayID) {
		t.Fatal("still suspended after the committed clear")
	}
}

// A suspension record the node cannot apply stops every run on the node,
// at a start's rebuild and when the running node meets it: a clear of a
// suspension that is not open breaks C8 0.2's rules, and a second
// suspension of an asset already suspended breaks the node's one per asset.
func TestBadSuspensionRecordHoldsEverything(t *testing.T) {
	for name, write := range map[string]func(*Scheduler) error{
		"orphan clear": func(s *Scheduler) error {
			sp := asset.Suspension{Reason: asset.SuspendAuthFailed, Ref: "inv-never-opened"}
			return s.commitSuspensionRecord(bg, audit.ActionAssetSuspensionClear, relayID, sp, "", "test")
		},
		"second suspension": func(s *Scheduler) error {
			for _, ref := range []string{"inv-first", "inv-second"} {
				sp := asset.Suspension{Reason: asset.SuspendAuthFailed, Ref: ref}
				if err := s.commitSuspensionRecord(bg, audit.ActionAssetSuspend, relayID, sp, "failed.auth_rejected", "test"); err != nil {
					return err
				}
			}
			return nil
		},
	} {
		c, dir := schedConfig(t, nil)
		r, _, _ := start(t, c, dir)
		s := newScheduler(t, r, suspendingCollector(t, false))
		if err := write(s); err != nil {
			t.Fatal(err)
		}
		col := suspendingCollector(t, false)
		s.c = col
		if rep := s.RunOnce(bg, 0); col.n() != 0 || s.Halted(relayID) != AlarmSuspensionsUnknown {
			t.Fatalf("%s, running node: run %+v, %d requests, halted %q", name, rep, col.n(), s.Halted(relayID))
		}
		r.Close()
		os.Remove(filepath.Join(c.Store.Dir, SuspensionsFileName))
		r, _, _ = start(t, c, dir)
		s = newScheduler(t, r, col)
		if why := s.Halted(relayID); why != AlarmSuspensionsUnknown {
			t.Fatalf("%s, after restart: halted %q", name, why)
		}
		r.Close()
	}
}
