package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// quarantiningCollector answers every run with a quarantined outcome, an
// unauthorized-line one while *unauthorized is set, and counts the runs.
func quarantiningCollector(unauthorized *bool) *fakeCollector {
	frame := []byte(`{"wire":"otsec.collectorwire/0.1","invocation_id":"` + okInvocation + `","result":{},"audit":[]}`)
	var seq uint64
	return &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		seq++
		reason := "result: does not decode"
		err := fmt.Errorf("%w: %w: %s", collectorclient.ErrOutcomeUnknown, collectorclient.ErrOutcomeQuarantined, reason)
		if *unauthorized {
			reason = "result: line 7 is not permitted for sel.ser.read_all"
			err = fmt.Errorf("%w: %w: %w: %s", collectorclient.ErrOutcomeUnknown, collectorclient.ErrOutcomeQuarantined, collectorclient.ErrUnauthorizedLine, reason)
		}
		return collectorclient.Response{Reply: accepted(req, seq), Quarantine: &collectorclient.Quarantine{Raw: frame, Reason: reason, UnauthorizedLine: *unauthorized}}, err
	}}
}

// quarantineNode is a node whose admin_dir is the locked tls_dir, as in
// the suspension tests, with a scheduler over a quarantining collector.
type quarantineNode struct {
	t            *testing.T
	c            *Config
	dir          string
	nc           *nodeconfigtest.Config
	r            *Runtime
	st           *Status
	s            *Scheduler
	f            *fakeCollector
	unauthorized bool
}

func newQuarantineNode(t *testing.T) *quarantineNode {
	t.Helper()
	q := &quarantineNode{t: t}
	q.c, q.dir, q.nc = suspendConfig(t)
	q.f = quarantiningCollector(&q.unauthorized)
	q.restart()
	return q
}

// restart starts the node again over the same store, as after a kill.
func (q *quarantineNode) restart() {
	q.t.Helper()
	if q.r != nil {
		q.r.Close()
	}
	q.r, q.st, _ = start(q.t, q.c, q.dir)
	q.t.Cleanup(func() { q.r.Close() })
	q.s = newScheduler(q.t, q.r, q.f)
}

// runs makes n quarantined runs, two records each.
func (q *quarantineNode) runs(n int, unauthorized bool) {
	q.t.Helper()
	q.unauthorized = unauthorized
	for i := 0; i < n; i++ {
		if rep := q.s.RunOnce(bg, 0); rep.Outcome != "quarantined" {
			q.t.Fatalf("run %d: %+v", i, rep)
		}
	}
}

// export runs the CLI's export with admin_dir writable, as an
// administrator's, and locks it again.
func (q *quarantineNode) export() QuarantineManifest {
	q.t.Helper()
	q.nc.UnlockTLS()
	defer lockTLS(q.t, q.nc)
	m, err := ExportQuarantine(bg, q.c, relayID, filepath.Join(q.t.TempDir(), "export"), time.Now())
	if err != nil {
		q.t.Fatal(err)
	}
	return m
}

// adminFile writes name in admin_dir and locks it.
func (q *quarantineNode) adminFile(name string, b []byte) {
	q.t.Helper()
	q.nc.UnlockTLS()
	if err := os.WriteFile(filepath.Join(q.nc.AdminDir, name), b, 0o600); err != nil {
		q.t.Fatal(err)
	}
	lockTLS(q.t, q.nc)
}

func (q *quarantineNode) removeAdminFile(name string) {
	q.t.Helper()
	q.nc.UnlockTLS()
	if err := os.Remove(filepath.Join(q.nc.AdminDir, name)); err != nil {
		q.t.Fatal(err)
	}
	lockTLS(q.t, q.nc)
}

func (q *quarantineNode) manifestHash() string {
	q.t.Helper()
	b, err := os.ReadFile(filepath.Join(q.nc.AdminDir, QuarantineExportFileName(relayID)))
	if err != nil {
		q.t.Fatal(err)
	}
	return sha256Of(b)
}

func (q *quarantineNode) clearFile(manifest, extra string) {
	q.t.Helper()
	q.adminFile(ClearQuarantineFileName, []byte(`{"schema":"`+ClearQuarantineSchema+`","asset_id":"`+relayID+`","manifest_sha256":"`+manifest+`","principal":"admin@site-a"}`+extra))
}

func (q *quarantineNode) seqs() []uint64 {
	q.t.Helper()
	got, err := q.r.Store(QuarantineStream(relayID)).Read(bg, QuarantineStream(relayID), 0, 1000)
	if err != nil {
		q.t.Fatal(err)
	}
	var out []uint64
	for _, st := range got {
		out = append(out, uint64(st.Key.Seq))
	}
	return out
}

func (q *quarantineNode) records(action audit.Action) []*audit.Record {
	q.t.Helper()
	var out []*audit.Record
	for _, rec := range auditRecords(q.t, q.r) {
		if rec.Action == action {
			out = append(out, rec)
		}
	}
	return out
}

func (q *quarantineNode) hasAlarm(code, part string) bool {
	return slices.ContainsFunc(q.st.Snapshot("x").Alarms, func(a StatusAlarm) bool { return a.Code == code && strings.Contains(a.Detail, part) })
}

func seqRange(first, last uint64) []uint64 {
	var out []uint64
	for s := first; s <= last; s++ {
		out = append(out, s)
	}
	return out
}

// The whole flow (P3-A5): the CLI exports the stream byte for byte; the
// node checks the manifest copy and records quarantine.exported once; a
// clear is recorded before anything is removed, then carried out 16 seqs
// per tick while the asset's runs are held; only the exported seqs go,
// and records added after the export stay with their captures; a second
// file naming the same export is recorded as stale and removes nothing.
func TestQuarantineExportAndClear(t *testing.T) {
	q := newQuarantineNode(t)
	q.runs(9, false) // seqs 1 to 18
	m := q.export()
	if len(m.Items) != 18 || m.Items[0].Seq != 1 || m.Items[17].Seq != 18 || m.Stream != string(QuarantineStream(relayID)) {
		t.Fatalf("manifest: %d items, stream %s", len(m.Items), m.Stream)
	}
	q.runs(1, false) // seqs 19 and 20, after the export

	q.s.QuarantineTick(bg)
	q.s.QuarantineTick(bg)
	ex := q.records(audit.ActionQuarantineExported)
	if len(ex) != 1 {
		t.Fatalf("%d quarantine.exported records, want 1", len(ex))
	}
	h := q.manifestHash()
	if got := ex[0].Quarantine; got.ManifestSHA256 != h || got.FirstSeq != 1 || got.LastSeq != 18 || got.Items != 18 || ex[0].Actor.Type != authz.PrincipalNode {
		t.Fatalf("exported record: %+v by %+v", got, ex[0].Actor)
	}
	if qs := q.st.Snapshot("x").Quarantine; len(qs) != 1 || qs[0].Clearing || qs[0].ManifestSHA256 != h {
		t.Fatalf("status before the clear: %+v", qs)
	}

	q.clearFile(h, "")
	q.s.QuarantineTick(bg) // records the clear and takes the first step
	cl := q.records(audit.ActionQuarantineCleared)
	if len(cl) != 1 || cl[0].Outcome != audit.OutcomeSucceeded || cl[0].Quarantine.RequestedBy != "admin@site-a" || cl[0].Quarantine.FirstSeq != 1 || cl[0].Quarantine.LastSeq != 18 {
		t.Fatalf("cleared records: %+v", cl)
	}
	if got := q.seqs(); !slices.Equal(got, []uint64{17, 18, 19, 20}) {
		t.Fatalf("after one step the stream holds %v", got)
	}
	if qs := q.st.Snapshot("x").Quarantine; len(qs) != 1 || !qs[0].Clearing {
		t.Fatalf("status while clearing: %+v", qs)
	}
	n := q.f.n()
	if rep := q.s.RunOnce(bg, 0); rep.Alarm != AlarmQuarantineClearIncomplete || q.f.n() != n {
		t.Fatalf("run while clearing: %+v", rep)
	}

	q.s.QuarantineTick(bg)
	if got := q.seqs(); !slices.Equal(got, []uint64{19, 20}) {
		t.Fatalf("after the clear the stream holds %v", got)
	}
	got, err := q.r.Store(QuarantineStream(relayID)).Read(bg, QuarantineStream(relayID), 18, 2)
	if err != nil || len(got) != 2 {
		t.Fatal(err)
	}
	for _, st := range got {
		if _, err := q.r.Store(QuarantineStream(relayID)).ReadCapture(bg, st.EvidenceRef); err != nil {
			t.Fatalf("capture of a record added after the export: %v", err)
		}
	}
	if qs := q.st.Snapshot("x").Quarantine; len(qs) != 0 {
		t.Fatalf("status after the clear: %+v", qs)
	}
	if !q.hasAlarm(AlarmQuarantineCleared, "is done") {
		t.Fatal("no quarantine-cleared alarm")
	}
	q.unauthorized = false
	if rep := q.s.RunOnce(bg, 0); !rep.Sent {
		t.Fatalf("run after the clear: %+v", rep)
	}

	// The same file again changes nothing and is not recorded again.
	q.s.QuarantineTick(bg)
	if len(q.records(audit.ActionQuarantineCleared)) != 1 {
		t.Fatal("the applied file was recorded again")
	}
	// Another file naming the cleared export is recorded as stale.
	q.clearFile(h, "\n")
	q.s.QuarantineTick(bg)
	cl = q.records(audit.ActionQuarantineCleared)
	if len(cl) != 2 || cl[1].Outcome != audit.OutcomeInfo || cl[1].ReasonCode != audit.ReasonAlreadyCleared {
		t.Fatalf("stale clear: %+v", cl)
	}
	if got := q.seqs(); !slices.Equal(got, []uint64{19, 20, 21, 22}) {
		t.Fatalf("a stale clear removed something: %v", got)
	}
}

// The export is the stream's records byte for byte, and the CLI refuses a
// directory that exists (A3-5).
func TestQuarantineExportFiles(t *testing.T) {
	q := newQuarantineNode(t)
	q.runs(1, false)
	dir := filepath.Join(t.TempDir(), "export")
	q.nc.UnlockTLS()
	m, err := ExportQuarantine(bg, q.c, relayID, dir, time.Now())
	lockTLS(t, q.nc)
	if err != nil {
		t.Fatal(err)
	}
	db := q.r.Store(QuarantineStream(relayID))
	stored, _ := db.Read(bg, QuarantineStream(relayID), 0, 10)
	for i, st := range stored {
		ev, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%d.event.json", st.Key.Seq)))
		if err != nil || !bytes.Equal(ev, st.Event) || m.Items[i].EventSHA256 != sha256Of(st.Event) {
			t.Fatalf("seq %d event not exported byte for byte: %v", st.Key.Seq, err)
		}
		c, _ := db.ReadCapture(bg, st.EvidenceRef)
		got, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%d.capture", st.Key.Seq)))
		if err != nil || !bytes.Equal(got, c.Bytes) || m.Items[i].CaptureSHA256 != sha256Of(c.Bytes) {
			t.Fatalf("seq %d capture not exported byte for byte: %v", st.Key.Seq, err)
		}
	}
	mb, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if q.manifestHash() != sha256Of(mb) {
		t.Fatal("the admin_dir copy is not manifest.json")
	}
	q.nc.UnlockTLS()
	_, err = ExportQuarantine(bg, q.c, relayID, dir, time.Now())
	lockTLS(t, q.nc)
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("export into an existing directory: %v", err)
	}
	if _, err := ExportQuarantine(bg, q.c, "not-scheduled", filepath.Join(t.TempDir(), "x"), time.Now()); err == nil {
		t.Fatal("export of an asset with no quarantine stream")
	}
}

// A manifest copy that does not match the stream both ways is not
// recorded, and a clear naming it removes nothing (A3-1).
func TestQuarantineManifestRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(m *QuarantineManifest)
		raw  func(b []byte) []byte
	}{
		"changed event hash":   {edit: func(m *QuarantineManifest) { m.Items[1].EventSHA256 = strings.Repeat("0", 64) }},
		"changed capture hash": {edit: func(m *QuarantineManifest) { m.Items[0].CaptureSHA256 = strings.Repeat("0", 64) }},
		"stored seq unlisted":  {edit: func(m *QuarantineManifest) { m.Items = slices.Delete(m.Items, 1, 2) }},
		"seq listed, not stored": {edit: func(m *QuarantineManifest) {
			m.Items = append(m.Items, QuarantineItem{Seq: 99, EventSHA256: m.Items[0].EventSHA256})
		}},
		"other node":     {edit: func(m *QuarantineManifest) { m.NodeID = "site-b-node1" }},
		"other asset":    {edit: func(m *QuarantineManifest) { m.AssetID = "9b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13" }},
		"unknown field":  {raw: func(b []byte) []byte { return bytes.Replace(b, []byte(`"schema"`), []byte(`"extra":1,"schema"`), 1) }},
		"trailing data":  {raw: func(b []byte) []byte { return append(b, []byte(`{}`)...) }},
		"seqs unordered": {edit: func(m *QuarantineManifest) { m.Items[0], m.Items[1] = m.Items[1], m.Items[0] }},
		"too large":      {raw: func(b []byte) []byte { return append(b, bytes.Repeat([]byte(" "), MaxQuarantineManifestBytes)...) }},
	} {
		t.Run(name, func(t *testing.T) {
			q := newQuarantineNode(t)
			q.runs(2, false)
			m := q.export()
			if tc.edit != nil {
				tc.edit(&m)
			}
			b, _ := json.Marshal(m)
			if tc.raw != nil {
				b = tc.raw(b)
			}
			q.adminFile(QuarantineExportFileName(relayID), b)
			q.s.QuarantineTick(bg)
			if n := len(q.records(audit.ActionQuarantineExported)); n != 0 {
				t.Fatalf("%d quarantine.exported records for a bad manifest", n)
			}
			if !slices.ContainsFunc(q.st.Snapshot("x").Alarms, func(a StatusAlarm) bool { return a.Code == AlarmQuarantineExportRefused }) {
				t.Fatal("no quarantine-export-refused alarm")
			}
			q.clearFile(sha256Of(b), "")
			q.s.QuarantineTick(bg)
			if got := q.seqs(); !slices.Equal(got, seqRange(1, 4)) || len(q.records(audit.ActionQuarantineCleared)) != 0 {
				t.Fatalf("a clear of an unrecorded manifest: stream %v", got)
			}
			if !q.hasAlarm(AlarmQuarantineClearRefused, "no quarantine.exported record") {
				t.Fatal("no quarantine-clear-refused alarm")
			}
		})
	}
}

// The clear's own checks, each of which removes nothing and records no
// clear: a listed seq no longer stored (A3-2), a manifest copy replaced
// after it was recorded, an audit database that takes no record (A3-3),
// and a file that is not a clear.
func TestQuarantineClearRefusals(t *testing.T) {
	setup := func(t *testing.T) (*quarantineNode, string) {
		q := newQuarantineNode(t)
		q.runs(2, false)
		q.export()
		q.s.QuarantineTick(bg)
		if len(q.records(audit.ActionQuarantineExported)) != 1 {
			t.Fatal("export not recorded")
		}
		return q, q.manifestHash()
	}
	check := func(t *testing.T, q *quarantineNode, want []uint64, alarm string) {
		t.Helper()
		if got := q.seqs(); !slices.Equal(got, want) {
			t.Fatalf("stream holds %v, want %v", got, want)
		}
		if n := len(q.records(audit.ActionQuarantineCleared)); n != 0 {
			t.Fatalf("%d quarantine.cleared records", n)
		}
		if !q.hasAlarm(AlarmQuarantineClearRefused, alarm) {
			t.Fatalf("no %s alarm saying %q: %+v", AlarmQuarantineClearRefused, alarm, q.st.Snapshot("x").Alarms)
		}
	}
	t.Run("listed seq gone", func(t *testing.T) {
		q, h := setup(t)
		consumers, _ := q.c.Consumers()
		if _, err := q.r.Store(QuarantineStream(relayID)).Discard(bg, consumers, QuarantineStream(relayID), []c5.Seq{3}); err != nil {
			t.Fatal(err)
		}
		q.clearFile(h, "")
		q.s.QuarantineTick(bg)
		check(t, q, []uint64{1, 2, 4}, "no longer matches")
	})
	t.Run("copy replaced", func(t *testing.T) {
		q, h := setup(t)
		q.runs(1, false)
		q.export() // a newer export replaces the copy; it is recorded too
		q.removeAdminFile(QuarantineExportFileName(relayID))
		q.clearFile(h, "")
		q.s.QuarantineTick(bg)
		check(t, q, seqRange(1, 6), "no longer manifest")
	})
	t.Run("audit takes no record", func(t *testing.T) {
		q, h := setup(t)
		q.clearFile(h, "")
		d := q.r.find(AuditDB)
		q.r.state.Lock()
		saved := d.log
		d.log = nil
		q.r.state.Unlock()
		q.s.settleMu.Lock()
		q.s.checkQuarantineClear(bg) // the fold needs the audit database
		q.s.stepClear(bg)
		q.s.settleMu.Unlock()
		q.r.state.Lock()
		d.log = saved
		q.r.state.Unlock()
		check(t, q, seqRange(1, 4), "not recorded")
	})
	t.Run("not a clear", func(t *testing.T) {
		q, h := setup(t)
		q.adminFile(ClearQuarantineFileName, []byte(`{"schema":"`+ClearQuarantineSchema+`","asset_id":"`+relayID+`","manifest_sha256":"`+h+`","principal":"not a principal"}`))
		q.s.QuarantineTick(bg)
		check(t, q, seqRange(1, 4), "human principal")
	})
}

// A clear stopped partway is finished from the chain's record, never from
// the files (A1 (a) to (c), A3): killed after the record and before the
// first step, or between steps, the restarted node holds the asset's runs
// from its first one and removes the rest of the range only, with both
// admin files gone. An unauthorized-line halt ends only once the whole
// range is gone.
func TestQuarantineClearResumesFromTheRecord(t *testing.T) {
	for _, between := range []bool{false, true} {
		t.Run(map[bool]string{false: "kill before the first step", true: "kill between steps"}[between], func(t *testing.T) {
			q := newQuarantineNode(t)
			q.runs(8, false) // seqs 1 to 16
			q.runs(1, true)  // seqs 17 and 18: halts the asset
			if q.s.Halted(relayID) != AlarmUnauthorizedLine {
				t.Fatal("not halted")
			}
			q.export()
			q.s.QuarantineTick(bg)
			h := q.manifestHash()
			q.clearFile(h, "")
			if between {
				q.s.QuarantineTick(bg) // the record and the first step
				if got := q.seqs(); !slices.Equal(got, []uint64{17, 18}) {
					t.Fatalf("after one step: %v", got)
				}
				if q.s.Halted(relayID) == "" {
					t.Fatal("halt ended mid-removal")
				}
			} else {
				q.s.settleMu.Lock()
				if err := q.s.fold(bg, true); err != nil {
					t.Fatal(err)
				}
				q.s.checkQuarantineClear(bg) // the record, no step
				q.s.settleMu.Unlock()
				if got := q.seqs(); len(got) != 18 || len(q.records(audit.ActionQuarantineCleared)) != 1 {
					t.Fatalf("before the kill: %v", got)
				}
			}
			q.removeAdminFile(ClearQuarantineFileName)
			q.removeAdminFile(QuarantineExportFileName(relayID))
			q.restart()
			if qs := q.st.Snapshot("x").Quarantine; len(qs) != 1 || !qs[0].Clearing {
				t.Fatalf("status after the restart: %+v", qs)
			}
			n := q.f.n()
			if rep := q.s.RunOnce(bg, 0); rep.Sent || q.f.n() != n {
				t.Fatalf("run before the clear is finished: %+v", rep)
			}
			for i := 0; i < 3 && len(q.st.Snapshot("x").Quarantine) > 0; i++ {
				q.s.QuarantineTick(bg)
			}
			if got := q.seqs(); len(got) != 0 {
				t.Fatalf("after the resume the stream holds %v", got)
			}
			if q.s.Halted(relayID) != "" {
				t.Fatalf("halted %q after the whole range is gone", q.s.Halted(relayID))
			}
			if !q.hasAlarm(AlarmQuarantineCleared, "collection resumes") {
				t.Fatal("no quarantine-cleared alarm saying collection resumes")
			}
			if rep := q.s.RunOnce(bg, 0); !rep.Sent {
				t.Fatalf("run after the clear: %+v", rep)
			}
		})
	}
}

// A halt whose unauthorized-line quarantine is outside the cleared range
// stays when the clear is done.
func TestQuarantineClearKeepsHaltOutsideRange(t *testing.T) {
	q := newQuarantineNode(t)
	q.runs(1, false)
	q.export() // seqs 1 and 2
	q.runs(1, true)
	q.s.QuarantineTick(bg)
	q.clearFile(q.manifestHash(), "")
	q.s.QuarantineTick(bg)
	if got := q.seqs(); !slices.Equal(got, []uint64{3, 4}) {
		t.Fatalf("stream holds %v", got)
	}
	if q.s.Halted(relayID) != AlarmUnauthorizedLine || !q.hasAlarm(AlarmQuarantineCleared, "the halt stays") {
		t.Fatalf("halt after a clear that left an unauthorized line: %q", q.s.Halted(relayID))
	}
}

// The checkpoint holds the recorded exports, so a start that reads the
// audit stream only after the checkpoint still knows them.
func TestQuarantineCheckpointHoldsExports(t *testing.T) {
	q := newQuarantineNode(t)
	q.runs(1, false)
	q.export()
	q.s.QuarantineTick(bg)
	q.s.settle(bg)
	f, err := readSuspensions(filepath.Join(q.c.Store.Dir, SuspensionsFileName))
	if err != nil {
		t.Fatal(err)
	}
	h := q.manifestHash()
	if e, ok := f.Quarantine[h]; !ok || e.AssetID != relayID || e.LastSeq != 2 || f.ThroughSeq == 0 {
		t.Fatalf("checkpoint: %+v", f)
	}
	q.restart()
	if qs := q.st.Snapshot("x").Quarantine; len(qs) != 1 || qs[0].ManifestSHA256 != h {
		t.Fatalf("status after a restart: %+v", qs)
	}
}

// One Discard step per tick across every recorded clear (A1 (c)): with
// two assets' clears recorded, one tick removes 16 seqs in all.
func TestQuarantineOneStepPerTick(t *testing.T) {
	const other = "3c8e5f21-9d4a-4b6c-8f32-8d5e1e7b9c24"
	var nc *nodeconfigtest.Config
	c, dir := schedConfig(t, func(n *nodeconfigtest.Config) {
		n.AddSEL751(other, "", 2324, 300)
		n.AdminDir = n.TLSDir
		nc = n
	})
	q := &quarantineNode{t: t, c: c, dir: dir, nc: nc}
	q.f = quarantiningCollector(&q.unauthorized)
	q.restart()
	if err := store.CreateDir(nc.TLSDir, ""); err != nil {
		t.Fatal(err)
	}
	lockTLS(t, nc)
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	hashes := map[string]string{}
	for i, a := range []string{relayID, other} {
		for j := 0; j < 9; j++ {
			if rep := q.s.RunOnce(bg, i); rep.Outcome != "quarantined" {
				t.Fatalf("%s run %d: %+v", a, j, rep)
			}
		}
		nc.UnlockTLS()
		if _, err := ExportQuarantine(bg, c, a, filepath.Join(t.TempDir(), "export"), time.Now()); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(filepath.Join(nc.AdminDir, QuarantineExportFileName(a)))
		hashes[a] = sha256Of(b)
		lockTLS(t, nc)
	}
	q.s.QuarantineTick(bg)
	// A clear naming one asset's export for the other removes nothing.
	q.adminFile(ClearQuarantineFileName, []byte(`{"schema":"`+ClearQuarantineSchema+`","asset_id":"`+other+`","manifest_sha256":"`+hashes[relayID]+`","principal":"admin@site-a"}`))
	q.s.QuarantineTick(bg)
	if n := len(q.records(audit.ActionQuarantineCleared)); n != 0 || !q.hasAlarm(AlarmQuarantineClearRefused, "of asset "+other) {
		t.Fatalf("a clear naming another asset's export: %d records", n)
	}
	for _, a := range []string{relayID, other} {
		q.adminFile(ClearQuarantineFileName, []byte(`{"schema":"`+ClearQuarantineSchema+`","asset_id":"`+a+`","manifest_sha256":"`+hashes[a]+`","principal":"admin@site-a"}`))
		q.s.settleMu.Lock()
		if err := q.s.fold(bg, true); err != nil {
			t.Fatal(err)
		}
		q.s.checkQuarantineClear(bg) // the record, no step
		q.s.settleMu.Unlock()
	}
	if n := len(q.records(audit.ActionQuarantineCleared)); n != 2 {
		t.Fatalf("%d clears recorded", n)
	}
	stored := func() (n int) {
		for _, a := range []string{relayID, other} {
			got, _ := q.r.Store(QuarantineStream(a)).Read(bg, QuarantineStream(a), 0, 100)
			n += len(got)
		}
		return n
	}
	q.s.QuarantineTick(bg)
	if n := stored(); n != 36-c5.DiscardStepEvents {
		t.Fatalf("%d records left after one tick, want %d", n, 36-c5.DiscardStepEvents)
	}
	for i := 0; i < 4; i++ {
		q.s.QuarantineTick(bg)
	}
	if n := stored(); n != 0 {
		t.Fatalf("%d records left", n)
	}
}
