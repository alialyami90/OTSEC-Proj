package node

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
)

// sensorGoldens are C8 0.13's valid records of the three sensor actions and
// of collector.request with a sensor target (C8-6), as contracts/audit pins
// them.
var sensorGoldens = []string{
	"collector-request-sensor-enrol.json",
	"sensor-enrolled.json",
	"sensor-enrolled-denied.json",
	"sensor-enrolled-rekey.json",
	"sensor-enrolled-state-unknown.json",
	"sensor-link-refused.json",
	"collector-request-sensor-revoke.json",
	"sensor-revoked.json",
	"sensor-revoked-no-link.json",
	"sensor-revoked-streams-empty.json",
}

// injectSensorChain appends every sensor golden to the node's audit chain,
// stamped otsec.audit/0.13 as written. The collector.request records take
// collector_seq 1 and 2, below the collector's own numbering in the test.
func injectSensorChain(t *testing.T, r *Runtime) {
	t.Helper()
	var out []c5.Record
	actions := map[audit.Action]bool{}
	cseq := uint64(0)
	for _, name := range sensorGoldens {
		b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "audit", "testdata", "valid", name))
		if err != nil {
			t.Fatal(err)
		}
		var rec audit.Record
		if err := json.Unmarshal(b, &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Contract != "otsec.audit/0.13" {
			t.Fatalf("%s is stamped %s", name, rec.Contract)
		}
		rec.Seq, rec.PrevHash = 0, ""
		rec.NodeID, rec.Actor.ID, rec.Time = string(r.cfg.NodeID), string(r.cfg.NodeID), r.received()
		if rec.Action == audit.ActionCollectorRequest {
			cseq++
			rec.CollectorSeq, rec.Actor.ID = cseq, "admin@site-a"
		}
		actions[rec.Action] = true
		eb, err := json.Marshal(&rec)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: eb})
	}
	for _, a := range []audit.Action{audit.ActionSensorEnrolled, audit.ActionSensorRevoked, audit.ActionSensorLinkRefused, audit.ActionCollectorRequest} {
		if !actions[a] {
			t.Fatalf("the chain holds no %s", a)
		}
	}
	if _, err := r.Log(AuditStream).AppendBatch(bg, out); err != nil {
		t.Fatal(err)
	}
}

// reader012 is the fold's reader with C8 0.13's three sensor actions
// removed, as the 0.12 reader has them: it refuses each as unknown.
func reader012(b []byte) (*audit.Record, error) {
	rec, err := audit.ParseRecord(b)
	if err != nil {
		return nil, err
	}
	switch rec.Action {
	case audit.ActionSensorEnrolled, audit.ActionSensorRevoked, audit.ActionSensorLinkRefused:
		return nil, fmt.Errorf("%w: unknown action %q", audit.ErrRecordRejected, rec.Action)
	}
	return rec, nil
}

// C8-1's fold test (P4-4-CC deliverable 5; docs/phase4/D3-sensor-link.md
// §11.2). Over an audit chain that holds every 0.13 sensor record and a
// collector.request with a sensor target, the scheduler's fold with the
// 0.13 reader holds no run, as the scheduler runs and again when a start
// rebuilds the suspensions from the whole stream. Control: the same chain
// folded by the reader without the three new actions, as the 0.12 reader
// has it, holds every run (asset-suspensions-unknown). That is C8 0.13's
// reader floor: a rollback below it stops collection on the node.
func TestC81SensorRecordsFoldHoldsNoRun(t *testing.T) {
	for _, control := range []bool{false, true} {
		t.Run(fmt.Sprintf("0.12-reader=%v", control), func(t *testing.T) {
			if control {
				parseAuditRecord = reader012
				t.Cleanup(func() { parseAuditRecord = audit.ParseRecord })
			}
			c, dir := schedConfig(t, nil)
			r, _, _ := start(t, c, dir)
			injectSensorChain(t, r)
			sent := 0
			seq := uint64(1000)
			s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) { sent++ }, &seq))
			rep := s.RunOnce(bg, 0)
			why := s.Halted(relayID)
			if control {
				if rep.Sent || sent != 0 || why != AlarmSuspensionsUnknown {
					r.Close()
					t.Fatalf("0.12 reader: run %+v, %d requests, halted %q; want every run held as %s", rep, sent, why, AlarmSuspensionsUnknown)
				}
				r.Close()
				return
			}
			if !rep.Sent || sent != 1 || why != "" || rep.Alarm != "" {
				r.Close()
				t.Fatalf("0.13 reader: run %+v, %d requests, halted %q; want the run sent", rep, sent, why)
			}
			// A start without the checkpoint folds the whole stream.
			r.Close()
			if err := os.Remove(filepath.Join(c.Store.Dir, SuspensionsFileName)); err != nil {
				t.Fatal(err)
			}
			r, _, _ = start(t, c, dir)
			defer r.Close()
			s = newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) { sent++ }, &seq))
			if rep := s.RunOnce(bg, 0); !rep.Sent || sent != 2 || s.Halted(relayID) != "" {
				t.Fatalf("0.13 reader after a start: run %+v, %d requests, halted %q", rep, sent, s.Halted(relayID))
			}
		})
	}
}
