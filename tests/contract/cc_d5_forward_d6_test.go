package contract

// P4-4-CC deliverable 5, "The backward fixtures also hold forward" (brief
// P4-4-CC; D4-104 item 2 (c)): on this branch the 0.13 records validate.
// The records are D6's cc-d0 audit-0.13-* files, which the 0.12 reader
// refuses (cc_d0_old_readers_d6_test.go). Here the 0.13 code reads each one,
// strictly, as Seal would write it, and reads the ten as one view of the
// node's chain: linked from seq 19's checkpoint, and with no break of
// C8-8's rules. Decisions 12 to 14 are before the view, so they are
// unknown, not a break. Ground truth: GT-HAND. Evidence class: desk.

import (
	"bytes"
	"testing"

	"otsec.local/otsec/contracts/audit"
)

func TestCCD5ForwardC813Records(t *testing.T) {
	var stored [][]byte
	var recs []*audit.Record
	for _, c := range ccD0Audit013 {
		b := bytes.TrimRight(ccD0File(t, c.file), "\r\n")
		r, err := audit.ParseRecord(b)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		// The writer's strict check: without its chain fields, the record
		// is one Seal takes, so it holds no field outside 0.13.
		m := ccD0Map(t, b)
		delete(m, "seq")
		delete(m, "prev_hash")
		if _, err := audit.ValidatePending(ccD0JSON(t, m)); err != nil {
			t.Errorf("%s as a pending record: %v", c.file, err)
		}
		stored, recs = append(stored, b), append(recs, r)
	}
	from := &audit.Checkpoint{NodeID: "d6-node", Seq: 19, Hash: audit.Hash([]byte("d6 cc-d0 record 19"))}
	if err := audit.VerifyChain("d6-node", stored, from, nil); err != nil {
		t.Errorf("VerifyChain: %v", err)
	}
	if err := audit.VerifySensorFrom(recs, 20); err != nil {
		t.Errorf("VerifySensorFrom: %v", err)
	}
	// St1: a revocation that ended no link and one that ended a link with
	// both streams empty read back apart.
	byFile := map[string]*audit.Record{}
	for i, c := range ccD0Audit013 {
		byFile[c.file] = recs[i]
	}
	if s := byFile["audit-0.13-sensor-revoked-no-link.json"].Sensor.Streams; s == nil || s.ObservationThroughSeq != nil || s.AlertThroughSeq != nil {
		t.Errorf("streams {} reads as %+v", s)
	}
	if s := byFile["audit-0.13-sensor-revoked-streams-zero.json"].Sensor.Streams; s == nil || s.ObservationThroughSeq == nil || s.AlertThroughSeq == nil ||
		*s.ObservationThroughSeq != 0 || *s.AlertThroughSeq != 0 {
		t.Errorf("streams with both keys at 0 reads as %+v", s)
	}
}
