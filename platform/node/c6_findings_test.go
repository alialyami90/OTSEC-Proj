package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/finding"
	c5 "otsec.local/otsec/contracts/store"
)

// C6 on #458 (P4-3-C6): the restart, prune and ceiling cases D4-54 asks
// for, beyond C5's own tests.

// lastAuditSeq is the newest seq of the node's audit stream.
func (n *advNode) lastAuditSeq() c5.Seq {
	n.t.Helper()
	var last c5.Seq
	for after := c5.Seq(0); ; {
		got, err := n.r.Store(AuditStream).Read(bg, AuditStream, after, 500)
		if err != nil {
			n.t.Fatal(err)
		}
		if len(got) == 0 {
			return last
		}
		after, last = got[len(got)-1].Key.Seq, got[len(got)-1].Key.Seq
	}
}

// pruneThrough appends one filler record, so the stream is never pruned
// empty, and prunes the audit stream through seq.
func (n *advNode) pruneThrough(seq c5.Seq) {
	n.t.Helper()
	appendAudit(n.t, n.r, filler)
	pruneLifeAudit(n.t, n.r, seq)
}

func operatorRefs(fs []finding.Finding) map[string]string {
	m := map[string]string{}
	for _, f := range fs {
		m[f.Advisory] = f.Identity.Evidence[0].ID
	}
	return m
}

// A chain pruned past the declared identity's policy.apply record, then a
// restart: the record is cited again, not written again, and no operator
// finding is revised (D4-54, C6 on #455).
func TestC6PruneThenRestartKeepsTheDeclaredRecord(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.put(k.sign(findPayload(t, 1)))
	n.step()
	before := n.findings()
	if len(before) != 2 || len(n.records(audit.ActionPolicyApply)) != 1 {
		t.Fatalf("setup: %d findings, %d declared records", len(before), len(n.records(audit.ActionPolicyApply)))
	}
	n.pruneThrough(n.lastAuditSeq())
	if got := len(n.records(audit.ActionPolicyApply)); got != 0 {
		t.Fatalf("the prune kept %d declared records", got)
	}

	n.restart()
	n.step()
	if got := len(n.records(audit.ActionPolicyApply)); got != 0 {
		t.Fatalf("a prune and a restart wrote the declared identity again (%d records)", got)
	}
	after := n.findings()
	if len(after) != len(before) {
		t.Fatalf("a prune and a restart revised operator findings: %d findings, was %d", len(after), len(before))
	}
	if l := n.assetFindings().LastEvaluation; l == nil || l.Version != 1 {
		t.Fatalf("no completed evaluation after the restart: %+v", l)
	}
	// And again: a second restart cites the same record.
	n.restart()
	n.step()
	if got := len(n.findings()); got != len(before) || len(n.records(audit.ActionPolicyApply)) != 0 {
		t.Fatalf("a second restart: %d findings, %d declared records", got, len(n.records(audit.ActionPolicyApply)))
	}
}

// The file lost after a prune: the record is written again, and the
// operator findings are revised once to cite it, never twice.
func TestC6LostFileAfterPruneRevisesOnce(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.put(k.sign(findPayload(t, 1)))
	n.step()
	before := operatorRefs(n.findings())
	n.pruneThrough(n.lastAuditSeq())
	if err := os.Remove(filepath.Join(n.cfg.Store.Dir, DeclaredIdentitiesFileName)); err != nil {
		t.Fatal(err)
	}

	n.restart()
	n.step()
	if got := len(n.records(audit.ActionPolicyApply)); got != 1 {
		t.Fatalf("%d declared records after the file was lost, want 1", got)
	}
	fs := n.findings()
	if len(fs) != 4 {
		t.Fatalf("%d findings, want each operator finding revised once", len(fs))
	}
	for adv, ref := range operatorRefs(fs) {
		if ref == before[adv] {
			t.Fatalf("%s still cites the pruned record %s", adv, ref)
		}
	}
	n.restart()
	n.step()
	if got := len(n.findings()); got != 4 || len(n.records(audit.ActionPolicyApply)) != 1 {
		t.Fatalf("the next restart: %d findings, %d declared records", got, len(n.records(audit.ActionPolicyApply)))
	}
}

// A mismatch read whose identity.read the ceiling refuses: the matcher
// pauses, so the entry naming the reported product keeps no stored
// finding. Status must then not show a completed evaluation that reads
// that entry as product-not-named, since the read that contradicts it was
// never evaluated (D4-54: a missing finding must not be confused with an
// evaluation that never ran).
func TestC6RefusedMismatchIsNotReadAsNotNamed(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.startWith(answering(okRun(t, invA, nil), mismatchRun(t, invB)))
	n.put(k.sign(findPayload(t, 1)))
	n.step()
	n.s.RunOnce(bg, 0)
	for _, f := range n.findings() {
		if f.Advisory == "adv-other" {
			t.Fatalf("setup: adv-other stored: %+v", f)
		}
	}

	// Fill the class so a small identity.read still fits and the mismatch's
	// larger one does not.
	// In batches (C1 on #458): one fsync per record took minutes on
	// Windows.
	small, _ := json.Marshal(identityReadDoc{Schema: IdentityReadSchema, AssetID: relayID, InvocationID: invD, ReadAt: "2026-10-24T09:00:00Z"})
	n.fillConfig(int64(len(small)))
	n.s.RunOnce(bg, 0)
	if snap := n.st.Snapshot("x"); snap.AssetStore == nil || snap.AssetStore.Refused[c5.SeriesIdentityRead] == 0 {
		t.Fatalf("setup: the mismatch's identity.read was not refused: %+v", snap.AssetStore)
	}

	st := n.assetFindings()
	idEv := ""
	if is, ok := n.st.Snapshot("x").Identity[relayID]; ok {
		idEv = is.EvidenceID
	}
	l := st.LastEvaluation
	if l != nil && l.Version == 1 && l.IdentityEvidenceID == idEv {
		t.Fatalf("after a mismatch that was neither stored nor evaluated, status still reads adv-other as product-not-named: last evaluation %+v, identity %s", l, idEv)
	}
}

// An operator-only asset with a stored mismatch, then the chain pruned and
// declared-identities.json lost: the declaration is unchanged, so the
// mismatch must still count. D4-55 says a lost file costs at most a new
// record and one revision per operator finding, "never a wrong class".
func TestC6LostFileKeepsAnOperatorMismatch(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.startWith(answering(mismatchRun(t, invB)))
	n.put(k.sign(findPayload(t, 1)))
	n.step()
	n.s.RunOnce(bg, 0)
	classes := func() map[string]finding.Class {
		m := map[string]finding.Class{}
		for _, f := range n.findings() {
			m[f.Advisory] = f.Class
		}
		return m
	}
	before := classes()
	if before["adv-in"] != finding.ApplicableByVersion || before["adv-out"] != finding.ApplicableByVersion {
		t.Fatalf("setup: the operator mismatch did not take: %v", before)
	}

	n.pruneThrough(n.lastAuditSeq())
	if err := os.Remove(filepath.Join(n.cfg.Store.Dir, DeclaredIdentitiesFileName)); err != nil {
		t.Fatal(err)
	}
	n.startWith(nil)
	n.step()
	after := classes()
	for adv, c := range before {
		if after[adv] != c {
			t.Fatalf("%s went from %s to %s when only the file was lost, with the declaration unchanged", adv, c, after[adv])
		}
	}
}
