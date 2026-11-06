package node

// C6's cases for item 3 part 2 (#454): a crash inside an identity change.
// Evidence class: simulated (the node on a temporary store, a fake
// collector, no device).

import (
	"testing"

	"otsec.local/otsec/modules/asset"
)

// A changed identity is a security signal of its own (the note section 6):
// identity-changed and its identity.changed health event, which is
// forwarded. The record is committed in the configuration database and the
// event in the evidence database, so a crash can fall between them. The
// signal must survive it, as an open configuration change's alarm does
// (heldConfigState at start): a restart that finds the newest identity
// record named a previous one and was never confirmed by an identity.read
// after it raises the change then, once.
func TestC6IdentityChangeSurvivesACrash(t *testing.T) {
	c, dir := identityConfig(t, nil)
	r, _, _ := start(t, c, dir)
	s := newScheduler(t, r, answering(okRun(t, invA, nil)))
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" {
		t.Fatalf("first run: %+v", rep)
	}

	// Run C reads another sel.cid. The node commits its identity record,
	// then crashes before it raises the change or stores the read: the
	// first steps of storeIdentity, done by hand.
	o := okRun(t, invC, changeCID)
	col := r.cfg.Schedule[0]
	st := s.identityOf(bg, relayID)
	declared, _ := r.cfg.Asset(relayID)
	rec, _, err := asset.Apply(withStoredReads(declared, st.doc.Asset.Attributes), o.Result, col.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	doc, capture, err := identityRecord(relayID, rec, o.Result, st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.storeItem3(bg, ConfigStream(relayID), doc, capture); err != nil {
		t.Fatal(err)
	}
	if ids, _ := identityRecords(t, r, relayID); len(ids) != 2 {
		t.Fatalf("%d identity records before the crash", len(ids))
	}
	r.Close()

	r, st2, _ := start(t, c, dir)
	defer r.Close()
	s = newScheduler(t, r, answering(okRun(t, invD, changeCID)))
	s.RunOnce(bg, 0)
	if ids, reads := identityRecords(t, r, relayID); len(ids) != 2 || len(reads) != 1 || reads[0].InvocationID != invD {
		t.Fatalf("after the restart and a run: %d identity records, reads %+v", len(ids), reads)
	}
	changed := 0
	for _, typ := range healthTypes(t, r) {
		if typ == HealthIdentityChanged {
			changed++
		}
	}
	if changed != 1 || countAlarms(st2, AlarmIdentityChanged) != 1 {
		t.Fatalf("the change committed before the crash raised %d identity.changed events and %d identity-changed alarms, want 1 each",
			changed, countAlarms(st2, AlarmIdentityChanged))
	}
}
