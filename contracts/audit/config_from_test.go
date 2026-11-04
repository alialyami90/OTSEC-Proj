package audit

import (
	"testing"

	"otsec.local/otsec/contracts/authz"
)

// fromChain is readsChain followed by an event baseline's records: its
// recording, its acknowledgement, and a checkpoint of each half that did not
// restore.
func fromChain() []*Record {
	recs := readsChain()
	recs = append(recs, recordedRec(31, authz.BaselineEvent, testEventV1, "", 1))
	recs = append(recs, ack08(testAsset, 30, testEventV1, "", OutcomeSucceeded)...)
	return append(recs, detectorNotRestored(90, testEventV1), learnerNotRestored(91, 2, testEventV1))
}

// TestVerifyConfigFromEveryCut: the view of a chain that VerifyConfig accepts
// verifies from every point it could have been pruned to (D4-40 item 8), and
// from seq 1 it is VerifyConfig.
func TestVerifyConfigFromEveryCut(t *testing.T) {
	c := fromChain()
	if err := VerifyConfig(c); err != nil {
		t.Fatal(err)
	}
	for i := range c {
		if err := VerifyConfigFrom(c[i:], c[i].Seq); err != nil {
			t.Errorf("view from record %d (%s): %v", c[i].Seq, c[i].Action, err)
		}
	}
	// The cuts VerifyConfig itself refuses, from seq 1.
	if err := VerifyConfigFrom(c[2:], 1); err == nil {
		t.Error("a view from seq 1 that lacks its first records: accepted")
	}
}

// TestVerifyConfigFromRefusals: only what is before the view is unknown. A
// reference into the view that does not resolve, a baseline other than the
// one the view started with, and anything after a collector.seq_reset in
// the view are checked as in VerifyConfig.
func TestVerifyConfigFromRefusals(t *testing.T) {
	c := fromChain()
	at := func(seq uint64) int {
		for i, r := range c {
			if r.Seq == seq {
				return i
			}
		}
		t.Fatalf("no record %d", seq)
		return 0
	}
	clone := func(r *Record) *Record {
		cp := *r
		cfg := *r.Config
		cp.Config = &cfg
		return &cp
	}
	// The view from the run decided at 8: its lowest decision is 8.
	view := func() []*Record { return append([]*Record(nil), c[at(13):]...) }
	first := uint64(13)
	approved := bySeq(c, 21)

	bad := map[string]func() ([]*Record, uint64){
		"a record before the view": func() ([]*Record, uint64) { return c[at(13)-1:], first },
		"a view from seq 0":        func() ([]*Record, uint64) { return c, 0 },
		"a decision in the view that does not resolve": func() ([]*Record, uint64) {
			r := clone(approved)
			r.Seq, r.Config.DecisionSeq = 95, 12 // 12 is a run, not an acceptance
			return append(view(), r), first
		},
		"a decision above the view's lowest that is not in it": func() ([]*Record, uint64) {
			r := clone(approved)
			r.Seq, r.Config.DecisionSeq = 95, 9
			return append(view(), r), first
		},
		"another baseline than the view started with": func() ([]*Record, uint64) {
			v := view()
			r := clone(bySeq(v, 21))
			r.Config.BaselineDigest = testSnapshot
			v[at(21)-at(13)] = r
			return v, first
		},
		"a decision before the view, after a reset in it": func() ([]*Record, uint64) {
			reset := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 92, Action: ActionCollectorSeqReset, Outcome: OutcomeInfo}
			r := clone(approved)
			r.Seq, r.Config.DecisionSeq = 93, 3
			return append(view(), reset, r), first
		},
		"a learner after the view's recording, at the wrong version": func() ([]*Record, uint64) {
			return append(view(), learnerNotRestored(96, 3, testEventV1)), first
		},
		"a detector of a baseline the view's acknowledgement did not set": func() ([]*Record, uint64) {
			return append(view(), detectorNotRestored(96, testEventV2)), first
		},
		"a first removal that leaves fewer than the newest two": func() ([]*Record, uint64) {
			v := append([]*Record(nil), c[at(25):]...)
			r := clone(bySeq(v, 30))
			r.Config.RemovedLastSeq = 45
			v[at(30)-at(25)] = r
			return v, 25
		},
		"a first removal with another kept digest": func() ([]*Record, uint64) {
			v := append([]*Record(nil), c[at(27):]...)
			r := clone(bySeq(v, 30))
			r.Config.KeptDigest = testReadB
			v[at(30)-at(27)] = r
			return v, 27
		},
		"a compared read of another baseline than the view started with": func() ([]*Record, uint64) {
			r := comparedNoDifference(96, 20, "2026-10-26T21:00:05Z", 49)
			r.Config.BaselineDigest = testSnapshot
			return append(view(), runAt(95, 20, "2026-10-26T21:00:00Z"), r), first
		},
		"a first removal whose range does not end at a read": func() ([]*Record, uint64) {
			v := append([]*Record(nil), c[at(25):]...)
			r := clone(bySeq(v, 30))
			r.Config.RemovedLastSeq = 44
			v[at(30)-at(25)] = r
			return v, 25
		},
		"a first removal whose range starts in the view": func() ([]*Record, uint64) {
			v := append([]*Record(nil), c[at(25):]...)
			r := clone(bySeq(v, 30))
			r.Config.RemovedFirstSeq = 43
			v[at(30)-at(25)] = r
			return v, 25
		},
		"a second removal that takes more than the view holds": func() ([]*Record, uint64) {
			r := nodeRec(98, "2026-10-26T22:00:00Z", ActionConfigReadsRemoved, "", Config{RemovedCount: 3, RemovedFirstSeq: 41, RemovedLastSeq: 45,
				RemovedDigest: RemovedReadsDigest([]string{testEqual, testReadA, testReadB}), KeptDigest: testReadC})
			return append(view(), r), first
		},
		"a repeat of a change in the view that is not there": func() ([]*Record, uint64) {
			v := append([]*Record(nil), c[at(24):]...)
			r := clone(bySeq(v, 25))
			r.Config.ChangeSeq = 99
			v[at(25)-at(24)] = r
			return v, 24
		},
	}
	// A collector.seq_reset in the view ends what is unknown, and what
	// follows it does not change the first epoch's lowest decision.
	reset := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 92, Action: ActionCollectorSeqReset, Outcome: OutcomeInfo}
	after := append(append([]*Record(nil), c[at(22):]...), reset, runAt(94, 1, "2026-10-26T23:00:00Z"))
	if err := VerifyConfigFrom(after, 22); err != nil {
		t.Errorf("a view with a reset and a run after it: %v", err)
	}
	// A detection whose epoch began before the view, with no earlier run in
	// it: the reset that bounds the change is unknown.
	d := clone(bySeq(c, 23))
	d.Config.UnchangedReadSeq, d.Config.UnchangedAt = 0, "2026-10-26T09:00:00Z"
	if err := VerifyConfigFrom([]*Record{bySeq(c, 22), d}, 22); err != nil {
		t.Errorf("a detection bounded by a reset before the view: %v", err)
	}
	for name, mk := range bad {
		recs, from := mk()
		if err := VerifyConfigFrom(recs, from); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The same removal from a view that starts before every read it takes is
	// checked in full: a wrong digest is refused there, and unknown only when
	// the view starts after the first read it takes.
	r := clone(bySeq(c, 30))
	r.Config.RemovedDigest = RemovedReadsDigest([]string{testReadA, testReadB})
	full := append(append([]*Record(nil), c[at(13):at(30)]...), r)
	if err := VerifyConfigFrom(full, first); err == nil {
		t.Error("a wrong removed_digest in a view that holds the reads: accepted")
	}
	part := append(append([]*Record(nil), c[at(25):at(30)]...), r)
	if err := VerifyConfigFrom(part, 25); err != nil {
		t.Errorf("a removal that takes a read from before the view: %v", err)
	}
}
