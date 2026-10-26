package audit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/authz"
)

// testAdmin names a test admin-signed request: the C7 test key's ID, a
// test principal, a fixed nonce and the SHA-256 of "otsec test admin
// payload". No real key or request is behind it.
func testAdmin() *Admin {
	return &Admin{AdminKeyID: "ed25519-183d5080d1a2ef2b", Principal: "admin@site-a", Nonce: "AAECAwQFBgcICQoLDA0ODw",
		PayloadSHA256: "d10534af6c12a7b32c701545e4ad53714b61e9292c531a999021b08d403b2310"}
}

var adminActor = Actor{Type: authz.PrincipalHuman, ID: "admin@site-a", Role: authz.RoleAdmin}

func adminRecord(outcome Outcome, seq uint64) Record {
	r := Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 20, PrevHash: strings.Repeat("6", 64), Time: baseTime(),
		Actor: adminActor, Action: ActionCollectorRequest, Outcome: outcome, CorrelationID: "req-20261026-0007", CollectorSeq: seq}
	if outcome == OutcomeDenied {
		r.ReasonCode = string(authz.RefuseAdminUnverified)
	}
	return r
}

// TestAdminFields (0.4): claimed only on the node's info record, verified
// and repeat_of only on an allowed one, repeat_of only with verified and
// below the record's own number, each group well formed, and none of it on
// a record stamped 0.3.
func TestAdminFields(t *testing.T) {
	ok := map[string]Record{
		"claimed on info": func() Record { r := adminRecord(OutcomeInfo, 0); r.Claimed = testAdmin(); return r }(),
		"verified":        func() Record { r := adminRecord(OutcomeAllowed, 9); r.Verified = testAdmin(); return r }(),
		"repeat": func() Record {
			r := adminRecord(OutcomeAllowed, 15)
			r.Verified, r.RepeatOf = testAdmin(), 9
			return r
		}(),
		"a 0.3 record without them": func() Record { r := adminRecord(OutcomeAllowed, 9); r.Contract = "otsec.audit/0.3"; return r }(),
	}
	for name, r := range ok {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]func(r *Record){
		"claimed stamped 0.3": func(r *Record) {
			r.Outcome, r.CollectorSeq, r.Claimed, r.Contract = OutcomeInfo, 0, testAdmin(), "otsec.audit/0.3"
		},
		"verified stamped 0.3": func(r *Record) { r.Verified, r.Contract = testAdmin(), "otsec.audit/0.3" },
		"repeat stamped 0.3":   func(r *Record) { r.Verified, r.RepeatOf, r.Contract = testAdmin(), 3, "otsec.audit/0.3" },
		"claimed on allowed":   func(r *Record) { r.Claimed = testAdmin() },
		"verified on info":     func(r *Record) { r.Outcome, r.CollectorSeq, r.Verified = OutcomeInfo, 0, testAdmin() },
		"verified on denied": func(r *Record) {
			r.Outcome, r.ReasonCode, r.Verified = OutcomeDenied, string(authz.RefuseAdminUnverified), testAdmin()
		},
		"repeat without verified":    func(r *Record) { r.RepeatOf = 3 },
		"repeat of itself":           func(r *Record) { r.Verified, r.RepeatOf = testAdmin(), r.CollectorSeq },
		"repeat of a later decision": func(r *Record) { r.Verified, r.RepeatOf = testAdmin(), r.CollectorSeq+1 },
		"repeat on denied": func(r *Record) {
			r.Outcome, r.ReasonCode, r.Verified, r.RepeatOf = OutcomeDenied, string(authz.RefuseAdminUnverified), testAdmin(), 3
		},
		"verified on another action": func(r *Record) {
			r.Action, r.Outcome, r.CorrelationID, r.Verified = ActionCredentialInstall, OutcomeSucceeded, "", testAdmin()
		},
		// A6: the action rule on its own, with an outcome claimed allows.
		"claimed on service.start": func(r *Record) {
			r.Action, r.Outcome, r.CollectorSeq, r.CorrelationID, r.Claimed = ActionServiceStart, OutcomeInfo, 0, "", testAdmin()
		},
		// A1 on #187: the record names one person.
		"verified, actor another person": func(r *Record) {
			r.Verified, r.Actor = testAdmin(), Actor{Type: authz.PrincipalHuman, ID: "bob@site-a", Role: authz.RoleAdmin}
		},
		"verified, actor differs only in case": func(r *Record) {
			r.Verified, r.Actor = testAdmin(), Actor{Type: authz.PrincipalHuman, ID: "Admin@site-a", Role: authz.RoleAdmin}
		},
		"verified, actor the node": func(r *Record) {
			r.Verified, r.Actor = testAdmin(), Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"}
		},
		"verified, actor a schedule of the same ID": func(r *Record) {
			r.Verified, r.Actor = testAdmin(), Actor{Type: authz.PrincipalSchedule, ID: "admin@site-a"}
		},
		"bad key id":        func(r *Record) { a := testAdmin(); a.AdminKeyID = "admin-1"; r.Verified = a },
		"bad nonce":         func(r *Record) { a := testAdmin(); a.Nonce = "short"; r.Verified = a },
		"bad payload hash":  func(r *Record) { a := testAdmin(); a.PayloadSHA256 = strings.ToUpper(a.PayloadSHA256); r.Verified = a },
		"bad principal":     func(r *Record) { a := testAdmin(); a.Principal = "-admin"; r.Verified = a },
		"empty claimed":     func(r *Record) { r.Outcome, r.CollectorSeq, r.Claimed = OutcomeInfo, 0, &Admin{} },
		"principal missing": func(r *Record) { a := testAdmin(); a.Principal = ""; r.Verified = a },
	}
	for name, mutate := range bad {
		r := adminRecord(OutcomeAllowed, 9)
		mutate(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestAdminGroupHoldsNoPayload: the group is closed, so a payload, a
// signature or a sealed secret cannot ride along in it.
func TestAdminGroupHoldsNoPayload(t *testing.T) {
	r := adminRecord(OutcomeInfo, 0)
	r.Claimed = testAdmin()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRecord(b); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"payload", "signature", "sealed"} {
		forged := strings.Replace(string(b), `"nonce":`, `"`+field+`":"eyJ4IjoxfQ","nonce":`, 1)
		if _, err := ParseRecord([]byte(forged)); err == nil {
			t.Errorf("claimed with %s accepted", field)
		}
	}
}

// seqRecords parses records for VerifyCollectorSeq.
func seqRecords(t *testing.T, recs []Record) []*Record {
	t.Helper()
	var out []*Record
	for _, b := range chain(t, recs) {
		r, err := ParseRecord(b)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// TestRepeatAccountsForTheFirstDecision (0.4): when the reply to the first
// decision was lost, the repeat names it and VerifyCollectorSeq counts it
// as recorded. When the first decision has a record, the repeat must name
// the same signed request. Other gaps are still gaps.
func TestRepeatAccountsForTheFirstDecision(t *testing.T) {
	start := Record{Actor: Actor{Type: authz.PrincipalSystem, ID: "node"}, Action: ActionAuditChainStart, Outcome: OutcomeInfo}
	claimed := Record{Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeInfo, CorrelationID: "req-1", Claimed: testAdmin()}
	accepted := func(seq, repeatOf uint64, a *Admin) Record {
		return Record{Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed, CorrelationID: "req-1",
			CollectorSeq: seq, Verified: a, RepeatOf: repeatOf}
	}
	other := testAdmin()
	other.Nonce = "BBECAwQFBgcICQoLDA0ODw"

	cases := map[string]struct {
		recs    []Record
		through uint64
		after   uint64
		ok      bool
	}{
		"first reply lost, repeat recorded": {
			recs: []Record{start, claimed, accepted(2, 1, testAdmin())}, through: 2, ok: true,
		},
		"both recorded": {
			recs: []Record{start, claimed, accepted(1, 0, testAdmin()), accepted(2, 1, testAdmin())}, through: 2, ok: true,
		},
		"two repeats of one lost first reply": {
			recs: []Record{start, claimed, accepted(2, 1, testAdmin()), accepted(3, 1, testAdmin())}, through: 3, ok: true,
		},
		"the first decision verified in an earlier window": {
			recs: []Record{start, accepted(2, 1, testAdmin())}, after: 1, through: 2, ok: true,
		},
		"a lost repeat is a gap": {
			recs: []Record{start, claimed, accepted(3, 1, testAdmin())}, through: 3,
		},
		"the repeat names another request's decision": {
			recs: []Record{start, accepted(1, 0, other), accepted(2, 1, testAdmin())}, through: 2,
		},
		"the repeat names a decision that was not an admin acceptance": {
			recs: []Record{start, {Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeDenied, ReasonCode: string(authz.RefuseAdminUnverified),
				CorrelationID: "req-0", CollectorSeq: 1}, accepted(2, 1, testAdmin())}, through: 2,
		},
		"the first decision recorded after its repeat": {
			recs: []Record{start, accepted(2, 1, testAdmin()), accepted(1, 0, testAdmin())}, through: 2,
		},
	}
	for name, c := range cases {
		err := VerifyCollectorSeq(seqRecords(t, c.recs), c.after, c.through)
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: %v", name, err)
		case !c.ok && !errors.Is(err, ErrChainBroken):
			t.Errorf("%s: got %v, want a broken chain", name, err)
		}
	}
}

// TestRepeatAcrossAReset: after a reset the numbering starts again, and a
// repeat names a number of the new epoch.
func TestRepeatAcrossAReset(t *testing.T) {
	node := Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"}
	high := uint64(1)
	recs := []Record{
		{Actor: Actor{Type: authz.PrincipalSystem, ID: "node"}, Action: ActionAuditChainStart, Outcome: OutcomeInfo},
		{Actor: node, Action: ActionCollectorInstallKey, Outcome: OutcomeInfo, InstallKeyID: "ik-old"},
		{Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed, CorrelationID: "req-1", CollectorSeq: 1, Verified: testAdmin()},
		{Actor: node, Action: ActionCollectorSeqReset, Outcome: OutcomeInfo, InstallKeyID: "ik-new", PreviousHigh: &high},
		{Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed, CorrelationID: "req-1", CollectorSeq: 2, Verified: testAdmin(), RepeatOf: 1},
	}
	if err := VerifyCollectorSeq(seqRecords(t, recs), 0, 2); err != nil {
		t.Fatalf("a lost first reply in the new epoch: %v", err)
	}
	// Without the repeat, the new epoch's decision 1 is a gap: the old
	// epoch's record of 1 does not count for it.
	if err := VerifyCollectorSeq(seqRecords(t, recs[:4]), 0, 1); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("got %v, want a broken chain", err)
	}
}

// TestRepeatAcrossWindows (A1 on #187): a window that ends between a lost
// first reply and its repeat reports the gap; verified again from the last
// good state, the next window, which holds the repeat, reports it covered,
// as the whole chain does.
func TestRepeatAcrossWindows(t *testing.T) {
	start := Record{Actor: Actor{Type: authz.PrincipalSystem, ID: "node"}, Action: ActionAuditChainStart, Outcome: OutcomeInfo}
	other := testAdmin()
	other.Nonce = "BBECAwQFBgcICQoLDA0ODw"
	recs := seqRecords(t, []Record{
		start,
		{Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed, CorrelationID: "req-0", CollectorSeq: 1, Verified: other},
		{Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeInfo, CorrelationID: "req-1", Claimed: testAdmin()},
		// Decision 2 accepted req-1; its reply was lost. The node resends.
		{Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed, CorrelationID: "req-1", CollectorSeq: 3, Verified: testAdmin(), RepeatOf: 2},
	})
	// The window ends after decision 2 was handed out, before the repeat.
	if _, err := VerifyCollectorSeqFrom(recs[:3], SeqState{}, 2); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("window before the repeat: got %v, want the gap reported", err)
	}
	good, err := VerifyCollectorSeqFrom(recs[:3], SeqState{}, 1)
	if err != nil {
		t.Fatalf("last good state: %v", err)
	}
	if _, err := VerifyCollectorSeqFrom(recs[3:], good, 3); err != nil {
		t.Fatalf("the next window, holding the repeat: %v", err)
	}
	if err := VerifyCollectorSeq(recs, 0, 3); err != nil {
		t.Fatalf("whole chain: %v", err)
	}
}

// TestRepeatOnlyFromAnAcceptance (A6 and A1 on #187): VerifyCollectorSeq
// holds its own rule for records it did not parse: a denied record, or a
// record of another action, carrying verified and repeat_of covers
// nothing and is no first decision.
func TestRepeatOnlyFromAnAcceptance(t *testing.T) {
	start := &Record{Action: ActionAuditChainStart}
	for name, r := range map[string]*Record{
		"denied":         {Action: ActionCollectorRequest, Outcome: OutcomeDenied, CollectorSeq: 2, Verified: testAdmin(), RepeatOf: 1},
		"another action": {Action: ActionCredentialInstall, Outcome: OutcomeSucceeded, CollectorSeq: 2, Verified: testAdmin(), RepeatOf: 1},
		// A6: the action check on its own, with the outcome a repeat has.
		"another action, allowed": {Action: ActionCredentialInstall, Outcome: OutcomeAllowed, CollectorSeq: 2, Verified: testAdmin(), RepeatOf: 1},
	} {
		if err := VerifyCollectorSeq([]*Record{start, r}, 0, 2); !errors.Is(err, ErrChainBroken) {
			t.Errorf("%s covers the gap: %v", name, err)
		}
	}
	// A denied record is no first decision for a later repeat to match.
	denied := &Record{Action: ActionCollectorRequest, Outcome: OutcomeDenied, CollectorSeq: 1, Verified: testAdmin()}
	repeat := &Record{Action: ActionCollectorRequest, Outcome: OutcomeAllowed, CollectorSeq: 2, Verified: testAdmin(), RepeatOf: 1}
	if err := VerifyCollectorSeq([]*Record{start, denied, repeat}, 0, 2); !errors.Is(err, ErrChainBroken) {
		t.Errorf("a repeat matched a denial: %v", err)
	}
}

// TestRepeatDoesNotReachAcrossAReset (A6's mutant on #187): the first
// decisions are per epoch. A repeat in the new epoch naming a number that
// was an admin acceptance before the reset, and is a run after it, does
// not match the old acceptance.
func TestRepeatDoesNotReachAcrossAReset(t *testing.T) {
	node := Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"}
	collector := Actor{Type: authz.PrincipalSchedule, ID: "sch-ser-751-feeder-3", Role: authz.RoleCollector}
	high := uint64(1)
	recs := seqRecords(t, []Record{
		{Actor: Actor{Type: authz.PrincipalSystem, ID: "node"}, Action: ActionAuditChainStart, Outcome: OutcomeInfo},
		{Actor: node, Action: ActionCollectorInstallKey, Outcome: OutcomeInfo, InstallKeyID: "ik-old"},
		{Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed, CorrelationID: "req-1", CollectorSeq: 1, Verified: testAdmin()},
		{Actor: node, Action: ActionCollectorSeqReset, Outcome: OutcomeInfo, InstallKeyID: "ik-new", PreviousHigh: &high},
		{Actor: collector, Action: ActionCollectorRequest, Outcome: OutcomeAllowed, CorrelationID: "req-run", CollectorSeq: 1},
		{Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed, CorrelationID: "req-1", CollectorSeq: 2, Verified: testAdmin(), RepeatOf: 1},
	})
	if err := VerifyCollectorSeq(recs, 0, 2); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("got %v, want a broken chain", err)
	}
}
