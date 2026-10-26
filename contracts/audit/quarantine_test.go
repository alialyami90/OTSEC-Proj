package audit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/authz"
)

// The 0.3 quarantine actions (P3-A5, A1 D3-1).

func exported(first, last, items uint64) Record {
	return Record{Actor: nodeActor, Action: ActionQuarantineExported, Outcome: OutcomeInfo, Target: &Target{AssetID: suspendedAsset},
		Quarantine: &Quarantine{ManifestSHA256: strings.Repeat("a", 64), FirstSeq: first, LastSeq: last, Items: items}}
}

func cleared(outcome Outcome, reason string) Record {
	r := exported(3, 10, 8)
	r.Action, r.Outcome, r.ReasonCode = ActionQuarantineCleared, outcome, reason
	r.Quarantine.ClearSHA256, r.Quarantine.RequestedBy = strings.Repeat("b", 64), "admin@site-a"
	return r
}

func TestQuarantineRecordsValidate(t *testing.T) {
	var (
		goodExport = exported(3, 10, 8)
		goodGaps   = exported(3, 10, 2) // seqs removed by an earlier clear leave gaps
		goodOne    = exported(7, 7, 1)
		goodClear  = cleared(OutcomeSucceeded, "")
		goodStale  = cleared(OutcomeInfo, ReasonAlreadyCleared)
	)
	parsed(t, goodExport, goodGaps, goodOne, goodClear, goodStale)
	withBase := func(r Record) Record {
		r.Contract, r.NodeID, r.Seq, r.PrevHash, r.Time = ContractID, "site-a-node-1", 2, strings.Repeat("0", 63)+"1", baseTime()
		return r
	}
	mut := func(r Record, f func(*Record)) Record {
		r = withBase(r)
		q, tg := *r.Quarantine, *r.Target // a case changes its own copies only
		r.Quarantine, r.Target = &q, &tg
		f(&r)
		return r
	}
	bad := map[string]Record{
		"export without quarantine":   mut(goodExport, func(r *Record) { r.Quarantine = nil }),
		"export without asset":        mut(goodExport, func(r *Record) { r.Target = nil }),
		"export on a malformed asset": mut(goodExport, func(r *Record) { r.Target.AssetID = "ASSET" }),
		"export by an admin":          mut(goodExport, func(r *Record) { r.Actor = Actor{Type: authz.PrincipalHuman, ID: "admin@site-a"} }),
		"export succeeded":            mut(goodExport, func(r *Record) { r.Outcome = OutcomeSucceeded }),
		"export short manifest hash":  mut(goodExport, func(r *Record) { r.Quarantine.ManifestSHA256 = strings.Repeat("a", 63) }),
		"export upper-case hash":      mut(goodExport, func(r *Record) { r.Quarantine.ManifestSHA256 = strings.Repeat("A", 64) }),
		"export from seq 0":           mut(goodExport, func(r *Record) { r.Quarantine.FirstSeq = 0 }),
		"export range reversed":       mut(goodExport, func(r *Record) { r.Quarantine.FirstSeq, r.Quarantine.LastSeq = 10, 3 }),
		"export no items":             mut(goodExport, func(r *Record) { r.Quarantine.Items = 0 }),
		"export more items than seqs": mut(goodExport, func(r *Record) { r.Quarantine.Items = 9 }),
		"export with a clear hash":    mut(goodExport, func(r *Record) { r.Quarantine.ClearSHA256 = strings.Repeat("b", 64) }),
		"export with requested_by":    mut(goodExport, func(r *Record) { r.Quarantine.RequestedBy = "admin@site-a" }),
		"clear without clear hash":    mut(goodClear, func(r *Record) { r.Quarantine.ClearSHA256 = "" }),
		"clear without requested_by":  mut(goodClear, func(r *Record) { r.Quarantine.RequestedBy = "" }),
		"clear bad requested_by":      mut(goodClear, func(r *Record) { r.Quarantine.RequestedBy = "admin site a" }),
		"clear by an admin":           mut(goodClear, func(r *Record) { r.Actor = Actor{Type: authz.PrincipalHuman, ID: "admin@site-a"} }),
		"clear info without reason":   mut(goodClear, func(r *Record) { r.Outcome = OutcomeInfo }),
		"clear info other reason":     mut(goodClear, func(r *Record) { r.Outcome, r.ReasonCode = OutcomeInfo, "stale" }),
		"clear succeeded with reason": mut(goodClear, func(r *Record) { r.ReasonCode = ReasonAlreadyCleared }),
		"clear failed":                mut(goodClear, func(r *Record) { r.Outcome, r.ReasonCode = OutcomeFailed, "discard_failed" }),
		"clear range reversed":        mut(goodClear, func(r *Record) { r.Quarantine.FirstSeq, r.Quarantine.LastSeq = 10, 3 }),
		"quarantine on another":       mut(goodExport, func(r *Record) { r.Action = ActionAssetSuspensionClear }),
		"export stamped 0.2":          mut(goodExport, func(r *Record) { r.Contract = "otsec.audit/0.2" }),
		"clear stamped 0.2":           mut(goodClear, func(r *Record) { r.Contract = "otsec.audit/0.2" }),
	}
	for name, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A quarantine field on a non-quarantine action is refused too.
	other := withBase(decided(1))
	other.Quarantine = &Quarantine{ManifestSHA256: strings.Repeat("a", 64), FirstSeq: 1, LastSeq: 1, Items: 1}
	if err := other.Validate(); err == nil {
		t.Error("quarantine on collector.request accepted")
	}
	// A 0.2 record carrying the 0.3 field is refused when parsed.
	b, _ := json.Marshal(func() Record {
		r := withBase(decided(1))
		r.Contract = "otsec.audit/0.2"
		r.Quarantine = other.Quarantine
		return r
	}())
	if _, err := ParseRecord(b); !errors.Is(err, ErrRecordRejected) {
		t.Fatalf("0.2 record with quarantine: %v", err)
	}
}
