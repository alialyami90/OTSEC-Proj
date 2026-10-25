package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
)

// The 0.2 node-state actions: collector.seq_reset, collector.seq_reset_ack,
// asset.suspend and asset.suspension_clear (docs/phase2/A3-c8-seq-reset.md).

var nodeActor = Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"}

const suspendedAsset = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"

func decided(n uint64) Record {
	return Record{Actor: Actor{Type: authz.PrincipalSchedule, ID: "sch-ser-751-feeder-3", Role: authz.RoleCollector},
		Action: ActionCollectorRequest, Outcome: OutcomeDenied, ReasonCode: string(authz.RefuseRateLimited),
		CorrelationID: fmt.Sprintf("req-%d", n), CollectorSeq: n}
}

func reset(previousHigh, firstSeen uint64, key string) Record {
	return Record{Actor: nodeActor, Action: ActionCollectorSeqReset, Outcome: OutcomeInfo,
		PreviousHigh: &previousHigh, FirstSeen: firstSeen, InstallKeyID: key}
}

func installKey(key string) Record {
	return Record{Actor: nodeActor, Action: ActionCollectorInstallKey, Outcome: OutcomeInfo, InstallKeyID: key}
}

func ack(key string) Record {
	return Record{Actor: nodeActor, Action: ActionCollectorSeqResetAck, Outcome: OutcomeInfo, InstallKeyID: key}
}

func suspend(reason asset.SuspensionReason, code, ref string) Record {
	return Record{Actor: nodeActor, Action: ActionAssetSuspend, Outcome: OutcomeInfo, Target: &Target{AssetID: suspendedAsset},
		Suspension: &Suspension{Reason: reason, Code: code}, CorrelationID: ref}
}

func clearSusp(reason asset.SuspensionReason, ref string) Record {
	return Record{Actor: nodeActor, Action: ActionAssetSuspensionClear, Outcome: OutcomeInfo, Target: &Target{AssetID: suspendedAsset},
		Suspension: &Suspension{Reason: reason}, CorrelationID: ref}
}

// parsed seals recs after a chain start and returns them parsed, without
// the start.
func parsed(t *testing.T, recs ...Record) []*Record {
	t.Helper()
	all := append([]Record{{Actor: Actor{Type: authz.PrincipalSystem, ID: "node"}, Action: ActionAuditChainStart, Outcome: OutcomeInfo}}, recs...)
	var out []*Record
	for _, b := range chain(t, all)[1:] {
		r, err := ParseRecord(b)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestNodeStateRecordsValidate(t *testing.T) {
	const key = "x25519-0123456789abcdef"
	var (
		goodReset      = reset(0, 1, key)
		goodResetByKey = reset(4, 0, key) // found by the key, before any reply
		goodInstallKey = installKey(key)
		goodAck        = ack(key)
		goodSuspend    = suspend(asset.SuspendAuthFailed, "failed.auth_rejected", "0f3e6c1a-8b2d-4e7f-9a15-6c4d2b8e0a71")
		goodOpSuspend  = suspend(asset.SuspendOperator, "", "admin@site-a")
		goodClear      = clearSusp(asset.SuspendAuthFailed, "0f3e6c1a-8b2d-4e7f-9a15-6c4d2b8e0a71")
	)
	good := []Record{goodReset, goodResetByKey, goodInstallKey, goodAck, goodSuspend, goodOpSuspend, goodClear}
	parsed(t, good...) // chain() parses each one
	withBase := func(r Record) Record {
		r.Contract, r.NodeID, r.Seq, r.PrevHash, r.Time = ContractID, "site-a-node-1", 2, strings.Repeat("0", 63)+"1", baseTime()
		return r
	}
	mut := func(r Record, f func(*Record)) Record { r = withBase(r); f(&r); return r }
	one := uint64(1)
	bad := map[string]Record{
		"reset without previous_high":   mut(goodReset, func(r *Record) { r.PreviousHigh = nil }),
		"reset without key":             mut(goodReset, func(r *Record) { r.InstallKeyID = "" }),
		"reset by a schedule":           mut(goodReset, func(r *Record) { r.Actor = decided(1).Actor }),
		"reset not info":                mut(goodReset, func(r *Record) { r.Outcome, r.ReasonCode = OutcomeFailed, "x" }),
		"reset with collector_seq":      mut(goodReset, func(r *Record) { r.CollectorSeq = 4 }),
		"ack without key":               mut(goodAck, func(r *Record) { r.InstallKeyID = "" }),
		"ack with previous_high":        mut(goodAck, func(r *Record) { r.PreviousHigh = &one }),
		"install_key without key":       mut(goodInstallKey, func(r *Record) { r.InstallKeyID = "" }),
		"install_key by a schedule":     mut(goodInstallKey, func(r *Record) { r.Actor = decided(1).Actor }),
		"suspend without code":          mut(goodSuspend, func(r *Record) { r.Suspension.Code = "" }),
		"suspend with a C1 code":        mut(goodSuspend, func(r *Record) { r.Suspension.Code = "auth-failed" }),
		"suspend with unknown reason":   mut(goodSuspend, func(r *Record) { r.Suspension = &Suspension{Reason: "made-up", Code: "failed.auth_rejected"} }),
		"suspend without asset":         mut(goodSuspend, func(r *Record) { r.Target = nil }),
		"suspend without ref":           mut(goodSuspend, func(r *Record) { r.CorrelationID = "" }),
		"operator suspend with code":    mut(goodOpSuspend, func(r *Record) { r.Suspension.Code = "failed.auth_rejected" }),
		"clear with code":               mut(goodClear, func(r *Record) { r.Suspension.Code = "failed.auth_rejected" }),
		"clear without suspension":      mut(goodClear, func(r *Record) { r.Suspension = nil }),
		"previous_high on another":      mut(decided(1), func(r *Record) { r.PreviousHigh = &one }),
		"first_seen on another":         mut(decided(1), func(r *Record) { r.FirstSeen = 1 }),
		"install_key_id on another":     mut(decided(1), func(r *Record) { r.InstallKeyID = "x25519-0123456789abcdef" }),
		"suspension on another":         mut(decided(1), func(r *Record) { r.Suspension = &Suspension{Reason: asset.SuspendOperator} }),
		"reset stamped 0.1":             mut(goodReset, func(r *Record) { r.Contract = "otsec.audit/0.1" }),
		"suspend stamped 0.1":           mut(goodSuspend, func(r *Record) { r.Contract = "otsec.audit/0.1" }),
		"clear by a human (file only)":  mut(goodClear, func(r *Record) { r.Actor = Actor{Type: authz.PrincipalHuman, ID: "admin@site-a"} }),
		"ack by a human (file only)":    mut(goodAck, func(r *Record) { r.Actor = Actor{Type: authz.PrincipalHuman, ID: "admin@site-a"} }),
		"suspend not info":              mut(goodSuspend, func(r *Record) { r.Outcome = OutcomeSucceeded }),
		"clear on a malformed asset id": mut(goodClear, func(r *Record) { r.Target.AssetID = "ASSET" }),
	}
	for name, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A 0.1 record carrying a 0.2 field is refused when parsed (strict
	// decoding of an earlier minor plus the field rule).
	b, _ := json.Marshal(mut(decided(1), func(r *Record) { r.Contract = "otsec.audit/0.1"; r.FirstSeen = 2 }))
	if _, err := ParseRecord(b); !errors.Is(err, ErrRecordRejected) {
		t.Fatalf("0.1 record with first_seen: %v", err)
	}
}

func TestVerifyCollectorSeqAcrossReset(t *testing.T) {
	const k1, k2 = "x25519-1111111111111111", "x25519-2222222222222222"
	ok := map[string]struct {
		recs           []Record
		after, through uint64
	}{
		"one reset":      {[]Record{decided(1), decided(2), decided(3), reset(3, 1, k1), decided(1), decided(2)}, 0, 2},
		"reset then ack": {[]Record{decided(1), reset(1, 1, k1), decided(1), ack(k1), decided(2)}, 0, 2},
		"two resets":     {[]Record{decided(1), reset(1, 1, k1), decided(1), decided(2), reset(2, 1, k2), ack(k2), decided(1)}, 0, 1},
		// Detected by the install key: the first reply seen is above the
		// old high, but the numbers before it in the new epoch are owed.
		"reset before any record": {[]Record{reset(0, 1, k1), decided(1)}, 0, 1},
		"from a verified point":   {[]Record{decided(5), reset(5, 1, k1), decided(1)}, 4, 1},
		// A6: a window that starts just before a reset has an empty epoch 1.
		"window starts at the reset": {[]Record{reset(5, 1, k1), decided(1)}, 5, 1},
		// A window inside epoch 2 with no reset in it is a plain window.
		"window inside epoch 2": {[]Record{decided(3), decided(4)}, 2, 4},
		// Found by the key before any request (A6 must 1): no first_seen.
		"reset found by the key":         {[]Record{installKey(k1), decided(1), reset(1, 0, k2), ack(k2), decided(1), decided(2)}, 0, 2},
		"trusted key carried by the ack": {[]Record{installKey(k1), decided(1), reset(1, 1, k2), decided(1), ack(k2), installKey(k2), decided(2)}, 0, 2},
		"a 0.1-style chain":              {[]Record{decided(1), decided(2)}, 0, 2},
	}
	for name, c := range ok {
		if err := VerifyCollectorSeq(parsed(t, c.recs...), c.after, c.through); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	broken := map[string]struct {
		recs           []Record
		after, through uint64
	}{
		"restart without a reset":         {[]Record{decided(1), decided(2), decided(1)}, 0, 2},
		"gap before the reset":            {[]Record{decided(1), decided(3), reset(3, 1, k1), decided(1)}, 0, 1},
		"previous_high above the records": {[]Record{decided(1), reset(2, 1, k1), decided(1)}, 0, 1},
		"previous_high below the records": {[]Record{decided(1), decided(2), reset(1, 1, k1), decided(1)}, 0, 1},
		"previous_high below after":       {[]Record{reset(2, 1, k1), decided(1)}, 4, 1},
		// Found by the key above the old high: 1..4 of the new collector
		// were never recorded.
		"numbers below first_seen":    {[]Record{decided(1), decided(2), reset(2, 5, k1), decided(5)}, 0, 5},
		"first record not first_seen": {[]Record{decided(1), reset(1, 1, k1), decided(2), decided(1)}, 0, 2},
		"first_seen never recorded":   {[]Record{decided(1), reset(1, 1, k1), reset(0, 1, k2), decided(1)}, 0, 1},
		"repeated install key":        {[]Record{decided(1), reset(1, 1, k1), decided(1), reset(1, 1, k1), decided(1)}, 0, 1},
		// A6 must 2: a reset that keeps the trusted key is not a reinstall,
		// including the first reset.
		"reset keeps the trusted key":    {[]Record{installKey(k1), decided(1), reset(1, 1, k1), decided(1)}, 0, 1},
		"key change without a reset":     {[]Record{installKey(k1), decided(1), installKey(k2), decided(2)}, 0, 2},
		"key change before the ack":      {[]Record{installKey(k1), decided(1), reset(1, 1, k2), decided(1), installKey(k2)}, 0, 1},
		"reset keeps the acked key":      {[]Record{decided(1), reset(1, 1, k1), decided(1), ack(k1), reset(1, 1, k1), decided(1)}, 0, 1},
		"numbers owed after a key reset": {[]Record{installKey(k1), decided(1), reset(1, 0, k2), decided(2)}, 0, 2},
		"ack without a reset":            {[]Record{decided(1), ack(k1)}, 0, 1},
		"ack on another key":             {[]Record{decided(1), reset(1, 1, k1), decided(1), ack(k2)}, 0, 1},
		"second ack":                     {[]Record{decided(1), reset(1, 1, k1), decided(1), ack(k1), ack(k1)}, 0, 1},
		"tail missing after a reset":     {[]Record{decided(1), reset(1, 1, k1), decided(1)}, 0, 2},
	}
	for name, c := range broken {
		if err := VerifyCollectorSeq(parsed(t, c.recs...), c.after, c.through); !errors.Is(err, ErrChainBroken) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestVerifySuspensions(t *testing.T) {
	const inv1, inv2 = "0f3e6c1a-8b2d-4e7f-9a15-6c4d2b8e0a71", "1a2b3c4d-8b2d-4e7f-9a15-6c4d2b8e0a71"
	open, err := VerifySuspensions(parsed(t,
		suspend(asset.SuspendAuthFailed, "failed.auth_rejected", inv1),
		suspend(asset.SuspendUnexpectedLevel, "failed.unexpected_access_level", inv2),
		clearSusp(asset.SuspendAuthFailed, inv1),
		decided(1),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].CorrelationID != inv2 {
		t.Fatalf("open after the clear: %+v", open)
	}
	for name, recs := range map[string][]Record{
		"clear with nothing set":  {clearSusp(asset.SuspendAuthFailed, inv1)},
		"clear on another ref":    {suspend(asset.SuspendAuthFailed, "failed.auth_rejected", inv1), clearSusp(asset.SuspendAuthFailed, inv2)},
		"clear on another reason": {suspend(asset.SuspendAuthFailed, "failed.auth_rejected", inv1), clearSusp(asset.SuspendUnexpectedLevel, inv1)},
		"clear twice": {suspend(asset.SuspendAuthFailed, "failed.auth_rejected", inv1),
			clearSusp(asset.SuspendAuthFailed, inv1), clearSusp(asset.SuspendAuthFailed, inv1)},
		"the same suspension twice": {suspend(asset.SuspendAuthFailed, "failed.auth_rejected", inv1),
			suspend(asset.SuspendAuthFailed, "failed.auth_rejected", inv1)},
	} {
		if _, err := VerifySuspensions(parsed(t, recs...)); !errors.Is(err, ErrChainBroken) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
