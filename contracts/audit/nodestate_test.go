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

// withKey puts a collector.install_key first, as a 0.2 node writes it
// before its first request, unless the chain already starts with one.
func withKey(recs []Record) []Record {
	if len(recs) > 0 && recs[0].Action == ActionCollectorInstallKey {
		return recs
	}
	return append([]Record{installKey("x25519-0000000000000000")}, recs...)
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
		if err := VerifyCollectorSeq(parsed(t, withKey(c.recs)...), c.after, c.through); err != nil {
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
		if err := VerifyCollectorSeq(parsed(t, withKey(c.recs)...), c.after, c.through); !errors.Is(err, ErrChainBroken) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// A6 on #105: with no trusted key before it, a reset cannot be told from
	// a restore that keeps the key, so it breaks the chain.
	if err := VerifyCollectorSeq(parsed(t, decided(1), reset(1, 1, k1), decided(1)), 0, 1); !errors.Is(err, ErrChainBroken) {
		t.Errorf("reset with no trusted key: got %v", err)
	}
}

func TestVerifySuspensions(t *testing.T) {
	const inv1, inv2 = "0f3e6c1a-8b2d-4e7f-9a15-6c4d2b8e0a71", "1a2b3c4d-8b2d-4e7f-9a15-6c4d2b8e0a71"
	open, err := VerifySuspensions(nil, parsed(t,
		suspend(asset.SuspendAuthFailed, "failed.auth_rejected", inv1),
		suspend(asset.SuspendUnexpectedLevel, "failed.unexpected_access_level", inv2),
		clearSusp(asset.SuspendAuthFailed, inv1),
		decided(1),
	))
	if err != nil {
		t.Fatal(err)
	}
	want := OpenSuspension{AssetID: suspendedAsset, Reason: asset.SuspendUnexpectedLevel, Ref: inv2, Code: "failed.unexpected_access_level"}
	if len(open) != 1 || open[0] != want {
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
		if _, err := VerifySuspensions(nil, parsed(t, recs...)); !errors.Is(err, ErrChainBroken) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// A node that prunes to a checkpoint verifies the tail from the checkpoint's
// open set: a clear of a suspension opened before it verifies, and the open
// set at the end is the next checkpoint (A5 on #105).
func TestVerifySuspensionsFromCheckpoint(t *testing.T) {
	const inv1, inv2 = "0f3e6c1a-8b2d-4e7f-9a15-6c4d2b8e0a71", "1a2b3c4d-8b2d-4e7f-9a15-6c4d2b8e0a71"
	checkpoint := []OpenSuspension{{AssetID: suspendedAsset, Reason: asset.SuspendAuthFailed, Ref: inv1, Code: "failed.auth_rejected"}}
	tail := parsed(t, clearSusp(asset.SuspendAuthFailed, inv1), suspend(asset.SuspendUnexpectedLevel, "failed.unexpected_access_level", inv2))
	if _, err := VerifySuspensions(nil, tail); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("tail without its checkpoint: %v", err)
	}
	open, err := VerifySuspensions(checkpoint, tail)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].Ref != inv2 {
		t.Fatalf("open after the tail: %+v", open)
	}
	if _, err := VerifySuspensions(checkpoint, parsed(t, suspend(asset.SuspendAuthFailed, "failed.auth_rejected", inv1))); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("suspend of one the checkpoint holds: %v", err)
	}
	if _, err := VerifySuspensions(append(checkpoint, checkpoint[0]), nil); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("a checkpoint holding one suspension twice: %v", err)
	}
	if open, err := VerifySuspensions(checkpoint, nil); err != nil || len(open) != 1 || open[0] != checkpoint[0] {
		t.Fatalf("empty tail: %+v, %v", open, err)
	}
}

// A chain verified window by window, with the SeqState carried between the
// windows, gives the result of the whole chain (A6 on #105).
func TestVerifyCollectorSeqFrom(t *testing.T) {
	const ka, kb, kc = "x25519-aaaaaaaaaaaaaaaa", "x25519-bbbbbbbbbbbbbbbb", "x25519-cccccccccccccccc"
	window := func(from SeqState, through uint64, recs ...Record) (SeqState, error) {
		t.Helper()
		return VerifyCollectorSeqFrom(parsed(t, recs...), from, through)
	}

	// A6's probe: a boundary between a reset and its acknowledgement.
	st, err := window(SeqState{}, 1, installKey(ka), decided(1), decided(2), decided(3), reset(3, 1, kb), decided(1))
	if err != nil {
		t.Fatal(err)
	}
	if want := (SeqState{After: 1, TrustedKey: ka, OpenResetKey: kb, ResetKeys: []string{kb}}); fmt.Sprint(st) != fmt.Sprint(want) {
		t.Fatalf("state after window 1: %+v", st)
	}
	st, err = window(st, 2, ack(kb), decided(2))
	if err != nil {
		t.Fatalf("window 2 after the split: %v", err)
	}
	if want := (SeqState{After: 2, TrustedKey: kb, ResetKeys: []string{kb}}); fmt.Sprint(st) != fmt.Sprint(want) {
		t.Fatalf("state after window 2: %+v", st)
	}

	// A6's probe: a restore that keeps the key, in a window that starts
	// after the collector.install_key record.
	st, err = window(SeqState{}, 1, installKey(ka), decided(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := window(st, 1, decided(2), reset(2, 1, ka), decided(1)); !errors.Is(err, ErrChainBroken) {
		t.Errorf("same-key reset in a later window: %v", err)
	}
	if err := VerifyCollectorSeq(parsed(t, decided(2), reset(2, 1, ka), decided(1)), 1, 1); !errors.Is(err, ErrChainBroken) {
		t.Errorf("same-key reset with no state: %v", err)
	}

	// A boundary between a reset and its first_seen record.
	st, err = window(SeqState{After: 1, TrustedKey: ka}, 0, reset(1, 1, kb))
	if err != nil || st.FirstSeen != 1 || st.After != 0 {
		t.Fatalf("window ending at the reset: %+v, %v", st, err)
	}
	if _, err := window(st, 1, decided(1)); err != nil {
		t.Errorf("first_seen in the next window: %v", err)
	}
	if _, err := window(st, 2, decided(2)); !errors.Is(err, ErrChainBroken) {
		t.Errorf("first record of the next window is not first_seen: %v", err)
	}

	// A reset key from an earlier window is never repeated.
	if _, err := window(SeqState{After: 1, TrustedKey: kc, ResetKeys: []string{kb, kc}}, 1, decided(2), reset(2, 1, kb), decided(1)); !errors.Is(err, ErrChainBroken) {
		t.Errorf("reset repeating an earlier window's key: %v", err)
	}

	broken := map[string]struct {
		from    SeqState
		through uint64
		recs    []Record
	}{
		"reset keeps the state's trusted key": {SeqState{After: 3, TrustedKey: ka}, 1, []Record{decided(4), reset(4, 1, ka), decided(1)}},
		"reset repeats the open reset's key":  {SeqState{After: 2, TrustedKey: ka, OpenResetKey: kb, ResetKeys: []string{kb}}, 1, []Record{decided(3), reset(3, 1, kb), decided(1)}},
		"install_key changes the state's key": {SeqState{After: 3, TrustedKey: ka}, 4, []Record{installKey(kc), decided(4)}},
		"install_key during an open reset":    {SeqState{After: 2, TrustedKey: ka, OpenResetKey: kb, ResetKeys: []string{kb}}, 3, []Record{installKey(kb), decided(3)}},
		"ack on another key":                  {SeqState{After: 2, TrustedKey: ka, OpenResetKey: kb, ResetKeys: []string{kb}}, 3, []Record{decided(3), ack(kc)}},
		"ack with nothing open":               {SeqState{After: 3, TrustedKey: ka}, 4, []Record{decided(4), ack(ka)}},
		"open key not among the reset keys":   {SeqState{After: 2, TrustedKey: ka, OpenResetKey: kb}, 3, []Record{decided(3)}},
		"through below the state's after":     {SeqState{After: 3, TrustedKey: ka}, 2, nil},
	}
	for name, c := range broken {
		if _, err := window(c.from, c.through, c.recs...); !errors.Is(err, ErrChainBroken) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// Every split of a chain into two windows gives what the whole chain gives:
// the same end state when it verifies, a break when it does not.
func TestVerifyCollectorSeqEverySplit(t *testing.T) {
	const ka, kb, kc = "x25519-aaaaaaaaaaaaaaaa", "x25519-bbbbbbbbbbbbbbbb", "x25519-cccccccccccccccc"
	// throughAt is the newest collector number of the current epoch after
	// the first n records: what the collector had reported by then.
	throughAt := func(recs []Record, n int) uint64 {
		var hi uint64
		for _, r := range recs[:n] {
			switch {
			case r.Action == ActionCollectorSeqReset:
				hi = 0
			case r.CollectorSeq > hi:
				hi = r.CollectorSeq
			}
		}
		return hi
	}
	chains := map[string]struct {
		recs []Record
		ok   bool
	}{
		"two resets": {[]Record{installKey(ka), decided(1), decided(2), reset(2, 1, kb), decided(1), ack(kb), decided(2),
			reset(2, 0, kc), ack(kc), decided(1)}, true},
		"same-key restore":       {[]Record{installKey(ka), decided(1), decided(2), reset(2, 1, ka), decided(1)}, false},
		"repeat of a reset key":  {[]Record{installKey(ka), decided(1), reset(1, 1, kb), decided(1), ack(kb), reset(1, 1, kb), decided(1)}, false},
		"gap after an ack":       {[]Record{installKey(ka), decided(1), reset(1, 1, kb), decided(1), ack(kb), decided(3)}, false},
		"restart with no reset":  {[]Record{installKey(ka), decided(1), decided(2), decided(1)}, false},
		"first_seen not first":   {[]Record{installKey(ka), decided(1), reset(1, 2, kb), decided(1), decided(2)}, false},
		"ack before its reset":   {[]Record{installKey(ka), decided(1), ack(kb), reset(1, 1, kb), decided(1)}, false},
		"key change at an ack":   {[]Record{installKey(ka), decided(1), reset(1, 1, kb), decided(1), ack(kb), installKey(kc)}, false},
		"window ends at a reset": {[]Record{installKey(ka), decided(1), reset(1, 1, kb)}, true},
	}
	for name, c := range chains {
		all := parsed(t, c.recs...)
		through := throughAt(c.recs, len(c.recs))
		whole, werr := VerifyCollectorSeqFrom(all, SeqState{}, through)
		if (werr == nil) != c.ok {
			t.Fatalf("%s whole: %v", name, werr)
		}
		for n := 0; n <= len(all); n++ {
			mid, err := VerifyCollectorSeqFrom(all[:n], SeqState{}, throughAt(c.recs, n))
			if err == nil {
				var end SeqState
				end, err = VerifyCollectorSeqFrom(all[n:], mid, through)
				if err == nil && fmt.Sprint(end) != fmt.Sprint(whole) {
					t.Errorf("%s split at %d: end %+v, whole %+v", name, n, end, whole)
				}
			}
			if (err == nil) != c.ok {
				t.Errorf("%s split at %d: %v, whole %v", name, n, err, werr)
			}
		}
	}
}
