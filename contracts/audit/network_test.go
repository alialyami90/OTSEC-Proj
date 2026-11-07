package audit

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/authz"
)

// The network test values (0.12). The sensor is C7's test sensor. The
// digests are fixed strings, not of any stored document.
const testSensor = "5a1f0c3e-2b4d-4e6f-8a9b-0c1d2e3f4a5b"

var (
	testDraft1   = "sha256:" + strings.Repeat("a", 64)
	testDraft2   = "sha256:" + strings.Repeat("b", 64)
	testAccepted = "sha256:" + strings.Repeat("c", 64) // the draft with the person's writers added
	testOldKeys  = "sha256:" + strings.Repeat("d", 64)
)

// testKeyEntries is the key set the collector names in these tests: the
// test admin key, allowed both baseline acknowledgements.
func testKeyEntries(kinds ...authz.RequestKind) []authz.AdminKeyEntry {
	if kinds == nil {
		kinds = []authz.RequestKind{authz.KindNodeBaselineAck, authz.KindNodeNetworkBaselineAck}
	}
	kinds = slices.Clone(kinds)
	slices.Sort(kinds)
	return []authz.AdminKeyEntry{{KeyID: "ed25519-183d5080d1a2ef2b", Principal: "admin@site-a", Status: authz.KeyActive, Kinds: kinds}}
}

var testKeysDigest = authz.AdminKeysDigest(testKeyEntries())

// netRec is a 0.12 record of the node about testSensor.
func netRec(seq uint64, action Action, reason string) *Record {
	return &Record{Contract: ReaderID, NodeID: "site-a-node-1", Seq: seq, PrevHash: strings.Repeat("6", 64),
		Time: at("2026-11-10T12:00:00Z"), Actor: nodeActor, Action: action, Outcome: OutcomeInfo, ReasonCode: reason,
		Target: &Target{SensorID: testSensor}}
}

// draftRec is config.baseline_recorded of the learner's frozen draft.
func draftRec(seq uint64, digest, previous string, version int) *Record {
	r := netRec(seq, ActionConfigBaselineRecorded, "")
	r.CorrelationID = strings.TrimPrefix(digest, "sha256:")
	r.Config = &Config{Kind: authz.BaselineNetwork, BaselineDigest: digest, PreviousDigest: previous, BaselineVersion: version}
	return r
}

// netAckRun is the collector's 0.12 acceptance of a node.network_baseline_ack
// (decision), under testKeysDigest, and the node's acknowledgement of
// baseline built from draft.
func netAckRun(seq, decision uint64, draft, baseline, previous string) []*Record {
	v := testAdmin()
	v.Kind, v.KeysDigest = authz.KindNodeNetworkBaselineAck, testKeysDigest
	accept := &Record{Contract: ReaderID, NodeID: "site-a-node-1", Seq: seq, PrevHash: strings.Repeat("6", 64),
		Time: at("2026-11-10T12:00:00Z"), Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed,
		CorrelationID: "req-net-ack", CollectorSeq: decision, Verified: v}
	ack := &Record{Contract: ReaderID, NodeID: "site-a-node-1", Seq: seq + 1, PrevHash: strings.Repeat("6", 64),
		Time: at("2026-11-10T12:00:01Z"), Actor: adminActor, Action: ActionConfigBaselineAcknowledge, Outcome: OutcomeSucceeded,
		Target: &Target{SensorID: testSensor}, CorrelationID: "req-net-ack",
		Config: &Config{DecisionSeq: decision, PayloadSHA256: v.PayloadSHA256, Kind: authz.BaselineNetwork,
			BaselineDigest: baseline, DraftDigest: draft, PreviousDigest: previous}}
	return []*Record{accept, ack}
}

// keysRec is the node's policy.apply admin_keys of entries.
func keysRec(seq uint64, previous string, entries []authz.AdminKeyEntry) *Record {
	r := netRec(seq, ActionPolicyApply, ReasonAdminKeys)
	r.Target = nil
	r.AdminKeys = &AdminKeys{Digest: authz.AdminKeysDigest(entries), PreviousDigest: previous, Keys: entries}
	return r
}

func retiredRec(seq uint64, reason string, version int, digest string, cursor uint64) *Record {
	r := netRec(seq, ActionConfigLearnerRetired, reason)
	r.Config = &Config{Kind: authz.BaselineNetwork, BaselineVersion: version, BaselineDigest: digest, CursorSeq: cursor}
	return r
}

// moveRec is a store.retention_moved of testSensor's alert stream with a
// retention of seven days.
func moveRec(seq uint64, bound string, from, to uint64, wall, cutoff, previous string) *Record {
	r := netRec(seq, ActionStoreRetentionMoved, "")
	r.Retention = &Retention{Stream: AlertStreamPrefix + testSensor, FromSeq: from, ToSeq: to, RetentionS: 7 * 24 * 3600,
		WallUTC: wall, CutoffUTC: cutoff, PreviousCutoffUTC: previous, Bound: bound}
	return r
}

// The writer stamp stays at 0.11 while this package reads 0.12 (D4-69):
// the node's B5 item 7 change moves it, and changes this test, in the same
// change that writes policy.apply admin_keys and verified.keys_digest.
func TestWriterStampStays011(t *testing.T) {
	if ContractID != "otsec.audit/0.11" {
		t.Fatalf("ContractID is %s: the writer stamp moves only with the node change that writes 0.12 records", ContractID)
	}
	if ReaderID != "otsec.audit/0.12" {
		t.Fatalf("ReaderID is %s", ReaderID)
	}
}

// networkGood is one valid record of each new action and kind, and of each
// new field.
func networkGood() map[string]*Record {
	verified := netAckRun(30, 12, testDraft1, testAccepted, "")[0]
	return map[string]*Record{
		"draft, first":              draftRec(5, testDraft1, "", 1),
		"draft, a re-learn":         draftRec(5, testDraft2, testDraft1, 2),
		"acknowledged":              netAckRun(30, 12, testDraft1, testAccepted, "")[1],
		"acknowledged, no writers":  netAckRun(30, 12, testDraft1, testDraft1, "")[1],
		"verified with keys_digest": verified,
		"learner acknowledged":      retiredRec(40, ReasonLearnerAcknowledged, 1, testAccepted, 977),
		"learner stopped":           retiredRec(40, ReasonLearnerStopped, 2, "", 0),
		"retention created":         moveRec(50, BoundCreated, 5, 5, "2026-11-10T00:00:00Z", "2026-11-09T23:00:00Z", ""),
		"retention moved":           moveRec(51, BoundWall, 5, 12, "2026-11-17T06:00:00Z", "2026-11-10T05:00:00Z", "2026-11-09T23:00:00Z"),
		"admin keys, first":         keysRec(60, "", testKeyEntries()),
		"admin keys, a change":      keysRec(60, testOldKeys, testKeyEntries()),
	}
}

func TestNetworkRecordsValid(t *testing.T) {
	for name, r := range networkGood() {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Every 0.12 record and field is refused on a record stamped 0.11.
func TestNetworkRecordsStamped011(t *testing.T) {
	for name, r := range networkGood() {
		r.Contract = "otsec.audit/0.11"
		if err := r.Validate(); err == nil {
			t.Errorf("%s stamped 0.11: accepted", name)
		}
	}
	// A 0.11 acceptance without keys_digest still passes.
	r := netAckRun(30, 12, testDraft1, testAccepted, "")[0]
	r.Contract, r.Verified.KeysDigest = "otsec.audit/0.11", ""
	if err := r.Validate(); err != nil {
		t.Fatalf("0.11 acceptance: %v", err)
	}
}

func TestNetworkFieldPlacement(t *testing.T) {
	bad := map[string]*Record{
		"retention on service.start": func() *Record {
			r := netRec(70, ActionServiceStart, "")
			r.Target, r.Retention = nil, moveRec(0, BoundCreated, 5, 5, "2026-11-10T00:00:00Z", "2026-11-09T23:00:00Z", "").Retention
			return r
		}(),
		"retention on policy.apply admin_keys": func() *Record {
			r := keysRec(70, "", testKeyEntries())
			r.Retention = moveRec(0, BoundCreated, 5, 5, "2026-11-10T00:00:00Z", "2026-11-09T23:00:00Z", "").Retention
			return r
		}(),
		"store.retention_moved without retention": func() *Record {
			r := moveRec(70, BoundCreated, 5, 5, "2026-11-10T00:00:00Z", "2026-11-09T23:00:00Z", "")
			r.Retention = nil
			return r
		}(),
		"sensor_id on service.start": func() *Record { return netRec(70, ActionServiceStart, "") }(),
		"sensor_id on an event baseline record": func() *Record {
			r := draftRec(5, testDraft1, "", 1)
			r.Config.Kind = authz.BaselineEvent
			return r
		}(),
		"sensor_id beside an asset on a detection": func() *Record {
			r := configChain()[3]
			r.Contract = ReaderID
			r.Target.SensorID = testSensor
			return r
		}(),
		"sensor_id on a collector request": func() *Record {
			r := netAckRun(30, 12, testDraft1, testAccepted, "")[0]
			r.Target = &Target{SensorID: testSensor}
			return r
		}(),
		"network draft with an asset too": func() *Record {
			r := draftRec(5, testDraft1, "", 1)
			r.Target.AssetID = testAsset
			return r
		}(),
		"network draft with neither": func() *Record {
			r := draftRec(5, testDraft1, "", 1)
			r.Target = nil
			return r
		}(),
		"network draft with an asset only": func() *Record {
			r := draftRec(5, testDraft1, "", 1)
			r.Target = &Target{AssetID: testAsset}
			return r
		}(),
		"network acknowledgement with an asset too": func() *Record {
			r := netAckRun(30, 12, testDraft1, testAccepted, "")[1]
			r.Target.AssetID = testAsset
			return r
		}(),
		"network acknowledgement with neither": func() *Record {
			r := netAckRun(30, 12, testDraft1, testAccepted, "")[1]
			r.Target = &Target{}
			return r
		}(),
		"retirement with an asset": func() *Record {
			r := retiredRec(40, ReasonLearnerStopped, 2, "", 0)
			r.Target = &Target{AssetID: testAsset}
			return r
		}(),
		"retention with an asset too": func() *Record {
			r := moveRec(50, BoundCreated, 5, 5, "2026-11-10T00:00:00Z", "2026-11-09T23:00:00Z", "")
			r.Target.AssetID = testAsset
			return r
		}(),
		"uppercase sensor": func() *Record {
			r := draftRec(5, testDraft1, "", 1)
			r.Target.SensorID = strings.ToUpper(testSensor)
			return r
		}(),
		"0.12 acceptance without keys_digest": func() *Record {
			r := netAckRun(30, 12, testDraft1, testAccepted, "")[0]
			r.Verified.KeysDigest = ""
			return r
		}(),
		"0.12 repeat without keys_digest": func() *Record {
			r := netAckRun(30, 12, testDraft1, testAccepted, "")[0]
			r.Verified.KeysDigest, r.RepeatOf, r.CollectorSeq = "", 12, 14
			return r
		}(),
		"keys_digest bare hex": func() *Record {
			r := netAckRun(30, 12, testDraft1, testAccepted, "")[0]
			r.Verified.KeysDigest = testKeysDigest[7:]
			return r
		}(),
		"keys_digest on claimed": func() *Record {
			r := netAckRun(30, 12, testDraft1, testAccepted, "")[0]
			r.Outcome, r.CollectorSeq, r.Claimed, r.Verified = OutcomeInfo, 0, r.Verified, nil
			return r
		}(),
		"admin_keys on another policy.apply": func() *Record {
			r := keysRec(60, "", testKeyEntries())
			r.ReasonCode = "asset_controls"
			return r
		}(),
		"policy.apply admin_keys without the list": func() *Record {
			r := keysRec(60, "", testKeyEntries())
			r.AdminKeys = nil
			return r
		}(),
		"admin_keys on service.start": func() *Record {
			r := keysRec(60, "", testKeyEntries())
			r.Action, r.ReasonCode = ActionServiceStart, ""
			return r
		}(),
		"draft_digest on an event acknowledgement": func() *Record {
			r := ackRun(testAsset, 7, authz.BaselineConfiguration, testBaseline, "", OutcomeSucceeded)[1]
			r.Contract, r.Config.DraftDigest = ReaderID, testDraft1
			return r
		}(),
		"draft_digest on a recorded draft": func() *Record {
			r := draftRec(5, testDraft1, "", 1)
			r.Config.DraftDigest = testDraft1
			return r
		}(),
		"cursor_seq on a recorded draft": func() *Record {
			r := draftRec(5, testDraft1, "", 1)
			r.Config.CursorSeq = 9
			return r
		}(),
		"kind network on a detection": func() *Record {
			r := configChain()[3]
			r.Contract, r.Config.Kind, r.Target = ReaderID, authz.BaselineNetwork, &Target{SensorID: testSensor}
			return r
		}(),
		"kind network on a checkpoint": func() *Record {
			r := draftRec(5, testDraft1, "", 1)
			r.Action, r.Outcome, r.ReasonCode = ActionConfigCheckpointNotRestored, OutcomeWarning, ReasonCheckpointCorrupt
			r.Config = &Config{Kind: authz.BaselineNetwork, CheckpointHalf: CheckpointLearner, CheckpointSeq: 4, BaselineVersion: 1}
			r.CorrelationID = CheckpointCorrelationID(CheckpointLearner, 4)
			return r
		}(),
		"network acknowledgement without draft_digest": func() *Record {
			r := netAckRun(30, 12, testDraft1, testAccepted, "")[1]
			r.Config.DraftDigest = ""
			return r
		}(),
		"network acknowledgement draft bare hex": func() *Record {
			r := netAckRun(30, 12, testDraft1, testAccepted, "")[1]
			r.Config.DraftDigest = testDraft1[7:]
			return r
		}(),
		"network acknowledgement by the node": func() *Record {
			r := netAckRun(30, 12, testDraft1, testAccepted, "")[1]
			r.Actor = nodeActor
			return r
		}(),
	}
	for name, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRetentionFields(t *testing.T) {
	move := func() *Record {
		return moveRec(51, BoundWall, 5, 12, "2026-11-17T06:00:00Z", "2026-11-10T05:00:00Z", "2026-11-09T23:00:00Z")
	}
	created := func() *Record {
		return moveRec(50, BoundCreated, 5, 5, "2026-11-10T00:00:00Z", "2026-11-09T23:00:00Z", "")
	}
	for _, b := range []string{BoundWall, BoundMonotonic, BoundStart} {
		r := move()
		r.Retention.Bound = b
		if err := r.Validate(); err != nil {
			t.Errorf("bound %s: %v", b, err)
		}
	}
	bad := map[string]*Record{
		"a move that passes nothing": func() *Record { r := move(); r.Retention.ToSeq = 5; return r }(),
		"a move backwards":           func() *Record { r := move(); r.Retention.ToSeq = 4; return r }(),
		"a move without a previous cutoff": func() *Record {
			r := move()
			r.Retention.PreviousCutoffUTC = ""
			return r
		}(),
		"created with a previous cutoff": func() *Record {
			r := created()
			r.Retention.PreviousCutoffUTC = "2026-11-09T22:00:00Z"
			return r
		}(),
		"created that moves":                   func() *Record { r := created(); r.Retention.ToSeq = 6; return r }(),
		"an unknown bound":                     func() *Record { r := move(); r.Retention.Bound = "manual"; return r }(),
		"no bound":                             func() *Record { r := move(); r.Retention.Bound = ""; return r }(),
		"another sensor's stream":              func() *Record { r := move(); r.Retention.Stream = AlertStreamPrefix + testAsset; return r }(),
		"the observation stream":               func() *Record { r := move(); r.Retention.Stream = "network-observation/" + testSensor; return r }(),
		"no retention":                         func() *Record { r := move(); r.Retention.RetentionS = 0; return r }(),
		"a wall time with an offset":           func() *Record { r := move(); r.Retention.WallUTC = "2026-11-17T09:00:00+03:00"; return r }(),
		"a cutoff that is not a time":          func() *Record { r := move(); r.Retention.CutoffUTC = "yesterday"; return r }(),
		"a previous cutoff that is not a time": func() *Record { r := move(); r.Retention.PreviousCutoffUTC = "2026-11-09"; return r }(),
		"by a person":                          func() *Record { r := move(); r.Actor = adminActor; return r }(),
		"as succeeded":                         func() *Record { r := move(); r.Outcome = OutcomeSucceeded; return r }(),
		"with a reason code":                   func() *Record { r := move(); r.ReasonCode = "hourly"; return r }(),
		"with config": func() *Record {
			r := move()
			r.Config = &Config{Kind: authz.BaselineNetwork}
			return r
		}(),
		"without a target": func() *Record { r := move(); r.Target = nil; return r }(),
	}
	for name, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLearnerRetiredFields(t *testing.T) {
	ack := func() *Record { return retiredRec(40, ReasonLearnerAcknowledged, 1, testAccepted, 977) }
	bad := map[string]*Record{
		"acknowledged without a digest": func() *Record { r := ack(); r.Config.BaselineDigest = ""; return r }(),
		"stopped with a digest":         func() *Record { r := ack(); r.ReasonCode = ReasonLearnerStopped; return r }(),
		"an unknown reason":             func() *Record { r := ack(); r.ReasonCode = "expired"; return r }(),
		"no reason":                     func() *Record { r := ack(); r.ReasonCode = ""; return r }(),
		"version 0":                     func() *Record { r := ack(); r.Config.BaselineVersion = 0; return r }(),
		"kind event":                    func() *Record { r := ack(); r.Config.Kind = authz.BaselineEvent; return r }(),
		"no kind":                       func() *Record { r := ack(); r.Config.Kind = ""; return r }(),
		"with a draft digest":           func() *Record { r := ack(); r.Config.DraftDigest = testDraft1; return r }(),
		"with a previous digest":        func() *Record { r := ack(); r.Config.PreviousDigest = testDraft1; return r }(),
		"with a decision":               func() *Record { r := ack(); r.Config.DecisionSeq = 12; return r }(),
		"with a checkpoint":             func() *Record { r := ack(); r.Config.CheckpointSeq = 4; return r }(),
		"by a person":                   func() *Record { r := ack(); r.Actor = adminActor; return r }(),
		"as a warning":                  func() *Record { r := ack(); r.Outcome = OutcomeWarning; return r }(),
		"without config":                func() *Record { r := ack(); r.Config = nil; return r }(),
	}
	for name, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAdminKeysFields(t *testing.T) {
	keys := func() *Record { return keysRec(60, testOldKeys, testKeyEntries()) }
	bad := map[string]*Record{
		"digest of other keys": func() *Record {
			r := keys()
			r.AdminKeys.Digest = authz.AdminKeysDigest(testKeyEntries(authz.KindNodeBaselineAck))
			return r
		}(),
		"no keys":            func() *Record { r := keys(); r.AdminKeys.Keys = nil; return r }(),
		"no digest":          func() *Record { r := keys(); r.AdminKeys.Digest = ""; return r }(),
		"previous is itself": func() *Record { r := keys(); r.AdminKeys.PreviousDigest = r.AdminKeys.Digest; return r }(),
		"previous bare hex":  func() *Record { r := keys(); r.AdminKeys.PreviousDigest = testOldKeys[7:]; return r }(),
		"by a person":        func() *Record { r := keys(); r.Actor = adminActor; return r }(),
		"as succeeded":       func() *Record { r := keys(); r.Outcome = OutcomeSucceeded; return r }(),
		"an unknown key kind": func() *Record {
			r := keys()
			r.AdminKeys.Keys = []authz.AdminKeyEntry{{KeyID: "ed25519-183d5080d1a2ef2b", Principal: "admin@site-a", Status: authz.KeyActive, Kinds: []authz.RequestKind{"run"}}}
			r.AdminKeys.Digest = authz.AdminKeysDigest(r.AdminKeys.Keys)
			return r
		}(),
	}
	for name, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// netChain is a valid 0.12 run: the key set, the draft, the acceptance
// and acknowledgement, the learner's retirement, and two retention chains
// on one stream, each begun by its own created record. The first created
// cutoff is the commit time of an alert younger than the retention (D6).
func netChain() []*Record {
	recs := []*Record{
		keysRec(2, "", testKeyEntries()),
		draftRec(3, testDraft1, "", 1),
	}
	recs = append(recs, netAckRun(4, 12, testDraft1, testAccepted, "")...)
	return append(recs,
		retiredRec(6, ReasonLearnerAcknowledged, 1, testAccepted, 977),
		moveRec(7, BoundCreated, 5, 5, "2026-11-10T00:00:00Z", "2026-11-09T23:00:00Z", ""),
		moveRec(8, BoundWall, 5, 12, "2026-11-17T06:00:00Z", "2026-11-10T05:00:00Z", "2026-11-09T23:00:00Z"),
		moveRec(9, BoundMonotonic, 12, 20, "2026-11-17T08:00:00Z", "2026-11-10T06:30:00Z", "2026-11-10T05:00:00Z"),
		// A forward target was added and removed: the consumer starts again
		// ahead of the last move.
		moveRec(10, BoundCreated, 31, 31, "2026-11-20T00:00:00Z", "2026-11-12T00:00:00Z", ""),
		moveRec(11, BoundWall, 31, 40, "2026-11-20T03:00:00Z", "2026-11-13T02:00:00Z", "2026-11-12T00:00:00Z"),
	)
}

func TestNetworkChainVerifies(t *testing.T) {
	recs := netChain()
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("record %d: %v", r.Seq, err)
		}
	}
	if err := VerifyConfig(recs); err != nil {
		t.Fatal(err)
	}
	// A re-learn: version 2 replaces the draft, and is acknowledged with
	// the first acknowledgement as its previous.
	more := append(netChain(), draftRec(12, testDraft2, testDraft1, 2))
	more = append(more, netAckRun(13, 13, testDraft2, testDraft2, testAccepted)...)
	more = append(more, retiredRec(15, ReasonLearnerAcknowledged, 2, testDraft2, 1400))
	if err := VerifyConfig(more); err != nil {
		t.Fatalf("re-learn: %v", err)
	}
}

func TestNetworkChainBreaks(t *testing.T) {
	cases := map[string]func() []*Record{
		"an acknowledgement of a draft that is not the latest": func() []*Record {
			recs := []*Record{keysRec(2, "", testKeyEntries()), draftRec(3, testDraft1, "", 1), draftRec(4, testDraft2, testDraft1, 2)}
			return append(recs, netAckRun(5, 12, testDraft1, testAccepted, "")...)
		},
		"an acknowledgement before any draft": func() []*Record {
			return append([]*Record{keysRec(2, "", testKeyEntries())}, netAckRun(4, 12, testDraft1, testAccepted, "")...)
		},
		"a gap between two moves": func() []*Record {
			recs := netChain()
			recs[7].Retention.FromSeq = 13
			return recs
		},
		"an overlap between two moves": func() []*Record {
			recs := netChain()
			recs[7].Retention.FromSeq = 11
			return recs
		},
		"a move with no created record before it": func() []*Record {
			recs := netChain()
			return append(recs[:5:5], recs[6:]...)
		},
		"a move that doesn't follow the latest created record": func() []*Record {
			recs := netChain()
			recs[9].Retention.FromSeq = 20
			return recs
		},
		"a previous cutoff that is not the record before's": func() []*Record {
			recs := netChain()
			recs[7].Retention.PreviousCutoffUTC = "2026-11-10T04:00:00Z"
			return recs
		},
		"a cutoff that doesn't advance": func() []*Record {
			recs := netChain()
			recs[7].Retention.CutoffUTC = "2026-11-10T05:00:00Z"
			return recs
		},
		"a cutoff later than the wall time less the retention": func() []*Record {
			recs := netChain()
			recs[7].Retention.CutoffUTC = "2026-11-10T08:00:01Z"
			return recs
		},
		"a retirement with no matching acknowledgement": func() []*Record {
			recs := netChain()
			recs[4].Config.BaselineDigest = testDraft2
			return recs
		},
		"a retirement before the acknowledgement": func() []*Record {
			recs := netChain()
			recs[2], recs[3], recs[4] = recs[4], recs[2], recs[3]
			return recs
		},
		"a second retirement of one run": func() []*Record {
			return append(netChain(), retiredRec(12, ReasonLearnerStopped, 1, "", 980))
		},
		"a decision applied before any admin_keys record": func() []*Record {
			recs := netChain()
			return recs[1:]
		},
		"a decision applied before the admin_keys record of its key set": func() []*Record {
			recs := netChain()
			recs[0], recs[1], recs[2], recs[3] = recs[1], recs[2], recs[3], recs[0]
			return recs
		},
		"a decision whose keys_digest is not the latest key set": func() []*Record {
			recs := netChain()
			other := keysRec(3, recs[0].AdminKeys.Digest, testKeyEntries(authz.KindNodeBaselineAck, authz.KindNodeChangeApproval, authz.KindNodeNetworkBaselineAck))
			return append([]*Record{recs[0], other}, recs[1:]...)
		},
		"a key set whose key may not sign the verified kind": func() []*Record {
			recs := netChain()
			recs[0] = keysRec(2, "", testKeyEntries(authz.KindNodeBaselineAck))
			recs[2].Verified.KeysDigest = recs[0].AdminKeys.Digest
			return recs
		},
		"a key set without the verified key": func() []*Record {
			recs := netChain()
			entries := []authz.AdminKeyEntry{{KeyID: "ed25519-9a7844a51ac7c94e", Principal: "bob@site-a", Status: authz.KeyActive,
				Kinds: []authz.RequestKind{authz.KindNodeNetworkBaselineAck}}}
			recs[0] = keysRec(2, "", entries)
			recs[2].Verified.KeysDigest = recs[0].AdminKeys.Digest
			return recs
		},
		"a first key set that names a previous one": func() []*Record {
			recs := netChain()
			recs[0].AdminKeys.PreviousDigest = testOldKeys
			return recs
		},
		"a key set whose previous is not the record before's": func() []*Record {
			recs := netChain()
			next := keysRec(12, testOldKeys, testKeyEntries(authz.KindNodeNetworkBaselineAck))
			return append(recs, next)
		},
		"a network acknowledgement after an acceptance of node.baseline_ack": func() []*Record {
			recs := netChain()
			recs[2].Verified.Kind = authz.KindNodeBaselineAck
			return recs
		},
		"a re-learn that skips a version": func() []*Record {
			return append(netChain(), draftRec(12, testDraft2, testDraft1, 3))
		},
	}
	for name, mk := range cases {
		recs := mk()
		for _, r := range recs {
			if err := r.Validate(); err != nil {
				t.Fatalf("%s: record %d does not validate: %v", name, r.Seq, err)
			}
		}
		if err := VerifyConfig(recs); !errors.Is(err, ErrChainBroken) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A view that starts after seq 1 accepts as given what it can't see: a
// move whose created record is before it, a retirement or acknowledgement
// whose acknowledgement or draft is before it, and a decision whose key set
// was recorded before it.
func TestNetworkChainFromView(t *testing.T) {
	recs := netChain()
	for name, view := range map[string][]*Record{
		"from the acknowledgement": recs[2:],
		"from the retirement":      recs[4:],
		"from a move":              recs[6:],
	} {
		if err := VerifyConfigFrom(view, view[0].Seq); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A view that holds the sensor's first draft still refuses an
	// acknowledgement of a draft never recorded.
	bad := []*Record{draftRec(3, testDraft1, "", 1)}
	bad = append(bad, netAckRun(4, 12, testDraft2, testAccepted, "")...)
	if err := VerifyConfigFrom(bad, 3); !errors.Is(err, ErrChainBroken) {
		t.Errorf("an unrecorded draft in a view holding the first: %v", err)
	}
}
