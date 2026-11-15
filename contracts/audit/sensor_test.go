package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/internal/strictjson"
)

// The sensor test values (0.13). The pins are fixed strings, not any key's.
var (
	testPinA    = "sha256:" + strings.Repeat("1", 64)
	testPinB    = "sha256:" + strings.Repeat("2", 64)
	testNodePin = "sha256:" + strings.Repeat("f", 64)
	// sensorKeySet is the key set the collector names: the test admin key,
	// allowed both sensor kinds.
	sensorKeySet = testKeyEntries(authz.KindNodeSensorEnrol, authz.KindNodeSensorRevoke)
)

// payloadOf is a test payload hash for decision d; no payload has it.
func payloadOf(d uint64) string { return fmt.Sprintf("%064x", d) }

func u64(n uint64) *uint64 { return &n }

// sensorAccept is the collector's acceptance (decision) of a sensor kind, as
// the node records it under C8-6.
func sensorAccept(seq, decision uint64, kind authz.RequestKind, gen, pin string) *Record {
	v := testAdmin()
	v.Kind, v.KeysDigest, v.PayloadSHA256 = kind, authz.AdminKeysDigest(sensorKeySet), payloadOf(decision)
	r := &Record{Contract: ReaderID, NodeID: "site-a-node-1", Seq: seq, PrevHash: strings.Repeat("6", 64),
		Time: at("2026-11-10T12:00:00Z"), Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed,
		CorrelationID: "req-sensor", CollectorSeq: decision, Verified: v,
		Target: &Target{SensorID: testSensor}, Sensor: &Sensor{Generation: gen, SensorSPKI: pin}}
	if kind == authz.KindNodeSensorRevoke {
		r.Sensor.Reason = string(authz.SensorRevokeCompromised)
	}
	return r
}

func enrolledRec(seq, decision uint64, gen string, reason authz.SensorEnrolReason, pin string) *Record {
	r := netRec(seq, ActionSensorEnrolled, "")
	r.Outcome = OutcomeSucceeded
	r.Sensor = &Sensor{DecisionSeq: decision, PayloadSHA256: payloadOf(decision), Generation: gen, SensorSPKI: pin,
		SensorAddress: "192.0.2.10:8443", NodeSPKI: testNodePin, NodeAddress: "192.0.2.1",
		NotAfter: "2027-11-10T00:00:00Z", Reason: string(reason)}
	return r
}

func revokedRec(seq, decision uint64, gen, pin string) *Record {
	r := netRec(seq, ActionSensorRevoked, "")
	r.Outcome = OutcomeSucceeded
	r.Sensor = &Sensor{DecisionSeq: decision, PayloadSHA256: payloadOf(decision), Generation: gen, SensorSPKI: pin,
		Reason: string(authz.SensorRevokeCompromised), AppliedAt: "2026-11-10T11:59:00.000000Z",
		Streams: &Streams{ObservationThroughSeq: u64(40), AlertThroughSeq: u64(7)}}
	return r
}

func refusedRec(seq uint64, code string) *Record {
	r := netRec(seq, ActionSensorLinkRefused, code)
	r.Outcome = OutcomeDenied
	r.Sensor = &Sensor{Generation: "2", Count: 3}
	return r
}

// sensorGood is one valid record of each form. These are the controls of
// the refusals below: each refused record differs from one of them in one
// field.
func sensorGood() map[string]*Record {
	prev := enrolledRec(6, 11, "2", authz.SensorEnrolRekey, testPinB)
	prev.Sensor.PreviousGeneration, prev.Sensor.PreviousSPKI = "1", testPinA
	unknown := enrolledRec(6, 11, "5", authz.SensorEnrolReplace, testPinB)
	unknown.Sensor.PreviousState = PreviousStateUnknown
	denied := enrolledRec(6, 11, "2", authz.SensorEnrolRenew, testPinB)
	denied.Outcome, denied.ReasonCode = OutcomeDenied, DeniedReason
	ipv6 := enrolledRec(4, 10, "1", authz.SensorEnrolNew, testPinA)
	ipv6.Sensor.SensorAddress, ipv6.Sensor.NodeAddress = "[2001:db8::10]:8443", "2001:db8::1"
	noLink := revokedRec(8, 12, "1", testPinA)
	noLink.Sensor.Streams = &Streams{}
	empty := revokedRec(8, 12, "1", testPinA)
	empty.Sensor.Streams = &Streams{ObservationThroughSeq: u64(0), AlertThroughSeq: u64(0)}
	voids := revokedRec(8, 12, "1", testPinA)
	voids.Sensor.SuspectFrom, voids.Sensor.BaselineDigest = "2026-11-09T00:00:00Z", testAccepted
	revokeReq := sensorAccept(7, 12, authz.KindNodeSensorRevoke, "1", testPinA)
	revokeReq.Sensor.SuspectFrom = "2026-11-09T00:00:00Z"
	repeat := sensorAccept(9, 13, authz.KindNodeSensorRevoke, "1", testPinA)
	repeat.RepeatOf, repeat.Verified.PayloadSHA256 = 12, payloadOf(12)
	return map[string]*Record{
		"enrolled, first":              enrolledRec(4, 10, "1", authz.SensorEnrolNew, testPinA),
		"enrolled, IPv6":               ipv6,
		"enrolled, previous":           prev,
		"enrolled, state unknown":      unknown,
		"enrolled, denied":             denied,
		"revoked, a link ended":        revokedRec(8, 12, "1", testPinA),
		"revoked, no link ended":       noLink,
		"revoked, both streams empty":  empty,
		"revoked, suspect and voids":   voids,
		"link_refused":                 refusedRec(9, RefusedRunForked),
		"collector.request, enrol":     sensorAccept(3, 10, authz.KindNodeSensorEnrol, "1", testPinA),
		"collector.request, revoke":    sensorAccept(7, 12, authz.KindNodeSensorRevoke, "1", testPinA),
		"collector.request, suspect":   revokeReq,
		"collector.request, a repeat":  repeat,
		"collector.request, info":      sensorInfo(),
		"collector.request, a network": netAckRun(30, 12, testDraft1, testAccepted, "")[0],
	}
}

// sensorInfo is the node's info record of a node.sensor_enrol it sends:
// claimed, unchecked, and naming no sensor (C8-6).
func sensorInfo() *Record {
	c := testAdmin()
	c.Kind = authz.KindNodeSensorEnrol
	return &Record{Contract: ReaderID, NodeID: "site-a-node-1", Seq: 2, PrevHash: strings.Repeat("6", 64),
		Time: at("2026-11-10T12:00:00Z"), Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeInfo,
		CorrelationID: "req-sensor", Claimed: c}
}

// parseEdited marshals r, applies edit to its JSON object, and parses the
// result as a stored record.
func parseEdited(t *testing.T, r *Record, edit func(m map[string]any)) error {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	if b, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	_, err = ParseRecord(b)
	return err
}

func sensorObj(m map[string]any) map[string]any { return m["sensor"].(map[string]any) }

func TestSensorRecordsValid(t *testing.T) {
	for name, r := range sensorGood() {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if err := parseEdited(t, r, func(map[string]any) {}); err != nil {
			t.Errorf("%s, stored: %v", name, err)
		}
	}
}

// C8-1: each action, and the sensor object, is new in 0.13. Control: the
// same record stamped 0.13 (TestSensorRecordsValid).
func TestSensorNeeds013(t *testing.T) {
	for name, r := range sensorGood() {
		if r.Sensor == nil {
			continue
		}
		r.Contract = "otsec.audit/0.12"
		err := r.Validate()
		if err == nil {
			t.Errorf("%s stamped 0.12: accepted", name)
		}
		// The action's own gate, before the object's.
		if sensorActions[r.Action] && (err == nil || !strings.Contains(err.Error(), string(r.Action)+" is new in 0.13")) {
			t.Errorf("%s stamped 0.12: %v, want the action's gate", name, err)
		}
	}
	// A 0.12 record cannot name a sensor kind, even on the info record.
	info := sensorInfo()
	info.Contract = "otsec.audit/0.12"
	if err := info.Validate(); err == nil || !strings.Contains(err.Error(), "new in 0.13") {
		t.Errorf("claimed sensor kind stamped 0.12: %v", err)
	}
}

// C8-1: the three actions are the node's, about the sensor and nothing else.
func TestSensorActionTarget(t *testing.T) {
	for _, r := range []*Record{enrolledRec(4, 10, "1", authz.SensorEnrolNew, testPinA), revokedRec(8, 12, "1", testPinA), refusedRec(9, RefusedBinding)} {
		for name, edit := range map[string]func(r *Record){
			"no target":           func(r *Record) { r.Target = nil },
			"an asset target":     func(r *Record) { r.Target = &Target{AssetID: testAsset} },
			"a sensor and asset":  func(r *Record) { r.Target.AssetID = testAsset },
			"a sensor, transport": func(r *Record) { r.Target.Family = "sel-751" },
			"a person's record":   func(r *Record) { r.Actor = adminActor },
			"no sensor object":    func(r *Record) { r.Sensor = nil },
		} {
			c := *r
			tg := *r.Target
			c.Target = &tg
			edit(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("%s, %s: accepted", r.Action, name)
			}
		}
	}
}

// S1: each action's sensor object holds exactly its own keys. Control: the
// valid records.
func TestSensorObjectKeys(t *testing.T) {
	good := sensorGood()
	for _, c := range []struct {
		name, record, key string
		value             any
	}{
		{"count on enrolled", "enrolled, first", "count", 1},
		{"streams on enrolled", "enrolled, first", "streams", map[string]any{}},
		{"applied_at on link_refused", "link_refused", "applied_at", "2026-11-10T11:00:00Z"},
		{"decision_seq on link_refused", "link_refused", "decision_seq", 10},
		{"not_after on revoked", "revoked, a link ended", "not_after", "2027-11-10T00:00:00Z"},
		{"previous_state on revoked", "revoked, a link ended", "previous_state", "unknown"},
		{"decision_seq on C8-6's object", "collector.request, enrol", "decision_seq", 10},
		{"reason on an enrol request", "collector.request, enrol", "reason", "new"},
		{"suspect_from on an enrol request", "collector.request, enrol", "suspect_from", "2026-11-09T00:00:00Z"},
		{"applied_at on a revoke request", "collector.request, revoke", "applied_at", "2026-11-10T11:00:00Z"},
	} {
		if err := parseEdited(t, good[c.record], func(m map[string]any) { sensorObj(m)[c.key] = c.value }); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	for record, required := range map[string][]string{
		"enrolled, first":           sensorKeys[ActionSensorEnrolled][0],
		"revoked, a link ended":     sensorKeys[ActionSensorRevoked][0],
		"link_refused":              sensorKeys[ActionSensorLinkRefused][0],
		"collector.request, enrol":  requestKeys[authz.KindNodeSensorEnrol][0],
		"collector.request, revoke": requestKeys[authz.KindNodeSensorRevoke][0],
	} {
		for _, key := range required {
			if err := parseEdited(t, good[record], func(m map[string]any) { delete(sensorObj(m), key) }); err == nil {
				t.Errorf("%s without %s: accepted", record, key)
			}
		}
	}
	// The object belongs on the sensor records and C8-6's collector.request.
	move := moveRec(5, BoundCreated, 0, 0, "2026-11-10T12:00:00Z", "2026-11-03T12:00:00Z", "")
	if err := move.Validate(); err != nil {
		t.Fatalf("control: %v", err)
	}
	move.Sensor = &Sensor{Generation: "1"}
	if err := move.Validate(); err == nil {
		t.Error("sensor on store.retention_moved: accepted")
	}
}

// C8-2 and S1-a: the enrolment record's codes, what it replaces, and the
// body's own C7 checks on a denied record too.
func TestSensorEnrolledRules(t *testing.T) {
	for _, code := range EnrolDeniedReasons {
		r := sensorGood()["enrolled, denied"]
		r.ReasonCode = code
		if err := r.Validate(); err != nil {
			t.Errorf("denied %s: %v", code, err)
		}
	}
	for name, edit := range map[string]func(r *Record){
		"a hyphen code":         func(r *Record) { r.Outcome, r.ReasonCode = OutcomeDenied, "node-key" },
		"a link code":           func(r *Record) { r.Outcome, r.ReasonCode = OutcomeDenied, RefusedPeerKey },
		"denied with no code":   func(r *Record) { r.Outcome = OutcomeDenied },
		"succeeded with a code": func(r *Record) { r.ReasonCode = DeniedGeneration },
		"outcome info":          func(r *Record) { r.Outcome = OutcomeInfo },
		"denied, port 0": func(r *Record) {
			r.Outcome, r.ReasonCode, r.Sensor.SensorAddress = OutcomeDenied, DeniedAssetAddress, "192.0.2.10:0"
		},
		"a hostname":              func(r *Record) { r.Sensor.SensorAddress = "sensor.example:8443" },
		"equal pins":              func(r *Record) { r.Sensor.NodeSPKI = r.Sensor.SensorSPKI },
		"new at generation 2":     func(r *Record) { r.Sensor.Generation = "2" },
		"an unknown reason":       func(r *Record) { r.Sensor.Reason = "restore" },
		"payload_sha256 prefixed": func(r *Record) { r.Sensor.PayloadSHA256 = "sha256:" + r.Sensor.PayloadSHA256 },
		"previous_state other":    func(r *Record) { r.Sensor.PreviousState = "lost" },
		"previous_state and pair": func(r *Record) {
			r.Sensor.PreviousState, r.Sensor.PreviousGeneration, r.Sensor.PreviousSPKI = PreviousStateUnknown, "1", testPinB
		},
		"previous_generation alone": func(r *Record) { r.Sensor.PreviousGeneration = "1" },
		"previous_spki alone":       func(r *Record) { r.Sensor.PreviousSPKI = testPinB },
		"previous_generation 01":    func(r *Record) { r.Sensor.PreviousGeneration, r.Sensor.PreviousSPKI = "01", testPinB },
		"previous_spki not a pin":   func(r *Record) { r.Sensor.PreviousGeneration, r.Sensor.PreviousSPKI = "1", strings.Repeat("2", 64) },
	} {
		r := enrolledRec(4, 10, "1", authz.SensorEnrolNew, testPinA)
		edit(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// C7-4 and C8-2 on a succeeded enrolment (D1's ruling 6896234420 on #699,
// N1): new exactly when none of previous_generation, previous_spki and
// previous_state is present, and previous_state only on a rekey or a
// replace. Controls: the accepted forms below, and a denied record, which
// these rules leave alone. The mutant that drops the first rule accepts the
// first three cases; the one that drops the second accepts the fourth.
func TestSensorEnrolledReplaces(t *testing.T) {
	enrol := func(gen string, reason authz.SensorEnrolReason, prev, state string) *Record {
		r := enrolledRec(6, 11, gen, reason, testPinB)
		if prev != "" {
			r.Sensor.PreviousGeneration, r.Sensor.PreviousSPKI = prev, testPinA
		}
		r.Sensor.PreviousState = state
		return r
	}
	for name, r := range map[string]*Record{
		"a renew with none of the three": enrol("2", authz.SensorEnrolRenew, "", ""),
		"a rekey with none of the three": enrol("2", authz.SensorEnrolRekey, "", ""),
		"a new with the previous pair":   enrol("1", authz.SensorEnrolNew, "1", ""),
		"a renew with previous_state":    enrol("2", authz.SensorEnrolRenew, "", PreviousStateUnknown),
		"a new with previous_state":      enrol("1", authz.SensorEnrolNew, "", PreviousStateUnknown),
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	denied := enrol("2", authz.SensorEnrolRenew, "", "")
	denied.Outcome, denied.ReasonCode = OutcomeDenied, DeniedReason
	for name, r := range map[string]*Record{
		"a new with none of the three":   enrol("1", authz.SensorEnrolNew, "", ""),
		"a renew with the previous pair": enrol("2", authz.SensorEnrolRenew, "1", ""),
		"a rekey with the previous pair": enrol("2", authz.SensorEnrolRekey, "1", ""),
		"a rekey with previous_state":    enrol("2", authz.SensorEnrolRekey, "", PreviousStateUnknown),
		"a replace with previous_state":  enrol("2", authz.SensorEnrolReplace, "", PreviousStateUnknown),
		"a denied renew with none":       denied,
	} {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// C8-3, T1 and St1: the revocation record.
func TestSensorRevokedRules(t *testing.T) {
	for name, edit := range map[string]func(r *Record){
		"denied":                 func(r *Record) { r.Outcome, r.ReasonCode = OutcomeDenied, "no_enrolment" },
		"info":                   func(r *Record) { r.Outcome = OutcomeInfo },
		"succeeded with a code":  func(r *Record) { r.ReasonCode = "compromised" },
		"no applied_at":          func(r *Record) { r.Sensor.AppliedAt = "" },
		"no streams":             func(r *Record) { r.Sensor.Streams = nil },
		"the observation alone":  func(r *Record) { r.Sensor.Streams.AlertThroughSeq = nil },
		"the alert alone":        func(r *Record) { r.Sensor.Streams.ObservationThroughSeq = nil },
		"applied_at an offset":   func(r *Record) { r.Sensor.AppliedAt = "2026-11-10T14:59:00+03:00" },
		"applied_at nanoseconds": func(r *Record) { r.Sensor.AppliedAt = "2026-11-10T11:59:00.0000001Z" },
		// The schema's pattern takes '.' only; time.Parse takes ',' too (D1's
		// ruling 6896234420 on #699, N2). Control: the same values with '.'
		// below.
		"applied_at a comma":              func(r *Record) { r.Sensor.AppliedAt = "2026-11-10T11:59:00,123456Z" },
		"applied_at a comma, nanoseconds": func(r *Record) { r.Sensor.AppliedAt = "2026-11-10T11:59:00,123456789Z" },
		"applied_at later":                func(r *Record) { r.Sensor.AppliedAt = "2026-11-10T12:00:00.000001Z" },
		// After the record's time as an instant, before it as a string.
		"applied_at later, half a second": func(r *Record) { r.Sensor.AppliedAt = "2026-11-10T12:00:00.5Z" },
		"an unknown reason":               func(r *Record) { r.Sensor.Reason = "rotated" },
		"baseline_digest bare":            func(r *Record) { r.Sensor.BaselineDigest = strings.Repeat("c", 64) },
		// D6's Q17 (6896196067): the mutant that skips the pattern accepts it.
		"payload_sha256 an uppercase hex digit": func(r *Record) {
			r.Sensor.PayloadSHA256 = "A" + r.Sensor.PayloadSHA256[1:]
		},
		"suspect_from an offset": func(r *Record) { r.Sensor.SuspectFrom = "2026-11-09T03:00:00+03:00" },
	} {
		r := revokedRec(8, 12, "1", testPinA)
		edit(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Equal and earlier instants are accepted at any precision: before the
	// record's time as an instant, after it as a string; and equal at two
	// precisions. Control for the comparison above.
	for name, c := range map[string][2]string{
		"earlier, after as a string": {"2026-11-10T12:00:00.5Z", "2026-11-10T12:00:00Z"},
		"equal, two precisions":      {"2026-11-10T12:00:00Z", "2026-11-10T12:00:00.000000Z"},
		"equal":                      {"2026-11-10T12:00:00.000125Z", "2026-11-10T12:00:00.000125Z"},
		"earlier, with a '.'":        {"2026-11-10T12:00:00Z", "2026-11-10T11:59:00.123456Z"},
	} {
		r := revokedRec(8, 12, "1", testPinA)
		r.Time, r.Sensor.AppliedAt = at(c[0]), c[1]
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, v := range map[string]any{"-1": -1, "1.5": 1.5, `"1"`: "1"} {
		err := parseEdited(t, revokedRec(8, 12, "1", testPinA), func(m map[string]any) {
			sensorObj(m)["streams"].(map[string]any)["alert_through_seq"] = v
		})
		if err == nil {
			t.Errorf("alert_through_seq %s: accepted", name)
		}
	}
	if err := parseEdited(t, revokedRec(8, 12, "1", testPinA), func(m map[string]any) {
		sensorObj(m)["applied_at"] = "2026-11-10T11:59:00,123456789Z"
	}); err == nil {
		t.Error("a stored applied_at with a comma: accepted")
	}
	if err := parseEdited(t, revokedRec(8, 12, "1", testPinA), func(m map[string]any) {
		sensorObj(m)["streams"].(map[string]any)["netbaseline_through_seq"] = 3
	}); err == nil {
		t.Error("a third stream: accepted")
	}
}

// St1-a: "no link ended" ({}) and "ended, both streams empty" (two zeros)
// are two records, byte for byte, through Seal.
func TestSensorStreamsBytes(t *testing.T) {
	good := sensorGood()
	for name, want := range map[string]string{
		"revoked, no link ended":      `"streams":{}`,
		"revoked, both streams empty": `"streams":{"observation_through_seq":0,"alert_through_seq":0}`,
	} {
		r := *good[name]
		r.Seq, r.PrevHash = 0, ""
		pending, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Seal(pending, 8, strings.Repeat("6", 64))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("%s: %s does not hold %s", name, b, want)
		}
	}
}

// C8-4, K1 and F1: the refusal record.
func TestSensorLinkRefusedRules(t *testing.T) {
	for _, code := range LinkRefusedReasons {
		if err := refusedRec(9, code).Validate(); err != nil {
			t.Errorf("%s: %v", code, err)
		}
	}
	one := refusedRec(9, RefusedExpired)
	one.Sensor.Count = 1
	if err := one.Validate(); err != nil {
		t.Errorf("count 1: %v", err)
	}
	for _, code := range []string{"peer-key", "run-regressed", "run-forked", "sensor-id", DeniedNodeKey, "hello", "tick"} {
		if err := refusedRec(9, code).Validate(); err == nil {
			t.Errorf("code %s: accepted", code)
		}
	}
	for name, edit := range map[string]func(r *Record){
		"succeeded":    func(r *Record) { r.Outcome, r.ReasonCode = OutcomeSucceeded, "" },
		"count 0":      func(r *Record) { r.Sensor.Count = 0 },
		"generation 0": func(r *Record) { r.Sensor.Generation = "0" },
	} {
		r := refusedRec(9, RefusedBinding)
		edit(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, v := range map[string]any{"1.5": 1.5, `"3"`: "3", "-1": -1} {
		if err := parseEdited(t, refusedRec(9, RefusedBinding), func(m map[string]any) { sensorObj(m)["count"] = v }); err == nil {
			t.Errorf("count %s: accepted", name)
		}
	}
}

// St1-b: JSON null is refused for the sensor object and every key in it,
// stored or pending. Control: the strict decoder alone reads each null as
// absent and accepts the bytes.
func TestSensorNullRefused(t *testing.T) {
	good := sensorGood()
	cases := map[string]func(m map[string]any){"sensor": func(m map[string]any) { m["sensor"] = nil }}
	for _, record := range []string{"enrolled, previous", "enrolled, state unknown", "revoked, suspect and voids", "link_refused"} {
		r := good[record]
		b, _ := json.Marshal(r.Sensor)
		var keys map[string]any
		_ = json.Unmarshal(b, &keys)
		for k := range keys {
			cases[record+": "+k] = func(m map[string]any) { sensorObj(m)[k] = nil }
		}
	}
	for _, k := range []string{"observation_through_seq", "alert_through_seq"} {
		cases["streams: "+k] = func(m map[string]any) { sensorObj(m)["streams"].(map[string]any)[k] = nil }
	}
	for name, edit := range cases {
		record := "revoked, suspect and voids"
		if i := strings.Index(name, ": "); i > 0 && good[name[:i]] != nil {
			record = name[:i]
		}
		r := good[record]
		b, _ := json.Marshal(r)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		edit(m)
		b, _ = json.Marshal(m)
		if !bytes.Contains(b, []byte("null")) {
			t.Fatalf("%s: no null in %s", name, b)
		}
		if err := strictjson.Decode(b, &Record{}); err != nil {
			t.Fatalf("%s: control, the strict decoder: %v", name, err)
		}
		if _, err := ParseRecord(b); !errors.Is(err, ErrRecordRejected) || !strings.Contains(err.Error(), "null") {
			t.Errorf("%s: stored, %v", name, err)
		}
		delete(m, "seq")
		delete(m, "prev_hash")
		pending, _ := json.Marshal(m)
		if _, err := ValidatePending(pending); !errors.Is(err, ErrRecordRejected) || !strings.Contains(err.Error(), "null") {
			t.Errorf("%s: pending, %v", name, err)
		}
	}
}

// S1 (D1's 6896052095 on #699): "" and 0, which the decoder reads as
// absent, are refused for every key of the sensor object, stored or pending,
// on every action, so that the object carries exactly its keys. Control: the
// strict decoder alone accepts the bytes and reads the key as absent. A
// streams value of 0 is a seq, and stays valid (St1).
func TestSensorUnsetRefused(t *testing.T) {
	good := sensorGood()
	for _, record := range []string{"enrolled, previous", "revoked, suspect and voids", "link_refused", "collector.request, suspect"} {
		for _, f := range reflect.VisibleFields(reflect.TypeOf(Sensor{})) {
			var zero any
			switch f.Type.Kind() {
			case reflect.String:
				zero = ""
			case reflect.Uint64:
				zero = 0
			default:
				continue // streams: an object, whose {} is valid
			}
			name := fmt.Sprintf("%s: %s %v", record, jsonName(f), zero)
			b, _ := json.Marshal(good[record])
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			sensorObj(m)[jsonName(f)] = zero
			b, _ = json.Marshal(m)
			var r Record
			if err := strictjson.Decode(b, &r); err != nil || !reflect.ValueOf(*r.Sensor).FieldByIndex(f.Index).IsZero() {
				t.Fatalf("%s: control, the strict decoder: %v", name, err)
			}
			if _, err := ParseRecord(b); !errors.Is(err, ErrRecordRejected) || !strings.Contains(fmt.Sprint(err), "reads as absent") {
				t.Errorf("%s: stored, %v", name, err)
			}
			delete(m, "seq")
			delete(m, "prev_hash")
			pending, _ := json.Marshal(m)
			if _, err := ValidatePending(pending); !errors.Is(err, ErrRecordRejected) || !strings.Contains(fmt.Sprint(err), "reads as absent") {
				t.Errorf("%s: pending, %v", name, err)
			}
		}
	}
	// streams with both keys at 0 is the record of a link ended with both
	// streams empty, and is read.
	b, _ := json.Marshal(good["revoked, both streams empty"])
	if !bytes.Contains(b, []byte(`"streams":{"observation_through_seq":0,"alert_through_seq":0}`)) {
		t.Fatalf("no zeros in %s", b)
	}
	if _, err := ParseRecord(b); err != nil {
		t.Errorf("streams with both keys at 0: %v", err)
	}
}

// C8-6: the sensor target and object only on an allowed, verified sensor
// kind, and required there.
func TestSensorRequest(t *testing.T) {
	for name, edit := range map[string]func(r *Record){
		"enrol without the target":  func(r *Record) { r.Target = nil },
		"enrol without the sensor":  func(r *Record) { r.Sensor = nil },
		"enrol with an asset too":   func(r *Record) { r.Target.AssetID = testAsset },
		"enrol with a bad pin":      func(r *Record) { r.Sensor.SensorSPKI = "sha256:" + strings.Repeat("A", 64) },
		"enrol with generation 01":  func(r *Record) { r.Sensor.Generation = "01" },
		"a network ack with target": func(r *Record) { r.Verified.Kind = authz.KindNodeNetworkBaselineAck },
	} {
		r := sensorGood()["collector.request, enrol"]
		edit(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, edit := range map[string]func(r *Record){
		"revoke without its reason":    func(r *Record) { r.Sensor.Reason = "" },
		"revoke with an unknown one":   func(r *Record) { r.Sensor.Reason = "rotated" },
		"a repeat without the target":  func(r *Record) { r.RepeatOf, r.CollectorSeq, r.Target = 11, 13, nil },
		"revoke, suspect_from not UTC": func(r *Record) { r.Sensor.SuspectFrom = "2026-11-09T03:00:00+03:00" },
	} {
		r := sensorGood()["collector.request, revoke"]
		edit(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The info and denied records, and every other kind, name no sensor.
	info := sensorInfo()
	info.Target = &Target{SensorID: testSensor}
	denied := adminRecord(OutcomeDenied, 14)
	denied.Contract, denied.Target = ReaderID, &Target{SensorID: testSensor}
	network := sensorGood()["collector.request, a network"]
	network.Sensor = &Sensor{Generation: "1", SensorSPKI: testPinA}
	for name, r := range map[string]*Record{"info with a target": info, "denied with a target": &denied, "network with sensor": network} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// sensorChain is a valid view from seq 2: the key set, an enrolment at
// generation 1, a rekey to generation 2, the revocation of generation 1's
// pin, and a refused link.
func sensorChain() []*Record {
	rekey := enrolledRec(6, 11, "2", authz.SensorEnrolRekey, testPinB)
	rekey.Sensor.PreviousGeneration, rekey.Sensor.PreviousSPKI = "1", testPinA
	revoked := revokedRec(8, 12, "1", testPinA)
	revoked.Sensor.Streams = &Streams{}
	return []*Record{
		keysRec(2, "", sensorKeySet),
		sensorAccept(3, 10, authz.KindNodeSensorEnrol, "1", testPinA),
		enrolledRec(4, 10, "1", authz.SensorEnrolNew, testPinA),
		sensorAccept(5, 11, authz.KindNodeSensorEnrol, "2", testPinB),
		rekey,
		sensorAccept(7, 12, authz.KindNodeSensorRevoke, "1", testPinA),
		revoked,
		refusedRec(9, RefusedRunForked),
	}
}

// cloneSensorChain copies recs deeply enough for one edit.
func cloneSensorChain(recs []*Record) []*Record {
	out := cloneChain(recs)
	for _, r := range out {
		if r.Sensor != nil {
			s := *r.Sensor
			r.Sensor = &s
		}
	}
	return out
}

func TestSensorChainValid(t *testing.T) {
	recs := sensorChain()
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("record %d: %v", r.Seq, err)
		}
	}
	if err := VerifySensorFrom(recs, 1); err != nil {
		t.Fatal(err)
	}
	// The sensor records leave the configuration chain's rules alone.
	if err := VerifyConfigFrom(recs, 1); err != nil {
		t.Fatalf("VerifyConfigFrom: %v", err)
	}
}

// C8-8: one chain that breaks each rule. The control of each is
// TestSensorChainValid's chain, which differs in that one place.
func TestVerifySensorFromBreaks(t *testing.T) {
	enrolAt := func(seq, decision uint64, gen string, reason authz.SensorEnrolReason, pin string) []*Record {
		return []*Record{sensorAccept(seq, decision, authz.KindNodeSensorEnrol, gen, pin), enrolledRec(seq+1, decision, gen, reason, pin)}
	}
	for name, edit := range map[string]func(recs []*Record) []*Record{
		"a generation skipped": func(recs []*Record) []*Record {
			recs[4].Sensor.Generation = "3"
			recs[3].Sensor.Generation = "3"
			return recs
		},
		"the first enrolment at 2": func(recs []*Record) []*Record {
			first := enrolAt(3, 10, "2", authz.SensorEnrolReplace, testPinA)
			first[1].Sensor.PreviousGeneration, first[1].Sensor.PreviousSPKI = "1", testPinB
			return append([]*Record{recs[0]}, first...)
		},
		"a revoked pin enrolled again, under another sensor": func(recs []*Record) []*Record {
			again := enrolAt(10, 13, "1", authz.SensorEnrolNew, testPinA)
			for _, r := range again {
				r.Target.SensorID = "7c1e0d2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f"
			}
			return append(recs, again...)
		},
		"a decision no acceptance has": func(recs []*Record) []*Record {
			recs[6].Sensor.DecisionSeq = 20
			return recs
		},
		"another payload": func(recs []*Record) []*Record {
			recs[2].Sensor.PayloadSHA256 = payloadOf(99)
			return recs
		},
		// The copied body fields (D1's ruling 6894951825, option (a)): each
		// edits the acceptance's copy only, so no other rule breaks.
		"an enrolment's generation not its acceptance's": func(recs []*Record) []*Record {
			recs[3].Sensor.Generation = "3"
			return recs
		},
		"an enrolment's pin not its acceptance's": func(recs []*Record) []*Record {
			recs[3].Sensor.SensorSPKI = testPinA
			return recs
		},
		"a revocation's generation not its acceptance's": func(recs []*Record) []*Record {
			recs[5].Sensor.Generation = "2"
			return recs
		},
		"a revocation's pin not its acceptance's": func(recs []*Record) []*Record {
			recs[5].Sensor.SensorSPKI = testPinB
			return recs
		},
		"a revocation's reason not its acceptance's": func(recs []*Record) []*Record {
			recs[5].Sensor.Reason = string(authz.SensorRevokeLost)
			return recs
		},
		"a revocation's suspect_from not its acceptance's": func(recs []*Record) []*Record {
			recs[5].Sensor.SuspectFrom = "2026-11-10T11:00:00Z"
			return recs
		},
		"another sensor's acceptance": func(recs []*Record) []*Record {
			recs[5].Target.SensorID = "7c1e0d2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f"
			return recs
		},
		"two revocations of one decision": func(recs []*Record) []*Record {
			again := *recs[6]
			again.Seq = 10
			return append(recs, &again)
		},
		"a renew with another pin": func(recs []*Record) []*Record {
			recs[4].Sensor.Reason = string(authz.SensorEnrolRenew)
			return recs
		},
		// What an enrolment replaces is the last enrolment (D1's ruling
		// 6896234420 on #699, N1). A renew under a new key whose previous_spki
		// is written as the new pin would carry the old run over (C7-4).
		"a renew under a new pin, previous_spki the new pin": func(recs []*Record) []*Record {
			recs[4].Sensor.Reason, recs[4].Sensor.PreviousSPKI = string(authz.SensorEnrolRenew), testPinB
			return recs
		},
		"previous_generation not the last enrolment's": func(recs []*Record) []*Record {
			recs[4].Sensor.PreviousGeneration = "7"
			return recs
		},
		"previous_state at the last enrolment's generation": func(recs []*Record) []*Record {
			pinC := "sha256:" + strings.Repeat("3", 64)
			again := enrolAt(10, 13, "2", authz.SensorEnrolReplace, pinC)
			again[1].Sensor.PreviousState = PreviousStateUnknown
			return append(recs, again...)
		},
		"one acceptance applied twice with previous_state": func(recs []*Record) []*Record {
			again := *recs[4]
			s := *again.Sensor
			again.Seq, again.Sensor = 10, &s
			s.PreviousGeneration, s.PreviousSPKI, s.PreviousState = "", "", PreviousStateUnknown
			return append(recs, &again)
		},
		"a rekey with the same pin": func(recs []*Record) []*Record {
			recs[4].Sensor.SensorSPKI, recs[3].Sensor.SensorSPKI = testPinA, testPinA
			recs[4].Sensor.PreviousSPKI = testPinA
			recs[5].Sensor.SensorSPKI, recs[6].Sensor.SensorSPKI = testPinB, testPinB
			return recs
		},
		"no key set before the decision": func(recs []*Record) []*Record { return recs[1:] },
		"a key set without the kind": func(recs []*Record) []*Record {
			entries := testKeyEntries(authz.KindNodeSensorEnrol)
			recs[0] = keysRec(2, "", entries)
			for _, i := range []int{1, 3, 5} {
				recs[i].Verified.KeysDigest = authz.AdminKeysDigest(entries)
			}
			return recs
		},
		// An enrolment keeps the same-epoch rule; a late revocation's is
		// TestVerifySensorFromLateRevoked's.
		"an enrolment's decision from before a reset": func(recs []*Record) []*Record {
			return append(append(recs[:4:4], resetRec(6)), recs[4:]...)
		},
		// The kind (D1's ruling 6895174039): an enrolment naming a
		// revocation's acceptance with the same generation and pin.
		"an enrolment naming a revocation's acceptance": func(recs []*Record) []*Record {
			recs[1] = sensorAccept(3, 10, authz.KindNodeSensorRevoke, "1", testPinA)
			return recs
		},
		// A revocation naming an enrolment's acceptance. It breaks on reason
		// as well, since a valid enrolment's acceptance carries none.
		"a revocation naming an enrolment's acceptance": func(recs []*Record) []*Record {
			recs[5] = sensorAccept(7, 12, authz.KindNodeSensorEnrol, "1", testPinA)
			return recs
		},
	} {
		t.Run(name, func(t *testing.T) {
			recs := edit(cloneSensorChain(sensorChain()))
			for _, r := range recs {
				if err := r.Validate(); err != nil {
					t.Fatalf("record %d: %v", r.Seq, err)
				}
			}
			if err := VerifySensorFrom(recs, 1); !errors.Is(err, ErrChainBroken) {
				t.Fatalf("%v, want broken", err)
			}
		})
	}
	// previous_state lifts the generation rule. Control for "a generation
	// skipped".
	recs := cloneSensorChain(sensorChain())
	recs[4].Sensor.Generation, recs[3].Sensor.Generation = "3", "3"
	recs[4].Sensor.PreviousGeneration, recs[4].Sensor.PreviousSPKI, recs[4].Sensor.PreviousState = "", "", PreviousStateUnknown
	if err := VerifySensorFrom(recs, 1); err != nil {
		t.Fatalf("previous_state: %v", err)
	}
	// suspect_from on both copies is accepted. Control for "a revocation's
	// suspect_from not its acceptance's".
	recs = cloneSensorChain(sensorChain())
	recs[5].Sensor.SuspectFrom, recs[6].Sensor.SuspectFrom = "2026-11-10T11:00:00Z", "2026-11-10T11:00:00Z"
	if err := VerifySensorFrom(recs, 1); err != nil {
		t.Fatalf("suspect_from on both: %v", err)
	}
	// A renew that keeps the last enrolment's pin, and previous_state above
	// the last enrolment's generation, are accepted. Controls for the N1
	// cases above.
	recs = cloneSensorChain(sensorChain())
	recs[3].Sensor.SensorSPKI, recs[4].Sensor.SensorSPKI, recs[4].Sensor.Reason = testPinA, testPinA, string(authz.SensorEnrolRenew)
	if err := VerifySensorFrom(recs[:5], 1); err != nil {
		t.Fatalf("a renew under the last pin: %v", err)
	}
	recs = cloneSensorChain(sensorChain())
	pinC := "sha256:" + strings.Repeat("3", 64)
	again := []*Record{sensorAccept(10, 13, authz.KindNodeSensorEnrol, "3", pinC),
		enrolledRec(11, 13, "3", authz.SensorEnrolReplace, pinC)}
	again[1].Sensor.PreviousState = PreviousStateUnknown
	recs = append(recs[:5], again...)
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("record %d: %v", r.Seq, err)
		}
	}
	if err := VerifySensorFrom(recs, 1); err != nil {
		t.Fatalf("previous_state above the last enrolment's generation: %v", err)
	}
}

// C8-8: a reference to a record before the view is unknown, not a break.
// Control: the same references in a view from seq 1 break the chain
// (TestVerifySensorFromBreaks).
func TestVerifySensorFromCut(t *testing.T) {
	recs := sensorChain()
	// From seq 5: enrolment 10 and its acceptance are before the view, so
	// the rekey's generation 2 has nothing to follow, and the key set is
	// unknown.
	if err := VerifySensorFrom(recs[3:], 5); err != nil {
		t.Fatalf("from seq 5: %v", err)
	}
	// From seq 7: the revocation names decision 12, which is in the view,
	// and a later revocation names decision 9, which no epoch of the view
	// holds.
	late := revokedRec(10, 9, "2", testPinB)
	if err := VerifySensorFrom(append(cloneSensorChain(recs[5:]), late), 7); err != nil {
		t.Fatalf("from seq 7: %v", err)
	}
	if err := VerifySensorFrom(append(cloneSensorChain(recs), late), 1); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("the same from seq 1: %v, want broken", err)
	}
	// D6's Q8 (6896196067): an unknown revocation still counts for "at most
	// one", by its decision and payload, so two of decision 9 break. The
	// mutant that counts only a revocation whose acceptance is found accepts
	// this view.
	again := revokedRec(11, 9, "2", testPinB)
	if err := VerifySensorFrom(append(cloneSensorChain(recs[5:]), late, again), 7); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("from seq 7, two late revocations of decision 9: %v, want broken", err)
	}

	// A sensor.revoked with no acceptance in the view is unknown, whatever
	// its decision (D1's ruling 6896234420 on #699, option (a)): its
	// acceptance may be in an epoch before the view. From seq 3 the view's
	// lowest collector_seq is 10. Control: the same chains from seq 1 break
	// (a decision no acceptance has, TestVerifySensorFromBreaks).
	for name, edit := range map[string]func(recs []*Record){
		"a revocation at the lowest decision, its acceptance not in view": func(recs []*Record) {
			recs[6].Sensor.DecisionSeq, recs[6].Sensor.PayloadSHA256 = 10, payloadOf(99)
		},
		"a revocation above the lowest decision, no acceptance": func(recs []*Record) {
			recs[6].Sensor.DecisionSeq, recs[6].Sensor.PayloadSHA256 = 13, payloadOf(13)
		},
	} {
		recs := cloneSensorChain(sensorChain())
		edit(recs)
		if err := VerifySensorFrom(recs[1:], 3); err != nil {
			t.Errorf("from seq 3, %s: %v", name, err)
		}
		if err := VerifySensorFrom(recs, 1); !errors.Is(err, ErrChainBroken) {
			t.Errorf("from seq 1, %s: %v, want broken", name, err)
		}
	}
	// An enrolment keeps the bound: its acceptance is in its own epoch, so a
	// decision at or above the view's lowest would be in the view. Control:
	// the mutant that drops "s.DecisionSeq < low" from the enrolment's
	// unknown case (M3) accepts this chain.
	recs = cloneSensorChain(sensorChain())
	recs[4].Sensor.DecisionSeq, recs[4].Sensor.PayloadSHA256 = 13, payloadOf(13)
	if err := VerifySensorFrom(recs[1:], 3); !errors.Is(err, ErrChainBroken) {
		t.Errorf("from seq 3, an enrolment above the bound, no acceptance: %v, want broken", err)
	}

	// D6's probe (6896196067): a revocation's acceptance in epoch 0, a
	// collector reset, another sensor's decision 5 in epoch 1, then the late
	// sensor.revoked naming decision 300. From seq 7 the acceptance is in an
	// epoch before the view, numbered by the earlier collector, so the
	// revocation is unknown. Control: the bound this replaces broke the view
	// from seq 7.
	other := sensorAccept(7, 5, authz.KindNodeSensorEnrol, "1", testPinB)
	other.Target.SensorID = "7c1e0d2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f"
	probe := []*Record{
		keysRec(2, "", sensorKeySet),
		sensorAccept(3, 10, authz.KindNodeSensorEnrol, "1", testPinA),
		enrolledRec(4, 10, "1", authz.SensorEnrolNew, testPinA),
		sensorAccept(5, 300, authz.KindNodeSensorRevoke, "1", testPinA),
		resetRec(6),
		other,
		revokedRec(8, 300, "1", testPinA),
	}
	for _, r := range probe {
		if err := r.Validate(); err != nil {
			t.Fatalf("probe record %d: %v", r.Seq, err)
		}
	}
	for first, i := range map[uint64]int{1: 0, 6: 4, 7: 5} {
		if err := VerifySensorFrom(probe[i:], first); err != nil {
			t.Errorf("D6's probe from seq %d: %v", first, err)
		}
	}

	// The enrolment's bound is taken before the view's first
	// collector.seq_reset (§11.2 C8-8). From seq 5: the acceptance of
	// decision 300; a sensor.enrolled in epoch 0 naming decision 10, below
	// 300, so its acceptance is before the view; a reset; and the new
	// collector's decision 5 in epoch 1. Control: the mutant that takes the
	// bound across resets (M4) puts it at 5, and breaks this chain.
	other = sensorAccept(8, 5, authz.KindNodeSensorEnrol, "1", testPinB)
	other.Target.SensorID = "7c1e0d2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f"
	m4 := []*Record{sensorAccept(5, 300, authz.KindNodeSensorRevoke, "1", testPinB),
		enrolledRec(6, 10, "1", authz.SensorEnrolNew, testPinA), resetRec(7), other}
	for _, r := range m4 {
		if err := r.Validate(); err != nil {
			t.Fatalf("record %d: %v", r.Seq, err)
		}
	}
	if err := VerifySensorFrom(m4, 5); err != nil {
		t.Errorf("from seq 5, an enrolment in epoch 0 below its epoch's lowest decision: %v", err)
	}
}

// S1-b: a repeat answer's own collector_seq names no decision; its
// repeat_of does. Control: a verifier that indexed every collector_seq
// would accept the first chain.
func TestVerifySensorFromRepeat(t *testing.T) {
	repeat := sensorAccept(8, 13, authz.KindNodeSensorRevoke, "1", testPinA)
	repeat.RepeatOf, repeat.Verified.PayloadSHA256 = 12, payloadOf(12)
	recs := cloneSensorChain(sensorChain())
	byRepeat := append(append(recs[:6:6], repeat), revokedRec(9, 13, "1", testPinA))
	byRepeat[7].Sensor.PayloadSHA256 = payloadOf(12)
	if err := VerifySensorFrom(byRepeat, 1); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("a revocation naming the repeat's collector_seq: %v, want broken", err)
	}
	// The first acceptance before the view: the repeat stands for it.
	cut := []*Record{recs[0], repeat, revokedRec(9, 12, "1", testPinA)}
	if err := VerifySensorFrom(cut, 2); err != nil {
		t.Fatalf("a revocation naming the first acceptance: %v", err)
	}
}

// resetRec is the node's collector.seq_reset at seq.
func resetRec(seq uint64) *Record {
	return &Record{Contract: ReaderID, NodeID: "site-a-node-1", Seq: seq, PrevHash: strings.Repeat("6", 64),
		Time: at("2026-11-10T12:00:00Z"), Actor: nodeActor, Action: ActionCollectorSeqReset, Outcome: OutcomeInfo,
		PreviousHigh: u64(12), InstallKeyID: "collector-2"}
}

// C8-8 under D1's ruling 6895174039 on #699, option (c): a sensor.revoked,
// which C8-3 lets the node write late, is judged by the key set and the
// collector epoch in force at its acceptance; a sensor.enrolled keeps the
// same-epoch rule and the latest key set before it. Each chain is
// sensorChain() through the revocation's acceptance (decision 12, seq 7),
// then what comes between, then the record.
func TestVerifySensorFromLateRevoked(t *testing.T) {
	// D5's two probes (6895040655): an admin_keys change adding one kind
	// with the key still active, and a collector reset.
	wider := testKeyEntries(authz.KindNodeSensorEnrol, authz.KindNodeSensorRevoke, authz.KindNodeBaselineAck)
	rotate := keysRec(8, authz.AdminKeysDigest(sensorKeySet), wider)
	// After the reset the collector reuses decision 12 for another sensor.
	reused := sensorAccept(9, 12, authz.KindNodeSensorEnrol, "1", testPinB)
	reused.Target.SensorID, reused.Verified.PayloadSHA256 = "7c1e0d2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f", payloadOf(99)
	late := func(seq uint64) *Record { return revokedRec(seq, 12, "1", testPinA) }
	upTo := func() []*Record { return cloneSensorChain(sensorChain())[:6] }
	for name, between := range map[string][]*Record{
		"written at once":                       nil,
		"an admin_keys change between":          {rotate},
		"a collector reset between":             {resetRec(8)},
		"a reset, and decision 12 reused":       {resetRec(8), reused},
		"a reset, then an admin_keys change":    {resetRec(8), keysRec(9, authz.AdminKeysDigest(sensorKeySet), wider)},
		"an admin_keys change, then two resets": {rotate, resetRec(9), resetRec(10)},
	} {
		recs := append(upTo(), between...)
		recs = append(recs, late(20))
		for _, r := range recs {
			if err := r.Validate(); err != nil {
				t.Fatalf("%s: record %d: %v", name, r.Seq, err)
			}
		}
		if err := VerifySensorFrom(recs, 1); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The same changes before a sensor.enrolled still break: an enrolment
	// adds trust, and one whose keys or epoch changed before it was applied
	// is not applied. The rekey (decision 11, seq 6) is the late record, and
	// the chain ends with it, so no later record breaks in its place.
	for name, between := range map[string]*Record{
		"an admin_keys change before an enrolment": keysRec(6, authz.AdminKeysDigest(sensorKeySet), wider),
		"a collector reset before an enrolment":    resetRec(6),
	} {
		recs := cloneSensorChain(sensorChain())
		recs = append(recs[:4:4], between, recs[4])
		if err := VerifySensorFrom(recs, 1); !errors.Is(err, ErrChainBroken) {
			t.Errorf("%s: %v, want broken", name, err)
		}
	}

	// A revocation whose acceptance-time key set lacks the kind breaks,
	// though a later key set holds it: 0.12's rule holds at the acceptance.
	enrolOnly := testKeyEntries(authz.KindNodeSensorEnrol)
	recs := upTo()
	recs[0] = keysRec(2, "", enrolOnly)
	for _, i := range []int{1, 3, 5} {
		recs[i].Verified.KeysDigest = authz.AdminKeysDigest(enrolOnly)
	}
	recs = append(recs, keysRec(8, authz.AdminKeysDigest(enrolOnly), sensorKeySet), late(9))
	if err := VerifySensorFrom(recs, 1); !errors.Is(err, ErrChainBroken) {
		t.Errorf("a key set at the acceptance without the kind: %v, want broken", err)
	}

	// D3's condition 1: at most one sensor.revoked names one acceptance,
	// across a reset.
	recs = append(upTo(), late(8), resetRec(9), late(10))
	if err := VerifySensorFrom(recs, 1); !errors.Is(err, ErrChainBroken) {
		t.Errorf("two revocations of one decision across a reset: %v, want broken", err)
	}
	// D6's Q7 (6896196067): the first acceptance of a decision is the one a
	// revocation names, so a repeat answer after the first revocation does
	// not open a second. The mutant that keeps the latest acceptance accepts
	// this chain.
	repeat := sensorAccept(9, 13, authz.KindNodeSensorRevoke, "1", testPinA)
	repeat.RepeatOf, repeat.Verified.PayloadSHA256 = 12, payloadOf(12)
	recs = append(upTo(), late(8), repeat, late(10))
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("record %d: %v", r.Seq, err)
		}
	}
	if err := VerifySensorFrom(recs, 1); !errors.Is(err, ErrChainBroken) {
		t.Errorf("two revocations of one decision around a repeat answer: %v, want broken", err)
	}
	// D6's Q5: after a reset the collector reuses decision 12 for the same
	// sensor with another payload; the late revocation is epoch 0's, found
	// by its payload. The mutant whose search ignores the payload finds
	// epoch 1's acceptance, and breaks this chain.
	reusedSame := sensorAccept(9, 12, authz.KindNodeSensorRevoke, "1", testPinA)
	reusedSame.Verified.PayloadSHA256 = payloadOf(99)
	recs = append(upTo(), resetRec(8), reusedSame, late(10))
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("record %d: %v", r.Seq, err)
		}
	}
	if err := VerifySensorFrom(recs, 1); err != nil {
		t.Errorf("decision 12 reused for the same sensor after a reset: %v", err)
	}

	// And a revocation whose acceptance is in no epoch still breaks.
	recs = append(upTo(), resetRec(8), revokedRec(9, 15, "1", testPinA))
	if err := VerifySensorFrom(recs, 1); !errors.Is(err, ErrChainBroken) {
		t.Errorf("a decision no epoch has: %v, want broken", err)
	}

	// In a view from seq 5, a late sensor.revoked in epoch 1 naming decision
	// 9, whose acceptance no epoch of the view holds, is unknown, not a
	// break. Control: the same chain from seq 1 breaks.
	whole := append(cloneSensorChain(sensorChain())[:5], resetRec(7), revokedRec(8, 9, "1", testPinA))
	if err := VerifySensorFrom(whole[3:], 5); err != nil {
		t.Errorf("a cut view, a revocation in epoch 1 before the view: %v", err)
	}
	if err := VerifySensorFrom(whole, 1); !errors.Is(err, ErrChainBroken) {
		t.Errorf("the same from seq 1: %v, want broken", err)
	}

	// The unknown rule is narrower for a sensor.enrolled (D6's B1 on #702):
	// an enrolment's acceptance must be in its own epoch, so in the same
	// view a sensor.enrolled in epoch 1 naming decision 9 breaks. Control:
	// the same enrolment in epoch 0, with no reset before it, is unknown.
	// The mutant that drops "epoch == 0 &&" from the unknown case accepts
	// the first chain.
	renew := func(seq uint64) *Record {
		r := enrolledRec(seq, 9, "3", authz.SensorEnrolRenew, testPinB)
		r.Sensor.PreviousGeneration, r.Sensor.PreviousSPKI = "2", testPinB
		return r
	}
	inEpoch1 := append(cloneSensorChain(sensorChain())[:5], resetRec(7), renew(8))
	inEpoch0 := append(cloneSensorChain(sensorChain())[:5], renew(7))
	for _, r := range append(inEpoch1[5:], inEpoch0[5]) {
		if err := r.Validate(); err != nil {
			t.Fatalf("record %d: %v", r.Seq, err)
		}
	}
	if err := VerifySensorFrom(inEpoch1[3:], 5); !errors.Is(err, ErrChainBroken) {
		t.Errorf("a cut view, an enrolment in epoch 1 before the view: %v, want broken", err)
	}
	if err := VerifySensorFrom(inEpoch0[3:], 5); err != nil {
		t.Errorf("a cut view, the same enrolment in epoch 0: %v", err)
	}
}

// C8-9: an acknowledgement before the latest sensor.revoked of its sensor
// is not in force; one after it is. Control: the two in the other order.
func TestNetworkAckInForce(t *testing.T) {
	ack := netAckRun(30, 12, testDraft1, testAccepted, "")[1]
	revoked := revokedRec(32, 14, "1", testPinA)
	if NetworkAckInForce([]*Record{ack, revoked}, ack) {
		t.Error("an acknowledgement before a revocation is in force")
	}
	revoked.Seq = 29
	if !NetworkAckInForce([]*Record{revoked, ack}, ack) {
		t.Error("an acknowledgement after a revocation is not in force")
	}
	other := revokedRec(32, 14, "1", testPinA)
	other.Target.SensorID = "7c1e0d2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f"
	if !NetworkAckInForce([]*Record{ack, other}, ack) {
		t.Error("another sensor's revocation voids the acknowledgement")
	}
	denied := *ack
	denied.Outcome, denied.ReasonCode = OutcomeDenied, "digest_mismatch"
	if NetworkAckInForce([]*Record{&denied}, &denied) {
		t.Error("a denied acknowledgement is in force")
	}
	// D6's Q10 (6896196067): an acknowledgement of kind configuration is
	// not a network one, with no revocation after it. The mutant without
	// the kind check reports it in force.
	config := ackRun(testAsset, 30, authz.BaselineConfiguration, testBaseline, "", OutcomeSucceeded)[1]
	if err := config.Validate(); err != nil {
		t.Fatalf("control: %v", err)
	}
	if NetworkAckInForce([]*Record{config}, config) {
		t.Error("a configuration-kind acknowledgement is in force")
	}
}
