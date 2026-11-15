package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/authz"
)

// The sensor records (0.13, docs/phase4/D3-sensor-link.md §11.2, C8-1 to
// C8-9; D4-92; the forms are D1's ruling on #683, comment 6894226253). All
// three are written by the node, with actor type node, and name the sensor
// as Target.SensorID and nothing else. Each carries one Sensor object with
// exactly its own fields.
const (
	// ActionSensorEnrolled is written before the node applies an
	// enrolment, and if the write fails nothing is applied (C8-2).
	ActionSensorEnrolled Action = "sensor.enrolled"
	// ActionSensorRevoked is written after the link that used the revoked
	// pin is closed, and may be written late (C8-3). It is always
	// succeeded: a verified revocation is never dropped.
	ActionSensorRevoked Action = "sensor.revoked"
	// ActionSensorLinkRefused is a peer that failed authentication or
	// binding, under C8-5's cap (C8-4).
	ActionSensorLinkRefused Action = "sensor.link_refused"
)

// sensorSince is the minor that added the sensor records, Record.Sensor, and
// the sensor target on collector.request (C8-6).
const sensorSince = 13

// The reason codes of a denied sensor.enrolled (C8-2), in the order the node
// checks them, so that one request has one reason. C8-2 writes them with
// hyphens; reason_code carries them in underscore form (F1).
const (
	DeniedNodeKey      = "node_key"      // node_spki is not the pin of the node's own link key
	DeniedGeneration   = "generation"    // not one above the last enrolment, or not 1 for a new sensor
	DeniedRevokedKey   = "revoked_key"   // the sensor's pin is one the node has revoked, under any sensor_id
	DeniedForkedKey    = "forked_key"    // the sensor's pin is one the node holds for a fork
	DeniedReason       = "reason"        // the reason does not agree with the pin (C7-4)
	DeniedNotAfter     = "not_after"     // not_after is not after issued_at, or more than 366 days after it
	DeniedAssetAddress = "asset_address" // the sensor's address is an asset's
)

// EnrolDeniedReasons are C8-2's seven codes, in its order.
var EnrolDeniedReasons = []string{DeniedNodeKey, DeniedGeneration, DeniedRevokedKey, DeniedForkedKey,
	DeniedReason, DeniedNotAfter, DeniedAssetAddress}

// The six reasons of sensor.link_refused (C8-4), a closed set on which C13
// 0.2 relies (CH-11). C8-4 and C13 write them with hyphens; reason_code
// carries them in underscore form (F1). The node maps its typed verdicts to
// these through a table of its own, never by rewriting C13's close-reason
// strings: a C13 close reason is not a C8 code.
const (
	RefusedPeerKey      = "peer_key"      // a handshake whose key's pin is not the enrolment's (CH-1)
	RefusedExpired      = "expired"       // a dial that would be due after not_after; the node does not make it (CH-1)
	RefusedBinding      = "binding"       // a hello's sensor_id, generation or pinned_by differ (CH-13 rows 2 and 7, CH-33)
	RefusedRunRegressed = "run_regressed" // a lower run counter, or a resume below what the node holds (CH-13 rows 3 and 5a)
	RefusedRunForked    = "run_forked"    // the highest counter under another run_id (CH-13 row 4); the link is held
	RefusedSensorID     = "sensor_id"     // a record, or a tick, under another sensor_id (CH-14, CH-8)
)

// LinkRefusedReasons are C8-4's six codes.
var LinkRefusedReasons = []string{RefusedPeerKey, RefusedExpired, RefusedBinding, RefusedRunRegressed,
	RefusedRunForked, RefusedSensorID}

// PreviousStateUnknown is Sensor.PreviousState's one value: the node's sensor
// state was unknown when it enrolled (C7-4, C8-2).
const PreviousStateUnknown = "unknown"

// maxAppliedAtDigits is applied_at's finest form: microseconds, the form of
// the node's record time (T1).
const maxAppliedAtDigits = 6

// Sensor is the sensor object (0.13). It is on the three sensor actions and
// on C8-6's collector.request, and each carries exactly its own fields:
//
//   - sensor.enrolled: decision_seq and payload_sha256, as the configuration
//     decisions carry them (the collector's first acceptance, and that
//     acceptance's verified.payload_sha256); the signed body's generation,
//     sensor_spki, sensor_address, node_spki, node_address, not_after and
//     reason; and what it replaces: previous_generation with previous_spki,
//     or previous_state, or none of the three for a first enrolment (C8-2).
//     A denied record carries the request's fields too.
//   - sensor.revoked: decision_seq, payload_sha256; the body's generation,
//     sensor_spki, reason and suspect_from when given; applied_at; streams;
//     and baseline_digest, the network acknowledgement it voids, when there
//     is one (C8-3).
//   - sensor.link_refused: generation and count (C8-4, C8-5).
//   - collector.request, allowed and verified for node.sensor_enrol or
//     node.sensor_revoke: the verified body's generation and sensor_spki,
//     and for a revocation its reason and suspect_from (C8-6).
//
// The body's fields are checked by C7's own checks (authz), so the rules
// have one source. JSON null is refused for every key of this object, and
// for the object itself, as C13 refuses it (St1-b); and "" and 0, which the
// decoder reads as absent, for every key of this object (S1).
type Sensor struct {
	DecisionSeq        uint64 `json:"decision_seq,omitempty"`
	PayloadSHA256      string `json:"payload_sha256,omitempty"`
	Generation         string `json:"generation,omitempty"`
	SensorSPKI         string `json:"sensor_spki,omitempty"`
	SensorAddress      string `json:"sensor_address,omitempty"`
	NodeSPKI           string `json:"node_spki,omitempty"`
	NodeAddress        string `json:"node_address,omitempty"`
	NotAfter           string `json:"not_after,omitempty"`
	Reason             string `json:"reason,omitempty"`
	SuspectFrom        string `json:"suspect_from,omitempty"`
	PreviousGeneration string `json:"previous_generation,omitempty"`
	PreviousSPKI       string `json:"previous_spki,omitempty"`
	PreviousState      string `json:"previous_state,omitempty"`
	// AppliedAt is the node's time when it marked the pin revoked, RFC 3339
	// UTC with Z, at most microseconds, truncated as the record's time is,
	// and never after the record's time, compared as instants (T1). A
	// writer that finds a saved value after the record's time writes the
	// record's time.
	AppliedAt string   `json:"applied_at,omitempty"`
	Streams   *Streams `json:"streams,omitempty"`
	// BaselineDigest is the network acknowledgement the revocation voids.
	BaselineDigest string `json:"baseline_digest,omitempty"`
	// Count is this refusal and those of the same sensor, generation and
	// reason that C8-5's cap held back since that key's last record, in
	// this node run: at least 1. It is kept in memory, so after a node
	// start it is a lower bound (K1).
	Count uint64 `json:"count,omitempty"`
}

// Streams names, for a sensor.revoked that ended a link, the sensor's two
// record streams with the last seq each holds from that link (St1, SL-R3).
// Each value is the node's C5 seq of that stream in its store (its
// LastCommitted, which pruning never lowers; 0 when the stream holds
// nothing), and not C13's seq, which is per run: observation_through_seq is
// taken once the connection's read loop has returned and the held records
// are committed, and alert_through_seq once the detector has judged every
// observation at or below it. The two come together, or the object is empty
// ({}) when no link was ended. The sensor's third stream, netbaseline/<id>,
// is left out: it holds no record from the sensor, and baseline_digest names
// the acknowledged baseline a revocation voids. Each is a pointer with
// omitempty, so {} and two zeros stay distinct.
type Streams struct {
	ObservationThroughSeq *uint64 `json:"observation_through_seq,omitempty"`
	AlertThroughSeq       *uint64 `json:"alert_through_seq,omitempty"`
}

// sensorActions are the three sensor records.
var sensorActions = map[Action]bool{ActionSensorEnrolled: true, ActionSensorRevoked: true, ActionSensorLinkRefused: true}

// sensorKind reports whether kind is one of C7 0.11's sensor kinds.
func sensorKind(kind authz.RequestKind) bool {
	return kind == authz.KindNodeSensorEnrol || kind == authz.KindNodeSensorRevoke
}

// The keys of each action's sensor object: required, then optional.
var sensorKeys = map[Action][2][]string{
	ActionSensorEnrolled: {
		{"decision_seq", "payload_sha256", "generation", "sensor_spki", "sensor_address", "node_spki", "node_address", "not_after", "reason"},
		{"previous_generation", "previous_spki", "previous_state"}},
	ActionSensorRevoked: {
		{"decision_seq", "payload_sha256", "generation", "sensor_spki", "reason", "applied_at", "streams"},
		{"suspect_from", "baseline_digest"}},
	ActionSensorLinkRefused: {{"generation", "count"}, nil},
}

// requestKeys are the keys of C8-6's sensor object, by kind.
var requestKeys = map[authz.RequestKind][2][]string{
	authz.KindNodeSensorEnrol:  {{"generation", "sensor_spki"}, nil},
	authz.KindNodeSensorRevoke: {{"generation", "sensor_spki", "reason"}, {"suspect_from"}},
}

// keys checks that s carries every required key and no key outside the two
// lists. A key is carried when its value is not the zero value.
func (s *Sensor) keys(required, optional []string) error {
	v := reflect.ValueOf(*s)
	carried := map[string]bool{}
	for i := 0; i < v.NumField(); i++ {
		name := jsonName(v.Type().Field(i))
		carried[name] = !v.Field(i).IsZero()
		if carried[name] && !slices.Contains(required, name) && !slices.Contains(optional, name) {
			return fmt.Errorf("carries %s, which is not its field", name)
		}
	}
	for _, k := range required {
		if !carried[k] {
			return fmt.Errorf("needs %s", k)
		}
	}
	return nil
}

func jsonName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	return name
}

// validateSensor checks the 0.13 fields: the sensor object only on the sensor
// actions and on C8-6's collector.request. No record stamped 0.12 or earlier
// can carry it: the actions are gated by actionSince, and a sensor kind on
// verified by Admin.validate.
func (r *Record) validateSensor() error {
	switch {
	case sensorActions[r.Action]:
		if err := r.validateSensorAction(); err != nil {
			return fmt.Errorf("audit: %s: %w", r.Action, err)
		}
	case r.Action == ActionCollectorRequest:
		if err := r.validateSensorRequest(); err != nil {
			return fmt.Errorf("audit: collector.request: %w", err)
		}
	case r.Sensor != nil:
		return fmt.Errorf("audit: sensor belongs on the sensor records and C8-6's collector.request, not %s", r.Action)
	}
	return nil
}

// onlySensorTarget reports whether the record's target is a sensor and
// nothing else.
func (r *Record) onlySensorTarget() bool {
	return r.Target != nil && r.Target.SensorID != "" && *r.Target == Target{SensorID: r.Target.SensorID}
}

func (r *Record) validateSensorAction() error {
	s := r.Sensor
	switch {
	case r.Actor.Type != authz.PrincipalNode:
		return errors.New("is written by the node (actor type node)")
	case !r.onlySensorTarget():
		return errors.New("needs a target sensor and nothing else")
	case s == nil:
		return errors.New("needs sensor")
	}
	k := sensorKeys[r.Action]
	if err := s.keys(k[0], k[1]); err != nil {
		return fmt.Errorf("sensor %w", err)
	}
	switch r.Action {
	case ActionSensorEnrolled:
		switch {
		case r.Outcome == OutcomeSucceeded && r.ReasonCode == "":
		case r.Outcome == OutcomeDenied && slices.Contains(EnrolDeniedReasons, r.ReasonCode):
		default:
			return fmt.Errorf("is succeeded with no reason code, or denied with one of %v", EnrolDeniedReasons)
		}
		if !hashPattern.MatchString(s.PayloadSHA256) {
			return errors.New("payload_sha256 is not 64 lowercase hex digits")
		}
		body := authz.NodeSensorEnrolBody{SensorID: r.Target.SensorID, Generation: s.Generation, SensorSPKI: s.SensorSPKI,
			SensorAddress: s.SensorAddress, NodeSPKI: s.NodeSPKI, NodeAddress: s.NodeAddress, NotAfter: s.NotAfter,
			Reason: authz.SensorEnrolReason(s.Reason)}
		if err := body.Validate(); err != nil {
			return err
		}
		switch {
		case s.PreviousState != "" && (s.PreviousState != PreviousStateUnknown || s.PreviousGeneration != "" || s.PreviousSPKI != ""):
			return fmt.Errorf("previous_state is %s, and never comes with previous_generation or previous_spki", PreviousStateUnknown)
		case (s.PreviousGeneration == "") != (s.PreviousSPKI == ""):
			return errors.New("previous_generation and previous_spki come together")
		case s.PreviousGeneration != "" && (!authz.ValidGeneration(s.PreviousGeneration) || !authz.ValidSPKI(s.PreviousSPKI)):
			return errors.New("previous_generation is a generation and previous_spki a pin")
		}
	case ActionSensorRevoked:
		if r.Outcome != OutcomeSucceeded || r.ReasonCode != "" {
			return errors.New("is succeeded, always, with no reason code (C8-3)")
		}
		if !hashPattern.MatchString(s.PayloadSHA256) {
			return errors.New("payload_sha256 is not 64 lowercase hex digits")
		}
		body := authz.NodeSensorRevokeBody{SensorID: r.Target.SensorID, Generation: s.Generation, SensorSPKI: s.SensorSPKI,
			Reason: authz.SensorRevokeReason(s.Reason), SuspectFrom: s.SuspectFrom}
		if err := body.Validate(); err != nil {
			return err
		}
		if err := r.checkAppliedAt(); err != nil {
			return err
		}
		if (s.Streams.ObservationThroughSeq == nil) != (s.Streams.AlertThroughSeq == nil) {
			return errors.New("streams holds both through_seqs, or neither when no link was ended")
		}
		if s.BaselineDigest != "" && !digestPattern.MatchString(s.BaselineDigest) {
			return errors.New("baseline_digest is not sha256:<hex>")
		}
	case ActionSensorLinkRefused:
		if r.Outcome != OutcomeDenied || !slices.Contains(LinkRefusedReasons, r.ReasonCode) {
			return fmt.Errorf("is denied with one of %v", LinkRefusedReasons)
		}
		if !authz.ValidGeneration(s.Generation) {
			return errors.New("generation is not a decimal from 1")
		}
	}
	return nil
}

// checkAppliedAt checks applied_at's form and that it is not after the
// record's own time, as instants: utcZ admits fractional seconds, so a string
// comparison would be wrong both ways.
func (r *Record) checkAppliedAt() error {
	a := r.Sensor.AppliedAt
	if !utcZ(a) {
		return fmt.Errorf("applied_at %q is not RFC 3339 UTC with Z", a)
	}
	if i := strings.IndexByte(a, '.'); i >= 0 && len(a)-i-2 > maxAppliedAtDigits {
		return fmt.Errorf("applied_at %q is finer than microseconds", a)
	}
	applied, _ := time.Parse(time.RFC3339Nano, a)
	at, _ := time.Parse(time.RFC3339Nano, r.Time.UTC) // checked by validateTime
	if applied.After(at) {
		return fmt.Errorf("applied_at %s is after the record's time %s", a, r.Time.UTC)
	}
	return nil
}

// validateSensorRequest checks C8-6 on a collector.request: a sensor target
// and the sensor object come together, and only on an allowed record whose
// verified kind is a sensor kind (verified is on allowed records only), where
// they are required. The info and denied records, and every other kind, name
// no sensor, as before 0.13. That verified.kind is a sensor kind only from
// 0.13 is Admin.validate's.
func (r *Record) validateSensorRequest() error {
	target := r.Target != nil && r.Target.SensorID != ""
	if r.Verified == nil || !sensorKind(r.Verified.Kind) {
		if target || r.Sensor != nil {
			return errors.New("a sensor target and sensor are on an allowed, verified node.sensor_enrol or node.sensor_revoke only")
		}
		return nil
	}
	s := r.Sensor
	switch {
	case !r.onlySensorTarget():
		return fmt.Errorf("an accepted %s needs a target sensor and nothing else", r.Verified.Kind)
	case s == nil:
		return fmt.Errorf("an accepted %s needs sensor", r.Verified.Kind)
	}
	k := requestKeys[r.Verified.Kind]
	if err := s.keys(k[0], k[1]); err != nil {
		return fmt.Errorf("sensor %w", err)
	}
	if r.Verified.Kind == authz.KindNodeSensorRevoke {
		body := authz.NodeSensorRevokeBody{SensorID: r.Target.SensorID, Generation: s.Generation, SensorSPKI: s.SensorSPKI,
			Reason: authz.SensorRevokeReason(s.Reason), SuspectFrom: s.SuspectFrom}
		return body.Validate()
	}
	if !authz.ValidGeneration(s.Generation) || !authz.ValidSPKI(s.SensorSPKI) {
		return errors.New("sensor's generation is a decimal from 1 and sensor_spki a pin")
	}
	return nil
}

// refuseSensorUnset refuses JSON null as the sensor object or as the value of
// any of its keys, at any minor (St1-b). The decoders read a null as absent,
// which would turn {"observation_through_seq":null,...} into {}, a record of
// no link ended, and "previous_state":null into a known state. It refuses ""
// and 0 as the value of a key of the sensor object too, since the decoder
// reads each as absent, so that the object carries exactly its keys (S1; D1's
// 6896052095 on #699). A streams value of 0 is a seq, and stays valid (St1).
// b is a record's raw bytes; a malformed record is left for the decoder to
// refuse.
func refuseSensorUnset(b []byte) error {
	var rec struct {
		Sensor json.RawMessage `json:"sensor"`
	}
	if json.Unmarshal(b, &rec) != nil || rec.Sensor == nil {
		return nil
	}
	if string(rec.Sensor) == "null" {
		return errors.New("sensor is null")
	}
	var s map[string]json.RawMessage
	if json.Unmarshal(rec.Sensor, &s) != nil {
		return nil
	}
	for _, f := range reflect.VisibleFields(reflect.TypeOf(Sensor{})) {
		switch v, ok := s[jsonName(f)]; {
		case ok && string(v) == "null":
			return fmt.Errorf("sensor.%s is null", jsonName(f))
		case ok && (string(v) == `""` || string(v) == "0"):
			return fmt.Errorf("sensor.%s is %s, which reads as absent: a writer leaves the key out", jsonName(f), v)
		}
	}
	var st map[string]json.RawMessage
	if json.Unmarshal(s["streams"], &st) != nil {
		return nil
	}
	for _, f := range reflect.VisibleFields(reflect.TypeOf(Streams{})) {
		if v, ok := st[jsonName(f)]; ok && string(v) == "null" {
			return fmt.Errorf("sensor.streams.%s is null", jsonName(f))
		}
	}
	return nil
}

// VerifySensorFrom checks C8-8's chain rules for the sensor records on the
// view of a node's chain from seq first on, beside VerifyChain, as
// VerifyConfigFrom does. Each record must already pass Validate. It is not
// part of the node's chain check at start: a break here must not switch off
// the assets' event baselines (#628 §1.3).
//
//   - A succeeded sensor.enrolled carries a generation one above that
//     sensor's last succeeded enrolment, or 1 for the first, unless it
//     carries previous_state.
//   - After a sensor.revoked, no later sensor.enrolled succeeds with its pin,
//     under any sensor_id.
//   - A succeeded sensor.enrolled follows an allowed, verified
//     collector.request earlier in the same collector epoch whose
//     collector_seq (or, for a repeat answer, repeat_of) is the record's
//     decision_seq, for the same sensor and payload_sha256 (C8-6). A
//     sensor.revoked, which C8-3 lets the node write late, follows such an
//     acceptance in its own epoch or an earlier one: the latest epoch's
//     acceptance of that decision_seq with the same sensor and
//     payload_sha256 (D1's ruling 6895174039 on #699, option (c)). The
//     acceptance is of the record's kind: node.sensor_enrol for a
//     sensor.enrolled, node.sensor_revoke for a sensor.revoked. The
//     record's copies of the verified body equal the acceptance's:
//     generation and sensor_spki, and on a sensor.revoked reason and
//     suspect_from too. A repeat's own collector_seq names no decision. At
//     most one sensor.revoked names one acceptance, across collector resets.
//   - Where previous_spki is present, a succeeded renew carries a pin equal
//     to it, and a rekey or a replace a different one (C7-4).
//   - C8 0.12's key-set rule: the decision was accepted under a key set that
//     lists the verified key as active and allowed the kind. For a
//     sensor.enrolled that is the latest policy.apply admin_keys before the
//     record, so a key-set change between the acceptance and the record
//     breaks the chain, and the node does not apply it. For a
//     sensor.revoked it is the latest one before the acceptance: a
//     revocation only takes trust away, and a key rotation after it is
//     accepted must not break a valid chain.
//
// In a view that starts after seq 1, a reference to what came before first
// is unknown, not a break, as in VerifyConfigFrom: for a sensor.enrolled in
// the view's first epoch, a decision below the lowest collector_seq the view
// records before its first collector.seq_reset; for a sensor.revoked, any
// decision whose acceptance no epoch of the view holds, since that
// acceptance may be in an epoch before the view, numbered by another
// collector (D1's ruling 6896234420 on #699, option (a)); a sensor's last
// enrolment; and the key set. A revocation only takes trust away, and a
// view from seq 1 still breaks on a missing acceptance.
func VerifySensorFrom(recs []*Record, first uint64) error {
	if first == 0 {
		return errors.New("audit: a view starts at seq 1 or later")
	}
	cut := first > 1
	low := ^uint64(0)
	for _, r := range recs {
		if r.Seq < first {
			return broken("record %d is before the view's first seq %d", r.Seq, first)
		}
	}
	for _, r := range recs {
		if r.Action == ActionCollectorSeqReset {
			break
		}
		if r.Action == ActionCollectorRequest && r.CollectorSeq != 0 && r.CollectorSeq < low {
			low = r.CollectorSeq
		}
	}
	type num struct {
		epoch int
		seq   uint64
	}
	// revocation is what at most one sensor.revoked names: the acceptance
	// found (its audit seq), or, when it is before the view, the decision and
	// payload, since its epoch is unknown.
	type revocation struct {
		acc      uint64
		decision uint64
		payload  string
	}
	epoch := 0
	accepted := map[num]*Record{}
	keysAt := map[*Record]*Record{}      // the latest admin_keys record before each acceptance
	revokedBy := map[revocation]uint64{} // the sensor.revoked that names each acceptance
	lastGen := map[string]uint64{}       // each sensor's last succeeded enrolment
	revokedPin := map[string]bool{}      // every pin a sensor.revoked names
	net := newNetworkChain(recs, cut)
	// match checks that acc, the acceptance r names, is for r's sensor,
	// payload and kind, and that r copies its body.
	match := func(r, acc *Record) error {
		s := r.Sensor
		switch {
		case acc.Target == nil || acc.Target.SensorID != r.Target.SensorID || acc.Verified.PayloadSHA256 != s.PayloadSHA256:
			return broken("record %d (%s) does not match the acceptance of decision %d", r.Seq, r.Action, s.DecisionSeq)
		case acc.Verified.Kind != sensorRecordKind[r.Action]:
			return broken("record %d (%s) names decision %d, an acceptance of %s", r.Seq, r.Action, s.DecisionSeq, acc.Verified.Kind)
		case acc.Sensor == nil || !copiesAcceptance(r.Action, s, acc.Sensor):
			return broken("record %d (%s) copies a body field that differs from the acceptance of decision %d (C8-6)", r.Seq, r.Action, s.DecisionSeq)
		}
		return nil
	}
	for _, r := range recs {
		switch {
		case r.Action == ActionCollectorSeqReset:
			epoch++
		case r.Action == ActionCollectorRequest && r.Verified != nil:
			k := num{epoch, r.CollectorSeq}
			if r.RepeatOf != 0 {
				k.seq = r.RepeatOf
			}
			if _, ok := accepted[k]; !ok {
				accepted[k] = r
				keysAt[r] = net.keys
			}
		case r.Action == ActionPolicyApply && r.AdminKeys != nil:
			if err := net.adminKeys(r); err != nil {
				return err
			}
		case r.Action == ActionSensorEnrolled && r.Outcome == OutcomeSucceeded:
			s, sensor := r.Sensor, r.Target.SensorID
			acc := accepted[num{epoch, s.DecisionSeq}]
			switch {
			case acc == nil && cut && epoch == 0 && s.DecisionSeq < low:
			case acc == nil:
				return broken("record %d (%s) names decision %d, which no earlier acceptance in its epoch has", r.Seq, r.Action, s.DecisionSeq)
			default:
				if err := match(r, acc); err != nil {
					return err
				}
				if err := net.granted(r, acc); err != nil {
					return err
				}
			}
			gen, _ := strconv.ParseUint(s.Generation, 10, 64) // checked by Validate
			if last, ok := lastGen[sensor]; s.PreviousState == "" && (ok || !cut) && gen != last+1 {
				return broken("record %d enrols sensor %s at generation %d, but its last enrolment is at %d", r.Seq, sensor, gen, last)
			}
			if revokedPin[s.SensorSPKI] {
				return broken("record %d enrols pin %s, which an earlier sensor.revoked revoked", r.Seq, s.SensorSPKI)
			}
			if s.PreviousSPKI != "" && (s.Reason == string(authz.SensorEnrolRenew)) != (s.SensorSPKI == s.PreviousSPKI) {
				return broken("record %d is a %s whose pin is %s and whose previous pin is %s", r.Seq, s.Reason, s.SensorSPKI, s.PreviousSPKI)
			}
			lastGen[sensor] = gen
		case r.Action == ActionSensorRevoked:
			s := r.Sensor
			var acc *Record
			for e := epoch; e >= 0 && acc == nil; e-- {
				if a := accepted[num{e, s.DecisionSeq}]; a != nil && a.Target != nil &&
					a.Target.SensorID == r.Target.SensorID && a.Verified.PayloadSHA256 == s.PayloadSHA256 {
					acc = a
				}
			}
			k := revocation{decision: s.DecisionSeq, payload: s.PayloadSHA256}
			switch {
			case acc != nil:
				k = revocation{acc: acc.Seq}
			case !cut:
				return broken("record %d (%s) names decision %d, which no earlier acceptance of its sensor and payload has", r.Seq, r.Action, s.DecisionSeq)
			}
			if prev, ok := revokedBy[k]; ok {
				return broken("record %d revokes under decision %d, which record %d already applied", r.Seq, s.DecisionSeq, prev)
			}
			revokedBy[k] = r.Seq
			if acc != nil {
				if err := match(r, acc); err != nil {
					return err
				}
				if err := net.grantedUnder(r, acc, keysAt[acc]); err != nil {
					return err
				}
			}
			revokedPin[s.SensorSPKI] = true
		}
	}
	return nil
}

// sensorRecordKind is the request kind whose acceptance each applied sensor
// record names.
var sensorRecordKind = map[Action]authz.RequestKind{
	ActionSensorEnrolled: authz.KindNodeSensorEnrol,
	ActionSensorRevoked:  authz.KindNodeSensorRevoke,
}

// copiesAcceptance reports whether a sensor record's copies of the verified
// body equal C8-6's copy on its acceptance: generation and sensor_spki, and
// on a sensor.revoked reason and suspect_from too (D1's ruling 6894951825,
// option (a)). The payload hash is over bytes the chain does not hold, so
// without this a writer fault could show one pin revoked while the node
// revoked another, and a later enrolment of that one would pass C8-8.
func copiesAcceptance(action Action, rec, acc *Sensor) bool {
	same := rec.Generation == acc.Generation && rec.SensorSPKI == acc.SensorSPKI
	if action == ActionSensorRevoked {
		same = same && rec.Reason == acc.Reason && rec.SuspectFrom == acc.SuspectFrom
	}
	return same
}

// NetworkAckInForce reports whether ack, a record in recs, is a succeeded
// config.baseline_acknowledged of kind network that is in force under C8-9
// (SL-R5): no sensor.revoked of its sensor follows it in the chain. That is a
// reader's rule, not a chain break, and every reader applies it through this
// function. recs must pass Validate.
func NetworkAckInForce(recs []*Record, ack *Record) bool {
	if ack.Action != ActionConfigBaselineAcknowledge || ack.Outcome != OutcomeSucceeded || !ack.networkRecord() {
		return false
	}
	for _, r := range recs {
		if r.Action == ActionSensorRevoked && r.Seq > ack.Seq && r.Target.SensorID == ack.Target.SensorID {
			return false
		}
	}
	return true
}
