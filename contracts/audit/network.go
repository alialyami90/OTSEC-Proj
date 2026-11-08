package audit

import (
	"errors"
	"fmt"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/version"
)

// The network records (0.12, docs/phase4/D3-c7-0.10-c8-0.12.md §2, D4-68).
// All are written by the node. A network baseline belongs to a C13 sensor,
// not an asset, so these records name Target.SensorID and no asset:
//
//   - config.baseline_recorded of kind network: the learner's frozen draft;
//   - config.baseline_acknowledged of kind network: a person accepted a
//     document built from that draft (C7 node.network_baseline_ack), with
//     the draft's digest as draft_digest;
//   - config.learner_retired: the learner left its stream's consumers;
//   - store.retention_moved: the alert stream's retention consumer moved.
//
// policy.apply with reason_code admin_keys records the administrator keys an
// accepted reply named (C7 0.10 admin.keys), and verified.keys_digest ties
// each accepted admin decision to that record. VerifyConfigFrom checks the
// chain rules.
const (
	// ActionStoreRetentionMoved is the retention consumer of a sensor's
	// alert stream moving its cursor, or being created (#532 §3). It is
	// written before the cursor commits, so a failed write keeps the
	// cursor where it was.
	ActionStoreRetentionMoved Action = "store.retention_moved"
	// ActionConfigLearnerRetired is a sensor's network learner leaving its
	// observation stream's consumers, because its baseline was
	// acknowledged or its run stopped (#532 §8). It is written before the
	// learner leaves, so a failed write keeps it.
	ActionConfigLearnerRetired Action = "config.learner_retired"
)

// networkSince is the minor that added the network records, Target.SensorID,
// Config.DraftDigest and CursorSeq, Retention, AdminKeys and
// Admin.KeysDigest.
const networkSince = 12

// The reason codes of config.learner_retired (info).
const (
	ReasonLearnerAcknowledged = "acknowledged"
	ReasonLearnerStopped      = "stopped"
)

// ReasonAdminKeys is the reason_code of the policy.apply record that names
// the administrator keys (AdminKeys).
const ReasonAdminKeys = "admin_keys"

// The bounds of a retention move (Retention.Bound).
const (
	BoundCreated   = "created"   // the consumer was created; nothing moved
	BoundWall      = "wall"      // the wall clock less the retention set the cutoff
	BoundMonotonic = "monotonic" // the previous cutoff plus the monotonic time since set it
	BoundStart     = "start"     // the one-hour limit after a node start set it
)

// AlertStreamPrefix is the C5 stream of a sensor's alerts, before the sensor
// ID (D5-c5-0.9.md §3).
const AlertStreamPrefix = "network-alert/"

// Retention is one move of a sensor's alert-stream retention consumer, on
// store.retention_moved only (0.12). The times are RFC 3339 UTC with Z.
type Retention struct {
	Stream            string `json:"stream"`
	FromSeq           uint64 `json:"from_seq"`
	ToSeq             uint64 `json:"to_seq"`
	RetentionS        int64  `json:"retention_s"`
	WallUTC           string `json:"wall_utc"`
	CutoffUTC         string `json:"cutoff_utc"`
	PreviousCutoffUTC string `json:"previous_cutoff_utc,omitempty"`
	Bound             string `json:"bound"`
}

// AdminKeys is the administrator key set an accepted C7 0.10 reply named, on
// policy.apply with reason_code admin_keys only (0.12). Digest is the reply's
// keys_digest and Keys its keys; PreviousDigest is the digest of the record
// before, absent the first time.
type AdminKeys struct {
	Digest         string                `json:"digest"`
	PreviousDigest string                `json:"previous_digest,omitempty"`
	Keys           []authz.AdminKeyEntry `json:"keys"`
}

// networkRecord reports whether r is one of the records that name a sensor.
func (r *Record) networkRecord() bool {
	switch r.Action {
	case ActionStoreRetentionMoved, ActionConfigLearnerRetired:
		return true
	case ActionConfigBaselineRecorded, ActionConfigBaselineAcknowledge:
		return r.Config != nil && r.Config.Kind == authz.BaselineNetwork
	}
	return false
}

// validateNetwork checks the 0.12 fields that are not Config's: sensor_id
// only on the network records, retention only on store.retention_moved, and
// admin_keys only on policy.apply with reason admin_keys, each required
// there, and none on a record stamped 0.11 or earlier.
func (r *Record) validateNetwork(minor int) error {
	sensor := r.Target != nil && r.Target.SensorID != ""
	if minor < networkSince && (sensor || r.Retention != nil || r.AdminKeys != nil) {
		return fmt.Errorf("audit: sensor_id, retention and admin_keys are new in 0.%d, so a 0.%d record cannot carry them", networkSince, minor)
	}
	if sensor && !r.networkRecord() {
		return fmt.Errorf("audit: sensor_id belongs on the network records, not %s", r.Action)
	}
	if (r.Action == ActionStoreRetentionMoved) != (r.Retention != nil) {
		return fmt.Errorf("audit: retention is on %s only, and required there", ActionStoreRetentionMoved)
	}
	if r.Retention != nil {
		if err := r.validateRetention(); err != nil {
			return err
		}
	}
	keys := r.Action == ActionPolicyApply && r.ReasonCode == ReasonAdminKeys
	if keys != (r.AdminKeys != nil) {
		return fmt.Errorf("audit: admin_keys is on %s with reason_code %s only, and required there", ActionPolicyApply, ReasonAdminKeys)
	}
	if keys {
		return r.validateAdminKeys()
	}
	return nil
}

// validateRetention checks store.retention_moved: the node's info record of
// one move of the sensor's alert-stream consumer. A created record starts a
// chain and moves nothing; every other moves the cursor forward from a
// previous cutoff, advances the cutoff past it, and keeps it at or behind
// the wall clock less the retention. Those need only the record's own
// fields, so they hold in every view (D6 on #545); that the move follows the
// record before it is VerifyConfigFrom's, with the chain.
func (r *Record) validateRetention() error {
	m := r.Retention
	switch {
	case r.Actor.Type != authz.PrincipalNode:
		return errors.New("audit: store.retention_moved is written by the node (actor type node)")
	case r.Outcome != OutcomeInfo || r.ReasonCode != "":
		return errors.New("audit: store.retention_moved has outcome info and no reason code")
	case r.Target == nil || !asset.ValidAssetID(r.Target.SensorID) || r.Target.AssetID != "":
		return errors.New("audit: store.retention_moved needs a target sensor and no asset")
	case r.Config != nil:
		return errors.New("audit: store.retention_moved carries no config")
	case m.Stream != AlertStreamPrefix+r.Target.SensorID:
		return fmt.Errorf("audit: store.retention_moved stream is %s<sensor_id>", AlertStreamPrefix)
	case m.RetentionS < 1:
		return errors.New("audit: retention_s is 1 or more")
	case !utcZ(m.WallUTC) || !utcZ(m.CutoffUTC) || (m.PreviousCutoffUTC != "" && !utcZ(m.PreviousCutoffUTC)):
		return errors.New("audit: retention times are RFC 3339 UTC with Z")
	}
	switch m.Bound {
	case BoundCreated:
		if m.ToSeq != m.FromSeq || m.PreviousCutoffUTC != "" {
			return errors.New("audit: a created retention record moves nothing (to_seq = from_seq) and has no previous_cutoff_utc")
		}
	case BoundWall, BoundMonotonic, BoundStart:
		if m.ToSeq <= m.FromSeq || m.PreviousCutoffUTC == "" {
			return errors.New("audit: a retention move passes at least one alert (to_seq > from_seq) and names previous_cutoff_utc")
		}
		cutoff, _ := time.Parse(time.RFC3339Nano, m.CutoffUTC)
		previous, _ := time.Parse(time.RFC3339Nano, m.PreviousCutoffUTC)
		wall, _ := time.Parse(time.RFC3339Nano, m.WallUTC)
		switch {
		case !cutoff.After(previous):
			return fmt.Errorf("audit: a retention move advances the cutoff past previous_cutoff_utc %s", m.PreviousCutoffUTC)
		case cutoff.After(wall.Add(-time.Duration(m.RetentionS) * time.Second)):
			return fmt.Errorf("audit: retention cutoff %s is later than wall_utc %s less retention_s %d", m.CutoffUTC, m.WallUTC, m.RetentionS)
		}
	default:
		return fmt.Errorf("audit: retention bound is %s, %s, %s or %s", BoundCreated, BoundWall, BoundMonotonic, BoundStart)
	}
	return nil
}

// validateAdminKeys checks a policy.apply admin_keys record: the node's info
// record of the key set an accepted reply named, the list exactly as C7
// checks it, and a previous digest that is another set.
func (r *Record) validateAdminKeys() error {
	k := r.AdminKeys
	switch {
	case r.Actor.Type != authz.PrincipalNode:
		return errors.New("audit: policy.apply admin_keys is written by the node (actor type node)")
	case r.Outcome != OutcomeInfo:
		return errors.New("audit: policy.apply admin_keys has outcome info")
	case k.PreviousDigest != "" && (!digestPattern.MatchString(k.PreviousDigest) || k.PreviousDigest == k.Digest):
		return errors.New("audit: admin_keys.previous_digest is sha256:<hex> and another key set")
	}
	if err := authz.ValidateAdminKeys(k.Digest, k.Keys); err != nil {
		return fmt.Errorf("audit: admin_keys: %w", err)
	}
	return nil
}

// validateLearnerRetired checks config.learner_retired: the node's info
// record, before it removes the learner from the consumers, of one learning
// run's retirement. acknowledged names the acknowledged baseline; stopped
// names none.
func (r *Record) validateLearnerRetired() error {
	c := r.Config
	switch {
	case r.Actor.Type != authz.PrincipalNode:
		return errors.New("audit: config.learner_retired is written by the node (actor type node)")
	case r.Outcome != OutcomeInfo:
		return errors.New("audit: config.learner_retired has outcome info")
	case c.Kind != authz.BaselineNetwork:
		return fmt.Errorf("audit: config.learner_retired has kind %s", authz.BaselineNetwork)
	case c.BaselineVersion < 1:
		return errors.New("audit: config.learner_retired needs the run's baseline_version, 1 or more")
	case c.DecisionSeq != 0 || c.PayloadSHA256 != "" || c.PreviousDigest != "" || c.DraftDigest != "" ||
		c.WindowStart != "" || c.WindowEnd != "" || c.Reason != "" || c.SnapshotDigest != "" || c.DifferenceDigest != "" ||
		c.ReadSeq != 0 || c.UnchangedAt != "" || c.UnchangedReadSeq != 0 || c.ApprovalSeq != 0 || c.ChangesDigest != "" ||
		c.ChangeSeq != 0 || c.SnapshotSeq != 0 || c.CheckpointHalf != "" || c.CheckpointSeq != 0 || c.removalFields():
		return errors.New("audit: config.learner_retired carries kind, baseline_version, cursor_seq and, when acknowledged, baseline_digest only")
	}
	switch r.ReasonCode {
	case ReasonLearnerAcknowledged:
		if !digestPattern.MatchString(c.BaselineDigest) {
			return errors.New("audit: an acknowledged config.learner_retired names the acknowledged baseline_digest sha256:<hex>")
		}
	case ReasonLearnerStopped:
		if c.BaselineDigest != "" {
			return errors.New("audit: a stopped config.learner_retired names no baseline")
		}
	default:
		return fmt.Errorf("audit: config.learner_retired reason is %s or %s", ReasonLearnerAcknowledged, ReasonLearnerStopped)
	}
	return nil
}

// networkChain holds VerifyConfigFrom's 0.12 state: per sensor, the latest
// recorded draft, whether the view holds the sensor's version-1 recording,
// the digests acknowledged, the runs retired; per alert stream, the latest
// retention record; and the latest admin_keys record.
type networkChain struct {
	cut      bool
	recorded map[string]*Record
	firstIn  map[string]bool
	acked    map[string]map[string]bool
	ackSeen  map[string]bool
	retired  map[string]map[int]bool
	stream   map[string]*Record
	keys     *Record
}

func newNetworkChain(recs []*Record, cut bool) *networkChain {
	n := &networkChain{cut: cut, recorded: map[string]*Record{}, firstIn: map[string]bool{}, acked: map[string]map[string]bool{},
		ackSeen: map[string]bool{}, retired: map[string]map[int]bool{}, stream: map[string]*Record{}}
	for _, r := range recs {
		if r.Action == ActionConfigBaselineRecorded && r.networkRecord() && r.Config.BaselineVersion == 1 {
			n.firstIn[r.Target.SensorID] = true
		}
	}
	return n
}

// record checks a config.baseline_recorded of kind network: it names, as
// previous_digest, the draft the sensor's last recording in the view
// recorded, with the next version.
func (n *networkChain) record(r *Record) error {
	c, sensor := r.Config, r.Target.SensorID
	if prev := n.recorded[sensor]; prev != nil {
		switch {
		case c.PreviousDigest != prev.Config.BaselineDigest:
			return broken("record %d records network baseline %s, but names %q as the one it replaces, and record %d recorded %s", r.Seq, c.BaselineDigest, c.PreviousDigest, prev.Seq, prev.Config.BaselineDigest)
		case c.BaselineVersion != prev.Config.BaselineVersion+1:
			return broken("record %d records network baseline version %d after version %d (record %d): versions rise by one", r.Seq, c.BaselineVersion, prev.Config.BaselineVersion, prev.Seq)
		}
	}
	n.recorded[sensor] = r
	return nil
}

// acknowledge checks a succeeded config.baseline_acknowledged of kind
// network: its draft_digest is the sensor's latest recorded draft, as far as
// the view shows. With no recording before it, it is refused only when the
// view holds the sensor's version-1 recording.
func (n *networkChain) acknowledge(r *Record) error {
	c, sensor := r.Config, r.Target.SensorID
	switch last := n.recorded[sensor]; {
	case last == nil && (n.firstIn[sensor] || !n.cut):
		return broken("record %d acknowledges a network baseline built from draft %s, but no draft of sensor %s is recorded before it", r.Seq, c.DraftDigest, sensor)
	case last != nil && last.Config.BaselineDigest != c.DraftDigest:
		return broken("record %d acknowledges a network baseline built from draft %s, but the latest draft recorded for sensor %s is %s (record %d)", r.Seq, c.DraftDigest, sensor, last.Config.BaselineDigest, last.Seq)
	}
	if n.acked[sensor] == nil {
		n.acked[sensor] = map[string]bool{}
	}
	n.acked[sensor][c.BaselineDigest] = true
	n.ackSeen[sensor] = true
	return nil
}

// retire checks a config.learner_retired: an acknowledged retirement follows
// a succeeded acknowledgement of the same sensor with the same digest, and a
// run (sensor and baseline_version) is retired once. In a view that starts
// after seq 1, an acknowledgement of a sensor with none in the view may be
// before it.
func (n *networkChain) retire(r *Record) error {
	c, sensor := r.Config, r.Target.SensorID
	if r.ReasonCode == ReasonLearnerAcknowledged && !n.acked[sensor][c.BaselineDigest] && !(n.cut && !n.ackSeen[sensor]) {
		return broken("record %d retires the learner of sensor %s as acknowledged %s, but no succeeded acknowledgement of that baseline comes before it", r.Seq, sensor, c.BaselineDigest)
	}
	if n.retired[sensor][c.BaselineVersion] {
		return broken("record %d retires learning run %d of sensor %s a second time", r.Seq, c.BaselineVersion, sensor)
	}
	if n.retired[sensor] == nil {
		n.retired[sensor] = map[int]bool{}
	}
	n.retired[sensor][c.BaselineVersion] = true
	return nil
}

// move checks a store.retention_moved. A created record starts a new chain
// for its stream. Within a chain each move starts where the record before it
// ended, names that record's cutoff as its previous one, advances it, and
// keeps it no later than the wall time less the retention. A move with no
// record before it is accepted as given in a view that starts after seq 1,
// and broken in one that holds the stream's start.
func (n *networkChain) move(r *Record) error {
	m := r.Retention
	if m.Bound == BoundCreated {
		n.stream[m.Stream] = r
		return nil
	}
	prev := n.stream[m.Stream]
	n.stream[m.Stream] = r
	if prev == nil {
		if n.cut {
			return nil
		}
		return broken("record %d moves the retention of %s, but no created record of the stream comes before it", r.Seq, m.Stream)
	}
	p := prev.Retention
	switch {
	case m.FromSeq != p.ToSeq:
		return broken("record %d moves %s from seq %d, but record %d left it at %d", r.Seq, m.Stream, m.FromSeq, prev.Seq, p.ToSeq)
	case m.PreviousCutoffUTC != p.CutoffUTC:
		return broken("record %d names previous cutoff %s, but record %d set %s", r.Seq, m.PreviousCutoffUTC, prev.Seq, p.CutoffUTC)
	}
	return nil
}

// adminKeys checks a policy.apply admin_keys record: its previous_digest is
// the digest of the record before it, and absent on the first in a view
// that starts at seq 1.
func (n *networkChain) adminKeys(r *Record) error {
	k := r.AdminKeys
	switch {
	case n.keys == nil && !n.cut && k.PreviousDigest != "":
		return broken("record %d names previous key set %s, but no admin_keys record comes before it", r.Seq, k.PreviousDigest)
	case n.keys != nil && k.PreviousDigest != n.keys.AdminKeys.Digest:
		return broken("record %d names previous key set %q, but record %d recorded %s", r.Seq, k.PreviousDigest, n.keys.Seq, n.keys.AdminKeys.Digest)
	}
	n.keys = r
	return nil
}

// granted checks that a decision applied by r, accepted by acc stamped 0.12
// or later, was made under the key set the latest admin_keys record before r
// names: the acceptance's keys_digest is that record's digest, and the
// verified key is active in it and its kinds include the verified kind (a
// revoked key's decision breaks the chain, D6 on #545). With no admin_keys
// record yet, it is unknown in a view that starts after seq 1.
func (n *networkChain) granted(r, acc *Record) error {
	if !atLeast(acc, networkSince) {
		return nil
	}
	v := acc.Verified
	if n.keys == nil {
		if n.cut {
			return nil
		}
		return broken("record %d applies decision %d before any policy.apply records the key set %s", r.Seq, acc.CollectorSeq, v.KeysDigest)
	}
	if n.keys.AdminKeys.Digest != v.KeysDigest {
		return broken("record %d applies a decision made under key set %s, but the latest admin_keys record (%d) is %s", r.Seq, v.KeysDigest, n.keys.Seq, n.keys.AdminKeys.Digest)
	}
	for _, e := range n.keys.AdminKeys.Keys {
		if e.KeyID != v.AdminKeyID {
			continue
		}
		if e.Status != authz.KeyActive {
			return broken("record %d applies a decision signed by %s, which the key set in record %d lists as %s", r.Seq, v.AdminKeyID, n.keys.Seq, e.Status)
		}
		for _, k := range e.Kinds {
			if k == v.Kind {
				return nil
			}
		}
		return broken("record %d applies %s signed by %s, whose kinds in record %d do not include it", r.Seq, v.Kind, v.AdminKeyID, n.keys.Seq)
	}
	return broken("record %d applies a decision signed by %s, which the key set in record %d does not hold", r.Seq, v.AdminKeyID, n.keys.Seq)
}

// atLeast reports whether r is stamped with minor or a later one.
func atLeast(r *Record, minor int) bool {
	got, err := version.Parse(r.Contract)
	return err == nil && got.Minor >= minor
}
