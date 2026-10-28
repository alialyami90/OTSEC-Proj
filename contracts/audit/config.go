package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
)

// The configuration actions (0.5, P4-A3). All four are written by the
// node. config.change_approved and config.baseline_acknowledged follow the
// collector's acceptance of a signed C7 0.6 request (node.change_approval,
// node.baseline_ack), so their actor is the verified person, as on that
// acceptance's own record. config.change_detected is the node's own finding
// that a configuration read differs from the asset's baseline, and
// config.baseline_restored its finding that a read after a recorded
// difference is equal to the baseline again.
const (
	ActionConfigChangeApproved      Action = "config.change_approved"
	ActionConfigChangeDetected      Action = "config.change_detected"
	ActionConfigBaselineAcknowledge Action = "config.baseline_acknowledged"
	ActionConfigBaselineRestored    Action = "config.baseline_restored"
)

// The configuration read actions (0.7, D4-20). Both are written by the node.
// config.read_compared is the node's record of a read that showed no
// difference from the asset's baseline, or only the change the asset's
// newest recorded change already is. config.reads_removed is its record,
// written before it removes any, of the oldest such reads' stored copies.
const (
	ActionConfigReadCompared Action = "config.read_compared"
	ActionConfigReadsRemoved Action = "config.reads_removed"
)

// The baseline record action (0.8, D4-26). It is written by the node, in the
// same commit step as the baseline record it names: both or neither. A
// configuration baseline is a person's acknowledgement of a snapshot that is
// already stored (config.baseline_acknowledged names it), and an event
// baseline is a record the node's learner writes with no person in the
// loop; this action is the chain's record of the second, and of any
// configuration baseline the node stores as a record of its own.
const ActionConfigBaselineRecorded Action = "config.baseline_recorded"

// configSince is the minor that added the configuration actions, Config and
// Admin.Kind; configReadsSince the one that added the read actions;
// configRecordedSince the one that added config.baseline_recorded and
// Config.BaselineVersion.
const (
	configSince         = 5
	configReadsSince    = 7
	configRecordedSince = 8
)

// EmptyChangesDigest is C9's ChangesDigest of a difference with no changes:
// "sha256:" and the SHA-256 of "[]". A detection or a repeated change always
// has at least one change, so no record carries it.
const EmptyChangesDigest = "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"

// keptReads is how many of an asset's newest compared reads a
// config.reads_removed leaves (D4-20 rule 3, B6 on #319): a person who views
// read N has at least one schedule interval before it is removed.
const keptReads = 2

// The reason codes of config.read_compared (info): the read showed no
// difference from the baseline, or the same change as the asset's newest
// recorded change against it.
const (
	ReasonNoDifference = "no_difference"
	ReasonSameChange   = "same_change"
)

// The reason codes of config.change_detected: warning when no approval
// covers the difference (the alarm), info when one does.
const (
	ReasonUnapprovedChange = "unapproved_change"
	ReasonApprovedChange   = "approved_change"
)

// Config is on the configuration actions only (0.5). Each action has
// exactly its own fields:
//
//   - config.change_approved: decision_seq, payload_sha256,
//     baseline_digest, window_start, window_end and reason, copied from the
//     node.change_approval body the collector accepted.
//   - config.baseline_acknowledged: decision_seq, payload_sha256, kind and
//     baseline_digest, from the node.baseline_ack body, and previous_digest
//     when the asset had a baseline of that kind before.
//   - config.change_detected: baseline_digest, snapshot_digest,
//     difference_digest, read_seq, unchanged_at, unchanged_read_seq (absent
//     when no earlier read is in the epoch), and approval_seq when an
//     approval covers the difference; from 0.7 also changes_digest.
//   - config.baseline_restored: baseline_digest, snapshot_digest and
//     read_seq of the first read equal to the baseline after a recorded
//     difference from it.
//   - config.read_compared (0.7): baseline_digest, snapshot_digest and
//     read_seq of a read that showed no difference from the baseline (reason
//     no_difference), or, with reason same_change, also change_seq and
//     changes_digest of the change it repeats.
//   - config.reads_removed (0.7): the removal fields only (removed_count,
//     removed_first_seq, removed_last_seq, removed_digest, kept_digest).
//   - config.baseline_recorded (0.8): kind, baseline_digest, and
//     previous_digest when the baseline replaces one; baseline_version for
//     kind event only.
//
// The digests are C9's (config.Digest) or C10's: "sha256:" and the SHA-256
// of the document's stored bytes. A configuration baseline is an
// acknowledged snapshot, so its baseline_digest is that snapshot's digest.
type Config struct {
	// DecisionSeq is the collector_seq of the collector's first acceptance
	// of the signed request: the allowed collector.request record's own
	// number, or the repeat_of of a repeat answer.
	DecisionSeq uint64 `json:"decision_seq,omitempty"`
	// PayloadSHA256 is that acceptance's verified.payload_sha256, lowercase
	// hex, so the record names exactly the signed bytes it acts on.
	PayloadSHA256 string `json:"payload_sha256,omitempty"`
	// Kind is the baseline's kind, on config.baseline_acknowledged and
	// config.baseline_recorded only.
	Kind           authz.BaselineKind `json:"kind,omitempty"`
	BaselineDigest string             `json:"baseline_digest,omitempty"`
	// PreviousDigest is the baseline of the same asset and kind that the
	// acknowledgement replaces (or would have replaced, when denied), on
	// config.baseline_acknowledged; and, on config.baseline_recorded, the
	// baseline the recorded one replaces (for an event baseline, C10's
	// Previous). Absent for the asset's first. With it, C8 alone shows each
	// asset's succession of baselines after the baseline records themselves
	// are pruned (B4 on #250).
	PreviousDigest string `json:"previous_digest,omitempty"`
	// BaselineVersion (0.8) is the recorded baseline's own version: C10's
	// Baseline.Version, 1 for an asset's first and one more for each re-learn.
	// On config.baseline_recorded of kind event only; a C9 configuration
	// snapshot has no version.
	BaselineVersion int    `json:"baseline_version,omitempty"`
	WindowStart     string `json:"window_start,omitempty"`
	WindowEnd       string `json:"window_end,omitempty"`
	// Reason is the approval's reason, shown with any alarm it silences.
	Reason           string `json:"reason,omitempty"`
	SnapshotDigest   string `json:"snapshot_digest,omitempty"`
	DifferenceDigest string `json:"difference_digest,omitempty"`
	// ReadSeq is the collector_seq of the collector's decision on the
	// configuration read that first found the difference (its allowed
	// collector.request record).
	ReadSeq uint64 `json:"read_seq,omitempty"`
	// UnchangedReadSeq is the collector_seq of the asset's last run of the
	// same operation before read_seq, in the same collector epoch, whatever
	// that run found: the change being recorded was not yet seen then, so it
	// happened after that run, or a failed run missed it. UnchangedAt is
	// that run's record time (RFC 3339 UTC). When the epoch has no earlier
	// run of the operation on the asset, UnchangedReadSeq is absent and
	// UnchangedAt is the time of the collector.seq_reset that began the
	// epoch. Both name a record already in the chain, so the node cannot
	// choose the time the change happened after (B6 on #250); naming a later
	// run than the last equal read only narrows what an approval covers.
	UnchangedAt      string `json:"unchanged_at,omitempty"`
	UnchangedReadSeq uint64 `json:"unchanged_read_seq,omitempty"`
	// ApprovalSeq is the decision_seq of the config.change_approved record
	// that covers the difference (ApprovalCovers). Absent when none does.
	ApprovalSeq uint64 `json:"approval_seq,omitempty"`
	// ChangesDigest (0.7) is C9's Difference.ChangesDigest (C9 0.2): "sha256:"
	// and the SHA-256 of the difference's changes array alone, in the order
	// Compare gives. It names neither snapshot nor the baseline, so two reads
	// of a configuration that stays changed have one, and so do the same
	// changes measured from another baseline: "the same change" is this digest
	// together with the same baseline_digest. On
	// config.change_detected (required from 0.7) and on config.read_compared
	// with reason same_change.
	ChangesDigest string `json:"changes_digest,omitempty"`
	// SnapshotSeq (0.7) is the seq, in the asset's configuration stream, of
	// the stored record of the snapshot this config.read_compared compared.
	// It increases from one compared read of the asset to the next, so a
	// config.reads_removed range ties to named reads.
	SnapshotSeq uint64 `json:"snapshot_seq,omitempty"`
	// ChangeSeq (0.7) is the seq of the config.change_detected record that a
	// same_change read repeats.
	ChangeSeq uint64 `json:"change_seq,omitempty"`
	// The removal fields (0.7), on config.reads_removed only. RemovedCount
	// reads of the asset were removed from its configuration stream, the
	// oldest of those the chain records as compared and not yet removed;
	// RemovedFirstSeq and RemovedLastSeq are the SnapshotSeq of the first
	// and last of them; the range may hold other stream records, which stay
	// (held differences and baselines). RemovedDigest is RemovedReadsDigest of their
	// snapshot digests in order. KeptDigest is the snapshot digest of the
	// newest compared read at the time, which stays with the one before it
	// (keptReads).
	RemovedCount    int    `json:"removed_count,omitempty"`
	RemovedFirstSeq uint64 `json:"removed_first_seq,omitempty"`
	RemovedLastSeq  uint64 `json:"removed_last_seq,omitempty"`
	RemovedDigest   string `json:"removed_digest,omitempty"`
	KeptDigest      string `json:"kept_digest,omitempty"`
}

// RemovedReadsDigest is the digest config.reads_removed carries over the
// snapshot digests of the reads it removed, in stream order: "sha256:" and
// the SHA-256 of each digest as written ("sha256:<hex>") followed by a line
// feed.
func RemovedReadsDigest(snapshotDigests []string) string {
	h := sha256.New()
	for _, d := range snapshotDigests {
		h.Write([]byte(d + "\n"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func (c *Config) removalFields() bool {
	return c.RemovedCount != 0 || c.RemovedFirstSeq != 0 || c.RemovedLastSeq != 0 || c.RemovedDigest != "" || c.KeptDigest != ""
}

func (c *Config) approvalBody(assetID string) *authz.NodeChangeApprovalBody {
	return &authz.NodeChangeApprovalBody{AssetID: assetID, BaselineDigest: c.BaselineDigest,
		WindowStart: c.WindowStart, WindowEnd: c.WindowEnd, Reason: c.Reason}
}

// validateConfig checks the 0.5 configuration actions and Config: Config
// only on them, each with a target asset, a correlation ID and exactly its
// fields, and none of it on a record stamped 0.4 or earlier.
func (r *Record) validateConfig(minor int) error {
	approved := r.Action == ActionConfigChangeApproved
	acked := r.Action == ActionConfigBaselineAcknowledge
	detected := r.Action == ActionConfigChangeDetected
	restored := r.Action == ActionConfigBaselineRestored
	compared := r.Action == ActionConfigReadCompared
	removed := r.Action == ActionConfigReadsRemoved
	recorded := r.Action == ActionConfigBaselineRecorded
	if !approved && !acked && !detected && !restored && !compared && !removed && !recorded {
		if r.Config != nil {
			return fmt.Errorf("audit: config belongs on the configuration actions, not %s", r.Action)
		}
		return nil
	}
	c := r.Config
	if c == nil {
		return fmt.Errorf("audit: %s needs config", r.Action)
	}
	if minor < configSince {
		return fmt.Errorf("audit: config is new in 0.%d, so a 0.%d record cannot carry it", configSince, minor)
	}
	if r.Target == nil || !asset.ValidAssetID(r.Target.AssetID) {
		return fmt.Errorf("audit: %s needs a target asset", r.Action)
	}
	if r.CorrelationID == "" {
		return fmt.Errorf("audit: %s needs a correlation_id", r.Action)
	}
	if recorded {
		return r.validateBaselineRecorded()
	}
	if c.BaselineVersion != 0 {
		return fmt.Errorf("audit: baseline_version belongs on config.baseline_recorded, not %s", r.Action)
	}
	if removed {
		return r.validateReadsRemoved()
	}
	if !digestPattern.MatchString(c.BaselineDigest) {
		return fmt.Errorf("audit: %s needs baseline_digest sha256:<hex>", r.Action)
	}
	if approved || acked {
		if c.ChangesDigest != "" || c.ChangeSeq != 0 || c.SnapshotSeq != 0 || c.removalFields() {
			return fmt.Errorf("audit: %s carries no read result or removal fields", r.Action)
		}
		return r.validateConfigDecision(approved)
	}
	switch {
	case r.Actor.Type != authz.PrincipalNode:
		return fmt.Errorf("audit: %s is written by the node (actor type node)", r.Action)
	case c.DecisionSeq != 0 || c.PayloadSHA256 != "" || c.Kind != "" || c.WindowStart != "" || c.WindowEnd != "" || c.Reason != "" || c.PreviousDigest != "":
		return fmt.Errorf("audit: %s carries no approval or acknowledgement fields", r.Action)
	case c.removalFields():
		return fmt.Errorf("audit: %s carries no removal fields", r.Action)
	case !digestPattern.MatchString(c.SnapshotDigest) || c.ReadSeq == 0:
		return fmt.Errorf("audit: %s needs snapshot_digest sha256:<hex> and read_seq", r.Action)
	}
	if restored {
		switch {
		case c.DifferenceDigest != "" || c.UnchangedAt != "" || c.UnchangedReadSeq != 0 || c.ApprovalSeq != 0:
			return errors.New("audit: config.baseline_restored has no difference, unchanged or approval fields")
		case c.ChangesDigest != "" || c.ChangeSeq != 0 || c.SnapshotSeq != 0:
			return errors.New("audit: config.baseline_restored has no changes_digest, change_seq or snapshot_seq")
		case r.Outcome != OutcomeInfo || r.ReasonCode != "":
			return errors.New("audit: config.baseline_restored has outcome info and no reason code")
		}
		return nil
	}
	if compared {
		return r.validateReadCompared()
	}
	switch {
	case c.ChangeSeq != 0 || c.SnapshotSeq != 0:
		return errors.New("audit: config.change_detected has no change_seq or snapshot_seq")
	case minor < configReadsSince && c.ChangesDigest != "":
		return fmt.Errorf("audit: changes_digest is new in 0.%d, so a 0.%d record cannot carry it", configReadsSince, minor)
	case minor >= configReadsSince && !digestPattern.MatchString(c.ChangesDigest):
		return errors.New("audit: config.change_detected needs changes_digest sha256:<hex> from 0.7")
	case c.ChangesDigest == EmptyChangesDigest:
		return errors.New("audit: config.change_detected has changes, so changes_digest is not the digest of none")
	case !digestPattern.MatchString(c.DifferenceDigest):
		return errors.New("audit: config.change_detected needs difference_digest sha256:<hex>")
	case c.SnapshotDigest == c.BaselineDigest:
		return errors.New("audit: config.change_detected names its baseline as the new snapshot")
	case c.ApprovalSeq >= c.ReadSeq:
		return errors.New("audit: approval_seq names a decision before read_seq")
	case c.UnchangedReadSeq >= c.ReadSeq:
		return errors.New("audit: unchanged_read_seq names a decision before read_seq")
	}
	if _, err := parseConfigTime(c.UnchangedAt); err != nil {
		return fmt.Errorf("audit: config.change_detected unchanged_at: %w", err)
	}
	switch {
	case r.Outcome == OutcomeWarning && r.ReasonCode == ReasonUnapprovedChange && c.ApprovalSeq == 0:
	case r.Outcome == OutcomeInfo && r.ReasonCode == ReasonApprovedChange && c.ApprovalSeq != 0:
	default:
		return fmt.Errorf("audit: config.change_detected is warning %s, or info %s with approval_seq", ReasonUnapprovedChange, ReasonApprovedChange)
	}
	return nil
}

// validateBaselineRecorded checks config.baseline_recorded: the node's own
// record, outcome info, of a baseline record it stored. It names the
// baseline's kind and digest, the baseline it replaces when there is one,
// and, for an event baseline, C10's version, which is 1 exactly when nothing
// is replaced. A configuration snapshot has no version.
func (r *Record) validateBaselineRecorded() error {
	c := r.Config
	switch {
	case r.Actor.Type != authz.PrincipalNode:
		return errors.New("audit: config.baseline_recorded is written by the node (actor type node)")
	case r.Outcome != OutcomeInfo || r.ReasonCode != "":
		return errors.New("audit: config.baseline_recorded has outcome info and no reason code")
	case c.Kind != authz.BaselineConfiguration && c.Kind != authz.BaselineEvent:
		return fmt.Errorf("audit: config.baseline_recorded kind is %q or %q", authz.BaselineConfiguration, authz.BaselineEvent)
	case !digestPattern.MatchString(c.BaselineDigest):
		return errors.New("audit: config.baseline_recorded needs baseline_digest sha256:<hex>")
	case c.DecisionSeq != 0 || c.PayloadSHA256 != "" || c.WindowStart != "" || c.WindowEnd != "" || c.Reason != "" ||
		c.SnapshotDigest != "" || c.DifferenceDigest != "" || c.ReadSeq != 0 || c.UnchangedAt != "" || c.UnchangedReadSeq != 0 ||
		c.ApprovalSeq != 0 || c.ChangesDigest != "" || c.ChangeSeq != 0 || c.SnapshotSeq != 0 || c.removalFields():
		return errors.New("audit: config.baseline_recorded carries kind, baseline_digest, previous_digest and baseline_version only")
	case c.PreviousDigest != "" && (!digestPattern.MatchString(c.PreviousDigest) || c.PreviousDigest == c.BaselineDigest):
		return errors.New("audit: previous_digest is sha256:<hex> and another baseline")
	}
	if c.Kind == authz.BaselineConfiguration {
		if c.BaselineVersion != 0 {
			return errors.New("audit: a configuration baseline has no version")
		}
		return nil
	}
	switch {
	case c.BaselineVersion < 1:
		return errors.New("audit: an event baseline needs baseline_version of 1 or more")
	case (c.BaselineVersion == 1) != (c.PreviousDigest == ""):
		return errors.New("audit: baseline_version is 1 exactly when no baseline is replaced (previous_digest absent)")
	}
	return nil
}

// validateReadCompared checks config.read_compared: the node's record of a
// read with no difference from the baseline (reason no_difference), or with
// the change the asset's newest recorded change already is (same_change, with
// that record's seq and the changes digest they share).
func (r *Record) validateReadCompared() error {
	c := r.Config
	switch {
	case c.DifferenceDigest != "" || c.UnchangedAt != "" || c.UnchangedReadSeq != 0 || c.ApprovalSeq != 0:
		return errors.New("audit: config.read_compared has no difference, unchanged or approval fields")
	case r.Outcome != OutcomeInfo:
		return errors.New("audit: config.read_compared has outcome info")
	case c.SnapshotSeq == 0:
		return errors.New("audit: config.read_compared needs snapshot_seq")
	}
	switch r.ReasonCode {
	case ReasonNoDifference:
		if c.ChangeSeq != 0 || c.ChangesDigest != "" {
			return errors.New("audit: config.read_compared no_difference names no change")
		}
	case ReasonSameChange:
		switch {
		case c.ChangeSeq == 0 || !digestPattern.MatchString(c.ChangesDigest):
			return errors.New("audit: config.read_compared same_change needs change_seq and changes_digest sha256:<hex>")
		case c.ChangesDigest == EmptyChangesDigest:
			return errors.New("audit: config.read_compared same_change repeats changes, so changes_digest is not the digest of none")
		case c.SnapshotDigest == c.BaselineDigest:
			return errors.New("audit: config.read_compared same_change names its baseline as the new snapshot")
		}
	default:
		return fmt.Errorf("audit: config.read_compared reason is %s or %s", ReasonNoDifference, ReasonSameChange)
	}
	return nil
}

// validateReadsRemoved checks config.reads_removed: the node's record, made
// before it removes any, of the stored copies of the asset's oldest recorded
// compared reads. It has the removal fields and nothing else.
func (r *Record) validateReadsRemoved() error {
	c := r.Config
	switch {
	case r.Actor.Type != authz.PrincipalNode:
		return errors.New("audit: config.reads_removed is written by the node (actor type node)")
	case r.Outcome != OutcomeInfo || r.ReasonCode != "":
		return errors.New("audit: config.reads_removed has outcome info and no reason code")
	case c.BaselineDigest != "" || c.DecisionSeq != 0 || c.PayloadSHA256 != "" || c.Kind != "" || c.PreviousDigest != "" ||
		c.WindowStart != "" || c.WindowEnd != "" || c.Reason != "" || c.SnapshotDigest != "" || c.DifferenceDigest != "" ||
		c.ReadSeq != 0 || c.UnchangedAt != "" || c.UnchangedReadSeq != 0 || c.ApprovalSeq != 0 || c.ChangesDigest != "" || c.ChangeSeq != 0 || c.SnapshotSeq != 0:
		return errors.New("audit: config.reads_removed carries the removal fields only")
	case c.RemovedCount < 1 || c.RemovedFirstSeq == 0 || c.RemovedLastSeq < c.RemovedFirstSeq || uint64(c.RemovedCount) > c.RemovedLastSeq-c.RemovedFirstSeq+1:
		return errors.New("audit: config.reads_removed needs removed_count and a removed_first_seq to removed_last_seq range that can hold them")
	case !digestPattern.MatchString(c.RemovedDigest) || !digestPattern.MatchString(c.KeptDigest):
		return errors.New("audit: config.reads_removed needs removed_digest and kept_digest sha256:<hex>")
	}
	return nil
}

// validateConfigDecision checks config.change_approved (approved) and
// config.baseline_acknowledged: the verified person as actor, the decision
// they follow, and the body's own rule (C7 Validate).
func (r *Record) validateConfigDecision(approved bool) error {
	c := r.Config
	switch {
	case r.Actor.Type != authz.PrincipalHuman:
		return fmt.Errorf("audit: the actor of %s is the verified person (actor type human)", r.Action)
	case r.Outcome != OutcomeSucceeded && r.Outcome != OutcomeDenied:
		return fmt.Errorf("audit: %s is succeeded, or denied when the node refuses to act on it", r.Action)
	case c.DecisionSeq == 0 || !hashPattern.MatchString(c.PayloadSHA256):
		return fmt.Errorf("audit: %s needs decision_seq and payload_sha256", r.Action)
	case c.SnapshotDigest != "" || c.DifferenceDigest != "" || c.ReadSeq != 0 || c.UnchangedAt != "" || c.UnchangedReadSeq != 0 || c.ApprovalSeq != 0:
		return fmt.Errorf("audit: %s carries no detection fields", r.Action)
	case approved && c.PreviousDigest != "":
		return errors.New("audit: previous_digest belongs on config.baseline_acknowledged")
	case c.PreviousDigest != "" && (!digestPattern.MatchString(c.PreviousDigest) || c.PreviousDigest == c.BaselineDigest):
		return errors.New("audit: previous_digest is sha256:<hex> and another baseline")
	}
	if approved {
		if c.Kind != "" {
			return errors.New("audit: config.change_approved has no kind: it approves a configuration change")
		}
		if err := c.approvalBody(r.Target.AssetID).Validate(); err != nil {
			return fmt.Errorf("audit: config.change_approved: %w", err)
		}
		return nil
	}
	if c.WindowStart != "" || c.WindowEnd != "" || c.Reason != "" {
		return errors.New("audit: config.baseline_acknowledged has no window or reason")
	}
	body := authz.NodeBaselineAckBody{AssetID: r.Target.AssetID, Kind: c.Kind, BaselineDigest: c.BaselineDigest}
	if err := body.Validate(); err != nil {
		return fmt.Errorf("audit: config.baseline_acknowledged: %w", err)
	}
	return nil
}

func parseConfigTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Location() != time.UTC || !strings.HasSuffix(s, "Z") {
		return time.Time{}, fmt.Errorf("%q is not RFC 3339 UTC with Z", s)
	}
	return t, nil
}

// ApprovalCovers reports why a config.change_approved record does not cover
// a config.change_detected record, or nil when it does. It covers when:
//
//   - the approval succeeded, on the same node and asset, against the same
//     baseline (baseline_digest);
//   - its decision is numbered below the decision on the read that first
//     found the difference (decision_seq < read_seq). Order decides "in
//     advance", never a time written in the approval, so a node cannot
//     reorder them. Both numbers must come from one collector epoch, which
//     VerifyConfig checks;
//   - its window overlaps the time in which the change happened: it starts
//     before the detection and ends after unchanged_at, the asset's last run
//     before the read that found the change.
//
// An approval covers any difference from its baseline in that time, not
// named settings: its reason says what was meant, and the alarm text shows
// which approval silenced a difference. The platform cannot place a change
// more finely than between two reads, so a window that ended between them
// covers a change made after it ended (B6 on #250); reading more often
// narrows that.
func ApprovalCovers(approval, detected *Record) error {
	if approval.Action != ActionConfigChangeApproved || approval.Outcome != OutcomeSucceeded || approval.Config == nil {
		return errors.New("audit: not a succeeded config.change_approved record")
	}
	if detected.Action != ActionConfigChangeDetected || detected.Config == nil {
		return errors.New("audit: not a config.change_detected record")
	}
	a, d := approval.Config, detected.Config
	switch {
	case approval.NodeID != detected.NodeID || approval.Target.AssetID != detected.Target.AssetID:
		return errors.New("audit: the approval is for another node or asset")
	case a.BaselineDigest != d.BaselineDigest:
		return errors.New("audit: the approval is against another baseline")
	case a.DecisionSeq >= d.ReadSeq:
		return fmt.Errorf("audit: the approval (decision %d) was not accepted before the read (decision %d)", a.DecisionSeq, d.ReadSeq)
	}
	start, end := a.approvalBody(approval.Target.AssetID).Window()
	unchanged, err := parseConfigTime(d.UnchangedAt)
	if err != nil {
		return fmt.Errorf("audit: unchanged_at: %w", err)
	}
	found, err := parseConfigTime(detected.Time.UTC)
	if err != nil {
		return fmt.Errorf("audit: detection time: %w", err)
	}
	if !start.Before(found) || !end.After(unchanged) {
		return errors.New("audit: the approval's window does not overlap the time the change happened in")
	}
	return nil
}

// VerifyConfig checks the configuration records of one node in chain order
// (0.5; 0.6 changes the alarm rule below; 0.7 adds the read records after the
// list), so that a node cannot silence an alarm with an approval that does not
// exist or does not cover it:
//
//   - each config.change_approved and config.baseline_acknowledged follows
//     the collector's acceptance it names (decision_seq): an allowed
//     collector.request record, earlier in the same collector epoch, with
//     that collector_seq (or repeat_of), verified by the record's actor,
//     for the same payload_sha256, and of the matching kind
//     (verified.kind);
//   - each config.change_detected names the decision on its read
//     (read_seq): an allowed collector.request record of a run on the same
//     asset, earlier in the same epoch;
//   - its unchanged_read_seq is the asset's last run of the same operation
//     before read_seq in the epoch, and unchanged_at is that run's record
//     time; or, with no such run, unchanged_read_seq is absent and
//     unchanged_at is the time of the collector.seq_reset that began the
//     epoch;
//   - each config.change_detected, config.baseline_restored and succeeded
//     config.change_approved names the asset's configuration baseline that
//     the last succeeded configuration-kind config.baseline_acknowledged
//     before it set, so a node cannot compare against, or approve changes
//     to, a baseline no person acknowledged (R4.8; B6 on #250);
//   - a config.change_detected with approval_seq names a succeeded
//     config.change_approved earlier in the same epoch that covers it
//     (ApprovalCovers);
//   - each config.baseline_restored names a real read of its asset in the
//     same way;
//   - once a difference from a baseline was recorded unapproved, no later
//     detection against the same baseline is approved until a
//     config.baseline_restored for that baseline, or a succeeded
//     configuration-kind config.baseline_acknowledged of the asset, follows
//     the alarm. An approval accepted after the alarm therefore never
//     silences the change that raised it. From 0.6 (D4-18) the
//     acknowledgement ends every open alarm of its asset raised before it,
//     whatever baseline the alarm was against, so re-acknowledging a
//     baseline starts it again from that acknowledgement; only an alarm
//     raised after the latest acknowledgement blocks a later approval. An
//     event-kind or denied acknowledgement ends nothing, and the alarm
//     records stay in the chain.
//
// From 0.8 each config.baseline_recorded of an asset and kind names, as
// previous_digest, the baseline the last one in recs recorded for that asset
// and kind, and an event baseline's baseline_version is one more than that
// record's. With none before it in recs, nothing is checked: recs may start
// after the asset's first. A record repeating the last digest breaks the
// chain, because Validate refuses a baseline that replaces itself. This
// checks the chain only: that the record and the stored baseline are written
// together is the writer's (C5), and nothing here ties an acknowledgement to
// a recorded baseline.
//
// Each succeeded config.baseline_acknowledged names, as previous_digest, the
// baseline of its asset and kind that the last succeeded acknowledgement in
// recs set, or none when recs shows none and it is the asset's first; so a
// node cannot record a skipped or reordered succession.
//
// From 0.7 results (detections, restores and config.read_compared) of an
// asset come in the order the reads were taken, within a collector epoch, and
// name runs of one operation until a configuration acknowledgement; and
// each config.read_compared names a real read of its asset that has
// no other result, against the asset's acknowledged baseline; reports no
// difference only when no change recorded against that baseline is still
// open (a restore or a configuration acknowledgement ends it); and repeats a
// change only by naming the newest one, by seq and changes_digest. Each
// config.reads_removed takes the oldest compared reads of its asset that no
// earlier removal took, leaving the two newest recorded (keptReads), with the
// removed_digest of those, the snapshot_seq of the first and last as its
// range, and the newest's digest as kept_digest.
//
// A collector.seq_reset starts a new epoch: numbers from before it name
// nothing after it, so an approval does not survive a collector reinstall.
// recs must start at the chain's first record, or at a point before every
// acceptance and read the records in it name, before the acknowledgement of
// each configuration baseline they name, before the last run on each asset
// ahead of each detection, and before the oldest compared read of each asset
// that a config.reads_removed in recs takes and an earlier removal did not.
func VerifyConfig(recs []*Record) error {
	type num struct {
		epoch int
		seq   uint64
	}
	type baseline struct{ asset, digest string }
	type opOf struct{ asset, op string }
	epoch := 0
	var reset *Record             // the collector.seq_reset that began this epoch
	accepted := map[num]*Record{} // allowed admin collector.request records, by decision
	runs := map[num]*Record{}     // allowed collector.request records of runs
	byOp := map[opOf][]*Record{}  // this epoch's runs, in chain order
	approvals := map[num]*Record{}
	alarmed := map[baseline]bool{} // an unapproved difference with no restore or configuration acknowledgement after it
	type kindOf struct {
		asset string
		kind  authz.BaselineKind
	}
	active := map[kindOf]string{} // the baseline the last succeeded acknowledgement set
	// 0.8: the last baseline the node recorded for each asset and kind.
	recorded := map[kindOf]*Record{}
	// 0.7 (D4-20): the newest recorded change against each baseline, until a
	// restore or a configuration acknowledgement ends it; the result each
	// read has been given; and, for each asset, the snapshot digests of its
	// compared reads that a config.reads_removed has not yet taken.
	lastChange := map[baseline]*Record{}
	resulted := map[num]Action{}
	type compared struct {
		digest string
		seq    uint64 // snapshot_seq
	}
	pending := map[string][]compared{}
	lastSnap := map[string]uint64{} // each asset's latest compared snapshot_seq, removed or not
	// The read decision of each asset's latest result, so that results come
	// in the order the reads were taken (B6 on #322), and the operation of
	// the runs its results name, which a configuration acknowledgement
	// resets. One read is in flight per asset, so a correct node writes the
	// results in order. Which operations are configuration reads is the
	// register's, not this contract's: only that an asset's results name one.
	lastRead := map[string]num{}
	resultOp := map[string]string{}
	inOrder := func(r, run *Record) error {
		k, asset := num{epoch, r.Config.ReadSeq}, r.Target.AssetID
		if prev, ok := lastRead[asset]; ok && prev.epoch == epoch && k.seq <= prev.seq {
			return broken("record %d (%s) gives read decision %d a result, but the asset's previous result is for decision %d: results follow the order of the reads", r.Seq, r.Action, k.seq, prev.seq)
		}
		if op, ok := resultOp[asset]; ok && op != run.OperationID {
			return broken("record %d (%s) names a run of %s, but the asset's earlier results name runs of %s", r.Seq, r.Action, run.OperationID, op)
		}
		lastRead[asset], resultOp[asset] = k, run.OperationID
		return nil
	}
	for _, r := range recs {
		switch {
		case r.Action == ActionCollectorSeqReset:
			epoch++
			reset, byOp = r, map[opOf][]*Record{}
		case r.Action == ActionCollectorRequest && r.Outcome == OutcomeAllowed:
			switch {
			case r.Verified != nil && r.RepeatOf != 0:
				if _, ok := accepted[num{epoch, r.RepeatOf}]; !ok {
					accepted[num{epoch, r.RepeatOf}] = r
				}
			case r.Verified != nil:
				accepted[num{epoch, r.CollectorSeq}] = r
			case r.OperationID != "" && r.Target != nil:
				runs[num{epoch, r.CollectorSeq}] = r
				k := opOf{r.Target.AssetID, r.OperationID}
				byOp[k] = append(byOp[k], r)
			}
		case r.Action == ActionConfigChangeApproved || r.Action == ActionConfigBaselineAcknowledge:
			c := r.Config
			want := authz.KindNodeChangeApproval
			if r.Action == ActionConfigBaselineAcknowledge {
				want = authz.KindNodeBaselineAck
			}
			acc := accepted[num{epoch, c.DecisionSeq}]
			switch {
			case acc == nil:
				return broken("record %d (%s) names decision %d, which no earlier acceptance in its epoch has", r.Seq, r.Action, c.DecisionSeq)
			case acc.Verified.Principal != r.Actor.ID || acc.Verified.PayloadSHA256 != c.PayloadSHA256:
				return broken("record %d (%s) does not match the acceptance of decision %d", r.Seq, r.Action, c.DecisionSeq)
			case acc.Verified.Kind != want:
				return broken("record %d (%s) follows an acceptance of %q, not %s", r.Seq, r.Action, acc.Verified.Kind, want)
			}
			if r.Action == ActionConfigChangeApproved && r.Outcome == OutcomeSucceeded {
				if err := acknowledged(r, active[kindOf{r.Target.AssetID, authz.BaselineConfiguration}]); err != nil {
					return err
				}
				approvals[num{epoch, c.DecisionSeq}] = r
			}
			if r.Action == ActionConfigBaselineAcknowledge && r.Outcome == OutcomeSucceeded {
				k := kindOf{r.Target.AssetID, c.Kind}
				if prev, ok := active[k]; ok && c.PreviousDigest != prev {
					return broken("record %d acknowledges %s after %s, but names %q as the baseline it replaces", r.Seq, c.BaselineDigest, prev, c.PreviousDigest)
				}
				active[k] = c.BaselineDigest
				if c.Kind == authz.BaselineConfiguration {
					// 0.6 (D4-18): the acknowledgement ends every open alarm
					// of the asset raised before it, whatever baseline it was
					// raised against; one raised after it is added later.
					for b := range alarmed {
						if b.asset == r.Target.AssetID {
							delete(alarmed, b)
						}
					}
					for b := range lastChange {
						if b.asset == r.Target.AssetID {
							delete(lastChange, b)
						}
					}
					delete(resultOp, r.Target.AssetID)
				}
			}
		case r.Action == ActionConfigChangeDetected || r.Action == ActionConfigBaselineRestored:
			c := r.Config
			run := runs[num{epoch, c.ReadSeq}]
			if run == nil || run.Target.AssetID != r.Target.AssetID {
				return broken("record %d names read decision %d, which is not an earlier run on asset %s in its epoch", r.Seq, c.ReadSeq, r.Target.AssetID)
			}
			if err := acknowledged(r, active[kindOf{r.Target.AssetID, authz.BaselineConfiguration}]); err != nil {
				return err
			}
			if r.Action == ActionConfigChangeDetected {
				if err := unchangedRead(r, byOp[opOf{run.Target.AssetID, run.OperationID}], reset); err != nil {
					return err
				}
			}
			k := baseline{r.Target.AssetID, c.BaselineDigest}
			if resulted[num{epoch, c.ReadSeq}] == ActionConfigReadCompared {
				return broken("record %d (%s) gives read decision %d a second result: a config.read_compared already has it", r.Seq, r.Action, c.ReadSeq)
			}
			if err := inOrder(r, run); err != nil {
				return err
			}
			resulted[num{epoch, c.ReadSeq}] = r.Action
			if r.Action == ActionConfigChangeDetected {
				lastChange[k] = r
			} else {
				delete(lastChange, k)
			}
			switch {
			case r.Action == ActionConfigBaselineRestored:
				delete(alarmed, k)
				continue
			case c.ApprovalSeq == 0:
				alarmed[k] = true
				continue
			case alarmed[k]:
				return broken("record %d is approved, but the unapproved difference from baseline %s is still open", r.Seq, c.BaselineDigest)
			}
			a := approvals[num{epoch, c.ApprovalSeq}]
			if a == nil {
				return broken("record %d names approval %d, which is not an earlier succeeded approval in its epoch", r.Seq, c.ApprovalSeq)
			}
			if err := ApprovalCovers(a, r); err != nil {
				return broken("record %d: approval %d does not cover it: %v", r.Seq, c.ApprovalSeq, err)
			}
		case r.Action == ActionConfigBaselineRecorded:
			c := r.Config
			k := kindOf{r.Target.AssetID, c.Kind}
			if prev := recorded[k]; prev != nil {
				switch {
				case c.PreviousDigest != prev.Config.BaselineDigest:
					return broken("record %d records %s baseline %s, but names %q as the one it replaces, and record %d recorded %s", r.Seq, c.Kind, c.BaselineDigest, c.PreviousDigest, prev.Seq, prev.Config.BaselineDigest)
				case c.Kind == authz.BaselineEvent && c.BaselineVersion != prev.Config.BaselineVersion+1:
					return broken("record %d records event baseline version %d after version %d (record %d): versions rise by one", r.Seq, c.BaselineVersion, prev.Config.BaselineVersion, prev.Seq)
				}
			}
			recorded[k] = r
		case r.Action == ActionConfigReadCompared:
			run, asset := runs[num{epoch, r.Config.ReadSeq}], r.Target.AssetID
			if err := readCompared(r, run, active[kindOf{asset, authz.BaselineConfiguration}],
				lastChange[baseline{asset, r.Config.BaselineDigest}], resulted[num{epoch, r.Config.ReadSeq}]); err != nil {
				return err
			}
			if err := inOrder(r, run); err != nil {
				return err
			}
			if r.Config.SnapshotSeq <= lastSnap[asset] {
				return broken("record %d has snapshot_seq %d, but the asset's previous compared read has %d: stream seqs increase", r.Seq, r.Config.SnapshotSeq, lastSnap[asset])
			}
			lastSnap[asset] = r.Config.SnapshotSeq
			resulted[num{epoch, r.Config.ReadSeq}] = r.Action
			pending[asset] = append(pending[asset], compared{r.Config.SnapshotDigest, r.Config.SnapshotSeq})
		case r.Action == ActionConfigReadsRemoved:
			p := pending[r.Target.AssetID]
			c := r.Config
			if c.RemovedCount+keptReads > len(p) {
				return broken("record %d removes %d reads of asset %s, but only %d compared reads are recorded and the %d newest stay", r.Seq, c.RemovedCount, r.Target.AssetID, len(p), keptReads)
			}
			digests := make([]string, c.RemovedCount)
			for i := range digests {
				digests[i] = p[i].digest
			}
			switch {
			case c.RemovedDigest != RemovedReadsDigest(digests):
				return broken("record %d: removed_digest is not the digest of the %d oldest compared reads of asset %s", r.Seq, c.RemovedCount, r.Target.AssetID)
			case c.RemovedFirstSeq != p[0].seq || c.RemovedLastSeq != p[c.RemovedCount-1].seq:
				return broken("record %d: the range %d to %d is not the snapshot_seq of the first and last of the %d reads removed (%d to %d)", r.Seq, c.RemovedFirstSeq, c.RemovedLastSeq, c.RemovedCount, p[0].seq, p[c.RemovedCount-1].seq)
			case c.KeptDigest != p[len(p)-1].digest:
				return broken("record %d: kept_digest is not the newest compared read of asset %s", r.Seq, r.Target.AssetID)
			}
			pending[r.Target.AssetID] = p[c.RemovedCount:]
		}
	}
	return nil
}

// readCompared checks a config.read_compared record (0.7) against what the
// chain has so far: the run it names (nil when none), the asset's active
// configuration baseline, the asset's newest recorded change against the
// baseline it names (nil when none, or ended by a restore or
// acknowledgement), and the result its read has already been given (the
// zero action when none). A read has one result, it compares against the
// acknowledged baseline, a no_difference read cannot follow a recorded change
// the baseline has not been restored from, and a same_change read repeats the
// newest recorded change exactly, by its changes digest.
func readCompared(r, run *Record, active string, last *Record, given Action) error {
	c := r.Config
	switch {
	case run == nil || run.Target.AssetID != r.Target.AssetID:
		return broken("record %d names read decision %d, which is not an earlier run on asset %s in its epoch", r.Seq, c.ReadSeq, r.Target.AssetID)
	case given != "":
		return broken("record %d gives read decision %d a second result: %s already has it", r.Seq, c.ReadSeq, given)
	}
	if err := acknowledged(r, active); err != nil {
		return err
	}
	switch r.ReasonCode {
	case ReasonNoDifference:
		if last != nil {
			return broken("record %d reports no difference from baseline %s, but record %d recorded a change against it and no restore or acknowledgement ended it", r.Seq, c.BaselineDigest, last.Seq)
		}
	case ReasonSameChange:
		switch {
		case last == nil || last.Seq != c.ChangeSeq:
			return broken("record %d repeats change %d, which is not the newest recorded change against baseline %s", r.Seq, c.ChangeSeq, c.BaselineDigest)
		case last.Config.ChangesDigest == "" || last.Config.ChangesDigest != c.ChangesDigest:
			return broken("record %d repeats change %d with changes_digest %s, but that change has %q", r.Seq, c.ChangeSeq, c.ChangesDigest, last.Config.ChangesDigest)
		}
	}
	return nil
}

// acknowledged checks that r names the asset's active configuration
// baseline: the one the last succeeded configuration-kind acknowledgement
// set ("" when recs holds none).
func acknowledged(r *Record, active string) error {
	switch {
	case active == "":
		return broken("record %d (%s) names baseline %s, but no earlier acknowledgement set a configuration baseline for asset %s", r.Seq, r.Action, r.Config.BaselineDigest, r.Target.AssetID)
	case r.Config.BaselineDigest != active:
		return broken("record %d (%s) names baseline %s, but the asset's acknowledged configuration baseline is %s", r.Seq, r.Action, r.Config.BaselineDigest, active)
	}
	return nil
}

// unchangedRead checks a detection's unchanged_read_seq and unchanged_at
// against the runs of its operation on its asset in this epoch, in chain
// order, and the collector.seq_reset that began the epoch (nil in the
// first).
func unchangedRead(r *Record, runs []*Record, reset *Record) error {
	c := r.Config
	var last *Record
	for _, run := range runs {
		if run.CollectorSeq < c.ReadSeq {
			last = run
		}
	}
	bound := last
	switch {
	case last != nil && c.UnchangedReadSeq != last.CollectorSeq:
		return broken("record %d names unchanged read %d, but the asset's last run before read %d is %d", r.Seq, c.UnchangedReadSeq, c.ReadSeq, last.CollectorSeq)
	case last == nil && c.UnchangedReadSeq != 0:
		return broken("record %d names unchanged read %d, but no earlier run on the asset is in its epoch", r.Seq, c.UnchangedReadSeq)
	case last == nil && reset == nil:
		return broken("record %d names no unchanged read, but its epoch has no collector reset to bound the change", r.Seq)
	case last == nil:
		bound = reset
	}
	want, err := parseConfigTime(bound.Time.UTC)
	if err != nil {
		return broken("record %d: the record its unchanged_at names has no usable time: %v", r.Seq, err)
	}
	if got, err := parseConfigTime(c.UnchangedAt); err != nil || !got.Equal(want) {
		return broken("record %d: unchanged_at %q is not the time of record %d (%s)", r.Seq, c.UnchangedAt, bound.Seq, bound.Time.UTC)
	}
	return nil
}
