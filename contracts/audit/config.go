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

// configSince is the minor that added the configuration actions, Config and
// Admin.Kind; configReadsSince the one that added the read actions.
const (
	configSince      = 5
	configReadsSince = 7
)

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
	// Kind is the baseline's kind, on config.baseline_acknowledged only.
	Kind           authz.BaselineKind `json:"kind,omitempty"`
	BaselineDigest string             `json:"baseline_digest,omitempty"`
	// PreviousDigest is the baseline of the same asset and kind that the
	// acknowledgement replaces (or would have replaced, when denied), on
	// config.baseline_acknowledged only; absent for the asset's first. With
	// it, C8 alone shows each asset's succession of baselines after the
	// baseline records themselves are pruned (B4 on #250).
	PreviousDigest string `json:"previous_digest,omitempty"`
	WindowStart    string `json:"window_start,omitempty"`
	WindowEnd      string `json:"window_end,omitempty"`
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
	// ChangeSeq (0.7) is the seq of the config.change_detected record that a
	// same_change read repeats.
	ChangeSeq uint64 `json:"change_seq,omitempty"`
	// The removal fields (0.7), on config.reads_removed only. RemovedCount
	// reads of the asset were removed from its configuration stream, the
	// oldest of those the chain records as compared and not yet removed;
	// RemovedFirstSeq and RemovedLastSeq are the stream seqs of the first
	// and last of them, and RemovedDigest is RemovedReadsDigest of their
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
	if !approved && !acked && !detected && !restored && !compared && !removed {
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
	if removed {
		return r.validateReadsRemoved()
	}
	if !digestPattern.MatchString(c.BaselineDigest) {
		return fmt.Errorf("audit: %s needs baseline_digest sha256:<hex>", r.Action)
	}
	if approved || acked {
		if c.ChangesDigest != "" || c.ChangeSeq != 0 || c.removalFields() {
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
		case c.ChangesDigest != "" || c.ChangeSeq != 0:
			return errors.New("audit: config.baseline_restored has no changes_digest or change_seq")
		case r.Outcome != OutcomeInfo || r.ReasonCode != "":
			return errors.New("audit: config.baseline_restored has outcome info and no reason code")
		}
		return nil
	}
	if compared {
		return r.validateReadCompared()
	}
	switch {
	case c.ChangeSeq != 0:
		return errors.New("audit: config.change_detected has no change_seq")
	case minor < configReadsSince && c.ChangesDigest != "":
		return fmt.Errorf("audit: changes_digest is new in 0.%d, so a 0.%d record cannot carry it", configReadsSince, minor)
	case minor >= configReadsSince && !digestPattern.MatchString(c.ChangesDigest):
		return errors.New("audit: config.change_detected needs changes_digest sha256:<hex> from 0.7")
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
		c.ReadSeq != 0 || c.UnchangedAt != "" || c.UnchangedReadSeq != 0 || c.ApprovalSeq != 0 || c.ChangesDigest != "" || c.ChangeSeq != 0:
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
// Each succeeded config.baseline_acknowledged names, as previous_digest, the
// baseline of its asset and kind that the last succeeded acknowledgement in
// recs set, or none when recs shows none and it is the asset's first; so a
// node cannot record a skipped or reordered succession.
//
// From 0.7 each config.read_compared names a real read of its asset that has
// no other result, against the asset's acknowledged baseline; reports no
// difference only when no change recorded against that baseline is still
// open (a restore or a configuration acknowledgement ends it); and repeats a
// change only by naming the newest one, by seq and changes_digest. Each
// config.reads_removed takes the oldest compared reads of its asset that no
// earlier removal took, leaving the two newest recorded (keptReads), with the
// removed_digest of those and the newest's digest as kept_digest.
//
// A collector.seq_reset starts a new epoch: numbers from before it name
// nothing after it, so an approval does not survive a collector reinstall.
// recs must start at the chain's first record, or at a point before every
// acceptance and read the records in it name, before the acknowledgement of
// each configuration baseline they name, and before the last run on each
// asset ahead of each detection.
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
	// 0.7 (D4-20): the newest recorded change against each baseline, until a
	// restore or a configuration acknowledgement ends it; the result each
	// read has been given; and, for each asset, the snapshot digests of its
	// compared reads that a config.reads_removed has not yet taken.
	lastChange := map[baseline]*Record{}
	resulted := map[num]Action{}
	pending := map[string][]string{}
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
		case r.Action == ActionConfigReadCompared:
			if err := readCompared(r, runs[num{epoch, r.Config.ReadSeq}], active[kindOf{r.Target.AssetID, authz.BaselineConfiguration}],
				lastChange[baseline{r.Target.AssetID, r.Config.BaselineDigest}], resulted[num{epoch, r.Config.ReadSeq}]); err != nil {
				return err
			}
			resulted[num{epoch, r.Config.ReadSeq}] = r.Action
			pending[r.Target.AssetID] = append(pending[r.Target.AssetID], r.Config.SnapshotDigest)
		case r.Action == ActionConfigReadsRemoved:
			p := pending[r.Target.AssetID]
			c := r.Config
			switch {
			case c.RemovedCount+keptReads > len(p):
				return broken("record %d removes %d reads of asset %s, but only %d compared reads are recorded and the %d newest stay", r.Seq, c.RemovedCount, r.Target.AssetID, len(p), keptReads)
			case c.RemovedDigest != RemovedReadsDigest(p[:c.RemovedCount]):
				return broken("record %d: removed_digest is not the digest of the %d oldest compared reads of asset %s", r.Seq, c.RemovedCount, r.Target.AssetID)
			case c.KeptDigest != p[len(p)-1]:
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
