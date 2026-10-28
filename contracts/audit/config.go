package audit

import (
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

// configSince is the minor that added the configuration actions, Config and
// Admin.Kind.
const configSince = 5

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
//     approval covers the difference.
//   - config.baseline_restored: baseline_digest, snapshot_digest and
//     read_seq of the first read equal to the baseline after a recorded
//     difference from it.
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
	BaselineDigest string             `json:"baseline_digest"`
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
	if !approved && !acked && !detected && !restored {
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
	if !digestPattern.MatchString(c.BaselineDigest) {
		return fmt.Errorf("audit: %s needs baseline_digest sha256:<hex>", r.Action)
	}
	if approved || acked {
		return r.validateConfigDecision(approved)
	}
	switch {
	case r.Actor.Type != authz.PrincipalNode:
		return fmt.Errorf("audit: %s is written by the node (actor type node)", r.Action)
	case c.DecisionSeq != 0 || c.PayloadSHA256 != "" || c.Kind != "" || c.WindowStart != "" || c.WindowEnd != "" || c.Reason != "" || c.PreviousDigest != "":
		return fmt.Errorf("audit: %s carries no approval or acknowledgement fields", r.Action)
	case !digestPattern.MatchString(c.SnapshotDigest) || c.ReadSeq == 0:
		return fmt.Errorf("audit: %s needs snapshot_digest sha256:<hex> and read_seq", r.Action)
	}
	if restored {
		switch {
		case c.DifferenceDigest != "" || c.UnchangedAt != "" || c.UnchangedReadSeq != 0 || c.ApprovalSeq != 0:
			return errors.New("audit: config.baseline_restored has no difference, unchanged or approval fields")
		case r.Outcome != OutcomeInfo || r.ReasonCode != "":
			return errors.New("audit: config.baseline_restored has outcome info and no reason code")
		}
		return nil
	}
	switch {
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
// (0.5), so that a node cannot silence an alarm with an approval that does
// not exist or does not cover it:
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
//     config.baseline_restored for that baseline follows the alarm. An
//     approval accepted after the alarm therefore never silences the change
//     that raised it; ending that alarm takes a baseline acknowledgement
//     (which moves the baseline) or a return to the baseline, recorded.
//
// Each succeeded config.baseline_acknowledged names, as previous_digest, the
// baseline of its asset and kind that the last succeeded acknowledgement in
// recs set, or none when recs shows none and it is the asset's first; so a
// node cannot record a skipped or reordered succession.
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
	alarmed := map[baseline]bool{} // an unapproved difference with no restore after it
	type kindOf struct {
		asset string
		kind  authz.BaselineKind
	}
	active := map[kindOf]string{} // the baseline the last succeeded acknowledgement set
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
