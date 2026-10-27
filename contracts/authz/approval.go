package authz

import (
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode"
	"unicode/utf8"
)

// The configuration kinds (0.6, P4-A3, D4-2). Both are admin-signed node
// kinds, like the 0.5 ones: the collector verifies, spends the nonce,
// checks that it collects from the asset, numbers the decision, and changes
// nothing of its own. The node acts on its own part only once the collector
// has accepted (CollectorReply.AdminAcceptance). See the package
// documentation, "Change approvals and baseline acknowledgements".
const (
	// KindNodeChangeApproval approves, in advance, a change to one asset's
	// configuration against the baseline it names, for a bounded window.
	KindNodeChangeApproval RequestKind = "node.change_approval"
	// KindNodeBaselineAck acknowledges one baseline, configuration or
	// event, as the asset's baseline.
	KindNodeBaselineAck RequestKind = "node.baseline_ack"
	// configKindsSince is the minor that added the two kinds and
	// AdminKey.Kinds.
	configKindsSince = 6
)

const (
	// MaxApprovalWindow is the longest an approval's window may be. A
	// payload with a longer window is refused (payload).
	MaxApprovalWindow = 24 * time.Hour
	// DefaultApprovalWindow is the window an admin client offers when the
	// administrator names none. The collector does not apply it: a payload
	// always states its window.
	DefaultApprovalWindow = 4 * time.Hour
	// MaxApprovalLead is how far ahead of the collector's clock an
	// approval's window may start (window), so an approval cannot wait
	// unnoticed for months.
	MaxApprovalLead = 7 * 24 * time.Hour
	// MaxApprovalReason bounds the reason in bytes.
	MaxApprovalReason = 256
)

// BaselineKind is what a baseline describes.
type BaselineKind string

const (
	BaselineConfiguration BaselineKind = "configuration" // a C9 configuration snapshot
	BaselineEvent         BaselineKind = "event"         // a C10 event-behaviour baseline
)

// baselineDigestPattern is the text form C9 and C10 give a baseline's
// hash: "sha256:" and the SHA-256 of the baseline record's exact stored
// bytes, in lowercase hex (D4-4 item 5). The collector checks the shape
// only; the node compares it with the hash of the bytes it holds, never
// with a hash anyone reports.
var baselineDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// NodeChangeApprovalBody (since 0.6) approves a change to one asset's
// configuration in advance (R3.4, R3.6). The approver is the envelope's
// signed principal, and the nonce and expiry are the payload's own, so
// none is repeated here (D4-2).
//
// "In advance" is decided by order, never by a time written here: the
// collector numbers its acceptance, and a difference counts as approved
// only if that number is below the number of the configuration read that
// found it. The window bounds when the change may happen. It is at most
// MaxApprovalWindow long, may not start more than MaxApprovalLead ahead of
// the collector's clock, and may not have ended when the collector
// verifies it. An approved change never moves the baseline: the new
// snapshot needs its own node.baseline_ack.
type NodeChangeApprovalBody struct {
	AssetID string `json:"asset_id"`
	// BaselineDigest names the configuration baseline the change is
	// approved against, as C9 writes its hash.
	BaselineDigest string `json:"baseline_digest"`
	WindowStart    string `json:"window_start"` // RFC 3339, UTC
	WindowEnd      string `json:"window_end"`   // RFC 3339, UTC, after WindowStart
	// Reason is the administrator's words for the change: printable
	// UTF-8, at most MaxApprovalReason bytes. It is shown with any alarm
	// the approval silences.
	Reason string `json:"reason"`
}

// Window returns the parsed window; it is valid on a body that passed
// validation.
func (b *NodeChangeApprovalBody) Window() (start, end time.Time) {
	start, _ = time.Parse(time.RFC3339, b.WindowStart)
	end, _ = time.Parse(time.RFC3339, b.WindowEnd)
	return start, end
}

// NodeBaselineAckBody (since 0.6) acknowledges one baseline as the asset's
// baseline of its kind (R3.2, R4.8). The node adopts it only when it holds
// a baseline of that asset and kind whose stored bytes hash to
// BaselineDigest; otherwise it refuses and audits the refusal. Only an
// acknowledgement moves a baseline: neither a first snapshot nor an
// approved change does.
type NodeBaselineAckBody struct {
	AssetID        string       `json:"asset_id"`
	Kind           BaselineKind `json:"kind"`
	BaselineDigest string       `json:"baseline_digest"`
}

func (b *NodeChangeApprovalBody) validate() error {
	switch {
	case !assetIDPattern.MatchString(b.AssetID):
		return refuse(RefuseInvalid, "asset_id")
	case !baselineDigestPattern.MatchString(b.BaselineDigest):
		return refuse(RefuseInvalid, "baseline_digest")
	}
	var w [2]time.Time
	for i, ts := range []string{b.WindowStart, b.WindowEnd} {
		t, err := parseUTC(ts)
		if err != nil {
			return refuse(RefuseInvalid, "window: %v", err)
		}
		w[i] = t
	}
	switch {
	case !w[1].After(w[0]):
		return refuse(RefuseInvalid, "window ends before it starts")
	case w[1].Sub(w[0]) > MaxApprovalWindow:
		return refuse(RefuseInvalid, "window is longer than %s", MaxApprovalWindow)
	}
	if err := validReason(b.Reason); err != nil {
		return refuse(RefuseInvalid, "reason: %v", err)
	}
	return nil
}

func (b *NodeBaselineAckBody) validate() error {
	switch {
	case !assetIDPattern.MatchString(b.AssetID):
		return refuse(RefuseInvalid, "asset_id")
	case b.Kind != BaselineConfiguration && b.Kind != BaselineEvent:
		return refuse(RefuseInvalid, "kind %q", b.Kind)
	case !baselineDigestPattern.MatchString(b.BaselineDigest):
		return refuse(RefuseInvalid, "baseline_digest")
	}
	return nil
}

// validReason accepts non-empty UTF-8 of at most MaxApprovalReason bytes
// with no control character, so the reason prints on one line in an alarm
// and a log.
func validReason(s string) error {
	switch {
	case s == "":
		return errors.New("empty")
	case len(s) > MaxApprovalReason:
		return fmt.Errorf("over %d bytes", MaxApprovalReason)
	case !utf8.ValidString(s):
		return errors.New("not UTF-8")
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return errors.New("has a control character")
		}
	}
	return nil
}

// parseUTC parses an RFC 3339 UTC time written in its canonical form, the
// same rule as issued_at and expires_at.
func parseUTC(ts string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil || t.Location() != time.UTC || t.Format(time.RFC3339Nano) != ts {
		return time.Time{}, fmt.Errorf("time %q is not RFC 3339 UTC", ts)
	}
	return t, nil
}

// checkApprovalWindow is the window step's rule for a change approval,
// judged at the collector's clock: the window has not ended, and starts at
// most MaxApprovalLead ahead.
func (b *NodeChangeApprovalBody) checkWindow(now time.Time) *AdminRejected {
	start, end := b.Window()
	switch {
	case !end.After(now):
		return adminReject(AdminCheckWindow, "the approval's window has ended")
	case start.After(now.Add(MaxApprovalLead)):
		return adminReject(AdminCheckWindow, "the approval's window starts more than %s ahead", MaxApprovalLead)
	}
	return nil
}

// DefaultAdminKinds are the kinds a key pinned without a list may sign:
// exactly the 0.5 kinds. A key gets node.change_approval or
// node.baseline_ack only when its list names them, so pinning nothing new
// fails closed (D4-2).
var DefaultAdminKinds = []RequestKind{
	KindCredentialInstall, KindCredentialRevoke, KindCredentialClearSusp, KindAssetClearSusp,
	KindNodeQuarantineClear, KindNodeSeqResetAck,
}

// Allows reports whether the key may sign kind: a kind in its list, or in
// DefaultAdminKinds when it has none (nil). An empty, non-nil list allows
// nothing.
func (k *AdminKey) Allows(kind RequestKind) bool {
	kinds := k.Kinds
	if kinds == nil {
		kinds = DefaultAdminKinds
	}
	for _, x := range kinds {
		if x == kind {
			return true
		}
	}
	return false
}

// ValidateAdminKinds checks a pinned key's list: admin kinds only, each
// once. The collector refuses to start with a key whose list fails it.
func ValidateAdminKinds(kinds []RequestKind) error {
	seen := map[RequestKind]bool{}
	for _, k := range kinds {
		switch {
		case !adminKinds[k]:
			return fmt.Errorf("authz: %q is not a kind an administrator signs", k)
		case seen[k]:
			return fmt.Errorf("authz: %q is listed twice", k)
		}
		seen[k] = true
	}
	return nil
}
