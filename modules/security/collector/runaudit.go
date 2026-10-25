package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
)

// RunAudit builds the pending C8 records a run reports (C7-A5-2): each
// carries the run's actor, target and invocation ID, and a collector_seq
// taken durably from the state. The collector writes no audit record
// itself; the node checks these (collectorclient) and writes them.
type RunAudit struct {
	nodeID     string
	now        func() time.Time
	nextSeq    func() (uint64, error)
	actor      audit.Actor
	target     audit.Target
	invocation string
	alarm      func(error)
	records    []json.RawMessage
}

// reasonPattern is C8's reason code syntax.
var reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)

func newRunAudit(p *Pipeline, plan *RunPlan) *RunAudit {
	t := audit.Target{
		AssetID:            plan.Asset.AssetID,
		Transport:          authz.Transport(plan.Endpoint.Transport),
		DownstreamSecurity: authz.DownstreamSecurity(plan.Endpoint.DownstreamSecurity.Level),
	}
	if plan.Register != nil {
		t.Family = plan.Register.Family
	}
	if plan.Credential != nil {
		t.CredentialRef, t.CredentialVersion = plan.Credential.ID, plan.Credential.Version
	}
	return &RunAudit{
		nodeID: p.cfg.NodeID, now: p.cfg.Now, nextSeq: plan.NextSeq,
		actor:      audit.Actor{Type: plan.Principal.Type, ID: plan.Principal.ID, Role: authz.RoleCollector},
		target:     t,
		invocation: plan.Invocation.InvocationID,
		alarm:      p.cfg.Alarm,
	}
}

// Add numbers and builds one record. mod sets the action's own fields. A
// record that cannot be numbered or does not validate is not reported, and
// the run raises an alarm: the node then sees the missing number as a gap,
// which is the honest outcome (audit.VerifyCollectorSeq).
func (a *RunAudit) Add(action audit.Action, outcome audit.Outcome, reason string, mod func(*audit.Record)) {
	if a == nil {
		return
	}
	seq, err := a.nextSeq()
	if err != nil {
		a.alarm(fmt.Errorf("collector: number %s for %s: %w", action, a.invocation, err))
		return
	}
	t := a.target
	r := audit.Record{
		Contract: audit.ContractID, NodeID: a.nodeID, Time: recordTime(a.now()),
		Actor: a.actor, Action: action, Outcome: outcome, ReasonCode: reason,
		Target: &t, CorrelationID: a.invocation, CollectorSeq: seq,
	}
	if mod != nil {
		mod(&r)
	}
	b, err := json.Marshal(r)
	if err == nil {
		_, err = audit.ValidatePending(b)
	}
	if err != nil {
		a.alarm(fmt.Errorf("collector: %s record for %s (collector_seq %d) not reported: %w", action, a.invocation, seq, err))
		return
	}
	a.records = append(a.records, b)
}

// Records returns the records built so far, in collector_seq order.
func (a *RunAudit) Records() []json.RawMessage {
	if a == nil {
		return nil
	}
	return append([]json.RawMessage(nil), a.records...)
}

// recordTime is the collector's clock as a C8 time. The collector runs on
// the node's host, so this is the node clock (C8-A4-3); its sync state is
// not known here.
func recordTime(t time.Time) audit.Time {
	return audit.Time{UTC: t.UTC().Format("2006-01-02T15:04:05.000000Z"), ResolutionNS: 1000, Clock: audit.Clock{Sync: event.SyncUnknown}}
}

// codeReason is a C2 code as a C8 reason: its name without the status, for
// example identity_mismatch for refused.identity_mismatch.
func codeReason(c adapter.Code) string {
	_, name, _ := strings.Cut(string(c), ".")
	if !reasonPattern.MatchString(name) {
		return "unknown"
	}
	return name
}

// suspendReason is a C7 suspension reason as a C8 reason: auth_failed for
// auth-failed.
func suspendReason(r authz.SuspendReason) string {
	name := strings.ReplaceAll(string(r), "-", "_")
	if !reasonPattern.MatchString(name) {
		return "unknown"
	}
	return name
}

// warningReason is a C3 posture warning ID as a C8 reason: maxacc_above_1
// for warn.maxacc_above_1.
func warningReason(id string) string {
	name := strings.TrimPrefix(id, "warn.")
	if !reasonPattern.MatchString(name) {
		return "unrecognized_warning"
	}
	return name
}

// ReportSession adds the records of one C2 result, in the order the session
// ran: the open, the credential use, each C2 refusal and posture warning,
// the operation, and the close with the transcript digest (D1-25).
// confirmed is whether the floor gate saw the login confirmed.
func (a *RunAudit) ReportSession(res adapter.Result, confirmed bool) {
	var code adapter.Code
	if res.Error != nil {
		code = res.Error.Code
	}
	session := res.Session.Connected || len(res.Transcript.Data) > 0
	if session {
		a.Add(audit.ActionDeviceSessionOpen, audit.OutcomeSucceeded, "", nil)
	}
	if res.Session.CredentialSent {
		if confirmed {
			a.Add(audit.ActionCredentialUse, audit.OutcomeSucceeded, "", nil)
		} else {
			reason := "login_not_confirmed"
			if code != "" {
				reason = codeReason(code)
			}
			a.Add(audit.ActionCredentialUse, audit.OutcomeFailed, reason, nil)
		}
	}
	for _, w := range res.Warnings {
		a.Add(audit.ActionDevicePostureWarning, audit.OutcomeWarning, warningReason(w.Code), func(r *audit.Record) {
			r.Detail = truncate(w.Setting, 128)
		})
	}
	if res.Status == adapter.StatusRefused {
		a.Add(audit.ActionDeviceRefused, audit.OutcomeDenied, codeReason(code), nil)
	}
	// The operation: done (ok, partial), or failed once the operate phase
	// had sent something. A refusal stops before the operation, even after
	// a check read in the operate phase, and device.refused records it.
	sent, operated := operateBytes(res.Transcript)
	if res.Status == adapter.StatusOK || res.Status == adapter.StatusPartial || (res.Status == adapter.StatusFailed && operated) {
		outcome, reason := audit.OutcomeSucceeded, ""
		if res.Status == adapter.StatusFailed {
			outcome, reason = audit.OutcomeFailed, codeReason(code)
		}
		a.Add(audit.ActionDeviceOp, outcome, reason, func(r *audit.Record) {
			r.OperationID = res.OperationID
			if operated {
				// A Level 0 read sends its line in the probe phase, so it
				// has no operate bytes and no digest.
				sum := sha256.Sum256(sent)
				r.BytesSentDigest = "sha256:" + hex.EncodeToString(sum[:])
			}
		})
	}
	if session {
		outcome, reason := audit.OutcomeSucceeded, ""
		if confirmed && !res.Session.QuitSent {
			outcome, reason = audit.OutcomeFailed, "qui_not_sent" // C7-A6-2
		}
		a.Add(audit.ActionDeviceSessionClose, outcome, reason, func(r *audit.Record) { r.TranscriptSHA256 = res.Transcript.SHA256 })
	}
}

// operateBytes is every byte sent in the operate phase, as stored
// (redactions included), and whether there was any.
func operateBytes(t adapter.Transcript) ([]byte, bool) {
	var out []byte
	any := false
	for _, sg := range t.Segments {
		if sg.Dir != adapter.Sent || sg.Phase != adapter.PhaseOperate || sg.Offset < 0 || sg.Offset+sg.Length > int64(len(t.Data)) {
			continue
		}
		any = true
		out = append(out, t.Data[sg.Offset:sg.Offset+sg.Length]...)
	}
	return out, any
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
