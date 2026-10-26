package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/node"
	"otsec.local/otsec/contracts/version"
)

// ContractID is the identifier every audit record carries.
const ContractID = "otsec.audit/0.4"

// MaxRecordBytes bounds one stored record. It is stable for every 0.x minor:
// a forwarder sizes its targets by it (C8-A4-6), so a later minor may lower
// what writers produce but never raise this bound.
const MaxRecordBytes = 16 << 10

var (
	nodeIDPattern = regexp.MustCompile(node.IDPattern) // D1-1
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// adminKeyIDPattern and adminNoncePattern are C7's (authz.AdminKeyID,
	// AdminRequest.Nonce), copied as the schema states them.
	adminKeyIDPattern = regexp.MustCompile(`^ed25519-[0-9a-f]{16}$`)
	adminNoncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	hashPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	codePattern       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	clockWordRegexp   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)     // an open clock source word
	operationIDPat    = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_]+)+$`) // TODO(C3): exported pattern
	// TODO(C2): C2's code syntax, status then name, e.g. failed.auth_rejected.
	c2CodePattern = regexp.MustCompile(`^(ok|refused|failed|partial)\.[a-z][a-z0-9_]{0,63}$`)
)

// Time is the platform timestamp of a record: C4's event.Received, so audit
// records and events share one clock vocabulary (C8-A4-3). It is always the
// node's clock; a record never carries a device time.
type Time = event.Received

// Clock is the node clock's state when the record was written (C4).
type Clock = event.Clock

func validateTime(t Time) error {
	parsed, err := time.Parse(time.RFC3339Nano, t.UTC)
	if err != nil || parsed.Location() != time.UTC || !strings.HasSuffix(t.UTC, "Z") {
		return fmt.Errorf("audit: time %q is not RFC 3339 UTC with Z", t.UTC)
	}
	if t.ResolutionNS <= 0 {
		return errors.New("audit: resolution_ns must be positive")
	}
	digits := 0
	if i := strings.IndexByte(t.UTC, '.'); i >= 0 {
		digits = len(t.UTC) - i - 2 // between '.' and 'Z'
	}
	granularity := int64(1_000_000_000)
	for i := 0; i < digits; i++ {
		granularity /= 10
	}
	if granularity < t.ResolutionNS {
		return fmt.Errorf("audit: time %q claims more precision than resolution %d ns", t.UTC, t.ResolutionNS)
	}
	switch t.Clock.Sync {
	case event.SyncSynchronized, event.SyncUnsynchronized, event.SyncUnknown:
	default:
		return fmt.Errorf("audit: clock sync %q is not valid", t.Clock.Sync)
	}
	if t.Clock.Source != "" && !clockWordRegexp.MatchString(t.Clock.Source) {
		return fmt.Errorf("audit: clock source %q is not valid", t.Clock.Source)
	}
	return nil
}

// Actor is who acted: a C7 principal, plus the role and session it acted in.
type Actor struct {
	Type       authz.PrincipalType `json:"type"`
	ID         string              `json:"id"`
	Role       authz.Role          `json:"role,omitempty"`
	SessionID  string              `json:"session_id,omitempty"`
	AuthMethod string              `json:"auth_method,omitempty"`
}

// Action is the closed set of audited actions in 0.2. A reader that meets an
// action it does not know keeps the record (the chain covers it) and shows it
// as ActionUnrecognized.
type Action string

const (
	ActionCollectorRequest     Action = "collector.request"           // every C7 request, accepted or refused
	ActionDeviceSessionOpen    Action = "device.session.open"         //
	ActionDeviceSessionClose   Action = "device.session.close"        //
	ActionCredentialUse        Action = "credential.use"              // the transport sent a credential through the slot
	ActionDeviceOp             Action = "device.op"                   // one register operation ran
	ActionDeviceRefused        Action = "device.refused"              // a C2 refusal (FID gate, LANG, no password prompt, ...)
	ActionDevicePostureWarning Action = "device.posture_warning"      // a C2 posture warning (MAXACC, FTPACC, HTTPACC)
	ActionCredentialInstall    Action = "credential.install"          //
	ActionCredentialRevoke     Action = "credential.revoke"           //
	ActionCredentialSuspend    Action = "credential.suspend"          //
	ActionCredentialClearSusp  Action = "credential.clear_suspension" //
	ActionRegisterVerify       Action = "register.verify"             //
	ActionRegisterActivate     Action = "register.activate"           //
	ActionAuthLogin            Action = "auth.login"                  //
	ActionAuthFail             Action = "auth.fail"                   //
	ActionAuthLogout           Action = "auth.logout"                 //
	ActionRoleGrant            Action = "role.grant"                  //
	ActionRoleRevoke           Action = "role.revoke"                 //
	ActionPolicyApply          Action = "policy.apply"                //
	ActionAuditChainStart      Action = "audit.chain.start"           // first record on a node
	ActionAuditCheckpoint      Action = "audit.checkpoint"            // a confirming receiver acknowledged (seq, hash)
	ActionAuditExport          Action = "audit.export"                //
	ActionClockChange          Action = "clock.change"                //
	ActionStorageAlarm         Action = "storage.alarm"               //
	ActionServiceStart         Action = "service.start"               //
	ActionServiceStop          Action = "service.stop"                //
	ActionStoreModeChange      Action = "store.mode_change"           // C5 mode change; reason_code is the new mode
	ActionNodePostureChange    Action = "node.posture_change"         // a posture label or standing condition was raised or cleared
	ActionNodeMigrationDate    Action = "node.migration_date"         // an admin recorded or changed the OS migration date (HR-9)
	ActionAssetCollectorAssign Action = "asset.collector_assign"      // collection of an asset moved to another node (A1 D1-3)
	// 0.2 (docs/phase2/A3-c8-seq-reset.md). All five are written by the node.
	ActionCollectorInstallKey  Action = "collector.install_key"   // the node trusts this collector install key (first start)
	ActionCollectorSeqReset    Action = "collector.seq_reset"     // the collector's numbering restarted: a reinstall
	ActionCollectorSeqResetAck Action = "collector.seq_reset_ack" // an admin acknowledged a reset on the key they confirmed
	ActionAssetSuspend         Action = "asset.suspend"           // the node suspended an asset (C1 Suspension)
	ActionAssetSuspensionClear Action = "asset.suspension_clear"  // an admin cleared an asset suspension
	// 0.3 (P3-A5 quarantine export and clear, A1 D3-1). Both are written by
	// the node.
	ActionQuarantineExported Action = "quarantine.exported" // the node verified an export manifest against its quarantine stream
	ActionQuarantineCleared  Action = "quarantine.cleared"  // the node applied an administrator's quarantine clear, before removing anything
	ActionUnrecognized       Action = "unrecognized"        // reader fallback only; never written
)

var actions = map[Action]bool{}

func init() {
	for _, a := range []Action{
		ActionCollectorRequest, ActionDeviceSessionOpen, ActionDeviceSessionClose, ActionCredentialUse,
		ActionDeviceOp, ActionDeviceRefused, ActionDevicePostureWarning, ActionCredentialInstall,
		ActionCredentialRevoke, ActionCredentialSuspend, ActionCredentialClearSusp, ActionRegisterVerify,
		ActionRegisterActivate, ActionAuthLogin, ActionAuthFail, ActionAuthLogout, ActionRoleGrant,
		ActionRoleRevoke, ActionPolicyApply, ActionAuditChainStart, ActionAuditCheckpoint, ActionAuditExport,
		ActionClockChange, ActionStorageAlarm, ActionServiceStart, ActionServiceStop,
		ActionStoreModeChange, ActionNodePostureChange, ActionNodeMigrationDate, ActionAssetCollectorAssign,
		ActionCollectorInstallKey, ActionCollectorSeqReset, ActionCollectorSeqResetAck, ActionAssetSuspend, ActionAssetSuspensionClear,
		ActionQuarantineExported, ActionQuarantineCleared,
	} {
		actions[a] = true
	}
}

// actionSince is the minor that added an action; absent means 0.1. A record
// stamped with an earlier minor cannot carry it.
var actionSince = map[Action]int{
	ActionCollectorInstallKey: 2, ActionCollectorSeqReset: 2, ActionCollectorSeqResetAck: 2, ActionAssetSuspend: 2, ActionAssetSuspensionClear: 2,
	ActionQuarantineExported: 3, ActionQuarantineCleared: 3,
}

// Normalize maps an action this reader does not know to ActionUnrecognized.
func (a Action) Normalize() Action {
	if actions[a] {
		return a
	}
	return ActionUnrecognized
}

// Outcome is the closed set of outcomes.
type Outcome string

const (
	OutcomeAllowed   Outcome = "allowed"   // a request was accepted
	OutcomeDenied    Outcome = "denied"    // a request or device step was refused
	OutcomeSucceeded Outcome = "succeeded" // an action completed
	OutcomeFailed    Outcome = "failed"    // an action was attempted and failed
	OutcomeWarning   Outcome = "warning"   // a posture warning; collection continued
	OutcomeInfo      Outcome = "info"      // a state record such as service.start
)

// Target is what an action was applied to.
type Target struct {
	AssetID            string                   `json:"asset_id,omitempty"`
	Transport          authz.Transport          `json:"transport,omitempty"`
	DownstreamSecurity authz.DownstreamSecurity `json:"downstream_security,omitempty"`
	CredentialRef      string                   `json:"credential_ref,omitempty"`
	CredentialVersion  uint32                   `json:"credential_version,omitempty"`
	Family             string                   `json:"family,omitempty"` // register family, e.g. "sel-751"
}

// Record is one audit record.
type Record struct {
	Contract         string  `json:"contract"`
	NodeID           string  `json:"node_id"`
	Seq              uint64  `json:"seq"`
	PrevHash         string  `json:"prev_hash"`
	Time             Time    `json:"time"`
	Actor            Actor   `json:"actor"`
	Action           Action  `json:"action"`
	Outcome          Outcome `json:"outcome"`
	ReasonCode       string  `json:"reason_code,omitempty"` // required for denied, failed and warning
	Target           *Target `json:"target,omitempty"`
	OperationID      string  `json:"operation_id,omitempty"`
	RegisterRevision uint64  `json:"register_revision,omitempty"`
	PolicyVersion    uint64  `json:"policy_version,omitempty"`
	ParamsDigest     string  `json:"params_digest,omitempty"`     // sha256 of the canonical parameters
	BytesSentDigest  string  `json:"bytes_sent_digest,omitempty"` // sha256 of the redacted bytes sent
	// TranscriptSHA256 is C2 Result.transcript.sha256: lowercase hex of the
	// SHA-256 of the session transcript exactly as stored, redactions
	// included. Required on device.session.close and on no other action
	// (A1 D1-25), so a stored transcript can be checked against the chain.
	// It is bare hex, unlike the "sha256:"-prefixed *_digest fields, so that
	// it compares byte for byte with the C2 field it copies; the algorithm
	// is in its name. An empty transcript still has a digest (e3b0c442...,
	// the SHA-256 of no bytes), so the field is never omitted on a close.
	TranscriptSHA256 string `json:"transcript_sha256,omitempty"`
	CorrelationID    string `json:"correlation_id,omitempty"` // C7 request ID, or the C2 invocation ID for invocationActions
	CollectorSeq     uint64 `json:"collector_seq,omitempty"`  // the collector's number for an event it reported (C7-A5-2)
	Detail           string `json:"detail,omitempty"`         // free text; never a secret or raw device output

	// PreviousHigh and FirstSeen are on collector.seq_reset only (0.2): the
	// highest collector_seq recorded before the reset (0 when none was),
	// and the number on the reply that showed it. FirstSeen is absent when
	// the node found the reset by the install key before sending anything.
	PreviousHigh *uint64 `json:"previous_high,omitempty"`
	FirstSeen    uint64  `json:"first_seen,omitempty"`
	// InstallKeyID is a collector install key ID, on collector.install_key,
	// collector.seq_reset and collector.seq_reset_ack only (0.2): the key the
	// node trusts, the new key a reset found, and the key an admin
	// acknowledged.
	InstallKeyID string `json:"install_key_id,omitempty"`
	// Suspension is on asset.suspend and asset.suspension_clear only (0.2).
	// The suspension's ref (the C2 invocation ID, or the operator principal
	// for reason operator) is correlation_id.
	Suspension *Suspension `json:"suspension,omitempty"`
	// Quarantine is on quarantine.exported and quarantine.cleared only
	// (0.3). The stream is quarantine/<target.asset_id>.
	Quarantine *Quarantine `json:"quarantine,omitempty"`

	// Claimed, Verified and RepeatOf (0.4) are on collector.request records
	// of an admin-signed request (C7 0.4 and later). Claimed is on the
	// node's info record, written before it sends: what the envelope and
	// payload say, which nothing has checked yet. Verified is on the
	// allowed record: CollectorReply.Admin, what the collector checked.
	// RepeatOf is on an allowed record whose reply was the repeat answer
	// (C7 0.5): the collector_seq of the first decision on the same signed
	// bytes, which ran nothing again.
	Claimed  *Admin `json:"claimed,omitempty"`
	Verified *Admin `json:"verified,omitempty"`
	RepeatOf uint64 `json:"repeat_of,omitempty"`
}

// Admin names one admin-signed request (C7 AdminAccepted): the signing
// key, the person it speaks for, the nonce and the SHA-256 of the signed
// payload bytes, lowercase hex. It never holds the payload or the
// signature.
type Admin struct {
	AdminKeyID    string `json:"admin_key_id"`
	Principal     string `json:"principal"` // a human principal ID
	Nonce         string `json:"nonce"`
	PayloadSHA256 string `json:"payload_sha256"`
}

func (a *Admin) validate() error {
	switch {
	case !adminKeyIDPattern.MatchString(a.AdminKeyID):
		return fmt.Errorf("admin_key_id %q", a.AdminKeyID)
	case !adminNoncePattern.MatchString(a.Nonce):
		return errors.New("nonce is not 22 base64url characters")
	case !hashPattern.MatchString(a.PayloadSHA256):
		return errors.New("payload_sha256 is not 64 lowercase hex digits")
	}
	return (authz.Principal{Type: authz.PrincipalHuman, ID: a.Principal}).Validate()
}

// adminSince is the minor that added Claimed, Verified and RepeatOf.
const adminSince = 4

// Quarantine names one verified export of an asset's quarantine stream
// (P3-A5): the manifest the node checked, and the range of the stream it
// lists. Every stored seq in first_seq..last_seq is listed, and only those
// (items of them), so the range names exactly the verified set; a clear
// removes only seqs in it.
type Quarantine struct {
	// ManifestSHA256 is the SHA-256 of the manifest's bytes as the node
	// read them, lowercase hex.
	ManifestSHA256 string `json:"manifest_sha256"`
	FirstSeq       uint64 `json:"first_seq"`
	LastSeq        uint64 `json:"last_seq"`
	// Items is how many seqs the manifest lists, at least one and at most
	// the range's length.
	Items uint64 `json:"items"`
	// ClearSHA256 is the SHA-256 of the clear-quarantine.json bytes the
	// node applied, lowercase hex. On quarantine.cleared only, required
	// there.
	ClearSHA256 string `json:"clear_sha256,omitempty"`
	// RequestedBy is the principal clear-quarantine.json names. On
	// quarantine.cleared only, required there. The file is not signed, so
	// this is what the file says, not who wrote it: the actor stays the
	// node, as on asset.suspension_clear, until a signed admin request
	// replaces the file.
	RequestedBy string `json:"requested_by,omitempty"`
}

// ReasonAlreadyCleared is quarantine.cleared's reason_code when the chain
// already holds a clear of the same manifest: the file changed nothing.
const ReasonAlreadyCleared = "already_cleared"

// Suspension names a C1 asset suspension on asset.suspend and
// asset.suspension_clear.
type Suspension struct {
	Reason asset.SuspensionReason `json:"reason"`
	// Code is the C2 outcome code that set it (Code.Suspends). Present on
	// asset.suspend except for reason operator; absent on a clear.
	Code string `json:"code,omitempty"`
}

func knownSuspension(r asset.SuspensionReason) bool {
	switch r {
	case asset.SuspendIdentityMismatch, asset.SuspendAuthFailed, asset.SuspendPasswordPromptAbsent,
		asset.SuspendLanguageNotEnglish, asset.SuspendFirmwareNotAllowed, asset.SuspendUnexpectedLevel, asset.SuspendOperator:
		return true
	}
	return false
}

// collectorActions are the actions only the collector performs. The node
// writes their records from what the collector reports.
var collectorActions = map[Action]bool{
	ActionDeviceSessionOpen: true, ActionDeviceSessionClose: true, ActionCredentialUse: true,
	ActionDeviceOp: true, ActionDeviceRefused: true, ActionDevicePostureWarning: true,
	ActionCredentialSuspend: true, ActionRegisterVerify: true, ActionRegisterActivate: true,
}

// CollectorReported reports whether a record states an event the collector
// reported, and so must carry its collector_seq (C7-A5-2): every action only
// the collector performs, the collector's decision on a request
// (collector.request allowed or denied), and the collector's result of a
// credential install, revocation or clearing. The node's own record that it
// sent a request (collector.request info) carries none.
func CollectorReported(r *Record) bool {
	switch r.Action {
	case ActionCollectorRequest:
		return r.Outcome == OutcomeAllowed || r.Outcome == OutcomeDenied
	case ActionCredentialInstall, ActionCredentialRevoke, ActionCredentialClearSusp:
		return r.Outcome != OutcomeInfo
	}
	return collectorActions[r.Action]
}

// GenesisPrevHash is prev_hash of a node's first record.
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// deviceActions need a target with an asset, and keep the plaintext label
// visible on every record.
var deviceActions = map[Action]bool{
	ActionDeviceSessionOpen: true, ActionDeviceSessionClose: true, ActionCredentialUse: true,
	ActionDeviceOp: true, ActionDeviceRefused: true, ActionDevicePostureWarning: true,
}

// invocationActions happen inside one C2 invocation. Their correlation_id is
// that invocation's ID, which C4 events carry as collection.invocation_id, so
// a reader can list the events a privileged read produced without matching
// time windows (C8-A4-4).
var invocationActions = map[Action]bool{
	ActionDeviceSessionOpen: true, ActionDeviceSessionClose: true, ActionCredentialUse: true,
	ActionDeviceOp: true, ActionDeviceRefused: true, ActionDevicePostureWarning: true,
}

// Validate checks one record on its own. Chain rules are in VerifyChain.
func (r *Record) Validate() error {
	reader, _ := version.Parse(ContractID)
	got, err := version.Parse(r.Contract)
	if err != nil || !reader.Accepts(got) {
		return fmt.Errorf("audit: contract %q", r.Contract)
	}
	if !nodeIDPattern.MatchString(r.NodeID) {
		return fmt.Errorf("audit: node id %q", r.NodeID)
	}
	if r.Seq == 0 {
		return errors.New("audit: seq starts at 1")
	}
	if !hashPattern.MatchString(r.PrevHash) {
		return errors.New("audit: prev_hash is not 64 lowercase hex digits")
	}
	if (r.Seq == 1) != (r.PrevHash == GenesisPrevHash) || (r.Seq == 1) != (r.Action == ActionAuditChainStart) {
		return errors.New("audit: seq 1, the genesis prev_hash and audit.chain.start go together")
	}
	if err := validateTime(r.Time); err != nil {
		return err
	}
	if err := (authz.Principal{Type: r.Actor.Type, ID: r.Actor.ID}).Validate(); err != nil {
		return fmt.Errorf("audit: actor: %w", err)
	}
	if r.Actor.SessionID != "" && !idPattern.MatchString(r.Actor.SessionID) {
		return errors.New("audit: actor session id")
	}
	if !actions[r.Action] {
		return fmt.Errorf("audit: unknown action %q", r.Action)
	}
	if since := actionSince[r.Action]; since > got.Minor {
		return fmt.Errorf("audit: %s is new in 0.%d, so a 0.%d record cannot carry it", r.Action, since, got.Minor)
	}
	if err := r.validateNodeState(); err != nil {
		return err
	}
	if err := r.validateAdmin(got.Minor); err != nil {
		return err
	}
	switch r.Outcome {
	case OutcomeAllowed, OutcomeSucceeded, OutcomeInfo:
		if r.ReasonCode != "" && !codePattern.MatchString(r.ReasonCode) {
			return fmt.Errorf("audit: reason code %q", r.ReasonCode)
		}
	case OutcomeDenied, OutcomeFailed, OutcomeWarning:
		if !codePattern.MatchString(r.ReasonCode) {
			return fmt.Errorf("audit: outcome %s needs a reason code", r.Outcome)
		}
	default:
		return fmt.Errorf("audit: unknown outcome %q", r.Outcome)
	}
	if r.Action == ActionCollectorRequest {
		switch r.Outcome {
		case OutcomeInfo: // written by the node before it sends the request (D1-11)
		case OutcomeAllowed:
		case OutcomeDenied:
			if authz.RefusalCode(r.ReasonCode).Normalize() == authz.RefuseUnknown && r.ReasonCode != string(authz.RefuseUnknown) {
				return fmt.Errorf("audit: %q is not a C7 refusal code", r.ReasonCode)
			}
		default:
			return errors.New("audit: collector.request is info (sent), allowed or denied")
		}
		if r.CorrelationID == "" {
			return errors.New("audit: collector.request needs the request ID as correlation_id")
		}
	}
	if invocationActions[r.Action] && r.CorrelationID == "" {
		return fmt.Errorf("audit: %s needs the C2 invocation ID as correlation_id", r.Action)
	}
	if need := CollectorReported(r); need != (r.CollectorSeq != 0) {
		if need {
			return fmt.Errorf("audit: %s %s is reported by the collector and needs collector_seq", r.Action, r.Outcome)
		}
		return fmt.Errorf("audit: %s %s is not a collector event and has no collector_seq", r.Action, r.Outcome)
	}
	if r.Action == ActionDevicePostureWarning && r.Outcome != OutcomeWarning {
		return errors.New("audit: device.posture_warning has outcome warning")
	}
	if r.Action == ActionDeviceRefused && r.Outcome != OutcomeDenied {
		return errors.New("audit: device.refused has outcome denied")
	}
	if deviceActions[r.Action] {
		if r.Target == nil || r.Target.AssetID == "" {
			return fmt.Errorf("audit: %s needs a target asset", r.Action)
		}
		if r.Target.Transport == "" || r.Target.DownstreamSecurity == "" {
			return fmt.Errorf("audit: %s must show transport and downstream security", r.Action)
		}
	}
	if r.Action == ActionCredentialUse && (r.Target == nil || r.Target.CredentialRef == "" || r.Target.CredentialVersion == 0) {
		return errors.New("audit: credential.use names the credential reference and version")
	}
	if t := r.Target; t != nil {
		if t.AssetID != "" && !asset.ValidAssetID(t.AssetID) {
			return fmt.Errorf("audit: asset id %q", t.AssetID)
		}
		if t.Transport != "" && t.Transport.Plaintext() && t.DownstreamSecurity != authz.DownstreamPlaintext {
			return fmt.Errorf("audit: transport %s must be labelled %s", t.Transport, authz.DownstreamPlaintext)
		}
	}
	if r.OperationID != "" && !operationIDPat.MatchString(r.OperationID) {
		return fmt.Errorf("audit: operation id %q", r.OperationID)
	}
	for _, d := range []string{r.ParamsDigest, r.BytesSentDigest} {
		if d != "" && !digestPattern.MatchString(d) {
			return fmt.Errorf("audit: digest %q is not sha256:<hex>", d)
		}
	}
	if r.CorrelationID != "" && !idPattern.MatchString(r.CorrelationID) && r.Suspension == nil {
		return errors.New("audit: correlation id")
	}
	// The digest is known only when the session ends; audit before act
	// covers its start with device.session.open (D1-25).
	switch {
	case r.Action == ActionDeviceSessionClose && !hashPattern.MatchString(r.TranscriptSHA256):
		return errors.New("audit: device.session.close needs transcript_sha256, 64 lowercase hex digits")
	case r.Action != ActionDeviceSessionClose && r.TranscriptSHA256 != "":
		return fmt.Errorf("audit: transcript_sha256 belongs on device.session.close, not %s", r.Action)
	}
	if len(r.Detail) > 512 {
		return errors.New("audit: detail over 512 bytes")
	}
	return nil
}

// validateNodeState checks the 0.2 node-state actions and their fields: each
// field only on its actions, and each action with exactly its fields.
func (r *Record) validateNodeState() error {
	reset := r.Action == ActionCollectorSeqReset
	ack := r.Action == ActionCollectorSeqResetAck || r.Action == ActionCollectorInstallKey
	susp := r.Action == ActionAssetSuspend || r.Action == ActionAssetSuspensionClear
	quar := r.Action == ActionQuarantineExported || r.Action == ActionQuarantineCleared
	if (r.PreviousHigh != nil || r.FirstSeen != 0) && !reset {
		return fmt.Errorf("audit: previous_high and first_seen belong on %s, not %s", ActionCollectorSeqReset, r.Action)
	}
	if r.InstallKeyID != "" && !reset && !ack {
		return fmt.Errorf("audit: install_key_id belongs on the collector key and reset actions, not %s", r.Action)
	}
	if r.Suspension != nil && !susp {
		return fmt.Errorf("audit: suspension belongs on %s and %s, not %s", ActionAssetSuspend, ActionAssetSuspensionClear, r.Action)
	}
	if r.Quarantine != nil && !quar {
		return fmt.Errorf("audit: quarantine belongs on %s and %s, not %s", ActionQuarantineExported, ActionQuarantineCleared, r.Action)
	}
	if quar {
		return r.validateQuarantine()
	}
	if !reset && !ack && !susp {
		return nil
	}
	if r.Outcome != OutcomeInfo || r.Actor.Type != authz.PrincipalNode {
		return fmt.Errorf("audit: %s is written by the node (actor type node) with outcome info", r.Action)
	}
	switch {
	case reset:
		if r.PreviousHigh == nil {
			return fmt.Errorf("audit: %s needs previous_high", r.Action)
		}
	case susp:
		if r.Target == nil || !asset.ValidAssetID(r.Target.AssetID) || r.Suspension == nil || !knownSuspension(r.Suspension.Reason) {
			return fmt.Errorf("audit: %s needs a target asset and a C1 suspension reason", r.Action)
		}
		// The ref is the C2 invocation ID, or an operator's C7 principal ID.
		if !asset.ValidPrincipalID(r.CorrelationID) {
			return fmt.Errorf("audit: %s needs the suspension's ref as correlation_id", r.Action)
		}
		code := r.Suspension.Code
		switch {
		case r.Action == ActionAssetSuspensionClear && code != "":
			return errors.New("audit: asset.suspension_clear names the suspension, not its C2 code")
		case r.Action == ActionAssetSuspend && r.Suspension.Reason == asset.SuspendOperator && code != "":
			return errors.New("audit: an operator suspension has no C2 code")
		case r.Action == ActionAssetSuspend && r.Suspension.Reason != asset.SuspendOperator && !c2CodePattern.MatchString(code):
			return fmt.Errorf("audit: asset.suspend needs the C2 code that set it, not %q", code)
		}
	}
	if (reset || ack) && !idPattern.MatchString(r.InstallKeyID) {
		return fmt.Errorf("audit: %s needs install_key_id", r.Action)
	}
	return nil
}

// validateAdmin checks the 0.4 admin fields: claimed only on a
// collector.request info record, verified and repeat_of only on an allowed
// one, with the verified person as its actor, repeat_of only with verified
// and below the record's own collector_seq (the repeat has its own number),
// and none on a record stamped 0.3 or earlier.
func (r *Record) validateAdmin(minor int) error {
	if r.Claimed == nil && r.Verified == nil && r.RepeatOf == 0 {
		return nil
	}
	if minor < adminSince {
		return fmt.Errorf("audit: claimed, verified and repeat_of are new in 0.%d, so a 0.%d record cannot carry them", adminSince, minor)
	}
	if r.Action != ActionCollectorRequest {
		return fmt.Errorf("audit: claimed, verified and repeat_of belong on %s, not %s", ActionCollectorRequest, r.Action)
	}
	if r.Claimed != nil {
		if r.Outcome != OutcomeInfo {
			return errors.New("audit: claimed is on the node's info record of the request it sent")
		}
		if err := r.Claimed.validate(); err != nil {
			return fmt.Errorf("audit: claimed: %w", err)
		}
	}
	if (r.Verified != nil || r.RepeatOf != 0) && r.Outcome != OutcomeAllowed {
		return errors.New("audit: verified and repeat_of are on the record of an accepted reply")
	}
	if r.Verified != nil {
		if err := r.Verified.validate(); err != nil {
			return fmt.Errorf("audit: verified: %w", err)
		}
		// A reader takes who authorised the action from verified, so the
		// record names one person: the actor is the verified person (A1 on
		// #187).
		if r.Actor.Type != authz.PrincipalHuman || r.Actor.ID != r.Verified.Principal {
			return errors.New("audit: the actor of a record with verified is the verified person")
		}
	}
	if r.RepeatOf != 0 && (r.Verified == nil || r.RepeatOf >= r.CollectorSeq) {
		return errors.New("audit: repeat_of needs verified and names a decision before the record's own collector_seq")
	}
	return nil
}

// validateQuarantine checks the 0.3 quarantine actions. Both are written by
// the node, about one asset, with the verified range. quarantine.exported
// is info. quarantine.cleared is succeeded when the clear passed every
// check and is recorded before anything is removed (audit before act; the
// removal is resumed from this record), or info with reason
// already_cleared when the chain already held a clear of the manifest and
// the file changed nothing.
func (r *Record) validateQuarantine() error {
	q := r.Quarantine
	if r.Actor.Type != authz.PrincipalNode {
		return fmt.Errorf("audit: %s is written by the node (actor type node)", r.Action)
	}
	if r.Target == nil || !asset.ValidAssetID(r.Target.AssetID) {
		return fmt.Errorf("audit: %s needs a target asset", r.Action)
	}
	if q == nil || !hashPattern.MatchString(q.ManifestSHA256) {
		return fmt.Errorf("audit: %s needs quarantine.manifest_sha256", r.Action)
	}
	if q.FirstSeq == 0 || q.LastSeq < q.FirstSeq || q.Items == 0 || q.Items > q.LastSeq-q.FirstSeq+1 {
		return fmt.Errorf("audit: %s range %d..%d with %d items", r.Action, q.FirstSeq, q.LastSeq, q.Items)
	}
	switch r.Action {
	case ActionQuarantineExported:
		if r.Outcome != OutcomeInfo {
			return errors.New("audit: quarantine.exported has outcome info")
		}
		if q.ClearSHA256 != "" || q.RequestedBy != "" {
			return errors.New("audit: clear_sha256 and requested_by belong on quarantine.cleared")
		}
	case ActionQuarantineCleared:
		switch {
		case r.Outcome == OutcomeSucceeded && r.ReasonCode == "":
		case r.Outcome == OutcomeInfo && r.ReasonCode == ReasonAlreadyCleared:
		default:
			return errors.New("audit: quarantine.cleared is succeeded, or info with reason already_cleared")
		}
		if !hashPattern.MatchString(q.ClearSHA256) {
			return errors.New("audit: quarantine.cleared needs quarantine.clear_sha256")
		}
		if err := (authz.Principal{Type: authz.PrincipalHuman, ID: q.RequestedBy}).Validate(); err != nil {
			return fmt.Errorf("audit: quarantine.cleared requested_by: %w", err)
		}
	}
	return nil
}

// forbiddenKeys may not appear as a field name anywhere in a record: names of
// secrets and raw device output, and any name that starts with "transcript",
// in any case. The one exception is transcript_sha256, spelled exactly so,
// which is a digest and not content (D1-25).
var forbiddenKeys = regexp.MustCompile(`(?i)^(secret|password|passwd|pwd|passphrase|credential_value|private_key|raw_output|transcript.*)$`)

// transcriptDigestKey is the one transcript-named field a record may carry.
const transcriptDigestKey = "transcript_sha256"

// ErrRecordRejected wraps every reason ParseRecord rejects a record.
var ErrRecordRejected = errors.New("audit: record rejected")

// ParseRecord parses and validates one stored record. A record stamped with
// this reader's minor or an earlier one is decoded strictly
// (strictjson.Decode), so it cannot carry a field this contract does not
// define (C8-A6-2). Stored records are evidence that a later minor may
// extend, so a record stamped with a later minor is decoded with
// strictjson.Forward (A1 D1-10), which rejects duplicate keys, a key that
// differs only in case from a field name, and trailing data, and ignores
// only unknown fields spelled unlike any field name. The chain covers those
// fields, so they cannot be altered unseen.
// Before decoding, it also rejects oversize records, invalid UTF-8, a raw CR,
// LF or NUL byte (Seal never writes one), and any field
// named like a secret or raw device output, at any depth. Writers go
// through Seal, which is fully strict (strictjson.Decode).
func ParseRecord(b []byte) (*Record, error) {
	if len(b) > MaxRecordBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrRecordRejected, len(b))
	}
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%w: not UTF-8", ErrRecordRejected)
	}
	if bytes.ContainsAny(b, "\r\n\x00") {
		return nil, fmt.Errorf("%w: raw CR, LF or NUL byte", ErrRecordRejected)
	}
	if err := walkKeys(b, func(k string) error {
		if k != transcriptDigestKey && forbiddenKeys.MatchString(k) {
			return fmt.Errorf("field %q may not appear in an audit record", k)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordRejected, err)
	}
	var r Record
	if err := strictjson.Forward(b, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordRejected, err)
	}
	reader, _ := version.Parse(ContractID)
	if got, err := version.Parse(r.Contract); err == nil && got.Major == reader.Major && got.Minor <= reader.Minor {
		r = Record{}
		if err := strictjson.Decode(b, &r); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRecordRejected, err)
		}
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordRejected, err)
	}
	return &r, nil
}

// walkKeys calls fn for every object key, rejects duplicate keys at any depth,
// and rejects anything after the first value.
func walkKeys(data []byte, fn func(string) error) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("nesting too deep")
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				k := kt.(string)
				if seen[strings.ToLower(k)] {
					return fmt.Errorf("duplicate key %q", k)
				}
				seen[strings.ToLower(k)] = true
				if err := fn(k); err != nil {
					return err
				}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case json.Delim('['):
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}
