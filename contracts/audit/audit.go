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

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/node"
	"otsec.local/otsec/contracts/version"
)

// ContractID is the identifier every audit record carries.
const ContractID = "otsec.audit/0.1"

// MaxRecordBytes bounds one stored record. It is stable for every 0.x minor:
// a forwarder sizes its targets by it (C8-A4-6), so a later minor may lower
// what writers produce but never raise this bound.
const MaxRecordBytes = 16 << 10

var (
	nodeIDPattern = regexp.MustCompile(node.IDPattern) // D1-1
	// TODO(C1): use asset.ValidAssetID once contracts/asset merges; this is
	// C1's rule, a lowercase UUID (C8-A4-2).
	assetIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hashPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	codePattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	clockWordRegexp = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)     // an open clock source word
	operationIDPat  = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_]+)+$`) // TODO(C3): exported pattern
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

// Action is the closed set of audited actions in 0.1. A reader that meets an
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
	ActionUnrecognized         Action = "unrecognized"                // reader fallback only; never written
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
	} {
		actions[a] = true
	}
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
	CorrelationID    string  `json:"correlation_id,omitempty"`    // C7 request ID, or the C2 invocation ID for invocationActions
	CollectorSeq     uint64  `json:"collector_seq,omitempty"`     // the collector's number for an event it reported (C7-A5-2)
	Detail           string  `json:"detail,omitempty"`            // free text; never a secret or raw device output
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
		if t.AssetID != "" && !assetIDPattern.MatchString(t.AssetID) {
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
	if r.CorrelationID != "" && !idPattern.MatchString(r.CorrelationID) {
		return errors.New("audit: correlation id")
	}
	if len(r.Detail) > 512 {
		return errors.New("audit: detail over 512 bytes")
	}
	return nil
}

// forbiddenKeys may not appear as a field name anywhere in a record.
var forbiddenKeys = regexp.MustCompile(`(?i)^(secret|password|passwd|pwd|passphrase|credential_value|private_key|raw_output|transcript)$`)

// ErrRecordRejected wraps every reason ParseRecord rejects a record.
var ErrRecordRejected = errors.New("audit: record rejected")

// ParseRecord parses and validates one stored record. Stored records are
// evidence that a later minor may extend, so C8 readers accept later minors:
// ParseRecord decodes with strictjson.Forward (A1 D1-10), which rejects
// duplicate keys, a key that differs only in case from a field name, and
// trailing data, and ignores only unknown fields spelled unlike any field
// name. The chain covers those fields, so they cannot be altered unseen.
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
		if forbiddenKeys.MatchString(k) {
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
