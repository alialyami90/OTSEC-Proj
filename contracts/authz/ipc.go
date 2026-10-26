package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/contracts/version"
)

// MaxRequestBytes bounds one collector request on the wire.
const MaxRequestBytes = 8 << 10

// RequestKind is the closed set of things the main process may ask the
// collector. Only KindRun can lead to device I/O.
type RequestKind string

const (
	KindRun                 RequestKind = "run"
	KindCredentialInstall   RequestKind = "credential.install"
	KindCredentialRevoke    RequestKind = "credential.revoke"
	KindCredentialClearSusp RequestKind = "credential.clear_suspension"
	KindAssetClearSusp      RequestKind = "asset.clear_suspension" // since 0.2
	// The node kinds (since 0.5) are admin-signed only. The collector
	// verifies, spends the nonce and numbers the decision, and changes
	// nothing of its own; the node acts on its own part only once the
	// collector has accepted (CollectorReply.AdminAcceptance).
	KindNodeQuarantineClear RequestKind = "node.quarantine_clear"
	KindNodeSeqResetAck     RequestKind = "node.seq_reset_ack"
	maxParams                           = 8
	maxParamValueLen                    = 64
	requestIDPatternSrc                 = `^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`
	paramNamePatternSrc                 = `^[a-z][a-z0-9_]{0,31}$`
)

var (
	requestIDPattern = regexp.MustCompile(requestIDPatternSrc)
	paramNamePattern = regexp.MustCompile(paramNamePatternSrc)
	// invocationRefPattern is a C2 invocation ID, a lowercase UUID.
	// TODO(C2): C2 imports this package, so the pattern is a copy.
	invocationRefPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// kindSince is the minor that added a request kind; absent means 0.1. A
// request stamped with an earlier minor cannot ask for it.
var kindSince = map[RequestKind]int{KindAssetClearSusp: 2, KindNodeQuarantineClear: nodeKindsSince, KindNodeSeqResetAck: nodeKindsSince}

// nodeKindsSince is the minor that added the node kinds, the repeat answer
// and CollectorReply.Admin.
const nodeKindsSince = 5

// CollectorRequest is the only message the main process sends to the
// collector. It is strict: decode it with DecodeRequest, never with a lenient
// decoder. Exactly one body field is set, the one that matches Kind.
type CollectorRequest struct {
	Contract      string      `json:"contract"`
	Kind          RequestKind `json:"kind"`
	RequestID     string      `json:"request_id"`
	OnBehalfOf    Principal   `json:"on_behalf_of"`
	PolicyVersion uint64      `json:"policy_version"`

	Run                 *RunBody                 `json:"run,omitempty"`
	CredentialInstall   *CredentialInstallBody   `json:"credential_install,omitempty"`
	CredentialRevoke    *CredentialRevokeBody    `json:"credential_revoke,omitempty"`
	CredentialClearSusp *CredentialClearSuspBody `json:"credential_clear_suspension,omitempty"`
	AssetClearSusp      *AssetClearSuspBody      `json:"asset_clear_suspension,omitempty"`
	// AdminSigned (since 0.4) carries a request an administrator signed,
	// in place of its body, which exists only inside the signed payload.
	// The collector checks it with VerifyAdminRequest.
	AdminSigned *AdminSigned `json:"admin_signed,omitempty"`
}

// RunBody asks the collector to run one C3 operation on one enrolled asset.
// It carries no command line, no limits and no secret: the collector takes the
// exact line, its limits and the transport from the verified register and the
// asset's capability profile.
type RunBody struct {
	AssetID         string            `json:"asset_id"`
	OperationID     string            `json:"operation_id"`
	Params          map[string]string `json:"params"`
	CredentialRef   string            `json:"credential_ref,omitempty"` // absent for a level 0 operation, required otherwise (C7-A2-5)
	RegisterVersion uint64            `json:"register_version"`         // must equal the collector's active, verified package version
}

// CredentialInstallBody installs or replaces one credential version.
type CredentialInstallBody struct {
	Ref    CredentialRef `json:"ref"`
	Sealed SealedSecret  `json:"sealed"`
}

// CredentialRevokeBody revokes every version of one credential reference.
type CredentialRevokeBody struct {
	RefID  string       `json:"ref_id"`
	Reason RevokeReason `json:"reason"`
}

// CredentialClearSuspBody clears a suspension on the exact version the admin
// reviewed.
type CredentialClearSuspBody struct {
	RefID   string `json:"ref_id"`
	Version uint32 `json:"version"`
}

// AssetClearSuspBody asks the collector to clear its own suspension of one
// asset (0.2, D2-15). The node sends it on its own behalf, after it has
// recorded its own asset.suspension_clear from the administrator's
// clear-suspension.json. The collector does not take the request's word
// for it: it reads the same administrator file itself and clears only when
// the body, the file and the invocation that suspended the asset all name
// the same asset and ref. Anything else is refused with
// suspension_mismatch and changes nothing. A clear of an asset the
// collector does not hold suspended, with a matching file, is accepted and
// changes nothing, so a retry after a lost reply settles. It never touches a credential's
// suspension, and credential.clear_suspension never touches an asset's.
type AssetClearSuspBody struct {
	AssetID string `json:"asset_id"`
	// Ref is the C2 invocation ID whose outcome suspended the asset.
	Ref string `json:"ref"`
}

// NodeQuarantineClearBody (since 0.5) is an administrator's clear of one
// quarantine the node holds (D3-1): the asset, a C1 asset ID, and the
// SHA-256 of the quarantine manifest the administrator reviewed. The
// collector checks its syntax only; the node checks it against its own
// quarantine before it clears.
type NodeQuarantineClearBody struct {
	AssetID        string `json:"asset_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// NodeSeqResetAckBody (since 0.5) acknowledges a collector_seq reset. It
// is empty: the install key it acknowledges is the payload's
// install_key_id, which the collector refuses unless it is its current
// key, so a second copy here could only disagree.
type NodeSeqResetAckBody struct{}

// RefusalCode is the closed set of reasons the collector refuses a request.
// A reader that meets a code it does not know treats it as RefuseUnknown.
type RefusalCode string

const (
	RefuseMalformed          RefusalCode = "malformed"         // not strict JSON, duplicate key, trailing data, bad UTF-8
	RefuseOversize           RefusalCode = "oversize"          // over MaxRequestBytes
	RefuseUnknownField       RefusalCode = "unknown_field"     // any field this contract does not define
	RefuseContract           RefusalCode = "contract_mismatch" // contract identifier missing or another major
	RefuseInvalid            RefusalCode = "invalid"           // a field fails its syntax or the body does not match kind
	RefusePrincipal          RefusalCode = "principal_not_permitted"
	RefuseUnknownOperation   RefusalCode = "unknown_operation" // not in the active register
	RefuseNotInvocable       RefusalCode = "not_invocable"     // session-control or state-changing
	RefuseBadParams          RefusalCode = "bad_params"        // parameter missing, extra, or failing its register pattern
	RefuseAssetNotEnrolled   RefusalCode = "asset_not_enrolled"
	RefuseCredentialMismatch RefusalCode = "credential_mismatch"         // ref is for another asset, node or transport
	RefuseCredentialUnusable RefusalCode = "credential_unusable"         // missing, suspended or revoked
	RefuseRegisterUnverified RefusalCode = "register_unverified"         // no verified register package is active
	RefuseRegisterVersion    RefusalCode = "register_version"            // request names another register version
	RefusePolicyVersion      RefusalCode = "policy_version"              // request names another policy version
	RefuseBusy               RefusalCode = "busy"                        // a session to this asset is already open (D9)
	RefuseRateLimited        RefusalCode = "rate_limited"                // minimum interval or failed-auth floor not elapsed
	RefuseSecretRejected     RefusalCode = "secret_rejected"             // write-time validation failed
	RefuseStateUnavailable   RefusalCode = "collector_state_unavailable" // collector state could not be read or flushed durably (C7-A5-3)
	RefuseSuspensionMismatch RefusalCode = "suspension_mismatch"         // since 0.2: the asset is not suspended by ref, or the administrator's file is absent, refused or names another
	RefuseAssetSuspended     RefusalCode = "asset_suspended"             // since 0.3: the collector holds the asset suspended; Refusal.Suspension names it
	RefuseAdminUnverified    RefusalCode = "admin_unverified"            // since 0.4: an admin request is unsigned, or its signature, binding, window or nonce fails (VerifyAdminRequest)
	RefuseUnknown            RefusalCode = "refused_unknown"             // fallback for unknown codes
)

// RefusalCodes lists every refusal code.
var RefusalCodes = []RefusalCode{
	RefuseMalformed, RefuseOversize, RefuseUnknownField, RefuseContract, RefuseInvalid,
	RefusePrincipal, RefuseUnknownOperation, RefuseNotInvocable, RefuseBadParams,
	RefuseAssetNotEnrolled, RefuseCredentialMismatch, RefuseCredentialUnusable,
	RefuseRegisterUnverified, RefuseRegisterVersion, RefusePolicyVersion, RefuseBusy,
	RefuseRateLimited, RefuseSecretRejected, RefuseStateUnavailable, RefuseSuspensionMismatch, RefuseAssetSuspended, RefuseAdminUnverified, RefuseUnknown,
}

// Normalize maps an unknown code to RefuseUnknown.
func (c RefusalCode) Normalize() RefusalCode {
	for _, k := range RefusalCodes {
		if c == k {
			return c
		}
	}
	return RefuseUnknown
}

// Refusal is a refused request's reason.
type Refusal struct {
	Code   RefusalCode `json:"code"`
	Detail string      `json:"detail,omitempty"` // never contains a secret or a raw line
	// Suspension (since 0.3) is the asset suspension the collector holds:
	// always set with asset_suspended, and set with suspension_mismatch
	// when the collector holds a suspension other than the one the clear
	// named. The node adopts it (see the package documentation, "Asset
	// suspensions").
	Suspension *HeldSuspension `json:"suspension,omitempty"`
	// Check (since 0.4) is set with admin_unverified only: the check the
	// admin-signed request failed. The node's C8 collector.request record
	// carries it, so an operator can tell a replay from a bad signature
	// afterwards (A1); it is the same for a wrong guess and a right one.
	Check AdminCheck `json:"check,omitempty"`
}

// HeldSuspension is an asset suspension the collector holds (since 0.3):
// its C1 reason, the invocation that set it, a lowercase UUID, and the C2
// outcome code that set it, which the node's C8 asset.suspend record needs
// (A5 on #125). Code is empty for a suspension recorded before the
// collector kept codes; the node does not adopt one without a code.
type HeldSuspension struct {
	Reason asset.SuspensionReason `json:"reason"`
	Ref    string                 `json:"ref"`
	Code   string                 `json:"code,omitempty"`
}

// heldCodePattern is the shape of a C2 code that suspends: a refusal or a
// failure. TODO(C2): C2 imports this package, so whether the code is known
// and suspends with Reason (adapter.Code.Suspends) is the reader's check.
var heldCodePattern = regexp.MustCompile(`^(refused|failed)\.[a-z][a-z0-9_]{0,63}$`)

// Validate checks the reason is a C1 reason an outcome code sets (operator
// suspensions are the node's, and the collector never holds one), the ref
// an invocation ID, and the code, when present, shaped as a C2 refusal or
// failure. The node must also check that the code is a known C2 code whose
// Suspends is Reason before it adopts the suspension.
func (h HeldSuspension) Validate() error {
	switch h.Reason {
	case asset.SuspendIdentityMismatch, asset.SuspendAuthFailed, asset.SuspendPasswordPromptAbsent,
		asset.SuspendLanguageNotEnglish, asset.SuspendFirmwareNotAllowed, asset.SuspendUnexpectedLevel:
	default:
		return fmt.Errorf("authz: held suspension: %q is not a reason an outcome code sets", h.Reason)
	}
	if !invocationRefPattern.MatchString(h.Ref) {
		return errors.New("authz: held suspension: ref is not an invocation ID (lowercase UUID)")
	}
	if h.Code != "" && !heldCodePattern.MatchString(h.Code) {
		return fmt.Errorf("authz: held suspension: %q is not a C2 refusal or failure code", h.Code)
	}
	return nil
}

// assetSuspendedSince is the minor that added asset_suspended and
// Refusal.Suspension.
const assetSuspendedSince = 3

// ForRequest is the refusal as the reply to a request stamped contract,
// in codes and fields that request's reader knows:
//   - before 0.3, a reader knows neither asset_suspended nor the
//     suspension field, and decodes replies strictly, so it gets what 0.2
//     collectors replied: asset_not_enrolled, the same detail, and no
//     suspension;
//   - before 0.4, a reader does not know admin_unverified, so an unsigned
//     admin request gets principal_not_permitted: its sender may not ask
//     for it without an administrator's signature.
func (r *Refusal) ForRequest(contract string) *Refusal {
	if r == nil || (r.Code != RefuseAssetSuspended && r.Code != RefuseAdminUnverified && r.Suspension == nil) {
		return r
	}
	got, err := version.Parse(contract)
	minor := 0
	if err == nil {
		minor = got.Minor
	}
	out := &Refusal{Code: r.Code, Detail: r.Detail, Suspension: r.Suspension, Check: r.Check}
	if minor < assetSuspendedSince {
		out.Suspension = nil
		if out.Code == RefuseAssetSuspended {
			out.Code = RefuseAssetNotEnrolled
		}
	}
	if minor < adminSignedSince {
		out.Check = ""
		if out.Code == RefuseAdminUnverified {
			out.Code = RefusePrincipal
		}
	}
	return out
}

func (r *Refusal) Error() string {
	if r.Detail == "" {
		return "authz: refused: " + string(r.Code)
	}
	return "authz: refused: " + string(r.Code) + ": " + r.Detail
}

func refuse(code RefusalCode, format string, a ...any) *Refusal {
	return &Refusal{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// ReplyStatus is the collector's answer. A reader treats anything other than
// "accepted" as a refusal.
type ReplyStatus string

const (
	ReplyAccepted ReplyStatus = "accepted"
	ReplyRefused  ReplyStatus = "refused"
)

// CollectorReply answers one request. Accepted means the collector took the
// request on; the device outcome arrives as a C2 result and C8 audit records,
// correlated by InvocationID.
type CollectorReply struct {
	Contract     string      `json:"contract"`
	RequestID    string      `json:"request_id"`
	Status       ReplyStatus `json:"status"`
	InvocationID string      `json:"invocation_id,omitempty"` // set for an accepted run
	Refusal      *Refusal    `json:"refusal,omitempty"`       // set when refused
	// CollectorSeq numbers this decision among every event the collector
	// reports (C7-A5-2). See the package documentation, "Collector sequence".
	CollectorSeq uint64 `json:"collector_seq"`
	// RepeatOf (since 0.5) is set on an accepted reply to admin-signed
	// bytes the collector had already accepted: the collector_seq of that
	// first decision. The collector did nothing again; this reply has its
	// own collector_seq like any other. See the package documentation,
	// "The node kinds and the repeat answer".
	RepeatOf uint64 `json:"repeat_of,omitempty"`
	// Admin (since 0.5) is set on every accepted reply to an admin-signed
	// request stamped 0.5 or later, and on no other reply: what the
	// collector verified.
	Admin *AdminAccepted `json:"admin,omitempty"`
}

// AdminAccepted is what the collector verified of an admin-signed request
// it accepted (since 0.5). The node's C8 record of the reply carries it,
// so the record of the request holds what the payload claimed and the
// record of the reply what was verified. PayloadSHA256 binds the
// acceptance to the exact signed bytes sent (AdminPayloadSHA256).
type AdminAccepted struct {
	AdminKeyID    string    `json:"admin_key_id"`
	Principal     Principal `json:"principal"`
	Nonce         string    `json:"nonce"`
	PayloadSHA256 string    `json:"payload_sha256"`
}

// AdminPayloadSHA256 is the lowercase hex SHA-256 of a signed request's
// payload bytes: the bytes the signature covers, as sent.
func AdminPayloadSHA256(env *AdminSigned) string {
	sum := sha256.Sum256(env.Payload)
	return hex.EncodeToString(sum[:])
}

// AnswersRepeat reports whether a request stamped contract may get the
// repeat answer and CollectorReply.Admin: from 0.5. An older reader decodes
// replies strictly and knows neither field, so it gets what a 0.4
// collector replied: a resent request is refused as a replay.
func AnswersRepeat(contract string) bool {
	got, err := version.Parse(contract)
	return err == nil && got.Minor >= nodeKindsSince
}

// AdminAcceptance checks that r accepts exactly the admin-signed request
// sent, and returns what the collector verified. The node acts on its own
// part of an admin request (a node kind, or its side of an asset clear)
// only when this returns no error: the reply answers this request ID, is
// accepted and numbered, names the payload's hash, the envelope's key and
// the request's person, and a repeat names an earlier decision.
func (r CollectorReply) AdminAcceptance(sent *CollectorRequest) (*AdminAccepted, error) {
	switch {
	case sent == nil || sent.AdminSigned == nil:
		return nil, errors.New("authz: the request sent is not admin-signed")
	case !r.Accepted():
		return nil, errors.New("authz: the reply does not accept the request")
	case r.RequestID != sent.RequestID:
		return nil, errors.New("authz: the reply answers another request")
	case r.Admin == nil:
		return nil, errors.New("authz: the acceptance names nothing the collector verified")
	case r.RepeatOf >= r.CollectorSeq:
		return nil, fmt.Errorf("authz: repeat_of %d is not an earlier decision than %d", r.RepeatOf, r.CollectorSeq)
	}
	a := r.Admin
	switch {
	case a.PayloadSHA256 != AdminPayloadSHA256(sent.AdminSigned):
		return nil, errors.New("authz: the acceptance is for other signed bytes")
	case a.AdminKeyID != sent.AdminSigned.KeyID:
		return nil, errors.New("authz: the acceptance names another admin key")
	case a.Principal != sent.OnBehalfOf:
		return nil, errors.New("authz: the acceptance names another person")
	case !adminNoncePattern.MatchString(a.Nonce):
		return nil, errors.New("authz: the acceptance's nonce is malformed")
	}
	return a, nil
}

// Accepted reports whether the reply accepts the request. Anything malformed
// or unknown counts as not accepted, and so does a reply with no collector
// sequence number, because its decision could not be accounted for in audit.
func (r CollectorReply) Accepted() bool {
	return AcceptsContract(r.Contract) && r.Status == ReplyAccepted && r.Refusal == nil && r.CollectorSeq != 0
}

// HeldSuspension is the asset suspension a refused reply says the
// collector holds, checked, or nil when it names none. A reply whose
// suspension is malformed, sits on another code, or is missing from
// asset_suspended is an error: the node then cannot adopt it, and alarms.
func (r CollectorReply) HeldSuspension() (*HeldSuspension, error) {
	if r.Refusal == nil {
		return nil, nil
	}
	h := r.Refusal.Suspension
	switch {
	case r.Refusal.Code == RefuseAssetSuspended && h == nil:
		return nil, errors.New("authz: asset_suspended names no suspension")
	case h == nil:
		return nil, nil
	case r.Refusal.Code != RefuseAssetSuspended && r.Refusal.Code != RefuseSuspensionMismatch:
		return nil, fmt.Errorf("authz: a suspension on refusal %s", r.Refusal.Code)
	}
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return h, nil
}

// DecodeRequest decodes and validates one request strictly. Every error is a
// *Refusal with a code from RefusalCodes.
func DecodeRequest(data []byte) (*CollectorRequest, error) {
	if len(data) > MaxRequestBytes {
		return nil, refuse(RefuseOversize, "%d bytes", len(data))
	}
	if !utf8.Valid(data) {
		return nil, refuse(RefuseMalformed, "not UTF-8")
	}
	var req CollectorRequest
	if err := strictjson.Decode(data, &req); err != nil {
		return nil, decodeRefusal(err)
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return &req, nil
}

// Validate checks a request's syntax and principal rules. It does not consult
// the register; ValidateAgainst does that.
func (r *CollectorRequest) Validate() error {
	if !AcceptsContract(r.Contract) {
		return refuse(RefuseContract, "contract %q", r.Contract)
	}
	if !requestIDPattern.MatchString(r.RequestID) {
		return refuse(RefuseInvalid, "request_id")
	}
	if err := r.OnBehalfOf.Validate(); err != nil {
		return refuse(RefuseInvalid, "%v", err)
	}
	if r.PolicyVersion == 0 {
		return refuse(RefuseInvalid, "policy_version must be at least 1")
	}
	set := 0
	for _, present := range []bool{r.Run != nil, r.CredentialInstall != nil, r.CredentialRevoke != nil, r.CredentialClearSusp != nil, r.AssetClearSusp != nil, r.AdminSigned != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return refuse(RefuseInvalid, "exactly one body must be set, got %d", set)
	}
	got, _ := version.Parse(r.Contract)
	if since, ok := kindSince[r.Kind]; ok && got.Minor < since {
		return refuse(RefuseInvalid, "kind %q needs otsec.authz/0.%d or later", r.Kind, since)
	}
	if r.AdminSigned != nil {
		// The envelope's contents are VerifyAdminRequest's to check, so
		// that every way it can fail is one refusal (admin_unverified).
		switch {
		case got.Minor < adminSignedSince:
			return refuse(RefuseInvalid, "admin_signed needs otsec.authz/0.%d or later", adminSignedSince)
		case !adminKinds[r.Kind]:
			return refuse(RefuseInvalid, "kind %q is not signed by an administrator", r.Kind)
		case r.OnBehalfOf.Type != PrincipalHuman:
			return refuse(RefusePrincipal, "an admin-signed request is on behalf of a person, not %s", r.OnBehalfOf.Type)
		}
		return nil
	}
	switch r.Kind {
	case KindRun:
		if r.Run == nil {
			return refuse(RefuseInvalid, "kind run needs a run body")
		}
		// L1 and AP-15: device I/O is asked for only by a site-local schedule
		// acting with the collector role, never directly by a person.
		if r.OnBehalfOf.Type != PrincipalSchedule {
			return refuse(RefusePrincipal, "run requests come from a schedule, not %s", r.OnBehalfOf.Type)
		}
		return r.Run.validate()
	case KindCredentialInstall, KindCredentialRevoke, KindCredentialClearSusp:
		if r.OnBehalfOf.Type != PrincipalHuman {
			return refuse(RefusePrincipal, "credential requests come from a person with the admin role")
		}
	case KindAssetClearSusp:
		// The node relays the administrator's file (D2-15); a person or a
		// schedule never asks the collector for it directly, except as an
		// admin-signed request (0.4), checked above.
		if r.OnBehalfOf.Type != PrincipalNode {
			return refuse(RefusePrincipal, "asset clear requests come from the node, not %s", r.OnBehalfOf.Type)
		}
	default:
		return refuse(RefuseInvalid, "unknown kind %q", r.Kind)
	}
	return validateBody(r.Kind, r.OnBehalfOf, requestBodies{CredentialInstall: r.CredentialInstall,
		CredentialRevoke: r.CredentialRevoke, CredentialClearSusp: r.CredentialClearSusp, AssetClearSusp: r.AssetClearSusp})
}

// requestBodies are the bodies of the kinds other than run, in the clear
// (up to 0.3) or inside an admin-signed payload (0.4).
type requestBodies struct {
	CredentialInstall   *CredentialInstallBody
	CredentialRevoke    *CredentialRevokeBody
	CredentialClearSusp *CredentialClearSuspBody
	AssetClearSusp      *AssetClearSuspBody
	NodeQuarantineClear *NodeQuarantineClearBody // admin-signed only
	NodeSeqResetAck     *NodeSeqResetAckBody     // admin-signed only
}

// validateBody checks that the one body set matches kind and passes its
// rules. The caller has checked that exactly one is set.
func validateBody(kind RequestKind, by Principal, b requestBodies) error {
	switch {
	case kind == KindCredentialInstall && b.CredentialInstall != nil:
		if err := b.CredentialInstall.Ref.Validate(); err != nil {
			return refuse(RefuseInvalid, "%v", err)
		}
		if b.CredentialInstall.Ref.CreatedBy != by {
			return refuse(RefuseInvalid, "ref.created_by must be the requesting admin")
		}
		if err := b.CredentialInstall.Sealed.Validate(); err != nil {
			return refuse(RefuseInvalid, "%v", err)
		}
	case kind == KindCredentialRevoke && b.CredentialRevoke != nil:
		if !credentialRefIDPattern.MatchString(b.CredentialRevoke.RefID) {
			return refuse(RefuseInvalid, "ref_id")
		}
		switch b.CredentialRevoke.Reason {
		case RevokeRotated, RevokeCompromised, RevokeDecommissioned, RevokeOperator:
		default:
			return refuse(RefuseInvalid, "revoke reason %q", b.CredentialRevoke.Reason)
		}
	case kind == KindCredentialClearSusp && b.CredentialClearSusp != nil:
		if !credentialRefIDPattern.MatchString(b.CredentialClearSusp.RefID) || b.CredentialClearSusp.Version == 0 {
			return refuse(RefuseInvalid, "ref_id or version")
		}
	case kind == KindAssetClearSusp && b.AssetClearSusp != nil:
		if !assetIDPattern.MatchString(b.AssetClearSusp.AssetID) {
			return refuse(RefuseInvalid, "asset_id")
		}
		if !invocationRefPattern.MatchString(b.AssetClearSusp.Ref) {
			return refuse(RefuseInvalid, "ref")
		}
	case kind == KindNodeQuarantineClear && b.NodeQuarantineClear != nil:
		if !assetIDPattern.MatchString(b.NodeQuarantineClear.AssetID) {
			return refuse(RefuseInvalid, "asset_id")
		}
		if !sha256HexPattern.MatchString(b.NodeQuarantineClear.ManifestSHA256) {
			return refuse(RefuseInvalid, "manifest_sha256")
		}
	case kind == KindNodeSeqResetAck && b.NodeSeqResetAck != nil:
	default:
		return refuse(RefuseInvalid, "body does not match kind %q", kind)
	}
	return nil
}

// sha256HexPattern is a SHA-256 digest in lowercase hex.
var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (b *RunBody) validate() error {
	if !assetIDPattern.MatchString(b.AssetID) {
		return refuse(RefuseInvalid, "asset_id")
	}
	if !operationIDPattern.MatchString(b.OperationID) {
		return refuse(RefuseInvalid, "operation_id")
	}
	if b.CredentialRef != "" && !credentialRefIDPattern.MatchString(b.CredentialRef) {
		return refuse(RefuseInvalid, "credential_ref")
	}
	if b.RegisterVersion == 0 {
		return refuse(RefuseInvalid, "register_version must be at least 1")
	}
	if b.Params == nil {
		return refuse(RefuseInvalid, "params must be present, even if empty")
	}
	if len(b.Params) > maxParams {
		return refuse(RefuseBadParams, "more than %d params", maxParams)
	}
	for k, v := range b.Params {
		if !paramNamePattern.MatchString(k) {
			return refuse(RefuseBadParams, "param name %q", k)
		}
		// A parameter is a typed value, never a line: printable ASCII with no
		// CR, LF or other control byte, and bounded length. The register's
		// own pattern for the parameter is applied in ValidateAgainst.
		if len(v) == 0 || len(v) > maxParamValueLen {
			return refuse(RefuseBadParams, "param %q length", k)
		}
		for i := 0; i < len(v); i++ {
			if v[i] < 0x20 || v[i] > 0x7e {
				return refuse(RefuseBadParams, "param %q has a byte outside printable ASCII", k)
			}
		}
	}
	return nil
}

// ValidateAgainst checks a run request against the collector's active,
// verified register (C3): the operation exists among the invocable
// operations (session-control lines and deny rules are never returned, C-A2-1),
// is read-only, runs in the operate phase (a probe-only operation belongs to
// the transport, before authentication, and a schedule cannot ask for it),
// carries a credential_ref exactly when its access level is above 0 (C7-A2-5),
// and the parameters render through Matcher.Render, which also applies the deny
// rules. The transport still checks every line with Matcher.Permit at egress.
// A nil matcher means no verified register package is active for the family.
func (b *RunBody) ValidateAgainst(m *register.Matcher) error {
	if m == nil {
		return refuse(RefuseRegisterUnverified, "no verified register package")
	}
	op, ok := m.Operation(b.OperationID)
	if !ok || op == nil {
		return refuse(RefuseUnknownOperation, "%s", b.OperationID)
	}
	if op.Classification != register.ReadOnly {
		return refuse(RefuseNotInvocable, "%s is %s", b.OperationID, op.Classification)
	}
	if !op.InPhase(register.PhaseOperate) {
		return refuse(RefuseNotInvocable, "%s does not run in the operate phase", b.OperationID)
	}
	// A level 0 operation (sel.id) is sent before ACC, so no password is
	// needed and none may be resolved; any other operation needs one.
	if (op.AccessLevel == register.ProbeAccessLevel) != (b.CredentialRef == "") {
		return refuse(RefuseCredentialMismatch, "%s at level %q: credential_ref must be present exactly when the level is above 0", b.OperationID, op.AccessLevel)
	}
	if _, err := m.Render(b.OperationID, b.Params); err != nil {
		return refuse(RefuseBadParams, "%s", b.OperationID)
	}
	return nil
}

// decodeRefusal maps a strictjson error to a refusal code: a key that is not
// a field of the request is unknown_field, a value of the wrong type is
// invalid, and anything else (bad syntax, a duplicate or case-folded key,
// trailing data) is malformed.
func decodeRefusal(err error) *Refusal {
	var typ *json.UnmarshalTypeError
	switch msg := err.Error(); {
	case strings.Contains(msg, "is not a field name"), strings.Contains(msg, "unknown field"):
		return refuse(RefuseUnknownField, "%v", err)
	case errors.As(err, &typ):
		return refuse(RefuseInvalid, "%v", err)
	default:
		return refuse(RefuseMalformed, "%v", err)
	}
}
