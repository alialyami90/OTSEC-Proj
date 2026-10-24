package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/register"
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
	maxParams                           = 8
	maxParamValueLen                    = 64
	requestIDPatternSrc                 = `^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`
	paramNamePatternSrc                 = `^[a-z][a-z0-9_]{0,31}$`
)

var (
	requestIDPattern = regexp.MustCompile(requestIDPatternSrc)
	paramNamePattern = regexp.MustCompile(paramNamePatternSrc)
)

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
}

// RunBody asks the collector to run one C3 operation on one enrolled asset.
// It carries no command line, no limits and no secret: the collector takes the
// exact line, its limits and the transport from the verified register and the
// asset's capability profile.
type RunBody struct {
	AssetID         string            `json:"asset_id"`
	OperationID     string            `json:"operation_id"`
	Params          map[string]string `json:"params"`
	CredentialRef   string            `json:"credential_ref"`
	RegisterVersion uint64            `json:"register_version"` // must equal the collector's active, verified package version
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
	RefuseCredentialMismatch RefusalCode = "credential_mismatch" // ref is for another asset, node or transport
	RefuseCredentialUnusable RefusalCode = "credential_unusable" // missing, suspended or revoked
	RefuseRegisterUnverified RefusalCode = "register_unverified" // no verified register package is active
	RefuseRegisterVersion    RefusalCode = "register_version"    // request names another register version
	RefusePolicyVersion      RefusalCode = "policy_version"      // request names another policy version
	RefuseBusy               RefusalCode = "busy"                // a session to this asset is already open (D9)
	RefuseRateLimited        RefusalCode = "rate_limited"        // minimum interval or failed-auth floor not elapsed
	RefuseSecretRejected     RefusalCode = "secret_rejected"     // write-time validation failed
	RefuseUnknown            RefusalCode = "refused_unknown"     // fallback for unknown codes
)

// RefusalCodes lists every refusal code.
var RefusalCodes = []RefusalCode{
	RefuseMalformed, RefuseOversize, RefuseUnknownField, RefuseContract, RefuseInvalid,
	RefusePrincipal, RefuseUnknownOperation, RefuseNotInvocable, RefuseBadParams,
	RefuseAssetNotEnrolled, RefuseCredentialMismatch, RefuseCredentialUnusable,
	RefuseRegisterUnverified, RefuseRegisterVersion, RefusePolicyVersion, RefuseBusy,
	RefuseRateLimited, RefuseSecretRejected, RefuseUnknown,
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
}

// Accepted reports whether the reply accepts the request. Anything malformed
// or unknown counts as not accepted.
func (r CollectorReply) Accepted() bool {
	return r.Contract == ContractID && r.Status == ReplyAccepted && r.Refusal == nil
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
	if r.Contract != ContractID {
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
	for _, present := range []bool{r.Run != nil, r.CredentialInstall != nil, r.CredentialRevoke != nil, r.CredentialClearSusp != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return refuse(RefuseInvalid, "exactly one body must be set, got %d", set)
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
		switch {
		case r.Kind == KindCredentialInstall && r.CredentialInstall != nil:
			if err := r.CredentialInstall.Ref.Validate(); err != nil {
				return refuse(RefuseInvalid, "%v", err)
			}
			if r.CredentialInstall.Ref.CreatedBy != r.OnBehalfOf {
				return refuse(RefuseInvalid, "ref.created_by must be the requesting admin")
			}
			if err := r.CredentialInstall.Sealed.Validate(); err != nil {
				return refuse(RefuseInvalid, "%v", err)
			}
		case r.Kind == KindCredentialRevoke && r.CredentialRevoke != nil:
			if !credentialRefIDPattern.MatchString(r.CredentialRevoke.RefID) {
				return refuse(RefuseInvalid, "ref_id")
			}
			switch r.CredentialRevoke.Reason {
			case RevokeRotated, RevokeCompromised, RevokeDecommissioned, RevokeOperator:
			default:
				return refuse(RefuseInvalid, "revoke reason %q", r.CredentialRevoke.Reason)
			}
		case r.Kind == KindCredentialClearSusp && r.CredentialClearSusp != nil:
			if !credentialRefIDPattern.MatchString(r.CredentialClearSusp.RefID) || r.CredentialClearSusp.Version == 0 {
				return refuse(RefuseInvalid, "ref_id or version")
			}
		default:
			return refuse(RefuseInvalid, "body does not match kind %q", r.Kind)
		}
		return nil
	default:
		return refuse(RefuseInvalid, "unknown kind %q", r.Kind)
	}
}

func (b *RunBody) validate() error {
	if !assetIDPattern.MatchString(b.AssetID) {
		return refuse(RefuseInvalid, "asset_id")
	}
	if !operationIDPattern.MatchString(b.OperationID) {
		return refuse(RefuseInvalid, "operation_id")
	}
	if !credentialRefIDPattern.MatchString(b.CredentialRef) {
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
// the transport, before authentication, and a schedule cannot ask for it), and
// the parameters render through Matcher.Render, which also applies the deny
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
