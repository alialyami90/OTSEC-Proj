package adapter

import (
	"errors"
	"fmt"
	"regexp"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/contracts/version"
)

// Contract is this package's identifier. Invocations are strict (unknown
// fields rejected); results are not.
const Contract = "otsec.adapter/0.1"

var self = version.ID{Name: "adapter", Major: 0, Minor: 1}

// Invocation asks the collector to run one register operation against one
// endpoint of one asset.
type Invocation struct {
	Schema       string `json:"schema"`
	InvocationID string `json:"invocation_id"` // lowercase UUID, unique per invocation
	RequestedAt  string `json:"requested_at"`  // RFC 3339 UTC with Z, as C1, C4 and C7
	PrincipalRef string `json:"principal_ref"` // who scheduled it: a C7 schedule principal ID
	AssetID      string `json:"asset_id"`      // C1
	EndpointID   string `json:"endpoint_id"`   // an endpoint of that asset (C1)
	ProfileID    string `json:"profile_id"`    // C1 capability profile
	OperationID  string `json:"operation_id"`  // a C3 register operation ID
	// Params are checked against the operation's parameter grammar before
	// connecting (C3). Absent for operations without parameters.
	Params map[string]string `json:"params,omitempty"`
	// CredentialRef is the ID of a C7 CredentialRef (cred_...). Required for
	// any operation above access level 0; the secret never appears here. The
	// collector resolves it and checks its binding (authz CredentialRef.Binds);
	// C2 checks only its syntax.
	CredentialRef string `json:"credential_ref,omitempty"`
	// Expected is the identity the device must report: the operator-declared
	// values of the asset's binding attributes (C1). A mismatch ends the
	// session (identity_mismatch).
	Expected []Expected `json:"expected_identity"`
	Limits   Limits     `json:"limits"`
}

// Expected is one binding attribute and its declared value.
type Expected struct {
	Name  string `json:"name"` // C1 attribute name, e.g. "firmware_id"
	Value string `json:"value"`
}

// Limits bound one invocation (R5.4). All are required. The ceilings below
// are hard: an invocation that asks for more is refused before connecting.
type Limits struct {
	ConnectTimeoutMS int64 `json:"connect_timeout_ms"`
	StepTimeoutMS    int64 `json:"step_timeout_ms"`    // per expected prompt
	DeadlineMS       int64 `json:"deadline_ms"`        // whole invocation
	MaxResponseBytes int64 `json:"max_response_bytes"` // received bytes, whole session
	// ConnectRetries applies only before any byte is sent. Nothing is ever
	// retried once a byte has left the node, and authentication is never
	// retried (D2).
	ConnectRetries int `json:"connect_retries"`
	// MinIntervalMS is the minimum time since the previous invocation that
	// connected to the same endpoint (rate limit).
	MinIntervalMS int64 `json:"min_interval_ms"`
}

// Ceilings (proposed; A6 to confirm against V-S13 and the capability matrix).
// The SEL-751 SER holds at most 1,024 rows (S22 Table 7.63); at about 80 bytes
// per row a full read is under 100 KiB, so 1 MiB leaves room for headers and
// settings without allowing an unbounded read.
const (
	MaxConnectTimeoutMS = 30_000
	MaxStepTimeoutMS    = 60_000
	MaxDeadlineMS       = 600_000
	MaxResponseBytes    = 1 << 20
	MaxConnectRetries   = 2
	MinMinIntervalMS    = 1_000
	// MaxConcurrentSessions is one: C2 0.1 runs one session per asset
	// (D9), and a profile may not allow more (D1-18).
	MaxConcurrentSessions = 1
)

var (
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// The shape of a register operation ID; RegisterLookup decides whether
	// the register has it.
	operationIDPattern = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_]+)+$`)
	// A copy of C7's credential reference ID syntax, which C7 does not
	// export; TestCredentialRefMatchesC7 keeps the two equal.
	credentialRefPattern = regexp.MustCompile(`^cred_[a-z0-9]{8,40}$`)
	paramName            = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	paramValue           = regexp.MustCompile(`^[A-Z0-9/]{1,32}$`)
)

// DecodeInvocation parses an invocation strictly (strictjson.Decode, D1-10):
// unknown fields, case-variant or duplicate keys and trailing data reject it.
func DecodeInvocation(b []byte) (Invocation, error) {
	var inv Invocation
	if err := strictjson.Decode(b, &inv); err != nil {
		return Invocation{}, fmt.Errorf("adapter: invocation: %w", err)
	}
	return inv, inv.Validate()
}

// Validate checks the invocation's shape and limits. It cannot know whether
// the operation is invocable; ValidateWith does.
func (inv Invocation) Validate() error {
	var errs []error
	fail := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	id, err := version.Parse(inv.Schema)
	if err != nil || !self.Accepts(id) {
		return fmt.Errorf("adapter: invocation: schema %q is not readable as %s", inv.Schema, Contract)
	}
	if !uuidPattern.MatchString(inv.InvocationID) {
		fail("invocation_id %q is not a lowercase UUID", inv.InvocationID)
	}
	if !asset.ValidTime(inv.RequestedAt) {
		fail("requested_at %q is not an RFC 3339 UTC time", inv.RequestedAt)
	}
	if (authz.Principal{Type: authz.PrincipalSchedule, ID: inv.PrincipalRef}).Validate() != nil {
		fail("principal_ref %q is not a C7 principal ID", inv.PrincipalRef)
	}
	if !asset.ValidAssetID(inv.AssetID) {
		fail("asset_id %q is not a C1 asset ID", inv.AssetID)
	}
	if !tokenPattern.MatchString(inv.EndpointID) || !tokenPattern.MatchString(inv.ProfileID) {
		fail("endpoint_id and profile_id are required tokens")
	}
	if !operationIDPattern.MatchString(inv.OperationID) {
		fail("operation_id %q is not an operation ID", inv.OperationID)
	}
	for k, v := range inv.Params {
		if !paramName.MatchString(k) || !paramValue.MatchString(v) {
			fail("params: %q=%q is not a parameter name and value", k, v)
		}
	}
	if inv.CredentialRef != "" && !credentialRefPattern.MatchString(inv.CredentialRef) {
		fail("credential_ref %q is not a C7 credential reference ID", inv.CredentialRef)
	}
	if len(inv.Expected) == 0 {
		fail("expected_identity is required: every session checks identity before authenticating (AP-27)")
	}
	seen := map[string]bool{}
	for i, e := range inv.Expected {
		if !asset.ValidAttributeName(e.Name) || e.Value == "" || seen[e.Name] {
			fail("expected_identity[%d]: needs a unique C1 attribute name and a value", i)
		}
		seen[e.Name] = true
	}
	l := inv.Limits
	switch {
	case l.ConnectTimeoutMS < 1 || l.ConnectTimeoutMS > MaxConnectTimeoutMS:
		fail("limits.connect_timeout_ms %d is outside 1..%d", l.ConnectTimeoutMS, MaxConnectTimeoutMS)
	case l.StepTimeoutMS < 1 || l.StepTimeoutMS > MaxStepTimeoutMS:
		fail("limits.step_timeout_ms %d is outside 1..%d", l.StepTimeoutMS, MaxStepTimeoutMS)
	case l.DeadlineMS < l.StepTimeoutMS || l.DeadlineMS > MaxDeadlineMS:
		fail("limits.deadline_ms %d is outside step_timeout_ms..%d", l.DeadlineMS, MaxDeadlineMS)
	case l.MaxResponseBytes < 1 || l.MaxResponseBytes > MaxResponseBytes:
		fail("limits.max_response_bytes %d is outside 1..%d", l.MaxResponseBytes, MaxResponseBytes)
	case l.ConnectRetries < 0 || l.ConnectRetries > MaxConnectRetries:
		fail("limits.connect_retries %d is outside 0..%d", l.ConnectRetries, MaxConnectRetries)
	case l.MinIntervalMS < MinMinIntervalMS:
		fail("limits.min_interval_ms %d is below %d", l.MinIntervalMS, MinMinIntervalMS)
	}
	if len(errs) > 0 {
		return fmt.Errorf("adapter: invocation: %w", errors.Join(errs...))
	}
	return nil
}

// OperationLookup answers whether an operation ID names an invocable
// operation and whether the parameters fit it. It must refuse session-control
// lines, deny rules and unknown IDs alike (C-A2-1). RegisterLookup is the
// implementation over the verified register package.
type OperationLookup interface {
	Invocable(operationID string, params map[string]string) (accessLevel string, err error)
}

// RegisterLookup is OperationLookup over a verified C3 package. Its Matcher
// never returns a session-control line or a deny rule as an operation, and
// Render refuses parameters that would produce any other line.
type RegisterLookup struct{ M *register.Matcher }

// Invocable implements OperationLookup.
func (r RegisterLookup) Invocable(id string, params map[string]string) (string, error) {
	o, ok := r.M.Operation(id)
	if !ok {
		return "", &NotInvocableError{OperationID: id}
	}
	if _, err := r.M.Render(id, params); err != nil {
		return "", err
	}
	return o.AccessLevel, nil
}

// CheckAgainst checks that the invocation is the one the collector builds
// for this asset and its capability profile: the same asset, one of its
// endpoints, its profile, the binding's declared values as the expected
// identity, a credential only where C1 allows one (asset.CredentialAllowed,
// A6 C1 R-1), and limits no looser than the profile's session_limits (D1-18).
// The profile's own limits must sit within the ceilings here. The first
// failure is returned with the code the collector reports.
func (inv Invocation) CheckAgainst(a asset.Asset, p asset.CapabilityProfile) error {
	refuse := func(c Code, f string, args ...any) error {
		return &CodedError{Code: c, Err: fmt.Errorf("adapter: invocation: "+f, args...)}
	}
	if a.Suspension != nil {
		return refuse(RefusedAssetSuspended, "asset %s is suspended (%s)", a.AssetID, a.Suspension.Reason)
	}
	if inv.CredentialRef != "" {
		if err := a.CredentialAllowed(p); err != nil {
			return refuse(RefusedCredentialUnavailable, "%v", err)
		}
	}
	if inv.AssetID != a.AssetID {
		return refuse(RefusedLimits, "asset_id %s is not asset %s", inv.AssetID, a.AssetID)
	}
	found := false
	for _, ep := range a.Endpoints {
		found = found || ep.ID == inv.EndpointID
	}
	if !found {
		return refuse(RefusedLimits, "endpoint %q is not an endpoint of the asset", inv.EndpointID)
	}
	if inv.ProfileID != p.ProfileID {
		return refuse(RefusedLimits, "profile_id %s is not profile %s", inv.ProfileID, p.ProfileID)
	}
	if err := a.CheckProfile(p); err != nil {
		return refuse(RefusedLimits, "%v", err)
	}
	want := map[string]string{}
	for _, name := range a.IdentityBinding.Attributes {
		v, ok := a.Declared(name)
		if !ok {
			return refuse(RefusedLimits, "binding attribute %q has no declared value", name)
		}
		want[name] = v
	}
	got := map[string]string{}
	for _, e := range inv.Expected {
		got[e.Name] = e.Value
	}
	if len(got) != len(want) {
		return refuse(RefusedLimits, "expected_identity has %d attributes, the binding %d", len(got), len(want))
	}
	for name, v := range want {
		if got[name] != v {
			return refuse(RefusedLimits, "expected_identity %s is not the declared value", name)
		}
	}
	l := p.SessionLimits
	switch {
	case l == nil:
		return refuse(RefusedLimits, "profile %s has no session_limits (D1-18)", p.ProfileID)
	case l.MinIntervalMS < MinMinIntervalMS || l.MaxConcurrentSessions > MaxConcurrentSessions:
		return refuse(RefusedLimits, "profile %s session_limits exceed the C2 ceilings", p.ProfileID)
	case inv.Limits.MinIntervalMS < l.MinIntervalMS:
		return refuse(RefusedLimits, "limits.min_interval_ms %d is below the profile's %d", inv.Limits.MinIntervalMS, l.MinIntervalMS)
	}
	return nil
}

// ValidateWith runs Validate and then checks the operation against the
// register. The error it returns for an operation that is not invocable
// carries the code RefusedNotInvocable; for parameters, RefusedInvalidParams.
func (inv Invocation) ValidateWith(reg OperationLookup) error {
	if err := inv.Validate(); err != nil {
		return &CodedError{Code: RefusedLimits, Err: err}
	}
	level, err := reg.Invocable(inv.OperationID, inv.Params)
	if err != nil {
		var nf *NotInvocableError
		if errors.As(err, &nf) {
			return &CodedError{Code: RefusedNotInvocable, Err: err}
		}
		return &CodedError{Code: RefusedInvalidParams, Err: err}
	}
	if level != "0" && inv.CredentialRef == "" {
		return &CodedError{Code: RefusedCredentialUnavailable,
			Err: fmt.Errorf("operation %s needs access level %s and the invocation names no credential", inv.OperationID, level)}
	}
	return nil
}

// NotInvocableError is what an OperationLookup returns for an ID that is
// unknown, session-control or denied.
type NotInvocableError struct{ OperationID string }

func (e *NotInvocableError) Error() string {
	return fmt.Sprintf("operation %q is not an invocable register operation", e.OperationID)
}

// CodedError pairs a validation failure with the result code the collector
// must report for it.
type CodedError struct {
	Code Code
	Err  error
}

func (e *CodedError) Error() string { return fmt.Sprintf("%s: %v", e.Code, e.Err) }
func (e *CodedError) Unwrap() error { return e.Err }
