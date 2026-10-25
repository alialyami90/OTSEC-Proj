package collector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/security/collectorwire"
)

// Enrolled is one asset this collector collects from, with its capability
// profile. It comes from the collector's own configuration, never from a
// request.
type Enrolled struct {
	Asset   asset.Asset
	Profile asset.CapabilityProfile
}

// Runner runs one accepted run: the adapter session against the device, and
// the outcome the node receives. The SEL-751 runner wraps A2's sel751.Run.
// Run must return even when the session fails; a failure is a C2 result.
type Runner interface {
	Run(ctx context.Context, plan RunPlan) RunReport
}

// RunPlan is one run that passed every check. Everything in it comes from
// the collector's configuration, its verified register and its stores; from
// the request only the operation, its parameters and the credential
// reference, all checked.
type RunPlan struct {
	Invocation adapter.Invocation
	Asset      asset.Asset
	Profile    asset.CapabilityProfile
	Endpoint   asset.Endpoint
	Register   *register.Package
	// Credential and Secret are nil for an operation at level 0.
	Credential *authz.CredentialRef
	Secret     *SecretHandle
	// Floor is the asset's failed-auth gate for this run.
	Floor *FloorGate
	// Dial connects only to the endpoint's configured host and port, and
	// only to a loopback address (D2-10, W-3).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// ReplySeq is the collector_seq of the accepted reply. NextSeq numbers
	// each event the run reports, durably.
	ReplySeq uint64
	NextSeq  func() (uint64, error)
}

// RunReport is what a run tells the pipeline besides the outcome. Its zero
// value is the cautious reading: QUI not sent, nothing learned.
type RunReport struct {
	Outcome collectorwire.RunOutcome
	// QUISent is true when the session sent QUI before the TCP close, or
	// when no login was confirmed. When a login was confirmed (the floor
	// gate saw "=>") and this is false, the relay may keep Level 1 until
	// TIDLE expires, so the pipeline sets the floor again: no new session
	// reaches the asset within TIDLE plus one minute (C7-A6-2).
	QUISent bool
	// Suspend is a credential fault the session found; empty when none.
	Suspend authz.SuspendReason
	// TIDLE is the port TIDLE read in the session; 0 when not read.
	TIDLE time.Duration
}

// PipelineConfig configures NewPipeline.
type PipelineConfig struct {
	NodeID        string
	PolicyVersion uint64
	Assets        []Enrolled
	State         *State
	Creds         *CredStore
	Registers     *Registers
	// Runner runs accepted runs. Nil means this collector hosts no adapter
	// yet: every run is refused with not_invocable after the checks that
	// need no adapter, and credential requests still work.
	Runner Runner
	// Limits are the C2 limits of every invocation, except MinIntervalMS,
	// which is the profile's. Zero values take DefaultLimits.
	Limits adapter.Limits
	// InstallLimit installs are allowed per InstallWindow. Zero means 10
	// per hour.
	InstallLimit  int
	InstallWindow time.Duration
	// ReadClearFile returns the administrator's clear-suspension.json
	// (ClearSuspensionFileName) from the folder the node and the collector
	// both read, after checking that neither service can write the folder
	// or the file (store.CheckProtectedDirFor, ReadProtectedFileFor). It
	// is read again for every asset.clear_suspension request, never
	// cached. Nil means no folder is configured, so no asset suspension
	// can be cleared.
	ReadClearFile func() ([]byte, error)
	// Alarm receives safety and integrity failures: a state write that
	// failed after a run, a result that fails the collector's own checks,
	// a runner panic. Nil drops them; the binary always sets it.
	Alarm func(error)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// NewID returns invocation IDs; nil means a random UUID. Tests only.
	NewID func() string
}

// DefaultLimits are the invocation limits when the configuration sets none.
// They sit within the C2 ceilings. ConnectRetries is 0: nothing is retried.
var DefaultLimits = adapter.Limits{
	ConnectTimeoutMS: 10_000,
	StepTimeoutMS:    15_000,
	DeadlineMS:       120_000,
	MaxResponseBytes: adapter.MaxResponseBytes,
	ConnectRetries:   0,
}

// Pipeline is the collector's Handler: it decides every request and runs
// the accepted ones.
type Pipeline struct {
	cfg    PipelineConfig
	assets map[string]Enrolled

	mu   sync.Mutex
	busy map[string]bool // assets with a session open (D9)
}

// NewPipeline checks the configuration: every asset valid, enrolled on this
// node, with a valid profile it matches.
func NewPipeline(cfg PipelineConfig) (*Pipeline, error) {
	if cfg.State == nil || cfg.Creds == nil || cfg.Registers == nil {
		return nil, errors.New("collector: pipeline needs state, credentials and registers")
	}
	if cfg.PolicyVersion == 0 {
		return nil, errors.New("collector: policy version must be at least 1")
	}
	if cfg.Limits == (adapter.Limits{}) {
		cfg.Limits = DefaultLimits
	}
	if cfg.InstallLimit <= 0 {
		cfg.InstallLimit = 10
	}
	if cfg.InstallWindow <= 0 {
		cfg.InstallWindow = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Alarm == nil {
		cfg.Alarm = func(error) {}
	}
	if cfg.NewID == nil {
		cfg.NewID = newUUID
	}
	p := &Pipeline{cfg: cfg, assets: map[string]Enrolled{}, busy: map[string]bool{}}
	for _, e := range cfg.Assets {
		if err := e.Asset.Validate(); err != nil {
			return nil, fmt.Errorf("collector: asset %s: %w", e.Asset.AssetID, err)
		}
		if string(e.Asset.NodeID) != cfg.NodeID {
			return nil, fmt.Errorf("collector: asset %s is enrolled on node %s, not %s", e.Asset.AssetID, e.Asset.NodeID, cfg.NodeID)
		}
		if err := e.Asset.CheckProfile(e.Profile); err != nil {
			return nil, fmt.Errorf("collector: asset %s: %w", e.Asset.AssetID, err)
		}
		if _, dup := p.assets[e.Asset.AssetID]; dup {
			return nil, fmt.Errorf("collector: asset %s is enrolled twice", e.Asset.AssetID)
		}
		p.assets[e.Asset.AssetID] = e
	}
	return p, nil
}

// Refuse answers a request that failed decoding.
func (p *Pipeline) Refuse(ctx context.Context, requestID string, r *authz.Refusal) authz.CollectorReply {
	seq, err := p.cfg.State.NextSeq()
	if err != nil {
		return refused(requestID, 0, &authz.Refusal{Code: authz.RefuseStateUnavailable, Detail: "collector_seq unavailable"})
	}
	return refused(requestID, seq, r)
}

// Handle decides one request that passed authz.DecodeRequest. The decision
// is numbered first, so a number exists for every decision whatever it is,
// including one whose own state write then fails.
func (p *Pipeline) Handle(ctx context.Context, req *authz.CollectorRequest) (authz.CollectorReply, Work) {
	seq, err := p.cfg.State.NextSeq()
	if err != nil {
		return refused(req.RequestID, 0, &authz.Refusal{Code: authz.RefuseStateUnavailable, Detail: "collector_seq unavailable"}), nil
	}
	if req.PolicyVersion != p.cfg.PolicyVersion {
		return refused(req.RequestID, seq, &authz.Refusal{Code: authz.RefusePolicyVersion,
			Detail: fmt.Sprintf("request names policy %d, the collector has %d", req.PolicyVersion, p.cfg.PolicyVersion)}), nil
	}
	var r error
	switch {
	case req.Kind == authz.KindRun && req.Run != nil:
		var work Work
		var invID string
		invID, work, r = p.decideRun(req, seq)
		if r == nil {
			return authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyAccepted, InvocationID: invID, CollectorSeq: seq}, work
		}
	case req.Kind == authz.KindCredentialInstall && req.CredentialInstall != nil:
		r = p.install(req)
	case req.Kind == authz.KindCredentialRevoke && req.CredentialRevoke != nil:
		r = p.human(req, func() error { _, err := p.cfg.Creds.Revoke(*req.CredentialRevoke); return err })
	case req.Kind == authz.KindCredentialClearSusp && req.CredentialClearSusp != nil:
		r = p.human(req, func() error { _, err := p.cfg.Creds.ClearSuspension(*req.CredentialClearSusp); return err })
	case req.Kind == authz.KindAssetClearSusp && req.AssetClearSusp != nil:
		r = p.clearAsset(req)
	default:
		r = &authz.Refusal{Code: authz.RefuseInvalid, Detail: "body does not match kind"}
	}
	if r != nil {
		return refused(req.RequestID, seq, asRefusal(r)), nil
	}
	return authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyAccepted, CollectorSeq: seq}, nil
}

// human runs a credential change after checking again that a person asked
// for it (C7 Validate already refuses anything else).
func (p *Pipeline) human(req *authz.CollectorRequest, f func() error) error {
	if req.OnBehalfOf.Type != authz.PrincipalHuman {
		return &authz.Refusal{Code: authz.RefusePrincipal, Detail: "credential requests come from a person with the admin role"}
	}
	return f()
}

// ClearSuspensionFileName, ClearSuspensionSchema and
// MaxClearSuspensionBytes are the node's (platform/node): the collector
// reads the same administrator file. cmd/otsec-collector's tests keep
// them equal.
const (
	ClearSuspensionFileName = "clear-suspension.json"
	ClearSuspensionSchema   = "otsec.clear-suspension/0.1"
	MaxClearSuspensionBytes = 4 << 10
)

type clearFile struct {
	Schema  string `json:"schema"`
	AssetID string `json:"asset_id"`
	Ref     string `json:"ref"`
}

// clearAsset decides an asset.clear_suspension (C7 0.2, D2-15). The node
// asks after it has recorded its own clear, but the request alone clears
// nothing: the collector reads the administrator's file itself, and the
// request, the file and the invocation that suspended the asset must all
// name the same asset and ref. Anything else is suspension_mismatch and
// changes nothing, so the asset stays suspended here. The decision reaches
// the audit chain as the node's collector.request record for this reply.
func (p *Pipeline) clearAsset(req *authz.CollectorRequest) error {
	if req.OnBehalfOf.Type != authz.PrincipalNode {
		return &authz.Refusal{Code: authz.RefusePrincipal, Detail: "asset clear requests come from the node"}
	}
	body := *req.AssetClearSusp
	if _, ok := p.assets[body.AssetID]; !ok {
		return &authz.Refusal{Code: authz.RefuseAssetNotEnrolled, Detail: body.AssetID}
	}
	if p.cfg.ReadClearFile == nil {
		return &authz.Refusal{Code: authz.RefuseSuspensionMismatch, Detail: "no administrators' folder is configured"}
	}
	b, err := p.cfg.ReadClearFile()
	if err != nil {
		msg := err.Error()
		if len(msg) > 256 {
			msg = msg[:256] // the reply detail is bounded (C7 reply schema)
		}
		return &authz.Refusal{Code: authz.RefuseSuspensionMismatch, Detail: ClearSuspensionFileName + " not read: " + msg}
	}
	var f clearFile
	if err := collectorwire.DecodeStrict(b, &f); err != nil || f.Schema != ClearSuspensionSchema {
		return &authz.Refusal{Code: authz.RefuseSuspensionMismatch, Detail: ClearSuspensionFileName + " is not a " + ClearSuspensionSchema + " object"}
	}
	if f.AssetID != body.AssetID || f.Ref != body.Ref {
		return &authz.Refusal{Code: authz.RefuseSuspensionMismatch, Detail: "the request and " + ClearSuspensionFileName + " name different suspensions"}
	}
	return p.cfg.State.ClearAssetSuspension(body.AssetID, body.Ref)
}

// install spends one install from the budget, then installs. The budget is
// spent before any check, so a request that a later check refuses still
// counts: that is what bounds guessing through the reuse rule.
func (p *Pipeline) install(req *authz.CollectorRequest) error {
	return p.human(req, func() error {
		if err := p.cfg.State.TakeInstall(p.cfg.InstallLimit, p.cfg.InstallWindow); err != nil {
			return err
		}
		var t InstallTarget
		if e, ok := p.assets[req.CredentialInstall.Ref.AssetID]; ok {
			a := e.Asset
			t.Asset = &a
			t.Register, _, _ = p.cfg.Registers.Active(e.Profile.ProductFamily)
		}
		_, err := p.cfg.Creds.Install(*req.CredentialInstall, t)
		return err
	})
}

// decideRun runs the checks for a run, in this order, and stops at the
// first refusal. Nothing before the accepted reply opens a connection.
//
//  1. The principal is a schedule, which acts with the collector role. A
//     person, whatever their role, never causes device I/O directly.
//  2. The asset is enrolled on this node.
//  3. D2-4: no endpoint of the asset is labelled device-observed, and the
//     run's endpoint is labelled simulated.
//  4. D2-10: every outbound endpoint of the asset has a loopback IP
//     literal as its host. Host names, localhost included, are refused.
//  5. The family's register package is active, which means its signature
//     verified in this collector, and the run names its revision; and an
//     adapter is hosted.
//  6. The operation is invocable, read-only, in the operate phase, with
//     parameters that render, and a credential exactly when it needs one
//     (RunBody.ValidateAgainst).
//  7. The invocation the collector builds passes C2's checks against the
//     asset and profile (Validate, ValidateWith, CheckAgainst): asset not
//     suspended, a binding that compares something, a credential only where
//     C1 allows one; and no earlier run's outcome suspended the asset.
//  8. The failed-auth floor, then the profile's minimum interval.
//  9. One session per device: no other run to the asset is open.
//  10. The credential: current version active, bound to this use, its
//     access level reached by the register; the secret is decrypted only
//     here, after every other check.
//  11. The run's start is recorded durably.
func (p *Pipeline) decideRun(req *authz.CollectorRequest, seq uint64) (string, Work, error) {
	body := req.Run
	// 1.
	if req.OnBehalfOf.Type != authz.PrincipalSchedule {
		return "", nil, &authz.Refusal{Code: authz.RefusePrincipal, Detail: "run requests come from a schedule"}
	}
	// 2.
	e, ok := p.assets[body.AssetID]
	if !ok {
		return "", nil, &authz.Refusal{Code: authz.RefuseAssetNotEnrolled, Detail: fmt.Sprintf("asset %s is not enrolled on this node", body.AssetID)}
	}
	// 3 and 4.
	ep, err := collectionEndpoint(e.Asset)
	if err != nil {
		return "", nil, err
	}
	// 5.
	pkg, m, ok := p.cfg.Registers.Active(e.Profile.ProductFamily)
	if !ok {
		return "", nil, &authz.Refusal{Code: authz.RefuseRegisterUnverified, Detail: fmt.Sprintf("no verified register package for family %s", e.Profile.ProductFamily)}
	}
	if body.RegisterVersion != pkg.Revision {
		return "", nil, &authz.Refusal{Code: authz.RefuseRegisterVersion, Detail: fmt.Sprintf("request names register %d, active is %d", body.RegisterVersion, pkg.Revision)}
	}
	if p.cfg.Runner == nil {
		return "", nil, &authz.Refusal{Code: authz.RefuseNotInvocable, Detail: fmt.Sprintf("this collector hosts no adapter for family %s", e.Profile.ProductFamily)}
	}
	// 6.
	if err := body.ValidateAgainst(m); err != nil {
		return "", nil, err
	}
	op, _ := m.Operation(body.OperationID)
	// 7.
	inv, err := p.invocation(req, e, ep)
	if err != nil {
		return "", nil, err
	}
	if err := p.cfg.State.CheckSuspended(body.AssetID); err != nil {
		return "", nil, err
	}
	// 8.
	if err := p.cfg.State.CheckFloor(body.AssetID); err != nil {
		return "", nil, err
	}
	if err := p.cfg.State.CheckInterval(body.AssetID, time.Duration(inv.Limits.MinIntervalMS)*time.Millisecond); err != nil {
		return "", nil, err
	}
	// 9.
	if !p.claim(body.AssetID) {
		return "", nil, &authz.Refusal{Code: authz.RefuseBusy, Detail: fmt.Sprintf("a session to asset %s is open", body.AssetID)}
	}
	release := func() { p.release(body.AssetID) }
	// 10.
	var secret *SecretHandle
	var cred *authz.CredentialRef
	if body.CredentialRef != "" {
		use := authz.Use{
			NodeID: p.cfg.NodeID, AssetID: body.AssetID, EndpointID: ep.ID,
			Transport: authz.Transport(ep.Transport), AckScope: ackScope(&ep), AccessLevel: op.AccessLevel,
		}
		h, ref, err := p.cfg.Creds.Acquire(body.CredentialRef, use, pkg)
		if err != nil {
			release()
			return "", nil, err
		}
		secret, cred = h, &ref
	}
	// 11.
	if err := p.cfg.State.BeginRun(body.AssetID); err != nil {
		if secret != nil {
			secret.Close()
		}
		release()
		return "", nil, err
	}
	plan := RunPlan{
		Invocation: inv, Asset: e.Asset, Profile: e.Profile, Endpoint: ep, Register: pkg,
		Credential: cred, Secret: secret, Floor: NewFloorGate(p.cfg.State, body.AssetID),
		Dial: endpointDialer(ep), ReplySeq: seq, NextSeq: p.cfg.State.NextSeq,
	}
	plan.Floor.Alarm = p.cfg.Alarm
	return inv.InvocationID, &runWork{p: p, plan: plan, release: release}, nil
}

// runWork is an accepted run. Whichever of Run and Discard the server calls
// first, the run happens at most once, and the secret is wiped and the
// device freed exactly once. A later call does nothing, so it can never run
// without the claim or free a claim a later run holds (D9; A6 on #97).
type runWork struct {
	p       *Pipeline
	plan    RunPlan
	release func()
	once    sync.Once
}

// Run runs the plan. Called after Run or Discard, it runs nothing and
// returns an outcome with no result.
func (w *runWork) Run(ctx context.Context) collectorwire.RunOutcome {
	out := collectorwire.RunOutcome{InvocationID: w.plan.Invocation.InvocationID}
	w.once.Do(func() {
		defer w.finish()
		out = w.p.execute(ctx, w.plan)
	})
	return out
}

// Discard frees what the decision holds when the run never starts: no
// connection is made, and the floor and interval stay as recorded.
func (w *runWork) Discard() { w.once.Do(w.finish) }

func (w *runWork) finish() {
	if w.plan.Secret != nil {
		w.plan.Secret.Close()
	}
	w.release()
}

// execute runs the plan and applies what the run reported to the stores.
func (p *Pipeline) execute(ctx context.Context, plan RunPlan) collectorwire.RunOutcome {
	deadline := time.Duration(plan.Invocation.Limits.DeadlineMS)*time.Millisecond + 10*time.Second
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	report := p.runSafely(ctx, plan)
	asset := plan.Asset.AssetID
	if report.TIDLE > 0 {
		if err := p.cfg.State.SetTIDLE(asset, report.TIDLE); err != nil {
			p.cfg.Alarm(fmt.Errorf("collector: record TIDLE of %s: %w", asset, err))
		}
	}
	// The outcome code's suspensions apply even when the result fails the
	// checks below: suspending is the cautious direction.
	code := outcomeCode(report.Outcome)
	if r := code.Suspends(); r != "" {
		if err := p.cfg.State.SuspendAsset(asset, r, plan.Invocation.InvocationID); err != nil {
			p.cfg.Alarm(fmt.Errorf("collector: suspend asset %s (%s): %w", asset, r, err))
		}
	}
	credSuspend := report.Suspend
	if credSuspend == "" {
		credSuspend = authz.SuspendReason(code.SuspendsCredential())
	}
	if credSuspend != "" && plan.Credential != nil {
		if _, _, err := p.cfg.Creds.Suspend(plan.Credential.ID, plan.Credential.Version, credSuspend); err != nil {
			p.cfg.Alarm(fmt.Errorf("collector: suspend %s: %w", plan.Credential.ID, err))
		}
	}
	if plan.Floor.LoginConfirmed() && !report.QUISent {
		// Level 1 may outlive the connection until TIDLE expires: set the
		// floor again so no session lands on it (no TIDLE reconnect).
		if err := p.cfg.State.BeginAuth(asset); err != nil {
			p.cfg.Alarm(fmt.Errorf("collector: set floor after unclean exit from %s: %w", asset, err))
		}
	}
	p.checkResult(plan, report.Outcome)
	return report.Outcome
}

// outcomeCode is the error code of the outcome's result, read leniently and
// without Result.Validate: a result inconsistent with its own bytes (an
// adapter fault, or a redaction over a prompt) still suspends what its code
// suspends (A6 on #106). "" when the result is ok or has no error object.
// An unknown code reads as failed.unknown, which suspends nothing.
func outcomeCode(o collectorwire.RunOutcome) adapter.Code {
	var r struct {
		Error *struct {
			Code adapter.Code `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(o.Result, &r) != nil || r.Error == nil {
		return ""
	}
	return r.Error.Code.Effective()
}

// runSafely calls the runner, and turns a panic into an alarm and an empty
// outcome, which the node treats as outcome unknown. The floor and the
// stores stay in their cautious state.
func (p *Pipeline) runSafely(ctx context.Context, plan RunPlan) (report RunReport) {
	defer func() {
		if v := recover(); v != nil {
			p.cfg.Alarm(fmt.Errorf("collector: runner panicked in invocation %s: %v", plan.Invocation.InvocationID, v))
			report = RunReport{Outcome: collectorwire.RunOutcome{InvocationID: plan.Invocation.InvocationID}}
		}
	}()
	return p.cfg.Runner.Run(ctx, plan)
}

// checkResult runs the collector's own checks on the result before it is
// sent (C2 EP-4): Validate, CheckLines against the verified register, and
// CheckAgainst the asset. A failure is an alarm, and the outcome is still
// sent, because evidence is never dropped; the node quarantines it.
func (p *Pipeline) checkResult(plan RunPlan, o collectorwire.RunOutcome) {
	id := plan.Invocation.InvocationID
	if o.InvocationID != id {
		p.cfg.Alarm(fmt.Errorf("collector: runner returned the outcome of %q for invocation %s", o.InvocationID, id))
		return
	}
	res, err := adapter.DecodeResult(o.Result)
	if err == nil {
		err = res.Validate()
	}
	if err == nil {
		if lerr := res.CheckLines(plan.Register, plan.Invocation); lerr != nil {
			p.cfg.Alarm(fmt.Errorf("collector: SAFETY: invocation %s put a line on the wire the register does not allow: %w", id, lerr))
			return
		}
		err = res.CheckAgainst(plan.Invocation, plan.Asset)
	}
	if err != nil {
		p.cfg.Alarm(fmt.Errorf("collector: result of invocation %s fails the collector's checks: %w", id, err))
	}
}

// invocation builds the C2 invocation for a run and checks it (step 7).
func (p *Pipeline) invocation(req *authz.CollectorRequest, e Enrolled, ep asset.Endpoint) (adapter.Invocation, error) {
	inv := adapter.Invocation{
		Schema:        adapter.Contract,
		InvocationID:  p.cfg.NewID(),
		RequestedAt:   p.cfg.Now().UTC().Format(time.RFC3339),
		PrincipalRef:  req.OnBehalfOf.ID,
		AssetID:       e.Asset.AssetID,
		EndpointID:    ep.ID,
		ProfileID:     e.Profile.ProfileID,
		OperationID:   req.Run.OperationID,
		Params:        req.Run.Params,
		CredentialRef: req.Run.CredentialRef,
		Limits:        p.cfg.Limits,
	}
	if len(inv.Params) == 0 {
		inv.Params = nil
	}
	if e.Profile.SessionLimits != nil {
		inv.Limits.MinIntervalMS = e.Profile.SessionLimits.MinIntervalMS
	}
	for _, name := range e.Asset.Effective().IdentityBinding.Attributes {
		if v, ok := e.Asset.Declared(name); ok {
			inv.Expected = append(inv.Expected, adapter.Expected{Name: name, Value: v})
		}
	}
	_, m, _ := p.cfg.Registers.Active(e.Profile.ProductFamily)
	if err := inv.ValidateWith(adapter.RegisterLookup{M: m}); err != nil {
		return adapter.Invocation{}, c2Refusal(err)
	}
	if err := inv.CheckAgainst(e.Asset, e.Profile); err != nil {
		return adapter.Invocation{}, c2Refusal(err)
	}
	return inv, nil
}

// c2Refusal maps a C2 invocation check to the C7 refusal the collector
// replies with. The C2 code stays in the detail.
func c2Refusal(err error) *authz.Refusal {
	code := authz.RefuseInvalid
	var ce *adapter.CodedError
	if errors.As(err, &ce) {
		switch ce.Code {
		case adapter.RefusedAssetSuspended:
			code = authz.RefuseAssetNotEnrolled
		case adapter.RefusedNotInvocable:
			code = authz.RefuseNotInvocable
		case adapter.RefusedInvalidParams:
			code = authz.RefuseBadParams
		case adapter.RefusedCredentialUnavailable:
			code = authz.RefuseCredentialUnusable
		}
	}
	return &authz.Refusal{Code: code, Detail: err.Error()}
}

// collectionEndpoint applies D2-4 and D2-10 to the asset and returns its one
// outbound endpoint. C7 0.1 runs carry no endpoint ID, so an asset with more
// than one outbound endpoint is refused rather than guessed at.
func collectionEndpoint(a asset.Asset) (asset.Endpoint, error) {
	var out []asset.Endpoint
	for _, ep := range a.Endpoints {
		if ep.Target == asset.DeviceObserved {
			return asset.Endpoint{}, &authz.Refusal{Code: authz.RefuseAssetNotEnrolled,
				Detail: fmt.Sprintf("D2-4: endpoint %s is labelled device-observed; Phase 2 collects from simulators only", ep.ID)}
		}
		if ep.Transport == asset.Telnet || ep.Transport == asset.SSH {
			if err := loopbackLiteral(ep.Host); err != nil {
				return asset.Endpoint{}, &authz.Refusal{Code: authz.RefuseAssetNotEnrolled,
					Detail: fmt.Sprintf("D2-10: endpoint %s: %v", ep.ID, err)}
			}
			out = append(out, ep)
		}
	}
	switch {
	case len(out) == 0:
		return asset.Endpoint{}, &authz.Refusal{Code: authz.RefuseAssetNotEnrolled, Detail: "asset has no outbound endpoint"}
	case len(out) > 1:
		return asset.Endpoint{}, &authz.Refusal{Code: authz.RefuseInvalid, Detail: "asset has more than one outbound endpoint and the run names none"}
	case out[0].Target != asset.Simulated:
		return asset.Endpoint{}, &authz.Refusal{Code: authz.RefuseAssetNotEnrolled,
			Detail: fmt.Sprintf("D2-4: endpoint %s is not labelled simulated", out[0].ID)}
	}
	return out[0], nil
}

// loopbackLiteral accepts only an IPv4 literal in 127.0.0.0/8 or the IPv6
// literal ::1 (D2-10). It never resolves a name, so "localhost" is refused,
// and it refuses zones and IPv4-mapped IPv6 forms.
func loopbackLiteral(host string) error {
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return fmt.Errorf("host %q is not an IP literal", host)
	}
	if (a.Is4() && a.IsLoopback()) || a == netip.IPv6Loopback() {
		return nil
	}
	return fmt.Errorf("host %q is not a loopback address", host)
}

// errDialRefused is returned by an endpoint dialer for any other address.
var errDialRefused = errors.New("collector: dial refused: not the run's endpoint")

// endpointDialer permits exactly the endpoint's host and port over TCP, and
// checks D2-10 again at dial time.
func endpointDialer(ep asset.Endpoint) func(ctx context.Context, network, addr string) (net.Conn, error) {
	want := net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if (network != "tcp" && network != "tcp4" && network != "tcp6") || addr != want {
			return nil, fmt.Errorf("%w: %s %s", errDialRefused, network, addr)
		}
		if err := loopbackLiteral(ep.Host); err != nil {
			return nil, fmt.Errorf("%w: %v", errDialRefused, err)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
}

func (p *Pipeline) claim(asset string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.busy[asset] {
		return false
	}
	p.busy[asset] = true
	return true
}

func (p *Pipeline) release(asset string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.busy, asset)
}

func refused(requestID string, seq uint64, r *authz.Refusal) authz.CollectorReply {
	return authz.CollectorReply{Contract: authz.ContractID, RequestID: requestID, Status: authz.ReplyRefused, Refusal: r, CollectorSeq: seq}
}

// asRefusal turns any decision error into a refusal: a C7 refusal as it is,
// a store failure as collector_state_unavailable, anything else as invalid.
func asRefusal(err error) *authz.Refusal {
	var r *authz.Refusal
	switch {
	case errors.As(err, &r):
		return r
	case errors.Is(err, ErrStateUnavailable):
		return &authz.Refusal{Code: authz.RefuseStateUnavailable, Detail: "collector state could not be read or written durably"}
	default:
		return &authz.Refusal{Code: authz.RefuseInvalid, Detail: err.Error()}
	}
}

// newUUID returns a random lowercase version 4 UUID.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("collector: no randomness: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
