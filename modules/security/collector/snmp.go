package collector

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/ied/snmpv3"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/modules/security/snmpegress"
)

// The SNMP path through the collector (P4-3-C3 deliverable 5, D4-54): the
// register lookup for SNMP runs, the credential with its engine ID pinned,
// C2's client with every message held to the egress check, and the result
// checked with CheckSNMP. Evidence class: desk and simulated. No SNMP agent
// or device has been contacted.

// registerFor returns the profile's register package: the one its firmware
// allowlist names, because the family's allowlist ships in its own package
// (C1 on deliverable 5). For the SEL-751 that is its product family; an
// SNMP profile's product family is the product (sel-2731), and its package
// is sel-27x1-rstp (D4-54). An allowlist of "none" finds no package, and a
// package of another family is never used.
func (p *Pipeline) registerFor(prof asset.CapabilityProfile) (*register.Package, *register.Matcher, bool) {
	name := prof.Firmware.Allowlist
	if name == "" || name == "none" {
		return nil, nil, false
	}
	pkg, m, ok := p.cfg.Registers.Active(name)
	if !ok || pkg == nil || pkg.Family != name {
		return nil, nil, false
	}
	return pkg, m, true
}

// snmpEndpoint reports whether runs on ep are SNMPv3 runs.
func snmpEndpoint(ep asset.Endpoint) bool { return ep.Transport == asset.SNMPv3 }

// snmpRun returns the run id names when it is an SNMP run: a run of pkg
// whose steps are all SNMP operations. Only a run is invoked over SNMP;
// an SNMP operation alone is a step, never an invocation.
func snmpRun(pkg *register.Package, id string) *register.Run {
	run := pkg.Run(id)
	if run == nil || len(run.Steps) == 0 {
		return nil
	}
	for _, s := range run.Steps {
		if pkg.SNMPOperation(s) == nil {
			return nil
		}
	}
	return run
}

// checkSNMPRun is step 6 for an SNMP run, in place of ValidateRun: a
// request that may name a run (C7 0.7), no parameters, a credential, and
// an snmpv3 endpoint. An SNMP run has no access level; the credential is
// held to the package's SNMP operations instead (C7 0.8).
func checkSNMPRun(req *authz.CollectorRequest, ep asset.Endpoint) error {
	body := req.Run
	switch {
	case !authz.NamesRuns(req.Contract):
		return &authz.Refusal{Code: authz.RefuseUnknownOperation, Detail: body.OperationID}
	case len(body.Params) != 0:
		return &authz.Refusal{Code: authz.RefuseBadParams, Detail: fmt.Sprintf("%s is a run and takes no parameters", body.OperationID)}
	case body.CredentialRef == "":
		return &authz.Refusal{Code: authz.RefuseCredentialMismatch, Detail: fmt.Sprintf("%s is an SNMPv3 run and needs a credential", body.OperationID)}
	case ep.Transport != asset.SNMPv3:
		return &authz.Refusal{Code: authz.RefuseNotInvocable, Detail: fmt.Sprintf("%s is an SNMP run, and endpoint %s is %s", body.OperationID, ep.ID, ep.Transport)}
	}
	return nil
}

// snmpLimits are an SNMP run's invocation limits, as Limits.ForRun gives a
// line run's: the longest step timeout, the run's deadline and its total
// bytes, all from the signed register. The client holds each step to its
// own limits as well.
func snmpLimits(l adapter.Limits, pkg *register.Package, run *register.Run) adapter.Limits {
	var step int64
	for _, s := range run.Steps {
		step = max(step, pkg.SNMPOperation(s).Limits.TimeoutMS)
	}
	l.StepTimeoutMS, l.DeadlineMS, l.MaxResponseBytes = step, run.DeadlineMS, run.MaxTotalBytes
	return l
}

// snmpLookup is C2's OperationLookup for SNMP runs, which RegisterLookup
// refuses: only an SNMP run of the package, with no parameters, is
// invocable. Its level is not a register access level: it only says that
// a credential is needed.
type snmpLookup struct{ pkg *register.Package }

// snmpLevel is what snmpLookup returns: not "0", so an SNMP run always
// names a credential.
const snmpLevel = "usm"

func (l snmpLookup) Invocable(id string, params map[string]string) (string, error) {
	if snmpRun(l.pkg, id) == nil {
		return "", &adapter.NotInvocableError{OperationID: id}
	}
	if len(params) != 0 {
		return "", fmt.Errorf("adapter: run %s takes no parameters", id)
	}
	return snmpLevel, nil
}

// SNMPRunner is the Runner for SNMPv3 runs: C2's client in
// modules/ied/snmpv3, with every message it writes checked by
// snmpegress.Check first (C11 section 4 rule 4).
type SNMPRunner struct {
	// Adapter names this build in every result.
	Adapter adapter.AdapterRef
	// Now is the transcript clock; nil means time.Now.
	Now func() time.Time
	// Alarm receives an egress refusal (a client fault the check caught)
	// and a result that cannot be encoded. Nil drops them.
	Alarm func(error)
}

// Run runs one plan. Before anything is sent, the declared FID must be on
// the register's allowlist with no condition SNMP cannot confirm (C2 2.3
// step 1). The secret is opened only for the session, and the keys are
// wiped when it ends (SecretHandle.Use).
func (r *SNMPRunner) Run(ctx context.Context, plan RunPlan) RunReport {
	now := r.Now
	if now == nil {
		now = time.Now
	}
	meta := snmpv3.Meta{Adapter: r.Adapter, Target: plan.Endpoint.Target, Started: now()}
	o := r.session(ctx, plan, now)
	if o.Code == adapter.FailedEgressViolation && r.Alarm != nil {
		r.Alarm(fmt.Errorf("collector: SAFETY: the egress check refused an SNMP message in invocation %s: %s", plan.Invocation.InvocationID, o.Detail))
	}
	res := snmpv3.Result(o, plan.Invocation, plan.Register, meta)
	// No login and no QUI: confirmed is false, so no floor is kept.
	plan.Audit.ReportSession(res, false)
	b, err := json.Marshal(res)
	if err != nil {
		if r.Alarm != nil {
			r.Alarm(fmt.Errorf("collector: encode the result of %s: %w", plan.Invocation.InvocationID, err))
		}
		b = nil
	}
	return RunReport{QUISent: true, Outcome: collectorwire.RunOutcome{Wire: collectorwire.WireID, InvocationID: plan.Invocation.InvocationID, Result: b}}
}

func (r *SNMPRunner) session(ctx context.Context, plan RunPlan, now func() time.Time) snmpv3.Outcome {
	refuse := func(c adapter.Code, detail string) snmpv3.Outcome { return snmpv3.Outcome{Code: c, Detail: detail} }
	fid, ok := plan.Asset.Declared(asset.AttrFirmwareID)
	if !ok {
		return refuse(adapter.RefusedFirmwareUndeclared, "the asset declares no firmware_id")
	}
	rule, err := plan.Register.Firmware.Decide(fid)
	if err != nil {
		return refuse(adapter.RefusedFirmwareNotAllowed, "the declared FID is not allowed by the register")
	}
	if len(rule.Conditions) > 0 {
		return refuse(adapter.RefusedFirmwareNotAllowed, "the FID's branch is allowed with conditions, which an SNMP run cannot confirm")
	}
	if plan.Credential == nil || plan.Credential.USM == nil || plan.Secret == nil {
		return refuse(adapter.RefusedCredentialUnavailable, "no snmpv3 credential")
	}
	usm := plan.Credential.USM
	engine, err := hex.DecodeString(usm.EngineID)
	if err != nil {
		return refuse(adapter.RefusedCredentialUnavailable, "the credential's engine ID is not hex")
	}
	nc, err := plan.Dial(ctx, "udp", net.JoinHostPort(plan.Endpoint.Host, strconv.Itoa(plan.Endpoint.Port)))
	if err != nil {
		return refuse(adapter.FailedConnect, "the endpoint's socket did not open")
	}
	defer nc.Close()
	var o snmpv3.Outcome
	err = plan.Secret.Use(func(secret []byte) error {
		authKey, privKey, err := authz.SplitUSMSecret(secret, usm)
		if err != nil {
			return err
		}
		s := snmpv3.Session{
			Conn: &udpConn{ctx: ctx, c: nc, now: now, buf: make([]byte, 65535)},
			Keys: snmpv3.Keys{User: usm.UserName, Auth: snmpv3.AuthProto(usm.Auth), AuthKey: authKey,
				Priv: snmpv3.PrivProto(usm.Priv), PrivKey: privKey},
			EngineID: engine,
			Permit:   egressPermit(plan.Register, engine, usm.UserName, privKey),
			Now:      now,
		}
		o = s.Run(plan.Register, plan.Invocation.OperationID)
		return nil
	})
	if err != nil {
		return refuse(adapter.RefusedCredentialUnavailable, "the credential's secret could not be used")
	}
	return o
}

// egressPermit is the client's Permit: snmpegress.Check over the final wire
// bytes of each message, against the register operation it is sent for.
// The check decodes the message itself and decrypts its scoped PDU with the
// credential's AES key; it shares no code with the client (AP-5).
func egressPermit(pkg *register.Package, engine []byte, user string, privKey []byte) func(string, bool, []byte) error {
	return func(step string, engineKnown bool, msg []byte) error {
		op := pkg.SNMPOperation(step)
		if op == nil || op.Limits == nil {
			return fmt.Errorf("%q is not an SNMP operation of the package", step)
		}
		eo := snmpegress.Op{PDU: snmpegress.PDU(op.PDU), OIDs: op.OIDs, Subtree: op.Subtree,
			MaxRepetitions: op.MaxRepetitions, MaxReplyBytes: int(op.Limits.MaxReplyBytes)}
		s := snmpegress.Session{EngineKnown: engineKnown, EngineID: engine, UserName: user, PrivKey: privKey}
		if rule := snmpegress.Check(msg, eo, s); rule != snmpegress.Allowed {
			return fmt.Errorf("egress rule %s", rule)
		}
		return nil
	}
}

// udpConn is snmpv3.Conn over a connected UDP socket, so Read returns only
// datagrams from the endpoint's address and port (D4-53). A read never
// outlives the run's context. The client's deadline is on the session clock
// now, which a test build steps (C5 on #461): the socket waits the same
// length of real time.
type udpConn struct {
	ctx context.Context
	c   net.Conn
	now func() time.Time
	buf []byte
}

func (u *udpConn) Write(b []byte) error {
	_, err := u.c.Write(b)
	return err
}

func (u *udpConn) Read(deadline time.Time) ([]byte, error) {
	deadline = time.Now().Add(deadline.Sub(u.now()))
	if d, ok := u.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := u.c.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	n, err := u.c.Read(u.buf)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, snmpv3.ErrDeadline
	}
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), u.buf[:n]...), nil
}
