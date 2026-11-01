// Package collectorclient is the node's side of C7: it sends one request to
// the collector and returns the collector's decision and, for an accepted
// run, the outcome, after checking both.
//
// The node trusts the collector's identity (the transport checks it before a
// byte is sent) but not its output's shape: a reply or outcome that breaks
// C7, C2 or C8 is refused here, so the node never stores a result or an
// audit record that would not verify later.
package collectorclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/security/collectorwire"
)

// ErrOutcomeUnknown means the collector accepted a run but the node has no
// outcome it can trust: the connection ended before the outcome arrived, or
// the outcome failed a check. The node records the run as outcome unknown,
// never as succeeded. The Response returned with it still holds the
// accepted reply, whose collector_seq the node must audit.
var ErrOutcomeUnknown = errors.New("collectorclient: run accepted, outcome unknown")

// ErrTimeout means the collector accepted a run and its outcome did not
// arrive within the bound the node holds it to (D4-24): the run's own
// deadline from the reply, plus authz.RunOutcomeGrace. It is returned with
// ErrOutcomeUnknown, so the node records the outcome as unknown as it does
// for any lost outcome, and the same request is not sent again in the
// session (the next scheduled slot may ask again).
var ErrTimeout = errors.New("collectorclient: outcome not received within the run's deadline")

// ErrOutcomeQuarantined means the outcome arrived but failed a check. It is
// always returned together with ErrOutcomeUnknown, and the Response carries
// the outcome as Quarantine: evidence the node must keep, never a result.
var ErrOutcomeQuarantined = errors.New("collectorclient: outcome failed verification; kept as quarantined evidence")

// ErrUnauthorizedLine means Result.CheckLines failed on the node: by the
// node's own copy of the register, the session put a line on the wire that
// the run was not allowed to send. It is returned together with
// ErrOutcomeQuarantined. The node raises a safety alarm (brief section 7,
// EP-4).
var ErrUnauthorizedLine = errors.New("collectorclient: the transcript holds a line the register does not permit for this run")

// ErrProtocol means the collector's reply broke C7. No decision can be read
// from it.
var ErrProtocol = errors.New("collectorclient: reply breaks C7")

// Client sends requests to one collector.
type Client struct {
	dial func(ctx context.Context) (net.Conn, error)

	// Register, when set, returns the node's own verified copy of the
	// register package at a version, or nil if the node holds none. The
	// client then runs Result.CheckLines on every run outcome against it, so
	// the "no unauthorized line" oracle (C2 EP-4) also runs outside the
	// collector. An outcome whose package the node cannot produce is
	// ErrOutcomeUnknown. When Register is nil, CheckLines runs only in the
	// collector, before the outcome is sent.
	Register func(version uint64) *register.Package

	// grace is how long past the collector's own bound the node waits for
	// an outcome; zero means authz.RunOutcomeGrace. Tests shorten it.
	grace time.Duration
}

// New returns a client for the collector at ep. ep.Peer is the identity the
// collector must hold: on Windows collectorwire.ServiceSID of
// collectorwire.CollectorService.
func New(ep collectorwire.Endpoint) *Client {
	return &Client{dial: func(ctx context.Context) (net.Conn, error) { return collectorwire.Dial(ctx, ep) }}
}

// NewWithDialer returns a client that connects with dial. It is for tests,
// which connect to a collector.Server over an in-memory pipe; the dialer
// must make the same identity check collectorwire.Dial does if it is ever
// used for a real collector.
func NewWithDialer(dial func(ctx context.Context) (net.Conn, error)) *Client {
	return &Client{dial: dial}
}

// Response is the collector's answer to one request.
type Response struct {
	Reply authz.CollectorReply
	// Outcome is set only for an accepted run whose outcome arrived and
	// passed every check.
	Outcome *Outcome
	// Quarantine is set when the outcome arrived but failed a check
	// (ErrOutcomeQuarantined). Exactly one of Outcome and Quarantine is set
	// when an outcome frame was read; neither when none arrived.
	Quarantine *Quarantine
}

// Quarantine is a run outcome that failed verification. Nothing in it is a
// result: the node must not normalize it, forward its observations or treat
// the run as succeeded. It is evidence of what the collector reported, and
// it is never discarded (brief section 1.4; EP-1): the node stores Raw as
// quarantined evidence and records the run as outcome unknown.
type Quarantine struct {
	// Raw is the outcome frame exactly as received.
	Raw []byte
	// Reason is the check that failed. A CheckLines failure quotes the
	// line it refused, and a faulty adapter could in principle have sent
	// anything as a line, so Reason belongs with the quarantined evidence,
	// not in an operational log.
	Reason string
	// UnauthorizedLine is true when CheckLines failed: the safety case.
	UnauthorizedLine bool
	// ResultJSON is the C2 result as sent, when the envelope decoded.
	ResultJSON []byte
	// Audit holds the records that each pass audit.ValidatePending, in the
	// collector's order, even when the failed check was about the records
	// as a set (order, correlation, pairing, digest). Each one is valid C8
	// on its own; whether the node writes them, and how it marks them, is
	// the node's decision, stated in docs/phase2/A3-collector.md.
	Audit []PendingRecord
}

// Outcome is a checked run outcome.
type Outcome struct {
	InvocationID string
	Result       adapter.Result
	// ResultJSON is the result exactly as the collector sent it.
	ResultJSON []byte
	// Audit holds the pending C8 records in the collector's order, ready
	// for the store to seal (audit.Seal).
	Audit []PendingRecord
}

// PendingRecord is one pending C8 record: its bytes as received, and the
// decoded fields.
type PendingRecord struct {
	Raw    []byte
	Record *audit.Record
}

// Do sends req and returns the collector's decision. A refusal is not an
// error: it is a Response whose Reply is refused. An error with a zero
// Response means no decision was received. An error wrapping
// ErrOutcomeUnknown comes with the accepted reply.
func (c *Client) Do(ctx context.Context, req *authz.CollectorRequest) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, fmt.Errorf("collectorclient: request not sent: %w", err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if len(body) > authz.MaxRequestBytes {
		return Response{}, fmt.Errorf("collectorclient: request not sent: %d bytes, limit %d", len(body), authz.MaxRequestBytes)
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if err := collectorwire.WriteFrame(conn, body, authz.MaxRequestBytes); err != nil {
		return Response{}, err
	}
	rb, err := collectorwire.ReadFrame(conn, collectorwire.MaxReplyBytes)
	if err != nil {
		return Response{}, fmt.Errorf("collectorclient: no reply: %w", err)
	}
	reply, err := collectorwire.DecodeReply(rb)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if err := checkReply(req, reply); err != nil {
		return Response{}, err
	}
	resp := Response{Reply: reply}
	if !reply.Accepted() || req.Kind != authz.KindRun {
		return resp, nil
	}

	// The outcome is awaited no longer than the collector bounds the run
	// itself (D4-24). The caller's context still ends the wait sooner: its
	// AfterFunc above moves the deadline into the past.
	bound := c.outcomeBound(reply)
	until := time.Now().Add(bound)
	conn.SetDeadline(until)
	if ctx.Err() != nil { // cancelled before the line above could be overtaken
		conn.SetDeadline(time.Unix(1, 0))
	}
	ob, err := collectorwire.ReadFrame(conn, collectorwire.MaxOutcomeBytes)
	if err != nil {
		var ne net.Error
		if ctx.Err() == nil && errors.As(err, &ne) && ne.Timeout() && !time.Now().Before(until) {
			return resp, fmt.Errorf("%w: %w after %s: %v", ErrOutcomeUnknown, ErrTimeout, bound, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrOutcomeUnknown, err)
	}
	out, q, err := checkOutcome(req, reply, ob, c.Register)
	if err != nil {
		resp.Quarantine = q
		return resp, err
	}
	resp.Outcome = out
	return resp, nil
}

// outcomeBound is how long to wait for the outcome of an accepted request:
// the run deadline the reply names (since C7 0.7) plus the grace the
// collector itself allows past it, and for a reply without one, the ceiling
// C3 puts on any deadline, so a collector that predates the field is
// bounded too.
func (c *Client) outcomeBound(r authz.CollectorReply) time.Duration {
	grace := c.grace
	if grace == 0 {
		grace = authz.RunOutcomeGrace
	}
	ms := r.RunDeadlineMS
	if ms == 0 {
		ms = authz.MaxRunDeadlineMS
	}
	return time.Duration(ms)*time.Millisecond + grace
}

// checkReply applies C7 to a decoded reply.
func checkReply(req *authz.CollectorRequest, r authz.CollectorReply) error {
	if !authz.AcceptsContract(r.Contract) {
		return fmt.Errorf("%w: contract %q", ErrProtocol, r.Contract)
	}
	switch r.Status {
	case authz.ReplyAccepted:
		if !r.Accepted() {
			return fmt.Errorf("%w: accepted reply with a refusal or no collector_seq", ErrProtocol)
		}
		if r.RequestID != req.RequestID {
			return fmt.Errorf("%w: reply for request %q, sent %q", ErrProtocol, r.RequestID, req.RequestID)
		}
		if (req.Kind == authz.KindRun) != (r.InvocationID != "") {
			return fmt.Errorf("%w: invocation_id must be set exactly on an accepted run", ErrProtocol)
		}
	case authz.ReplyRefused:
		if r.Refusal == nil {
			return fmt.Errorf("%w: refused reply without a refusal", ErrProtocol)
		}
		if r.InvocationID != "" {
			return fmt.Errorf("%w: refused reply with an invocation_id", ErrProtocol)
		}
		// An empty request_id is the collector saying it could not decode
		// the request; any other value must be ours.
		if r.RequestID != "" && r.RequestID != req.RequestID {
			return fmt.Errorf("%w: reply for request %q, sent %q", ErrProtocol, r.RequestID, req.RequestID)
		}
		r.Refusal.Code = r.Refusal.Code.Normalize()
	default:
		return fmt.Errorf("%w: status %q", ErrProtocol, r.Status)
	}
	return nil
}

// invocationActions are the C8 actions that happen inside one C2
// invocation, whose correlation_id is the invocation ID (C8-A4-4). C8 keeps
// its own copy unexported.
var invocationActions = map[audit.Action]bool{
	audit.ActionDeviceSessionOpen: true, audit.ActionDeviceSessionClose: true, audit.ActionCredentialUse: true,
	audit.ActionDeviceOp: true, audit.ActionDeviceRefused: true, audit.ActionDevicePostureWarning: true,
}

// checkOutcome applies C2 and C8 to an outcome and ties it to the request
// and the reply. On any failure it returns the outcome as a Quarantine.
func checkOutcome(req *authz.CollectorRequest, reply authz.CollectorReply, b []byte, reg func(uint64) *register.Package) (*Outcome, *Quarantine, error) {
	q := &Quarantine{Raw: b}
	fail := func(cause error) (*Outcome, *Quarantine, error) {
		q.Reason = cause.Error()
		if q.UnauthorizedLine {
			return nil, q, fmt.Errorf("%w: %w: %w: %v", ErrOutcomeUnknown, ErrOutcomeQuarantined, ErrUnauthorizedLine, cause)
		}
		return nil, q, fmt.Errorf("%w: %w: %v", ErrOutcomeUnknown, ErrOutcomeQuarantined, cause)
	}
	o, err := collectorwire.DecodeOutcome(b)
	if err != nil {
		return fail(err)
	}
	q.ResultJSON = []byte(o.Result)
	// Keep every record that is valid on its own before judging the set,
	// so a failure later still leaves the session records with the node.
	recs := make([]*audit.Record, len(o.Audit))
	var recErr error
	for i, raw := range o.Audit {
		rec, err := audit.ValidatePending(raw)
		if err != nil {
			if recErr == nil {
				recErr = fmt.Errorf("audit record %d: %w", i, err)
			}
			continue
		}
		recs[i] = rec
		q.Audit = append(q.Audit, PendingRecord{Raw: []byte(raw), Record: rec})
	}

	if o.InvocationID != reply.InvocationID {
		return fail(fmt.Errorf("outcome for invocation %q, reply named %q", o.InvocationID, reply.InvocationID))
	}
	res, err := adapter.DecodeResult(o.Result)
	if err != nil {
		return fail(fmt.Errorf("result: %w", err))
	}
	if err := res.Validate(); err != nil {
		return fail(fmt.Errorf("result: %w", err))
	}
	if res.InvocationID != reply.InvocationID || res.OperationID != req.Run.OperationID || res.RegisterVersion != req.Run.RegisterVersion {
		return fail(fmt.Errorf("result is for invocation %q, operation %q, register %d; the run was %q, %q, %d",
			res.InvocationID, res.OperationID, res.RegisterVersion, reply.InvocationID, req.Run.OperationID, req.Run.RegisterVersion))
	}
	if reg != nil {
		p := reg(req.Run.RegisterVersion)
		if p == nil {
			return fail(fmt.Errorf("no verified register package %d on the node to check the lines against", req.Run.RegisterVersion))
		}
		// CheckLines reads only the invocation's identity, operation and
		// parameters, which the node knows from its own request.
		inv := adapter.Invocation{InvocationID: reply.InvocationID, OperationID: req.Run.OperationID, Params: req.Run.Params}
		if err := res.CheckLines(p, inv); err != nil {
			q.UnauthorizedLine = true
			return fail(fmt.Errorf("result: %w", err))
		}
	}
	if recErr != nil {
		return fail(recErr)
	}

	out := &Outcome{InvocationID: o.InvocationID, Result: res, ResultJSON: []byte(o.Result), Audit: q.Audit}
	last := reply.CollectorSeq
	var opens, closes int
	for i, rec := range recs {
		if !audit.CollectorReported(rec) {
			return fail(fmt.Errorf("audit record %d: %s %s is not an event the collector reports", i, rec.Action, rec.Outcome))
		}
		// Numbers rise within one run. They need not be contiguous here,
		// because runs on other assets take numbers in between; the audit
		// chain as a whole is contiguous (audit.VerifyCollectorSeq).
		if rec.CollectorSeq <= last {
			return fail(fmt.Errorf("audit record %d: collector_seq %d after %d", i, rec.CollectorSeq, last))
		}
		last = rec.CollectorSeq
		if invocationActions[rec.Action] && rec.CorrelationID != o.InvocationID {
			return fail(fmt.Errorf("audit record %d: %s correlates to %q, not this invocation", i, rec.Action, rec.CorrelationID))
		}
		switch rec.Action {
		case audit.ActionDeviceSessionOpen:
			opens++
		case audit.ActionDeviceSessionClose:
			closes++
			if rec.TranscriptSHA256 != res.Transcript.SHA256 {
				return fail(fmt.Errorf("audit record %d: session close names transcript %s, result has %s", i, rec.TranscriptSHA256, res.Transcript.SHA256))
			}
		}
	}
	// One run is at most one session (C2 MaxConcurrentSessions, D9). A
	// transcript with any bytes means a session was opened, and its digest
	// must reach the chain through the close record (D1-25).
	if opens > 1 || closes != opens {
		return fail(fmt.Errorf("%d session open and %d session close records; want at most one, paired", opens, closes))
	}
	if len(res.Transcript.Data) > 0 && opens == 0 {
		return fail(errors.New("result has a transcript but no session records"))
	}
	return out, nil, nil
}
