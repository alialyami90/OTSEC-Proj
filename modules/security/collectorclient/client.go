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
	"otsec.local/otsec/modules/security/collectorwire"
)

// ErrOutcomeUnknown means the collector accepted a run but the node has no
// outcome it can trust: the connection ended before the outcome arrived, or
// the outcome failed a check. The node records the run as outcome unknown,
// never as succeeded. The Response returned with it still holds the
// accepted reply, whose collector_seq the node must audit.
var ErrOutcomeUnknown = errors.New("collectorclient: run accepted, outcome unknown")

// ErrProtocol means the collector's reply broke C7. No decision can be read
// from it.
var ErrProtocol = errors.New("collectorclient: reply breaks C7")

// Client sends requests to one collector.
type Client struct {
	dial func(ctx context.Context) (net.Conn, error)
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

	ob, err := collectorwire.ReadFrame(conn, collectorwire.MaxOutcomeBytes)
	if err != nil {
		return resp, fmt.Errorf("%w: %v", ErrOutcomeUnknown, err)
	}
	out, err := checkOutcome(req, reply, ob)
	if err != nil {
		return resp, fmt.Errorf("%w: %v", ErrOutcomeUnknown, err)
	}
	resp.Outcome = out
	return resp, nil
}

// checkReply applies C7 to a decoded reply.
func checkReply(req *authz.CollectorRequest, r authz.CollectorReply) error {
	if r.Contract != authz.ContractID {
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
// and the reply.
func checkOutcome(req *authz.CollectorRequest, reply authz.CollectorReply, b []byte) (*Outcome, error) {
	o, err := collectorwire.DecodeOutcome(b)
	if err != nil {
		return nil, err
	}
	if o.InvocationID != reply.InvocationID {
		return nil, fmt.Errorf("outcome for invocation %q, reply named %q", o.InvocationID, reply.InvocationID)
	}
	res, err := adapter.DecodeResult(o.Result)
	if err != nil {
		return nil, fmt.Errorf("result: %w", err)
	}
	if err := res.Validate(); err != nil {
		return nil, fmt.Errorf("result: %w", err)
	}
	if res.InvocationID != reply.InvocationID || res.OperationID != req.Run.OperationID || res.RegisterVersion != req.Run.RegisterVersion {
		return nil, fmt.Errorf("result is for invocation %q, operation %q, register %d; the run was %q, %q, %d",
			res.InvocationID, res.OperationID, res.RegisterVersion, reply.InvocationID, req.Run.OperationID, req.Run.RegisterVersion)
	}

	out := &Outcome{InvocationID: o.InvocationID, Result: res, ResultJSON: []byte(o.Result)}
	last := reply.CollectorSeq
	var opens, closes int
	for i, raw := range o.Audit {
		rec, err := audit.ValidatePending(raw)
		if err != nil {
			return nil, fmt.Errorf("audit record %d: %w", i, err)
		}
		if !audit.CollectorReported(rec) {
			return nil, fmt.Errorf("audit record %d: %s %s is not an event the collector reports", i, rec.Action, rec.Outcome)
		}
		// Numbers rise within one run. They need not be contiguous here,
		// because runs on other assets take numbers in between; the audit
		// chain as a whole is contiguous (audit.VerifyCollectorSeq).
		if rec.CollectorSeq <= last {
			return nil, fmt.Errorf("audit record %d: collector_seq %d after %d", i, rec.CollectorSeq, last)
		}
		last = rec.CollectorSeq
		if invocationActions[rec.Action] && rec.CorrelationID != o.InvocationID {
			return nil, fmt.Errorf("audit record %d: %s correlates to %q, not this invocation", i, rec.Action, rec.CorrelationID)
		}
		switch rec.Action {
		case audit.ActionDeviceSessionOpen:
			opens++
		case audit.ActionDeviceSessionClose:
			closes++
			if rec.TranscriptSHA256 != res.Transcript.SHA256 {
				return nil, fmt.Errorf("audit record %d: session close names transcript %s, result has %s", i, rec.TranscriptSHA256, res.Transcript.SHA256)
			}
		}
		out.Audit = append(out.Audit, PendingRecord{Raw: []byte(raw), Record: rec})
	}
	// One run is at most one session (C2 MaxConcurrentSessions, D9). A
	// transcript with any bytes means a session was opened, and its digest
	// must reach the chain through the close record (D1-25).
	if opens > 1 || closes != opens {
		return nil, fmt.Errorf("%d session open and %d session close records; want at most one, paired", opens, closes)
	}
	if len(res.Transcript.Data) > 0 && opens == 0 {
		return nil, errors.New("result has a transcript but no session records")
	}
	return out, nil
}
