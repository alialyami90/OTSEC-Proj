package collectorclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/security/collector"
	"otsec.local/otsec/modules/security/collectorwire"
)

const (
	invocation = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30" // result-ok.json
	transcript = "058846bcaceb20ef8553ddb4c4b6663fc2bbab1ce31e7201b5a0e992a7bbff20"
)

func runReq() *authz.CollectorRequest {
	return &authz.CollectorRequest{
		Contract: authz.ContractID, Kind: authz.KindRun, RequestID: "req-1",
		OnBehalfOf:    authz.Principal{Type: authz.PrincipalSchedule, ID: "sch-ser-751-feeder-3"},
		PolicyVersion: 3,
		Run: &authz.RunBody{AssetID: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", OperationID: "sel.ser.read_all",
			Params: map[string]string{}, CredentialRef: "cred_7f3k2m9q4x", RegisterVersion: 2},
	}
}

func resultOK(t *testing.T) json.RawMessage {
	t.Helper()
	b, err := os.ReadFile("testdata/result-ok.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// record builds a pending C8 record the collector would report for this
// run, and checks it is one C8 accepts, so a failing test is about the
// client, not the fixture.
func record(t *testing.T, action audit.Action, seq uint64, mod func(*audit.Record)) json.RawMessage {
	t.Helper()
	r := audit.Record{
		Contract: audit.ContractID, NodeID: "site-a-node-1",
		Time:   audit.Time{UTC: "2026-10-24T09:15:00.123456Z", ResolutionNS: 1000, Clock: audit.Clock{Sync: "synchronized", Source: "ntp"}},
		Actor:  audit.Actor{Type: "schedule", ID: "sch-ser-751-feeder-3", Role: "collector"},
		Action: action, Outcome: audit.OutcomeSucceeded,
		Target: &audit.Target{AssetID: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", Transport: "telnet",
			DownstreamSecurity: "plaintext-unauthenticated", CredentialRef: "cred_7f3k2m9q4x", CredentialVersion: 2, Family: "sel-751"},
		CorrelationID: invocation, CollectorSeq: seq,
	}
	if action == audit.ActionDeviceSessionClose {
		r.TranscriptSHA256 = transcript
	}
	if action == audit.ActionDeviceOp {
		r.OperationID = "sel.ser.read_all"
	}
	if mod != nil {
		mod(&r)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func validFixture(t *testing.T, raw json.RawMessage) {
	t.Helper()
	if _, err := audit.ValidatePending(raw); err != nil {
		t.Fatalf("fixture record not valid C8: %v\n%s", err, raw)
	}
}

func session(t *testing.T, first uint64) []json.RawMessage {
	recs := []json.RawMessage{
		record(t, audit.ActionDeviceSessionOpen, first, nil),
		record(t, audit.ActionCredentialUse, first+1, nil),
		record(t, audit.ActionDeviceOp, first+2, nil),
		record(t, audit.ActionDeviceSessionClose, first+3, nil),
	}
	for _, r := range recs {
		validFixture(t, r)
	}
	return recs
}

func accepted(seq uint64) authz.CollectorReply {
	return authz.CollectorReply{Contract: authz.ContractID, RequestID: "req-1", Status: authz.ReplyAccepted, InvocationID: invocation, CollectorSeq: seq}
}

// scripted answers one request with the given frames, then closes.
func scripted(t *testing.T, frames ...[]byte) *Client {
	t.Helper()
	return NewWithDialer(func(ctx context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			s.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := collectorwire.ReadFrame(s, authz.MaxRequestBytes); err != nil {
				return
			}
			for _, f := range frames {
				if err := collectorwire.WriteFrame(s, f, len(f)); err != nil {
					return
				}
			}
		}()
		return c, nil
	})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func outcome(t *testing.T, inv string, result json.RawMessage, recs []json.RawMessage) []byte {
	t.Helper()
	b, err := collectorwire.EncodeOutcome(collectorwire.RunOutcome{InvocationID: inv, Result: result, Audit: recs})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestRunOutcomeChecked(t *testing.T) {
	c := scripted(t, mustJSON(t, accepted(10)), outcome(t, invocation, resultOK(t), session(t, 11)))
	resp, err := c.Do(ctx(t), runReq())
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Reply.Accepted() || resp.Outcome == nil {
		t.Fatalf("response %+v", resp)
	}
	o := resp.Outcome
	if o.Result.Transcript.SHA256 != transcript || len(o.Audit) != 4 || o.Audit[3].Record.TranscriptSHA256 != transcript {
		t.Fatalf("outcome %+v", o)
	}
	// The raw bytes are what the store seals.
	if _, err := audit.Seal(o.Audit[0].Raw, 2, audit.Hash([]byte("previous record"))); err != nil {
		t.Fatal(err)
	}
}

func sel751(t *testing.T) *register.Package {
	t.Helper()
	b, err := os.ReadFile("testdata/register-sel-751.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// With the node's own register package, the client runs CheckLines: the
// result's lines pass, and a result that sent a line the register does not
// permit for this run is outcome unknown. Without the package the node
// claims to hold, the outcome cannot be checked.
func TestCheckLinesOnTheNode(t *testing.T) {
	p := sel751(t)
	held := func(v uint64) *register.Package {
		if v == p.Revision {
			return p
		}
		return nil
	}
	c := scripted(t, mustJSON(t, accepted(10)), outcome(t, invocation, resultOK(t), session(t, 11)))
	c.Register = held
	if resp, err := c.Do(ctx(t), runReq()); err != nil || resp.Outcome == nil {
		t.Fatalf("valid lines: %+v, %v", resp, err)
	}

	// The same result, claimed as the run of another operation: its SER line
	// is not that operation's.
	other := runReq()
	other.Run.OperationID = "sel.id"
	other.Run.CredentialRef = ""
	res := json.RawMessage(strings.Replace(string(resultOK(t)), `"sel.ser.read_all"`, `"sel.id"`, 1))
	frame := outcome(t, invocation, res, session(t, 11))
	c = scripted(t, mustJSON(t, accepted(10)), frame)
	c.Register = held
	resp, err := c.Do(ctx(t), other)
	t.Logf("other operation: %v", err)
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, ErrOutcomeQuarantined) || !errors.Is(err, ErrUnauthorizedLine) {
		t.Fatalf("got %v, want ErrOutcomeUnknown, ErrOutcomeQuarantined and ErrUnauthorizedLine", err)
	}
	// The evidence of the unauthorized line stays with the node: the frame
	// as received, the transcript holding the line, and the session records
	// whose close names the transcript's digest (A6 and A1 on #79).
	q := resp.Quarantine
	if resp.Outcome != nil || q == nil || !q.UnauthorizedLine || string(q.Raw) != string(frame) {
		t.Fatalf("quarantine %+v", q)
	}
	r, derr := adapter.DecodeResult(q.ResultJSON)
	if derr != nil || !strings.Contains(string(r.Transcript.Data), "SER\r\n") {
		t.Fatalf("transcript not reachable from the quarantine: %v", derr)
	}
	if len(q.Audit) != 4 || q.Audit[3].Record.TranscriptSHA256 != r.Transcript.SHA256 || !strings.Contains(q.Reason, "sel.ser.read_all") {
		t.Fatalf("quarantine records %d, reason %q", len(q.Audit), q.Reason)
	}

	c = scripted(t, mustJSON(t, accepted(10)), outcome(t, invocation, resultOK(t), session(t, 11)))
	c.Register = func(uint64) *register.Package { return nil }
	if _, err := c.Do(ctx(t), runReq()); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("no package: %v", err)
	}
}

func TestRefusalIsNotAnError(t *testing.T) {
	refused := authz.CollectorReply{Contract: authz.ContractID, RequestID: "req-1", Status: authz.ReplyRefused,
		Refusal: &authz.Refusal{Code: "some_future_code"}, CollectorSeq: 4}
	resp, err := scripted(t, mustJSON(t, refused)).Do(ctx(t), runReq())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Reply.Accepted() || resp.Outcome != nil || resp.Reply.Refusal.Code != authz.RefuseUnknown {
		t.Fatalf("response %+v", resp)
	}
}

func TestReplyBreakingC7Refused(t *testing.T) {
	cases := map[string]any{
		"other request":       authz.CollectorReply{Contract: authz.ContractID, RequestID: "req-2", Status: authz.ReplyAccepted, InvocationID: invocation, CollectorSeq: 1},
		"no collector_seq":    authz.CollectorReply{Contract: authz.ContractID, RequestID: "req-1", Status: authz.ReplyAccepted, InvocationID: invocation},
		"other contract":      authz.CollectorReply{Contract: "otsec.authz/1.0", RequestID: "req-1", Status: authz.ReplyAccepted, InvocationID: invocation, CollectorSeq: 1},
		"accepted, refusal":   authz.CollectorReply{Contract: authz.ContractID, RequestID: "req-1", Status: authz.ReplyAccepted, InvocationID: invocation, CollectorSeq: 1, Refusal: &authz.Refusal{Code: authz.RefuseBusy}},
		"run, no invocation":  authz.CollectorReply{Contract: authz.ContractID, RequestID: "req-1", Status: authz.ReplyAccepted, CollectorSeq: 1},
		"refused, no reason":  authz.CollectorReply{Contract: authz.ContractID, RequestID: "req-1", Status: authz.ReplyRefused, CollectorSeq: 1},
		"refused, invocation": authz.CollectorReply{Contract: authz.ContractID, RequestID: "req-1", Status: authz.ReplyRefused, InvocationID: invocation, CollectorSeq: 1, Refusal: &authz.Refusal{Code: authz.RefuseBusy}},
		"unknown status":      authz.CollectorReply{Contract: authz.ContractID, RequestID: "req-1", Status: "maybe", CollectorSeq: 1},
		"unknown field":       map[string]any{"contract": authz.ContractID, "request_id": "req-1", "status": "refused", "refusal": map[string]any{"code": "busy"}, "collector_seq": 1, "extra": 1},
	}
	for name, r := range cases {
		resp, err := scripted(t, mustJSON(t, r)).Do(ctx(t), runReq())
		t.Logf("%s: %v", name, err)
		if !errors.Is(err, ErrProtocol) || resp.Reply.Status != "" {
			t.Errorf("%s: %+v, %v; want ErrProtocol and no reply", name, resp, err)
		}
	}
}

func TestBadOutcomeIsOutcomeUnknown(t *testing.T) {
	good := session(t, 11)
	res := resultOK(t)
	otherRes := json.RawMessage(strings.Replace(string(res), `"operation_id": "sel.ser.read_all"`, `"operation_id": "sel.id"`, 1))
	if string(otherRes) == string(res) {
		otherRes = json.RawMessage(strings.Replace(string(res), `"operation_id":"sel.ser.read_all"`, `"operation_id":"sel.id"`, 1))
	}
	cases := map[string][]byte{
		"other invocation": outcome(t, "7f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30", res, good),
		"result not C2":    outcome(t, invocation, json.RawMessage(`{"schema":"otsec.adapter/0.1"}`), good),
		"other operation":  outcome(t, invocation, otherRes, good),
		"close digest wrong": outcome(t, invocation, res, []json.RawMessage{good[0], good[1], good[2],
			record(t, audit.ActionDeviceSessionClose, 14, func(r *audit.Record) { r.TranscriptSHA256 = strings.Repeat("0", 64) })}),
		"seq not rising":    outcome(t, invocation, res, []json.RawMessage{good[0], good[2], good[1], good[3]}),
		"seq at reply":      outcome(t, invocation, res, session(t, 10)),
		"other correlation": outcome(t, invocation, res, []json.RawMessage{good[0], record(t, audit.ActionCredentialUse, 12, func(r *audit.Record) { r.CorrelationID = "x" }), good[2], good[3]}),
		"open, no close":    outcome(t, invocation, res, good[:3]),
		"no session":        outcome(t, invocation, res, []json.RawMessage{}),
		"two sessions":      outcome(t, invocation, res, append(append([]json.RawMessage{}, good...), session(t, 15)...)),
		"not collector's":   outcome(t, invocation, res, append([]json.RawMessage{record(t, audit.ActionAuthLogin, 11, func(r *audit.Record) { r.CollectorSeq = 0; r.Target = nil; r.CorrelationID = "" })}, session(t, 12)...)),
		"secret field":      outcome(t, invocation, res, []json.RawMessage{json.RawMessage(strings.Replace(string(good[0]), `"action"`, `"password":"x","action"`, 1)), good[1], good[2], good[3]}),
		"not an outcome":    []byte(`{"wire":"otsec.collectorwire/0.1"}`),
	}
	for name, ob := range cases {
		resp, err := scripted(t, mustJSON(t, accepted(10)), ob).Do(ctx(t), runReq())
		t.Logf("%s: %v", name, err)
		if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, ErrOutcomeQuarantined) || !resp.Reply.Accepted() || resp.Outcome != nil {
			t.Errorf("%s: outcome %v, err %v; want ErrOutcomeQuarantined with the accepted reply", name, resp.Outcome != nil, err)
		}
		// Nothing that arrived is dropped.
		if q := resp.Quarantine; q == nil || string(q.Raw) != string(ob) || q.Reason == "" || q.UnauthorizedLine {
			t.Errorf("%s: quarantine %+v", name, q)
		}
	}
}

// The connection ends after the accepted reply: the node keeps the reply
// (its collector_seq must be audited) and treats the run as outcome unknown.
func TestLostOutcomeKeepsReply(t *testing.T) {
	resp, err := scripted(t, mustJSON(t, accepted(10))).Do(ctx(t), runReq())
	if !errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, ErrOutcomeQuarantined) || resp.Reply.CollectorSeq != 10 || resp.Outcome != nil || resp.Quarantine != nil {
		t.Fatalf("%+v, %v", resp, err)
	}
}

func TestInvalidRequestNotSent(t *testing.T) {
	var dialed atomic.Bool
	c := NewWithDialer(func(context.Context) (net.Conn, error) { dialed.Store(true); return nil, errors.New("dialed") })
	bad := runReq()
	bad.OnBehalfOf = authz.Principal{Type: authz.PrincipalHuman, ID: "monitor-1"}
	if _, err := c.Do(ctx(t), bad); err == nil || dialed.Load() {
		t.Fatalf("err %v, dialed %v", err, dialed.Load())
	}
	bad = runReq()
	bad.Run.Params = map[string]string{"x": "SER\r\nACC"}
	if _, err := c.Do(ctx(t), bad); err == nil || dialed.Load() {
		t.Fatalf("err %v, dialed %v", err, dialed.Load())
	}
}

func TestContextCancelsWait(t *testing.T) {
	c := NewWithDialer(func(ctx context.Context) (net.Conn, error) {
		cl, s := net.Pipe()
		go func() {
			collectorwire.ReadFrame(s, authz.MaxRequestBytes)
			io.Copy(io.Discard, s) // never answers
		}()
		return cl, nil
	})
	cx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	done := make(chan error, 1)
	go func() { _, err := c.Do(cx, runReq()); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("no error after cancel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Do did not return after cancel")
	}
}

// End to end over the server: the client and the collector server agree on
// the framing and the checks.
type runHandler struct {
	t   *testing.T
	seq atomic.Uint64
}

func (h *runHandler) Handle(ctx context.Context, req *authz.CollectorRequest) (authz.CollectorReply, collector.Work) {
	seq := h.seq.Add(1)
	first := h.seq.Add(4) - 3
	recs := session(h.t, first)
	return authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyAccepted, InvocationID: invocation, CollectorSeq: seq},
		func(context.Context) collectorwire.RunOutcome {
			return collectorwire.RunOutcome{InvocationID: invocation, Result: resultOK(h.t), Audit: recs}
		}
}

func (h *runHandler) Refuse(ctx context.Context, id string, r *authz.Refusal) authz.CollectorReply {
	return authz.CollectorReply{Contract: authz.ContractID, RequestID: id, Status: authz.ReplyRefused, Refusal: r, CollectorSeq: h.seq.Add(1)}
}

func TestWithServer(t *testing.T) {
	ln := &chanListener{c: make(chan net.Conn), done: make(chan struct{})}
	s := &collector.Server{Handler: &runHandler{t: t}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	go s.Serve(ln)
	defer s.Close()
	c := NewWithDialer(func(ctx context.Context) (net.Conn, error) {
		cl, sv := net.Pipe()
		ln.c <- sv
		return cl, nil
	})
	resp, err := c.Do(ctx(t), runReq())
	if err != nil || resp.Outcome == nil || resp.Reply.CollectorSeq != 1 || resp.Outcome.Audit[0].Record.CollectorSeq != 2 {
		t.Fatalf("%+v, %v", resp, err)
	}
}

type chanListener struct {
	c    chan net.Conn
	done chan struct{}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.c:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { close(l.done); return nil }
func (l *chanListener) Addr() net.Addr { return &net.UnixAddr{Name: "mem", Net: "unix"} }
