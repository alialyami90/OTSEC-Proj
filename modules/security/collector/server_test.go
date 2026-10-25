package collector

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorwire"
)

// memListener is an in-memory listener; the transports have their own tests
// in collectorwire.
type memListener struct {
	conns  chan net.Conn
	errs   chan error
	closed chan struct{}
	once   sync.Once
}

func newMemListener() *memListener {
	return &memListener{conns: make(chan net.Conn), errs: make(chan error, 4), closed: make(chan struct{})}
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case err := <-l.errs:
		return nil, err
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *memListener) Addr() net.Addr { return &net.UnixAddr{Name: "mem", Net: "unix"} }

func (l *memListener) dial(t *testing.T) net.Conn {
	t.Helper()
	c, s := net.Pipe()
	select {
	case l.conns <- s:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not accept")
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}

// fakeHandler numbers every decision and records what reached it.
type fakeHandler struct {
	seq      atomic.Uint64
	mu       sync.Mutex
	handled  []*authz.CollectorRequest
	refused  []authz.RefusalCode
	decide   func(req *authz.CollectorRequest, seq uint64) (authz.CollectorReply, Work)
	workSeen chan struct{}
}

func (h *fakeHandler) Handle(ctx context.Context, req *authz.CollectorRequest) (authz.CollectorReply, Work) {
	h.mu.Lock()
	h.handled = append(h.handled, req)
	h.mu.Unlock()
	seq := h.seq.Add(1)
	if h.decide != nil {
		return h.decide(req, seq)
	}
	return authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
		Refusal: &authz.Refusal{Code: authz.RefuseRegisterUnverified}, CollectorSeq: seq}, nil
}

func (h *fakeHandler) Refuse(ctx context.Context, requestID string, r *authz.Refusal) authz.CollectorReply {
	h.mu.Lock()
	h.refused = append(h.refused, r.Code)
	h.mu.Unlock()
	return authz.CollectorReply{Contract: authz.ContractID, RequestID: requestID, Status: authz.ReplyRefused, Refusal: r, CollectorSeq: h.seq.Add(1)}
}

func (h *fakeHandler) counts() (int, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.handled), len(h.refused)
}

func startServer(t *testing.T, h Handler) (*memListener, *Server) {
	t.Helper()
	ln := newMemListener()
	s := &Server{Handler: h, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		s.Close()
		if err := <-done; !errors.Is(err, ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln, s
}

const runRequest = `{"contract":"otsec.authz/0.1","kind":"run","request_id":"req-1",` +
	`"on_behalf_of":{"type":"schedule","id":"sch-ser-751-feeder-3"},"policy_version":3,` +
	`"run":{"asset_id":"2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13","operation_id":"sel.ser.read_all","params":{},` +
	`"credential_ref":"cred_7f3k2m9q4x","register_version":12}}`

func exchange(t *testing.T, ln *memListener, frame []byte) (authz.CollectorReply, net.Conn) {
	t.Helper()
	c := ln.dial(t)
	if _, err := c.Write(frame); err != nil {
		t.Fatal(err)
	}
	b, err := collectorwire.ReadFrame(c, collectorwire.MaxReplyBytes)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	r, err := collectorwire.DecodeReply(b)
	if err != nil {
		t.Fatal(err)
	}
	return r, c
}

func frame(body string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}

// A request with any field C7 does not define is refused before the handler
// sees it, so it cannot lead to device I/O (P2-A3 acceptance).
func TestFieldOutsideC7RefusedBeforeHandler(t *testing.T) {
	h := &fakeHandler{}
	ln, _ := startServer(t, h)
	cases := map[string]string{
		"top level":      strings.Replace(runRequest, `"policy_version":3`, `"policy_version":3,"debug":true`, 1),
		"run body":       strings.Replace(runRequest, `"params":{}`, `"params":{},"command":"SER 1"`, 1),
		"principal":      strings.Replace(runRequest, `"id":"sch-ser-751-feeder-3"`, `"id":"sch-ser-751-feeder-3","role":"admin"`, 1),
		"limits":         strings.Replace(runRequest, `"register_version":12`, `"register_version":12,"limits":{"deadline_ms":1}`, 1),
		"secret in body": strings.Replace(runRequest, `"credential_ref":"cred_7f3k2m9q4x"`, `"credential_ref":"cred_7f3k2m9q4x","password":"x"`, 1),
	}
	for name, body := range cases {
		r, c := exchange(t, ln, frame(body))
		c.Close()
		if r.Accepted() || r.Refusal == nil || r.Refusal.Code != authz.RefuseUnknownField || r.CollectorSeq == 0 {
			t.Errorf("%s: reply %+v", name, r)
		}
	}
	if handled, refused := h.counts(); handled != 0 || refused != len(cases) {
		t.Fatalf("handled %d, refused %d; want 0 and %d", handled, refused, len(cases))
	}
}

func TestMalformedRequestsRefused(t *testing.T) {
	h := &fakeHandler{}
	ln, _ := startServer(t, h)
	cases := map[string]struct {
		frame []byte
		want  authz.RefusalCode
	}{
		"duplicate key": {frame(strings.Replace(runRequest, `"kind":"run"`, `"kind":"run","kind":"run"`, 1)), authz.RefuseMalformed},
		"not JSON":      {frame(`run sel.ser.read_all`), authz.RefuseMalformed},
		"trailing data": {frame(runRequest + `{}`), authz.RefuseMalformed},
		"empty frame":   {[]byte{0, 0, 0, 0}, authz.RefuseMalformed},
		"oversize":      {binary.BigEndian.AppendUint32(nil, authz.MaxRequestBytes+1), authz.RefuseOversize},
		"run by person": {frame(strings.Replace(runRequest, `"type":"schedule","id":"sch-ser-751-feeder-3"`, `"type":"human","id":"monitor-1"`, 1)), authz.RefusePrincipal},
		"wrong major":   {frame(strings.Replace(runRequest, `otsec.authz/0.1`, `otsec.authz/1.0`, 1)), authz.RefuseContract},
	}
	for name, c := range cases {
		r, conn := exchange(t, ln, c.frame)
		conn.Close()
		if r.Accepted() || r.Refusal == nil || r.Refusal.Code != c.want || r.CollectorSeq == 0 || r.RequestID != "" {
			t.Errorf("%s: reply %+v, want refused %s with a collector_seq and no request_id", name, r, c.want)
		}
	}
	if handled, _ := h.counts(); handled != 0 {
		t.Fatalf("%d malformed requests reached Handle", handled)
	}
}

// A connection that ends before a whole request is not a decision and takes
// no collector_seq.
func TestIncompleteRequestTakesNoNumber(t *testing.T) {
	h := &fakeHandler{}
	ln, _ := startServer(t, h)
	c := ln.dial(t)
	c.Write(frame(runRequest)[:20])
	c.Close()
	r, c2 := exchange(t, ln, frame(runRequest))
	c2.Close()
	if r.CollectorSeq != 1 {
		t.Fatalf("collector_seq %d after an incomplete request, want 1", r.CollectorSeq)
	}
}

func acceptRun(work Work) func(*authz.CollectorRequest, uint64) (authz.CollectorReply, Work) {
	return func(req *authz.CollectorRequest, seq uint64) (authz.CollectorReply, Work) {
		return authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyAccepted,
			InvocationID: "inv-1", CollectorSeq: seq}, work
	}
}

func TestAcceptedRunSendsOutcomeAfterReply(t *testing.T) {
	release := make(chan struct{})
	h := &fakeHandler{decide: acceptRun(func(ctx context.Context) collectorwire.RunOutcome {
		<-release
		return collectorwire.RunOutcome{InvocationID: "inv-1", Result: json.RawMessage(`{"r":1}`), Audit: []json.RawMessage{}}
	})}
	ln, _ := startServer(t, h)
	r, c := exchange(t, ln, frame(runRequest))
	defer c.Close()
	// The reply arrived while the work was still blocked.
	if !r.Accepted() || r.InvocationID != "inv-1" {
		t.Fatalf("reply %+v", r)
	}
	close(release)
	b, err := collectorwire.ReadFrame(c, collectorwire.MaxOutcomeBytes)
	if err != nil {
		t.Fatal(err)
	}
	o, err := collectorwire.DecodeOutcome(b)
	if err != nil || o.InvocationID != "inv-1" || string(o.Result) != `{"r":1}` {
		t.Fatalf("outcome %+v, %v", o, err)
	}
}

// A handler that accepts without work, or hands out work with a refusal, is
// a bug; the node gets no reply rather than a decision it cannot account
// for.
func TestHandlerContractBreachDropsConnection(t *testing.T) {
	noop := Work(func(context.Context) collectorwire.RunOutcome { return collectorwire.RunOutcome{} })
	breaches := map[string]func(*authz.CollectorRequest, uint64) (authz.CollectorReply, Work){
		"accepted without work": acceptRun(nil),
		"refused with work": func(req *authz.CollectorRequest, seq uint64) (authz.CollectorReply, Work) {
			return authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
				Refusal: &authz.Refusal{Code: authz.RefuseBusy}, CollectorSeq: seq}, noop
		},
		"accepted without seq": func(req *authz.CollectorRequest, seq uint64) (authz.CollectorReply, Work) {
			return authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyAccepted, InvocationID: "i"}, noop
		},
		"accepted without invocation": func(req *authz.CollectorRequest, seq uint64) (authz.CollectorReply, Work) {
			return authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyAccepted, CollectorSeq: seq}, noop
		},
	}
	for name, decide := range breaches {
		ln, _ := startServer(t, &fakeHandler{decide: decide})
		c := ln.dial(t)
		c.Write(frame(runRequest))
		if _, err := collectorwire.ReadFrame(c, collectorwire.MaxReplyBytes); err == nil {
			t.Errorf("%s: got a reply", name)
		}
		c.Close()
	}
}

// An accepted credential request has no work and no invocation ID, and gets
// its reply; with work or an invocation ID it is a breach.
func TestAcceptedCredentialRequest(t *testing.T) {
	revoke, _ := json.Marshal(authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindCredentialRevoke, RequestID: "req-2",
		OnBehalfOf: authz.Principal{Type: authz.PrincipalHuman, ID: "admin@site-a"}, PolicyVersion: 1,
		CredentialRevoke: &authz.CredentialRevokeBody{RefID: "cred_slice0001", Reason: authz.RevokeOperator}})
	accept := func(inv string, w Work) func(*authz.CollectorRequest, uint64) (authz.CollectorReply, Work) {
		return func(req *authz.CollectorRequest, seq uint64) (authz.CollectorReply, Work) {
			return authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyAccepted, InvocationID: inv, CollectorSeq: seq}, w
		}
	}
	ln, _ := startServer(t, &fakeHandler{decide: accept("", nil)})
	r, c := exchange(t, ln, frame(string(revoke)))
	c.Close()
	if !r.Accepted() || r.InvocationID != "" {
		t.Fatalf("reply %+v", r)
	}
	noop := Work(func(context.Context) collectorwire.RunOutcome { return collectorwire.RunOutcome{} })
	for name, d := range map[string]func(*authz.CollectorRequest, uint64) (authz.CollectorReply, Work){
		"with work":          accept("inv-1", noop),
		"with an invocation": accept("inv-1", nil),
	} {
		ln, _ := startServer(t, &fakeHandler{decide: d})
		c := ln.dial(t)
		c.Write(frame(string(revoke)))
		if _, err := collectorwire.ReadFrame(c, collectorwire.MaxReplyBytes); err == nil {
			t.Errorf("%s: got a reply", name)
		}
		c.Close()
	}
}

func TestOutcomeForAnotherInvocationDropped(t *testing.T) {
	h := &fakeHandler{decide: acceptRun(func(ctx context.Context) collectorwire.RunOutcome {
		return collectorwire.RunOutcome{InvocationID: "inv-2", Result: json.RawMessage(`{}`)}
	})}
	ln, _ := startServer(t, h)
	r, c := exchange(t, ln, frame(runRequest))
	defer c.Close()
	if !r.Accepted() {
		t.Fatalf("reply %+v", r)
	}
	if _, err := collectorwire.ReadFrame(c, collectorwire.MaxOutcomeBytes); err == nil {
		t.Fatal("outcome for another invocation was sent")
	}
}

func TestCloseCancelsWork(t *testing.T) {
	started := make(chan struct{})
	h := &fakeHandler{decide: acceptRun(func(ctx context.Context) collectorwire.RunOutcome {
		close(started)
		<-ctx.Done()
		return collectorwire.RunOutcome{InvocationID: "inv-1", Result: json.RawMessage(`{}`)}
	})}
	ln := newMemListener()
	s := &Server{Handler: h, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	go s.Serve(ln)
	_, c := exchange(t, ln, frame(runRequest))
	defer c.Close()
	<-started
	closed := make(chan struct{})
	go func() {
		go func() { // read the outcome and close, as the node does
			collectorwire.ReadFrame(c, collectorwire.MaxOutcomeBytes)
			c.Close()
		}()
		s.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return while work was running")
	}
}

// A client the transport refused is logged and the server keeps serving.
func TestPeerRefusedKeepsServing(t *testing.T) {
	h := &fakeHandler{}
	ln, _ := startServer(t, h)
	ln.errs <- collectorwire.ErrPeerRefused
	r, c := exchange(t, ln, frame(runRequest))
	c.Close()
	if r.CollectorSeq != 1 {
		t.Fatalf("reply %+v", r)
	}
}

// A client that sends an oversize frame with its body still gets the
// refusal: the body is never read as a request, and the server drains it
// (bounded) instead of closing on unread data (A6 review of #79).
func TestOversizeBodyStillGetsRefusal(t *testing.T) {
	h := &fakeHandler{}
	ln, _ := startServer(t, h)
	c := ln.dial(t)
	defer c.Close()
	n := authz.MaxRequestBytes + 1000
	sent := make(chan error, 1)
	go func() {
		c.Write(binary.BigEndian.AppendUint32(nil, uint32(n)))
		_, err := c.Write(make([]byte, n))
		sent <- err
	}()
	b, err := collectorwire.ReadFrame(c, collectorwire.MaxReplyBytes)
	if err != nil {
		t.Fatal(err)
	}
	r, err := collectorwire.DecodeReply(b)
	if err != nil || r.Refusal == nil || r.Refusal.Code != authz.RefuseOversize {
		t.Fatalf("reply %+v, %v", r, err)
	}
	if handled, _ := h.counts(); handled != 0 {
		t.Fatal("oversize request reached Handle")
	}
	// The whole body was accepted: the server drained it rather than
	// leaving it unread.
	select {
	case err := <-sent:
		if err != nil {
			t.Fatalf("body write: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not drain the body")
	}
}
