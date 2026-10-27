// Package collector is the privileged collector (D2-1, ADR-0002): the C7
// IPC server, and, in later changes, the credential store, the durable
// collector state (the failed-auth floor and collector_seq) and the run
// pipeline that hosts the SEL-751 adapter.
//
// This file is the server. It reads one request per connection, decodes it
// with authz.DecodeRequest, and hands only a request that passed every C7
// syntax rule to the Handler. A request with a field C7 does not define, or
// any other strictness failure, is answered by Handler.Refuse and never
// reaches Handler.Handle, so it cannot lead to device I/O.
package collector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorwire"
)

// Work is the run an accepted request leads to. The server calls exactly one
// of its methods, once:
//
//   - Run, after the accepted reply has been written. What it returns is sent
//     as the RunOutcome frame. It must return an outcome even when the run
//     fails: a failure is a C2 result, never a missing frame.
//   - Discard, when the run will never start: the reply could not be
//     written, or the handler broke the reply contract. It releases what the
//     accepted decision holds (the device, a decrypted secret) without any
//     device I/O (A6 on #97).
type Work interface {
	Run(ctx context.Context) collectorwire.RunOutcome
	Discard()
}

// WorkFunc is a Work that holds nothing to release.
type WorkFunc func(ctx context.Context) collectorwire.RunOutcome

// Run calls f.
func (f WorkFunc) Run(ctx context.Context) collectorwire.RunOutcome { return f(ctx) }

// Discard does nothing.
func (WorkFunc) Discard() {}

// Handler decides requests. It owns collector_seq: every reply it returns
// carries the next number, durably recorded, because each decision is an
// event the node must audit (C7-A5-2).
type Handler interface {
	// Handle decides a request that passed authz.DecodeRequest. For an
	// accepted run it returns the work; for anything else work is nil.
	Handle(ctx context.Context, req *authz.CollectorRequest) (authz.CollectorReply, Work)
	// Refuse answers a request that failed decoding. requestID is empty,
	// because nothing in an undecodable request can be trusted.
	Refuse(ctx context.Context, requestID string, r *authz.Refusal) authz.CollectorReply
}

// Server serves C7 requests to a Handler.
type Server struct {
	Handler Handler
	// Log receives one line per connection outcome. It never receives a
	// request body, a secret, or a device line. Nil means slog.Default.
	Log *slog.Logger
	// MaxConns bounds concurrent connections; further clients wait in the
	// listener's backlog. Zero means 4.
	MaxConns int
	// RequestTimeout bounds reading the request and writing the reply.
	// Zero means 5 seconds.
	RequestTimeout time.Duration
	// OutcomeTimeout bounds writing the outcome frame once the work has
	// returned. Zero means 30 seconds.
	OutcomeTimeout time.Duration

	mu     sync.Mutex
	ln     net.Listener
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed bool
}

// ErrServerClosed is returned by Serve after Close.
var ErrServerClosed = errors.New("collector: server closed")

// lingerTimeout is how long the server waits, after its last frame, for the
// client to close first. A pipe whose server closes first may discard data
// the client has not read yet; waiting for the client's end of stream
// avoids that on both transports.
const lingerTimeout = 5 * time.Second

// lingerMaxBytes bounds what linger drains. A client that sent an oversize
// frame may still be writing its body; draining it lets the client read the
// refusal instead of meeting a reset, and the bound stops a client from
// holding the connection by writing forever.
const lingerMaxBytes = 64 << 10

// Serve accepts connections until Close. A peer that fails the transport's
// identity check is logged and skipped.
func (s *Server) Serve(ln net.Listener) error {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		return ErrServerClosed
	}
	s.ln, s.cancel = ln, cancel
	s.mu.Unlock()

	max := s.MaxConns
	if max <= 0 {
		max = 4
	}
	slots := make(chan struct{}, max)
	for {
		slots <- struct{}{}
		c, err := ln.Accept()
		if err != nil {
			<-slots
			if errors.Is(err, collectorwire.ErrPeerRefused) {
				s.log().Warn("collector: peer refused", "err", err)
				continue
			}
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return ErrServerClosed
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-slots }()
			s.serveConn(ctx, c)
		}()
	}
}

// Close stops accepting, cancels running work through its context, and
// waits for every connection to finish.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln, cancel := s.ln, s.cancel
	s.mu.Unlock()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
	return err
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	rt := s.RequestTimeout
	if rt <= 0 {
		rt = 5 * time.Second
	}
	c.SetDeadline(time.Now().Add(rt))

	var reply authz.CollectorReply
	var work Work
	var kind authz.RequestKind
	body, err := collectorwire.ReadFrame(c, authz.MaxRequestBytes)
	switch {
	case errors.Is(err, collectorwire.ErrFrameTooLarge):
		// The body was not read; answer and close.
		reply = s.Handler.Refuse(ctx, "", &authz.Refusal{Code: authz.RefuseOversize})
	case errors.Is(err, collectorwire.ErrEmptyFrame):
		reply = s.Handler.Refuse(ctx, "", &authz.Refusal{Code: authz.RefuseMalformed, Detail: "empty frame"})
	case err != nil:
		// No complete request arrived: nothing to decide, nothing to number.
		s.log().Info("collector: no request", "err", err)
		return
	default:
		req, derr := authz.DecodeRequest(body)
		if derr != nil {
			var r *authz.Refusal
			if !errors.As(derr, &r) {
				r = &authz.Refusal{Code: authz.RefuseMalformed}
			}
			reply = s.Handler.Refuse(ctx, "", r)
		} else {
			kind = req.Kind
			reply, work = s.Handler.Handle(ctx, req)
		}
	}

	// The server's own invariants on what the handler returned: work comes
	// exactly with an accepted run, which also carries an invocation ID; an
	// accepted credential request has neither. A handler that breaks this
	// is a bug; the connection is dropped without a reply, so the node sees
	// a failed request, never a run it cannot account for.
	acceptedRun := reply.Accepted() && kind == authz.KindRun
	if acceptedRun != (work != nil) || (acceptedRun && reply.InvocationID == "") || (!acceptedRun && reply.InvocationID != "") {
		s.log().Error("collector: handler broke the reply contract; dropping connection",
			"request_id", reply.RequestID, "status", reply.Status, "has_work", work != nil)
		if work != nil {
			work.Discard()
		}
		return
	}
	out, err := json.Marshal(reply)
	if err == nil {
		err = collectorwire.WriteFrame(c, out, collectorwire.MaxReplyBytes)
	}
	if err != nil {
		s.log().Warn("collector: reply not written", "request_id", reply.RequestID, "collector_seq", reply.CollectorSeq, "err", err)
		// The run was accepted and numbered but the node did not get the
		// reply; it must not start, since the node cannot record it.
		if work != nil {
			work.Discard()
		}
		return
	}
	s.log().Info("collector: request decided", "request_id", reply.RequestID, "status", reply.Status,
		"collector_seq", reply.CollectorSeq, "repeat_of", reply.RepeatOf, "refusal", refusalCode(reply))
	if work == nil {
		linger(c)
		return
	}

	// The run has no deadline from this connection: the adapter's own
	// limits (C2 deadline_ms) bound it, and Close cancels ctx.
	c.SetDeadline(time.Time{})
	outcome := work.Run(ctx)
	if outcome.InvocationID != reply.InvocationID {
		s.log().Error("collector: outcome invocation_id differs from the reply; dropping connection", "request_id", reply.RequestID)
		return
	}
	ob, err := collectorwire.EncodeOutcome(outcome)
	if err != nil {
		s.log().Error("collector: outcome not encodable", "request_id", reply.RequestID, "err", err)
		return
	}
	ot := s.OutcomeTimeout
	if ot <= 0 {
		ot = 30 * time.Second
	}
	c.SetDeadline(time.Now().Add(ot))
	if err := collectorwire.WriteFrame(c, ob, collectorwire.MaxOutcomeBytes); err != nil {
		s.log().Warn("collector: outcome not written", "request_id", reply.RequestID, "invocation_id", reply.InvocationID, "err", err)
		return
	}
	linger(c)
}

// linger waits for the client to close after the server's last frame,
// discarding at most lingerMaxBytes of anything it still sends, for at most
// lingerTimeout.
func linger(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(lingerTimeout))
	io.Copy(io.Discard, io.LimitReader(c, lingerMaxBytes))
}

func refusalCode(r authz.CollectorReply) string {
	if r.Refusal == nil {
		return ""
	}
	return string(r.Refusal.Code)
}
