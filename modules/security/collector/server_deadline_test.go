package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorwire"
)

// The tests below are of RequestTimeout (D1's ruling on #752, D4-119): the
// reply keeps its own bound after a slow decision, and the read and write
// bounds still hold. A decision is made slow by a handler that sleeps, not
// by disk load.
const (
	testRT       = 250 * time.Millisecond
	slowDecision = 3 * testRT // past the deadline armed at accept
)

// slowHandler makes every decision, Handle and Refuse alike, take d, as a
// slow disk under NextSeq and the admin writes does, and records when each
// decision was made.
type slowHandler struct {
	Handler
	d       time.Duration
	decided chan time.Time
}

func newSlowHandler(h Handler) *slowHandler {
	return &slowHandler{Handler: h, d: slowDecision, decided: make(chan time.Time, 4)}
}

func (h *slowHandler) Handle(ctx context.Context, req *authz.CollectorRequest) (authz.CollectorReply, Work) {
	time.Sleep(h.d)
	r, w := h.Handler.Handle(ctx, req)
	h.decided <- time.Now()
	return r, w
}

func (h *slowHandler) Refuse(ctx context.Context, requestID string, r *authz.Refusal) authz.CollectorReply {
	time.Sleep(h.d)
	reply := h.Handler.Refuse(ctx, requestID, r)
	h.decided <- time.Now()
	return reply
}

// startServerRT is startServer with a RequestTimeout and a log writer.
func startServerRT(t *testing.T, h Handler, rt time.Duration, log io.Writer) *memListener {
	t.Helper()
	ln := newMemListener()
	s := &Server{Handler: h, RequestTimeout: rt, Log: slog.New(slog.NewTextHandler(log, nil))}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		s.Close()
		if err := <-done; !errors.Is(err, ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln
}

// T1. A decision slower than RequestTimeout is still answered, with the
// number the handler gave it, so the node records it and no collector_seq
// gap appears. Control: without the write deadline re-armed after the
// decision, each case fails with "no reply: EOF", and the run's work is
// discarded.
func TestSlowDecisionStillAnswered(t *testing.T) {
	t.Run("accepted credential request", func(t *testing.T) {
		revoke, _ := json.Marshal(authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindCredentialRevoke, RequestID: "req-2",
			OnBehalfOf: authz.Principal{Type: authz.PrincipalHuman, ID: "admin@site-a"}, PolicyVersion: 1,
			CredentialRevoke: &authz.CredentialRevokeBody{RefID: "cred_slice0001", Reason: authz.RevokeOperator}})
		h := newSlowHandler(&fakeHandler{decide: func(req *authz.CollectorRequest, seq uint64) (authz.CollectorReply, Work) {
			return authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyAccepted, CollectorSeq: seq}, nil
		}})
		ln := startServerRT(t, h, testRT, io.Discard)
		r, c := exchange(t, ln, frame(string(revoke)))
		c.Close()
		if !r.Accepted() || r.RequestID != "req-2" || r.CollectorSeq != 1 {
			t.Fatalf("reply %+v, want accepted req-2 with collector_seq 1", r)
		}
	})
	// Refuse numbers its decision too (Pipeline.Refuse calls NextSeq), on
	// each of its three paths (D6's N1 on #758).
	for name, c := range map[string]struct {
		frame []byte
		want  authz.RefusalCode
	}{
		"refused before Handle": {frame(`not JSON`), authz.RefuseMalformed},
		"refused oversize":      {binary.BigEndian.AppendUint32(nil, uint32(authz.MaxRequestBytes+1)), authz.RefuseOversize},
		"refused empty frame":   {frame(""), authz.RefuseMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			h := newSlowHandler(&fakeHandler{})
			ln := startServerRT(t, h, testRT, io.Discard)
			r, conn := exchange(t, ln, c.frame)
			conn.Close()
			if r.Accepted() || r.Refusal == nil || r.Refusal.Code != c.want || r.CollectorSeq != 1 {
				t.Fatalf("reply %+v, want refused %s with collector_seq 1", r, c.want)
			}
		})
	}
	t.Run("accepted run", func(t *testing.T) {
		w := newTrackedWork()
		h := newSlowHandler(&fakeHandler{decide: acceptRun(w)})
		ln := startServerRT(t, h, testRT, io.Discard)
		r, c := exchange(t, ln, frame(runRequest))
		defer c.Close()
		if !r.Accepted() || r.InvocationID != "inv-1" || r.CollectorSeq != 1 {
			t.Fatalf("reply %+v", r)
		}
		b, err := collectorwire.ReadFrame(c, collectorwire.MaxOutcomeBytes)
		if err != nil {
			t.Fatalf("no outcome: %v", err)
		}
		if o, err := collectorwire.DecodeOutcome(b); err != nil || o.InvocationID != "inv-1" {
			t.Fatalf("outcome %+v, %v", o, err)
		}
		if w.runs.Load() != 1 || w.discards.Load() != 0 {
			t.Fatalf("runs %d, discards %d; want 1 and 0", w.runs.Load(), w.discards.Load())
		}
	})
}

// T2. The read bound still counts from accept: a peer that sends nothing,
// or half a frame, loses its connection within about RequestTimeout, and
// nothing is decided or numbered.
func TestReadBoundCountsFromAccept(t *testing.T) {
	h := &fakeHandler{}
	ln := startServerRT(t, h, testRT, io.Discard)
	for name, sent := range map[string][]byte{"nothing": nil, "half a frame": frame(runRequest)[:20]} {
		c := ln.dial(t)
		start := time.Now()
		if len(sent) > 0 {
			if _, err := c.Write(sent); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		c.SetReadDeadline(start.Add(3 * time.Second))
		_, err := c.Read(make([]byte, 1))
		if !errors.Is(err, io.EOF) {
			t.Errorf("%s: read %v after %v, want the server to close within about %v", name, err, time.Since(start), testRT)
		}
		c.Close()
	}
	if handled, refused := h.counts(); handled != 0 || refused != 0 {
		t.Fatalf("handled %d, refused %d; want 0 and 0", handled, refused)
	}
}

// T3. The write bound still holds after a slow decision: a peer that never
// reads the reply loses its connection about RequestTimeout after the
// decision, the accepted run never starts, and its work is discarded.
func TestWriteBoundAfterSlowDecision(t *testing.T) {
	w := newTrackedWork()
	h := newSlowHandler(&fakeHandler{decide: acceptRun(w)})
	var log bytes.Buffer // read only after w.wait, which follows the server's write
	ln := startServerRT(t, h, testRT, &log)
	c := ln.dial(t)
	defer c.Close()
	if _, err := c.Write(frame(runRequest)); err != nil {
		t.Fatal(err)
	}
	w.wait(t)
	held := time.Since(<-h.decided)
	if w.runs.Load() != 0 || w.discards.Load() != 1 {
		t.Fatalf("runs %d, discards %d; want 0 and 1", w.runs.Load(), w.discards.Load())
	}
	if held < testRT/2 {
		t.Errorf("reply abandoned %v after the decision, want about %v", held, testRT)
	}
	if !strings.Contains(log.String(), "reply not written") {
		t.Errorf("log %q, want \"reply not written\"", log.String())
	}
}
