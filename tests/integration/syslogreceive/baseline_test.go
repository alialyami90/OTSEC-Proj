package syslogreceive

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/receive"
)

// heldLog holds the next batch, once armed, after the store has committed
// it and before AppendBatch returns to the receiver, until release is
// closed: its rows are in the store and the receiver has not counted them
// stored, a moment every commit passes through.
type heldLog struct {
	receive.Appender
	armed     atomic.Bool
	committed chan struct{}
	release   chan struct{}
}

func (h *heldLog) AppendBatch(ctx context.Context, recs []c5.Record) ([]c5.Receipt, error) {
	out, err := h.Appender.AppendBatch(ctx, recs)
	if h.armed.CompareAndSwap(true, false) {
		close(h.committed)
		<-h.release
	}
	return out, err
}

// The baseline of awaitMarker's check (P4-SYSLOG-OUTAGE, D4-116). The
// outage test's second flood failed the check on #731's head 0167022b (run
// 44057337591): 473 counted stored since its baseline and 472 new rows,
// with every message counted stored in the store. heldLog reproduces the
// moment by order, not by timing: a batch committed and not yet counted.
// The two reads the flood took (rows, then status) differ by the batch
// there. baseline, started there, does not return: it signals on
// rig.polled a poll that found messages held, and only then is the batch
// released. Once the batch is counted it returns a pair on which
// awaitMarker's check passes. Controls, run by hand and recorded in the PR:
// the two reads in baseline's place fail here, as baseline returning while
// the batch is held; given to awaitMarker they fail "counts 1 stored since
// the flood began and the store has 0 new rows", the form of the CI failure.
func TestMarkerBaselineIsSettled(t *testing.T) {
	h := &heldLog{committed: make(chan struct{}), release: make(chan struct{})}
	g := start(t, asset.SyslogUDP, nil, receive.Limits{}, func(c *receive.Config) { h.Appender, c.Log = c.Log, h })
	free := sync.OnceFunc(func() { close(h.release) })
	t.Cleanup(free) // before the rig's close, which waits for Serve
	known := dialFrom(t, ipA, "udp", g.addr)
	h.armed.Store(true)
	fmt.Fprint(known, "<13>a6 committed, not counted")
	select {
	case <-h.committed:
	case <-time.After(2 * time.Minute):
		t.Fatalf("the datagram was not committed: %+v", g.r.Status())
	}
	if rows, st := g.rows(), g.r.Status(); rows != 1 || st.Stored != 0 {
		t.Fatalf("a committed batch held: %d rows and %d counted stored, want 1 and 0", rows, st.Stored)
	}

	type pair struct {
		rows int64
		st   receive.Status
	}
	got := make(chan pair, 1)
	g.polled = make(chan struct{}, 1)
	go func() {
		defer close(got) // also when baseline fails the test from here
		rows, st := g.baseline()
		got <- pair{rows, st}
	}()
	select {
	case p, ok := <-got:
		if !ok {
			t.FailNow()
		}
		t.Fatalf("baseline returned %d rows and %d counted stored while a committed batch is not counted", p.rows, p.st.Stored)
	case <-g.polled:
	}
	free()
	p, ok := <-got
	if !ok {
		t.FailNow()
	}
	if p.rows != 1 || p.st.Stored != 1 {
		t.Fatalf("baseline after the batch was counted: %d rows and %d counted stored, want 1 and 1", p.rows, p.st.Stored)
	}
	g.awaitMarker(known, "<13>a6 marker", p.rows, p.st)
}
