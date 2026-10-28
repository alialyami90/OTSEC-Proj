package syslogreceive

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/receive"
)

// D4-21 (#317) on the real store: unknown senders hold at most a quarter of
// a datagram listener's queue. B1's criterion: under the same stall, the
// known sender loses no more with an unknown flood than without one. A
// share bounds that only while the known sender's datagrams fit in the
// other three quarters; past that, the flood can cost it at most the
// quarter. So two stalls, each run with and without the flood:
//   - short: the known datagrams fit in three quarters of the queue, and
//     none is lost either way;
//   - long: they do not, and the loss with the flood is at most the loss
//     without it plus a quarter of the queue.
// The stall is a gate in front of the real Log: the writer takes the first
// datagram and waits there, so everything after it queues, and nothing is
// timed. Evidence class: simulated, loopback only.

// gateLog holds every AppendBatch until open is closed.
type gateLog struct {
	inner   receive.Appender
	open    chan struct{}
	entered atomic.Bool
}

func (g *gateLog) AppendBatch(ctx context.Context, recs []c5.Record) ([]c5.Receipt, error) {
	g.entered.Store(true)
	select {
	case <-g.open:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return g.inner.AppendBatch(ctx, recs)
}

const shareQueue = 1024 // receive's default Limits.Queue

// stalled sends one known datagram, waits until the writer holds it at the
// gate, sends known known datagrams (and as many unknown ones, interleaved,
// when flood), opens the gate once every datagram is read, and returns the
// known datagrams lost and the status.
func stalled(t *testing.T, known int, flood bool) (lost int, st receive.Status) {
	t.Helper()
	gate := &gateLog{open: make(chan struct{})}
	g := startUnknown(t, asset.SyslogUDP, 64<<20, receive.Limits{Rate: 1e6, Burst: 1e6,
		UnknownRate: 1e6, UnknownBurst: 1e6, UnknownBytes: 64 << 20, UnknownWindow: time.Hour},
		func(a receive.Appender) receive.Appender { gate.inner = a; return gate })
	u := dialFrom(t, ipU, "udp", g.addr)
	a := dialFrom(t, ipA, "udp", g.addr)
	if _, err := fmt.Fprintf(a, "<13>device first"); err != nil {
		t.Fatal(err)
	}
	for limit := time.Now().Add(time.Minute); !gate.entered.Load(); time.Sleep(time.Millisecond) {
		if time.Now().After(limit) {
			t.Fatal("the writer never reached the store")
		}
	}
	big := strings.Repeat("u", 900)
	sent := 1
	for i := 0; i < known; i++ {
		if flood {
			if _, err := fmt.Fprintf(u, "<13>unknown %04d %s", i, big); err != nil {
				t.Fatal(err)
			}
			sent++
		}
		if _, err := fmt.Fprintf(a, "<13>device %04d", i); err != nil {
			t.Fatal(err)
		}
		sent++
		if i%10 == 9 {
			// Paced, so the socket buffer does not drop what the test counts.
			time.Sleep(5 * time.Millisecond)
		}
	}
	for limit := time.Now().Add(time.Minute); g.r.Status().Received != int64(sent); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(limit) {
			// The kernel may drop datagrams before the receiver reads
			// them; nobody counts those (F-016), so the case needs every
			// one read.
			t.Fatalf("read %d of %d datagrams", g.r.Status().Received, sent)
		}
	}
	close(gate.open)
	for limit := time.Now().Add(2 * time.Minute); ; time.Sleep(20 * time.Millisecond) {
		st = g.r.Status()
		if st.Stored+sumMap(st.Dropped) == st.Received {
			break
		}
		if time.Now().After(limit) {
			t.Fatalf("accounting did not settle: %+v", st)
		}
	}
	v := g.view()
	// Every known datagram lost is counted as queue-full, and what is
	// stored keeps the device's order.
	lost = known + 1 - len(v.known)
	if int64(lost) > st.Dropped[receive.DropQueueFull] {
		t.Errorf("%d known datagrams lost, only %d counted as queue-full", lost, st.Dropped[receive.DropQueueFull])
	}
	for i := 2; i < len(v.known); i++ {
		if v.known[i] <= v.known[i-1] {
			t.Errorf("known stored out of order: %q after %q", v.known[i], v.known[i-1])
			break
		}
	}
	if flood {
		// The flood held at most its quarter: whatever the store took of
		// it, nothing past the share was queued.
		if n := len(v.unknown); n > shareQueue/4 {
			t.Errorf("%d unknown datagrams stored from one stall, more than a quarter of the queue (%d)", n, shareQueue/4)
		}
		if st.Dropped[unknownQueueFull] == 0 {
			t.Errorf("no %s: the flood never reached its share (%+v)", unknownQueueFull, st.Dropped)
		}
	}
	if len(v.misfiled) != 0 {
		t.Errorf("misfiled: %q", v.misfiled)
	}
	t.Logf("known %d, flood %v: %d known lost; dropped %+v", known, flood, lost, st.Dropped)
	return lost, st
}

func TestB6D421ShortStallLosesNoKnown(t *testing.T) {
	// 600 fit in the three quarters (768) the share leaves.
	const known = 600
	without, _ := stalled(t, known, false)
	with, _ := stalled(t, known, true)
	if without != 0 || with != 0 {
		t.Errorf("known datagrams lost: %d without the flood, %d with it; want none either way", without, with)
	}
}

func TestB6D421LongStallFloodCostsAtMostAQuarter(t *testing.T) {
	// 1200 do not fit in the queue at all: the stall alone loses some.
	const known = 1200
	without, _ := stalled(t, known, false)
	with, _ := stalled(t, known, true)
	if without == 0 {
		t.Fatalf("the stall alone lost nothing: the case does not test what it says")
	}
	if with > without+shareQueue/4 {
		t.Errorf("known datagrams lost: %d with the flood, %d without; the flood may cost at most a quarter of the queue (%d)", with, without, shareQueue/4)
	}
	t.Logf("D4-21, long stall: the flood cost the known sender %d datagrams (bound %d)", with-without, shareQueue/4)
}
