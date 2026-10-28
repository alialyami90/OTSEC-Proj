package receive

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
)

// maxDatagram is above the largest UDP payload (65507 bytes), so no
// datagram is ever cut by the read.
const maxDatagram = 65536

// serveDatagrams reads UDP datagrams until ctx ends. A datagram is one
// message (RFC 5426), kept whole. The sender cannot be slowed, so a
// datagram over its sender's rate, one that finds the queue full, and a
// batch the store refuses are dropped and counted (drop-and-count), and the
// counts are reported as intake.drop-counted every Limits.ReportEvery. Unknown
// senders' datagrams share the queue with known senders' but may hold at most
// half of its places; one past that is dropped as queue-full.
func (r *Receiver) serveDatagrams(ctx, cctx context.Context) error {
	q := make(chan msg, r.lim.Queue)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.writeDatagrams(cctx, q)
	}()
	reported := make(chan struct{})
	go func() {
		defer close(reported)
		r.reportDrops(ctx, cctx)
	}()
	go func() {
		<-ctx.Done()
		r.pc.Close()
	}()
	buf := make([]byte, maxDatagram)
	for {
		n, addr, err := r.pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			r.update(func(s *Status) { s.LastErr = "read: " + err.Error() })
			continue
		}
		r.update(func(s *Status) { s.Received++ })
		if n == 0 {
			r.update(func(s *Status) { s.Empty++ })
			continue
		}
		from := addrOf(addr)
		_, known := r.cfg.Senders[from]
		if !r.limit.allow(from, known, time.Now()) {
			r.drop(DropRateLimit, 1)
			continue
		}
		if r.queued.Load()+int64(n) > r.lim.MaxQueueBytes {
			r.drop(DropQueueFull, 1)
			continue
		}
		m := msg{frame: frame{msg: append([]byte(nil), buf[:n]...)}, from: from, auth: event.AuthNone, rcv: r.cfg.Received()}
		if !known {
			// Spent as read (payUnknown), and only with room to queue it: this
			// loop is the queue's only sender.
			// An unknown sender may hold at most half the queue's places, so
			// a flood of them behind a slow store cannot take the places a
			// known sender's datagrams need (HR-11). The check comes before
			// payUnknown so a datagram dropped here spends no budget.
			if len(q) == cap(q) || r.unknownQueued.Load() >= int64(max(cap(q)/2, 1)) {
				r.drop(DropQueueFull, 1)
				continue
			}
			if !r.payUnknown(&m) {
				continue
			}
		}
		select {
		case q <- m:
			r.queued.Add(int64(n))
			if m.rec != nil {
				r.unknownQueued.Add(1)
			}
		default:
			r.drop(DropQueueFull, 1)
		}
	}
	close(q)
	<-done
	<-reported
	// The writer has stored or dropped everything read: the last count.
	r.reportOnce(cctx)
	return nil
}

// writeDatagrams commits queued datagrams in arrival order. A refused part
// is dropped and counted, never retried: the datagrams behind it would
// otherwise be dropped instead.
func (r *Receiver) writeDatagrams(cctx context.Context, q <-chan msg) {
	taken := func(m msg) msg {
		if m.rec != nil {
			r.unknownQueued.Add(-1)
		}
		return m
	}
	for m := range q {
		batch := []msg{taken(m)}
	fill:
		for len(batch) < store.MaxBatch {
			select {
			case m, ok := <-q:
				if !ok {
					break fill
				}
				batch = append(batch, taken(m))
			default:
				break fill
			}
		}
		var n int64
		for _, m := range batch {
			n += int64(len(m.msg))
		}
		recs, kept := r.records(batch)
		if len(recs) == 0 {
			r.queued.Add(-n)
			continue
		}
		r.commitSplit(cctx, recs, kept, false)
		r.queued.Add(-n)
	}
}

// reportDrops reports the messages dropped since the last report, one
// intake.drop-counted event per reason, every Limits.ReportEvery until ctx
// ends (Serve reports once more after its writers stop). A report that
// cannot be committed is kept and its count goes into the next one.
func (r *Receiver) reportDrops(ctx, cctx context.Context) {
	t := time.NewTicker(r.lim.ReportEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.reportOnce(cctx)
		case <-ctx.Done():
			return
		}
	}
}

func (r *Receiver) reportOnce(ctx context.Context) {
	r.mu.Lock()
	var reasons []string
	delta := map[string]int64{}
	for reason, n := range r.st.Dropped {
		if d := n - r.reported[reason]; d > 0 {
			reasons = append(reasons, reason)
			delta[reason] = d
		}
	}
	r.mu.Unlock()
	sort.Strings(reasons)
	for _, reason := range reasons {
		h := event.Health{Type: event.HealthDropCounted, Details: map[string]string{
			"listener": r.cfg.ID, "stream": string(r.cfg.Stream), "reason": reason,
			"count": strconv.FormatInt(delta[reason], 10),
		}}
		if _, err := r.cfg.Health.Emit(ctx, h); err != nil {
			r.update(func(s *Status) { s.LastErr = "drop report: " + err.Error() })
			continue
		}
		r.mu.Lock()
		r.reported[reason] += delta[reason]
		r.mu.Unlock()
	}
}
