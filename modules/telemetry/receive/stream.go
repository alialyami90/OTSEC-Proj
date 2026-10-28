package receive

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
)

// serveStreams accepts TCP or TLS connections until ctx ends. cctx is the
// commit context, which outlives ctx by Grace.
func (r *Receiver) serveStreams(ctx, cctx context.Context) error {
	reported := make(chan struct{})
	go func() {
		defer close(reported)
		r.reportDrops(ctx, cctx)
	}()
	var wg sync.WaitGroup
	conns := map[net.Conn]bool{}
	var mu sync.Mutex
	go func() {
		<-ctx.Done()
		r.ln.Close()
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
	}()
	backoff := 5 * time.Millisecond
	for {
		c, err := r.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				<-reported
				// Every writer has stored or dropped what it read.
				r.reportOnce(cctx)
				return nil
			}
			r.update(func(s *Status) { s.LastErr = "accept: " + err.Error() })
			if !sleep(ctx, backoff) {
				continue
			}
			backoff = min(2*backoff, time.Second)
			continue
		}
		backoff = 5 * time.Millisecond
		from := addrOf(c.RemoteAddr())
		if !r.admit(from) {
			c.Close()
			continue
		}
		mu.Lock()
		if ctx.Err() != nil {
			mu.Unlock()
			c.Close()
			r.release(from)
			continue
		}
		conns[c] = true
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer r.release(from)
			r.serveConn(ctx, cctx, c, from)
			mu.Lock()
			delete(conns, c)
			mu.Unlock()
		}()
	}
}

// admit counts a new connection from addr, or refuses it over the limits.
// Unknown senders together hold at most MaxUnknownConns, so however many
// addresses can reach the port, the other connections stay free for
// configured devices.
func (r *Receiver) admit(addr netip.Addr) bool {
	_, known := r.cfg.Senders[addr]
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.st.Connections >= r.lim.MaxConns || r.perSrc[addr] >= r.lim.MaxConnsPerSource {
		r.st.Refused["limit"]++
		return false
	}
	if !known && r.st.UnknownConnections >= r.lim.MaxUnknownConns {
		r.st.Refused["unknown-limit"]++
		return false
	}
	r.st.Connections++
	if !known {
		r.st.UnknownConnections++
	}
	r.perSrc[addr]++
	return true
}

func (r *Receiver) release(addr netip.Addr) {
	_, known := r.cfg.Senders[addr]
	r.mu.Lock()
	defer r.mu.Unlock()
	r.st.Connections--
	if !known {
		r.st.UnknownConnections--
	}
	if r.perSrc[addr]--; r.perSrc[addr] <= 0 {
		delete(r.perSrc, addr)
	}
}

// serveConn reads one connection's frames and hands them, in order, to one
// writer that commits them. The queue between them is Limits.Queue frames
// long: when the store is slow or refusing, the reader stops reading, and
// TCP flow control holds the sender. Nothing read from a known sender is
// dropped; an unknown sender's message past the unknown budget is.
func (r *Receiver) serveConn(ctx, cctx context.Context, c net.Conn, from netip.Addr) {
	defer c.Close()
	auth := event.AuthNone
	var cert []byte // the verified leaf of a tls-mutual sender
	if r.tlsCfg != nil {
		tc := tls.Server(c, r.tlsCfg)
		hctx, cancel := context.WithTimeout(ctx, r.lim.HandshakeTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			r.update(func(s *Status) {
				s.Refused["tls"]++
				s.LastErr = "tls handshake from " + from.String() + ": " + err.Error()
			})
			return
		}
		auth = event.AuthTLSServerOnly
		if chains := tc.ConnectionState().VerifiedChains; len(chains) > 0 {
			auth, cert = event.AuthTLSMutual, chains[0][0].Raw
		}
		c = tc
	}
	_, known := r.cfg.Senders[from]
	idle := r.lim.IdleTimeout
	if !known {
		idle = r.lim.UnknownIdleTimeout
	}
	q := make(chan msg, r.lim.Queue)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.write(cctx, q)
	}()
	defer func() {
		close(q)
		<-done
	}()
	f := &framer{r: bufio.NewReaderSize(c, 4096), max: r.lim.MaxMessage, deadline: c.SetReadDeadline,
		idle: idle, whole: r.lim.FrameTimeout, now: time.Now}
	var discarded, empty int64
	for {
		fr, err := f.next()
		if d, e := f.discarded-discarded, f.empty-empty; d != 0 || e != 0 {
			discarded, empty = f.discarded, f.empty
			r.update(func(s *Status) { s.Discarded += d; s.Empty += e })
		}
		if fr != nil {
			r.update(func(s *Status) { s.Received++ })
			m := msg{frame: *fr, from: from, auth: auth, cert: cert, rcv: r.cfg.Received()}
			if known || r.payUnknown(&m) {
				select {
				case q <- m:
				case <-cctx.Done():
					// The grace after stopping has ended with the writer still
					// held by the store: the frame is read but cannot be
					// stored. RFC 5425 has no acknowledgement to withhold.
					r.update(func(s *Status) { s.LastErr = "stopped with a frame unstored from " + from.String() })
					return
				}
			}
		}
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				r.update(func(s *Status) { s.LastErr = "connection from " + from.String() + ": " + err.Error() })
			}
			return
		}
		if !sleep(ctx, r.limit.reserve(from, known, time.Now())) {
			return
		}
	}
}

// write commits a connection's frames in order, as many per batch as are
// waiting, up to Limits.Queue, so a connection never has more than
// 2 x Queue + 1 frames read and not stored: the batch in hand, the queue
// behind it and the frame the reader holds. A batch the store refuses is held and tried again every
// Limits.Retry until it commits or cctx ends (refuse-new): a stream message
// is never dropped while the node runs.
func (r *Receiver) write(cctx context.Context, q <-chan msg) {
	most := min(store.MaxBatch, r.lim.Queue)
	for m := range q {
		batch := []msg{m}
	fill:
		for len(batch) < most {
			select {
			case m, ok := <-q:
				if !ok {
					break fill
				}
				batch = append(batch, m)
			default:
				break fill
			}
		}
		if !r.commit(cctx, batch) {
			// cctx ended: drain so the reader is not blocked.
			for range q {
			}
			return
		}
	}
}

// commit stores a stream batch in parts of at most the commit cap
// (commitParts), waiting while the store refuses a part. It returns false
// when cctx ends first. An unknown sender's frames were paid for as read
// (payUnknown), so a held part spends the unknown budget once.
func (r *Receiver) commit(cctx context.Context, batch []msg) bool {
	recs, kept := r.records(batch)
	if len(recs) == 0 {
		return true
	}
	return r.commitParts(cctx, recs, kept, true)
}
