package receive

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/node"
	"otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/normalize"
)

// HealthUnknownSource is the C4 health type raised the first time a sender
// that no asset claims is heard on a listener. Its message is stored like
// any other, with asset-unresolved (C4's type set is open).
const HealthUnknownSource = "syslog.unknown-source"

// Drop reasons, the reason detail of intake.drop-counted. Only datagrams
// are dropped; a stream is slowed or held instead.
const (
	DropRateLimit = "rate-limit" // the sender, or all unknown senders, over their rate
	DropQueueFull = "queue-full" // arriving faster than the store commits
	DropStore     = "store"      // the store refused the batch (quota, or not open)
)

// ErrConfig is returned by New and ServerTLS for a configuration the
// listener refuses.
var ErrConfig = errors.New("receive: invalid configuration")

// Appender commits records and returns their receipts. *store.Log is one;
// the node hands over a wrapper for the listener's database that fails
// while the database is not open.
type Appender interface {
	AppendBatch(ctx context.Context, recs []store.Record) ([]store.Receipt, error)
}

// HealthSink commits a platform health event on the node's health stream,
// as for the forwarder: the sink builds the pending C4 event and returns
// its key once the commit has returned.
type HealthSink interface {
	Emit(ctx context.Context, h event.Health) (store.Key, error)
}

// Config is one listener.
type Config struct {
	Node node.ID
	// ID is the node configuration's listener ID; Stream is its C5 stream,
	// of class syslog-stream for TCP and TLS and syslog-datagram for UDP.
	ID     string
	Stream store.StreamID
	// Transport is syslog-tls, syslog-tcp or syslog-udp; Address is the
	// ip:port to bind, an IP literal.
	Transport asset.Transport
	Address   string
	// Target is what is behind the listener (D1-24 amendment).
	Target asset.EvidenceClass
	// TLS is ServerTLS's configuration, required for syslog-tls only.
	TLS *tls.Config
	// Plaintext must be true for syslog-tcp and syslog-udp: the lab-only
	// flag, until the owner decides on plaintext Syslog (ADR-0005).
	Plaintext bool
	Senders   Senders
	Log       Appender
	Health    HealthSink
	// Received is the node clock's reading as a C4 receive time.
	Received func() event.Received
	Limits   Limits
}

// Limits bound what one listener accepts. Zero values take the defaults.
type Limits struct {
	// MaxMessage is the longest stream frame kept whole (default 8192, the
	// RFC 5425 size a receiver should accept; at least 2048). A datagram
	// is always kept whole: UDP bounds it at 65507 bytes.
	MaxMessage int
	// Rate and Burst bound messages per sender address (defaults 100 per
	// second, burst 200). UnknownRate and UnknownBurst bound all unknown
	// senders together (defaults 4 times the per-sender values).
	Rate         float64
	Burst        int
	UnknownRate  float64
	UnknownBurst int
	// MaxSources is how many sender addresses the rate limiter tracks
	// (default 4096).
	MaxSources int
	// MaxConns and MaxConnsPerSource bound open stream connections
	// (defaults 64 and 4); a connection over either is closed at accept.
	MaxConns, MaxConnsPerSource int
	// IdleTimeout closes a connection that starts no frame for this long
	// (default 10 minutes); FrameTimeout bounds one frame once its first
	// byte is in (default 30 s); HandshakeTimeout bounds TLS (default 10 s).
	IdleTimeout, FrameTimeout, HandshakeTimeout time.Duration
	// Queue is how many messages wait for the store per connection, or for
	// the datagram listener (defaults 64 and 1024).
	Queue int
	// Retry is the wait before a refused stream batch is tried again
	// (default 1 s). Grace is how long queued messages may still commit
	// after the listener is stopped (default 5 s).
	Retry, Grace time.Duration
	// ReportEvery is how often datagram drop counts are reported (default
	// 10 s).
	ReportEvery time.Duration
	// MaxUnknown bounds how many unknown sender addresses are remembered
	// and reported one by one (default 256); past it one summary is
	// reported.
	MaxUnknown int
	// MaxQueueBytes bounds the bytes of datagrams waiting for the store
	// (default 8 MiB); a datagram past it is dropped as queue-full.
	MaxQueueBytes int64
}

func (l Limits) withDefaults(udp bool) Limits {
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	defD := func(v *time.Duration, d time.Duration) {
		if *v == 0 {
			*v = d
		}
	}
	def(&l.MaxMessage, 8192)
	if l.Rate == 0 {
		l.Rate = 100
	}
	def(&l.Burst, 200)
	if l.UnknownRate == 0 {
		l.UnknownRate = 4 * l.Rate
	}
	def(&l.UnknownBurst, 4*l.Burst)
	def(&l.MaxSources, 4096)
	def(&l.MaxConns, 64)
	def(&l.MaxConnsPerSource, 4)
	defD(&l.IdleTimeout, 10*time.Minute)
	defD(&l.FrameTimeout, 30*time.Second)
	defD(&l.HandshakeTimeout, 10*time.Second)
	if udp {
		def(&l.Queue, 1024)
	} else {
		def(&l.Queue, 64)
	}
	defD(&l.Retry, time.Second)
	defD(&l.Grace, 5*time.Second)
	defD(&l.ReportEvery, 10*time.Second)
	def(&l.MaxUnknown, 256)
	if l.MaxQueueBytes == 0 {
		l.MaxQueueBytes = 8 << 20
	}
	return l
}

func (l Limits) validate() error {
	switch {
	case l.MaxMessage < 2048 || l.MaxMessage > 65536:
		return fmt.Errorf("max message %d not in [2048, 65536]", l.MaxMessage)
	case l.Rate < 0 || l.Burst < 1 || l.UnknownRate < 0 || l.UnknownBurst < 1:
		return errors.New("rates must be positive and bursts at least 1")
	case l.MaxSources < 1 || l.MaxConns < 1 || l.MaxConnsPerSource < 1 || l.Queue < 1 || l.MaxUnknown < 1 || l.MaxQueueBytes < maxDatagram:
		return errors.New("counts must be positive")
	case l.IdleTimeout < 0 || l.FrameTimeout < 0 || l.HandshakeTimeout < 0 || l.Retry < 0 || l.Grace < 0 || l.ReportEvery < 0:
		return errors.New("durations must be positive")
	}
	return nil
}

// Status is a listener's state for node status and `otsec health`.
type Status struct {
	ID        string
	Transport asset.Transport
	Address   string
	Open      bool // bound and serving
	// Connections is the number of open stream connections.
	Connections int
	// Received counts messages read off the wire; Stored counts those
	// committed with a receipt. LastMessage is when the last was stored.
	Received, Stored int64
	LastMessage      time.Time
	// Dropped counts datagrams dropped, by reason (DropRateLimit,
	// DropQueueFull, DropStore).
	Dropped map[string]int64
	// Refused counts stream connections closed before any frame was read,
	// by reason: "limit" (MaxConns or MaxConnsPerSource) or "tls".
	Refused map[string]int64
	// Truncated and Misframed count stored messages with FlagTruncated and
	// FlagFraming. Discarded counts bytes past MaxMessage in an over-long
	// line, which were never stored; Empty counts empty lines.
	Truncated, Misframed, Discarded, Empty int64
	// UnknownSenders counts distinct unknown addresses heard, up to
	// Limits.MaxUnknown; UnknownOverflow is set once more were heard.
	UnknownSenders  int
	UnknownOverflow bool
	// Held is true while a stream batch waits for the store to take it
	// (refuse-new: no more is read from that connection meanwhile).
	Held    bool
	LastErr string
}

// Receiver is one Syslog listener.
type Receiver struct {
	cfg    Config
	lim    Limits
	limit  *limiter
	lab    bool
	tlsCfg *tls.Config

	mu       sync.Mutex
	st       Status
	held     int
	perSrc   map[netip.Addr]int
	unknown  map[netip.Addr]bool
	summary  bool // the past-MaxUnknown summary has been raised
	reported map[string]int64
	queued   atomic.Int64 // datagram bytes waiting for the store

	ln net.Listener
	pc net.PacketConn
}

// New checks a listener's configuration. It binds nothing.
func New(cfg Config) (*Receiver, error) {
	udp := cfg.Transport == asset.SyslogUDP
	lim := cfg.Limits.withDefaults(udp)
	bad := func(format string, args ...any) (*Receiver, error) {
		return nil, fmt.Errorf("%w: listener %s: %s", ErrConfig, cfg.ID, fmt.Sprintf(format, args...))
	}
	if !cfg.Node.Valid() {
		return bad("node %q", cfg.Node)
	}
	if !cfg.Stream.Valid() {
		return bad("stream %q", cfg.Stream)
	}
	switch cfg.Transport {
	case asset.SyslogTLS:
		if cfg.TLS == nil {
			return bad("syslog-tls needs a TLS configuration (ServerTLS)")
		}
	case asset.SyslogTCP, asset.SyslogUDP:
		if !cfg.Plaintext {
			return bad("%s is plaintext; it runs only under the lab-only flag until the owner decides", cfg.Transport)
		}
		if cfg.TLS != nil {
			return bad("%s takes no TLS configuration", cfg.Transport)
		}
	default:
		return bad("transport %q is not a Syslog transport", cfg.Transport)
	}
	ap, err := netip.ParseAddrPort(cfg.Address)
	if err != nil || ap.Addr().Zone() != "" {
		return bad("address %q is not ip:port", cfg.Address)
	}
	if cfg.Target != asset.DeviceObserved && cfg.Target != asset.Simulated {
		return bad("target %q is not %s or %s", cfg.Target, asset.DeviceObserved, asset.Simulated)
	}
	if cfg.Log == nil || cfg.Health == nil || cfg.Received == nil {
		return bad("log, health sink and clock are required")
	}
	if err := lim.validate(); err != nil {
		return bad("%v", err)
	}
	for a, s := range cfg.Senders {
		if a != a.Unmap() || s.AssetID == "" || (s.Target != asset.DeviceObserved && s.Target != asset.Simulated) {
			return bad("sender %s: %+v", a, s)
		}
	}
	r := &Receiver{
		cfg: cfg, lim: lim, limit: newLimiter(lim), lab: cfg.Plaintext, tlsCfg: cfg.TLS,
		perSrc: map[netip.Addr]int{}, unknown: map[netip.Addr]bool{}, reported: map[string]int64{},
		st: Status{ID: cfg.ID, Transport: cfg.Transport, Address: cfg.Address, Dropped: map[string]int64{}, Refused: map[string]int64{}},
	}
	return r, nil
}

// Listen binds the listener's address and returns the bound address.
func (r *Receiver) Listen() (net.Addr, error) {
	if r.cfg.Transport == asset.SyslogUDP {
		pc, err := net.ListenPacket("udp", r.cfg.Address)
		if err != nil {
			return nil, fmt.Errorf("receive: listener %s: %w", r.cfg.ID, err)
		}
		r.pc = pc
		return pc.LocalAddr(), nil
	}
	ln, err := net.Listen("tcp", r.cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("receive: listener %s: %w", r.cfg.ID, err)
	}
	r.ln = ln
	return ln.Addr(), nil
}

// Serve receives until ctx ends, then closes the listener, lets queued
// messages commit for up to Limits.Grace, and returns nil. Listen must have
// succeeded.
func (r *Receiver) Serve(ctx context.Context) error {
	if r.ln == nil && r.pc == nil {
		return fmt.Errorf("receive: listener %s: not bound", r.cfg.ID)
	}
	r.update(func(s *Status) { s.Open = true })
	defer r.update(func(s *Status) { s.Open = false })
	// Commits outlive ctx by Grace, so what was read is stored if it can be.
	cctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, func() { time.AfterFunc(r.lim.Grace, cancel) })
	defer stop()
	defer cancel()
	if r.pc != nil {
		return r.serveDatagrams(ctx, cctx)
	}
	return r.serveStreams(ctx, cctx)
}

// Run is Listen then Serve.
func (r *Receiver) Run(ctx context.Context) error {
	if _, err := r.Listen(); err != nil {
		return err
	}
	return r.Serve(ctx)
}

// Status returns a copy of the listener's state.
func (r *Receiver) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.st
	s.Dropped = copyMap(r.st.Dropped)
	s.Refused = copyMap(r.st.Refused)
	s.Held = r.held > 0
	return s
}

func copyMap(m map[string]int64) map[string]int64 {
	c := make(map[string]int64, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func (r *Receiver) update(fn func(*Status)) {
	r.mu.Lock()
	fn(&r.st)
	r.mu.Unlock()
}

// msg is one message read off the wire, waiting to be stored.
type msg struct {
	frame
	from netip.Addr
	auth event.OriginAuth
	rcv  event.Received
}

// record builds msg's C5 record.
func (r *Receiver) record(m msg) (store.Record, error) {
	src, known := r.cfg.Senders[m.from]
	in := normalize.SyslogInput{
		Node: r.cfg.Node, Stream: r.cfg.Stream, Message: m.msg, Sender: m.from.String(),
		Auth: m.auth, Received: m.rcv, Flags: m.flags, Dialect: normalize.DialectRFC,
		EvidenceClass: r.cfg.Target,
	}
	if known {
		in.AssetID, in.Dialect = src.AssetID, src.Dialect
		if src.Target != asset.DeviceObserved {
			in.EvidenceClass = asset.Simulated
		}
	}
	e, err := normalize.Syslog(in)
	if err != nil {
		return store.Record{}, err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return store.Record{}, err
	}
	class := store.ClassSyslogStream
	if r.cfg.Transport == asset.SyslogUDP {
		class = store.ClassSyslogDatagram
	}
	return store.Record{Stream: r.cfg.Stream, Class: class, Event: b}, nil
}

// records builds the records of a batch. A message that cannot be built
// is a fault in this package, never in the bytes (normalize.Syslog takes
// any bytes); it is reported and the batch fails.
func (r *Receiver) records(ms []msg) ([]store.Record, error) {
	recs := make([]store.Record, 0, len(ms))
	for _, m := range ms {
		rec, err := r.record(m)
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// stored notes a committed batch and raises the unknown-source alarm for
// each unknown sender heard for the first time. At most MaxUnknown
// addresses are remembered; the first unknown sender past them raises one
// summary alarm, and later ones none, so spoofed sources cannot grow the
// table or the health stream.
func (r *Receiver) stored(ctx context.Context, ms []msg, receipts []store.Receipt) {
	type alarm struct {
		i       int
		summary bool
	}
	var alarms []alarm
	r.mu.Lock()
	r.st.Stored += int64(len(ms))
	r.st.LastMessage = time.Now()
	for i, m := range ms {
		for _, f := range m.flags {
			switch f {
			case normalize.FlagTruncated:
				r.st.Truncated++
			case normalize.FlagFraming:
				r.st.Misframed++
			}
		}
		if _, known := r.cfg.Senders[m.from]; known || r.unknown[m.from] {
			continue
		}
		switch {
		case len(r.unknown) < r.lim.MaxUnknown:
			r.unknown[m.from] = true
			r.st.UnknownSenders = len(r.unknown)
			alarms = append(alarms, alarm{i, false})
		case !r.summary:
			r.summary = true
			r.st.UnknownOverflow = true
			alarms = append(alarms, alarm{i, true})
		}
	}
	r.mu.Unlock()
	for _, a := range alarms {
		r.alarmUnknown(ctx, ms[a.i], receipts[a.i].Key(), a.summary)
	}
}

// alarmUnknown reports an unknown sender with the first message stored from
// it, or, past MaxUnknown, that more unknown senders are being heard. An
// alarm that cannot be committed is raised again with the next message
// that would have raised it.
func (r *Receiver) alarmUnknown(ctx context.Context, m msg, key store.Key, summary bool) {
	h := event.Health{Type: HealthUnknownSource, Related: []event.EventID{key}, Details: map[string]string{
		"listener": r.cfg.ID, "transport": string(r.cfg.Transport), "sender": m.from.String(), "auth": string(m.auth),
	}}
	if summary {
		h.Details["more_senders"] = "true"
		h.Details["unknown_senders"] = strconv.Itoa(r.lim.MaxUnknown)
	}
	if _, err := r.cfg.Health.Emit(ctx, h); err != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		if summary {
			r.summary = false
		} else {
			delete(r.unknown, m.from)
			r.st.UnknownSenders = len(r.unknown)
		}
		r.st.LastErr = "unknown-source alarm: " + err.Error()
	}
}

// addrOf returns a remote address as the listener's sender key.
func addrOf(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// sleep waits d or until ctx ends, and reports whether it waited d.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
