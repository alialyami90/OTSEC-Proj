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

// Health types this package raises (C4's type set is open).
const (
	// HealthUnknownSource is raised the first time a sender that no asset
	// claims is heard on a listener. Its message is stored like any other,
	// with asset-unresolved.
	HealthUnknownSource = "syslog.unknown-source"
	// HealthUnknownBudget is raised when unknown senders' messages are
	// dropped because their storage budget (Limits.UnknownBytes) is spent,
	// at most once per Limits.UnknownWindow.
	HealthUnknownBudget = "syslog.unknown-budget"
)

// Drop reasons, the reason detail of intake.drop-counted. A known sender's
// stream message is never dropped: its stream is slowed or held instead.
const (
	DropRateLimit     = "rate-limit"     // a datagram: the sender, or all unknown senders, over their rate
	DropQueueFull     = "queue-full"     // a datagram arriving faster than the store commits
	DropStore         = "store"          // a datagram batch the store refused (quota, or not open), or a message whose record could not be built
	DropUnknownBudget = "unknown-budget" // an unknown sender's message past Limits.UnknownBytes
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
	// Plaintext must be true for syslog-tcp and syslog-udp: plaintext is
	// enabled per listener by the operator, TLS being the default (D3-5).
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
	// MaxUnknownConns bounds those from unknown senders (default 16, or a
	// quarter of MaxConns if less; below MaxConns), so the rest are kept
	// for configured devices.
	MaxConns, MaxConnsPerSource, MaxUnknownConns int
	// IdleTimeout closes a connection that starts no frame for this long
	// (default 10 minutes; UnknownIdleTimeout, default 30 s, for an unknown
	// sender); FrameTimeout bounds one frame once its first byte is in
	// (default 30 s); HandshakeTimeout bounds TLS (default 10 s).
	IdleTimeout, UnknownIdleTimeout, FrameTimeout, HandshakeTimeout time.Duration
	// UnknownBytes is how many record bytes all unknown senders together
	// may store per UnknownWindow (defaults 1 MiB per hour; at least
	// 256 KiB), so unattributed traffic cannot fill the class quota that
	// configured devices' events need. It is a token bucket: up to
	// UnknownBytes at once, refilled evenly over the window. A message past
	// it is dropped and counted as unknown-budget.
	UnknownBytes  int64
	UnknownWindow time.Duration
	// Queue is how many messages wait for the store per connection, or for
	// the datagram listener (defaults 64 and 1024). A stream batch is also
	// at most Queue, so a connection holds at most 2 x Queue + 1 messages
	// read and not stored.
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
	def(&l.MaxUnknownConns, min(16, max(1, l.MaxConns/4)))
	defD(&l.IdleTimeout, 10*time.Minute)
	defD(&l.UnknownIdleTimeout, min(30*time.Second, l.IdleTimeout))
	if l.UnknownBytes == 0 {
		l.UnknownBytes = 1 << 20
	}
	defD(&l.UnknownWindow, time.Hour)
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

// minUnknownBytes keeps the unknown budget above the largest record one
// datagram can make, so no single message is refused for its size alone.
const minUnknownBytes = 256 << 10

func (l Limits) validate() error {
	switch {
	case l.MaxMessage < 2048 || l.MaxMessage > 65536:
		return fmt.Errorf("max message %d not in [2048, 65536]", l.MaxMessage)
	case l.Rate < 0 || l.Burst < 1 || l.UnknownRate < 0 || l.UnknownBurst < 1:
		return errors.New("rates must be positive and bursts at least 1")
	case l.MaxSources < 1 || l.MaxConns < 1 || l.MaxConnsPerSource < 1 || l.Queue < 1 || l.MaxUnknown < 1 || l.MaxQueueBytes < maxDatagram:
		return errors.New("counts must be positive")
	case l.MaxUnknownConns < 1 || l.MaxUnknownConns >= l.MaxConns:
		return fmt.Errorf("max unknown connections %d not in [1, max connections %d)", l.MaxUnknownConns, l.MaxConns)
	case l.UnknownBytes < minUnknownBytes:
		return fmt.Errorf("unknown bytes %d below %d", l.UnknownBytes, minUnknownBytes)
	case l.IdleTimeout < 0 || l.UnknownIdleTimeout < 0 || l.FrameTimeout < 0 || l.HandshakeTimeout < 0 || l.Retry < 0 || l.Grace < 0 || l.ReportEvery < 0 || l.UnknownWindow <= 0:
		return errors.New("durations must be positive")
	case l.UnknownIdleTimeout > l.IdleTimeout:
		return errors.New("the unknown-sender idle timeout is above the idle timeout")
	}
	return nil
}

// Status is a listener's state for node status and `otsec health`.
type Status struct {
	ID        string
	Transport asset.Transport
	Address   string
	Open      bool // bound and serving
	// Connections is the number of open stream connections;
	// UnknownConnections counts those from unknown senders.
	Connections, UnknownConnections int
	// Received counts messages read off the wire; Stored counts those
	// committed with a receipt. LastMessage is when the last was stored.
	Received, Stored int64
	LastMessage      time.Time
	// Dropped counts messages dropped, by reason (DropRateLimit,
	// DropQueueFull, DropStore, DropUnknownBudget).
	Dropped map[string]int64
	// Refused counts stream connections closed before any frame was read,
	// by reason: "limit" (MaxConns or MaxConnsPerSource), "unknown-limit"
	// (MaxUnknownConns) or "tls".
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
	tlsCfg *tls.Config

	mu       sync.Mutex
	st       Status
	held     int
	perSrc   map[netip.Addr]int
	budget   bucket    // unknown senders' record bytes
	budgetAt time.Time // when HealthUnknownBudget was last raised
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
			return bad("%s is plaintext; it runs only when the operator enables plaintext for this listener", cfg.Transport)
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
		cfg: cfg, lim: lim, limit: newLimiter(lim), tlsCfg: cfg.TLS,
		perSrc: map[netip.Addr]int{}, unknown: map[netip.Addr]bool{}, reported: map[string]int64{},
		budget: bucket{tokens: float64(lim.UnknownBytes)},
		st:     Status{ID: cfg.ID, Transport: cfg.Transport, Address: cfg.Address, Dropped: map[string]int64{}, Refused: map[string]int64{}},
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

// Close releases a bound listener that will not be served, for a node that
// cannot start all its listeners. It is not for stopping one: a serving
// listener stops when Serve's context ends, and Close refuses it. Serve
// after Close returns an error; Close twice is a no-op.
func (r *Receiver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.st.Open {
		return fmt.Errorf("receive: listener %s is serving; end Serve's context to stop it", r.cfg.ID)
	}
	var err error
	if r.ln != nil {
		err = r.ln.Close()
	}
	if r.pc != nil {
		err = r.pc.Close()
	}
	r.ln, r.pc = nil, nil
	return err
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

// records builds the records of a batch, one by one, and returns them with
// the messages they hold. Two kinds of message are left out, dropped and
// counted:
//
//   - one whose record cannot be built. That is a fault in this package,
//     never in the bytes (normalize.Syslog takes any bytes), and it costs
//     only that message, not the batch;
//   - an unknown sender's message past the unknown budget, so unattributed
//     traffic never takes the storage configured devices' events need.
func (r *Receiver) records(ctx context.Context, ms []msg) ([]store.Record, []msg) {
	recs := make([]store.Record, 0, len(ms))
	kept := ms[:0:0]
	var faults, over int64
	for _, m := range ms {
		rec, err := r.record(m)
		if err != nil {
			faults++
			r.update(func(s *Status) { s.LastErr = "record from " + m.from.String() + ": " + err.Error() })
			continue
		}
		if _, known := r.cfg.Senders[m.from]; !known && !r.spend(len(rec.Event)) {
			over++
			continue
		}
		recs = append(recs, rec)
		kept = append(kept, m)
	}
	if faults > 0 {
		r.drop(DropStore, faults)
	}
	if over > 0 {
		r.drop(DropUnknownBudget, over)
		r.alarmBudget(ctx)
	}
	return recs, kept
}

// spend takes n bytes from the unknown senders' budget and reports whether
// they were there.
func (r *Receiver) spend(n int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	size := float64(r.lim.UnknownBytes)
	r.budget.refill(time.Now(), size/r.lim.UnknownWindow.Seconds(), size)
	if r.budget.tokens < float64(n) {
		return false
	}
	r.budget.tokens -= float64(n)
	return true
}

// alarmBudget raises HealthUnknownBudget, at most once per UnknownWindow.
// The dropped messages themselves are counted in intake.drop-counted. An
// alarm that cannot be committed is raised again at the next drop.
func (r *Receiver) alarmBudget(ctx context.Context) {
	r.mu.Lock()
	now := time.Now()
	if !r.budgetAt.IsZero() && now.Sub(r.budgetAt) < r.lim.UnknownWindow {
		r.mu.Unlock()
		return
	}
	r.budgetAt = now
	r.mu.Unlock()
	h := event.Health{Type: HealthUnknownBudget, Details: map[string]string{
		"listener": r.cfg.ID, "transport": string(r.cfg.Transport),
		"budget_bytes": strconv.FormatInt(r.lim.UnknownBytes, 10), "window": r.lim.UnknownWindow.String(),
	}}
	if _, err := r.cfg.Health.Emit(ctx, h); err != nil {
		r.mu.Lock()
		r.budgetAt = time.Time{}
		r.st.LastErr = "unknown-budget alarm: " + err.Error()
		r.mu.Unlock()
	}
}

func (r *Receiver) drop(reason string, n int64) {
	r.update(func(s *Status) { s.Dropped[reason] += n })
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
