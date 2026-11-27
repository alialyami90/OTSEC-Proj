package sensorlink

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

// C13 0.2 and 0.3 fixtures for the intake, desk only: no sensor produced
// them and no device was contacted.
const (
	testDigest  = "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	otherDigest = "sha256:1f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	testRun2    = "1c9e4c6d-1a2f-4e3b-8c7d-5f6a7b8c9d0f"
	otherSensor = "7a1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f8"
)

func z() *uint64 { return ptr(uint64(0)) }

func coverage02() netobs.Coverage {
	cv := coverage()
	cv.ConfigDigest, cv.Settings.PRPWindowMS = testDigest, netobs.DefaultPRPWindowMS
	return cv
}

// obs02 is a flow start of the 0.2 channel, from master to relay.
func obs02(seq int) *netobs.Observation {
	o := flow(seq, "192.0.2.10", "192.0.2.20")
	o.Schema, o.MadeUTC, o.Coverage = netobs.Identifier02, "2026-11-07T10:00:00.200000Z", coverage02()
	return o
}

func obs03(seq int) *netobs.Observation {
	o := obs02(seq)
	o.Schema = netobs.Identifier03
	return o
}

func agent02() *netobs.Agent {
	return &netobs.Agent{Closes: netobs.AgentCloses{Handshake: z(), NodeHello: z(), NodeHelloTimeout: z(), Binding: z(), Ack: z(),
		Type: z(), Idle: z(), FrameTooLarge: z(), Superseded: z(), RunComplete: z(), Shutdown: z()},
		TakenAhead: z(), SyncLate: z(), EntriesUnreadable: z()}
}

func heartbeat02(seq int, packets uint64) *netobs.Heartbeat {
	h := heartbeat(seq, packets)
	h.Schema, h.Coverage = netobs.Identifier02, coverage02()
	h.Counters.DropsDriver = z()
	for _, x := range []**uint64{&h.Counters.DropsHolder, &h.Counters.FramesOverlong, &h.Counters.FramesOutgoing,
		&h.Counters.PRPMismatched, &h.Counters.PRPTableFull, &h.Counters.PRPTagDiffers, &h.Counters.PRPWrongLAN,
		&h.Counters.EngineLinesRefused} {
		*x = z()
	}
	h.RingOldestUTC = "2026-11-07T09:00:00.000000Z"
	h.Interfaces = []netobs.InterfaceCount{{Name: "eth1", Carrier: "up", Packets: packets}}
	h.Agent, h.EgressCheck = agent02(), "ok"
	return h
}

// hello02 offers testRun as run 5 of generation 2, from first_seq 1.
func hello02() *netobs.SensorHello {
	return &netobs.SensorHello{Schema: netobs.Identifier02, Type: netobs.TypeSensorHello, SensorID: testSensor, Generation: "2",
		RunCounter: "5", RunID: testRun, Current: ptr(true), FirstSeq: "1", NewestSeq: "20", DropsChannel: "0",
		Lost: []netobs.Span{}, Prior: prior(), PinnedBy: "signature", ConfigDigest: testDigest, BufferBytes: "2147483648",
		SensorUTC: "2026-11-07T10:00:00Z"}
}

func prior() *netobs.Prior {
	return &netobs.Prior{RunsSkipped: "4", RecordsLost: "0", Lost: []netobs.Span{}, PreviousEnd: "clean", StartedBy: "agent"}
}

func tick02(newest, sent, drops int) *netobs.Tick {
	return &netobs.Tick{Schema: netobs.Identifier02, Type: netobs.TypeTick, SensorID: testSensor, RunID: testRun,
		SensorUTC: "2026-11-07T10:00:10Z", NewestSeq: strconv.Itoa(newest), SentSeq: strconv.Itoa(sent),
		DropsChannel: strconv.Itoa(drops), Lost: []netobs.Span{}, BufferedRecords: "0", BufferedBytes: "0"}
}

func lspan(from, to string) netobs.Span {
	return netobs.Span{FromUTC: "2026-11-07T" + from + "Z", ToUTC: "2026-11-07T" + to + "Z"}
}

// enrolment is generation 2 of testSensor, its position begun at 1.
func enrolment() Enrolment {
	return Enrolment{SensorID: testSensor, Generation: 2, Began: 1, ConfigDigest: testDigest}
}

// memPins is sensors.json's pinned_by, kept across a restart by sharing it.
type memPins struct {
	mu   sync.Mutex
	m    map[uint64]string
	fail bool
}

func newPins() *memPins { return &memPins{m: map[uint64]string{}} }

func (p *memPins) PinnedBy(g uint64) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.m[g], nil
}

func (p *memPins) KeepPinnedBy(g uint64, v string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return errors.New("test: pins not kept")
	}
	p.m[g] = v
	return nil
}

// cursorStore is the observation stream's source cursor in the test's
// network database; failSave makes the next saves on their own fail.
type cursorStore struct {
	s        netStore
	mu       sync.Mutex
	failSave int
}

func (c *cursorStore) SourceCursor(ctx context.Context) ([]byte, error) {
	defer timed(c.s.name, time.Now())
	return c.s.db.SourceCursor(ctx, obsStream)
}

func (c *cursorStore) SaveSourceCursor(ctx context.Context, b []byte) error {
	c.mu.Lock()
	if c.failSave > 0 {
		c.failSave--
		c.mu.Unlock()
		return errors.New("test: the save failed")
	}
	c.mu.Unlock()
	defer timed(c.s.name, time.Now())
	return c.s.db.SaveSourceCursor(ctx, obsStream, b)
}

func (c *cursorStore) failNext(n int) {
	c.mu.Lock()
	c.failSave = n
	c.mu.Unlock()
}

// cursorNow reads the saved cursor.
func cursorNow(t *testing.T, cs *cursorStore) *Cursor {
	t.Helper()
	b, err := cs.SourceCursor(bg)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		return nil
	}
	c, err := decodeCursor(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// alarms records the raises.
type alarms struct {
	mu   sync.Mutex
	list []string
}

func (a *alarms) raise(name, detail string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.list = append(a.list, name+": "+detail)
}

func (a *alarms) count(name string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, s := range a.list {
		if len(s) > len(name) && s[:len(name)+1] == name+":" {
			n++
		}
	}
	return n
}

// rig is one node's link and its stores; restart makes a new link over the
// same stores, as a node restart does.
type rig struct {
	t     *testing.T
	s     netStore
	cs    *cursorStore
	pins  *memPins
	al    *alarms
	clk   *aclock
	wall  time.Time
	owed  []Owed
	owedE error
	mu    sync.Mutex
	l     *Link
	opt   func(*Options)
}

// rigIdle is the rig's idle deadline: far past any test's run, so no
// connection is closed for the runner's speed. The deadline is real time
// (conn.go's read and ack), while these tests run on the rig's clocks: at
// 10 s, a connection left open while other steps ran (a new rig, a
// restart, WriteOwed, a store's setup) was closed on a slow runner (D1's
// ruling 9 on #788; brief P4-NODE-WINTIME). A test of the idle close sets
// its own deadline (conn_rows_test.go's "idle", decisionRig).
const rigIdle = time.Hour

func newRig(t *testing.T, opt func(*Options)) *rig {
	s := openNet(t, 64<<20)
	r := &rig{t: t, s: s, cs: &cursorStore{s: s}, pins: newPins(), clk: &aclock{},
		wall: time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC), opt: opt}
	r.restart()
	return r
}

func (r *rig) restart() *Link {
	r.t.Helper()
	r.al = &alarms{}
	o := Options{Assets: testAssets(), Store: r.s, Monotonic: r.clk.mono, Received: received, Cursor: r.cs, Pins: r.pins,
		Now: r.now, Raise: r.al.raise,
		Owed: func(_ context.Context, w Owed) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.owedE != nil {
				return r.owedE
			}
			r.owed = append(r.owed, w)
			return nil
		},
		Timeouts: ConnTimeouts{Hello: 10 * time.Second, Idle: rigIdle}}
	if r.opt != nil {
		r.opt(&o)
	}
	l, err := New(Config{NodeID: testNode, SensorID: testSensor, EvidenceClass: asset.Simulated, OutageHours: 1,
		ObservationQuota: 64 << 20, Stream: obsStream}, o)
	if err != nil {
		r.t.Fatal(err)
	}
	r.l = l
	return l
}

// now and addWall are the node's wall clock, moved by the test.
func (r *rig) now() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.wall
}

func (r *rig) addWall(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.wall = r.wall.Add(d)
}

// peer is the test source's end of one connection: it sends frames and
// reads the node's acks.
type peer struct {
	t    *testing.T
	c    net.Conn
	acks chan *netobs.Ack
	done chan string
	l    *Link
	sent uint64 // frames sent on this connection
	base uint64 // the link's frame count before it
}

// dial hands the link a connection, as P4-4-DE's dialer will, and serves
// it under en.
func (r *rig) dial(en Enrolment) *peer { return r.dialCtx(bg, en) }

// dialCtx is dial with the node's context ctx.
func (r *rig) dialCtx(ctx context.Context, en Enrolment) *peer {
	return r.dialWrap(ctx, en, func(c Conn) Conn { return c })
}

// dialWrap is dialCtx with the node's end of the pipe wrapped.
func (r *rig) dialWrap(ctx context.Context, en Enrolment, wrap func(Conn) Conn) *peer {
	a, b := net.Pipe()
	l := r.l
	p := &peer{t: r.t, c: a, acks: make(chan *netobs.Ack, 1024), done: make(chan string, 1), l: l, base: l.ConnStats().Frames}
	go func() { p.done <- l.ServeConn(ctx, wrap(b), en) }()
	go func() {
		defer close(p.acks)
		for {
			f, err := netobs.ReadFrame(a)
			if err != nil {
				return
			}
			m, err := netobs.DecodeFromNode(f)
			if err != nil || m.Ack == nil {
				r.t.Errorf("the node sent a frame that is not an ack: %v %s", err, f)
				return
			}
			p.acks <- m.Ack
		}
	}()
	r.t.Cleanup(func() { a.Close() })
	return p
}

func (p *peer) send(vs ...any) {
	p.t.Helper()
	for _, v := range vs {
		b, ok := v.([]byte)
		if !ok {
			var err error
			if b, err = json.Marshal(v); err != nil {
				p.t.Fatal(err)
			}
		}
		if err := netobs.WriteFrame(p.c, b); err != nil {
			p.t.Fatalf("send: %v", err)
		}
		p.sent++
	}
}

// waitBound is how long a wait for the link's progress waits before it
// fails: until a minute before the test binary's -timeout, and never less
// than 20 s. The wait is real time, since the link acts on a frame in its
// own goroutine and no clock of the rig moves it, and a store commit can
// stall for longer than 20 s on a loaded disk (F-016 saw 37.9 s on the
// hosted Windows runner; on the owner's PC during #802, "the link acted on
// 0 of 1 frames"). So a slow commit is waited out, and a link that never
// acts still fails here, by name, before the binary's timeout prints its
// stacks (brief P4-NODE-WINTIME).
func waitBound(t *testing.T) time.Duration {
	d := 10 * time.Minute
	if end, ok := t.Deadline(); ok {
		d = time.Until(end) - time.Minute
	}
	return max(d, 20*time.Second)
}

// taken waits until the link has acted on every frame sent.
func (p *peer) taken() {
	p.t.Helper()
	deadline := time.Now().Add(waitBound(p.t))
	for p.l.ConnStats().Frames-p.base < p.sent {
		if time.Now().After(deadline) {
			p.t.Fatalf("the link acted on %d of %d frames", p.l.ConnStats().Frames-p.base, p.sent)
		}
		time.Sleep(time.Millisecond)
	}
}

// ack waits for an ack of seq; a lower one is skipped, a higher one
// fails.
func (p *peer) ack(seq uint64) {
	p.t.Helper()
	deadline := time.After(waitBound(p.t))
	for {
		select {
		case a, ok := <-p.acks:
			if !ok {
				p.t.Fatalf("the connection closed before an ack of %d", seq)
			}
			switch n := num(a.Seq); {
			case n == seq:
				return
			case n > seq:
				p.t.Fatalf("ack %d, want %d", n, seq)
			}
		case <-deadline:
			p.t.Fatalf("no ack of %d", seq)
		}
	}
}

// ackAtLeast waits for an ack at or above seq.
func (p *peer) ackAtLeast(seq uint64) {
	p.t.Helper()
	deadline := time.After(waitBound(p.t))
	for {
		select {
		case a, ok := <-p.acks:
			if !ok {
				p.t.Fatalf("the connection closed before an ack of %d", seq)
			}
			if num(a.Seq) >= seq {
				return
			}
		case <-deadline:
			p.t.Fatalf("no ack of %d", seq)
		}
	}
}

// closed waits for the node's close reason.
func (p *peer) closed() string {
	p.t.Helper()
	select {
	case r := <-p.done:
		return r
	case <-time.After(waitBound(p.t)):
		p.t.Fatal("the node did not close the connection")
		return ""
	}
}

// end ends the stream from the sensor's side and returns the node's reason.
func (p *peer) end() string {
	p.t.Helper()
	p.c.Close()
	return p.closed()
}

// open asserts the connection is still open: a heartbeat-free probe, a
// tick that changes nothing, is read and the link answers nothing new.
func (p *peer) stillOpen() {
	p.t.Helper()
	select {
	case r := <-p.done:
		p.t.Fatalf("the connection closed: %q", r)
	default:
	}
}

// storedObs reads the stored observations back.
func storedObs(t *testing.T, s netStore) []*netobs.Observation {
	t.Helper()
	var out []*netobs.Observation
	for _, st := range stored(t, s) {
		var e event.Event
		if err := json.Unmarshal(st.Event, &e); err != nil {
			t.Fatal(err)
		}
		o, err := netobs.ObservationFromEvent(&e)
		if err != nil {
			t.Fatalf("stored record: %v", err)
		}
		out = append(out, o)
	}
	return out
}

// settle waits until the link has taken n records' outcomes (committed,
// refused or dropped), observed through its counts.
func settle(t *testing.T, l *Link, want func(Stats) bool) {
	t.Helper()
	deadline := time.Now().Add(waitBound(t))
	for time.Now().Before(deadline) {
		if want(l.Stats()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the link did not reach the state: %+v", l.Stats())
}

func refused(l *Link, reason string) uint64 { return l.Stats().Refused[reason] }

func closes(l *Link, reason string) uint64 { return l.ConnStats().Closes[reason] }

// aclock is the test's monotonic clock, safe to move while the link reads
// it. A hold armed by holdNext stops the next reader after its reading.
type aclock struct {
	n    atomic.Int64
	hold atomic.Pointer[clockHold]
}

// clockHold is one reader held: reached is closed when it has read, and it
// returns once release is closed. in, when set, holds only a read made
// directly by the function whose name ends in it.
type clockHold struct {
	reached, release chan struct{}
	in               string
}

func (c *aclock) mono() time.Duration {
	v := time.Hour + time.Duration(c.n.Load())
	if h := c.hold.Load(); h != nil && (h.in == "" || readBy(h.in)) && c.hold.CompareAndSwap(h, nil) {
		close(h.reached)
		<-h.release
	}
	return v
}

// readBy reports whether the clock's reader, the first caller outside
// aclock (D6's probes on #774 name a reader so), ends in fn.
func readBy(fn string) bool {
	pc := make([]uintptr, 8)
	fr := runtime.CallersFrames(pc[:runtime.Callers(3, pc)])
	for {
		f, more := fr.Next()
		if !strings.Contains(f.Function, "aclock") {
			return strings.HasSuffix(f.Function, fn)
		}
		if !more {
			return false
		}
	}
}

func (c *aclock) add(d time.Duration) { c.n.Add(int64(d)) }

// holdNext arms a hold for the next reader of the clock.
func (c *aclock) holdNext() *clockHold { return c.holdIn("") }

// holdIn arms a hold for the next read made directly by fn.
func (c *aclock) holdIn(fn string) *clockHold {
	h := &clockHold{reached: make(chan struct{}), release: make(chan struct{}), in: fn}
	c.hold.Store(h)
	return h
}
