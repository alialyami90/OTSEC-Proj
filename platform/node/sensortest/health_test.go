package sensortest

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/sensorlink"
)

// The sensor's health events against the node's own health stream
// (platform/sensorlink's Health, through Runtime.SensorHealthSink), on the
// test clock. The intake is driven through a test connection handed to an
// unwired link; F-027's gate holds. Desk only: no sensor produced the
// records.

const (
	runID  = "0b9e4c6d-1a2f-4e3b-8c7d-5f6a7b8c9d0e"
	digest = "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
)

// netLog is the sensor's observation stream in the node's network database.
type netLog struct {
	r      *node.Runtime
	stream c5.StreamID
}

func (n netLog) Append(ctx context.Context, rec c5.Record) (c5.Receipt, error) {
	return n.r.Log(n.stream).Append(ctx, rec)
}

func (n netLog) AppendBatch(ctx context.Context, recs []c5.Record) ([]c5.Receipt, error) {
	return n.r.Log(n.stream).AppendBatch(ctx, recs)
}

var errNotOpen = errors.New("test: the network database is not open")

func (n netLog) LastCommitted(ctx context.Context) (uint64, error) {
	db := n.r.Store(n.stream)
	if db == nil {
		return 0, errNotOpen
	}
	s, err := db.LastCommitted(ctx, n.stream)
	return uint64(s), err
}

func (n netLog) SourceCursor(ctx context.Context) ([]byte, error) {
	db := n.r.Store(n.stream)
	if db == nil {
		return nil, errNotOpen
	}
	return db.SourceCursor(ctx, n.stream)
}

func (n netLog) SaveSourceCursor(ctx context.Context, b []byte) error {
	db := n.r.Store(n.stream)
	if db == nil {
		return errNotOpen
	}
	return db.SaveSourceCursor(ctx, n.stream, b)
}

type pins struct {
	mu sync.Mutex
	m  map[uint64]string
}

func (p *pins) PinnedBy(g uint64) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.m[g], nil
}
func (p *pins) KeepPinnedBy(g uint64, v string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[g] = v
	return nil
}

// gate is the node's sink with the named types refused, as the ceiling
// refuses them.
type ceilingGate struct {
	sink sensorlink.HealthSink
	mu   sync.Mutex
	shut map[string]bool
}

func (g *ceilingGate) WriteHealth(ctx context.Context, typ string, d map[string]string) error {
	g.mu.Lock()
	shut := g.shut[typ]
	g.mu.Unlock()
	if shut {
		return errors.New("test: past the platform ceiling")
	}
	return g.sink.WriteHealth(ctx, typ, d)
}

func (g *ceilingGate) set(types ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.shut = map[string]bool{}
	for _, t := range types {
		g.shut[t] = true
	}
}

// linkRig is one unwired sensor link over the node's network database and
// health stream, made again at each restart over the same stores and run
// file, the node itself left running.
type linkRig struct {
	t      *testing.T
	g      *rig
	r      *node.Runtime
	sink   *ceilingGate
	pins   *pins
	path   string
	file   *sensorlink.RunFile
	h      *sensorlink.Health
	l      *sensorlink.Link
	mu     sync.Mutex
	raised []string
}

func newLinkRig(t *testing.T, g *rig, r *node.Runtime) *linkRig {
	k := &linkRig{t: t, g: g, r: r, sink: &ceilingGate{sink: r.SensorHealthSink()}, pins: &pins{m: map[uint64]string{}},
		path: filepath.Join(t.TempDir(), "sensorrun.json")}
	k.make()
	return k
}

func (k *linkRig) raise(alarm, detail string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.raised = append(k.raised, alarm+": "+detail)
}

func (k *linkRig) count(alarm string) (n int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, a := range k.raised {
		if strings.HasPrefix(a, alarm+":") {
			n++
		}
	}
	return n
}

func (k *linkRig) make() {
	k.t.Helper()
	k.raised = nil
	stream := node.NetObservationStream(sensorID)
	nl := netLog{r: k.r, stream: stream}
	k.file = sensorlink.OpenRunFile(k.path)
	k.h = sensorlink.NewHealth(sensorlink.HealthConfig{SensorID: sensorID, Sink: k.sink, Monotonic: k.g.monoNow, Now: k.g.now, Raise: k.raise, File: k.file})
	l, err := sensorlink.New(sensorlink.Config{NodeID: "site-a-node1", SensorID: sensorID, EvidenceClass: asset.Simulated, OutageHours: 1,
		ObservationQuota: 64 << 20, Stream: stream}, sensorlink.Options{Store: nl, Monotonic: k.g.monoNow, Now: k.g.now,
		Received: func() event.Received {
			return event.Received{UTC: "2026-11-13T10:00:01.000000Z", ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}}
		},
		Cursor: nl, Pins: k.pins, Raise: k.raise, Health: k.h, Timeouts: sensorlink.ConnTimeouts{Hello: 10 * time.Second, Idle: 10 * time.Second}})
	if err != nil {
		k.t.Fatal(err)
	}
	k.l = l
}

// restart makes the link again, applies the run file and writes what the
// cursor owes, as the node's start does.
func (k *linkRig) restart() {
	k.t.Helper()
	k.make()
	if err := k.file.Start(bg, k.l); err != nil {
		k.t.Fatal(err)
	}
	if err := k.l.WriteOwed(bg); err != nil && !errors.Is(err, sensorlink.ErrHealthHeld) {
		k.t.Fatal(err)
	}
}

// conn is the sensor's end of one connection.
type conn struct {
	t    *testing.T
	c    net.Conn
	done chan string
	acks chan uint64
}

func (k *linkRig) dial() *conn {
	a, b := net.Pipe()
	c := &conn{t: k.t, c: a, done: make(chan string, 1), acks: make(chan uint64, 64)}
	l := k.l
	go func() {
		c.done <- l.ServeConn(bg, b, sensorlink.Enrolment{SensorID: sensorID, Generation: 2, Began: 1, ConfigDigest: digest})
	}()
	go func() {
		for {
			f, err := netobs.ReadFrame(a)
			if err != nil {
				close(c.acks)
				return
			}
			m, err := netobs.DecodeFromNode(f)
			if err != nil || m.Ack == nil {
				return
			}
			var n uint64
			for _, ch := range m.Ack.Seq {
				n = n*10 + uint64(ch-'0')
			}
			c.acks <- n
		}
	}()
	k.t.Cleanup(func() { a.Close() })
	return c
}

func (c *conn) send(v any) {
	c.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		c.t.Fatal(err)
	}
	if err := netobs.WriteFrame(c.c, b); err != nil {
		c.t.Fatal(err)
	}
}

func (c *conn) ack(seq uint64) {
	c.t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case n, ok := <-c.acks:
			if !ok {
				c.t.Fatalf("closed before an ack of %d", seq)
			}
			if n == seq {
				return
			}
		case <-deadline:
			c.t.Fatalf("no ack of %d", seq)
		}
	}
}

func (c *conn) end() string {
	c.c.Close()
	select {
	case r := <-c.done:
		return r
	case <-time.After(20 * time.Second):
		c.t.Fatal("the node did not close the connection")
		return ""
	}
}

func z() *uint64 { v := uint64(0); return &v }

func hello(lost ...netobs.Span) *netobs.SensorHello {
	t := true
	drops := "0"
	if len(lost) > 0 {
		drops = "1"
	}
	return &netobs.SensorHello{Schema: netobs.Identifier02, Type: netobs.TypeSensorHello, SensorID: sensorID, Generation: "2",
		RunCounter: "5", RunID: runID, Current: &t, FirstSeq: "1", NewestSeq: "20", DropsChannel: drops, Lost: append([]netobs.Span{}, lost...),
		Prior:    &netobs.Prior{RunsSkipped: "0", RecordsLost: "0", Lost: []netobs.Span{}, PreviousEnd: "clean", StartedBy: "agent"},
		PinnedBy: "signature", ConfigDigest: digest, BufferBytes: "2147483648", SensorUTC: "2026-11-13T10:00:00Z"}
}

func heartbeat(seq int, driver uint64) *netobs.Heartbeat {
	cv := netobs.Coverage{SensorVersion: "0.1.0", Engine: netobs.Engine{Name: "test-engine", Version: "1"},
		Interfaces: []netobs.Interface{{Name: "eth1", Attachment: "span", LAN: "single"}},
		PRP:        netobs.PRP{LANsSeen: []string{}}, HSR: netobs.HSRNotDecoded, VLANsSeen: []int{10}, UntaggedSeen: true,
		Decodes: []string{"dnp3"}, Degraded: []string{}, ConfigDigest: digest, SinceUTC: "2026-11-13T08:00:00.000000Z",
		Settings: netobs.Settings{SAReplyTimeoutMS: netobs.DefaultSAReplyTimeoutMS, MaxPendingDNP3: netobs.DefaultMaxPendingDNP3,
			FlowIdleS: netobs.DefaultFlowIdleS, PRPWindowMS: netobs.DefaultPRPWindowMS}}
	p := uint64(100 * seq)
	return &netobs.Heartbeat{Schema: netobs.Identifier02, Type: netobs.TypeHeartbeat, SensorID: sensorID, RunID: runID,
		Seq: itoa(seq), AtUTC: "2026-11-13T10:00:10.000000Z", Coverage: cv, InterfaceCheck: "ok",
		Counters: netobs.Counters{Packets: p, Bytes: 90 * p, DropsDriver: &driver, DropsHolder: z(), FramesOverlong: z(),
			FramesOutgoing: z(), PRPMismatched: z(), PRPTableFull: z(), PRPTagDiffers: z(), PRPWrongLAN: z(), EngineLinesRefused: z()},
		RingOldestUTC: "2026-11-13T09:00:00.000000Z", Interfaces: []netobs.InterfaceCount{{Name: "eth1", Carrier: "up", Packets: p}},
		Agent: &netobs.Agent{Closes: netobs.AgentCloses{Handshake: z(), NodeHello: z(), NodeHelloTimeout: z(), Binding: z(), Ack: z(),
			Type: z(), Idle: z(), FrameTooLarge: z(), Superseded: z(), RunComplete: z(), Shutdown: z()},
			TakenAhead: z(), SyncLate: z(), EntriesUnreadable: z()}, EgressCheck: "ok"}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// healthEvents reads the node's health stream for events of typ.
func healthEvents(t *testing.T, r *node.Runtime, typ string) []*event.Event {
	t.Helper()
	got, err := r.Store(node.HealthStream).Read(bg, node.HealthStream, 0, 10000)
	if err != nil {
		t.Fatal(err)
	}
	var out []*event.Event
	for _, st := range got {
		var e event.Event
		if err := json.Unmarshal(st.Event, &e); err != nil {
			t.Fatal(err)
		}
		if e.Health != nil && e.Health.Type == typ {
			out = append(out, &e)
		}
	}
	return out
}

// S-10 (d) (C13 0.2 section 15; SL-T24 (d)): the node killed after the
// save that admits a new span and before its gap's event commits (the
// write refused, then the link made again over the same stores): after
// the restart the lost gap's event is in the node's health stream, once
// or twice, and sensor-records-lost stands. Control: a node that writes
// the gap only when it admits the span, under which the health stream
// holds none after the restart, before the start writes what the cursor
// owes.
func TestLostGapEventAfterRestart(t *testing.T) {
	g := newRig(t)
	r, _ := g.start(node.SensorSeams{})
	defer r.Close()
	k := newLinkRig(t, g, r)
	k.sink.set(sensorlink.EventCoverageGap)
	c := k.dial()
	c.send(hello(netobs.Span{FromUTC: "2026-11-13T09:00:00Z", ToUTC: "2026-11-13T09:05:00Z"}))
	c.ack(0)
	c.end()
	if n := len(healthEvents(t, r, sensorlink.EventCoverageGap)); n != 0 {
		t.Fatalf("%d gap events before the restart", n)
	}
	k.sink.set()
	k.make() // control: no start's write of what the cursor owes
	if n := len(healthEvents(t, r, sensorlink.EventCoverageGap)); n != 0 {
		t.Fatalf("control: %d gap events", n)
	}
	k.restart()
	ev := healthEvents(t, r, sensorlink.EventCoverageGap)
	if n := len(ev); n < 1 || n > 2 {
		t.Fatalf("%d gap events after the restart", n)
	}
	if d := ev[0].Health.Details; d["cause"] != "lost" || d["from_utc"] != "2026-11-13T09:00:00Z" || d["run_id"] != runID || d["covered"] != "false" {
		t.Fatalf("gap event %v", d)
	}
	if k.count(sensorlink.AlarmRecordsLost) == 0 {
		t.Fatalf("raises %v", k.raised)
	}
}

// E4-7's node leg (C4 0.4 section 3; P4-4-CC's table): a sensor.counters
// and a sensor.redial-granted held past the ceiling are kept in
// sensorrun.json as counts and facts, with no C4 event bytes; with room
// again, the events written carry the writing binary's event.Identifier.
// Control: a held event kept as built bytes, re-stamped to a later minor,
// which the node's store refuses.
func TestHeldPoolEventBuiltAtWrite(t *testing.T) {
	g := newRig(t)
	r, _ := g.start(node.SensorSeams{})
	defer r.Close()
	k := newLinkRig(t, g, r)
	k.sink.set(sensorlink.EventCounters, sensorlink.EventRedialGranted)
	c := k.dial()
	c.send(hello())
	c.ack(0)
	g.advanceMono(time.Second)
	c.send(heartbeat(1, 3))
	c.ack(1)
	k.h.Event(bg, sensorlink.EventRedialGranted, map[string]string{"generation": "2", "request_sha256": strings.Repeat("a", 64)})
	g.advanceMono(time.Minute)
	if err := k.h.Flush(bg); err == nil {
		t.Fatal("written past the ceiling")
	}
	b, err := os.ReadFile(k.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"name":"sensor.counters"`) || !strings.Contains(string(b), `"name":"sensor.redial-granted"`) {
		t.Fatalf("sensorrun.json holds %s", b)
	}
	for _, s := range []string{"otsec.event/", `"received"`, `"origin"`} {
		if strings.Contains(string(b), s) {
			t.Fatalf("event bytes (%s) in sensorrun.json: %s", s, b)
		}
	}
	k.sink.set()
	g.advanceMono(sensorlink.CountersSpacing)
	if err := k.h.Flush(bg); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{sensorlink.EventCounters, sensorlink.EventRedialGranted} {
		ev := healthEvents(t, r, typ)
		if len(ev) != 1 || ev[0].Schema != event.Identifier {
			t.Fatalf("%s: %d events, schema %v", typ, len(ev), ev)
		}
	}
	if d := healthEvents(t, r, sensorlink.EventCounters)[0].Health.Details; d["diff.drops_driver"] != "3" || d[event.DetailCaptureLoss] != "drops_driver" {
		t.Fatalf("sensor.counters %v", d)
	}
	c.end()

	// Control: the event built at its hold and kept as bytes, re-stamped
	// to a later minor (a rollback's view), is refused at its write.
	held := event.Event{Schema: "otsec.event/0.5", ID: event.EventID{NodeID: "site-a-node1", Stream: event.Stream(node.HealthStream)},
		Origin: event.OriginPlatform, Kind: event.KindHealth, Source: event.Source{OriginAuth: event.AuthPlatform},
		Received: event.Received{UTC: "2026-11-13T10:00:01.000000Z", ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}},
		Health:   &event.Health{Type: sensorlink.EventRedialGranted, Details: map[string]string{"sensor_id": sensorID}}}
	eb, err := json.Marshal(held)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Log(node.HealthStream).Append(bg, c5.Record{Stream: node.HealthStream, Class: c5.ClassPlatform, Event: eb})
	if err == nil || !strings.Contains(err.Error(), "0.5") {
		t.Fatalf("control: the store took an event of a later minor (%v); the test cannot tell", err)
	}
	t.Logf("control refused: %v", err)
}
