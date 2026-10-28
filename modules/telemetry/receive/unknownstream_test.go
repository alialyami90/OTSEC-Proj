package receive

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
)

const testUnknown = store.StreamID("syslog-unknown/lab")

// streamCommitter keeps what it commits per stream, as the real store does,
// and refuses a stream's batches, having written nothing, while its refusal
// is set: CodeQuotaReached, as a full class does, or another code.
type streamCommitter struct {
	mu      sync.Mutex
	recs    map[store.StreamID][]store.Record
	refuse  map[store.StreamID]store.Code
	calls   map[store.StreamID]int
	classes map[store.StreamID]store.StreamClass
}

func newStreamCommitter() *streamCommitter {
	return &streamCommitter{recs: map[store.StreamID][]store.Record{}, refuse: map[store.StreamID]store.Code{}, calls: map[store.StreamID]int{}}
}

func (c *streamCommitter) CommitBatch(_ context.Context, stream store.StreamID, recs []store.Record) (store.Commit, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls[stream]++
	if code := c.refuse[stream]; code != "" {
		return store.Commit{}, &store.Error{Code: code, Detail: "test"}
	}
	for _, r := range recs {
		if r.Class != c.classes[stream] {
			return store.Commit{}, &store.Error{Code: store.CodeInvalid, Detail: "record of class " + string(r.Class) + " in " + string(stream)}
		}
	}
	first := store.Seq(len(c.recs[stream]) + 1)
	c.recs[stream] = append(c.recs[stream], recs...)
	return store.Commit{Node: testNode, Stream: stream, FirstSeq: first, Count: len(recs), Sync: store.SyncFull, At: time.Now()}, nil
}

func (c *streamCommitter) setRefuse(s store.StreamID, code store.Code) {
	c.mu.Lock()
	c.refuse[s] = code
	c.mu.Unlock()
}

func (c *streamCommitter) callsOn(s store.StreamID) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[s]
}

// events decodes the events committed to s, in commit order, with their
// records' streams and classes checked against the event's own.
func (c *streamCommitter) events(t testing.TB, s store.StreamID) []event.Event {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []event.Event
	for _, r := range c.recs[s] {
		var e event.Event
		if err := json.Unmarshal(r.Event, &e); err != nil {
			t.Fatal(err)
		}
		if r.Stream != s || e.ID.Stream != s {
			t.Errorf("record of stream %s, event of stream %s, committed to %s", r.Stream, e.ID.Stream, s)
		}
		out = append(out, e)
	}
	return out
}

// refusingLog refuses an unknown stream's batches, having written nothing,
// with an error of its own while on is set: a refusal that is not the quota
// and that does not stop the real Log, which a committer's error would.
type refusingLog struct {
	inner Appender
	on    atomic.Bool
}

func (l *refusingLog) AppendBatch(ctx context.Context, recs []store.Record) ([]store.Receipt, error) {
	if l.on.Load() && recs[0].Class == store.ClassSyslogUnknown {
		return nil, &store.Error{Code: store.CodeInvalid, Detail: "test refusal"}
	}
	return l.inner.AppendBatch(ctx, recs)
}

// unknownRig is a rig with Config.UnknownStream set, over a stream-aware
// committer behind a real store.Log. addrB is the unknown sender.
func unknownRig(t *testing.T, transport asset.Transport, mut func(*Config)) (*rig, *streamCommitter) {
	t.Helper()
	sc := newStreamCommitter()
	known := store.ClassSyslogStream
	if transport == asset.SyslogUDP {
		known = store.ClassSyslogDatagram
	}
	sc.classes = map[store.StreamID]store.StreamClass{testStream: known, testUnknown: store.ClassSyslogUnknown}
	log, err := store.NewLog(sc, testNode, sc.classes, store.GroupOptions{MaxEvents: 100, MaxWait: 5 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	g := newRig(t, transport, func(c *Config) {
		onlyA(c)
		c.Log = log
		c.UnknownStream = testUnknown
		if mut != nil {
			mut(c)
		}
	})
	return g, sc
}

func assetOf(e event.Event) string {
	if e.Source.Asset == nil {
		return ""
	}
	return e.Source.Asset.ID
}

// TestUnknownDatagramsGoToTheUnknownStream (HR-11): a known sender's
// datagrams are stored in the listener's stream and an unknown sender's in
// the unknown stream, each in its order, whatever the order they arrive in.
func TestUnknownDatagramsGoToTheUnknownStream(t *testing.T) {
	g, sc := unknownRig(t, asset.SyslogUDP, nil)
	a, b := g.udp(addrA), g.udp(addrB)
	defer a.Close()
	defer b.Close()
	want := map[string][]string{"A": nil, "B": nil}
	for i, m := range bigMsgs(40, 20) {
		c, k := a, "A"
		if i%3 == 0 {
			c, k = b, "B"
		}
		if _, err := c.Write([]byte(m)); err != nil {
			t.Fatal(err)
		}
		want[k] = append(want[k], m)
		time.Sleep(time.Millisecond)
	}
	g.wait("read", func() bool { return g.r.Status().Received == 40 })
	g.settled()
	if s := g.r.Status(); s.Stored != 40 || len(s.Dropped) != 0 {
		t.Fatalf("status %+v", s)
	}
	ks, us := sc.events(t, testStream), sc.events(t, testUnknown)
	if len(ks) != len(want["A"]) || len(us) != len(want["B"]) {
		t.Fatalf("known %d, unknown %d; want %d and %d", len(ks), len(us), len(want["A"]), len(want["B"]))
	}
	for _, e := range ks {
		if assetOf(e) != assetA {
			t.Errorf("known stream holds %+v", e.Source)
		}
	}
	for _, e := range us {
		if assetOf(e) != "" || !hasFlag(e, "asset-unresolved") {
			t.Errorf("unknown stream holds %+v", e.Source)
		}
	}
	if got := msgs(t, ks); strings.Join(got, "\n") != strings.Join(want["A"], "\n") {
		t.Error("the known stream is out of order")
	}
	if got := msgs(t, us); strings.Join(got, "\n") != strings.Join(want["B"], "\n") {
		t.Error("the unknown stream is out of order")
	}
	// The first message from the unknown sender raised the alarm, relating to
	// its record in the unknown stream.
	hs := g.health.of(HealthUnknownSource)
	if len(hs) != 1 || len(hs[0].Related) != 1 || hs[0].Related[0].Stream != testUnknown {
		t.Errorf("unknown-source alarms %+v", hs)
	}
}

func hasFlag(e event.Event, f string) bool {
	for _, x := range e.Flags {
		if string(x) == f {
			return true
		}
	}
	return false
}

// TestUnknownDatagramsDroppedAtTheClassQuota (HR-11): with the class full the
// unknown sender's datagrams are dropped and counted as unknown-full, and the
// known sender's are stored as before.
func TestUnknownDatagramsDroppedAtTheClassQuota(t *testing.T) {
	g, sc := unknownRig(t, asset.SyslogUDP, nil)
	sc.setRefuse(testUnknown, store.CodeQuotaReached)
	a, b := g.udp(addrA), g.udp(addrB)
	defer a.Close()
	defer b.Close()
	for i, m := range bigMsgs(30, 20) {
		c := a
		if i%2 == 0 {
			c = b
		}
		c.Write([]byte(m))
		time.Sleep(time.Millisecond)
	}
	g.wait("read", func() bool { return g.r.Status().Received == 30 })
	g.settled()
	s := g.r.Status()
	if s.Stored != 15 || s.Dropped[DropUnknownFull] != 15 || s.Dropped[DropStore] != 0 {
		t.Errorf("status %+v", s)
	}
	if s.LastErr != "" {
		t.Errorf("a full unknown class set LastErr %q, which is for real faults", s.LastErr)
	}
	if n := len(sc.events(t, testStream)); n != 15 {
		t.Errorf("the known sender has %d stored, want 15", n)
	}
	if n := len(sc.events(t, testUnknown)); n != 0 {
		t.Errorf("the full class stored %d", n)
	}
	// The drops are reported like any other.
	g.wait("drop report", func() bool {
		for _, h := range g.health.of(event.HealthDropCounted) {
			if h.Details["reason"] == DropUnknownFull {
				return true
			}
		}
		return false
	})
}

// TestUnknownStreamIsNotHeldAtTheQuota (HR-11): an unknown sender's TCP
// connection is read on while the class is full, its messages dropped and
// counted, where a known sender's refused batch is held. Room in the class
// again, and its next message is stored.
func TestUnknownStreamIsNotHeldAtTheQuota(t *testing.T) {
	g, sc := unknownRig(t, asset.SyslogTCP, nil)
	sc.setRefuse(testUnknown, store.CodeQuotaReached)
	c := g.dial(addrB)
	defer c.Close()
	c.Write(octet(bigMsgs(10, 20)...))
	g.wait("dropped", func() bool { return g.r.Status().Dropped[DropUnknownFull] == 10 })
	if s := g.r.Status(); s.Held || s.Stored != 0 || s.Dropped[DropStore] != 0 {
		t.Errorf("status %+v", s)
	}
	// The connection is still being read.
	c.Write(octet(bigMsgs(1, 20)...))
	g.wait("dropped again", func() bool { return g.r.Status().Dropped[DropUnknownFull] == 11 })
	sc.setRefuse(testUnknown, "")
	c.Write(octet(m1))
	g.wait("stored", func() bool { return len(sc.events(t, testUnknown)) == 1 })
	if n := len(sc.events(t, testStream)); n != 0 {
		t.Errorf("the known stream holds %d", n)
	}
}

// TestKnownStreamConnectionNeverWaitsOnTheUnknownStream (HR-11): the unknown
// stream refusing everything, including with an error other than the quota,
// does not touch a known sender's connection, which makes no call on it.
func TestKnownStreamConnectionNeverWaitsOnTheUnknownStream(t *testing.T) {
	g, sc := unknownRig(t, asset.SyslogTCP, nil)
	sc.setRefuse(testUnknown, store.CodeLogStopped)
	c := g.dial(addrA)
	defer c.Close()
	c.Write(octet(m1, m2))
	g.wait("known stored", func() bool { return len(sc.events(t, testStream)) == 2 })
	if n := sc.callsOn(testUnknown); n != 0 {
		t.Errorf("%d calls on the unknown stream from a known sender", n)
	}
	if g.r.Status().Held {
		t.Error("held")
	}
}

// TestUnknownStreamOtherRefusalIsHeldOnAStream: only the quota drops. Any other
// refusal of an unknown sender's batch on a stream is held and retried, as a
// known sender's is, and the messages are stored once it clears.
func TestUnknownStreamOtherRefusalIsHeldOnAStream(t *testing.T) {
	var rl *refusingLog
	g, sc := unknownRig(t, asset.SyslogTCP, func(c *Config) {
		rl = &refusingLog{inner: c.Log}
		rl.on.Store(true)
		c.Log = rl
	})
	c := g.dial(addrB)
	defer c.Close()
	c.Write(octet(m1))
	g.wait("held", func() bool { return g.r.Status().Held })
	if d := g.r.Status().Dropped; len(d) != 0 {
		t.Errorf("dropped %v", d)
	}
	rl.on.Store(false)
	g.wait("stored", func() bool { return len(sc.events(t, testUnknown)) == 1 })
}

// TestUnknownDatagramOtherRefusalIsCountedAsStore: a datagram part refused for
// a reason other than the quota is dropped as store, as for a known sender.
func TestUnknownDatagramOtherRefusalIsCountedAsStore(t *testing.T) {
	g, _ := unknownRig(t, asset.SyslogUDP, func(c *Config) {
		rl := &refusingLog{inner: c.Log}
		rl.on.Store(true)
		c.Log = rl
	})
	b := g.udp(addrB)
	defer b.Close()
	b.Write([]byte(m1))
	g.wait("read", func() bool { return g.r.Status().Received == 1 })
	g.settled()
	if s := g.r.Status(); s.Dropped[DropStore] != 1 || s.Dropped[DropUnknownFull] != 0 {
		t.Errorf("status %+v", s)
	}
}

// TestUnknownStreamPartsStillSplit: the commit caps apply to the unknown
// stream's parts as to the known stream's.
func TestUnknownStreamPartsStillSplit(t *testing.T) {
	g, sc := unknownRig(t, asset.SyslogTCP, func(c *Config) { c.MaxCommitRecords = 3 })
	c := g.dial(addrB)
	defer c.Close()
	c.Write(octet(bigMsgs(10, 20)...))
	g.wait("stored", func() bool { return len(sc.events(t, testUnknown)) == 10 })
	// 10 records in at most 3 per call: at least 4 calls.
	if n := sc.callsOn(testUnknown); n < 4 {
		t.Errorf("%d calls for 10 records at a cap of 3", n)
	}
}

// TestNewRefusesBadUnknownStream: the unknown stream must be a valid stream
// other than the listener's own.
func TestNewRefusesBadUnknownStream(t *testing.T) {
	base := func(u store.StreamID) error {
		_, err := New(Config{
			Node: testNode, ID: "lab", Stream: testStream, UnknownStream: u, Transport: asset.SyslogTCP, Address: "127.0.0.1:0",
			Target: asset.Simulated, Plaintext: true, Senders: testSenders(),
			Log: &tapLog{}, Health: &sink{}, Received: received,
		})
		return err
	}
	if err := base(testUnknown); err != nil {
		t.Errorf("a valid unknown stream: %v", err)
	}
	for _, u := range []store.StreamID{testStream, "not a stream", "../x"} {
		if err := base(u); err == nil || !strings.Contains(err.Error(), "unknown stream") {
			t.Errorf("unknown stream %q: %v", u, err)
		}
	}
}

// TestUnknownFloodCannotTakeTheKnownQueuePlaces (HR-11): with the store held,
// an unknown sender's datagrams hold at most half the queue's places, so a
// known sender's datagrams still queue and are all stored once the store
// takes them. Without the share, the unknown flood fills the queue and the
// known sender's datagrams are dropped as queue-full (the same drop, with a
// slow disk, as B6 saw on hosted Windows in #316).
func TestUnknownFloodCannotTakeTheKnownQueuePlaces(t *testing.T) {
	const queue, knownN, unknownN = 200, 100, 400
	tap := &tapLog{gate: make(chan struct{})}
	g, sc := unknownRig(t, asset.SyslogUDP, func(c *Config) {
		c.Limits.Queue = queue
		c.Limits.UnknownBytes = 64 << 20
		c.Limits.Rate, c.Limits.Burst, c.Limits.UnknownRate, c.Limits.UnknownBurst = 100000, 100000, 100000, 100000
		tap.inner = c.Log
		c.Log = tap
	})
	a, b := g.udp(addrA), g.udp(addrB)
	defer a.Close()
	defer b.Close()
	// The first datagram goes alone, so the writer takes it and then waits
	// at the gate for the store; everything after it queues.
	a.Write([]byte(m1))
	g.wait("first read", func() bool { return g.r.Status().Received == 1 })
	time.Sleep(50 * time.Millisecond)
	sent := 1
	for i := 0; i < unknownN; i++ {
		b.Write([]byte(fmt.Sprintf("<13>unknown %03d", i)))
		sent++
		if i%4 == 0 && i/4 < knownN-1 {
			a.Write([]byte(fmt.Sprintf("<13>device %03d", i/4)))
			sent++
		}
		if i%20 == 19 {
			time.Sleep(2 * time.Millisecond)
		}
	}
	g.wait("all read", func() bool { return g.r.Status().Received == int64(sent) })
	close(tap.gate)
	g.settled()
	s := g.r.Status()
	if s.Stored+sumDropped(s) != s.Received {
		t.Fatalf("accounting %+v", s)
	}
	if known := len(sc.events(t, testStream)); known != knownN {
		t.Errorf("the known sender has %d of %d stored; status %+v", known, knownN, s)
	}
	if s.Dropped[DropQueueFull] == 0 {
		t.Errorf("no unknown datagram was dropped for the queue: the test did not fill it; status %+v", s)
	}
}

func sumDropped(s Status) (n int64) {
	for _, d := range s.Dropped {
		n += d
	}
	return n
}
