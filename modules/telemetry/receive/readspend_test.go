package receive

import (
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
)

// The edge record of #178 (A6 on Windows): read before the window, spent
// inside it. The node counts what unknown senders stored by received time
// (Config.UnknownSpent); spent in the writer, a record read before the
// window and committed inside it fell out of that count, and a restart then
// started with more than the uninterrupted bucket held. Here the clock is
// the test's: records are read at 0, the store commits them a window and a
// second later, and the budget a restart would start with must not exceed
// what the running listener holds.
func TestSpentWhenRead(t *testing.T) {
	const window = 10 * time.Second
	at := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return at }
	cfg := withSpent(0)
	cfg.Limits.UnknownWindow = window
	cfg.Received = func() event.Received {
		return event.Received{UTC: clock().Format("2006-01-02T15:04:05.000000Z"), ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}}
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	size := r.lim.UnknownBytes
	r.now, r.budget = clock, startBudget(size, 0, at)
	stranger := netip.MustParseAddr("192.0.2.9")
	one := func() msg {
		return msg{frame: frame{msg: []byte(unknownMsg)}, from: stranger, auth: event.AuthNone, rcv: cfg.Received()}
	}
	probe, err := r.record(one())
	if err != nil {
		t.Fatal(err)
	}
	n := int(size)/len(probe.Event) + 3
	var read []msg
	for range n {
		m := one()
		if r.payUnknown(&m) {
			read = append(read, m)
		}
	}
	if len(read) == 0 {
		t.Fatal("no unknown message paid for from a full budget")
	}
	if d := r.Status().Dropped[DropUnknownBudget]; len(read) == n || d != int64(n-len(read)) {
		t.Errorf("%d of %d paid for as read past a budget of %d, %d dropped as unknown-budget", len(read), n, size, d)
	}

	at = at.Add(window + time.Second)
	recs, _ := r.records(read)
	var spent, stored int64
	for _, rec := range recs {
		var e struct {
			Received struct {
				UTC string `json:"utc"`
			} `json:"received"`
		}
		if err := json.Unmarshal(rec.Event, &e); err != nil {
			t.Fatal(err)
		}
		ts, err := time.Parse(time.RFC3339Nano, e.Received.UTC)
		if err != nil {
			t.Fatal(err)
		}
		stored += int64(len(rec.Event))
		if ts.After(at.Add(-window)) {
			spent += int64(len(rec.Event))
		}
	}
	restarted := startBudget(size, spent, at).tokens
	r.spend(0)
	r.mu.Lock()
	live := r.budget.tokens
	r.mu.Unlock()
	if stored == 0 || stored > size || restarted > live {
		t.Errorf("stored %d of a budget of %d, read at 0 and committed at %v: a restart now starts with %.0f, the running listener holds %.0f",
			stored, size, window+time.Second, restarted, live)
	}
}

// An unknown sender's messages past the budget are dropped as they are
// read, while the store holds the writer, so they take no queue room: a
// known sender's datagram sent after them is still queued and stored. When
// they were spent in the writer, they filled the queue on a slow store and
// the known sender's datagrams were dropped as queue-full (A6's 20 s marker
// stall on Windows).
func TestUnknownPastBudgetTakesNoQueueRoom(t *testing.T) {
	var bl *blockingLog
	g := newRig(t, asset.SyslogUDP, func(c *Config) {
		onlyA(c)
		bl = &blockingLog{Appender: c.Log, entered: make(chan struct{}, 1), release: make(chan struct{})}
		c.Log = bl
		c.Limits.Queue, c.Limits.UnknownBytes, c.Limits.UnknownWindow = 64, minUnknownBytes, time.Hour
	})
	release := sync.OnceFunc(func() { close(bl.release) })
	t.Cleanup(release)
	flood := g.udp(addrB)
	defer flood.Close()
	flood.Write([]byte(unknownMsg))
	<-bl.entered
	// Past the budget, and past the queue's 64 had they been queued. Sent
	// until counted, since a datagram can be lost before the read (UDP).
	for end := time.Now().Add(20 * time.Second); g.r.Status().Dropped[DropUnknownBudget] < 100; time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("unknown messages past the budget not dropped while the store is held; status %+v", g.r.Status())
		}
		flood.Write([]byte(unknownMsg))
	}
	known := g.udp(addrA)
	defer known.Close()
	const knownMsg = "<13>Oct 11 22:14:15 a known"
	known.Write([]byte(knownMsg))
	// Queued behind the store: the unknown messages the budget paid for,
	// every one len(unknownMsg) bytes, and the known one.
	g.wait("the known datagram queued", func() bool {
		return g.r.queued.Load()%int64(len(unknownMsg)) == int64(len(knownMsg))
	})
	if s := g.r.Status(); s.Dropped[DropQueueFull] != 0 {
		t.Errorf("queue-full drops with the queue holding only what the budget allows: %+v", s)
	}
	release()
	g.wait("the known datagram stored", func() bool {
		for _, m := range msgs(t, g.store.events(t)) {
			if m == knownMsg {
				return true
			}
		}
		return false
	})
	g.settled()
	if n, max := g.unknownBytes(), int(minUnknownBytes); n == 0 || n > max {
		t.Errorf("unknown senders stored %d bytes, budget %d", n, max)
	}
}

// On a stream too, an unknown sender's frames are paid for as read: with
// the writer held by the store on the first frame, the frames past the
// budget are dropped by the reader. Spent in the writer, none was dropped
// until the store let go, since the reader stopped at a full queue.
func TestUnknownStreamSpentWhenRead(t *testing.T) {
	var bl *blockingLog
	g := newRig(t, asset.SyslogTCP, func(c *Config) {
		onlyA(c)
		bl = &blockingLog{Appender: c.Log, entered: make(chan struct{}, 1), release: make(chan struct{})}
		c.Log = bl
		c.Limits.UnknownBytes, c.Limits.UnknownWindow = minUnknownBytes, time.Hour
	})
	release := sync.OnceFunc(func() { close(bl.release) })
	t.Cleanup(release)
	c := g.dial(addrB)
	defer c.Close()
	c.Write([]byte(unknownMsg + "\n"))
	<-bl.entered
	for range 100 {
		c.Write([]byte(unknownMsg + "\n"))
	}
	g.wait("frames past the budget dropped while the store is held", func() bool {
		return g.r.Status().Dropped[DropUnknownBudget] > 0
	})
	release()
	g.wait("all 101 read and stored or dropped", func() bool {
		s := g.r.Status()
		return s.Received == 101 && s.Stored+s.Dropped[DropUnknownBudget] == 101
	})
	if n, max := g.unknownBytes(), int(minUnknownBytes); n == 0 || n > max {
		t.Errorf("unknown senders stored %d bytes, budget %d", n, max)
	}
}
