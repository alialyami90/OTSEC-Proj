package receive

import (
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
)

// onlyA makes addrB an unknown sender.
func onlyA(c *Config) {
	c.Senders = Senders{addrA: testSenders()[addrA]}
}

// refusedAtAccept reports whether the listener closed c without serving it.
func refusedAtAccept(c interface {
	SetReadDeadline(time.Time) error
	Read([]byte) (int, error)
}) bool {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := c.Read(make([]byte, 1))
	return err != nil && !strings.Contains(err.Error(), "timeout")
}

// TestUnknownConnsReserved (A3 F1): unknown senders cannot take more than
// MaxUnknownConns connections, so a configured device still connects when
// they hold all theirs.
func TestUnknownConnsReserved(t *testing.T) {
	g := newRig(t, asset.SyslogTCP, func(c *Config) {
		onlyA(c)
		c.Limits.MaxConns, c.Limits.MaxUnknownConns = 4, 2
	})
	for i := 0; i < 2; i++ {
		c := g.dial(addrB)
		defer c.Close()
	}
	g.wait("unknown connections held", func() bool { return g.r.Status().UnknownConnections == 2 })
	extra := g.dial(addrB)
	defer extra.Close()
	if !refusedAtAccept(extra) {
		t.Error("an unknown sender got a connection past MaxUnknownConns")
	}
	g.wait("refused", func() bool { return g.r.Status().Refused["unknown-limit"] == 1 })
	// The two connections left are the known sender's.
	for i := 0; i < 2; i++ {
		c := g.dial(addrA)
		defer c.Close()
		c.Write(octet(m1))
	}
	g.wait("known stored", func() bool { return g.store.count() == 2 })
	for _, e := range g.store.events(t) {
		if e.Source.Asset == nil || e.Source.Asset.ID != assetA {
			t.Errorf("stored %+v, want asset A", e.Source)
		}
	}
	if s := g.r.Status(); s.Connections != 4 || s.UnknownConnections != 2 || s.Refused["limit"] != 0 {
		t.Errorf("status %+v", s)
	}
}

// TestUnknownIdleShort (A3 F1): an unknown sender that sends nothing is
// closed after UnknownIdleTimeout; a known sender keeps IdleTimeout.
func TestUnknownIdleShort(t *testing.T) {
	g := newRig(t, asset.SyslogTCP, func(c *Config) {
		onlyA(c)
		c.Limits.IdleTimeout, c.Limits.UnknownIdleTimeout = time.Minute, 100*time.Millisecond
	})
	known := g.dial(addrA)
	defer known.Close()
	unknown := g.dial(addrB)
	defer unknown.Close()
	start := time.Now()
	if !refusedAtAccept(unknown) {
		t.Fatal("the idle unknown connection was not closed")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("closed after %v", d)
	}
	time.Sleep(200 * time.Millisecond)
	known.Write(octet(m1))
	g.wait("known stored", func() bool { return g.store.count() == 1 })
	g.wait("released", func() bool { return g.r.Status().UnknownConnections == 0 })
}

// unknownMsg is an RFC 3164 message about 4 KiB long.
var unknownMsg = "<34>Oct 11 22:14:15 flood app: " + strings.Repeat("x", 4000)

// settled waits until every message received is stored or dropped.
func (g *rig) settled() {
	g.t.Helper()
	g.wait("settled", func() bool {
		s := g.r.Status()
		n := s.Stored
		for _, d := range s.Dropped {
			n += d
		}
		return n == s.Received
	})
}

// unknownBytes sums the record bytes stored for unknown senders.
func (g *rig) unknownBytes() int {
	g.store.mu.Lock()
	defer g.store.mu.Unlock()
	n := 0
	for _, r := range g.store.recs {
		if strings.Contains(string(r.Event), `"asset-unresolved"`) {
			n += len(r.Event)
		}
	}
	return n
}

// TestUnknownBudgetDatagrams (A3 F2): an unknown flood stores no more than
// its budget and is then dropped and counted, with one alarm, so a store
// whose quota is only a little above the budget still takes a known
// sender's datagrams.
func TestUnknownBudgetDatagrams(t *testing.T) {
	const budget = minUnknownBytes
	g := newRig(t, asset.SyslogUDP, func(c *Config) {
		onlyA(c)
		c.Limits.UnknownBytes = budget
	})
	g.store.setQuota(budget + 32<<10)
	flood := g.udp(addrB)
	defer flood.Close()
	deadline := time.Now().Add(5 * time.Second)
	for g.r.Status().Dropped[DropUnknownBudget] < 10 {
		if time.Now().After(deadline) {
			t.Fatalf("budget never spent; status %+v", g.r.Status())
		}
		flood.Write([]byte(unknownMsg))
		time.Sleep(time.Millisecond)
	}
	g.settled()
	if n := g.unknownBytes(); n == 0 || n > budget {
		t.Errorf("unknown senders stored %d bytes, budget %d", n, budget)
	}
	before := g.store.count()
	known := g.udp(addrA)
	defer known.Close()
	for i := 0; i < 10; i++ {
		known.Write([]byte(m2))
		time.Sleep(time.Millisecond)
	}
	g.wait("known stored", func() bool { return g.store.count() == before+10 })
	for _, e := range g.store.events(t)[before:] {
		if e.Source.Asset == nil || e.Source.Asset.ID != assetA {
			t.Errorf("stored %+v, want asset A", e.Source)
		}
	}
	s := g.r.Status()
	if s.Dropped[DropStore] != 0 || s.Dropped[DropRateLimit] != 0 {
		t.Errorf("dropped %v: only unknown-budget drops expected", s.Dropped)
	}
	g.wait("drops reported", func() bool {
		for _, h := range g.health.of(event.HealthDropCounted) {
			if h.Details["reason"] == DropUnknownBudget {
				return true
			}
		}
		return false
	})
	if hs := g.health.of(HealthUnknownBudget); len(hs) != 1 || hs[0].Details["budget_bytes"] != "262144" {
		t.Errorf("budget alarms %+v, want one", hs)
	}
}

// TestUnknownBudgetStream (A3 F2): on a stream, an unknown sender's
// messages past the budget are dropped and counted, the connection is still
// read, the drops are reported, and a known sender's stream is stored.
func TestUnknownBudgetStream(t *testing.T) {
	const budget = minUnknownBytes
	g := newRig(t, asset.SyslogTCP, func(c *Config) {
		onlyA(c)
		c.Limits.UnknownBytes = budget
	})
	g.store.setQuota(budget + 32<<10)
	flood := g.dial(addrB)
	defer flood.Close()
	frames := make([]string, 100)
	for i := range frames {
		frames[i] = unknownMsg
	}
	flood.Write(octet(frames...))
	g.wait("flood read", func() bool { return g.r.Status().Received == 100 })
	g.settled()
	if s := g.r.Status(); s.Dropped[DropUnknownBudget] == 0 || s.Held {
		t.Errorf("status %+v", s)
	}
	if n := g.unknownBytes(); n > budget {
		t.Errorf("unknown senders stored %d bytes, budget %d", n, budget)
	}
	before := g.store.count()
	known := g.dial(addrA)
	defer known.Close()
	known.Write(octet(m1, m2))
	g.wait("known stored", func() bool { return g.store.count() == before+2 })
	g.wait("drops reported", func() bool {
		for _, h := range g.health.of(event.HealthDropCounted) {
			if h.Details["reason"] == DropUnknownBudget {
				return true
			}
		}
		return false
	})
}

// TestUnknownBudgetAlarmRetried: a budget alarm the health stream refuses
// is raised at the next drop.
func TestUnknownBudgetAlarmRetried(t *testing.T) {
	g := newRig(t, asset.SyslogUDP, func(c *Config) {
		onlyA(c)
		c.Limits.UnknownBytes = minUnknownBytes
	})
	g.health.fail.Store(true)
	flood := g.udp(addrB)
	defer flood.Close()
	send := func(until func() bool) {
		deadline := time.Now().Add(5 * time.Second)
		for !until() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out; status %+v", g.r.Status())
			}
			flood.Write([]byte(unknownMsg))
			time.Sleep(time.Millisecond)
		}
	}
	send(func() bool { return strings.Contains(g.r.Status().LastErr, "unknown-budget alarm") })
	g.health.fail.Store(false)
	send(func() bool { return len(g.health.of(HealthUnknownBudget)) == 1 })
}
